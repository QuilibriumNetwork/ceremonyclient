//! Trait for syncing the global prover tree from archives.
//!
//! Workers need to sync the prover tree to resolve leader rotation,
//! verify FrameHeaders, and attribute shard work. In Go this is
//! `AppConsensusEngine.performBlockingGlobalHypersync` which calls
//! `HyperSyncSelf` against the master/archive. The Rust port can't
//! call `quil-rpc` from `quil-engine` (circular dep), so the trait
//! lives here and the implementation lives in `quil-node`.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use async_trait::async_trait;
use quil_types::error::Result;
use quil_types::proto::global::AppShardFrame;

/// Syncs the global prover tree (vertex-adds set for the global
/// intrinsic address) from an archive. Returns `true` if the
/// locally-recomputed root matches `expected_root` after sync.
///
/// Implementations should:
/// 1. Connect to an archive endpoint (mTLS)
/// 2. Pull the prover tree via `ensure_prover_tree_incremental`
/// with `expected_root` pinned
/// 3. Return whether the final root matches
#[async_trait]
pub trait ProverTreeSyncer: Send + Sync {
    /// Sync the global prover tree, pinning EACH phase to `expected_roots[phase]`
    /// — `[prover_tree_commitment (phase 0), prover_tree_aux_roots (1,2,3)]` from
    /// the global header (all four phases anchored). Empty slice ⇒
    /// trust the peer (bootstrap). Returns `Ok(true)` if post-sync roots match,
    /// `Ok(false)` if the sync completed but roots still diverge, `Err` on failure.
    async fn sync_prover_tree(&self, expected_roots: &[Vec<u8>]) -> Result<bool>;

    /// Sync a specific app-shard's subtrees from an archive, pinning EACH of
    /// the four phases to `expected_roots[phase]` — the finalized header's
    /// `state_roots` (all four phases anchored, not just vertex-adds).
    /// Used to catch a shard's CRDT up after a frame gap / restart / late-join.
    /// `filter` is the shard filter; the impl derives the `ShardKey`.
    /// An empty entry (or empty slice) trusts the peer for that phase
    /// (bootstrap). Default is a no-op (`Ok(false)`) for syncers without shard
    /// sync.
    async fn sync_shard_tree(&self, _filter: &[u8], _expected_roots: &[Vec<u8>]) -> Result<bool> {
        Ok(false)
    }

    /// Fetch an app-shard frame from an archive. `frame_number == 0` requests
    /// the latest frame and is used to seed an empty worker's clock lineage.
    async fn get_app_shard_frame(&self, _filter: &[u8], _frame_number: u64) -> Result<Option<AppShardFrame>> {
        Ok(None)
    }
}

pub(crate) enum ShardSyncResult {
    Anchored { anchor: AppShardFrame, predecessor: Option<AppShardFrame> },
    /// `pinned`: the origins' sealed state, verified against their roots;
    /// otherwise the archive's current subtree, unauthenticated.
    Inherited { pinned: bool },
    /// Why nothing usable was installed.
    NotReady(&'static str),
}

/// The owning actor authenticates and installs a checkpoint. A recovery task
/// keeps this exact target through completion, even if a worker is reassigned.
#[async_trait]
pub(crate) trait ShardRecoveryTarget: Send + Sync {
    fn materialized(&self) -> u64;
    /// Consecutive descendants ending at a certified frame authenticate a
    /// frame with no certificate of its own. The actor verifies the whole chain.
    async fn replay(&self, frame: AppShardFrame, descendants: Vec<AppShardFrame>) -> Result<u64>;
    async fn validate(&self, anchor: AppShardFrame, predecessor: Option<AppShardFrame>) -> Result<bool>;
    async fn install(&self, anchor: AppShardFrame, predecessor: Option<AppShardFrame>) -> Result<()>;
    fn inherited(&self);
    /// `(source filter, sealed roots)` of the certified state a shard with no
    /// frame of its own syncs against (`app_handoff::origin_anchors`).
    async fn origin_anchors(&self) -> Result<Vec<(Vec<u8>, [[u8; 32]; 4])>> {
        Ok(Vec::new())
    }
    /// The base-state roots a refused archive tip attests: the certified
    /// first frame of a session GLOBAL ended at the current session's base.
    async fn discarded_base_roots(&self, _frame: AppShardFrame) -> Result<Option<Vec<Vec<u8>>>> {
        Ok(None)
    }
    /// The frame GLOBAL has executed the shard's current session through
    /// (`app_handoff::committed_tip`): replay targets at least this, and an
    /// archive below it is behind, not a sign the worker is up to date.
    async fn committed_tip(&self) -> Option<u64> {
        None
    }
    /// Whether this shard owes a re-anchor (`app_handoff::ReanchorMarker`),
    /// its head past its session's fence on frames the fence discarded, and
    /// whether this sync makes the attempt.
    async fn reanchor_fence(&self) -> ReanchorAttempt {
        ReanchorAttempt::NotOwed
    }
    /// An attempt of the owed re-anchor installed nothing, for `reason`.
    fn reanchor_failed(&self, _reason: String) {}
}

#[async_trait]
impl ShardRecoveryTarget for crate::app_engine::AppEngineHandle {
    fn materialized(&self) -> u64 { self.materialized_frame() }
    async fn replay(&self, frame: AppShardFrame, descendants: Vec<AppShardFrame>) -> Result<u64> {
        self.replay_archive_frame(frame, descendants).await
    }
    async fn validate(&self, anchor: AppShardFrame, predecessor: Option<AppShardFrame>) -> Result<bool> {
        self.validate_sync_anchor(anchor, predecessor).await
    }
    async fn install(&self, anchor: AppShardFrame, predecessor: Option<AppShardFrame>) -> Result<()> {
        self.complete_archive_sync(anchor, predecessor).await
    }
    fn inherited(&self) {
        self.send(crate::app_engine::AppEngineMessage::ShardSyncCompleted { synced_to_frame: 0 });
    }
    async fn origin_anchors(&self) -> Result<Vec<(Vec<u8>, [[u8; 32]; 4])>> {
        crate::app_engine::AppEngineHandle::origin_anchors(self).await
    }
    async fn discarded_base_roots(&self, frame: AppShardFrame) -> Result<Option<Vec<Vec<u8>>>> {
        crate::app_engine::AppEngineHandle::discarded_base_roots(self, frame).await
    }
    async fn committed_tip(&self) -> Option<u64> {
        crate::app_engine::AppEngineHandle::committed_tip(self).await
    }
    async fn reanchor_fence(&self) -> ReanchorAttempt {
        crate::app_engine::AppEngineHandle::reanchor_fence(self).await
    }
    fn reanchor_failed(&self, reason: String) {
        self.send(crate::app_engine::AppEngineMessage::ReanchorFailed { reason });
    }
}

/// What a shard sync starting now does about a re-anchor at the fence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReanchorAttempt {
    /// None is owed: the sync runs as usual.
    NotOwed,
    /// This sync makes the owed attempt, at the fence it names.
    Take(u64),
    /// One is owed and another sync has its attempt: this one does nothing,
    /// since the shard's own lineage is discarded and nothing else may write
    /// its trees.
    Elsewhere,
}

/// One turn's replay: the frames it materialized, the batches they took,
/// and its time spent on archive requests and on the engine's replay.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReplayTurn {
    pub frames: u64,
    pub batches: u32,
    pub fetch_ms: u64,
    pub replay_ms: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ShardRecoveryProgress {
    /// `archive_tip`: the highest tip an archive reported (`None`: none had a
    /// frame of the shard). `committed_tip`: GLOBAL's executed frame of the
    /// session. Materialized below the committed tip is not up to date.
    Replayed { materialized: u64, archive_tip: Option<u64>, committed_tip: Option<u64>, turn: ReplayTurn },
    Anchored { frame: u64 },
    Inherited { pinned: bool },
    NotReady(&'static str),
    /// Nothing was attempted, for a reason that is no failure of the
    /// recovery (a re-anchor at the fence has its own attempt): no counter,
    /// streak or archive state changes.
    Deferred(&'static str),
}

impl std::fmt::Display for ShardRecoveryProgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let tip = |tip: &Option<u64>| tip.map_or_else(|| "none".to_string(), |tip| tip.to_string());
        match self {
            Self::Replayed { materialized, archive_tip, committed_tip, .. } => write!(f,
                "replayed to frame {materialized} (archive tip {}, committed tip {})", tip(archive_tip), tip(committed_tip)),
            Self::Anchored { frame } => write!(f, "installed the archive checkpoint at frame {frame}"),
            Self::Inherited { pinned: true } => f.write_str("inherited the origins' sealed state"),
            Self::Inherited { pinned: false } => f.write_str("inherited the covered archive subtree, unpinned"),
            Self::NotReady(reason) | Self::Deferred(reason) => f.write_str(reason),
        }
    }
}

/// Common recovery path for thread and separate-process workers. A saved
/// lineage replays certified bodies; an empty worker fetches and authenticates
/// the archive checkpoint before tree writes, then waits for actor installation.
///
/// `blocked`: the successor-blocked flag of a worker holding a recovery turn
/// (`None` without one). A turn replays one batch, and while the flag stays
/// set further batches up to the replay target, within the turn budget
/// ([`crate::recovery_turns::holds_turn`]).
pub(crate) async fn recover_shard_from_latest(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    local: Option<AppShardFrame>,
    target: &dyn ShardRecoveryTarget,
    blocked: Option<&AtomicBool>,
) -> Result<ShardRecoveryProgress> {
    use crate::worker_execution::recovery_phase;
    // No archive extends a head the fence discarded: the local lineage is
    // not replayed, and the shard is anchored again.
    match target.reanchor_fence().await {
        ReanchorAttempt::Take(fence) => {
            let result = reanchor_shard_at_fence(syncer, filter, fence, target).await;
            match &result {
                Ok(ShardRecoveryProgress::NotReady(reason)) => target.reanchor_failed((*reason).to_string()),
                Err(error) => target.reanchor_failed(error.to_string()),
                Ok(_) => {}
            }
            return result;
        }
        ReanchorAttempt::Elsewhere => return Ok(ShardRecoveryProgress::Deferred(REANCHOR_ELSEWHERE)),
        ReanchorAttempt::NotOwed => {}
    }
    if let Some(local) = local {
        recovery_phase("replaying_frames");
        let committed_tip = target.committed_tip().await;
        let (started, from, replay_us) = (Instant::now(), target.materialized(), &AtomicU64::new(0));
        let (mut materialized, mut batches) = (from, 0);
        // A batch short of its target replayed all its frames: each frame
        // advances the replay or fails it.
        let replay = loop {
            let replay = replay_shard_from_latest(
                syncer, filter, local.clone(), materialized, committed_tip, |frame, child| async move {
                    let at = Instant::now();
                    let advanced = target.replay(frame, child).await;
                    replay_us.fetch_add(at.elapsed().as_micros() as u64, Ordering::Relaxed);
                    advanced
                },
            ).await?;
            batches += 1;
            if replay.materialized >= replay.target || !crate::recovery_turns::holds_turn(blocked, started.elapsed()) {
                break replay;
            }
            materialized = replay.materialized;
        };
        let replay_ms = replay_us.load(Ordering::Relaxed) / 1000;
        let turn = ReplayTurn {
            frames: replay.materialized.saturating_sub(from), batches,
            fetch_ms: (started.elapsed().as_millis() as u64).saturating_sub(replay_ms), replay_ms,
        };
        return Ok(ShardRecoveryProgress::Replayed {
            materialized: replay.materialized, archive_tip: replay.archive_tip, committed_tip, turn,
        });
    }
    let anchors = target.origin_anchors().await.unwrap_or_else(|error| {
        tracing::warn!(filter = %hex::encode(filter), %error, "origin anchors unavailable; bootstrap unpinned");
        Vec::new()
    });
    let committed_tip = target.committed_tip().await;
    recovery_phase("fetching_checkpoint");
    match sync_shard_from_latest_attested(
        syncer, filter, None, &anchors, committed_tip,
        |anchor, predecessor| target.validate(anchor, predecessor),
        |frame| target.discarded_base_roots(frame),
    ).await? {
        ShardSyncResult::Anchored { anchor, predecessor } => {
            let frame = anchor.header.as_ref().map_or(0, |header| header.frame_number);
            recovery_phase("installing_checkpoint");
            target.install(anchor, predecessor).await?;
            Ok(ShardRecoveryProgress::Anchored { frame })
        }
        ShardSyncResult::Inherited { pinned } => { target.inherited(); Ok(ShardRecoveryProgress::Inherited { pinned }) }
        ShardSyncResult::NotReady(reason) => Ok(ShardRecoveryProgress::NotReady(reason)),
    }
}

/// Why a re-anchor at the session fence installed nothing.
pub(crate) const REANCHOR_NO_TIP: &str = "GLOBAL's committed frame of the session is not known here";
pub(crate) const REANCHOR_UNAVAILABLE: &str = "the archive does not hold the frame GLOBAL committed or the state before it";
pub(crate) const REANCHOR_REFUSED: &str = "the archive's copy of the frame GLOBAL committed was refused at validation";
/// A sync that is not the owed re-anchor's attempt (`ReanchorAttempt::Elsewhere`).
pub(crate) const REANCHOR_ELSEWHERE: &str = "a re-anchor at the session fence is owed and has its own attempt";
/// Marks the failure of a re-anchor step that runs on this node.
pub(crate) const REANCHOR_ON_THIS_NODE: &str = "on this node";

fn on_this_node(step: &'static str) -> impl Fn(quil_types::error::QuilError) -> quil_types::error::QuilError {
    move |error| quil_types::error::QuilError::ExecutionUnavailable(format!("re-anchor {step} {REANCHOR_ON_THIS_NODE}: {error}"))
}

/// Re-anchor a shard whose head lies past its session's fence on frames the
/// fence discarded, which this node cannot rewind (`app_handoff::fence_rewind`).
/// The anchor is the frame GLOBAL committed for the session
/// (`app_handoff::committed_tip`): the fence, the successor's base, while
/// the successor has executed nothing, its executed tip after. It is
/// authenticated as a bootstrap's is, and the shard's trees are synced
/// pinned to its roots; the actor then rebases the shard's frames and cursor
/// below it and replays it. Nothing is inherited unpinned: without an
/// archive that serves the anchor and its state, the shard waits.
async fn reanchor_shard_at_fence(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    fence: u64,
    target: &dyn ShardRecoveryTarget,
) -> Result<ShardRecoveryProgress> {
    use crate::worker_execution::recovery_phase;
    recovery_phase("fetching_checkpoint");
    let Some(committed) = target.committed_tip().await.filter(|&tip| tip > 0 && tip >= fence) else {
        return Ok(ShardRecoveryProgress::NotReady(REANCHOR_NO_TIP));
    };
    let mut validate = |anchor, predecessor| {
        let validated = target.validate(anchor, predecessor);
        async move { validated.await.map_err(on_this_node("validation")) }
    };
    let Some(frame) = syncer.get_app_shard_frame(filter, committed).await? else {
        return Ok(ShardRecoveryProgress::NotReady(REANCHOR_UNAVAILABLE));
    };
    let Some((anchor, predecessor)) = authenticated_anchor(syncer, filter, frame, Some(committed), &mut validate).await? else {
        return Ok(ShardRecoveryProgress::NotReady(REANCHOR_REFUSED));
    };
    let roots = anchor.header.as_ref().map(|header| header.state_roots.clone()).unwrap_or_default();
    recovery_phase("installing_leaves");
    if !syncer.sync_shard_tree(filter, &roots).await? {
        return Ok(ShardRecoveryProgress::NotReady(REANCHOR_UNAVAILABLE));
    }
    recovery_phase("installing_checkpoint");
    target.install(anchor, predecessor).await.map_err(on_this_node("installation"))?;
    Ok(ShardRecoveryProgress::Anchored { frame: committed })
}

/// Archives asked for a shard's tip when the first answer is behind GLOBAL's
/// committed session tip, and attempts per frame: each request goes to the
/// next archive in the pool.
const TIP_PROBES: usize = 3;
const FRAME_ATTEMPTS: usize = 3;

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ShardReplay {
    pub materialized: u64,
    /// The highest tip an archive reported; `None` when none had a frame.
    pub archive_tip: Option<u64>,
    pub target: u64,
}

/// A frame of `filter` from the first of `attempts` archive requests that has
/// it. `Ok(None)` when every archive answered without it.
async fn fetch_shard_frame(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    number: u64,
    attempts: usize,
) -> Result<Option<AppShardFrame>> {
    let mut failure = None;
    let mut answered = false;
    for _ in 0..attempts.max(1) {
        match syncer.get_app_shard_frame(filter, number).await {
            Ok(Some(frame)) => return Ok(Some(frame)),
            Ok(None) => answered = true,
            Err(error) => failure = Some(error),
        }
    }
    match failure {
        Some(error) if !answered => Err(error),
        _ => Ok(None),
    }
}

/// Repair a materialized worker by replaying a bounded number of certified
/// frames through its owning engine. Tree-only fast-forward loses fee, spend,
/// settlement and accumulator history and can race normal materialization.
///
/// The target is the highest archive tip, and at least `committed` (GLOBAL's
/// executed frame of the session): an archive can answer with an old tip, or
/// none, while it or another holds the frames, so one archive's answer alone
/// never ends recovery below what GLOBAL has executed. Every frame is still
/// authenticated by `replay`.
pub(crate) async fn replay_shard_from_latest<F, Fut>(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    local: AppShardFrame,
    mut materialized: u64,
    committed: Option<u64>,
    mut replay: F,
) -> Result<ShardReplay>
where
    F: FnMut(AppShardFrame, Vec<AppShardFrame>) -> Fut,
    Fut: std::future::Future<Output = Result<u64>>,
{
    use prost::Message;
    use quil_types::error::QuilError;
    let height = |frame: &AppShardFrame| frame.header.as_ref().map_or(0, |h| h.frame_number);
    let committed = committed.unwrap_or(0);
    let mut remote: Option<AppShardFrame> = None;
    let mut failure = None;
    for probe in 0..TIP_PROBES {
        // The local head satisfying GLOBAL is not evidence that this archive
        // is current. Keep the bounded rotation going until a peer reaches
        // both the known local lineage and the committed checkpoint.
        if probe > 0 && remote.as_ref().is_some_and(|frame| height(frame) >= height(&local).max(committed)) {
            break;
        }
        match syncer.get_app_shard_frame(filter, 0).await {
            Ok(Some(frame)) if frame.header.as_ref().is_some_and(|h| h.address == filter) => {
                if remote.as_ref().is_none_or(|best| height(&frame) > height(best)) {
                    remote = Some(frame);
                }
            }
            Ok(Some(_)) if probe == 0 && committed == 0 => {
                return Err(QuilError::InvalidArgument("wrong-shard archive replay tip".into()));
            }
            Ok(_) => {}
            Err(error) => failure = Some(error),
        }
    }
    if remote.is_none() {
        if let Some(error) = failure.filter(|_| committed <= height(&local)) {
            return Err(error);
        }
    }
    let archive_tip = remote.as_ref().map(height);
    let tip = match remote {
        Some(remote) if height(&remote) >= height(&local) => remote,
        _ => local,
    };
    if tip.header.as_ref().is_none_or(|h| h.address != filter) {
        return Err(QuilError::InvalidArgument("wrong-shard archive replay tip".into()));
    }
    let tip_height = height(&tip);
    let target = tip_height.max(committed);
    if archive_tip.unwrap_or(0) < committed && materialized < committed {
        tracing::info!(filter = %hex::encode(filter), materialized, ?archive_tip, committed_tip = committed,
            "archive shard tip is behind GLOBAL's committed session tip; replaying by frame number");
    }
    for _ in 0..32 {
        if materialized >= target { break; }
        let next = materialized + 1;
        let frame = if next == tip_height {
            tip.clone()
        } else {
            fetch_shard_frame(syncer, filter, next, FRAME_ATTEMPTS).await?.ok_or_else(|| {
                QuilError::ExecutionUnavailable(format!(
                    "archive replay is missing shard frame {next} (archive tip {archive_tip:?}, committed {committed})"
                ))
            })?
        };
        if frame.header.as_ref().is_none_or(|h| h.address != filter || h.frame_number != next)
            || frame.encoded_len() > 16 * 1024 * 1024 {
            return Err(QuilError::InvalidArgument("invalid or oversized archive replay frame".into()));
        }
        let certified = |frame: &AppShardFrame| frame.header.as_ref()
            .and_then(|header| header.public_key_signature_bls48581.as_ref())
            .is_some_and(|signature| !signature.signature.is_empty());
        let mut descendants = Vec::new();
        let mut bytes = frame.encoded_len();
        if !certified(&frame) {
            for offset in 1..=crate::frame_validator::MAX_REPLAY_DESCENDANTS {
                let number = next.checked_add(offset as u64)
                    .filter(|number| *number <= target)
                    .ok_or_else(|| QuilError::ExecutionUnavailable(
                        "archive replay has no certified descendant within its target".into()))?;
                let child = if number == tip_height { tip.clone() } else {
                    fetch_shard_frame(syncer, filter, number, FRAME_ATTEMPTS).await?
                        .ok_or_else(|| QuilError::ExecutionUnavailable(format!(
                            "archive replay is missing descendant frame {number}")))?
                };
                bytes = bytes.saturating_add(child.encoded_len());
                if child.header.as_ref().is_none_or(|h| h.address != filter || h.frame_number != number)
                    || bytes > crate::frame_validator::MAX_REPLAY_CHAIN_BYTES {
                    return Err(QuilError::InvalidArgument("invalid or oversized archive replay chain".into()));
                }
                let terminal = certified(&child);
                descendants.push(child);
                if terminal { break; }
            }
            if !descendants.last().is_some_and(certified) {
                return Err(QuilError::ExecutionUnavailable("archive replay certified descendant limit reached".into()));
            }
        }
        let advanced = replay(frame, descendants).await?;
        if advanced < next {
            return Err(QuilError::ExecutionUnavailable("archive replay did not materialize its frame".into()));
        }
        materialized = advanced;
    }
    Ok(ShardReplay { materialized, archive_tip, target })
}

/// The base state of a session based at frame 0 of which GLOBAL executed no
/// frame, when the archive's latest frame (`refused`) failed validation: it
/// belongs to a session GLOBAL ended without executing it, and the archive's
/// current subtree may include its writes. Sync only state something
/// certifies: the origins' sealed roots, else the pre-state roots `refused`
/// attests as the certified first frame of a session ended at this base
/// (`attest_base`). Otherwise refuse; never inherit the subtree unpinned. A
/// shard whose sessions all ended at frame 0 kept every member unstaged and
/// its committee nullifying every view (…a1a80, generation 13, 2026-10-22).
async fn sync_unexecuted_base<A, AFut>(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    origin_anchors: &[(Vec<u8>, [[u8; 32]; 4])],
    refused: AppShardFrame,
    attest_base: &mut A,
) -> Result<ShardSyncResult>
where
    A: FnMut(AppShardFrame) -> AFut,
    AFut: std::future::Future<Output = Result<Option<Vec<Vec<u8>>>>>,
{
    use crate::worker_execution::recovery_phase;
    let number = refused.header.as_ref().map_or(0, |header| header.frame_number);
    if !origin_anchors.is_empty() {
        recovery_phase("installing_leaves");
        for (source, roots) in origin_anchors {
            let pinned: Vec<Vec<u8>> = roots.iter().map(|root| root.to_vec()).collect();
            if !syncer.sync_shard_tree(source, &pinned).await? {
                return Ok(ShardSyncResult::NotReady(
                    "the archive does not hold the session's certified base state, or its roots differ",
                ));
            }
        }
        tracing::info!(filter = %hex::encode(filter), refused_frame = number, origins = origin_anchors.len(),
            "archive's latest shard frame refused; bootstrapped from the origins' sealed state at the session base");
        return Ok(ShardSyncResult::Inherited { pinned: true });
    }
    let Some(roots) = attest_base(refused).await? else {
        return Ok(ShardSyncResult::NotReady(
            "the archive checkpoint failed validation, and nothing certifies the session's base state",
        ));
    };
    recovery_phase("installing_leaves");
    if !syncer.sync_shard_tree(filter, &roots).await? {
        return Ok(ShardSyncResult::NotReady(
            "the archive does not hold the session's attested base state, or its roots differ",
        ));
    }
    tracing::info!(filter = %hex::encode(filter), refused_frame = number,
        "archive's latest shard frame refused; bootstrapped from the base state its certified first frame attests");
    Ok(ShardSyncResult::Inherited { pinned: true })
}

/// An anchor and its predecessor, both accepted by `validate`; `None` when
/// refused. A malformed or wrong-shard anchor, or one that is not frame
/// `expected`, is an error.
async fn authenticated_anchor<F, Fut>(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    anchor: AppShardFrame,
    expected: Option<u64>,
    validate: &mut F,
) -> Result<Option<(AppShardFrame, Option<AppShardFrame>)>>
where
    F: FnMut(AppShardFrame, Option<AppShardFrame>) -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
{
    use quil_types::error::QuilError;
    let header = anchor.header.as_ref().ok_or_else(|| QuilError::InvalidArgument("archive anchor has no header".into()))?;
    if header.address != filter || header.frame_number == 0
        || expected.is_some_and(|number| header.frame_number != number)
        || header.state_roots.len() != 4 || header.state_roots.iter().any(|root| root.len() != 32) {
        return Err(QuilError::InvalidArgument("malformed or wrong-shard archive anchor".into()));
    }
    let predecessor = if header.frame_number > 1 {
        syncer.get_app_shard_frame(filter, header.frame_number - 1).await?
    } else { None };
    Ok(validate(anchor.clone(), predecessor.clone()).await?.then_some((anchor, predecessor)))
}

/// [`sync_shard_from_latest_attested`] for a session whose base needs no
/// attestation.
#[cfg(test)]
pub(crate) async fn sync_shard_from_latest<F, Fut>(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    local: Option<AppShardFrame>,
    origin_anchors: &[(Vec<u8>, [[u8; 32]; 4])],
    committed: Option<u64>,
    validate: F,
) -> Result<ShardSyncResult>
where
    F: FnMut(AppShardFrame, Option<AppShardFrame>) -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
{
    sync_shard_from_latest_attested(
        syncer, filter, local, origin_anchors, committed, validate, |_| async { Ok(None) },
    ).await
}

/// A stale worker must discover the archive tip even when it has a local
/// clock head. Authenticate the selected chain before installing any leaves.
/// The validator runs on the engine that owns the worker's committee view.
///
/// `committed`: the frame GLOBAL has executed the shard's current session
/// through, or its base (`app_handoff::committed_tip`). When the archive's
/// latest frame is refused, the anchor falls back to that frame, and
/// `attest_base` gives the base-state
/// roots a refused archive tip attests (see [`sync_unexecuted_base`]).
pub(crate) async fn sync_shard_from_latest_attested<F, Fut, A, AFut>(
    syncer: &dyn ProverTreeSyncer,
    filter: &[u8],
    local: Option<AppShardFrame>,
    origin_anchors: &[(Vec<u8>, [[u8; 32]; 4])],
    committed: Option<u64>,
    mut validate: F,
    mut attest_base: A,
) -> Result<ShardSyncResult>
where
    F: FnMut(AppShardFrame, Option<AppShardFrame>) -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
    A: FnMut(AppShardFrame) -> AFut,
    AFut: std::future::Future<Output = Result<Option<Vec<Vec<u8>>>>>,
{
    use crate::worker_execution::recovery_phase;
    let remote = syncer.get_app_shard_frame(filter, 0).await?;
    let height = |frame: &AppShardFrame| frame.header.as_ref().map_or(0, |h| h.frame_number);
    let anchor = match (local, remote) {
        (Some(local), Some(remote)) if height(&local) > height(&remote) => Some(local),
        (_, Some(remote)) => Some(remote),
        (local, None) => local,
    };
    let Some(anchor) = anchor else {
        // A new child without a certified frame of its own holds its origins'
        // state. Sync each origin's range pinned to its sealed roots, which the
        // sync verifies; the origins partition the child's range. Without
        // certified origins, or when no archive still resolves them (retention),
        // inherit the covered archive subtree unpinned, as before.
        recovery_phase("installing_leaves");
        if !origin_anchors.is_empty() {
            let mut pinned = true;
            for (source, roots) in origin_anchors {
                let pinned_roots: Vec<Vec<u8>> = roots.iter().map(|root| root.to_vec()).collect();
                let failure = match syncer.sync_shard_tree(source, &pinned_roots).await {
                    Ok(true) => continue,
                    Ok(false) => "the archive does not hold it or the synced roots differ".to_string(),
                    Err(error) => error.to_string(),
                };
                tracing::warn!(filter = %hex::encode(filter), source = %hex::encode(source),
                    sealed_roots = ?roots.iter().map(hex::encode).collect::<Vec<_>>(), %failure,
                    "origin's sealed state could not be synced");
                pinned = false;
                break;
            }
            if pinned {
                tracing::info!(filter = %hex::encode(filter), origins = origin_anchors.len(),
                    "shard bootstrapped from its origins' sealed state");
                return Ok(ShardSyncResult::Inherited { pinned: true });
            }
            // A same-filter origin's sealed roots are what this shard's
            // successor requires at startup (`successor_state_matches`): an
            // unpinned copy is refused there unless it equals them, and the
            // worker installed it, reported success and was refused again
            // every few seconds. Wait for an archive that holds the state.
            if origin_anchors.iter().any(|(source, _)| source.as_slice() == filter) {
                tracing::warn!(filter = %hex::encode(filter),
                    "the predecessor's sealed state is not available from the archive; not inheriting unpinned state its successor would refuse");
                return Ok(ShardSyncResult::NotReady("the predecessor's sealed state is not available from the archive"));
            }
            tracing::warn!(filter = %hex::encode(filter),
                "origins' sealed state is not available from the archive; inheriting the covered subtree unpinned");
        } else {
            tracing::info!(filter = %hex::encode(filter),
                "no certified origin state for this shard; inheriting the covered subtree unpinned");
        }
        return Ok(if syncer.sync_shard_tree(filter, &[]).await? {
            ShardSyncResult::Inherited { pinned: false }
        } else { ShardSyncResult::NotReady("the archive could not supply the covered subtree") });
    };
    let latest = height(&anchor);
    let refused = (committed == Some(0)).then(|| anchor.clone());
    let (anchor, predecessor) = match authenticated_anchor(syncer, filter, anchor, None, &mut validate).await? {
        Some(pair) => pair,
        // The latest frame an archive holds can lie above the checkpoint GLOBAL
        // fenced the shard's last session at: frames its closing committee
        // finalized that GLOBAL never executed. Validation refuses every frame
        // past a terminal checkpoint, and archives serve them as the latest
        // until a successor produces past them. A member holding none of the
        // shard's data never bootstrapped, so never started, and a successor
        // that needed such members for quorum never produced (2026-10-13). The
        // frame GLOBAL committed is the successor's base and authenticated.
        None => {
            // GLOBAL executed no frame of a session based at frame 0, which
            // has no frame to anchor at.
            if let Some(refused) = refused {
                return sync_unexecuted_base(syncer, filter, origin_anchors, refused, &mut attest_base).await;
            }
            let Some(committed) = committed.filter(|&number| number > 0 && number < latest) else {
                return Ok(ShardSyncResult::NotReady("the archive checkpoint failed validation"));
            };
            let fallback = match syncer.get_app_shard_frame(filter, committed).await? {
                Some(frame) => authenticated_anchor(syncer, filter, frame, Some(committed), &mut validate).await?,
                None => None,
            };
            let Some(pair) = fallback else {
                return Ok(ShardSyncResult::NotReady("the archive checkpoint failed validation"));
            };
            tracing::info!(filter = %hex::encode(filter), latest, committed,
                "archive's latest shard frame refused; bootstrapping from the frame GLOBAL committed");
            pair
        }
    };
    let expected_roots = anchor.header.as_ref().map(|header| header.state_roots.clone()).unwrap_or_default();
    recovery_phase("installing_leaves");
    Ok(if syncer.sync_shard_tree(filter, &expected_roots).await? {
        ShardSyncResult::Anchored { anchor, predecessor }
    } else { ShardSyncResult::NotReady("the archive does not hold the checkpoint's state, or its roots differ") })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct Target {
        calls: Arc<Mutex<Vec<String>>>,
        cursor: std::sync::atomic::AtomicU64,
        valid: bool,
        install_ok: bool,
        /// The successor-blocked flag, cleared once frame `unblock_at` replays.
        blocked: AtomicBool,
        unblock_at: u64,
    }
    #[async_trait]
    impl ShardRecoveryTarget for Target {
        fn materialized(&self) -> u64 { self.cursor.load(std::sync::atomic::Ordering::SeqCst) }
        async fn replay(&self, frame: AppShardFrame, _descendants: Vec<AppShardFrame>) -> Result<u64> {
            let number = frame.header.unwrap().frame_number;
            assert_eq!(number, self.materialized()+1);
            self.calls.lock().unwrap().push(format!("replay {number}"));
            self.cursor.store(number, std::sync::atomic::Ordering::SeqCst);
            if number == self.unblock_at { self.blocked.store(false, std::sync::atomic::Ordering::SeqCst); }
            Ok(number)
        }
        async fn validate(&self, anchor: AppShardFrame, predecessor: Option<AppShardFrame>) -> Result<bool> {
            let number = anchor.header.unwrap().frame_number;
            assert_eq!(predecessor.unwrap().header.unwrap().frame_number, number-1);
            self.calls.lock().unwrap().push(format!("validate {number}"));
            Ok(self.valid)
        }
        async fn install(&self, anchor: AppShardFrame, _: Option<AppShardFrame>) -> Result<()> {
            let number = anchor.header.unwrap().frame_number;
            self.calls.lock().unwrap().push(format!("install {number}"));
            if !self.install_ok { return Err(quil_types::error::QuilError::ExecutionUnavailable("actor rejected checkpoint".into())); }
            self.cursor.store(number, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
        fn inherited(&self) { panic!("a certified archive tip must never use unanchored inheritance") }
    }

    #[tokio::test]
    async fn headless_worker_recovers_from_archive_and_waits_for_authenticated_installation() {
        for (valid, install_ok) in [(true, true), (false, true), (true, false)] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let archive = Archive { latest:Some(frame(500)), calls:calls.clone() };
            let target = Target { calls:calls.clone(), cursor:0.into(), valid, install_ok, blocked:false.into(), unblock_at:0 };
            let result = recover_shard_from_latest(&archive, &[5;32], None, &target, None).await;
            let mut expected = vec!["fetch 0", "fetch 499", "validate 500"];
            if valid { expected.extend(["sync 244", "install 500"]); }
            assert_eq!(*calls.lock().unwrap(), expected);
            if !valid { assert_eq!(result.unwrap(), ShardRecoveryProgress::NotReady("the archive checkpoint failed validation")); }
            else if !install_ok { assert!(result.is_err()); }
            else { assert_eq!(result.unwrap(), ShardRecoveryProgress::Anchored { frame:500 }); }
            assert_eq!(target.materialized(), if valid && install_ok { 500 } else { 0 });
        }
    }

    #[tokio::test]
    async fn existing_worker_lineage_replays_instead_of_replacing_its_tree() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest:Some(frame(500)), calls:calls.clone() };
        let target = Target { calls:calls.clone(), cursor:129.into(), valid:false, install_ok:false, blocked:false.into(), unblock_at:0 };
        let result = recover_shard_from_latest(&archive, &[5;32], Some(frame(130)), &target, None).await.unwrap();
        let ShardRecoveryProgress::Replayed { materialized, archive_tip, committed_tip, turn } = result else { panic!("expected a replay") };
        assert_eq!((materialized, archive_tip, committed_tip, turn.frames, turn.batches), (161, Some(500), None, 32, 1));
        let calls = calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|s| s.starts_with("replay ")).count(), 32);
        assert!(!calls.iter().any(|s| s.starts_with("sync ") || s.starts_with("install ")));
    }

    /// A blocked successor keeps its turn: it replays batch after batch up to
    /// its target, while any other recovery replays one batch per turn.
    #[tokio::test]
    async fn a_blocked_successor_replays_to_its_target_in_one_turn() {
        for (blocked, expected, batches) in [(Some(true), 200, 3), (Some(false), 161, 1), (None, 161, 1)] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let archive = Archive { latest: Some(frame(200)), calls: calls.clone() };
            let target = Target { calls: calls.clone(), cursor: 129.into(), valid: false, install_ok: false,
                blocked: blocked.unwrap_or(false).into(), unblock_at: 0 };
            let result = recover_shard_from_latest(&archive, &[5; 32], Some(frame(130)), &target,
                blocked.map(|_| &target.blocked)).await.unwrap();
            let ShardRecoveryProgress::Replayed { materialized, archive_tip, turn, .. } = result else { panic!("expected a replay") };
            assert_eq!((materialized, archive_tip, turn.frames, turn.batches), (expected, Some(200), expected - 129, batches), "{blocked:?}");
            let calls = calls.lock().unwrap();
            let replayed: Vec<_> = calls.iter().filter(|call| call.starts_with("replay ")).cloned().collect();
            assert_eq!(replayed, (130..=expected).map(|n| format!("replay {n}")).collect::<Vec<_>>());
            assert_eq!(calls.iter().filter(|call| *call == "fetch 0").count(), batches as usize, "one tip probe per batch");
        }
    }

    /// The turn ends with the batch in which the successor stopped being
    /// blocked.
    #[tokio::test]
    async fn a_successor_no_longer_blocked_hands_its_turn_back_after_the_batch() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(600)), calls: calls.clone() };
        let target = Target { calls: calls.clone(), cursor: 129.into(), valid: false, install_ok: false,
            blocked: true.into(), unblock_at: 170 };
        let result = recover_shard_from_latest(&archive, &[5; 32], Some(frame(130)), &target, Some(&target.blocked)).await.unwrap();
        let ShardRecoveryProgress::Replayed { materialized, turn, .. } = result else { panic!("expected a replay") };
        assert_eq!((materialized, turn.frames, turn.batches), (193, 64, 2));
    }

    /// A failed batch ends a blocked successor's turn with the failure; the
    /// frames replayed before it stay materialized.
    #[tokio::test]
    async fn a_blocked_successors_turn_ends_at_a_failed_batch() {
        let archive = ChainArchive { missing: Some(170), wrong_shard: false, unsigned_end: 0 };
        let target = Target { calls: Arc::new(Mutex::new(Vec::new())), cursor: 130.into(), valid: false, install_ok: false,
            blocked: true.into(), unblock_at: 0 };
        let error = recover_shard_from_latest(&archive, &[5; 32], Some(frame(130)), &target, Some(&target.blocked)).await.unwrap_err();
        assert!(error.to_string().contains("missing shard frame 170"), "{error}");
        assert_eq!(target.materialized(), 169);
    }

    struct Archive {
        latest: Option<AppShardFrame>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    /// A certified frame (its certificate is not checked here).
    fn frame(number: u64) -> AppShardFrame {
        AppShardFrame {
            header: Some(quil_types::proto::global::FrameHeader {
                address: vec![5; 32], frame_number: number,
                state_roots: vec![vec![number as u8; 32]; 4],
                public_key_signature_bls48581: Some(quil_types::proto::keys::Bls48581AggregateSignature {
                    signature: vec![1], ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[async_trait]
    impl ProverTreeSyncer for Archive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
        async fn get_app_shard_frame(&self, _: &[u8], number: u64) -> Result<Option<AppShardFrame>> {
            self.calls.lock().unwrap().push(format!("fetch {number}"));
            Ok(if number == 0 { self.latest.clone() } else { Some(frame(number)) })
        }
        async fn sync_shard_tree(&self, _: &[u8], roots: &[Vec<u8>]) -> Result<bool> {
            self.calls.lock().unwrap().push(format!("sync {}", roots[0][0]));
            Ok(true)
        }
    }

    #[tokio::test]
    async fn stale_local_head_uses_newer_certified_archive_anchor_before_any_tree_write() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(600)), calls: calls.clone() };
        let validate_calls = calls.clone();
        let result = sync_shard_from_latest(&archive, &[5; 32], Some(frame(130)), &[], None,
            move |anchor, predecessor| {
                assert_eq!(anchor.header.unwrap().frame_number, 600);
                assert_eq!(predecessor.unwrap().header.unwrap().frame_number, 599);
                validate_calls.lock().unwrap().push("validate 600".into());
                async { Ok(true) }
            }).await.unwrap();
        assert!(matches!(result, ShardSyncResult::Anchored { .. }));
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "fetch 599", "validate 600", "sync 88"]);
    }

    #[tokio::test]
    async fn archive_replay_fills_a_stale_workers_gap_in_bounded_batches_without_tree_sync() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(600)), calls: calls.clone() };
        let replayed = Arc::new(Mutex::new(Vec::new()));
        let seen = replayed.clone();
        let result = replay_shard_from_latest(&archive, &[5; 32], frame(130), 129, None,
            move |frame, _child| {
                let height = frame.header.unwrap().frame_number;
                seen.lock().unwrap().push(height);
                async move { Ok(height) }
            }).await.unwrap();
        assert_eq!(result, ShardReplay { materialized: 161, archive_tip: Some(600), target: 600 });
        assert_eq!(*replayed.lock().unwrap(), (130..=161).collect::<Vec<_>>());
        assert_eq!(calls.lock().unwrap().len(), 33);
        assert!(calls.lock().unwrap().iter().all(|call| call.starts_with("fetch ")));
    }

    /// Serves certified frames up to a tip of 134, except frame 132, which
    /// has no certificate of its own.
    struct BareArchive;

    #[async_trait]
    impl ProverTreeSyncer for BareArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
        async fn get_app_shard_frame(&self, _: &[u8], number: u64) -> Result<Option<AppShardFrame>> {
            let mut served = frame(if number == 0 { 134 } else { number });
            if number == 132 {
                served.header.as_mut().unwrap().public_key_signature_bls48581 = None;
            }
            Ok(Some(served))
        }
        async fn sync_shard_tree(&self, _: &[u8], _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
    }

    /// A frame with no certificate of its own is replayed together with the
    /// certified frame after it, which finalized it.
    #[tokio::test]
    async fn archive_replay_hands_an_uncertified_frame_its_certified_child() {
        let replayed = Arc::new(Mutex::new(Vec::new()));
        let seen = replayed.clone();
        let result = replay_shard_from_latest(&BareArchive, &[5; 32], frame(130), 130, None,
            move |frame, child| {
                let height = frame.header.unwrap().frame_number;
                seen.lock().unwrap().push((height, child.into_iter().map(|child| child.header.unwrap().frame_number).collect::<Vec<_>>()));
                async move { Ok(height) }
            }).await.unwrap();
        assert_eq!(result, ShardReplay { materialized: 134, archive_tip: Some(134), target: 134 });
        assert_eq!(*replayed.lock().unwrap(), vec![(131, vec![]), (132, vec![133]), (133, vec![]), (134, vec![])]);
    }

    struct ChainArchive { missing: Option<u64>, wrong_shard: bool, unsigned_end: u64 }

    #[async_trait]
    impl ProverTreeSyncer for ChainArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
        async fn get_app_shard_frame(&self, _: &[u8], number: u64) -> Result<Option<AppShardFrame>> {
            if self.missing == Some(number) { return Ok(None); }
            let mut served = frame(if number == 0 { 200 } else { number });
            if (131..=self.unsigned_end).contains(&number) {
                served.header.as_mut().unwrap().public_key_signature_bls48581 = None;
            }
            if self.wrong_shard && number == 132 { served.header.as_mut().unwrap().address = vec![9; 32]; }
            Ok(Some(served))
        }
        async fn sync_shard_tree(&self, _: &[u8], _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
    }

    #[tokio::test]
    async fn archive_replay_fetches_past_consecutive_unsigned_headers() {
        let archive = ChainArchive { missing: None, wrong_shard: false, unsigned_end: 132 };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let seen = calls.clone();
        let result = replay_shard_from_latest(&archive, &[5; 32], frame(130), 130, None,
            move |frame, descendants| {
                let height = frame.header.unwrap().frame_number;
                seen.lock().unwrap().push((height, descendants.iter()
                    .map(|child| child.header.as_ref().unwrap().frame_number).collect::<Vec<_>>()));
                async move { Ok(height) }
            }).await.unwrap();
        assert_eq!(result.materialized, 162);
        let calls = calls.lock().unwrap();
        assert_eq!(calls[0], (131, vec![132, 133]));
        assert_eq!(calls[1], (132, vec![133]));
        assert_eq!(calls[2], (133, vec![]));
    }

    #[tokio::test]
    async fn archive_replay_never_sends_an_unbounded_missing_or_wrong_shard_chain_to_the_actor() {
        for archive in [
            ChainArchive { missing: None, wrong_shard: false, unsigned_end: 200 },
            ChainArchive { missing: Some(132), wrong_shard: false, unsigned_end: 132 },
            ChainArchive { missing: None, wrong_shard: true, unsigned_end: 132 },
        ] {
            assert!(replay_shard_from_latest(&archive, &[5; 32], frame(130), 130, None,
                |_, _| async { panic!("incomplete chain must not reach replay") }).await.is_err());
        }
    }

    #[tokio::test]
    async fn archive_replay_stops_on_engine_rejection_and_never_skips_the_gap() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(600)), calls: calls.clone() };
        assert!(replay_shard_from_latest(&archive, &[5; 32], frame(130), 129, None,
            |_, _| async { Err(quil_types::error::QuilError::InvalidSignature("rejected certificate".into())) }
        ).await.is_err());
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "fetch 130"]);
    }

    #[tokio::test]
    async fn rejected_archive_chain_never_installs_its_tree() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(600)), calls: calls.clone() };
        let result = sync_shard_from_latest(&archive, &[5; 32], Some(frame(130)), &[], None,
            |_, _| async { Ok(false) }).await.unwrap();
        assert!(matches!(result, ShardSyncResult::NotReady(_)));
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "fetch 599"]);
    }

    /// GLOBAL fenced the shard's last session at 505; its committee had
    /// finalized 506 and 507, which archives still serve as the latest and
    /// validation refuses (past the terminal checkpoint). A member without the
    /// shard's data bootstraps from the frame GLOBAL committed instead.
    #[tokio::test]
    async fn a_refused_archive_tip_falls_back_to_the_committed_frame() {
        let validate = |anchor: AppShardFrame, predecessor: Option<AppShardFrame>| {
            let number = anchor.header.unwrap().frame_number;
            assert_eq!(predecessor.unwrap().header.unwrap().frame_number, number - 1);
            async move { Ok(number <= 505) }
        };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(507)), calls: calls.clone() };
        let result = sync_shard_from_latest(&archive, &[5; 32], None, &[], Some(505), validate).await.unwrap();
        let ShardSyncResult::Anchored { anchor, .. } = result else { panic!("expected the committed frame as the anchor") };
        assert_eq!(anchor.header.unwrap().frame_number, 505);
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "fetch 506", "fetch 505", "fetch 504", "sync 249"]);

        // Without a committed frame below it the refusal stands.
        for committed in [None, Some(0), Some(507)] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let archive = Archive { latest: Some(frame(507)), calls: calls.clone() };
            let result = sync_shard_from_latest(&archive, &[5; 32], None, &[], committed, validate).await.unwrap();
            assert!(matches!(result, ShardSyncResult::NotReady(_)));
            assert_eq!(*calls.lock().unwrap(), ["fetch 0", "fetch 506"]);
        }
    }

    /// A session based at 0 of which GLOBAL executed nothing; the archive's
    /// latest frame (1) is refused. Certified origins pin the base state;
    /// otherwise the refused frame's attested pre-state roots do; with
    /// neither the sync refuses and never takes the archive's subtree
    /// unpinned (the mock panics on an unpinned sync).
    #[tokio::test]
    async fn a_refused_tip_over_an_unexecuted_base_syncs_only_certified_state() {
        let refuse = |_: AppShardFrame, _: Option<AppShardFrame>| async { Ok(false) };

        let anchors = vec![(vec![1; 32], [[0x51; 32]; 4])];
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(1)), calls: calls.clone() };
        let result = sync_shard_from_latest(&archive, &[5; 32], None, &anchors, Some(0), refuse).await.unwrap();
        assert!(matches!(result, ShardSyncResult::Inherited { pinned: true }));
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "sync 81"], "pinned to the origin's sealed roots");

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(1)), calls: calls.clone() };
        let attested = |refused: AppShardFrame| async move {
            assert_eq!(refused.header.unwrap().frame_number, 1);
            Ok(Some(vec![vec![0x22; 32]; 4]))
        };
        let result = sync_shard_from_latest_attested(&archive, &[5; 32], None, &[], Some(0), refuse, attested)
            .await.unwrap();
        assert!(matches!(result, ShardSyncResult::Inherited { pinned: true }));
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "sync 34"], "pinned to the attested pre-state");

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(1)), calls: calls.clone() };
        let result = sync_shard_from_latest_attested(&archive, &[5; 32], None, &[], Some(0), refuse,
            |_| async { Ok(None) }).await.unwrap();
        assert!(matches!(result, ShardSyncResult::NotReady(reason) if reason.contains("nothing certifies")));
        assert_eq!(*calls.lock().unwrap(), ["fetch 0"], "no unpinned sync");

        // A committed frame above 0 keeps its own fallback; nothing is attested.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(507)), calls: calls.clone() };
        let never = |_: AppShardFrame| async { panic!("attested only over an unexecuted base 0") };
        let result = sync_shard_from_latest_attested(&archive, &[5; 32], None, &[], Some(507), refuse, never)
            .await.unwrap();
        assert!(matches!(result, ShardSyncResult::NotReady(_)));
    }

    /// Serves frame 1 as its latest; every pinned tree sync fails (the
    /// archive does not retain that state); an unpinned one panics.
    struct UnretainedArchive {
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl ProverTreeSyncer for UnretainedArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
        async fn get_app_shard_frame(&self, _: &[u8], number: u64) -> Result<Option<AppShardFrame>> {
            self.calls.lock().unwrap().push(format!("fetch {number}"));
            Ok(Some(frame(1)))
        }
        async fn sync_shard_tree(&self, _: &[u8], roots: &[Vec<u8>]) -> Result<bool> {
            self.calls.lock().unwrap().push(format!("sync {}", roots[0][0]));
            Ok(false)
        }
    }

    /// Over an unexecuted base 0, an archive that cannot serve the certified
    /// base state leaves the sync not ready; it never falls back to the
    /// archive's current subtree.
    #[tokio::test]
    async fn an_unretained_base_state_is_never_replaced_by_unpinned_state() {
        let refuse = |_: AppShardFrame, _: Option<AppShardFrame>| async { Ok(false) };
        let anchors = vec![(vec![1; 32], [[0x51; 32]; 4])];
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = UnretainedArchive { calls: calls.clone() };
        let result = sync_shard_from_latest(&archive, &[5; 32], None, &anchors, Some(0), refuse).await.unwrap();
        assert!(matches!(result, ShardSyncResult::NotReady(reason) if reason.contains("certified base state")));
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "sync 81"], "pinned only");

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = UnretainedArchive { calls: calls.clone() };
        let result = sync_shard_from_latest_attested(&archive, &[5; 32], None, &[], Some(0), refuse,
            |_| async { Ok(Some(vec![vec![0x22; 32]; 4])) }).await.unwrap();
        assert!(matches!(result, ShardSyncResult::NotReady(reason) if reason.contains("attested base state")));
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "sync 34"], "pinned only");
    }

    /// Holds no frame of the shard; records each tree sync as
    /// `(filter's first byte, pinned root's first byte or None)` and refuses
    /// the pinned sync of `refuse`.
    struct FramelessArchive {
        calls: Arc<Mutex<Vec<(u8, Option<u8>)>>>,
        refuse: Option<Vec<u8>>,
    }

    #[async_trait]
    impl ProverTreeSyncer for FramelessArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
        async fn get_app_shard_frame(&self, _: &[u8], _: u64) -> Result<Option<AppShardFrame>> { Ok(None) }
        async fn sync_shard_tree(&self, filter: &[u8], roots: &[Vec<u8>]) -> Result<bool> {
            self.calls.lock().unwrap().push((filter[0], roots.first().map(|root| root[0])));
            Ok(roots.is_empty() || self.refuse.as_deref() != Some(filter))
        }
    }

    /// A shard with no frame of its own syncs each origin's range pinned to
    /// its sealed roots, and inherits the covered subtree unpinned only when
    /// it has no certified origin or the archive cannot serve one.
    #[tokio::test]
    async fn a_frameless_shard_syncs_its_origins_pinned_to_their_sealed_roots() {
        let child = vec![5; 32];
        let (left, right) = (vec![1; 32], vec![2; 32]);
        let anchors = vec![(left.clone(), [[0x51; 32]; 4]), (right.clone(), [[0x61; 32]; 4])];
        let never = |_: AppShardFrame, _: Option<AppShardFrame>| async { panic!("no frame to validate") };

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = FramelessArchive { calls: calls.clone(), refuse: None };
        let result = sync_shard_from_latest(&archive, &child, None, &anchors, None, never).await.unwrap();
        assert!(matches!(result, ShardSyncResult::Inherited { pinned: true }));
        assert_eq!(*calls.lock().unwrap(), [(1, Some(0x51)), (2, Some(0x61))], "pinned, never unpinned");

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = FramelessArchive { calls: calls.clone(), refuse: Some(right) };
        let result = sync_shard_from_latest(&archive, &child, None, &anchors, None, never).await.unwrap();
        assert!(matches!(result, ShardSyncResult::Inherited { pinned: false }));
        assert_eq!(*calls.lock().unwrap(), [(1, Some(0x51)), (2, Some(0x61)), (5, None)], "falls back when an origin is unavailable");

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = FramelessArchive { calls: calls.clone(), refuse: None };
        let result = sync_shard_from_latest(&archive, &child, None, &[], None, never).await.unwrap();
        assert!(matches!(result, ShardSyncResult::Inherited { pinned: false }));
        assert_eq!(*calls.lock().unwrap(), [(5, None)], "no certified origin: unpinned");
    }

    /// A successor of a same-filter predecessor must start from exactly the
    /// predecessor's sealed state (`successor_state_matches`). When no archive
    /// serves it, an unpinned copy would be installed, reported as success and
    /// refused at startup, over and over: recovery waits instead.
    #[tokio::test]
    async fn an_unavailable_same_filter_seal_is_never_replaced_by_unpinned_state() {
        let filter = vec![5; 32];
        let anchors = vec![(filter.clone(), [[0x71; 32]; 4])];
        let never = |_: AppShardFrame, _: Option<AppShardFrame>| async { panic!("no frame to validate") };
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = FramelessArchive { calls: calls.clone(), refuse: Some(filter.clone()) };
        let result = sync_shard_from_latest(&archive, &filter, None, &anchors, None, never).await.unwrap();
        assert!(matches!(result, ShardSyncResult::NotReady(_)));
        assert_eq!(*calls.lock().unwrap(), [(5, Some(0x71))], "pinned only");
    }

    /// Serves frames through 140, reports `tip` as its latest (`None`: no
    /// latest frame indexed) and records each request.
    struct BehindArchive {
        tip: Option<u64>,
        calls: Arc<Mutex<Vec<u64>>>,
    }

    #[async_trait]
    impl ProverTreeSyncer for BehindArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
        async fn get_app_shard_frame(&self, _: &[u8], number: u64) -> Result<Option<AppShardFrame>> {
            self.calls.lock().unwrap().push(number);
            Ok(match number {
                0 => self.tip.map(frame),
                n if n <= 140 => Some(frame(n)),
                _ => None,
            })
        }
        async fn sync_shard_tree(&self, _: &[u8], _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
    }

    /// An archive whose latest is at or below the worker's head, or that has
    /// none, is not proof the worker is current: GLOBAL's committed session
    /// tip is the target, the tip is probed on further archives, and frames
    /// are requested by number. Past what any archive holds it stops with the
    /// missing frame named, never reporting the worker up to date.
    #[tokio::test]
    async fn replay_targets_the_committed_tip_when_archives_report_an_old_one() {
        for tip in [Some(130), None] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let archive = BehindArchive { tip, calls: calls.clone() };
            let result = replay_shard_from_latest(&archive, &[5; 32], frame(130), 130, Some(137),
                |frame, _| async move { Ok(frame.header.unwrap().frame_number) }).await.unwrap();
            assert_eq!(result, ShardReplay { materialized: 137, archive_tip: tip, target: 137 });
            assert_eq!(calls.lock().unwrap()[..TIP_PROBES], [0; TIP_PROBES], "the tip is asked of more archives");
        }
        let archive = BehindArchive { tip: Some(130), calls: Arc::new(Mutex::new(Vec::new())) };
        let missing = replay_shard_from_latest(&archive, &[5; 32], frame(130), 130, Some(150),
            |frame, _| async move { Ok(frame.header.unwrap().frame_number) }).await.unwrap_err();
        assert!(missing.to_string().contains("missing shard frame 141"), "{missing}");
    }

    /// Rotate across peer responses even when the local head already covers
    /// GLOBAL. A stale/absent first response must not hide a newer peer head.
    struct RotatingArchive {
        tips: Mutex<std::collections::VecDeque<Option<u64>>>,
        calls: Arc<Mutex<Vec<u64>>>,
    }

    #[async_trait]
    impl ProverTreeSyncer for RotatingArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
        async fn get_app_shard_frame(&self, _: &[u8], number: u64) -> Result<Option<AppShardFrame>> {
            self.calls.lock().unwrap().push(number);
            Ok(if number == 0 { self.tips.lock().unwrap().pop_front().flatten().map(frame) }
                else { Some(frame(number)) })
        }
        async fn sync_shard_tree(&self, _: &[u8], _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
    }

    #[tokio::test]
    async fn replay_probes_past_stale_peer_when_local_head_covers_global() {
        for first in [Some(83), None] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let archive = RotatingArchive { tips: Mutex::new([first, Some(134)].into()), calls: calls.clone() };
            let replayed = Arc::new(Mutex::new(Vec::new()));
            let installed = replayed.clone();
            let result = replay_shard_from_latest(&archive, &[5; 32], frame(130), 130, Some(127),
                move |frame, _| {
                    let height = frame.header.unwrap().frame_number;
                    installed.lock().unwrap().push(height);
                    async move { Ok(height) }
                }).await.unwrap();
            assert_eq!(result, ShardReplay { materialized: 134, archive_tip: Some(134), target: 134 });
            assert_eq!(*replayed.lock().unwrap(), [131, 132, 133, 134]);
            assert_eq!(*calls.lock().unwrap(), [0, 0, 131, 132, 133]);
        }
    }

    #[tokio::test]
    async fn replay_tip_rotation_is_bounded_and_stops_at_a_current_peer() {
        for (tips, expected_calls, expected_tip) in [
            (vec![Some(83); TIP_PROBES + 1], TIP_PROBES, 83),
            (vec![Some(130), Some(134)], 1, 130),
        ] {
            let calls = Arc::new(Mutex::new(Vec::new()));
            let archive = RotatingArchive { tips: Mutex::new(tips.into()), calls: calls.clone() };
            let result = replay_shard_from_latest(&archive, &[5; 32], frame(130), 130, Some(127),
                |_, _| async { panic!("already materialized through the known target") }).await.unwrap();
            assert_eq!(result, ShardReplay { materialized: 130, archive_tip: Some(expected_tip), target: 130 });
            assert_eq!(*calls.lock().unwrap(), vec![0; expected_calls]);
        }
    }

    /// A worker that owes a re-anchor at `fence`, with GLOBAL's committed
    /// frame `committed`; validates frames through `valid_through`.
    struct Reanchoring {
        calls: Arc<Mutex<Vec<String>>>,
        fence: Option<u64>,
        committed: Option<u64>,
        valid_through: u64,
        install_fails: bool,
        elsewhere: bool,
        failures: Mutex<Vec<String>>,
    }

    impl Reanchoring {
        fn new(calls: &Arc<Mutex<Vec<String>>>, fence: Option<u64>, committed: Option<u64>) -> Self {
            Self {
                calls: calls.clone(), fence, committed, valid_through: 505, install_fails: false,
                elsewhere: false, failures: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl ShardRecoveryTarget for Reanchoring {
        fn materialized(&self) -> u64 { 507 }
        async fn replay(&self, frame: AppShardFrame, _: Vec<AppShardFrame>) -> Result<u64> {
            let number = frame.header.unwrap().frame_number;
            self.calls.lock().unwrap().push(format!("replay {number}"));
            Ok(number)
        }
        async fn validate(&self, anchor: AppShardFrame, predecessor: Option<AppShardFrame>) -> Result<bool> {
            let number = anchor.header.unwrap().frame_number;
            assert_eq!(predecessor.unwrap().header.unwrap().frame_number, number - 1);
            self.calls.lock().unwrap().push(format!("validate {number}"));
            Ok(number <= self.valid_through)
        }
        async fn install(&self, anchor: AppShardFrame, _: Option<AppShardFrame>) -> Result<()> {
            self.calls.lock().unwrap().push(format!("install {}", anchor.header.unwrap().frame_number));
            if self.install_fails {
                return Err(quil_types::error::QuilError::ExecutionUnavailable("shard engine rejected sync completion".into()));
            }
            Ok(())
        }
        fn inherited(&self) { panic!("a re-anchor never inherits unpinned state") }
        async fn committed_tip(&self) -> Option<u64> { self.committed }
        async fn reanchor_fence(&self) -> ReanchorAttempt {
            match self.fence {
                Some(_) if self.elsewhere => ReanchorAttempt::Elsewhere,
                Some(fence) => ReanchorAttempt::Take(fence),
                None => ReanchorAttempt::NotOwed,
            }
        }
        fn reanchor_failed(&self, reason: String) { self.failures.lock().unwrap().push(reason); }
    }

    /// GLOBAL fenced the shard's last session at 505; this worker installed
    /// the archive's 507, a frame the fence discarded. It owes a re-anchor:
    /// its lineage is not replayed, and it anchors at the frame GLOBAL
    /// committed (the fence), authenticated, with its trees pinned to that
    /// frame's roots, before the actor installs it. Without a re-anchor the
    /// same worker replays its lineage, as before.
    #[tokio::test]
    async fn a_head_past_the_fence_is_reanchored_at_the_committed_frame_not_replayed() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(507)), calls: calls.clone() };
        let target = Reanchoring::new(&calls, Some(505), Some(505));
        let result = recover_shard_from_latest(&archive, &[5; 32], Some(frame(507)), &target, None).await.unwrap();
        assert_eq!(result, ShardRecoveryProgress::Anchored { frame: 505 });
        assert_eq!(*calls.lock().unwrap(), ["fetch 505", "fetch 504", "validate 505", "sync 249", "install 505"]);
        assert!(target.failures.lock().unwrap().is_empty());

        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(507)), calls: calls.clone() };
        let target = Reanchoring::new(&calls, None, Some(505));
        let result = recover_shard_from_latest(&archive, &[5; 32], Some(frame(507)), &target, None).await.unwrap();
        assert!(matches!(result, ShardRecoveryProgress::Replayed { .. }), "{result:?}");
        assert!(calls.lock().unwrap().iter().all(|call| call.starts_with("fetch 0")), "{:?}", calls.lock().unwrap());
    }

    /// A re-anchor owed after a persistent replay mismatch records the
    /// cursor as its fence, below the frame GLOBAL committed: it anchors at
    /// that frame, with the trees pinned to its roots, not at the fence.
    #[tokio::test]
    async fn a_reanchor_below_the_committed_frame_anchors_at_it() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(507)), calls: calls.clone() };
        let target = Reanchoring::new(&calls, Some(500), Some(505));
        let result = recover_shard_from_latest(&archive, &[5; 32], Some(frame(500)), &target, None).await.unwrap();
        assert_eq!(result, ShardRecoveryProgress::Anchored { frame: 505 });
        assert_eq!(*calls.lock().unwrap(), ["fetch 505", "fetch 504", "validate 505", "sync 249", "install 505"]);
    }

    /// Serves certified frames, but its tree sync never reaches their roots.
    struct StatelessArchive {
        calls: Arc<Mutex<Vec<String>>>,
    }

    #[async_trait]
    impl ProverTreeSyncer for StatelessArchive {
        async fn sync_prover_tree(&self, _: &[Vec<u8>]) -> Result<bool> { unreachable!() }
        async fn get_app_shard_frame(&self, _: &[u8], number: u64) -> Result<Option<AppShardFrame>> {
            self.calls.lock().unwrap().push(format!("fetch {number}"));
            Ok(Some(frame(number)))
        }
        async fn sync_shard_tree(&self, _: &[u8], roots: &[Vec<u8>]) -> Result<bool> {
            self.calls.lock().unwrap().push(format!("sync {}", roots.first().map_or(0, |root| root[0])));
            Ok(false)
        }
    }

    /// A re-anchor that no archive can serve, or whose frame fails
    /// validation, installs nothing, never syncs unpinned (the shard holds
    /// data, and its successor refuses anything but the committed state),
    /// and tells the actor why.
    #[tokio::test]
    async fn a_reanchor_waits_for_an_archive_rather_than_inherit_unpinned_state() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let frameless = FramelessArchive { calls: Arc::new(Mutex::new(Vec::new())), refuse: None };
        let target = Reanchoring::new(&calls, Some(505), Some(505));
        let result = recover_shard_from_latest(&frameless, &[5; 32], Some(frame(507)), &target, None).await.unwrap();
        assert_eq!(result, ShardRecoveryProgress::NotReady(REANCHOR_UNAVAILABLE));
        assert!(frameless.calls.lock().unwrap().is_empty(), "no tree sync at all");
        assert_eq!(*target.failures.lock().unwrap(), [REANCHOR_UNAVAILABLE]);

        let calls = Arc::new(Mutex::new(Vec::new()));
        let stateless = StatelessArchive { calls: calls.clone() };
        let target = Reanchoring::new(&calls, Some(505), Some(505));
        let result = recover_shard_from_latest(&stateless, &[5; 32], Some(frame(507)), &target, None).await.unwrap();
        assert_eq!(result, ShardRecoveryProgress::NotReady(REANCHOR_UNAVAILABLE));
        assert_eq!(*calls.lock().unwrap(), ["fetch 505", "fetch 504", "validate 505", "sync 249"], "never installed");
        assert_eq!(*target.failures.lock().unwrap(), [REANCHOR_UNAVAILABLE]);

        let calls = Arc::new(Mutex::new(Vec::new()));
        let stateless = StatelessArchive { calls: calls.clone() };
        let mut target = Reanchoring::new(&calls, Some(505), Some(505));
        target.valid_through = 504;
        let result = recover_shard_from_latest(&stateless, &[5; 32], Some(frame(507)), &target, None).await.unwrap();
        assert_eq!(result, ShardRecoveryProgress::NotReady(REANCHOR_REFUSED));
        assert_eq!(*calls.lock().unwrap(), ["fetch 505", "fetch 504", "validate 505"], "no tree write");
        assert_eq!(*target.failures.lock().unwrap(), [REANCHOR_REFUSED]);

        let calls = Arc::new(Mutex::new(Vec::new()));
        let stateless = StatelessArchive { calls: calls.clone() };
        let target = Reanchoring::new(&calls, Some(505), None);
        let result = recover_shard_from_latest(&stateless, &[5; 32], Some(frame(507)), &target, None).await.unwrap();
        assert_eq!(result, ShardRecoveryProgress::NotReady(REANCHOR_NO_TIP));
        assert!(calls.lock().unwrap().is_empty(), "nothing asked of an archive");
        assert_eq!(*target.failures.lock().unwrap(), [REANCHOR_NO_TIP]);

        // A step on this node that fails says so, for the warning's scope.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(507)), calls: calls.clone() };
        let mut target = Reanchoring::new(&calls, Some(505), Some(505));
        target.install_fails = true;
        assert!(recover_shard_from_latest(&archive, &[5; 32], Some(frame(507)), &target, None).await.is_err());
        let failures = target.failures.lock().unwrap();
        assert!(failures.len() == 1 && failures[0].contains("re-anchor installation on this node: "), "{failures:?}");
        drop(failures);

        // A sync that is not the attempt's touches nothing, lineage or not,
        // and is no failure of the re-anchor.
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: Some(frame(507)), calls: calls.clone() };
        let mut target = Reanchoring::new(&calls, Some(505), Some(505));
        target.elsewhere = true;
        for local in [Some(frame(507)), None] {
            let result = recover_shard_from_latest(&archive, &[5; 32], local, &target, None).await.unwrap();
            assert_eq!(result, ShardRecoveryProgress::Deferred(REANCHOR_ELSEWHERE));
        }
        assert!(calls.lock().unwrap().is_empty(), "{:?}", calls.lock().unwrap());
        assert!(target.failures.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn missing_peer_tip_does_not_turn_an_existing_worker_into_unanchored_bootstrap() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let archive = Archive { latest: None, calls: calls.clone() };
        let result = sync_shard_from_latest(&archive, &[5; 32], Some(frame(130)), &[], None,
            |anchor, predecessor| async move {
                assert_eq!(anchor.header.unwrap().frame_number, 130);
                assert_eq!(predecessor.unwrap().header.unwrap().frame_number, 129);
                Ok(false)
            }).await.unwrap();
        assert!(matches!(result, ShardSyncResult::NotReady(_)));
        assert_eq!(*calls.lock().unwrap(), ["fetch 0", "fetch 129"]);

        // A malformed source must be refused even if the supplied validator
        // would accept; no forest call can be made without four exact roots.
        let mut malformed = frame(600);
        malformed.header.as_mut().unwrap().state_roots[0].pop();
        let archive = Archive { latest: Some(malformed), calls: calls.clone() };
        assert!(sync_shard_from_latest(&archive, &[5; 32], None, &[], None,
            |_, _| async { panic!("malformed anchor reached validator") }).await.is_err());
        assert_eq!(calls.lock().unwrap().last().unwrap(), "fetch 0");
    }
}
