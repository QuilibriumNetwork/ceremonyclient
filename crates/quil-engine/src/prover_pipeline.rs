//! End-to-end submission pipeline for prover lifecycle actions.
//!
//! The lifecycle evaluator produces abstract `LifecycleAction`s; this
//! module turns them into signed canonical-bytes messages wrapped in a
//! `MessageBundle` and submits them via a pluggable
//! [`ProverMessageTransport`] (gRPC fan-out + BlossomSub in production,
//! a single in-memory broadcast in tests).
//!
//! Mirrors Go's `publishProverMessage` at
//! `node/consensus/global/global_consensus_engine.go:154-159`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use tracing::{debug, info, warn};

use quil_execution::global_intrinsic::{
    addressed_signature::AddressedSignature,
    prover_filter_ops::ProverLeave,
    prover_join::ProverJoin,
    prover_ops::{ProverConfirm, ProverReject, ProverSeniorityMerge, ShardMerge, ShardSplit},
    sig_with_pop::SignatureWithPop,
};
use quil_execution::message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest};
use quil_types::crypto::{FrameProver, Signer};
use quil_types::error::{QuilError, Result};

use crate::provers::lifecycle::{LifecycleAction, ProverLifecycle};
use crate::worker::WorkerManager;
use crate::prover_message_transport::ProverMessageTransport;
use crate::message_collector::{MessageCollector, SubmitOutcome};
use crate::current_frame::CurrentFrame;

/// End-to-end submission pipeline for prover lifecycle actions.
///
/// Owns no transport details — the caller injects an
/// [`Arc<dyn ProverMessageTransport>`] that knows how to ship a
/// `CanonicalMessageBundle` on `GLOBAL_PROVER` (production: gRPC
/// fan-out + BlossomSub; tests: in-memory network).
pub struct ProverPipeline {
    pub lifecycle: Arc<ProverLifecycle>,
    pub worker_manager: Arc<dyn WorkerManager>,
    pub frame_prover: Arc<dyn FrameProver>,
    pub key_manager: Arc<dyn quil_keys::KeyManager + Send + Sync>,
    pub bls_pubkey: Vec<u8>,
    pub prover_address: [u8; 32],
    /// Ed448 seeds loaded from `config.engine.multisig_prover_enrollment_paths`
    /// plus the local peer's own Ed448 seed, used to build merge
    /// helpers for `ProverSeniorityMerge`. Each seed signs the local
    /// BLS prover pubkey with the `PROVER_SENIORITY_MERGE` domain so
    /// on-chain materialization can attribute historical seniority
    /// from the old peer keys.
    pub multisig_ed448_seeds: Vec<[u8; 57]>,
    /// Optional delegate address for ProverJoin emissions. Mirrors Go's
    /// `config.Engine.DelegateAddress` at
    /// `node/consensus/global/worker_allocator.go:1483-1490` —
    /// hex-decoded when set, empty `Vec::new()` when unset. Empty is
    /// the default and is functionally equivalent to "delegate ==
    /// prover_address" inside the materializer (the join handler
    /// substitutes `prover_address` when `len(DelegateAddress) != 32`),
    /// but the canonical-bytes wire form differs — preserve byte-level
    /// parity with default Go nodes by leaving this empty unless the
    /// operator explicitly configured a delegate.
    pub delegate_address: Vec<u8>,
    /// Transport used to ship outbound `MessageBundle` bytes on
    /// `GLOBAL_PROVER` and to fetch the latest frame header for VDF
    /// challenge derivation in [`Self::submit_join`].
    pub transport: Arc<dyn ProverMessageTransport>,
    /// Live hypergraph CRDT — read by the storage-attestation confirm hook
    /// (`submit_confirm`) to partition each confirmed shard's committed
    /// subtree into PoRep leaves. Required for data-shard confirmations.
    pub hypergraph: Option<Arc<quil_hypergraph::HypergraphCrdt>>,
    /// Replica store the confirm hook persists per-leaf SDR replicas into
    /// (keyed by `(epoch, leaf_id)`), so the per-frame producer can later
    /// answer openings. Required for data-shard confirmations.
    pub replica_store: Option<quil_store::replica_store::ReplicaStore>,
    /// Per-shard storage: the hypergraph and replica store of the worker that
    /// holds and attests a shard, when it is not the node's own (a thread
    /// worker opens its own database). Confirmation must encode the same data
    /// into the same replica store the attesting worker proves from, or the
    /// registered leaf roots diverge from its attestations once the shard's
    /// data changes and every storage frame is rejected.
    pub storage_for_filter: Option<std::sync::Arc<
        dyn Fn(&[u8]) -> Option<(std::sync::Arc<quil_hypergraph::HypergraphCrdt>, quil_store::replica_store::ReplicaStore)>
            + Send + Sync,
    >>,
    /// Leaf roots prepared by the standalone (cluster-mode) worker serving a
    /// filter, from its own store: `Ok(None)` when no such worker serves it.
    /// Called from a blocking task, with the time the worker may take.
    /// Without it the master encoded from its own store, which lacks the
    /// shard's data, and the worker's attestations were rejected for leaves
    /// it could never prove.
    pub remote_storage_confirm: Option<RemoteStorageConfirm>,
    /// Splits and merges this node has recorded but not applied. A confirm in
    /// the epoch before one applies also registers the shards it creates from
    /// the confirmed ones (see `pre_registration_targets`).
    pub pending_shard_changes: Option<std::sync::Arc<
        dyn Fn() -> Vec<quil_types::store::PendingShardChange> + Send + Sync,
    >>,
    /// Local global-message collector, for LOOPBACK of ops this node generates
    /// for ITSELF (ShardSplit/ShardMerge from the coverage orchestrator, which
    /// runs on the frame producer). A producer must include its own generated op
    /// in the frame it builds; the network publish only reaches OTHER nodes, so
    /// on a single-archive network (no other archive to accept, gossipsub won't
    /// self-loopback) the op would otherwise never land. Loop it into the same
    /// collector the gRPC/gossip ingest feeds. `None` disables loopback (tests).
    pub local_message_collector: Option<Arc<MessageCollector>>,
    /// Current-frame tracker, used to tag looped-back ops with the CONSENSUS RANK
    /// (`effective_rank()`) exactly as the gRPC ingest does (grpc.rs:400) so the
    /// leader's `collect_for_rank` picks them up. `None` disables loopback.
    pub current_frame: Option<Arc<CurrentFrame>>,
}

pub type RemoteStorageConfirm = std::sync::Arc<
    dyn Fn(&[u8], &[Vec<u8>], u64, std::time::Duration) -> Result<Option<Vec<quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots>>>
        + Send + Sync,
>;

/// Hard ceiling on lifecycle submissions that do NOT perform VDF
/// compute (confirms, rejects, leaves, seniority merge). Each of
/// these is sign + canonicalize + publish; the only legitimately
/// slow piece is the gRPC fan-out, which has its own per-archive
/// timeout in the transport. 30s is well above the worst case but
/// bounds the spawned task so a transport bug, runtime starvation,
/// or stuck publish can't silently wedge a dispatch forever.
const NON_VDF_SUBMIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// What a confirm encodes, per confirmed filter: the filter, from its own
/// storage, then the shards a split or merge applying at `epoch` creates from
/// it (see `pre_registration_targets`). A merge target two confirmed sources
/// share is encoded once, from the first.
fn confirm_encoding_plan(
    filters: &[Vec<u8>],
    changes: &[quil_types::store::PendingShardChange],
    epoch: u64,
) -> Vec<(Vec<u8>, Vec<Vec<u8>>)> {
    let mut claimed: Vec<Vec<u8>> = filters.to_vec();
    filters
        .iter()
        .map(|filter| {
            let targets: Vec<Vec<u8>> = if filter.is_empty() {
                Vec::new()
            } else {
                quil_execution::global_intrinsic::leaf_root_registration::pre_registration_targets(
                    changes,
                    std::slice::from_ref(filter),
                    epoch,
                )
                .into_iter()
                .filter(|target| !claimed.contains(target))
                .collect()
            };
            claimed.extend(targets.iter().cloned());
            (filter.clone(), targets)
        })
        .collect()
}

type LeafRoots = Vec<quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots>;

/// One filter's confirm preparation: its leaf roots, or why the standalone
/// worker that serves it did not prepare them, with its error.
enum Prepared {
    Roots(LeafRoots),
    Unanswered(LeftOutCause, QuilError),
}

/// Why a confirm leaves a seat out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum LeftOutCause {
    /// Its worker failed: unreachable, refused, or another error.
    Failed,
    /// Its worker was asked and had not answered by the round's deadline.
    Late,
    /// The round's deadline passed before its worker was asked.
    Unasked,
    /// Its worker's answer omitted or repeated a shard it was asked for.
    Incomplete,
    /// It pre-registers a shard a left-out seat was to encode.
    MergeTarget,
}

impl LeftOutCause {
    fn name(self) -> &'static str {
        match self {
            Self::Failed => "failed",
            Self::Late => "late",
            Self::Unasked => "unasked",
            Self::Incomplete => "incomplete",
            Self::MergeTarget => "merge target",
        }
    }
}

/// A seat a confirm leaves out, with why; retried on the next cycle.
struct LeftOutSeat {
    filter: Vec<u8>,
    /// Shards this seat was to pre-register for the confirm.
    targets: Vec<Vec<u8>>,
    cause: LeftOutCause,
    error: QuilError,
}

/// What a confirm submits: the filters whose storage was prepared and their
/// leaf roots, in the order requested, and the seats it leaves out.
struct PreparedConfirm {
    filters: Vec<Vec<u8>>,
    roots: LeafRoots,
    left_out: Vec<LeftOutSeat>,
}

impl PreparedConfirm {
    /// Release the left-out seats' reservations so the next cycle retries
    /// them; the submitted seats stay reserved until published.
    fn release_left_out(&self, attempt: &mut crate::submission_attempts::SubmissionAttempt) {
        let left_out: Vec<Vec<u8>> = self.left_out.iter().map(|seat| seat.filter.clone()).collect();
        attempt.release(&left_out);
    }
}

/// Prepare a confirm of `filters` along `confirm_encoding_plan`. A seat whose
/// standalone worker does not answer is left out, so the seats whose workers
/// answer are confirmed instead of all failing together; it is retried on the
/// next cycle. A seat that was to encode a shard a left-out seat had claimed
/// (a shared merge target) is left out with it, so every submitted seat
/// registers the shards a change creates from it, as a full confirm does.
/// When no seat is left, the first worker error aborts the confirm, as does
/// any other preparation error.
fn prepare_confirm<F>(
    filters: &[Vec<u8>],
    changes: &[quil_types::store::PendingShardChange],
    epoch: u64,
    mut prepare: F,
) -> Result<PreparedConfirm>
where
    F: FnMut(&[u8], &[Vec<u8>]) -> Result<Prepared>,
{
    let mut prepared: Vec<(Vec<u8>, Vec<Vec<u8>>, LeafRoots)> = Vec::with_capacity(filters.len());
    let mut left_out: Vec<LeftOutSeat> = Vec::new();
    for (filter, targets) in confirm_encoding_plan(filters, changes, epoch) {
        match prepare(&filter, &targets)? {
            Prepared::Roots(roots) => prepared.push((filter, targets, roots)),
            Prepared::Unanswered(cause, error) => left_out.push(LeftOutSeat { filter, targets, cause, error }),
        }
    }
    // A shard claimed by a left-out seat is encoded by no submitted seat.
    loop {
        let orphaned: Vec<&Vec<u8>> = left_out.iter().flat_map(|seat| seat.targets.iter()).collect();
        let Some(position) = prepared.iter().position(|(filter, targets, _)| {
            quil_execution::global_intrinsic::leaf_root_registration::pre_registration_targets(
                changes,
                std::slice::from_ref(filter),
                epoch,
            )
            .iter()
            .any(|target| orphaned.contains(&target) && !targets.contains(target))
        }) else {
            break;
        };
        let (filter, targets, _) = prepared.remove(position);
        left_out.push(LeftOutSeat {
            filter,
            targets,
            cause: LeftOutCause::MergeTarget,
            error: QuilError::ExecutionUnavailable(
                "a shard it pre-registers was to be encoded by a left-out seat".into(),
            ),
        });
    }
    if prepared.is_empty() && !left_out.is_empty() {
        return Err(left_out.remove(0).error);
    }
    let mut confirm = PreparedConfirm { filters: Vec::with_capacity(prepared.len()), roots: Vec::new(), left_out };
    for (filter, _, roots) in prepared {
        confirm.filters.push(filter);
        confirm.roots.extend(roots);
    }
    Ok(confirm)
}

/// Standalone workers asked at once for their seats' leaf roots.
const REMOTE_PREPARATIONS: usize = 8;

/// How long one standalone worker may take to encode its seat's replicas and
/// answer: encoding a large shard is slow.
const REMOTE_PREPARATION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(600);

/// The share of an epoch one confirm's round of standalone-worker
/// preparations may take. A seat's renewal is due from its epoch's first
/// frame and lapses at the next boundary. Without a deadline each worker that
/// never answers held the round for its whole timeout, eight at a time, while
/// the round kept an encoder permit: 40 such workers held it for 50 minutes
/// of a two-hour mainnet epoch (720 frames of `IDEAL_FRAME_TIME`). A sixth of
/// an epoch, 20 minutes on mainnet, still gives a worker asked in the round's
/// first half its full timeout, and leaves five more rounds in the epoch for
/// the seats a round leaves out.
const REMOTE_ROUND_EPOCH_SHARE: u64 = 6;

/// When a round of standalone-worker preparations starting now must end.
fn remote_round_deadline() -> std::time::Instant {
    let epoch_ms = quil_types::consensus::epoch_length_frames()
        .saturating_mul(crate::difficulty::IDEAL_FRAME_TIME as u64);
    std::time::Instant::now() + std::time::Duration::from_millis(epoch_ms / REMOTE_ROUND_EPOCH_SHARE)
}

/// A standalone worker's answer for a seat: its leaf roots, `None` when no
/// standalone worker runs the seat, or why it gave none.
type RemoteAnswer = std::result::Result<Option<LeafRoots>, (LeftOutCause, QuilError)>;

/// Ask the standalone workers for their seats' leaf roots, `parallel` at a
/// time, keyed by filter, until `deadline`. Each answer may take up to the
/// worker's timeout, and a worker that does not answer must not hold up those
/// that do. Each worker encodes only its own shard, so the queries are
/// independent. A worker is given at most the time left before `deadline`:
/// one that has not answered by then is late, and a seat whose turn comes
/// after the deadline is not asked, so the round ends by it.
fn query_remote_workers<F>(
    requests: &[(Vec<u8>, Vec<Vec<u8>>)],
    parallel: usize,
    deadline: std::time::Instant,
    query: F,
) -> HashMap<Vec<u8>, RemoteAnswer>
where
    F: Fn(&[u8], &[Vec<u8>], std::time::Duration) -> Result<Option<LeafRoots>> + Sync,
{
    if requests.is_empty() {
        return HashMap::new();
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let answers = Mutex::new(HashMap::with_capacity(requests.len()));
    let threads = parallel.max(1).min(requests.len());
    std::thread::scope(|scope| {
        for _ in 0..threads {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some((filter, targets)) = requests.get(index) else { break };
                let timeout = deadline
                    .saturating_duration_since(std::time::Instant::now())
                    .min(REMOTE_PREPARATION_TIMEOUT);
                let answer = if timeout.is_zero() {
                    Err((
                        LeftOutCause::Unasked,
                        QuilError::ExecutionUnavailable("not asked before the confirm round's deadline".into()),
                    ))
                } else {
                    let asked = std::time::Instant::now();
                    query(filter, targets, timeout).map_err(|error| {
                        let cause = if asked.elapsed() >= timeout { LeftOutCause::Late } else { LeftOutCause::Failed };
                        (cause, error)
                    })
                };
                answers.lock().unwrap_or_else(|e| e.into_inner()).insert(filter.clone(), answer);
            });
        }
    });
    answers.into_inner().unwrap_or_else(|e| e.into_inner())
}

/// Seats whose standalone workers were asked and had not answered by their
/// round's deadline. The next round asks them after the others, so workers
/// that never answer cannot fill every slot of each round while the seats
/// planned after them go unasked. Holds only this node's own seats.
#[derive(Default)]
struct LateSeats(Mutex<std::collections::HashSet<Vec<u8>>>);

impl LateSeats {
    /// Order `requests` with the late seats last, otherwise as planned.
    fn ask_last(&self, requests: &mut [(Vec<u8>, Vec<Vec<u8>>)]) {
        let late = self.0.lock().unwrap_or_else(|e| e.into_inner());
        requests.sort_by_key(|(filter, _)| late.contains(filter));
    }

    /// Record the round's `answers`: a seat asked and late is late, one that
    /// answered or failed in time is not; an unasked seat keeps its place.
    fn record(&self, answers: &HashMap<Vec<u8>, RemoteAnswer>) {
        let mut late = self.0.lock().unwrap_or_else(|e| e.into_inner());
        for (filter, answer) in answers {
            match answer {
                Err((LeftOutCause::Late, _)) => {
                    late.insert(filter.clone());
                }
                Err((LeftOutCause::Unasked, _)) => {}
                _ => {
                    late.remove(filter);
                }
            }
        }
    }
}

fn late_seats() -> &'static LateSeats {
    static LATE: OnceLock<LateSeats> = OnceLock::new();
    LATE.get_or_init(LateSeats::default)
}

/// Whether `roots` hold exactly one group for `filter` and one for each of
/// `targets`, and none for another shard: the worker encoded every shard the
/// seat registers, so the confirm registers the shards a pending change
/// creates from it.
fn answers_every_requested_shard(filter: &[u8], targets: &[Vec<u8>], roots: &LeafRoots) -> bool {
    roots.len() == 1 + targets.len()
        && std::iter::once(filter)
            .chain(targets.iter().map(Vec::as_slice))
            .all(|shard| roots.iter().filter(|group| group.filter == shard).count() == 1)
}

/// A standalone worker's answer as the preparation of the seat `filter`,
/// asked to encode `targets` too: its leaf roots when they cover every shard
/// asked for, or why the seat is left out; `None` when no standalone worker
/// runs the seat, which the master then encodes from its own store.
fn remote_answer(filter: &[u8], targets: &[Vec<u8>], answer: RemoteAnswer) -> Option<Prepared> {
    match answer {
        Ok(Some(roots)) if answers_every_requested_shard(filter, targets, &roots) => Some(Prepared::Roots(roots)),
        Ok(Some(roots)) => Some(Prepared::Unanswered(
            LeftOutCause::Incomplete,
            QuilError::ExecutionUnavailable(format!(
                "worker answered {} leaf-root groups, not one for its shard and each of its {} targets",
                roots.len(),
                targets.len(),
            )),
        )),
        Ok(None) => None,
        Err((cause, error)) => Some(Prepared::Unanswered(cause, error)),
    }
}

/// How many left-out seats each cause accounts for, e.g. `failed 2, late 1`.
fn left_out_causes(left_out: &[LeftOutSeat]) -> String {
    let mut counts: std::collections::BTreeMap<LeftOutCause, usize> = Default::default();
    for seat in left_out {
        *counts.entry(seat.cause).or_default() += 1;
    }
    counts.into_iter().map(|(cause, count)| format!("{} {count}", cause.name())).collect::<Vec<_>>().join(", ")
}

/// The distinct errors of left-out seats with their counts, most frequent
/// first, at most three.
fn left_out_errors(left_out: &[LeftOutSeat]) -> String {
    let mut counts: Vec<(String, usize)> = Vec::new();
    for seat in left_out {
        let error = seat.error.to_string();
        match counts.iter_mut().find(|(seen, _)| *seen == error) {
            Some((_, count)) => *count += 1,
            None => counts.push((error, 1)),
        }
    }
    counts.sort_by(|a, b| b.1.cmp(&a.1));
    let more = counts.len().saturating_sub(3);
    let mut summary: Vec<String> = counts.into_iter().take(3).map(|(error, count)| format!("{error} ({count})")).collect();
    if more > 0 {
        summary.push(format!("{more} more"));
    }
    summary.join("; ")
}

/// A seniority-merge target GLOBAL already consumed: a join or seniority
/// merge stamped its spent marker, and GLOBAL refuses every later seniority
/// merge naming it, whoever submits it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConsumedMergeTarget {
    /// The target's Ed448 public key.
    pubkey: Vec<u8>,
    /// The merge that consumed it: `join merge` or `seniority merge`.
    marker: &'static str,
    /// The prover the marker credits, when it names one.
    credited: Option<Vec<u8>>,
}

/// Read a spent marker from the node's committed GLOBAL state.
fn spent_marker(
    crdt: &Arc<quil_hypergraph::HypergraphCrdt>,
    address: &[u8; 32],
) -> Result<Option<Vec<u8>>> {
    let va_disc = quil_execution::hypergraph_state::vertex_adds_discriminator()?;
    quil_execution::hypergraph_state::HypergraphState::new(crdt.clone()).get(
        &quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS[..],
        address,
        &va_disc,
    )
}

/// Build the `ProverSeniorityMerge` of `seeds` at `frame_number`, leaving out
/// the targets whose join- or seniority-merge spent marker `lookup` finds:
/// GLOBAL refuses those forever (`verify_prover_seniority_merge_spent_markers`).
/// Each target signs the prover key on its own, so the others still form a
/// valid merge; `None` when no target is left.
fn seniority_merge<F>(
    frame_number: u64,
    seeds: &[[u8; 57]],
    bls_pubkey: &[u8],
    prover_address: &[u8; 32],
    bls_signer: &dyn Signer,
    mut lookup: F,
) -> Result<(Option<ProverSeniorityMerge>, Vec<ConsumedMergeTarget>)>
where
    F: FnMut(&[u8; 32]) -> Result<Option<Vec<u8>>>,
{
    use quil_execution::global_intrinsic::materialize::{
        spent_join_merge_address, spent_seniority_merge_address,
    };
    let merge_domain_tag: &[u8] = b"PROVER_SENIORITY_MERGE";

    // Build one SeniorityMerge record per helper seed GLOBAL can still credit.
    let mut merge_targets: Vec<quil_execution::global_intrinsic::SeniorityMerge> =
        Vec::with_capacity(seeds.len());
    let mut consumed = Vec::new();
    'seeds: for seed in seeds {
        let helper_pubkey = quil_p2p::ed448_identity::derive_public_key(seed);
        for (marker, spent) in [
            ("join merge", spent_join_merge_address(&helper_pubkey)?),
            ("seniority merge", spent_seniority_merge_address(&helper_pubkey)?),
        ] {
            if let Some(blob) = lookup(&spent)? {
                let tree = quil_execution::prover_registry::rebuild_vertex_tree_from_blob(&blob);
                let credited = quil_execution::global_schema::read_field(&tree, "merge:SpentMerge", "ProverAddress")
                    .filter(|address| address.len() == 32);
                consumed.push(ConsumedMergeTarget { pubkey: helper_pubkey, marker, credited });
                continue 'seeds;
            }
        }
        let helper_signer = quil_crypto::Ed448Signer::from_bytes(seed, &helper_pubkey)?;
        let helper_sig = <quil_crypto::Ed448Signer as Signer>::sign_with_domain(
            &helper_signer,
            bls_pubkey,
            merge_domain_tag,
        )?;

        merge_targets.push(quil_execution::global_intrinsic::SeniorityMerge {
            signature: helper_sig,
            key_type: quil_types::crypto::KeyType::Ed448 as u32,
            prover_public_key: helper_pubkey,
        });
    }
    if merge_targets.is_empty() {
        return Ok((None, consumed));
    }

    // BLS-sign `frame_be || helper_pubkeys_concat` under the
    // PROVER_SENIORITY_MERGE domain.
    let mut message: Vec<u8> = Vec::with_capacity(8 + merge_targets.len() * 57);
    message.extend_from_slice(&frame_number.to_be_bytes());
    for mt in &merge_targets {
        message.extend_from_slice(&mt.prover_public_key);
    }
    let domain = ProverPipeline::domain(merge_domain_tag)?;
    let bls_sig = bls_signer.sign_with_domain(&message, &domain)?;

    let merge = ProverSeniorityMerge {
        frame_number,
        public_key_signature_bls48581: Some(AddressedSignature {
            signature: bls_sig,
            address: prover_address.to_vec(),
        }),
        merge_targets,
    };
    Ok((Some(merge), consumed))
}

/// The last 6 characters of an identifier, as logs name peers and provers.
fn tail(id: &str) -> &str {
    &id[id.len().saturating_sub(6)..]
}

/// Whom a consumed target's seniority went to, and what the operator can do
/// about it: nothing when it went to this prover.
fn consumed_target_credit(target: &ConsumedMergeTarget, own: &[u8; 32]) -> (String, Option<&'static str>) {
    match &target.credited {
        Some(address) if address.as_slice() == own => ("this prover".into(), None),
        Some(address) => (
            format!("prover …{}", tail(&hex::encode(address))),
            Some("its seniority counts for that prover; restore that prover's key to recover it"),
        ),
        None => ("no recorded prover".into(), Some("none: GLOBAL credits each target once")),
    }
}

/// Consumed merge targets this node reported, with the epoch of the report:
/// a target found consumed is reported at once and again at most once per
/// epoch while the lifecycle keeps proposing merges. Holds only this node's
/// own targets.
#[derive(Default)]
struct ConsumedTargetReports(Mutex<HashMap<ConsumedMergeTarget, u64>>);

impl ConsumedTargetReports {
    /// Whether `target` is due a report in `epoch`; records the report.
    fn due(&self, target: &ConsumedMergeTarget, epoch: u64) -> bool {
        let Ok(mut reported) = self.0.lock() else { return false };
        if reported.get(target).is_some_and(|last| *last >= epoch) {
            return false;
        }
        reported.insert(target.clone(), epoch);
        true
    }
}

fn consumed_target_reports() -> &'static ConsumedTargetReports {
    static REPORTS: OnceLock<ConsumedTargetReports> = OnceLock::new();
    REPORTS.get_or_init(ConsumedTargetReports::default)
}

impl ProverPipeline {
    fn dispatch_confirmation(
        self: &Arc<Self>, filters: Vec<Vec<u8>>, frame_number: u64,
        needs_storage: bool, prune_replicas: bool,
    ) {
        let Some(attempt) = self.lifecycle.submission_attempts.begin(&filters, frame_number) else {
            tracing::info!(frame = frame_number, filters = filters.len(), needs_storage,
                "confirmation dispatch skipped: an attempt for this filter/epoch is already recorded");
            return;
        };
        tracing::info!(frame = frame_number, filters = filters.len(), needs_storage, prune_replicas,
            "dispatching prover confirmation");
        let me = self.clone();
        tokio::spawn(async move {
            // Limit expensive preparation independently from network timeouts.
            // Keep the reservation inside the blocking task: cancelling its
            // waiter cannot start a second encoder while the first still runs.
            let (filters, roots, attempt) = if needs_storage {
                static ENCODERS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(2);
                let Ok(permit) = ENCODERS.acquire().await else { return; };
                let encoder = me.clone();
                let encoded_filters = filters.clone();
                let prepared = tokio::task::spawn_blocking(move || {
                    let _permit = permit;
                    if prune_replicas {
                        let current_epoch = quil_types::consensus::epoch_for_frame(frame_number);
                        prune_confirmation_replicas(
                            encoder.replica_store.as_ref(), encoder.storage_for_filter.as_deref(),
                            &encoded_filters, current_epoch,
                        );
                    }
                    let confirm = encoder.storage_confirm_leaf_roots(&encoded_filters, frame_number);
                    (confirm, attempt)
                }).await;
                match prepared {
                    Ok((Ok(prepared), mut attempt)) => {
                        if !prepared.left_out.is_empty() {
                            prepared.release_left_out(&mut attempt);
                            me.report_left_out_seats(frame_number, &prepared);
                        }
                        (prepared.filters, prepared.roots, attempt)
                    }
                    Ok((Err(e), _attempt)) => {
                        warn!(frame = frame_number, %e, "confirmation preparation failed; retrying on next cycle");
                        return;
                    }
                    Err(e) => {
                        warn!(frame = frame_number, %e, "confirmation preparation task failed");
                        return;
                    }
                }
            } else {
                (filters, Vec::new(), attempt)
            };
            match tokio::time::timeout(
                NON_VDF_SUBMIT_TIMEOUT,
                me.submit_confirm(filters, frame_number, roots),
            ).await {
                Ok(Ok(())) => {
                    attempt.published(me.current_frame.as_ref().map(|f| f.effective()).unwrap_or(frame_number));
                }
                Ok(Err(e)) => warn!(frame = frame_number, %e, "confirmation submission failed"),
                Err(_) => warn!(frame = frame_number, "confirmation submission timed out"),
            }
        });
    }

    /// Warn, once per confirm, of the seats it leaves out because their
    /// workers did not prepare their storage, or not by the round's deadline:
    /// the confirm goes ahead for the others, and these are retried on the
    /// next cycle.
    fn report_left_out_seats(&self, frame_number: u64, prepared: &PreparedConfirm) {
        const LISTED: usize = 16;
        let workers = self.worker_manager.range_workers().unwrap_or_default();
        let mut core_ids: Vec<u32> = prepared
            .left_out
            .iter()
            .filter_map(|seat| workers.iter().find(|w| w.filter == seat.filter).map(|w| w.core_id))
            .collect();
        core_ids.sort_unstable();
        core_ids.dedup();
        let listed = core_ids.iter().take(LISTED).map(u32::to_string).collect::<Vec<_>>().join(",");
        warn!(
            frame = frame_number,
            epoch = quil_types::consensus::epoch_for_frame(frame_number),
            left_out = prepared.left_out.len(),
            requested = prepared.left_out.len() + prepared.filters.len(),
            submitted = prepared.filters.len(),
            causes = %left_out_causes(&prepared.left_out),
            core_ids = %listed,
            more_core_ids = core_ids.len().saturating_sub(LISTED),
            errors = %left_out_errors(&prepared.left_out),
            scope = "local workers",
            action = "check that these workers run, the master can reach them and they answer within the round",
            "confirmation leaves out seats whose workers did not prepare their storage in time; \
             submitting the others, retrying these on next cycle"
        );
    }

    /// Dispatch a lifecycle action. Non-blocking: spawns a tokio task
    /// to handle the (slow) VDF + sign + submit work so the caller's
    /// frame-processing loop continues.
    pub fn dispatch(self: &Arc<Self>, action: LifecycleAction) {
        // Confirmations acquire the same reservation inside their preparation
        // helper, where ownership also follows blocking encoders. Other shard
        // operations reserve before spawning so another evaluation cannot race.
        let mut reservation = match &action {
            LifecycleAction::ProposeJoin { filters, frame_number, .. }
            | LifecycleAction::RejectJoins { filters, frame_number }
            | LifecycleAction::ProposeLeave { filters, frame_number }
            | LifecycleAction::RejectLeaves { filters, frame_number } => {
                match self.lifecycle.submission_attempts.begin(filters, *frame_number) {
                    Some(attempt) => Some(attempt),
                    None => {
                        info!(frame = *frame_number, filters = filters.len(),
                            "shard submission deferred: another operation owns a filter");
                        return;
                    }
                }
            }
            _ => None,
        };
        match action {
            LifecycleAction::Noop => {}
            LifecycleAction::ProposeJoin { filters, worker_ids, frame_number } => {
                let me = self.clone();
                // Guard against overlapping VDF computations — set before
                // spawn so the next evaluate() sees it immediately.
                me.lifecycle.set_proof_in_progress(true);
                // Hard ceiling on the whole submit. VDF compute is
                // `spawn_blocking` and can run 10-20s on a slow box;
                // archive RPC has its own per-call timeout; BlossomSub
                // publish is fast. 90s is well above the legitimate
                // worst case but bounded — if anything in this path
                // ever hangs (transport bug, runtime starvation, etc.)
                // `proof_in_progress` clears so the lifecycle can
                // try again on the next frame instead of being
                // permanently stuck.
                const SUBMIT_JOIN_TIMEOUT: std::time::Duration =
                    std::time::Duration::from_secs(90);
                // TODO
                // Chunk the filters so no single ProverJoin exceeds the
                // decoder's `MAX_FILTERS` (100) / `MAX_PROOF_LEN` (51600 =
                // 100*516) ceiling — a >100-shard node would otherwise emit one
                // over-cap message the archive silently drops at decode. Each
                // chunk is an independent, valid join (one prover key, a subset
                // of shards) that the archive processes additively; `submit_join`
                // marks all `worker_ids` pending on each, which is idempotent.
                // Today there are ~49 shards ⇒ a single chunk, byte-identical to
                // the pre-chunking behaviour. Each chunk gets its own VDF-bounded
                // timeout since chunk N's proofs are independent of chunk N-1's.
                const MAX_FILTERS_PER_JOIN: usize = 100;
                tokio::spawn(async move {
                    let chunks: Vec<Vec<Vec<u8>>> = if filters.is_empty() {
                        vec![Vec::new()]
                    } else {
                        filters
                            .chunks(MAX_FILTERS_PER_JOIN)
                            .map(|c| c.to_vec())
                            .collect()
                    };
                    let chunk_count = chunks.len();
                    let mut attempt = reservation.take().expect("join reservation acquired");
                    for (idx, chunk) in chunks.into_iter().enumerate() {
                        let submitted_filters = chunk.clone();
                        match tokio::time::timeout(
                            SUBMIT_JOIN_TIMEOUT,
                            me.submit_join(chunk, &worker_ids, frame_number),
                        )
                        .await
                        {
                            Ok(Ok(())) => {
                                let published = me.current_frame.as_ref()
                                    .map(|f| f.effective()).unwrap_or(frame_number);
                                attempt.published_subset(&submitted_filters, published);
                            }
                            Ok(Err(e)) => {
                                warn!(frame = frame_number, chunk = idx, chunk_count, %e, "ProposeJoin submission failed");
                                break;
                            }
                            Err(_) => {
                                warn!(
                                    frame = frame_number,
                                    chunk = idx,
                                    chunk_count,
                                    timeout_s = SUBMIT_JOIN_TIMEOUT.as_secs(),
                                    "ProposeJoin submission timed out — clearing proof_in_progress",
                                );
                                break;
                            }
                        }
                    }
                    me.lifecycle.set_proof_in_progress(false);
                });
            }
            LifecycleAction::ConfirmJoins { filters, frame_number } => {
                self.dispatch_confirmation(filters, frame_number, true, false);
            }
            LifecycleAction::RejectJoins { filters, frame_number } => {
                let me = self.clone();
                // TODO
                let attempt = reservation.take().expect("shard reservation acquired");
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        NON_VDF_SUBMIT_TIMEOUT,
                        me.submit_reject(filters, frame_number),
                    ).await {
                        Ok(Ok(())) => {
                            attempt.published(me.current_frame.as_ref()
                                .map(|f| f.effective()).unwrap_or(frame_number));
                        }
                        Ok(Err(e)) => {
                            warn!(frame = frame_number, %e, "RejectJoins submission failed");
                        }
                        Err(_) => {
                            warn!(
                                frame = frame_number,
                                timeout_s = NON_VDF_SUBMIT_TIMEOUT.as_secs(),
                                "RejectJoins submission timed out",
                            );
                        }
                    }
                });
            }
            LifecycleAction::ProposeLeave { filters, frame_number } => {
                let me = self.clone();
                // TODO
                let attempt = reservation.take().expect("shard reservation acquired");
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        NON_VDF_SUBMIT_TIMEOUT,
                        me.submit_leave(filters, frame_number),
                    ).await {
                        Ok(Ok(())) => {
                            attempt.published(me.current_frame.as_ref()
                                .map(|f| f.effective()).unwrap_or(frame_number));
                        }
                        Ok(Err(e)) => {
                            warn!(frame = frame_number, %e, "ProposeLeave submission failed");
                        }
                        Err(_) => {
                            warn!(
                                frame = frame_number,
                                timeout_s = NON_VDF_SUBMIT_TIMEOUT.as_secs(),
                                "ProposeLeave submission timed out",
                            );
                        }
                    }
                });
            }
            LifecycleAction::ConfirmLeaves { filters, frame_number } => {
                self.dispatch_confirmation(filters, frame_number, false, false);
            }
            LifecycleAction::ReconfirmEpoch { filters, frame_number } => {
                self.dispatch_confirmation(filters, frame_number, true, true);
            }
            LifecycleAction::RejectLeaves { filters, frame_number } => {
                let me = self.clone();
                // TODO
                let attempt = reservation.take().expect("shard reservation acquired");
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        NON_VDF_SUBMIT_TIMEOUT,
                        me.submit_reject(filters, frame_number),
                    ).await {
                        Ok(Ok(())) => {
                            attempt.published(me.current_frame.as_ref()
                                .map(|f| f.effective()).unwrap_or(frame_number));
                        }
                        Ok(Err(e)) => {
                            warn!(frame = frame_number, %e, "RejectLeaves submission failed");
                        }
                        Err(_) => {
                            warn!(
                                frame = frame_number,
                                timeout_s = NON_VDF_SUBMIT_TIMEOUT.as_secs(),
                                "RejectLeaves submission timed out",
                            );
                        }
                    }
                });
            }
            LifecycleAction::ProposeSeniorityMerge { frame_number } => {
                let me = self.clone();
                // TODO
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        NON_VDF_SUBMIT_TIMEOUT,
                        me.submit_seniority_merge(frame_number),
                    ).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => {
                            warn!(frame = frame_number, %e, "ProposeSeniorityMerge submission failed");
                        }
                        Err(_) => {
                            warn!(
                                frame = frame_number,
                                timeout_s = NON_VDF_SUBMIT_TIMEOUT.as_secs(),
                                "ProposeSeniorityMerge submission timed out",
                            );
                        }
                    }
                });
            }
        }
    }

    fn domain(label: &[u8]) -> Result<[u8; 32]> {
        let mut dp = quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS.to_vec();
        dp.extend_from_slice(label);
        quil_crypto::poseidon::hash_bytes_to_32(&dp)
    }

    fn bls_signer(&self) -> Result<Box<dyn Signer>> {
        self.key_manager
            .get_signer(quil_types::crypto::KeyType::Falcon512)
            .map_err(|e| QuilError::Internal(format!("no BLS signer: {e}")))
    }

    /// Submit a `ProverJoin` for the given filters. Normally driven
    /// by the lifecycle's `ProposeJoin` action; exposed pub so admin
    /// tooling (`NodeService::request_join`) can force an immediate
    /// submission bypassing the cooldown / readiness gate.
    ///
    /// `worker_ids` is the list of workers that will be pinned to
    /// each filter on success. Pass empty slice for admin submissions
    /// where worker assignment happens after registry confirmation.
    pub async fn submit_join(
        &self,
        filters: Vec<Vec<u8>>,
        worker_ids: &[u32],
        lifecycle_frame: u64,
    ) -> Result<()> {
        info!(
            filter_count = filters.len(),
            lifecycle_frame,
            "building ProverJoin"
        );

        let header = self.transport.latest_global_frame_header().await?;
        let frame_number = header.frame_number;

        // VDF proof-of-sequential-work is no longer required to join.
        // The `proof` field is retained in the wire format (empty here)
        // purely so historical joins still decode; new joins carry none.
        let all_proofs: Vec<u8> = Vec::new();

        // Seniority merge targets: our own + enrolled Ed448 seeds. The join op
        // itself only carries the BLS prover key, so the ONLY way the join can
        // factor in our libp2p peer-id(s)' premainnet seniority is to attach
        // them as merge targets — each Ed448 seed signs our BLS pubkey under
        // the `PROVER_JOIN_MERGE` domain (the same domain `verify_prover_join`
        // checks and `invoke_join` derives peer-ids from). Without this the
        // prover joins at seniority 0 regardless of what its peer-id earned,
        // and only a later `ProverSeniorityMerge` could raise it. A seed whose
        // peer-id has no premainnet seniority contributes 0 — harmless. This is
        // the same seed set used for `submit_seniority_merge` (own key first,
        // then `multisig_prover_enrollment_paths`).
        let merge_targets: Vec<quil_execution::global_intrinsic::SeniorityMerge> = {
            let mut mts =
                Vec::with_capacity(self.multisig_ed448_seeds.len());
            for seed in &self.multisig_ed448_seeds {
                let helper_pubkey = quil_p2p::ed448_identity::derive_public_key(seed);
                let helper_signer =
                    quil_crypto::Ed448Signer::from_bytes(seed, &helper_pubkey)?;
                let helper_sig = <quil_crypto::Ed448Signer as Signer>::sign_with_domain(
                    &helper_signer,
                    &self.bls_pubkey,
                    b"PROVER_JOIN_MERGE",
                )?;
                mts.push(quil_execution::global_intrinsic::SeniorityMerge {
                    signature: helper_sig,
                    key_type: quil_types::crypto::KeyType::Ed448 as u32,
                    prover_public_key: helper_pubkey,
                });
            }
            mts
        };

        // Build + sign. Go signs the full ProverJoin canonical bytes
        // with signature=nil, then fills in the signature:
        // see global_prover_join.go:1074-1079.
        let signer = self.bls_signer()?;
        let unsigned = ProverJoin {
            filters: filters.clone(),
            frame_number,
            public_key_signature_bls48581: None,
            delegate_address: self.delegate_address.clone(),
            merge_targets: merge_targets.clone(),
            proof: all_proofs.clone(),
        };
        let join_message = unsigned.to_canonical_bytes()?;
        let join_domain = Self::domain(b"PROVER_JOIN")?;
        let signature = signer.sign_with_domain(&join_message, &join_domain)?;
        // Proof of possession: sign own pubkey with it, using BLS48_POP_SK domain.
        let pop_signature = signer.sign_with_domain(&self.bls_pubkey, b"BLS48_POP_SK")?;

        let signed = ProverJoin {
            filters: filters.clone(),
            frame_number,
            public_key_signature_bls48581: Some(SignatureWithPop {
                signature,
                public_key: Some(self.bls_pubkey.clone()),
                pop_signature,
            }),
            delegate_address: self.delegate_address.clone(),
            merge_targets,
            proof: all_proofs,
        };
        let bytes = signed.to_canonical_bytes()?;

        info!(
            frame = frame_number,
            filter_count = filters.len(),
            bytes_len = bytes.len(),
            "submitting ProverJoin"
        );
        crate::metrics::inc_prover_joins_submitted();

        self.publish_prover_message(bytes).await?;

        // Publish succeeded — NOW burn the 4-frame cooldown. Setting
        // this earlier (in lifecycle's evaluate) would waste join
        // opportunities whenever an archive is unreachable or a VDF
        // self-verify fails: the next eligible frame would be gated
        // by a cooldown from a join that never actually reached the
        // network. Matches Go's post-success set at
        // `worker_allocator.go:224`.
        self.lifecycle.record_join_attempt(lifecycle_frame);

        // Persist the pending frame on each worker so reconcile can tell
        // "proposal in flight" from "orphaned". Uses `lifecycle_frame`
        // (not `frame_number`) — the timestamp matches the cooldown
        // timer on WorkerAllocator.
        for &core_id in worker_ids {
            let _ = self.worker_manager.set_pending_filter_frame(core_id, lifecycle_frame);
        }

        Ok(())
    }

    async fn submit_confirm(
        &self,
        filters: Vec<Vec<u8>>,
        frame_number: u64,
        leaf_roots: Vec<quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots>,
    ) -> Result<()> {
        // Storage-attestation confirm hook (PoRep): at/after activation,
        // partition each confirmed shard, SDR-encode + persist this prover's
        // per-leaf replicas, and fold the registered leaf roots into the
        // confirm. The signature covers `confirm_signing_message`, which
        // appends the leaf-root set — byte-identical to the legacy
        // concat(filters)||frame message when the set is empty (pre-activation
        // / deps absent), so default Go-parity is preserved.
        // From the confirm release frame the confirm reports and signs this
        // build's release, which GLOBAL records on each confirmed allocation.
        let release = quil_execution::global_intrinsic::prover_release::release_for_confirm(frame_number);
        let msg = quil_execution::global_intrinsic::prover_verify::confirm_signing_message(
            &filters,
            frame_number,
            &leaf_roots,
            release.as_ref(),
        );

        let signer = self.bls_signer()?;
        let domain = Self::domain(b"PROVER_CONFIRM")?;
        let signature = signer.sign_with_domain(&msg, &domain)?;

        let confirm = ProverConfirm {
            filter: vec![],
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature,
                address: self.prover_address.to_vec(),
            }),
            filters: filters.clone(),
            leaf_roots,
            release,
        };
        let bytes = confirm.to_canonical_bytes()?;

        info!(frame = frame_number, filter_count = filters.len(), leaf_roots = confirm.leaf_roots.len(),
            leaf_entries = confirm.leaf_roots.iter().map(|g| g.entries.len()).sum::<usize>(),
            release = %confirm.release.map_or_else(|| "none".to_string(), |release| release.to_string()),
            "submitting ProverConfirm");
        crate::metrics::inc_prover_confirms_submitted();
        self.publish_prover_message(bytes).await
    }

    /// Partition committed shard data into PoRep leaves, encode and persist the
    /// next epoch's replicas, and return their roots. Preparation errors abort
    /// submission so the lifecycle can retry, except a standalone worker's: its
    /// seat is left out of this confirm (see `prepare_confirm`). Standalone
    /// workers are asked concurrently, within a round deadline, and their
    /// answers must cover every shard asked for. Global confirms need no
    /// replicas.
    fn storage_confirm_leaf_roots(
        &self,
        filters: &[Vec<u8>],
        frame_number: u64,
    ) -> Result<PreparedConfirm> {
        let (Some(crdt), Some(replica_store)) =
            (self.hypergraph.as_ref(), self.replica_store.as_ref())
        else {
            if filters.iter().all(Vec::is_empty) {
                return Ok(PreparedConfirm { filters: filters.to_vec(), roots: Vec::new(), left_out: Vec::new() });
            }
            return Err(QuilError::Internal("storage confirmation requires hypergraph and replica store".into()));
        };
        // Epoch-aligned: a confirm in epoch E encodes + registers leaf roots for
        // the NEXT epoch E+1 (the `next` slot). The prover encodes ahead so that
        // when it becomes active next epoch it is already proving against an
        // on-chain registration. The per-frame proving path
        // (`storage_vote_openings`) reads replica@CURRENT-epoch, which this same
        // store wrote one epoch earlier — so encode-ahead lines up exactly.
        let epoch = quil_types::consensus::epoch_for_frame(frame_number) + 1;
        // Shards a split or merge applying next epoch creates from a confirmed
        // shard are registered too, encoded from that shard's storage: its
        // holder is on one of them once the change applies.
        let changes = match self.pending_shard_changes.as_ref() {
            Some(pending) if frame_number >= quil_execution::global_intrinsic::leaf_root_registration::pre_registration_frame() => pending(),
            _ => Vec::new(),
        };
        // The thread worker holding each shard, if any. A shard none holds is
        // prepared by the standalone worker running it, else by the master.
        let local: HashMap<_, _> = filters
            .iter()
            .filter(|filter| !filter.is_empty())
            .map(|filter| (filter.clone(), self.storage_for_filter.as_ref().and_then(|resolve| resolve(filter))))
            .collect();
        let mut answers = match self.remote_storage_confirm.as_ref() {
            Some(remote) => {
                let mut requests: Vec<(Vec<u8>, Vec<Vec<u8>>)> = confirm_encoding_plan(filters, &changes, epoch)
                    .into_iter()
                    .filter(|(filter, _)| matches!(local.get(filter), Some(None)))
                    .collect();
                late_seats().ask_last(&mut requests);
                let answers = query_remote_workers(
                    &requests,
                    REMOTE_PREPARATIONS,
                    remote_round_deadline(),
                    |filter, targets, timeout| remote(filter, targets, frame_number, timeout),
                );
                late_seats().record(&answers);
                answers
            }
            None => HashMap::new(),
        };
        prepare_confirm(filters, &changes, epoch, |filter, targets| {
            if let Some(prepared) = answers.remove(filter).and_then(|answer| remote_answer(filter, targets, answer)) {
                return Ok(prepared);
            }
            let worker = local.get(filter).cloned().flatten();
            let (filter_crdt, filter_replicas) = match worker.as_ref() {
                Some((worker_crdt, worker_replicas)) => (worker_crdt.as_ref(), worker_replicas),
                None => (crdt.as_ref(), replica_store),
            };
            let encoded: Vec<Vec<u8>> = std::iter::once(filter.to_vec()).chain(targets.iter().cloned()).collect();
            Ok(Prepared::Roots(crate::app_shard_metadata::compute_storage_confirm(
                filter_crdt,
                filter_replicas,
                &encoded,
                &self.prover_address,
                epoch,
                quil_types::consensus::STORAGE_BLOCK_POLY_SIZE,
                &quil_crypto::sdr::SdrParams::default(),
            )?))
        })
    }

    async fn submit_reject(&self, filters: Vec<Vec<u8>>, frame_number: u64) -> Result<()> {
        // Go: sign(concat(filters) || u64(frame_number), PROVER_REJECT_domain).
        // See global_prover_reject.go:260-295.
        let mut msg = Vec::new();
        for f in &filters { msg.extend_from_slice(f); }
        msg.extend_from_slice(&frame_number.to_be_bytes());

        let signer = self.bls_signer()?;
        let domain = Self::domain(b"PROVER_REJECT")?;
        let signature = signer.sign_with_domain(&msg, &domain)?;

        let reject = ProverReject {
            filter: vec![],
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature,
                address: self.prover_address.to_vec(),
            }),
            filters: filters.clone(),
        };
        let bytes = reject.to_canonical_bytes()?;

        info!(frame = frame_number, filter_count = filters.len(), "submitting ProverReject");
        crate::metrics::inc_prover_rejects_submitted();
        self.publish_prover_message(bytes).await
    }

    /// Submit a `ShardSplit` proposal for the given shard → child set.
    /// Go signs `u64_be(frame) || shard_address` under the
    /// `SHARD_SPLIT` domain. See `global_shard_split.go:205-230`.
    pub async fn submit_shard_split(
        &self,
        shard_address: Vec<u8>,
        proposed_shards: Vec<Vec<u8>>,
        frame_number: u64,
    ) -> Result<()> {
        let mut msg = Vec::with_capacity(8 + shard_address.len());
        msg.extend_from_slice(&frame_number.to_be_bytes());
        msg.extend_from_slice(&shard_address);

        let signer = self.bls_signer()?;
        let domain = Self::domain(b"SHARD_SPLIT")?;
        let signature = signer.sign_with_domain(&msg, &domain)?;

        let split = ShardSplit {
            shard_address: shard_address.clone(),
            proposed_shards,
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature,
                address: self.prover_address.to_vec(),
            }),
        };
        let bytes = split.to_canonical_bytes()?;
        debug!(
            frame = frame_number,
            shard = hex::encode(&shard_address),
            "submitting ShardSplit"
        );
        crate::metrics::inc_shard_splits_submitted();
        self.publish_prover_message_local_first(bytes).await
    }

    /// Submit a `ShardMerge` proposal for the given shard list →
    /// parent. Go signs `u64_be(frame) || parent_address` under the
    /// `SHARD_MERGE` domain. See `global_shard_merge.go:203-230`.
    pub async fn submit_shard_merge(
        &self,
        shard_addresses: Vec<Vec<u8>>,
        parent_address: Vec<u8>,
        frame_number: u64,
    ) -> Result<()> {
        let mut msg = Vec::with_capacity(8 + parent_address.len());
        msg.extend_from_slice(&frame_number.to_be_bytes());
        msg.extend_from_slice(&parent_address);

        let signer = self.bls_signer()?;
        let domain = Self::domain(b"SHARD_MERGE")?;
        let signature = signer.sign_with_domain(&msg, &domain)?;

        let merge = ShardMerge {
            shard_addresses,
            parent_address: parent_address.clone(),
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature,
                address: self.prover_address.to_vec(),
            }),
        };
        let bytes = merge.to_canonical_bytes()?;
        debug!(
            frame = frame_number,
            parent = hex::encode(&parent_address),
            "submitting ShardMerge"
        );
        crate::metrics::inc_shard_merges_submitted();
        self.publish_prover_message_local_first(bytes).await
    }

    /// Submit a `ProverSeniorityMerge` to raise on-chain seniority.
    /// Mirrors Go's `submitSeniorityMerge` at `worker_allocator.go:1725-1783`
    /// and `ProverSeniorityMerge.Prove` at `global_prover_seniority_merge.go:270-349`.
    async fn submit_seniority_merge(&self, frame_number: u64) -> Result<()> {
        if self.multisig_ed448_seeds.is_empty() {
            return Err(QuilError::Internal(
                "seniority merge: no multisig Ed448 seeds loaded".into(),
            ));
        }

        let bls_signer = self.bls_signer()?;
        let (merge, consumed) = seniority_merge(
            frame_number,
            &self.multisig_ed448_seeds,
            &self.bls_pubkey,
            &self.prover_address,
            bls_signer.as_ref(),
            |address| self.hypergraph.as_ref().map_or(Ok(None), |crdt| spent_marker(crdt, address)),
        )?;
        self.report_consumed_merge_targets(&consumed, frame_number);
        let Some(merge) = merge else {
            // GLOBAL would refuse it: no target is left to credit.
            self.lifecycle.hold_seniority_merge(frame_number);
            return Ok(());
        };
        let bytes = merge.to_canonical_bytes()?;

        info!(
            frame = frame_number,
            helpers = merge.merge_targets.len(),
            consumed = consumed.len(),
            "submitting ProverSeniorityMerge"
        );
        self.publish_prover_message(bytes).await
    }

    /// Report each consumed merge target once, and at most once per epoch
    /// while it stays out of the merges this node proposes: a warning when
    /// its seniority went elsewhere, a note when it went to this prover.
    fn report_consumed_merge_targets(&self, consumed: &[ConsumedMergeTarget], frame_number: u64) {
        let epoch = quil_types::consensus::epoch_for_frame(frame_number);
        for target in consumed.iter().filter(|target| consumed_target_reports().due(target, epoch)) {
            let peer = bs58::encode(quil_p2p::peer_id_from_ed448_pubkey(&target.pubkey)).into_string();
            let target_peer = format!("…{}", tail(&peer));
            match consumed_target_credit(target, &self.prover_address) {
                (credited_to, None) => info!(
                    frame = frame_number,
                    epoch,
                    target_peer = %target_peer,
                    marker = target.marker,
                    credited_to = %credited_to,
                    "seniority merge target already credited to this prover; \
                     left out of its seniority merges"
                ),
                (credited_to, Some(action)) => warn!(
                    frame = frame_number,
                    epoch,
                    target_peer = %target_peer,
                    marker = target.marker,
                    credited_to = %credited_to,
                    scope = "committed GLOBAL state",
                    action,
                    "seniority merge target already consumed: GLOBAL refuses to merge it again, \
                     so this node leaves it out of its seniority merges"
                ),
            }
        }
    }

    async fn submit_leave(&self, filters: Vec<Vec<u8>>, frame_number: u64) -> Result<()> {
        // Go's leave message format differs — length-prefixed:
        //   u32(num_filters) || for each: u32(len) || filter || u64(frame).
        // See global_prover_leave.go:230-245.
        let mut msg = Vec::new();
        msg.extend_from_slice(&(filters.len() as u32).to_be_bytes());
        for f in &filters {
            msg.extend_from_slice(&(f.len() as u32).to_be_bytes());
            msg.extend_from_slice(f);
        }
        msg.extend_from_slice(&frame_number.to_be_bytes());

        let signer = self.bls_signer()?;
        let domain = Self::domain(b"PROVER_LEAVE")?;
        let signature = signer.sign_with_domain(&msg, &domain)?;

        let leave = ProverLeave {
            filters: filters.clone(),
            frame_number,
            public_key_signature_bls48581: Some(AddressedSignature {
                signature,
                address: self.prover_address.to_vec(),
            }),
        };
        let bytes = leave.to_canonical_bytes()?;

        info!(frame = frame_number, filter_count = filters.len(), "submitting ProverLeave");
        crate::metrics::inc_prover_leaves_submitted();
        self.publish_prover_message(bytes).await
    }

    /// Wrap `inner_bytes` in a `MessageBundle` and hand off to the
    /// configured transport. The transport is responsible for the
    /// gRPC fan-out + pubsub publish (production) or in-memory
    /// broadcast (tests).
    fn build_prover_bundle(&self, inner_bytes: Vec<u8>) -> Result<Vec<u8>> {
        let req = CanonicalMessageRequest::wrap(inner_bytes)?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;
        let bundle = CanonicalMessageBundle {
            requests: vec![Some(req)],
            timestamp: now_ms,
        };
        bundle.to_canonical_bytes()
    }

    async fn publish_prover_message(&self, inner_bytes: Vec<u8>) -> Result<()> {
        let tracked = inner_bytes.clone();
        let bundle_bytes = self.build_prover_bundle(inner_bytes)?;
        self.transport.publish_prover_bundle(bundle_bytes).await?;
        let frame = self.current_frame.as_ref().map_or(0, |frame| frame.effective());
        crate::own_prover_ops::tracker().submitted(&tracked, frame);
        Ok(())
    }

    /// Loop a self-generated op into the LOCAL mempool (the same collector the
    /// gRPC/gossip ingest feeds), tagged with the current consensus rank exactly
    /// like the gRPC ingest (grpc.rs:400). Returns true if the op is now in the
    /// local mempool (freshly Accepted, or already present as a Duplicate).
    fn loopback_to_local_mempool(&self, bundle_bytes: &[u8]) -> bool {
        match (&self.local_message_collector, &self.current_frame) {
            (Some(mc), Some(cf)) => matches!(
                mc.add_message_outcome(cf.effective_rank(), bundle_bytes.to_vec()),
                SubmitOutcome::Accepted | SubmitOutcome::Duplicate
            ),
            _ => false,
        }
    }

    /// Publish a self-generated op LOCAL-FIRST: add it to this node's own mempool
    /// (so a frame PRODUCER includes its own op) AND best-effort publish to remote
    /// paths. Succeeds if EITHER path delivered — so a single-archive producer
    /// (where the remote publish has no acceptor and gossipsub won't self-loop)
    /// still submits its op instead of failing with "no archive accepted". Used
    /// for ShardSplit/ShardMerge, which the coverage orchestrator generates on
    /// the frame producer itself.
    async fn publish_prover_message_local_first(&self, inner_bytes: Vec<u8>) -> Result<()> {
        let bundle_bytes = self.build_prover_bundle(inner_bytes)?;
        let looped = self.loopback_to_local_mempool(&bundle_bytes);
        let published = self.transport.publish_prover_bundle(bundle_bytes).await;
        if looped || published.is_ok() {
            if looped {
                debug!("prover op looped back into local mempool (producer self-inclusion)");
            }
            Ok(())
        } else {
            published
        }
    }
}

/// Retire obsolete replicas before encoding the next epoch so its writes do
/// not overlap a fourth epoch. Clean the stores confirmations actually use. Preserve
/// the previous epoch too: early in an epoch, frames can still anchor their
/// storage beacon before its boundary. Publication is not registration proof.
fn prune_confirmation_replicas(
    master: Option<&quil_store::replica_store::ReplicaStore>,
    worker: Option<&(dyn Fn(&[u8]) -> Option<(
        Arc<quil_hypergraph::HypergraphCrdt>, quil_store::replica_store::ReplicaStore,
    )> + Send + Sync)>,
    filters: &[Vec<u8>],
    current_epoch: u64,
) {
    let keep_from = crate::app_shard_metadata::replica_keep_from(current_epoch);
    let workers = filters.iter().filter_map(|filter| {
        worker.and_then(|resolve| resolve(filter)).map(|(_, replicas)| replicas)
    });
    for (store_index, store) in master.cloned().into_iter().chain(workers).enumerate() {
        if let Err(error) = store.evict_below_epoch(keep_from) {
            warn!(store_index, keep_from_epoch = keep_from, %error, "replica cleanup failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::confirm_encoding_plan;
    use quil_types::store::{PendingShardChange, ShardChangeKind};

    #[test]
    fn confirmation_prunes_worker_stores_and_keeps_boundary_replicas() {
        use std::sync::Arc;
        use quil_store::replica_store::ReplicaStore;
        let make = || ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        let master = make(); let worker_a = make(); let worker_b = make(); let unrelated = make();
        for store in [&master,&worker_a,&worker_b,&unrelated] {
            for epoch in 5..=8 { store.put(epoch,b"leaf",&[epoch as u8]).unwrap(); }
        }
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),
            Arc::new(quil_tries::ShaInclusionProver),
        ));
        let resolve = |filter:&[u8]| match filter {
            [1] => Some((crdt.clone(),worker_a.clone())),
            [2] => Some((crdt.clone(),worker_b.clone())),
            _ => None,
        };
        super::prune_confirmation_replicas(Some(&master),Some(&resolve),&[vec![1],vec![2],vec![99]],7);
        for store in [&master,&worker_a,&worker_b] {
            assert!(store.get(5,b"leaf").unwrap().is_none(),"old epochs must be pruned in each encoded store");
            for epoch in 6..=8 { assert_eq!(store.get(epoch,b"leaf").unwrap(),Some(vec![epoch as u8]),"previous/current/next replicas stay readable"); }
        }
        assert_eq!(unrelated.get(5,b"leaf").unwrap(),Some(vec![5]),"unselected stores are untouched");
        // A low epoch cannot underflow the retention boundary.
        super::prune_confirmation_replicas(None,Some(&resolve),&[vec![1]],0);
        assert_eq!(worker_a.get(6,b"leaf").unwrap(),Some(vec![6]));
    }

    #[test]
    fn a_failed_master_cleanup_does_not_skip_worker_cleanup() {
        use std::sync::Arc;
        use quil_store::replica_store::ReplicaStore;
        let primary = Arc::new(quil_store::RocksDb::open_in_memory().unwrap());
        let writable = ReplicaStore::new(primary.clone());
        writable.put(5,b"leaf",b"old").unwrap();
        let readonly = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_for_read_only_live(primary.inner().path()).unwrap()));
        assert_eq!(readonly.get(5,b"leaf").unwrap(),Some(b"old".to_vec()));
        let worker = ReplicaStore::new(Arc::new(quil_store::RocksDb::open_in_memory().unwrap()));
        worker.put(5,b"leaf",b"old").unwrap();worker.put(7,b"leaf",b"current").unwrap();
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_hypergraph::testing::MemStore::new()),Arc::new(quil_tries::ShaInclusionProver),
        ));
        let resolve = |_:&[u8]|Some((crdt.clone(),worker.clone()));
        super::prune_confirmation_replicas(Some(&readonly),Some(&resolve),&[vec![1]],7);
        assert_eq!(readonly.get(5,b"leaf").unwrap(),Some(b"old".to_vec()));
        assert!(worker.get(5,b"leaf").unwrap().is_none());
        assert_eq!(worker.get(7,b"leaf").unwrap(),Some(b"current".to_vec()));
    }

    fn change(kind: ShardChangeKind, parent: u8, children: &[u8]) -> PendingShardChange {
        PendingShardChange {
            kind,
            parent: vec![parent],
            children: children.iter().map(|c| vec![*c]).collect(),
            effective_epoch: 8,
            proposed_frame: 0,
        }
    }

    fn roots_of(filter: &[u8]) -> quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots {
        quil_execution::global_intrinsic::leaf_root_registration::ConfirmLeafRoots {
            filter: filter.to_vec(),
            entries: Vec::new(),
        }
    }

    fn unanswered() -> quil_types::error::QuilError {
        quil_types::error::QuilError::ExecutionUnavailable("worker storage confirm: tcp connect error".into())
    }

    fn left_out_filters(prepared: &super::PreparedConfirm) -> Vec<Vec<u8>> {
        prepared.left_out.iter().map(|seat| seat.filter.clone()).collect()
    }

    #[test]
    fn a_confirm_skips_a_filter_whose_worker_does_not_answer() {
        use std::sync::Arc;
        let attempts = Arc::new(crate::submission_attempts::SubmissionAttempts::default());
        let filters = vec![vec![1], vec![2]];
        let mut attempt = attempts.begin(&filters, FRAME).unwrap();
        let prepared = super::prepare_confirm(&filters, &[], 2, |filter, _| {
            Ok(match filter {
                [2] => super::Prepared::Unanswered(super::LeftOutCause::Failed, unanswered()),
                _ => super::Prepared::Roots(vec![roots_of(filter)]),
            })
        })
        .expect("the seat whose worker answers is confirmed");
        assert_eq!(prepared.filters, vec![vec![1]], "the confirm names only the prepared seat");
        assert_eq!(prepared.roots, vec![roots_of(&[1])]);
        assert_eq!(left_out_filters(&prepared), vec![vec![2]]);
        assert_eq!(super::left_out_errors(&prepared.left_out), "execution unavailable: worker storage confirm: tcp connect error (1)");
        prepared.release_left_out(&mut attempt);
        assert!(attempts.begin(&[vec![2]], FRAME).is_some(), "the left-out seat is free for the next cycle");
        assert!(attempts.begin(&[vec![1]], FRAME).is_none(), "the submitted seat stays reserved");
        attempt.published(FRAME);
        assert!(attempts.begin(&[vec![1]], FRAME + 1).is_none(), "only the submitted seat is fenced as published");
        assert!(attempts.begin(&[vec![2]], FRAME + 1).is_some());
    }

    #[test]
    fn a_confirm_whose_workers_all_fail_is_not_submitted() {
        use std::sync::Arc;
        let attempts = Arc::new(crate::submission_attempts::SubmissionAttempts::default());
        let filters = vec![vec![1], vec![2]];
        let attempt = attempts.begin(&filters, FRAME).unwrap();
        let result = super::prepare_confirm(&filters, &[], 2, |_, _| Ok(super::Prepared::Unanswered(super::LeftOutCause::Failed, unanswered())));
        let error = result.err().expect("nothing to submit");
        assert_eq!(error.to_string(), unanswered().to_string(), "fails as before, with the first worker error");
        drop(attempt);
        assert!(attempts.begin(&filters, FRAME).is_some(), "every seat is retried on the next cycle");
    }

    #[test]
    fn a_worker_that_does_not_answer_does_not_hold_up_the_others() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{mpsc, Mutex};
        let (answered, answer_seen) = mpsc::channel::<()>();
        let (answered, answer_seen) = (Mutex::new(answered), Mutex::new(answer_seen));
        let overlapped = AtomicBool::new(false);
        // The silent worker's seat comes first, as it may in plan order.
        let requests = vec![(vec![2], Vec::new()), (vec![1], Vec::new())];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut answers = super::query_remote_workers(&requests, 8, deadline, |filter, _, _| match filter {
            // Stands in for a worker that times out: it gives up once the
            // other has answered, or after five seconds if asked after it.
            [2] => {
                let seen = answer_seen.lock().unwrap().recv_timeout(std::time::Duration::from_secs(5)).is_ok();
                overlapped.store(seen, Ordering::SeqCst);
                Err(unanswered())
            }
            _ => {
                let _ = answered.lock().unwrap().send(());
                Ok(Some(vec![roots_of(filter)]))
            }
        });
        assert!(overlapped.load(Ordering::SeqCst), "the answering worker is asked while the other is waited for");
        let prepared = super::prepare_confirm(&[vec![2], vec![1]], &[], 2, |filter, targets| {
            Ok(answers.remove(filter).and_then(|answer| super::remote_answer(filter, targets, answer)).expect("every seat was asked"))
        })
        .expect("the answering worker's seat is confirmed");
        assert_eq!(prepared.filters, vec![vec![1]]);
        assert_eq!(prepared.roots, vec![roots_of(&[1])]);
        assert_eq!(left_out_filters(&prepared), vec![vec![2]]);
    }

    /// A round ends at its deadline: a worker that has not answered by then
    /// is late, the seats after it are not asked, and both are left out
    /// rather than encoded by the master. The next round asks the late seat
    /// after the others, so the seats behind it answer.
    #[test]
    fn a_round_ends_at_its_deadline_and_asks_late_seats_last_next() {
        use super::LeftOutCause;
        let late = super::LateSeats::default();
        let asked = std::sync::Mutex::new(Vec::new());
        // [2] stands in for a worker that never answers: it holds its call
        // for the whole time it is given.
        let query = |filter: &[u8], _: &[Vec<u8>], timeout: std::time::Duration| {
            asked.lock().unwrap().push(filter.to_vec());
            if filter == [2] {
                std::thread::sleep(timeout);
                return Err(quil_types::error::QuilError::ExecutionUnavailable("worker storage confirm timed out".into()));
            }
            Ok(Some(vec![roots_of(filter)]))
        };
        let round = |answers: &std::collections::HashMap<Vec<u8>, super::RemoteAnswer>, filter: u8| {
            match answers.get(&vec![filter]).expect("every seat has an answer") {
                Ok(Some(_)) => None,
                Ok(None) => panic!("no seat runs on the master"),
                Err((cause, _)) => Some(*cause),
            }
        };
        let plan = || vec![(vec![2], Vec::new()), (vec![1], Vec::new()), (vec![3], Vec::new())];

        let mut requests = plan();
        late.ask_last(&mut requests);
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_millis(300);
        let mut answers = super::query_remote_workers(&requests, 1, deadline, query);
        assert!(started.elapsed() < std::time::Duration::from_secs(2), "the round ends by its deadline");
        assert_eq!(*asked.lock().unwrap(), vec![vec![2]]);
        assert_eq!([2, 1, 3].map(|filter| round(&answers, filter)),
            [Some(LeftOutCause::Late), Some(LeftOutCause::Unasked), Some(LeftOutCause::Unasked)]);
        late.record(&answers);
        let unasked = answers.remove(&vec![1]).unwrap();
        assert!(matches!(super::remote_answer(&[1], &[], unasked), Some(super::Prepared::Unanswered(LeftOutCause::Unasked, _))),
            "an unasked seat is left out, not encoded by the master");

        let mut requests = plan();
        late.ask_last(&mut requests);
        assert_eq!(requests.iter().map(|(filter, _)| filter[0]).collect::<Vec<_>>(), vec![1, 3, 2], "the late seat is asked last");
        asked.lock().unwrap().clear();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(300);
        let answers = super::query_remote_workers(&requests, 1, deadline, query);
        assert_eq!([1, 3, 2].map(|filter| round(&answers, filter)), [None, None, Some(LeftOutCause::Late)]);
        late.record(&answers);

        let mut answered = std::collections::HashMap::new();
        answered.insert(vec![2], Ok(Some(vec![roots_of(&[2])])));
        late.record(&answered);
        let mut requests = plan();
        late.ask_last(&mut requests);
        assert_eq!(requests.iter().map(|(filter, _)| filter[0]).collect::<Vec<_>>(), vec![2, 1, 3], "a seat that answers is late no more");
    }

    /// A worker's answer must hold one group for its shard and one for each
    /// shard it was asked to pre-register: one that omits or repeats a group
    /// leaves its seat out, and with it the seat that shares its merge target.
    #[test]
    fn a_worker_answer_missing_or_repeating_a_requested_shard_leaves_its_seat_out() {
        let changes = vec![change(ShardChangeKind::Merge, 2, &[20, 21])];
        let filters = [vec![20], vec![21], vec![5]];
        let plan = confirm_encoding_plan(&filters, &changes, 8);
        assert_eq!(plan[0], (vec![20], vec![vec![2]]), "20 encodes the merge target");
        for (groups, submitted, left_out) in [
            (vec![vec![20], vec![2]], vec![vec![20], vec![21], vec![5]], Vec::new()),
            (vec![vec![20]], vec![vec![5]], vec![vec![20], vec![21]]),
            (vec![vec![20], vec![2], vec![2]], vec![vec![5]], vec![vec![20], vec![21]]),
            (vec![vec![20], vec![20], vec![2]], vec![vec![5]], vec![vec![20], vec![21]]),
        ] {
            let mut answers: std::collections::HashMap<Vec<u8>, super::RemoteAnswer> = plan
                .iter()
                .map(|(filter, targets)| {
                    let answered: Vec<Vec<u8>> = if filter == &vec![20] { groups.clone() }
                        else { std::iter::once(filter).chain(targets).cloned().collect() };
                    (filter.clone(), Ok(Some(answered.iter().map(|group| roots_of(group)).collect())))
                })
                .collect();
            let prepared = super::prepare_confirm(&filters, &changes, 8, |filter, targets| {
                Ok(answers.remove(filter).and_then(|answer| super::remote_answer(filter, targets, answer)).expect("every seat was asked"))
            })
            .unwrap();
            assert_eq!(prepared.filters, submitted, "worker of 20 answered {groups:?}");
            assert_eq!(left_out_filters(&prepared), left_out, "worker of 20 answered {groups:?}");
            if !left_out.is_empty() {
                assert_eq!(super::left_out_causes(&prepared.left_out), "incomplete 1, merge target 1");
            }
        }
    }

    #[test]
    fn a_seat_sharing_a_merge_target_with_a_left_out_seat_is_left_out_too() {
        let changes = vec![change(ShardChangeKind::Merge, 2, &[20, 21])];
        let prepared = super::prepare_confirm(&[vec![20], vec![21], vec![5]], &changes, 8, |filter, targets| {
            Ok(match filter {
                [20] => super::Prepared::Unanswered(super::LeftOutCause::Failed, unanswered()),
                _ => super::Prepared::Roots(
                    std::iter::once(filter).chain(targets.iter().map(Vec::as_slice)).map(roots_of).collect(),
                ),
            })
        })
        .unwrap();
        assert_eq!(prepared.filters, vec![vec![5]], "21 would confirm without registering the merge target 20 claimed");
        assert_eq!(prepared.roots, vec![roots_of(&[5])]);
        assert_eq!(left_out_filters(&prepared), vec![vec![20], vec![21]]);
    }

    #[test]
    fn a_local_preparation_error_still_aborts_the_confirm() {
        let result = super::prepare_confirm(&[vec![1], vec![2]], &[], 2, |filter, _| match filter {
            [1] => Err(quil_types::error::QuilError::Internal("store".into())),
            _ => Ok(super::Prepared::Roots(vec![roots_of(filter)])),
        });
        assert!(result.is_err());
    }

    #[test]
    fn a_confirm_encodes_the_shards_a_change_creates_from_each_filter_once() {
        let changes = vec![change(ShardChangeKind::Split, 1, &[10, 11]), change(ShardChangeKind::Merge, 2, &[20, 21])];
        assert_eq!(
            confirm_encoding_plan(&[vec![1], vec![20], vec![21], vec![]], &changes, 8),
            vec![
                (vec![1], vec![vec![10], vec![11]]),
                (vec![20], vec![vec![2]]),
                (vec![21], vec![]),
                (vec![], vec![]),
            ],
            "each split child from the parent's storage; a shared merge target once",
        );
        assert_eq!(confirm_encoding_plan(&[vec![1]], &changes, 9), vec![(vec![1], vec![])], "only a change applying next epoch");
    }

    const FRAME: u64 = 720;
    const BLS_KEY: &[u8] = b"prover key";
    const OWN: [u8; 32] = [7; 32];
    const OTHER: [u8; 32] = [8; 32];
    const SEEDS: [[u8; 57]; 2] = [[1; 57], [2; 57]];

    fn pubkey(seed: &[u8; 57]) -> Vec<u8> {
        quil_p2p::ed448_identity::derive_public_key(seed)
    }

    /// Stands in for the prover's BLS signer; Ed448 signs deterministically.
    fn prover_signer() -> quil_crypto::Ed448Signer {
        quil_crypto::Ed448Signer::from_bytes(&[9; 57], &pubkey(&[9; 57])).unwrap()
    }

    /// Committed GLOBAL state holding a spent marker at each address, as the
    /// merge that consumed the target stamps it for the prover it credits.
    fn global_with_markers(markers: &[([u8; 32], [u8; 32])]) -> std::sync::Arc<quil_hypergraph::HypergraphCrdt> {
        use quil_execution::hypergraph_state::{vertex_adds_discriminator, HypergraphState};
        use std::sync::Arc;
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(
            Arc::new(quil_store::RocksHypergraphStore::new(db.inner())),
            Arc::new(quil_hypergraph::testing::StubProver),
        ));
        crdt.set_forest(quil_forest::Forest::with_namespace(db.inner(), quil_store::FOREST_NAMESPACE));
        let state = HypergraphState::new(crdt.clone());
        let va_disc = vertex_adds_discriminator().unwrap();
        for (address, credited) in markers {
            let marker = quil_execution::global_intrinsic::materialize::create_spent_merge_tree(credited).unwrap();
            let blob = quil_execution::prover_registry::vertex_tree_to_blob(&marker);
            state
                .set(&quil_execution::global_schema::GLOBAL_INTRINSIC_ADDRESS[..], address, &va_disc, 1, blob)
                .unwrap();
        }
        state.commit().unwrap();
        state.abort();
        crdt.commit_with_global_cursor(1, &quil_store::encoding::global_materialized_cursor_key()).unwrap();
        crdt
    }

    fn merge_with(
        global: &std::sync::Arc<quil_hypergraph::HypergraphCrdt>,
        seeds: &[[u8; 57]],
    ) -> (Option<super::ProverSeniorityMerge>, Vec<super::ConsumedMergeTarget>) {
        super::seniority_merge(FRAME, seeds, BLS_KEY, &OWN, &prover_signer(), |address| {
            super::spent_marker(global, address)
        })
        .unwrap()
    }

    /// The merge of `seeds` as built before consumed targets were left out.
    fn merge_of(seeds: &[[u8; 57]]) -> super::ProverSeniorityMerge {
        use quil_types::crypto::Signer;
        let merge_targets: Vec<quil_execution::global_intrinsic::SeniorityMerge> = seeds
            .iter()
            .map(|seed| quil_execution::global_intrinsic::SeniorityMerge {
                signature: quil_crypto::Ed448Signer::from_bytes(seed, &pubkey(seed))
                    .unwrap()
                    .sign_with_domain(BLS_KEY, b"PROVER_SENIORITY_MERGE")
                    .unwrap(),
                key_type: quil_types::crypto::KeyType::Ed448 as u32,
                prover_public_key: pubkey(seed),
            })
            .collect();
        let mut message = FRAME.to_be_bytes().to_vec();
        for target in &merge_targets {
            message.extend_from_slice(&target.prover_public_key);
        }
        let domain = super::ProverPipeline::domain(b"PROVER_SENIORITY_MERGE").unwrap();
        super::ProverSeniorityMerge {
            frame_number: FRAME,
            public_key_signature_bls48581: Some(super::AddressedSignature {
                signature: prover_signer().sign_with_domain(&message, &domain).unwrap(),
                address: OWN.to_vec(),
            }),
            merge_targets,
        }
    }

    fn consumed_by(seed: &[u8; 57], marker: &'static str, credited: [u8; 32]) -> super::ConsumedMergeTarget {
        super::ConsumedMergeTarget { pubkey: pubkey(seed), marker, credited: Some(credited.to_vec()) }
    }

    #[test]
    fn a_merge_of_unconsumed_targets_is_unchanged() {
        let (merge, consumed) = merge_with(&global_with_markers(&[]), &SEEDS);
        assert_eq!(merge, Some(merge_of(&SEEDS)));
        assert!(consumed.is_empty());
    }

    #[test]
    fn a_target_another_prover_consumed_is_not_merged_and_names_that_prover() {
        let spent = quil_execution::global_intrinsic::materialize::spent_join_merge_address(&pubkey(&SEEDS[0])).unwrap();
        let (merge, consumed) = merge_with(&global_with_markers(&[(spent, OTHER)]), &SEEDS[..1]);
        assert_eq!(merge, None, "GLOBAL refuses a merge naming a consumed target");
        assert_eq!(consumed, vec![consumed_by(&SEEDS[0], "join merge", OTHER)]);
        let (credited_to, action) = super::consumed_target_credit(&consumed[0], &OWN);
        assert_eq!(credited_to, "prover …080808");
        assert!(action.is_some_and(|action| action.contains("restore that prover's key")), "{action:?}");
    }

    #[test]
    fn a_target_this_prover_consumed_is_not_merged_again() {
        let spent = quil_execution::global_intrinsic::materialize::spent_seniority_merge_address(&pubkey(&SEEDS[0])).unwrap();
        let (merge, consumed) = merge_with(&global_with_markers(&[(spent, OWN)]), &SEEDS[..1]);
        assert_eq!(merge, None);
        assert_eq!(consumed, vec![consumed_by(&SEEDS[0], "seniority merge", OWN)]);
        let (credited_to, action) = super::consumed_target_credit(&consumed[0], &OWN);
        assert_eq!(credited_to, "this prover");
        assert_eq!(action, None, "nothing for the operator to do");
    }

    #[test]
    fn a_merge_keeps_only_the_unconsumed_targets() {
        let spent = quil_execution::global_intrinsic::materialize::spent_seniority_merge_address(&pubkey(&SEEDS[0])).unwrap();
        let (merge, consumed) = merge_with(&global_with_markers(&[(spent, OTHER)]), &SEEDS);
        assert_eq!(merge, Some(merge_of(&SEEDS[1..])), "the prover signs the remaining target alone");
        assert_eq!(consumed, vec![consumed_by(&SEEDS[0], "seniority merge", OTHER)]);
    }

    #[test]
    fn a_consumed_target_is_reported_once_per_epoch() {
        let reports = super::ConsumedTargetReports::default();
        let target = consumed_by(&SEEDS[0], "join merge", OTHER);
        assert!(reports.due(&target, 5), "reported when found");
        assert!(!reports.due(&target, 5), "not again within the epoch");
        assert!(reports.due(&target, 6), "repeated the next epoch");
        assert!(reports.due(&consumed_by(&SEEDS[0], "join merge", OWN), 6), "a changed marker is reported at once");
    }
}
