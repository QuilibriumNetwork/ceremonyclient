//! Archive-side ingest of full app-shard frames.
//!
//! Archives don't run an `AppConsensusEngine`, but they bulk-subscribe to
//! all shard traffic (`[0xFF;32]`) and must materialize every shard's
//! state so they can serve it via HyperSync. This receives the full
//! `AppShardFrame`s published on `shard_frame_bitmask`, verifies them, and
//! materializes them — in strict frame order per shard — into the
//! archive's (global) hypergraph CRDT via its existing
//! `ExecutionEngineManager`.
//!
//! Verification (no consensus participation required):
//!   1. The header's quorum aggregate BLS cert is checked against the
//!      shard committee (active provers under the frame's address) via
//!      `BlsAppFrameValidator` — same check the consensus path uses. This
//!      proves the header (and its `requests_root`) was finalized by the
//!      shard's quorum.
//!   2. The carried `requests` are recomputed to a `requests_root` and
//!      required to equal the signed one — defends against a relay
//!      swapping requests under an otherwise-valid header.
//!
//! A frame that passes, and is admitted (certified, or linked to by a
//! certified frame), is also stored in the archive's clock store, from which
//! it serves shard frames to peers.

use std::collections::{BTreeMap, HashMap};
use std::ops::RangeInclusive;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, info, warn};

use quil_types::consensus::{AppFrameValidator, ProverRegistry as ProverRegistryTrait};
use quil_types::crypto::{BlsConstructor, FrameProver, InclusionProver};
use quil_types::proto::global::AppShardFrame;

use crate::app_engine::{compute_requests_root, materialize_app_shard_requests};
use crate::frame_validator::BlsAppFrameValidator;

pub struct ArchiveAppShardIngest {
    /// Shared with the gap fetch, which prepares a fetched frame's historical
    /// storage registrations into it before the frame reaches this ingest.
    validator: Arc<BlsAppFrameValidator>,
    execution_manager: Arc<quil_execution::ExecutionEngineManager>,
    inclusion_prover: Arc<dyn InclusionProver>,
    hypergraph: Arc<quil_hypergraph::HypergraphCrdt>,
    /// Per-shard (address) → highest frame number materialized.
    /// Lazily seeded from the durable cursor (`kv_db`) on first access so
    /// it survives restart instead of resetting to 0 and re-materializing
    /// (or skipping frames the CRDT already advanced past).
    last_materialized: HashMap<Vec<u8>, u64>,
    /// Out-of-order verified frames, buffered until the gap fills:
    /// address → (frame_number → frame).
    buffered: HashMap<Vec<u8>, HashMap<u64, AppShardFrame>>,
    /// Validated frames without a certificate, waiting for a certified
    /// descendant to link to them: address → ((frame, identity) → frame).
    held: HashMap<Vec<u8>, std::collections::BTreeMap<(u64, [u8; 32]), AppShardFrame>>,
    /// Global clock frames, for the certified world-state size app frames price from.
    clock_store: Arc<dyn quil_types::store::ClockStore>,
    /// Where to ask for a frame this archive is missing: `(shard filter, frame)`.
    /// `None` leaves a gap unrecoverable, which is what it was before.
    gap_requests: Option<tokio::sync::mpsc::Sender<(Vec<u8>, u64)>>,
    /// Where to ask, behind every request on `gap_requests`, for frames a
    /// GLOBAL frame after the executing one rewards ([`Self::prefetch_through`]).
    prefetch_requests: Option<tokio::sync::mpsc::Sender<(Vec<u8>, u64)>>,
    /// Frames asked for per address, when, and whether on `gap_requests`, so a
    /// gap that persists across many inbound frames or passes asks once.
    requested: HashMap<Vec<u8>, BTreeMap<u64, (Instant, bool)>>,
    /// Frames received whose anchoring GLOBAL frame is not stored here, per
    /// address: frame → that GLOBAL frame. Not asked for again until it is.
    awaiting_anchor: HashMap<Vec<u8>, BTreeMap<u64, u64>>,
    /// The GLOBAL frames [`Self::awaiting_anchor`] has logged waiting on.
    anchors_noted: std::collections::BTreeSet<u64>,
    /// Frames are materialized only through [`Self::materialize_through`], at
    /// the points the GLOBAL chain sequences, never on arrival.
    sequenced: bool,
    /// The frame a GLOBAL frame waits on per address, since when, and whether
    /// its header-only materialization was refused and logged.
    missing_since: HashMap<Vec<u8>, (u64, Instant, bool)>,
    /// How long a provably empty frame's body is sought before the frame is
    /// materialized from its certified header ([`EMPTY_FRAME_BODY_GRACE`]).
    empty_body_grace: Duration,
    #[cfg(test)]
    skip_header_authentication: bool,
}

const GAP_RETRY_INTERVAL: Duration = Duration::from_secs(30);
/// Retry interval while a GLOBAL frame waits on the missing frame: GLOBAL
/// execution is stalled for as long as it is missing.
const GLOBAL_WAIT_RETRY_INTERVAL: Duration = Duration::from_secs(5);
const MAX_BUFFERED_FRAMES_PER_SHARD: usize = 128;
/// Frames of one shard asked for at once while a GLOBAL frame waits on it.
/// Asked one at a time, each only once the one before it arrived, an archive
/// behind by thousands of frames per shard recovered about one frame a second:
/// QmQr15 executed one GLOBAL frame every two hours or more while the network
/// made 3.8 a minute, and fell further behind (2026-10-19).
const GAP_WINDOW: u64 = 32;
/// How far above its cursor a shard's frames are fetched for GLOBAL frames
/// after the executing one. Below the buffer bound, so prefetched frames are
/// never evicted by the frames above them, and small enough that every shard
/// read ahead holding this many frames stays within memory.
const PREFETCH_DEPTH: u64 = 64;
const _: () = assert!(PREFETCH_DEPTH < MAX_BUFFERED_FRAMES_PER_SHARD as u64);
/// Frames without a certificate held per shard until a certified descendant
/// links to them. Keyed by output identity, so a well-formed impostor cannot
/// displace the real frame at the same height.
const MAX_HELD_FRAMES_PER_SHARD: usize = 32;
/// How long GLOBAL execution waits for the body of a frame whose certified
/// header proves it carried no requests before materializing it from that
/// header. Every gap-fetch round in the meantime asks every member and archive.
const EMPTY_FRAME_BODY_GRACE: Duration = Duration::from_secs(90);

impl ArchiveAppShardIngest {
    pub fn new(
        prover_registry: Arc<dyn ProverRegistryTrait>,
        bls_constructor: Arc<dyn BlsConstructor>,
        frame_prover: Arc<dyn FrameProver>,
        execution_manager: Arc<quil_execution::ExecutionEngineManager>,
        inclusion_prover: Arc<dyn InclusionProver>,
        hypergraph: Arc<quil_hypergraph::HypergraphCrdt>,
        clock_store: Arc<dyn quil_types::store::ClockStore>,
    ) -> Self {
        Self {
            // clock_store is REQUIRED: post-genesis app frames
            // (global_frame_number > 0) use the deterministic ρ_N-bound
            // output, which the validator recomputes from the anchored global
            // frame's VDF output. Without a clock store that branch
            // (frame_validator: deterministic-output) hard-errors and the
            // archive rejects every post-genesis app frame at ingest, so it
            // never materializes app-shard state.
            validator: Arc::new(
                BlsAppFrameValidator::new(prover_registry, bls_constructor, frame_prover)
                    .with_clock_store(clock_store.clone())
                    .with_handoff_authority(hypergraph.clone()),
            ),
            clock_store,
            execution_manager,
            inclusion_prover,
            hypergraph,
            last_materialized: HashMap::new(),
            buffered: HashMap::new(),
            held: HashMap::new(),
            gap_requests: None,
            prefetch_requests: None,
            requested: HashMap::new(),
            awaiting_anchor: HashMap::new(),
            anchors_noted: std::collections::BTreeSet::new(),
            sequenced: false,
            missing_since: HashMap::new(),
            empty_body_grace: EMPTY_FRAME_BODY_GRACE,
            #[cfg(test)]
            skip_header_authentication: false,
        }
    }

    /// Materialize only at GLOBAL-sequenced points ([`Self::materialize_through`]).
    ///
    /// GLOBAL reward execution reads shard and world sizes from the state this
    /// ingest writes. Materialized on arrival, the same GLOBAL frame could
    /// credit different rewards on archives that ingested a moment apart,
    /// diverging their prover roots. Arrival-time ingest also
    /// shared the CRDT's staging with an in-place GLOBAL execution, so either
    /// commit could publish the other's partial mutations.
    pub fn sequenced(mut self) -> Self {
        self.sequenced = true;
        self
    }

    /// Ask `requests` for any app-shard frame this archive is missing.
    ///
    /// Without it a single missed frame — one produced while this node was
    /// restarting, say — is never recovered: the frames after it buffer
    /// forever, the durable cursor never advances, and that application's
    /// app-shard state is frozen for good. That is invisible while an
    /// application is whole, because a wallet reads its own node, and fatal
    /// once it splits, when a wallet's node covers only part of it and must
    /// read an archive.
    pub fn with_gap_fetch(mut self, requests: tokio::sync::mpsc::Sender<(Vec<u8>, u64)>) -> Self {
        self.gap_requests = Some(requests);
        self
    }

    /// Where [`Self::prefetch_through`] asks for frames. The fetcher serves
    /// these only when no request from [`Self::with_gap_fetch`] is waiting.
    pub fn with_prefetch(mut self, requests: tokio::sync::mpsc::Sender<(Vec<u8>, u64)>) -> Self {
        self.prefetch_requests = Some(requests);
        self
    }

    /// Where to fetch a storage registration that neither this archive's
    /// executed GLOBAL state nor its live registry holds: the one an app
    /// frame's GLOBAL anchor names when this archive's execution is behind
    /// that anchor. Executing the next GLOBAL frame first needs the app frames
    /// it rewards, so an archive that fell behind could otherwise never
    /// validate them or execute again: one sat at 869,765 for two days
    /// ("historical storage registration unavailable at epoch 1208"). The
    /// gap fetch prepares them ([`Self::validator`]); each proof is checked
    /// against the root the anchor frame declares.
    pub fn with_storage_history_source(mut self, source: crate::storage_history::GlobalVertexProofSource) -> Self {
        self.validator = match Arc::try_unwrap(self.validator) {
            Ok(validator) => Arc::new(validator.with_storage_history_source(source)),
            Err(shared) => shared,
        };
        self
    }

    /// The validator this ingest checks frames with, for preparing a frame's
    /// historical storage registrations without holding the ingest.
    pub fn validator(&self) -> Arc<BlsAppFrameValidator> {
        self.validator.clone()
    }

    /// This ingest's checks on a received frame, to run without holding the
    /// ingest ([`Self::admit_verified`]).
    pub fn verifier(&self) -> ArchiveFrameVerifier {
        ArchiveFrameVerifier {
            validator: self.validator.clone(),
            execution_manager: self.execution_manager.clone(),
            inclusion_prover: self.inclusion_prover.clone(),
            has_forest: self.hypergraph.has_forest(),
            clock_store: self.clock_store.clone(),
        }
    }

    /// Park frame `number` of `address` until GLOBAL frame `anchor`, which it
    /// is anchored to and which this archive has not stored, is stored: no
    /// request for it goes out before then ([`ArchiveFrameVerifier::missing_anchor`]).
    ///
    /// Every such frame fails validation, so asking for it again only loads
    /// the shard's members: an archive missing GLOBAL frames 907,473–907,511
    /// fetched and refused about 200 frames a second (2026-10-20).
    pub fn await_anchor(&mut self, address: &[u8], number: u64, anchor: u64) {
        if self.materialized_height(address).is_ok_and(|height| number <= height) {
            return;
        }
        self.awaiting_anchor.entry(address.to_vec()).or_default().insert(number, anchor);
        if self.anchors_noted.insert(anchor) {
            info!(anchor, frame = number, address = %hex::encode(&address[..address.len().min(8)]),
                "archive app-shard frames wait for a GLOBAL frame this archive has not stored; \
                 they are asked for again once it is");
        }
    }

    /// Read the cursor co-committed with app state. Read failures must not look
    /// like genesis and trigger reexecution against already advanced state.
    pub fn materialized_height(&mut self, address: &[u8]) -> quil_types::error::Result<u64> {
        if let Some(&h) = self.last_materialized.get(address) {
            return Ok(h);
        }
        let h = self.hypergraph.read_frame_cursor(
            &quil_store::encoding::consensus_materialized_cursor_key(address),
        )?;
        self.last_materialized.insert(address.to_vec(), h);
        Ok(h)
    }

    /// Publish in memory only after state and cursor have committed together.
    fn set_materialized_height(&mut self, address: &[u8], frame: u64) {
        self.last_materialized.insert(address.to_vec(), frame);
        if let Some(requested) = self.requested.get_mut(address) {
            *requested = requested.split_off(&(frame + 1));
            if requested.is_empty() {
                self.requested.remove(address);
            }
        }
        if let Some(waiting) = self.awaiting_anchor.get_mut(address) {
            *waiting = waiting.split_off(&(frame + 1));
            if waiting.is_empty() {
                self.awaiting_anchor.remove(address);
            }
            let awaiting = &self.awaiting_anchor;
            self.anchors_noted.retain(|anchor| awaiting.values().any(|waiting| waiting.values().any(|a| a == anchor)));
        }
        self.missing_since.remove(address);
    }

    /// Retry missing frames and deferred execution even if gossip goes quiet.
    /// Sequenced ingest is driven by GLOBAL execution instead.
    /// Committee-handoff flag day (`LegacyHistory::Discard`): before the
    /// GLOBAL frame `global_frame` executes, once it reaches activation,
    /// discard every application frame chain this archive holds (frames,
    /// per-frame records and cursors; application state kept) and what this
    /// ingest remembers of them. Runs once per store. Returns whether it did.
    pub fn discard_legacy_history_at(&mut self, global_frame: u64) -> quil_types::error::Result<bool> {
        let Some(policy) = quil_types::consensus::committee_handoff_policy()
            .filter(|policy| policy.legacy_history == quil_types::consensus::LegacyHistory::Discard)
        else {
            return Ok(false);
        };
        if global_frame < policy.activation_frame || self.clock_store.app_frame_history_discarded()?.is_some() {
            return Ok(false);
        }
        self.clock_store.discard_app_frame_history(global_frame)?;
        self.last_materialized.clear();
        self.buffered.clear();
        self.held.clear();
        self.requested.clear();
        crate::app_engine::forget_legacy_relay_boundaries();
        tracing::info!(global_frame, "committee-handoff flag day: archive discarded its legacy app frame history");
        Ok(true)
    }

    pub fn retry_pending(&mut self) {
        if self.sequenced {
            return;
        }
        let addresses: Vec<_> = self.buffered.keys().cloned().collect();
        for address in addresses {
            self.try_materialize(&address);
        }
    }

    /// Ingest a gossiped full `AppShardFrame` (prost bytes).
    pub fn ingest(&mut self, data: &[u8]) {
        let frame = match <AppShardFrame as prost::Message>::decode(data) {
            Ok(f) => f,
            Err(_) => return,
        };
        let (address, frame_number) = match frame.header.as_ref() {
            Some(h) if !h.address.is_empty() => (h.address.clone(), h.frame_number),
            _ => {
                debug!("archive ingest: shard frame missing header or empty address — dropping");
                return;
            }
        };

        // Reaching here means a full app-shard frame actually arrived on the
        // frame topic. Logged because its ABSENCE is the only symptom when an
        // archive holds no app-shard state, and every rejection below is a
        // warning — so without this, "never received" and "never published"
        // look identical from the archive's log.
        let held = match self.materialized_height(&address) {
            Ok(height) => height,
            Err(error) => {
                warn!(error = %error, "archive ingest deferred: materialized cursor unavailable");
                return;
            }
        };
        debug!(
            frame = frame_number,
            held,
            address = %hex::encode(&address[..address.len().min(8)]),
            "archive ingest: received a full app-shard frame"
        );
        // Already materialized (or older) — ignore.
        if frame_number <= held {
            return;
        }

        let verifier = self.verifier();
        if let Some(anchor) = verifier.missing_anchor(&frame) {
            self.await_anchor(&address, frame_number, anchor);
            return;
        }
        let Some(certified) = verifier.verify(&frame) else { return };
        self.admit(&address, frame, certified);
        if !self.sequenced {
            self.try_materialize(&address);
        }
    }

    /// Admit a frame [`ArchiveFrameVerifier::verify`] passed, as [`Self::ingest`]
    /// does. The gap fetch verifies the frames it recovers without holding the
    /// ingest or the message loop, which used to run every check in turn.
    pub fn admit_verified(&mut self, frame: AppShardFrame, certified: bool) {
        let Some((address, frame_number)) = frame.header.as_ref()
            .filter(|header| !header.address.is_empty())
            .map(|header| (header.address.clone(), header.frame_number))
        else {
            return;
        };
        match self.materialized_height(&address) {
            Ok(held) if frame_number > held => {}
            Ok(_) => return,
            Err(error) => {
                warn!(error = %error, "archive ingest deferred: materialized cursor unavailable");
                return;
            }
        }
        self.admit(&address, frame, certified);
        if !self.sequenced {
            self.try_materialize(&address);
        }
    }

    /// Buffer a validated frame for in-order materialization. A certified
    /// frame is buffered as is; a frame without a certificate only when the
    /// buffered frame after it links to it (`app_frame_links_to_child`), and
    /// otherwise it is held until such a frame arrives. So `buffered` only
    /// ever holds certified frames and the ancestors they authenticate.
    ///
    /// A member may build on a notarized parent before it finalizes; the
    /// child's finalization then makes the parent final with no certificate
    /// of its own. Refusing such a parent leaves archives waiting for it
    /// forever and halts GLOBAL's sequenced ingest.
    fn admit(&mut self, address: &[u8], frame: AppShardFrame, certified: bool) {
        use crate::frame_validator::app_frame_links_to_child;
        let Some(header) = frame.header.clone() else { return };
        let number = header.frame_number;
        let linked = self.buffered.get(address)
            .and_then(|buffered| buffered.get(&(number + 1)))
            .and_then(|child| child.header.as_ref())
            .is_some_and(|child| app_frame_links_to_child(&header, child));
        if !certified && !linked {
            let Ok(identity) = quil_crypto::poseidon::hash_bytes_to_32(&header.output) else { return };
            let held = self.held.entry(address.to_vec()).or_default();
            held.insert((number, identity), frame);
            while held.len() > MAX_HELD_FRAMES_PER_SHARD {
                let Some(farthest) = held.keys().next_back().copied() else { break };
                held.remove(&farthest);
            }
            return;
        }
        // Held ancestors this frame now authenticates, down the chain.
        let mut authenticated = vec![(number, frame)];
        let mut child = header;
        if let Some(held) = self.held.get_mut(address) {
            while child.frame_number > 0 {
                let below = child.frame_number - 1;
                let parent = held.range((below, [0; 32])..=(below, [0xff; 32]))
                    .find(|(_, parent)| parent.header.as_ref().is_some_and(|p| app_frame_links_to_child(p, &child)))
                    .map(|(key, _)| *key);
                let Some(key) = parent else { break };
                let parent = held.remove(&key).expect("found above");
                child = parent.header.clone().expect("held frames have headers");
                authenticated.push((below, parent));
            }
        }
        for (number, frame) in authenticated {
            self.store_for_serving(&frame);
            self.buffered.entry(address.to_vec()).or_default().insert(number, frame);
        }
        let buffered = self.buffered.entry(address.to_vec()).or_default();
        if buffered.len() > MAX_BUFFERED_FRAMES_PER_SHARD {
            if let Some(farthest) = buffered.keys().max().copied() {
                buffered.remove(&farthest);
            }
        }
    }

    /// Store an authenticated frame where this archive serves shard frames
    /// from (`get_app_shard_frame`, the latest by frame 0). Only admitted frames
    /// get here: certified ones and the ancestors a certified frame links to.
    /// The receive loop used to store every gossiped frame before this check,
    /// so one forged far-future frame could pin the head an archive serves;
    /// and frames recovered through the gap fetch were never stored at all.
    fn store_for_serving(&self, frame: &AppShardFrame) {
        let Some(header) = frame.header.as_ref() else { return };
        let Ok(selector) = quil_crypto::poseidon::hash_bytes_to_32(&header.output) else { return };
        // Two transactions: the commit reads the staged copy from the store.
        let stored = self.clock_store.new_transaction(false)
            .and_then(|txn| {
                self.clock_store.stage_shard_clock_frame(&selector, frame, txn.as_ref())?;
                txn.commit()
            })
            .and_then(|()| {
                let txn = self.clock_store.new_transaction(false)?;
                self.clock_store.commit_shard_clock_frame(&header.address, header.frame_number, &selector, txn.as_ref(), false)?;
                txn.commit()
            });
        if let Err(error) = stored {
            warn!(frame = header.frame_number, %error,
                address = %hex::encode(&header.address[..header.address.len().min(8)]),
                "archive ingest: storing a verified shard frame for serving failed");
        }
    }

    fn try_materialize(&mut self, address: &[u8]) {
        if let Err(error) = self.materialize_in_order(address, u64::MAX, &HashMap::new()) {
            warn!(error = %error, "archive materialize deferred");
        }
    }

    /// Materialize `address`'s buffered frames in order through `through`, the
    /// highest frame of that shard a GLOBAL frame about to execute rewards.
    /// `Ok(false)` while a frame at or below `through` is missing (it is
    /// requested); an error leaves the cursor where it was, for a retry.
    ///
    /// GLOBAL reward execution reads the shard and world sizes this state
    /// makes up, so every archive must hold exactly the frames the GLOBAL chain
    /// has referenced when it executes a frame: never materialize ahead of
    /// that, never execute behind it.
    pub fn materialize_through(&mut self, address: &[u8], through: u64) -> quil_types::error::Result<bool> {
        self.materialize_in_order(address, through, &HashMap::new())
    }

    /// [`Self::materialize_through`] for a GLOBAL frame that carries the
    /// certified `headers` (by frame number) of this shard. A frame among them
    /// whose body no endpoint serves is materialized from its header once
    /// the header proves the frame carried no requests
    /// ([`Self::empty_frame_from_header`]).
    pub fn materialize_through_vouched(
        &mut self,
        address: &[u8],
        through: u64,
        headers: &HashMap<u64, quil_types::proto::global::FrameHeader>,
    ) -> quil_types::error::Result<bool> {
        self.materialize_in_order(address, through, headers)
    }

    fn materialize_in_order(
        &mut self,
        address: &[u8],
        through: u64,
        vouched: &HashMap<u64, quil_types::proto::global::FrameHeader>,
    ) -> quil_types::error::Result<bool> {
        let reached = loop {
            let last = self.materialized_height(address)?;
            if last >= through {
                break true;
            }
            let Some(next) = last.checked_add(1) else { break true };
            let frame = match self.buffered.get(address).and_then(|m| m.get(&next)) {
                Some(f) => f.clone(),
                None => match self.empty_frame_from_header(address, next, vouched) {
                    Some(frame) => frame,
                    None => break false, // gap — wait for the missing frame (or sync)
                },
            };
            let fee_multiplier_vote = frame
                .header
                .as_ref()
                .map(|h| h.fee_multiplier_vote)
                .unwrap_or(0);
            let global_frame_number = frame.header.as_ref().map_or(0, |h| h.global_frame_number);
            let world_size = crate::app_engine::certified_world_size(self.clock_store.as_ref(), global_frame_number)
                .map_err(|e| quil_types::error::QuilError::ExecutionUnavailable(format!(
                    "archive materialize of frame {next}: certified world size unavailable: {e}"
                )))?;
            // Fees decide whether a token operation is admitted, so the archive
            // prices exactly as the committee did: certified header difficulty,
            // vote and anchored world size.
            let materialized = materialize_app_shard_requests(
                self.execution_manager.as_ref(),
                &frame.requests,
                next,
                frame.header.as_ref().map_or(0, |h| h.difficulty),
                world_size,
                fee_multiplier_vote,
                address,
                frame.header.as_ref().map_or(0, |h| h.global_frame_number),
            )?;
            self.set_materialized_height(address, next);
            if let Some(m) = self.buffered.get_mut(address) {
                m.remove(&next);
            }
            // Info, not debug: an archive holding app-shard state is a
            // duty, and its only positive evidence. At debug a WORKING
            // ingest is indistinguishable from one that never ran,
            // which is how "the archive attempts zero ingests" was
            // read off a log that simply never said otherwise.
            info!(
                frame = next,
                processed = materialized.processed,
                skipped = materialized.skipped,
                address = %hex::encode(address),
                "archive materialized shard frame"
            );
        };
        // Gap detection: the next-needed frame is missing while frames are
        // buffered ahead of it, or while a GLOBAL frame needs it. Ask for it
        // through `with_gap_fetch` — nothing else will deliver it, since gossip
        // carries a frame once.
        let last = *self.last_materialized.get(address).unwrap_or(&0);
        let next_needed = last + 1;
        let ahead = self.buffered.get(address).map_or(0, |m| m.keys().filter(|&&f| f > next_needed).count());
        let missing = !self.buffered.get(address).is_some_and(|m| m.contains_key(&next_needed));
        let waiting = !reached && through != u64::MAX;
        if missing && (ahead > 0 || waiting) {
            // A frame already held without a certificate needs its certified
            // descendant, not itself: ask for the first frame above the run.
            let mut wanted = next_needed;
            while self.is_held(address, wanted) {
                wanted += 1;
            }
            // While a GLOBAL frame waits, every missing frame it needs is asked
            // for at once, up to the window; otherwise the first missing frame.
            let (upto, interval) = if waiting {
                (through.min(last.saturating_add(GAP_WINDOW)).max(wanted), GLOBAL_WAIT_RETRY_INTERVAL)
            } else {
                (wanted, GAP_RETRY_INTERVAL)
            };
            let requested = self.request_frames(address, wanted..=upto, true, interval);
            if requested > 0 {
                warn!(
                    address = %hex::encode(address),
                    missing_from = next_needed,
                    requested,
                    buffered_ahead = ahead,
                    "archive app-shard frame gap awaiting recovery"
                );
            }
        }
        // Bound the buffer to frames still ahead of us. An outstanding request
        // stays: a GLOBAL frame can need a frame with nothing buffered past it,
        // and advancing the cursor clears it.
        if let Some(held) = self.held.get_mut(address) {
            held.retain(|&(frame, _), _| frame > last);
            if held.is_empty() {
                self.held.remove(address);
            }
        }
        if let Some(m) = self.buffered.get_mut(address) {
            m.retain(|&f, _| f > last);
            if m.is_empty() {
                self.buffered.remove(address);
            }
        }
        Ok(reached)
    }

    /// Ask for the frames of `address` that a GLOBAL frame after the executing
    /// one rewards, through `through` and at most [`PREFETCH_DEPTH`] above the
    /// cursor, behind every request a waiting GLOBAL frame makes. They wait in
    /// the buffer, unmaterialized, for the GLOBAL frame that sequences them.
    /// Only for a shard this archive already holds frames of: the stored GLOBAL
    /// frames this reads ahead in are not verified against executed state yet,
    /// and a header naming any other address may be forged. Returns how many
    /// frames were asked for.
    pub fn prefetch_through(&mut self, address: &[u8], through: u64) -> quil_types::error::Result<usize> {
        let last = self.materialized_height(address)?;
        let upto = through.min(last.saturating_add(PREFETCH_DEPTH));
        if last == 0 || upto <= last {
            return Ok(0);
        }
        Ok(self.request_frames(address, last + 1..=upto, false, GAP_RETRY_INTERVAL))
    }

    /// Ask for each frame of `frames` neither buffered nor held, unless it was
    /// asked for within `interval` (at this priority or above). `urgent` asks
    /// on `gap_requests`, otherwise on `prefetch_requests`. A full queue
    /// leaves the rest for the next pass.
    fn request_frames(&mut self, address: &[u8], frames: RangeInclusive<u64>, urgent: bool, interval: Duration) -> usize {
        let sender = if urgent { self.gap_requests.clone() } else { self.prefetch_requests.clone() };
        let Some(sender) = sender else { return 0 };
        let mut sent = 0;
        let mut stored: HashMap<u64, bool> = HashMap::new();
        for number in frames {
            if self.buffered.get(address).is_some_and(|buffered| buffered.contains_key(&number))
                || self.is_held(address, number)
            {
                continue;
            }
            if let Some(anchor) = self.awaiting_anchor.get(address).and_then(|waiting| waiting.get(&number)).copied() {
                let clock = &self.clock_store;
                if !*stored.entry(anchor).or_insert_with(|| clock.get_global_clock_frame_header(anchor).is_ok()) {
                    continue;
                }
                // The anchor arrived: the frame can validate now, so ask at once.
                if let Some(waiting) = self.awaiting_anchor.get_mut(address) {
                    waiting.remove(&number);
                    if waiting.is_empty() {
                        self.awaiting_anchor.remove(address);
                    }
                }
                self.anchors_noted.remove(&anchor);
                if let Some(requested) = self.requested.get_mut(address) {
                    requested.remove(&number);
                }
            }
            let due = self.requested.get(address).and_then(|requested| requested.get(&number))
                .is_none_or(|&(at, was_urgent)| (urgent && !was_urgent) || at.elapsed() >= interval);
            if !due {
                continue;
            }
            if sender.try_send((address.to_vec(), number)).is_err() {
                break;
            }
            self.requested.entry(address.to_vec()).or_default().insert(number, (Instant::now(), urgent));
            sent += 1;
        }
        sent
    }

    /// Whether a frame `number` of `address` is held without a certificate.
    fn is_held(&self, address: &[u8], number: u64) -> bool {
        self.held.get(address)
            .is_some_and(|held| held.range((number, [0; 32])..=(number, [0xff; 32])).next().is_some())
    }

    /// The frame `number` of `address`, rebuilt from the certified header the
    /// executing GLOBAL frame carries, when no endpoint has served its body for
    /// [`EMPTY_FRAME_BODY_GRACE`] and the header proves the frame carried no
    /// requests (an all-zero `requests_root`, which the frame's output binds).
    ///
    /// Materializing a frame reads only its requests and header fields, so
    /// such a frame leaves exactly the state its body would, on every archive,
    /// whether or not it holds the body. The rebuilt frame lacks the storage
    /// attestation, so it is never stored for serving. A frame that carried
    /// requests cannot be rebuilt and keeps waiting for its body.
    ///
    /// GLOBAL 903,302 rewarded frame 2063 of a shard whose body no member or
    /// archive served, and every archive's execution stopped there
    /// (2026-10-19); decided 2026-10-19.
    fn empty_frame_from_header(
        &mut self,
        address: &[u8],
        number: u64,
        vouched: &HashMap<u64, quil_types::proto::global::FrameHeader>,
    ) -> Option<AppShardFrame> {
        let header = vouched.get(&number)
            .filter(|header| header.address == address && header.frame_number == number)?;
        if !requests_root_is_empty(&header.requests_root) {
            return None;
        }
        let since = match self.missing_since.get(address) {
            Some(&(frame, since, _)) if frame == number => since,
            _ => {
                self.missing_since.insert(address.to_vec(), (number, Instant::now(), false));
                return None;
            }
        };
        if since.elapsed() < self.empty_body_grace {
            return None;
        }
        let frame = AppShardFrame { header: Some(header.clone()), requests: Vec::new(), storage_attestation: None };
        if let Err(reason) = self.authenticate_header(&frame) {
            if let Some(entry) = self.missing_since.get_mut(address).filter(|entry| !entry.2) {
                entry.2 = true;
                warn!(frame = number, address = %hex::encode(address), %reason,
                    "archive cannot materialize an empty shard frame from its header: the header does not authenticate");
            }
            return None;
        }
        warn!(frame = number, address = %hex::encode(address), waited_secs = since.elapsed().as_secs(),
            "archive materialized an empty shard frame from its certified header: no endpoint served its body");
        Some(frame)
    }

    /// Certificate and deterministic output (which binds `requests_root`),
    /// without the storage attestation the body would carry.
    fn authenticate_header(&self, frame: &AppShardFrame) -> Result<(), String> {
        #[cfg(test)]
        if self.skip_header_authentication {
            return Ok(());
        }
        match self.validator.validate_certified_without_storage(frame) {
            Ok(true) => Ok(()),
            Ok(false) => Err("certificate refused".into()),
            Err(error) => Err(error.to_string()),
        }
    }
}

/// The checks a received app-shard frame passes before [`ArchiveAppShardIngest`]
/// admits it, apart from the ingest, so they can run without holding it.
#[derive(Clone)]
pub struct ArchiveFrameVerifier {
    validator: Arc<BlsAppFrameValidator>,
    execution_manager: Arc<quil_execution::ExecutionEngineManager>,
    inclusion_prover: Arc<dyn InclusionProver>,
    has_forest: bool,
    clock_store: Arc<dyn quil_types::store::ClockStore>,
}

impl ArchiveFrameVerifier {
    /// The GLOBAL frame `frame` is anchored to, when this archive has not
    /// stored it. Validation derives the frame's output from that GLOBAL
    /// frame, so it cannot pass before the GLOBAL frame is stored.
    pub fn missing_anchor(&self, frame: &AppShardFrame) -> Option<u64> {
        let anchor = frame.header.as_ref()?.global_frame_number;
        (anchor > 0 && self.clock_store.get_global_clock_frame_header(anchor).is_err()).then_some(anchor)
    }

    /// `Some(certified)` when `frame` may be admitted, `certified` saying
    /// whether it carries its own certificate; `None` (logged) when refused.
    pub fn verify(&self, frame: &AppShardFrame) -> Option<bool> {
        let header = frame.header.as_ref().filter(|header| !header.address.is_empty())?;
        let (address, frame_number, requests_root) = (&header.address, header.frame_number, &header.requests_root);
        // 1. Quorum BLS cert + VDF against the shard committee. A frame with
        // no certificate of its own is one a certified descendant finalized
        // (see `admit`): it gets every check but the quorum here, and is only
        // ever materialized once a certified frame links to it.
        let certified = has_certificate(frame);
        let validated = if certified { self.validator.validate(frame) } else { self.validator.validate_proposal(frame) };
        match validated {
            Ok(true) => {}
            Ok(false) => {
                warn!(
                    frame = frame_number,
                    address = %hex::encode(&address[..address.len().min(8)]),
                    "archive ingest: shard frame REJECTED — quorum cert / signature validation returned false"
                );
                return None;
            }
            Err(e) => {
                // Elevated from debug: this is the primary "why wasn't my shard
                // frame accepted" signal. A common cause is the anchored GLOBAL
                // frame being absent from the local clock store (ρ_N unavailable,
                // frame_validator.rs), which chains directly off any global-frame
                // propagation gap.
                warn!(
                    frame = frame_number,
                    address = %hex::encode(&address[..address.len().min(8)]),
                    certified,
                    error = %e,
                    "archive ingest: shard frame validation FAILED — rejecting"
                );
                return None;
            }
        }

        // 2. Verify the carried requests recompute to the signed root.
        let canonical: Vec<Vec<u8>> = frame
            .requests
            .iter()
            .filter_map(|b| crate::consensus_wire::proto_message_bundle_to_canonical_bytes(b).ok())
            .collect();
        if canonical.len() != frame.requests.len() {
            warn!(
                frame = frame_number,
                address = %hex::encode(&address[..address.len().min(8)]),
                converted = canonical.len(),
                total = frame.requests.len(),
                "archive ingest: {} of {} request bundles failed canonical conversion (consensus-wire converter gap) — rejecting frame",
                frame.requests.len().saturating_sub(canonical.len()),
                frame.requests.len(),
            );
            return None;
        }
        let recomputed = match compute_requests_root(
            &canonical,
            address,
            frame_number,
            Some(self.execution_manager.as_ref()),
            Some(self.inclusion_prover.as_ref()),
            self.has_forest,
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!(
                    frame = frame_number,
                    address = %hex::encode(&address[..address.len().min(8)]),
                    error = %e,
                    "archive ingest: requests_root recompute errored — rejecting frame"
                );
                return None;
            }
        };
        if recomputed != *requests_root {
            warn!(frame = frame_number, "archive ingest: requests_root mismatch — rejecting");
            return None;
        }

        Some(certified)
    }
}

/// The `requests_root` of a frame with no requests: zero bytes, 32 on the
/// forest path and 64 on the legacy one ([`compute_requests_root`]).
fn requests_root_is_empty(root: &[u8]) -> bool {
    matches!(root.len(), 32 | 64) && root.iter().all(|&byte| byte == 0)
}

/// Frames above a gap-fetched frame without a certificate that the gap
/// fetch follows to the certified descendant making it final: as many as
/// the ingest holds without one.
const MAX_LINKED_RUN: usize = MAX_HELD_FRAMES_PER_SHARD;

fn has_certificate(frame: &AppShardFrame) -> bool {
    frame.header.as_ref()
        .and_then(|header| header.public_key_signature_bls48581.as_ref())
        .is_some_and(|signature| !signature.signature.is_empty())
}

/// Prepare the historical storage registrations a gap-fetched frame's
/// validation needs ([`BlsAppFrameValidator::prepare_storage_history`]),
/// returning the frames to hand the ingest and whether preparing succeeded.
///
/// A frame without a certificate is final only through a certified
/// descendant, and its registrations are fetched only once that descendant's
/// certificate and every link down to the frame check out, as a member's
/// archive replay does. The run up to the descendant comes from `fetch` and
/// is handed over with the frame. The gap fetch used to prepare certified
/// frames only, so the ingest refused such a frame on every retry and never
/// asked for its descendant: one archive sat at GLOBAL 870,123 for 20 hours
/// on frames 291–292 of a shard (2026-10-12).
pub async fn prepare_gap_fetched<F, Fut>(
    validator: &BlsAppFrameValidator,
    frame: AppShardFrame,
    mut fetch: F,
) -> (Vec<AppShardFrame>, quil_types::error::Result<()>)
where
    F: FnMut(u64) -> Fut,
    Fut: std::future::Future<Output = Option<AppShardFrame>>,
{
    use quil_types::error::QuilError;
    let mut run = vec![frame];
    while let Some(parent) = run.last().filter(|frame| !has_certificate(frame)).and_then(|frame| frame.header.clone()) {
        if run.len() > MAX_LINKED_RUN {
            return (run, Err(QuilError::ExecutionUnavailable(format!(
                "no certified descendant within {MAX_LINKED_RUN} frames"))));
        }
        let Some(child) = fetch(parent.frame_number + 1).await else {
            return (run, Err(QuilError::ExecutionUnavailable(format!(
                "certified descendant unavailable: frame {} not fetched", parent.frame_number + 1))));
        };
        if !child.header.as_ref().is_some_and(|child| crate::frame_validator::app_frame_links_to_child(&parent, child)) {
            return (run, Err(QuilError::InvalidArgument(format!(
                "fetched frame {} does not link to frame {}", parent.frame_number + 1, parent.frame_number))));
        }
        run.push(child);
    }
    let prepared = async {
        let (descendant, linked) = run.split_last().expect("the run holds the fetched frame");
        if !linked.is_empty() && !validator.validate_certified_without_storage(descendant)? {
            return Err(QuilError::InvalidSignature("certified descendant of a gap-fetched frame is invalid".into()));
        }
        validator.prepare_storage_history(descendant).await?;
        for frame in linked.iter().rev() {
            validator.prepare_storage_history_of_linked(frame).await?;
        }
        Ok(())
    }.await;
    (run, prepared)
}

#[cfg(test)]
mod tests {
    use super::*;
    use quil_types::proto::global::FrameHeader;

    fn fixture() -> (ArchiveAppShardIngest, Arc<quil_hypergraph::testing::MemStore>) {
        fixture_with_clock(None)
    }

    /// The fixture, serving from `clock` when given.
    fn fixture_with_clock(
        clock: Option<Arc<dyn quil_types::store::ClockStore>>,
    ) -> (ArchiveAppShardIngest, Arc<quil_hypergraph::testing::MemStore>) {
        let store = Arc::new(quil_hypergraph::testing::MemStore::new());
        let inclusion = Arc::new(quil_types::crypto::NoopInclusionProver);
        let crdt = Arc::new(quil_hypergraph::HypergraphCrdt::new(store.clone(), inclusion.clone()));
        let crypto = quil_execution::testing::NoopExecutionCrypto::new();
        let manager = Arc::new(quil_execution::ExecutionEngineManager::new(
            inclusion.clone(), crypto.key_manager, crdt.clone(), crypto.circuit_compiler,
            crypto.clock_store.clone(), Arc::new(quil_execution::testing::NoopHypergraphConfigResolver), false,
        ));
        (ArchiveAppShardIngest::new(
            Arc::new(crate::test_support::TestProverRegistry::new()),
            Arc::new(quil_crypto::FalconKeyConstructor),
            Arc::new(quil_crypto::WesolowskiFrameProver::new(2048)),
            manager, inclusion, crdt, clock.unwrap_or(crypto.clock_store),
        ), store)
    }

    // These fixtures enter after certificate validation to exercise the gap
    // queue and the actual materializer/cursor commit independently of crypto.
    fn verified_frame(filter: &[u8], number: u64) -> AppShardFrame {
        AppShardFrame {
            header: Some(FrameHeader { address: filter.to_vec(), frame_number: number, ..Default::default() }),
            requests: Vec::new(),
            storage_attestation: None,
        }
    }

    /// Frames `1..=to` of one shard, each naming the one before it.
    fn chain(filter: &[u8], to: u64) -> Vec<AppShardFrame> {
        let mut frames: Vec<AppShardFrame> = Vec::new();
        for number in 1..=to {
            let mut frame = verified_frame(filter, number);
            let header = frame.header.as_mut().unwrap();
            header.rank = number * 2;
            header.output = vec![number as u8; 32];
            if let Some(parent) = frames.last() {
                header.parent_selector = quil_crypto::poseidon::hash_bytes_to_32(&parent.header.as_ref().unwrap().output)
                    .unwrap().to_vec();
            }
            frames.push(frame);
        }
        frames
    }

    /// A frame the committee notarized and a certified descendant finalized
    /// has no certificate of its own. It is held until a certified frame
    /// links to it, then materialized in order; one that does not link never is.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_uncertified_frame_is_admitted_only_under_a_certified_descendant() {
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let frames = chain(&filter, 5);
        let buffered = |ingest: &ArchiveAppShardIngest| {
            let mut numbers: Vec<u64> = ingest.buffered.get(&filter).map_or(Vec::new(), |m| m.keys().copied().collect());
            numbers.sort();
            numbers
        };

        // The ancestor first: held, then promoted by its certified child.
        let (mut ingest, _) = fixture();
        ingest.admit(&filter, frames[0].clone(), true);
        ingest.admit(&filter, frames[1].clone(), false);
        assert_eq!(buffered(&ingest), vec![1]);
        ingest.admit(&filter, frames[2].clone(), true);
        assert_eq!(buffered(&ingest), vec![1, 2, 3]);
        ingest.retry_pending();
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 3);

        // The child first: the ancestor is buffered on arrival. A chain of
        // two held frames is promoted by one certified descendant.
        let (mut ingest, _) = fixture();
        ingest.admit(&filter, frames[2].clone(), true);
        ingest.admit(&filter, frames[1].clone(), false);
        assert_eq!(buffered(&ingest), vec![2, 3]);
        let (mut ingest, _) = fixture();
        ingest.admit(&filter, frames[1].clone(), false);
        ingest.admit(&filter, frames[2].clone(), false);
        ingest.admit(&filter, frames[3].clone(), true);
        assert_eq!(buffered(&ingest), vec![2, 3, 4]);

        // An impostor at the same height never links, whatever arrives.
        let (mut ingest, _) = fixture();
        let mut impostor = frames[1].clone();
        impostor.header.as_mut().unwrap().output = vec![0xee; 32];
        ingest.admit(&filter, impostor, false);
        ingest.admit(&filter, frames[2].clone(), true);
        assert_eq!(buffered(&ingest), vec![3]);

        // A held run asks for the certified frame above it, not for itself.
        let (mut ingest, _) = fixture();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        ingest = ingest.with_gap_fetch(tx);
        ingest.admit(&filter, frames[0].clone(), true);
        ingest.admit(&filter, frames[4].clone(), true);
        ingest.admit(&filter, frames[1].clone(), false);
        ingest.admit(&filter, frames[2].clone(), false);
        ingest.retry_pending();
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 1);
        assert_eq!(rx.try_recv().unwrap(), (filter.clone(), 4));
    }

    /// An admitted frame is stored where the archive serves shard frames from.
    /// A frame without a certificate is stored only once a certified frame
    /// links to it, and an impostor at its height never is.
    #[tokio::test(flavor = "multi_thread")]
    async fn admitted_frames_are_stored_for_serving() {
        use quil_types::store::ClockStore as _;
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let frames = chain(&filter, 3);
        let clock = Arc::new(quil_store::testing::InMemoryClockStore::new());
        let (mut ingest, _) = fixture_with_clock(Some(clock.clone()));
        let served = |number| clock.get_shard_clock_frame(&filter, number, false).ok();
        ingest.admit(&filter, frames[0].clone(), true);
        assert_eq!(served(1), Some(frames[0].clone()));
        let mut impostor = frames[1].clone();
        impostor.header.as_mut().unwrap().output = vec![0xee; 32];
        ingest.admit(&filter, impostor, false);
        ingest.admit(&filter, frames[1].clone(), false);
        assert_eq!(served(2), None, "held until a certified frame links to it");
        ingest.admit(&filter, frames[2].clone(), true);
        assert_eq!(served(2), Some(frames[1].clone()));
        assert_eq!(served(3), Some(frames[2].clone()));
        assert_eq!(clock.get_latest_shard_clock_frame(&filter).unwrap(), frames[2]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_failed_gap_fetch_retries_then_drains_and_restores_its_cursor() {
        let (mut ingest, _) = fixture();
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        ingest = ingest.with_gap_fetch(tx);
        ingest.buffered.entry(filter.clone()).or_default().insert(2, verified_frame(&filter, 2));
        ingest.retry_pending();
        assert_eq!(rx.try_recv().unwrap(), (filter.clone(), 1));
        ingest.retry_pending();
        assert!(rx.try_recv().is_err(), "one active request per gap");
        // The peer had no frame / connection failed. No new gossip arrives.
        ingest.requested.get_mut(&filter).unwrap().get_mut(&1).unwrap().0 = Instant::now() - GAP_RETRY_INTERVAL;
        ingest.retry_pending();
        assert_eq!(rx.try_recv().unwrap(), (filter.clone(), 1), "timer retries without inbound frames");
        ingest.buffered.get_mut(&filter).unwrap().insert(1, verified_frame(&filter, 1));
        ingest.retry_pending();
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 2);
        assert!(ingest.buffered.is_empty());
        assert!(ingest.requested.is_empty());
        ingest.last_materialized.clear();
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 2, "recover the co-committed cursor");
    }

    /// Sequenced ingest materializes only when GLOBAL execution asks, in
    /// order, exactly through the frame asked for, and asks for a missing
    /// frame a GLOBAL frame needs even with nothing buffered past it.
    #[tokio::test(flavor = "multi_thread")]
    async fn sequenced_ingest_materializes_only_through_what_global_execution_asks() {
        let (ingest, _) = fixture();
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (tx, mut rx) = tokio::sync::mpsc::channel(4);
        let mut ingest = ingest.with_gap_fetch(tx).sequenced();
        for number in 1..=3 {
            ingest.buffered.entry(filter.clone()).or_default().insert(number, verified_frame(&filter, number));
        }
        ingest.retry_pending();
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 0, "nothing on arrival or on the timer");

        assert!(ingest.materialize_through(&filter, 2).unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 2, "exactly through the frame asked for");
        assert!(ingest.buffered[&filter].contains_key(&3));

        assert!(!ingest.materialize_through(&filter, 4).unwrap(), "frame 4 is missing");
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 3);
        assert_eq!(rx.try_recv().unwrap(), (filter.clone(), 4), "requested with nothing buffered past it");
        assert!(!ingest.materialize_through(&filter, 4).unwrap());
        assert!(rx.try_recv().is_err(), "one active request per gap");
        // GLOBAL execution is waiting: the request is repeated sooner than an
        // ordinary gap's.
        ingest.requested.get_mut(&filter).unwrap().get_mut(&4).unwrap().0 = Instant::now() - GLOBAL_WAIT_RETRY_INTERVAL;
        assert!(!ingest.materialize_through(&filter, 4).unwrap());
        assert_eq!(rx.try_recv().unwrap(), (filter.clone(), 4), "retried while GLOBAL waits");

        ingest.buffered.entry(filter.clone()).or_default().insert(4, verified_frame(&filter, 4));
        assert!(ingest.materialize_through(&filter, 4).unwrap());
        assert!(ingest.materialize_through(&filter, 1).unwrap(), "behind the cursor is already there");
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 4);
    }

    /// A GLOBAL frame waiting on a shard asks for every missing frame it needs
    /// at once, up to the window, and each only once per retry interval. Frames
    /// later GLOBAL frames need are asked for behind those, up to the prefetch
    /// depth, only for a shard already held, and are not materialized until a
    /// GLOBAL frame sequences them. A frame only prefetched is asked for again
    /// at once when a GLOBAL frame comes to wait on it.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_waiting_global_frame_asks_for_a_window_of_frames_and_prefetches_behind_it() {
        let (ingest, _) = fixture();
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let (prefetch_tx, mut prefetch_rx) = tokio::sync::mpsc::channel(256);
        let mut ingest = ingest.with_gap_fetch(tx).with_prefetch(prefetch_tx).sequenced();
        let drain = |rx: &mut tokio::sync::mpsc::Receiver<(Vec<u8>, u64)>| {
            let mut frames = Vec::new();
            while let Ok((address, number)) = rx.try_recv() {
                assert_eq!(address, filter);
                frames.push(number);
            }
            frames
        };

        assert_eq!(ingest.prefetch_through(&filter, 50).unwrap(), 0, "no frame of this shard held yet");
        ingest.buffered.entry(filter.clone()).or_default().insert(1, verified_frame(&filter, 1));
        ingest.buffered.entry(filter.clone()).or_default().insert(5, verified_frame(&filter, 5));
        assert!(!ingest.materialize_through(&filter, 200).unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 1);
        let window: Vec<u64> = (2..=1 + GAP_WINDOW).filter(|&number| number != 5).collect();
        assert_eq!(drain(&mut rx), window, "the window above the cursor, less what is buffered");
        assert!(!ingest.materialize_through(&filter, 200).unwrap());
        assert!(drain(&mut rx).is_empty(), "each asked once per interval");

        assert_eq!(ingest.prefetch_through(&filter, 500).unwrap(), (PREFETCH_DEPTH - GAP_WINDOW) as usize);
        assert_eq!(drain(&mut prefetch_rx), (2 + GAP_WINDOW..=1 + PREFETCH_DEPTH).collect::<Vec<_>>(),
            "behind the window, to the prefetch depth");
        assert_eq!(ingest.prefetch_through(&filter, 500).unwrap(), 0);

        for number in 2..=40 {
            ingest.buffered.entry(filter.clone()).or_default().insert(number, verified_frame(&filter, number));
        }
        assert!(ingest.materialize_through(&filter, 20).unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 20, "prefetched frames wait for their GLOBAL frame");
        assert!(ingest.requested[&filter].keys().all(|&number| number > 20), "requests at or below the cursor are dropped");
        assert!(!ingest.materialize_through(&filter, 60).unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 40);
        assert_eq!(drain(&mut rx), (41..=60).collect::<Vec<_>>(), "prefetched frames a GLOBAL frame waits on");
        assert!(drain(&mut prefetch_rx).is_empty());

        ingest.admit_verified(verified_frame(&filter, 3), true);
        assert!(ingest.buffered.get(&filter).is_none_or(|buffered| !buffered.contains_key(&3)), "below the cursor");
        ingest.admit_verified(verified_frame(&filter, 41), true);
        assert!(ingest.buffered[&filter].contains_key(&41));
    }

    /// A frame anchored to a GLOBAL frame this archive has not stored cannot
    /// validate, so it is not asked for again, however long a GLOBAL frame
    /// waits on it, until that GLOBAL frame is stored; then it is asked for
    /// at once.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_frame_anchored_to_a_missing_global_frame_is_asked_for_once_that_frame_is_stored() {
        let db = quil_store::RocksDb::open_in_memory().unwrap();
        let clock: Arc<dyn quil_types::store::ClockStore> = Arc::new(quil_store::RocksClockStore::new(db.inner()));
        let (ingest, _) = fixture_with_clock(Some(clock.clone()));
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (tx, mut rx) = tokio::sync::mpsc::channel(256);
        let mut ingest = ingest.with_gap_fetch(tx).sequenced();
        let drain = |rx: &mut tokio::sync::mpsc::Receiver<(Vec<u8>, u64)>| {
            let mut frames = Vec::new();
            while let Ok((_, number)) = rx.try_recv() {
                frames.push(number);
            }
            frames
        };
        let all_due = |ingest: &mut ArchiveAppShardIngest| {
            for request in ingest.requested.get_mut(&filter).unwrap().values_mut() {
                request.0 = Instant::now() - GLOBAL_WAIT_RETRY_INTERVAL;
            }
        };
        ingest.buffered.entry(filter.clone()).or_default().insert(1, verified_frame(&filter, 1));
        assert!(!ingest.materialize_through(&filter, 3).unwrap());
        assert_eq!(drain(&mut rx), vec![2, 3]);

        let mut anchored = verified_frame(&filter, 2);
        anchored.header.as_mut().unwrap().global_frame_number = 907_473;
        let verifier = ingest.verifier();
        assert_eq!(verifier.missing_anchor(&anchored), Some(907_473));
        assert_eq!(verifier.missing_anchor(&verified_frame(&filter, 2)), None, "a frame anchored to no GLOBAL frame");
        ingest.await_anchor(&filter, 2, 907_473);
        ingest.await_anchor(&filter, 1, 907_473);
        assert_eq!(ingest.awaiting_anchor[&filter].keys().copied().collect::<Vec<_>>(), vec![2], "not at or below the cursor");

        all_due(&mut ingest);
        assert!(!ingest.materialize_through(&filter, 3).unwrap());
        assert_eq!(drain(&mut rx), vec![3], "the parked frame is not asked for again");

        let txn = clock.new_transaction(false).unwrap();
        clock.put_global_clock_frame(&quil_types::proto::global::GlobalFrame {
            header: Some(quil_types::proto::global::GlobalFrameHeader { frame_number: 907_473, ..Default::default() }),
            requests: Vec::new(),
        }, txn.as_ref()).unwrap();
        txn.commit().unwrap();
        assert_eq!(verifier.missing_anchor(&anchored), None);
        assert!(!ingest.materialize_through(&filter, 3).unwrap());
        assert_eq!(drain(&mut rx), vec![2], "asked for at once, ahead of its retry interval");
        assert!(ingest.awaiting_anchor.is_empty() && ingest.anchors_noted.is_empty());

        ingest.await_anchor(&filter, 3, 907_480);
        for number in 2..=3 {
            ingest.buffered.entry(filter.clone()).or_default().insert(number, verified_frame(&filter, number));
        }
        assert!(ingest.materialize_through(&filter, 3).unwrap());
        assert!(ingest.awaiting_anchor.is_empty() && ingest.anchors_noted.is_empty(),
            "frames at or below the cursor no longer wait");
    }

    /// A frame no endpoint serves is materialized from the certified header the
    /// GLOBAL frame carries only when that header proves it had no requests,
    /// and only after the body has been sought for the grace period. A frame
    /// that had requests, or one the GLOBAL frame does not carry, keeps waiting.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_lost_empty_frame_is_materialized_from_its_certified_header() {
        let (ingest, _) = fixture();
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        let (tx, _rx) = tokio::sync::mpsc::channel(16);
        let mut ingest = ingest.with_gap_fetch(tx).sequenced();
        ingest.skip_header_authentication = true;
        ingest.buffered.entry(filter.clone()).or_default().insert(1, verified_frame(&filter, 1));
        let header = |number: u64, requests_root: Vec<u8>| quil_types::proto::global::FrameHeader {
            requests_root,
            ..verified_frame(&filter, number).header.unwrap()
        };
        let vouched = |header: quil_types::proto::global::FrameHeader| HashMap::from([(header.frame_number, header)]);

        let empty = vouched(header(2, vec![0; 32]));
        assert!(!ingest.materialize_through_vouched(&filter, 2, &empty).unwrap(), "the body is sought first");
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 1);
        ingest.missing_since.get_mut(&filter).unwrap().1 = Instant::now() - EMPTY_FRAME_BODY_GRACE;
        assert!(!ingest.materialize_through(&filter, 2).unwrap(), "only a header the GLOBAL frame carries");
        assert!(ingest.materialize_through_vouched(&filter, 2, &empty).unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 2);
        assert!(ingest.missing_since.is_empty());

        let with_requests = vouched(header(3, vec![7; 32]));
        assert!(!ingest.materialize_through_vouched(&filter, 3, &with_requests).unwrap());
        assert!(ingest.missing_since.is_empty(), "a frame with requests is never rebuilt");
        let legacy_empty = vouched(header(3, vec![0; 64]));
        assert!(!ingest.materialize_through_vouched(&filter, 3, &legacy_empty).unwrap());
        ingest.missing_since.get_mut(&filter).unwrap().1 = Instant::now() - EMPTY_FRAME_BODY_GRACE;
        let elsewhere = HashMap::from([(3, quil_types::proto::global::FrameHeader {
            address: vec![9; 32], ..header(3, vec![0; 64])
        })]);
        assert!(!ingest.materialize_through_vouched(&filter, 3, &elsewhere).unwrap(), "another shard's header");
        assert!(ingest.materialize_through_vouched(&filter, 3, &legacy_empty).unwrap());
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 3);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn failed_commit_keeps_the_frame_for_a_timer_retry() {
        let (mut ingest, store) = fixture();
        let filter = quil_execution::domains::QUIL_TOKEN.to_vec();
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 0);
        ingest.buffered.entry(filter.clone()).or_default().insert(1, verified_frame(&filter, 1));
        store.fail_commit_setup(true, false);
        ingest.retry_pending();
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 0);
        assert!(ingest.buffered[&filter].contains_key(&1));
        ingest.last_materialized.clear();
        assert!(ingest.materialized_height(&filter).is_err(), "a failed cursor read is not genesis");
        store.fail_commit_setup(false, false);
        ingest.retry_pending();
        assert_eq!(ingest.materialized_height(&filter).unwrap(), 1);
    }
}
