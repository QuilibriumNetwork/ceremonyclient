//! App-shard production KPIs: `GET /shards/production` and the `/stats`
//! `app_shards` summary.
//!
//! A [`ProductionIndex`] walks stored GLOBAL frames together with their
//! materialization outcomes. An app frame counts as applied only when the
//! bundle carrying its header materialized `Succeeded`, and only once per
//! `(shard filter, app frame)`: a header carried twice, in one GLOBAL frame or
//! a later one, is one applied app frame. Seal drain headers (in
//! `committee_handoff` bundles) execute app frames without reward; they are
//! counted apart and never make a shard producing.
//!
//! The index keeps its own cursor, `indexed_through`, advanced by
//! [`run_indexer`] at most [`MAX_FRAMES_PER_TICK`] frames per tick. The same
//! task combines the index with the registry census and committed handoff
//! state into a [`Snapshot`] after each advance; the handlers only read the
//! latest one. Responses name both the head and `indexed_through`, so index
//! lag is told apart from network lag. Windows are counted in GLOBAL frames;
//! seconds follow from the median frame interval.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::{Digest, Sha256};

use quil_types::consensus::MIN_SHARD_CONSENSUS_PROVERS;
use quil_types::error::QuilError;
use quil_types::proto::global::{message_request::Request, FrameHeader, GlobalFrame};
use quil_types::store::{ClockStore, RequestOutcome, RequestStatus};

/// GLOBAL frames the rate counters cover.
pub const WINDOW_FRAMES: u64 = 240;
/// GLOBAL frames re-read on start (one epoch); also how long a shard with no
/// inclusion keeps its last applied app frame.
pub const REBUILD_FRAMES: u64 = quil_types::consensus::EPOCH_LENGTH_FRAMES;
/// A frame still missing, or still without outcomes while it carries
/// requests, once GLOBAL has materialized this many frames past it, is
/// counted as unknown and stepped over (the outcome write is best-effort).
pub const OUTCOME_GRACE: u64 = 32;
/// Most frames indexed per tick, so catch-up never bursts.
pub const MAX_FRAMES_PER_TICK: u64 = 32;
/// Indexer tick.
pub const TICK: Duration = Duration::from_secs(2);
/// Cache-Control of `/shards/production`: about one GLOBAL frame.
pub const CACHE_CONTROL: &str = "public, max-age=15";
/// The snapshot is rebuilt after every advance, and at least this often
/// while the index waits, so the head and the census stay current.
pub const SNAPSHOT_REFRESH: Duration = Duration::from_secs(15);
/// A wait beyond the grace is warned about again this often.
pub const STALL_REPEAT: Duration = Duration::from_secs(600);
/// Snapshot builds are summarized this often; slower builds are logged at
/// most once per minute.
pub const BUILD_SUMMARY: Duration = Duration::from_secs(600);
pub const SLOW_BUILD: Duration = Duration::from_secs(1);

/// Reads `(committee size, signers)` from a CW finalization certificate
/// (the bytes after the `CWCT` prefix). UNAUTHENTICATED: only applied
/// headers, whose certificate materialization verified, are read.
pub type SignerReader = fn(&[u8]) -> Option<(usize, usize)>;
/// Reads the `(filter, app frame)` of each drain header in a
/// `committee_handoff` payload.
pub type DrainReader = fn(&[u8]) -> Vec<(Vec<u8>, u64)>;

pub fn cw_signers(cert: &[u8]) -> Option<(usize, usize)> {
    quil_cw_consensus::app_cert::unverified_signers(cert)
}

pub fn seal_drain_headers(payload: &[u8]) -> Vec<(Vec<u8>, u64)> {
    use quil_execution::global_intrinsic::{frame_header, handoff::SealSubmission};
    let Ok(sealed) = SealSubmission::from_canonical_bytes(payload) else {
        return Vec::new();
    };
    sealed
        .drain
        .iter()
        .filter_map(|bytes| frame_header::FrameHeader::from_canonical_bytes(bytes).ok())
        .map(|header| (header.address, header.frame_number))
        .collect()
}

/// The decoders the index applies to request payloads; injected so tests
/// need no real certificates.
#[derive(Clone, Copy)]
pub struct Decoders {
    pub signers: SignerReader,
    pub drains: DrainReader,
}

impl Default for Decoders {
    fn default() -> Self {
        Self { signers: cw_signers, drains: seal_drain_headers }
    }
}

/// Who signed an applied header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signers {
    /// CW certificate: the signing committee's size and its signers.
    Certificate { committee: usize, signed: usize },
    /// Legacy BLS aggregate: the bitmask's popcount; the committee size is
    /// not in the header.
    Legacy { signed: usize },
    Unreadable,
}

impl Signers {
    fn read(header: &FrameHeader, reader: SignerReader) -> Self {
        let Some(sig) = header.public_key_signature_bls48581.as_ref() else {
            return Signers::Unreadable;
        };
        match quil_cw_consensus::app_cert::unwrap_cert_from_header(&sig.signature) {
            Some(cert) => reader(cert).map_or(Signers::Unreadable, |(committee, signed)| {
                Signers::Certificate { committee, signed }
            }),
            None => Signers::Legacy {
                signed: sig.bitmask.iter().map(|b| b.count_ones() as usize).sum(),
            },
        }
    }

    fn signed(&self) -> Option<u64> {
        match *self {
            Signers::Certificate { signed, .. } | Signers::Legacy { signed } => Some(signed as u64),
            Signers::Unreadable => None,
        }
    }

    fn committee(&self) -> Option<u64> {
        match *self {
            Signers::Certificate { committee, .. } => Some(committee as u64),
            _ => None,
        }
    }
}

/// The highest app frame of a shard GLOBAL applied, where and how.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LastApplied {
    pub app_frame: u64,
    pub global_frame: u64,
    pub rank: u64,
    pub signers: Signers,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    /// A `Succeeded` header; `new` when its app frame is above every app
    /// frame applied before it.
    Applied { new: bool },
    /// A `Rejected`, `Failed` or `Skipped` header.
    NotApplied,
    /// A header whose bundle has no recorded outcome.
    Unknown,
    /// A drain header above the shard's executed app frames.
    Drained,
}

struct Inclusion {
    filter: Arc<[u8]>,
    kind: Kind,
    /// Fee total of a newly applied header, else 0.
    fee: u128,
}

struct FrameEntry {
    frame: u64,
    timestamp: Option<i64>,
    /// Never stored: no shard's production in it is known.
    missing: bool,
    /// Carries requests without (all) outcomes: its headers are unknown.
    outcomes_missing: bool,
    inclusions: Vec<Inclusion>,
}

#[derive(Default)]
struct ShardAgg {
    max_applied: Option<u64>,
    /// Highest app frame applied or drained, and the GLOBAL frame it was.
    max_executed: Option<u64>,
    executed_at: u64,
    last: Option<LastApplied>,
    /// GLOBAL frame of the latest inclusion.
    touched: u64,
}

/// Window counters of one shard.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WindowCounts {
    /// Distinct app frames newly applied.
    pub applied: u64,
    /// `Succeeded` shard headers, re-inclusions included.
    pub inclusions: u64,
    pub not_applied: u64,
    pub unknown: u64,
    pub drained: u64,
    pub fees: u128,
}

/// What the index holds for one shard.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShardView {
    pub window: WindowCounts,
    pub last: Option<LastApplied>,
}

/// The index as the snapshot reads it.
#[derive(Clone, Debug, Default)]
pub struct IndexView {
    pub indexed_through: Option<u64>,
    /// The window spans `WINDOW_FRAMES` indexed frames, none missing, and
    /// the index is not waiting beyond the grace.
    pub window_complete: bool,
    /// The frame the index has waited for beyond the grace.
    pub waiting_frame: Option<u64>,
    pub missing_frames: u64,
    pub outcome_less_frames: u64,
    /// Median of consecutive GLOBAL header timestamp differences (ms).
    pub median_frame_interval_ms: Option<i64>,
    pub shards: HashMap<Vec<u8>, ShardView>,
}

/// Index of applied app frames over the latest GLOBAL frames.
pub struct ProductionIndex {
    decoders: Decoders,
    /// Frame indexed next when nothing is indexed yet.
    start: u64,
    first_indexed: Option<u64>,
    indexed_through: Option<u64>,
    window: VecDeque<FrameEntry>,
    shards: HashMap<Arc<[u8]>, ShardAgg>,
}

/// What one [`ProductionIndex::advance`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Advance {
    pub indexed: u64,
    /// Frames stepped over as never stored.
    pub missing: Vec<u64>,
    /// Frames stepped over without outcomes.
    pub outcome_less: Vec<u64>,
    /// The frame the index waits for (not stored yet, or not materialized).
    pub waiting: Option<u64>,
    /// GLOBAL's materialized frame, when this advance read it.
    pub materialized: Option<u64>,
    pub error: Option<String>,
}

/// Frames and outcomes as the index reads them.
pub trait FrameSource {
    /// The stored frame, `None` when it is not stored.
    fn frame(&self, number: u64) -> quil_types::error::Result<Option<GlobalFrame>>;
    /// Its per-bundle outcomes, empty until it materializes.
    fn outcomes(&self, number: u64) -> Vec<RequestOutcome>;
}

pub struct StoreSource<'a>(pub &'a dyn ClockStore);

impl FrameSource for StoreSource<'_> {
    fn frame(&self, number: u64) -> quil_types::error::Result<Option<GlobalFrame>> {
        match self.0.get_global_clock_frame(number) {
            Ok(frame) => Ok(Some(frame)),
            Err(QuilError::NotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn outcomes(&self, number: u64) -> Vec<RequestOutcome> {
        self.0.get_global_clock_frame_outcomes(number).unwrap_or_default()
    }
}

impl ProductionIndex {
    /// An empty index that starts at GLOBAL frame `start`.
    pub fn new(start: u64, decoders: Decoders) -> Self {
        Self {
            decoders,
            start,
            first_indexed: None,
            indexed_through: None,
            window: VecDeque::new(),
            shards: HashMap::new(),
        }
    }

    pub fn indexed_through(&self) -> Option<u64> {
        self.indexed_through
    }

    fn next_frame(&self) -> u64 {
        self.indexed_through.map_or(self.start, |t| t.saturating_add(1))
    }

    /// Index frames from the next one through `head`, at most `max` of
    /// them. Stops at a frame that is not stored or carries requests without
    /// outcomes, unless `materialized()` (GLOBAL's materialized frame, read
    /// once and only when needed) is [`OUTCOME_GRACE`] frames past it: then
    /// the frame is indexed as unknown.
    pub fn advance(
        &mut self,
        source: &dyn FrameSource,
        head: u64,
        max: u64,
        materialized: &mut dyn FnMut() -> Option<u64>,
    ) -> Advance {
        let mut out = Advance::default();
        let mut cursor: Option<Option<u64>> = None;
        let mut past_grace = |n: u64| {
            let through: Option<u64> = *cursor.get_or_insert_with(|| materialized());
            through.is_some_and(|m| m >= n.saturating_add(OUTCOME_GRACE))
        };
        while out.indexed < max {
            let n = self.next_frame();
            if n > head {
                break;
            }
            let frame = match source.frame(n) {
                Ok(frame) => frame.filter(|f| f.header.as_ref().is_some_and(|h| h.frame_number == n)),
                Err(e) => {
                    out.error = Some(e.to_string());
                    break;
                }
            };
            match frame {
                None => {
                    if !past_grace(n) {
                        out.waiting = Some(n);
                        break;
                    }
                    self.apply_missing(n);
                    out.missing.push(n);
                }
                Some(frame) => {
                    let outcomes =
                        if frame.requests.is_empty() { Vec::new() } else { source.outcomes(n) };
                    if !frame.requests.is_empty() && outcomes.is_empty() {
                        if !past_grace(n) {
                            out.waiting = Some(n);
                            break;
                        }
                        self.apply(&frame, None);
                        out.outcome_less.push(n);
                    } else {
                        self.apply(&frame, Some(outcomes.as_slice()));
                    }
                }
            }
            out.indexed += 1;
        }
        out.materialized = cursor.flatten();
        out
    }

    /// Index one GLOBAL frame. `outcomes` aligns to `frame.requests`; `None`
    /// (or a short list) leaves the uncovered headers unknown. Frames at or
    /// below `indexed_through` are ignored; skipped frames count as missing.
    pub fn apply(&mut self, frame: &GlobalFrame, outcomes: Option<&[RequestOutcome]>) -> bool {
        let Some(header) = frame.header.as_ref() else { return false };
        let n = header.frame_number;
        if !self.begin(n) {
            return false;
        }
        let outcomes_missing = !frame.requests.is_empty()
            && outcomes.is_none_or(|o| o.len() < frame.requests.len());
        let mut inclusions = Vec::new();
        for (i, bundle) in frame.requests.iter().enumerate() {
            let status = outcomes.and_then(|o| o.get(i)).map(|o| &o.status);
            for request in &bundle.requests {
                match &request.request {
                    Some(Request::Shard(shard)) => inclusions.push(self.include_shard(n, shard, status)),
                    Some(Request::CommitteeHandoff(payload)) if status == Some(&RequestStatus::Succeeded) => {
                        for (filter, app_frame) in (self.decoders.drains)(payload) {
                            if let Some(inclusion) = self.include_drain(n, &filter, app_frame) {
                                inclusions.push(inclusion);
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        self.push(FrameEntry {
            frame: n,
            timestamp: Some(header.timestamp),
            missing: false,
            outcomes_missing,
            inclusions,
        });
        true
    }

    /// Index frame `n` as missing (never stored).
    pub fn apply_missing(&mut self, n: u64) -> bool {
        if !self.begin(n) {
            return false;
        }
        self.push(FrameEntry::missing(n));
        true
    }

    fn begin(&mut self, n: u64) -> bool {
        match self.indexed_through {
            Some(t) if n <= t => return false,
            Some(t) if n - t > WINDOW_FRAMES => {
                self.window.clear();
                self.first_indexed = Some(n);
            }
            Some(t) => {
                for gap in t + 1..n {
                    self.window.push_back(FrameEntry::missing(gap));
                }
            }
            None => self.first_indexed = Some(n),
        }
        true
    }

    fn push(&mut self, entry: FrameEntry) {
        let through = entry.frame;
        self.window.push_back(entry);
        self.indexed_through = Some(through);
        while self.window.front().is_some_and(|e| e.frame.saturating_add(WINDOW_FRAMES) <= through) {
            self.window.pop_front();
        }
        self.forget_before(through.saturating_sub(REBUILD_FRAMES));
    }

    /// Forget what a restart's rebuild of the last `REBUILD_FRAMES` frames
    /// would not know: shards with no inclusion after `horizon`, and applied
    /// or executed app frames recorded at or before it. A continuous index
    /// and a rebuilt one then agree.
    fn forget_before(&mut self, horizon: u64) {
        self.shards.retain(|_, agg| agg.touched > horizon);
        for agg in self.shards.values_mut() {
            if agg.last.is_some_and(|l| l.global_frame <= horizon) {
                agg.last = None;
                agg.max_applied = None;
            }
            if agg.max_executed.is_some() && agg.executed_at <= horizon {
                agg.max_executed = agg.last.map(|l| l.app_frame);
                agg.executed_at = agg.last.map_or(0, |l| l.global_frame);
            }
        }
    }

    fn intern(&mut self, filter: &[u8], global_frame: u64) -> Arc<[u8]> {
        let key = match self.shards.get_key_value(filter) {
            Some((key, _)) => key.clone(),
            None => {
                let key: Arc<[u8]> = filter.into();
                self.shards.insert(key.clone(), ShardAgg::default());
                key
            }
        };
        if let Some(agg) = self.shards.get_mut(&key) {
            agg.touched = agg.touched.max(global_frame);
        }
        key
    }

    fn include_shard(&mut self, n: u64, shard: &FrameHeader, status: Option<&RequestStatus>) -> Inclusion {
        let filter = self.intern(&shard.address, n);
        let reader = self.decoders.signers;
        let agg = self.shards.get_mut(&filter).expect("interned");
        let (kind, fee) = match status {
            Some(RequestStatus::Succeeded) => {
                let new = agg.max_applied.is_none_or(|max| shard.frame_number > max);
                let mut fee = 0;
                if new {
                    agg.max_applied = Some(shard.frame_number);
                    if agg.max_executed.is_none_or(|m| shard.frame_number > m) {
                        agg.max_executed = Some(shard.frame_number);
                        agg.executed_at = n;
                    }
                    agg.last = Some(LastApplied {
                        app_frame: shard.frame_number,
                        global_frame: n,
                        rank: shard.rank,
                        signers: Signers::read(shard, reader),
                    });
                    fee = quil_execution::global_intrinsic::frame_header::fee_total_from_bytes(&shard.fee_total);
                }
                (Kind::Applied { new }, fee)
            }
            Some(_) => (Kind::NotApplied, 0),
            None => (Kind::Unknown, 0),
        };
        Inclusion { filter, kind, fee }
    }

    fn include_drain(&mut self, n: u64, filter: &[u8], app_frame: u64) -> Option<Inclusion> {
        let filter = self.intern(filter, n);
        let agg = self.shards.get_mut(&filter).expect("interned");
        if agg.max_executed.is_some_and(|max| app_frame <= max) {
            return None;
        }
        agg.max_executed = Some(app_frame);
        agg.executed_at = n;
        Some(Inclusion { filter, kind: Kind::Drained, fee: 0 })
    }

    pub fn window_complete(&self) -> bool {
        let (Some(first), Some(through)) = (self.first_indexed, self.indexed_through) else {
            return false;
        };
        through - first + 1 >= WINDOW_FRAMES && !self.window.iter().any(|e| e.missing)
    }

    /// Median of consecutive header timestamp differences over the window.
    pub fn median_frame_interval_ms(&self) -> Option<i64> {
        let mut diffs: Vec<i64> = self
            .window
            .iter()
            .zip(self.window.iter().skip(1))
            .filter(|(a, b)| b.frame == a.frame + 1)
            .filter_map(|(a, b)| Some(b.timestamp? - a.timestamp?))
            .collect();
        if diffs.is_empty() {
            return None;
        }
        diffs.sort_unstable();
        Some(diffs[(diffs.len() - 1) / 2])
    }

    /// The window counters and last applied app frame of every shard.
    pub fn view(&self) -> IndexView {
        let mut shards: HashMap<Vec<u8>, ShardView> = self
            .shards
            .iter()
            .map(|(f, agg)| (f.to_vec(), ShardView { window: WindowCounts::default(), last: agg.last }))
            .collect();
        for entry in &self.window {
            for inclusion in &entry.inclusions {
                let Some(shard) = shards.get_mut(&*inclusion.filter) else { continue };
                let w = &mut shard.window;
                match inclusion.kind {
                    Kind::Applied { new } => {
                        w.inclusions += 1;
                        if new {
                            w.applied += 1;
                            w.fees = w.fees.saturating_add(inclusion.fee);
                        }
                    }
                    Kind::NotApplied => w.not_applied += 1,
                    Kind::Unknown => w.unknown += 1,
                    Kind::Drained => w.drained += 1,
                }
            }
        }
        IndexView {
            indexed_through: self.indexed_through,
            window_complete: self.window_complete(),
            waiting_frame: None,
            missing_frames: self.window.iter().filter(|e| e.missing).count() as u64,
            outcome_less_frames: self.window.iter().filter(|e| e.outcomes_missing).count() as u64,
            median_frame_interval_ms: self.median_frame_interval_ms(),
            shards,
        }
    }

    /// Approximate heap bytes the index holds.
    pub fn heap_bytes(&self) -> usize {
        let window: usize = self
            .window
            .iter()
            .map(|e| std::mem::size_of::<FrameEntry>() + e.inclusions.capacity() * std::mem::size_of::<Inclusion>())
            .sum();
        let shards: usize = self
            .shards
            .keys()
            .map(|f| f.len() + 16 + std::mem::size_of::<(Arc<[u8]>, ShardAgg)>() + 8)
            .sum();
        window + shards
    }
}

impl FrameEntry {
    fn missing(frame: u64) -> Self {
        Self { frame, timestamp: None, missing: true, outcomes_missing: false, inclusions: Vec::new() }
    }
}

// ---------------------------------------------------------------------------
// Classification and response
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    /// The window is not fully indexed, holds a missing frame, or the
    /// shard has headers of unknown outcome and none applied: no claim.
    NoData,
    Producing,
    /// Fewer effectively active members than a certificate needs.
    BelowQuorum,
    /// Enough active members, no applied app frame in the window. Can be a
    /// lifecycle phase (handoff, activation, sync): no stall claim.
    StaffedNotProducing,
}

impl Class {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "no_data" => Some(Class::NoData),
            "producing" => Some(Class::Producing),
            "below_quorum" => Some(Class::BelowQuorum),
            "staffed_not_producing" => Some(Class::StaffedNotProducing),
            _ => None,
        }
    }
}

/// Classes, exclusive and in this order. An applied app frame is positive
/// evidence, so it outranks the shard's headers of unknown outcome.
pub fn classify(window_complete: bool, applied_in_window: u64, unknown_in_window: u64, active_members: u64) -> Class {
    if !window_complete {
        Class::NoData
    } else if applied_in_window > 0 {
        Class::Producing
    } else if unknown_in_window > 0 {
        Class::NoData
    } else if active_members < MIN_SHARD_CONSENSUS_PROVERS {
        Class::BelowQuorum
    } else {
        Class::StaffedNotProducing
    }
}

/// A shard's committed handoff head: its executed tip and session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Committed {
    pub app_head: u64,
    pub generation: u64,
    pub members: u64,
}

/// Where the snapshot's grid (the live set and the grid digest) comes from.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GridSource {
    /// The shards store's rows: current on an archive, whose materializer
    /// records splits and merges.
    #[default]
    LocalStore,
    /// The node's archive shard-info cache. A regular node's shards store
    /// keeps the genesis grid (it materializes no GLOBAL frames), so its
    /// current grid is the last archive `GetAppShards` answer.
    ArchiveCache,
}

/// The node's archive shard-info cache: each filter the last archive
/// refresh listed, with its byte size and data-shard count; `None` before
/// the first refresh answers.
pub type ArchiveGridProvider = Arc<dyn Fn() -> Option<HashMap<Vec<u8>, (u64, u64)>> + Send + Sync>;

/// The grid a snapshot classifies against.
#[derive(Clone, Debug, Default)]
pub struct GridView {
    pub source: GridSource,
    /// The `/provers/shards` set over this grid; empty when unavailable.
    pub live: BTreeSet<Vec<u8>>,
    /// The QUIL grid's filters (see [`grid_filters`]); `None` when
    /// unavailable.
    pub grid: Option<BTreeSet<Vec<u8>>>,
    /// Why the grid is unavailable.
    pub unavailable: Option<&'static str>,
}

const NO_STORE_GRID: &str = "the shards store holds no QUIL grid row";
const NO_CACHE: &str = "no archive shard-info refresh has answered yet";
const NO_CACHE_GRID: &str = "the archive shard-info cache lists no QUIL grid shard";

/// The grid from the shards store, for an archive: its rows and the
/// shard sizes `compute_shard_sizes` reads (lowercase hex keys).
pub fn grid_from_store(
    registry: &[Vec<u8>],
    sizes: &HashMap<String, (num_bigint::BigInt, u64)>,
    rows: &[quil_types::store::ShardInfo],
) -> GridView {
    let grid = grid_filters(rows);
    if grid.is_empty() {
        return GridView { source: GridSource::LocalStore, unavailable: Some(NO_STORE_GRID), ..Default::default() };
    }
    GridView {
        source: GridSource::LocalStore,
        live: live_filters(registry.iter().map(Vec::as_slice), sizes),
        grid: Some(grid),
        unavailable: None,
    }
}

/// The grid from the node's archive shard-info cache, for a regular node.
/// Without an answer it is unavailable, so no inclusion reads off-grid
/// against the genesis grid.
pub fn grid_from_cache(registry: &[Vec<u8>], cache: Option<HashMap<Vec<u8>, (u64, u64)>>) -> GridView {
    let Some(cache) = cache.filter(|c| !c.is_empty()) else {
        return GridView { source: GridSource::ArchiveCache, live: BTreeSet::new(), grid: None, unavailable: Some(NO_CACHE) };
    };
    let grid = quil_grid(cache.keys().map(Vec::as_slice));
    if grid.is_empty() {
        return GridView { source: GridSource::ArchiveCache, unavailable: Some(NO_CACHE_GRID), ..Default::default() };
    }
    let sizes: HashMap<String, (num_bigint::BigInt, u64)> = cache
        .iter()
        .map(|(filter, (bytes, data_shards))| (hex::encode(filter), (num_bigint::BigInt::from(*bytes), *data_shards)))
        .collect();
    GridView {
        source: GridSource::ArchiveCache,
        live: live_filters(registry.iter().map(Vec::as_slice), &sizes),
        grid: Some(grid),
        unavailable: None,
    }
}

/// What the response combines with the index.
pub struct Inputs<'a> {
    pub head_frame: u64,
    /// The live set and the grid.
    pub grid: &'a GridView,
    /// Effectively active allocations by filter.
    pub active: &'a HashMap<Vec<u8>, u64>,
    /// Shards in a full coverage halt.
    pub halted: &'a BTreeSet<Vec<u8>>,
    pub committed: &'a HashMap<Vec<u8>, Committed>,
    /// QUIL subunits as a decimal QUIL string.
    pub quil: fn(u128) -> String,
}

#[derive(Clone, Debug, Serialize)]
pub struct WindowInfo {
    pub head_frame: u64,
    pub indexed_through: Option<u64>,
    pub window_frames: u64,
    pub window_complete: bool,
    /// The frame the index has waited for beyond the grace (not stored or
    /// not materialized); the window reads incomplete meanwhile.
    pub index_waiting_frame: Option<u64>,
    /// From self-reported GLOBAL header timestamps.
    pub median_frame_interval_ms: Option<i64>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct ClassCounts {
    pub no_data: u64,
    pub producing: u64,
    pub below_quorum: u64,
    pub staffed_not_producing: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Summary {
    /// Denominator of the class counts: the `/provers/shards` set.
    pub live_shards: u64,
    pub classes: ClassCounts,
    pub applied_in_window: u64,
    pub inclusions_in_window: u64,
    pub not_applied_in_window: u64,
    pub unknown_outcome_in_window: u64,
    pub drained_in_window: u64,
    /// Shard headers in the window for filters off the live set; `null`
    /// while the grid is unavailable.
    pub off_grid_inclusions_in_window: Option<u64>,
    /// Frames never stored: every shard reads `no_data` while one is in
    /// the window.
    pub missing_frames_in_window: u64,
    /// Frames without (all) outcomes: shards with headers in them and none
    /// applied read `no_data`.
    pub outcome_less_frames_in_window: u64,
    /// Fees only, not rewards.
    pub fees_relayed_in_window_quil: String,
    /// The QUIL grid's rows (frozen ones included), from `grid_source`, and
    /// their digest as #816's archive shard-list check and #817's
    /// `qclient node archive shards` compute it, to tell archives' grids
    /// apart. Not a denominator: rows, not live shards. `null` while
    /// unavailable, with the reason in `grid_unavailable`.
    pub grid_source: GridSource,
    pub grid_shards: Option<u64>,
    pub grid_digest: Option<String>,
    pub grid_unavailable: Option<&'static str>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ShardProduction {
    pub filter: String,
    pub class: Class,
    pub last_applied_app_frame: Option<u64>,
    pub last_applied_global_frame: Option<u64>,
    pub last_applied_rank: Option<u64>,
    pub signers_last: Option<u64>,
    pub committee_last: Option<u64>,
    /// GLOBAL's executed tip of the head session (drains included).
    pub committed_app_head: Option<u64>,
    pub session_generation: Option<u64>,
    pub session_members: Option<u64>,
    pub active_members: u64,
    pub applied_in_window: u64,
    pub inclusions_in_window: u64,
    pub not_applied_in_window: u64,
    pub unknown_outcome_in_window: u64,
    pub drained_in_window: u64,
    pub fees_relayed_in_window_quil: String,
    pub coverage_halt: bool,
}

#[derive(Clone, Debug)]
pub struct ProductionReport {
    pub window: WindowInfo,
    pub summary: Summary,
    /// Sorted by filter.
    pub shards: Vec<ShardProduction>,
}

#[derive(Serialize)]
pub struct ProductionResponse<'a> {
    #[serde(flatten)]
    pub window: &'a WindowInfo,
    pub summary: &'a Summary,
    pub shards: Vec<&'a ShardProduction>,
}

/// The `/stats` `app_shards` object.
#[derive(Clone, Debug, Serialize)]
pub struct AppShardsStats {
    #[serde(flatten)]
    pub window: WindowInfo,
    #[serde(flatten)]
    pub summary: Summary,
}

impl ProductionReport {
    /// The response for an optional class and (lowercase hex) filter.
    pub fn response(&self, class: Option<Class>, filter: Option<&str>) -> ProductionResponse<'_> {
        ProductionResponse {
            window: &self.window,
            summary: &self.summary,
            shards: self
                .shards
                .iter()
                .filter(|s| class.is_none_or(|c| s.class == c))
                .filter(|s| filter.is_none_or(|f| s.filter == f))
                .collect(),
        }
    }

    pub fn stats(&self) -> AppShardsStats {
        AppShardsStats { window: self.window.clone(), summary: self.summary.clone() }
    }
}

/// The live (`/provers/shards`) set: registry filters on the current grid,
/// plus grid shards holding data without provers. `sizes` is keyed by
/// lowercase hex filter, as `compute_shard_sizes` builds it.
pub fn live_filters<'a>(
    registry: impl IntoIterator<Item = &'a [u8]>,
    sizes: &HashMap<String, (num_bigint::BigInt, u64)>,
) -> BTreeSet<Vec<u8>> {
    let mut live: BTreeSet<Vec<u8>> = registry
        .into_iter()
        .filter(|f| sizes.contains_key(&hex::encode(f)))
        .map(<[u8]>::to_vec)
        .collect();
    for (filter, (size, _)) in sizes {
        if size.sign() != num_bigint::Sign::NoSign {
            if let Ok(f) = hex::decode(filter) {
                live.insert(f);
            }
        }
    }
    live
}

/// Short digest of a sorted filter list: SHA-256 over each filter,
/// length-prefixed (u32 big-endian), first 4 bytes in lowercase hex. A copy of
/// #816's `ShardList::digest` (quil-rpc's archive shard-list check), so the
/// explorer and a node print equal digests for equal lists; share one
/// function once both are merged.
pub fn grid_digest(filters: &BTreeSet<Vec<u8>>) -> String {
    let mut hasher = Sha256::new();
    for filter in filters {
        hasher.update((filter.len() as u32).to_be_bytes());
        hasher.update(filter);
    }
    hex::encode(&hasher.finalize()[..4])
}

/// Combine the index with the census and committed state.
pub fn assemble(view: &IndexView, inputs: &Inputs) -> ProductionReport {
    let window = WindowInfo {
        head_frame: inputs.head_frame,
        indexed_through: view.indexed_through,
        window_frames: WINDOW_FRAMES,
        window_complete: view.window_complete,
        index_waiting_frame: view.waiting_frame,
        median_frame_interval_ms: view.median_frame_interval_ms,
    };
    let empty = ShardView::default();
    let mut classes = ClassCounts::default();
    let mut totals = WindowCounts::default();
    let live = &inputs.grid.live;
    let mut shards = Vec::with_capacity(live.len());
    for filter in live {
        let shard = view.shards.get(filter).unwrap_or(&empty);
        let active = inputs.active.get(filter).copied().unwrap_or(0);
        let class = classify(view.window_complete, shard.window.applied, shard.window.unknown, active);
        match class {
            Class::NoData => classes.no_data += 1,
            Class::Producing => classes.producing += 1,
            Class::BelowQuorum => classes.below_quorum += 1,
            Class::StaffedNotProducing => classes.staffed_not_producing += 1,
        }
        let w = &shard.window;
        totals.applied += w.applied;
        totals.inclusions += w.inclusions;
        totals.not_applied += w.not_applied;
        totals.unknown += w.unknown;
        totals.drained += w.drained;
        totals.fees = totals.fees.saturating_add(w.fees);
        let committed = inputs.committed.get(filter);
        shards.push(ShardProduction {
            filter: hex::encode(filter),
            class,
            last_applied_app_frame: shard.last.map(|l| l.app_frame),
            last_applied_global_frame: shard.last.map(|l| l.global_frame),
            last_applied_rank: shard.last.map(|l| l.rank),
            signers_last: shard.last.and_then(|l| l.signers.signed()),
            committee_last: shard.last.and_then(|l| l.signers.committee()),
            committed_app_head: committed.map(|c| c.app_head),
            session_generation: committed.map(|c| c.generation),
            session_members: committed.map(|c| c.members),
            active_members: active,
            applied_in_window: w.applied,
            inclusions_in_window: w.inclusions,
            not_applied_in_window: w.not_applied,
            unknown_outcome_in_window: w.unknown,
            drained_in_window: w.drained,
            fees_relayed_in_window_quil: (inputs.quil)(w.fees),
            coverage_halt: inputs.halted.contains(filter),
        });
    }
    let off_grid: u64 = view
        .shards
        .iter()
        .filter(|(f, _)| !live.contains(*f))
        .map(|(_, s)| s.window.inclusions + s.window.not_applied + s.window.unknown)
        .sum();
    let grid = inputs.grid.grid.as_ref().filter(|_| inputs.grid.unavailable.is_none());
    let summary = Summary {
        live_shards: live.len() as u64,
        classes,
        applied_in_window: totals.applied,
        inclusions_in_window: totals.inclusions,
        not_applied_in_window: totals.not_applied,
        unknown_outcome_in_window: totals.unknown,
        drained_in_window: totals.drained,
        off_grid_inclusions_in_window: grid.map(|_| off_grid),
        missing_frames_in_window: view.missing_frames,
        outcome_less_frames_in_window: view.outcome_less_frames,
        fees_relayed_in_window_quil: (inputs.quil)(totals.fees),
        grid_source: inputs.grid.source,
        grid_shards: grid.map(|g| g.len() as u64),
        grid_digest: grid.map(grid_digest),
        grid_unavailable: inputs.grid.unavailable,
    };
    ProductionReport { window, summary, shards }
}

/// The latest response, built by the indexer task.
pub struct Snapshot {
    pub report: ProductionReport,
    /// The unselected response body.
    pub body: Vec<u8>,
}

impl Snapshot {
    pub fn new(report: ProductionReport) -> Self {
        let mut body = serde_json::to_vec(&report.response(None, None)).unwrap_or_else(|_| b"null".to_vec());
        body.push(b'\n');
        Self { report, body }
    }
}

/// Whether the indexer rebuilds the snapshot: after the index view changed,
/// or once the last build is [`SNAPSHOT_REFRESH`] old.
pub fn snapshot_due(view_changed: bool, last_build: Option<Instant>, now: Instant) -> bool {
    view_changed || last_build.is_none_or(|at| now.saturating_duration_since(at) >= SNAPSHOT_REFRESH)
}

/// Stage durations of one snapshot build.
#[derive(Clone, Copy, Debug, Default)]
pub struct BuildTimings {
    /// Live set, shard sizes and grid; cached for 180 s, so mostly zero.
    pub shard_sets: Duration,
    /// Registry provers and the effectively active census.
    pub census: Duration,
    pub halts: Duration,
    /// Committed snapshot capture and the head session reads.
    pub committed: Duration,
    pub assemble: Duration,
    pub total: Duration,
    pub grid_source: GridSource,
    pub grid_unavailable: Option<&'static str>,
}

fn param<'a>(params: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    params.get(name).map(|s| s.trim()).filter(|s| !s.is_empty())
}

/// `?class=` (any case) and `?filter=` (hex, returned lowercase) of
/// `/shards/production`; empty values select nothing.
pub fn parse_selection(params: &HashMap<String, String>) -> Result<(Option<Class>, Option<String>), &'static str> {
    let class = match param(params, "class") {
        None => None,
        Some(c) => Some(Class::parse(&c.to_lowercase()).ok_or("invalid class")?),
    };
    let filter = match param(params, "filter") {
        None => None,
        Some(h) => Some(hex::encode(hex::decode(h).map_err(|_| "invalid filter")?)),
    };
    Ok((class, filter))
}

/// The QUIL grid's filters as an archive answers `GetAppShards` for the
/// QUIL shard key: every shards-store row under it, frozen rows (under a
/// pending split or merge) included, each as `shard_prefix_to_filter(L2,
/// prefix)`. QUIL only, as #817's `qclient node archive shards` queries it
/// and as #816 lists it on mainnet nodes, whose stores hold only that key,
/// so the digests compare. Other apps' rows are left out.
pub fn grid_filters(rows: &[quil_types::store::ShardInfo]) -> BTreeSet<Vec<u8>> {
    rows.iter()
        .filter(|row| row.shard_key.len() == 35 && row.shard_key[3..35] == quil_execution::domains::QUIL_TOKEN)
        .map(|row| quil_forest::shard_prefix_to_filter(&row.shard_key[3..35], &row.prefix))
        .filter(|filter| !filter.is_empty())
        .collect()
}

/// The QUIL grid's filters among `filters` (an archive answer's list).
pub fn quil_grid<'a>(filters: impl IntoIterator<Item = &'a [u8]>) -> BTreeSet<Vec<u8>> {
    filters
        .into_iter()
        .filter(|filter| filter.starts_with(&quil_execution::domains::QUIL_TOKEN))
        .map(<[u8]>::to_vec)
        .collect()
}

/// A wait beyond the grace: the index stopped at a frame the head is
/// [`OUTCOME_GRACE`] or more frames past.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StallEvent {
    Started { frame: u64 },
    Persisting { frame: u64, waited: Duration },
    Ended { frame: u64, waited: Duration },
}

struct Stall {
    frame: u64,
    since: Instant,
    warned: Instant,
}

#[derive(Default)]
pub struct StallTracker {
    current: Option<Stall>,
}

impl StallTracker {
    pub fn waiting_frame(&self) -> Option<u64> {
        self.current.as_ref().map(|s| s.frame)
    }

    /// Note this tick's wait: start, repeat every [`STALL_REPEAT`], end.
    pub fn observe(&mut self, waiting: Option<u64>, head: u64, now: Instant) -> Option<StallEvent> {
        let beyond = waiting.filter(|&n| head >= n.saturating_add(OUTCOME_GRACE));
        match (beyond, self.current.as_mut()) {
            (Some(frame), None) => {
                self.current = Some(Stall { frame, since: now, warned: now });
                Some(StallEvent::Started { frame })
            }
            (Some(frame), Some(stall)) => {
                stall.frame = frame;
                if now.saturating_duration_since(stall.warned) < STALL_REPEAT {
                    return None;
                }
                stall.warned = now;
                Some(StallEvent::Persisting { frame, waited: now.saturating_duration_since(stall.since) })
            }
            (None, Some(stall)) => {
                let event = StallEvent::Ended { frame: stall.frame, waited: now.saturating_duration_since(stall.since) };
                self.current = None;
                Some(event)
            }
            (None, None) => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Indexer task
// ---------------------------------------------------------------------------

fn materialized_frame(state: &crate::ExplorerState) -> Option<u64> {
    quil_execution::global_intrinsic::handoff::CommittedView::capture(&state.crdt)
        .ok()
        .map(|view| view.frame())
}

/// The indexer task's state, moved to a blocking worker for each tick.
#[derive(Default)]
struct Indexer {
    index: Option<ProductionIndex>,
    stall: StallTracker,
    sets: crate::handlers::ShardSets,
    last_build: Option<Instant>,
}

struct Tick {
    rebuild: bool,
    advance: Advance,
    stall: Option<StallEvent>,
    build: Option<(BuildTimings, u64)>,
    next: u64,
    through: Option<u64>,
}

impl Indexer {
    fn tick(&mut self, state: &crate::ExplorerState, head: u64) -> Tick {
        let rebuild = self.index.is_none();
        let index = self
            .index
            .get_or_insert_with(|| ProductionIndex::new(head.saturating_sub(REBUILD_FRAMES - 1), Decoders::default()));
        let max = if rebuild { u64::MAX } else { MAX_FRAMES_PER_TICK };
        let source = StoreSource(state.clock_store.as_ref());
        let advance = index.advance(&source, head, max, &mut || materialized_frame(state));
        let stall = self.stall.observe(advance.waiting, head, Instant::now());
        let view_changed = rebuild || advance.indexed > 0 || stall.is_some();
        let mut build = None;
        if snapshot_due(view_changed, self.last_build, Instant::now()) {
            let mut view = index.view();
            view.waiting_frame = self.stall.waiting_frame();
            view.window_complete &= view.waiting_frame.is_none();
            let (report, timings) = crate::handlers::build_production_report(state, head, &view, &mut self.sets);
            let live = report.summary.live_shards;
            *state.production_snapshot.write() = Some(Arc::new(Snapshot::new(report)));
            self.last_build = Some(Instant::now());
            build = Some((timings, live));
        }
        Tick { rebuild, advance, stall, build, next: index.next_frame(), through: index.indexed_through() }
    }
}

fn ms(d: Duration) -> u64 {
    d.as_millis() as u64
}

fn stall_cause(frame: u64, materialized: Option<u64>) -> &'static str {
    match materialized {
        None => "GLOBAL's materialized frame cannot be read from this archive's committed state: check its materializer",
        Some(m) if m < frame => {
            "this archive has not stored or materialized the frame yet: expected while it syncs; \
             ends when materialization reaches it"
        }
        Some(_) => "the frame lacks materialization outcomes: it counts as unknown once materialization is past it by the grace",
    }
}

/// Snapshot build durations: a summary every [`BUILD_SUMMARY`], and builds
/// slower than [`SLOW_BUILD`] at most once a minute.
struct BuildLog {
    since: Instant,
    count: u64,
    total: Duration,
    max: Duration,
    last_slow: Option<Instant>,
}

impl BuildLog {
    fn record(&mut self, t: &BuildTimings, live_shards: u64, now: Instant) {
        self.count += 1;
        self.total += t.total;
        self.max = self.max.max(t.total);
        if t.total >= SLOW_BUILD && self.last_slow.is_none_or(|at| now.saturating_duration_since(at) >= Duration::from_secs(60)) {
            self.last_slow = Some(now);
            tracing::info!(
                total_ms = ms(t.total),
                shard_sets_ms = ms(t.shard_sets),
                census_ms = ms(t.census),
                halts_ms = ms(t.halts),
                committed_ms = ms(t.committed),
                assemble_ms = ms(t.assemble),
                live_shards,
                grid_source = ?t.grid_source,
                grid_unavailable = ?t.grid_unavailable,
                "explorer production snapshot build took over a second (off the request path; responses serve the previous one meanwhile)",
            );
        }
        if now.saturating_duration_since(self.since) >= BUILD_SUMMARY {
            tracing::info!(
                builds = self.count,
                mean_ms = ms(self.total / self.count.max(1) as u32),
                max_ms = ms(self.max),
                live_shards,
                grid_source = ?t.grid_source,
                grid_unavailable = ?t.grid_unavailable,
                "explorer production snapshot builds",
            );
            *self = BuildLog { since: now, count: 0, total: Duration::ZERO, max: Duration::ZERO, last_slow: self.last_slow };
        }
    }
}

fn log_tick(tick: &Tick, head: u64, elapsed: Duration, failing: &mut Option<String>, builds: &mut BuildLog) {
    let advance = &tick.advance;
    if tick.rebuild {
        let (build_ms, live_shards, grid_source) =
            tick.build.map_or((None, None, None), |(t, live)| (Some(ms(t.total)), Some(live), Some(t.grid_source)));
        tracing::info!(
            through = ?tick.through,
            frames = advance.indexed,
            waiting = ?advance.waiting,
            elapsed_ms = ms(elapsed),
            build_ms = ?build_ms,
            live_shards = ?live_shards,
            grid_source = ?grid_source,
            "explorer production index rebuilt",
        );
    }
    if let (Some(first), Some(last)) = (advance.missing.first(), advance.missing.last()) {
        tracing::info!(
            first,
            last,
            count = advance.missing.len(),
            "explorer production index: this archive lacks these GLOBAL frames although materialization \
             passed them by the grace; every shard reads no_data until they leave the window",
        );
    }
    if let (Some(first), Some(last)) = (advance.outcome_less.first(), advance.outcome_less.last()) {
        tracing::info!(
            first,
            last,
            count = advance.outcome_less.len(),
            "explorer production index: this archive lacks materialization outcomes of these GLOBAL frames \
             although materialization passed them by the grace; their shard headers count as unknown, and \
             a shard with one and no applied app frame reads no_data until they leave the window",
        );
    }
    match tick.stall {
        Some(StallEvent::Started { frame }) => tracing::warn!(
            frame,
            materialized = ?advance.materialized,
            head,
            grace = OUTCOME_GRACE,
            cause = stall_cause(frame, advance.materialized),
            "explorer production index waits for a GLOBAL frame the head passed by the grace; \
             /shards/production reads no_data until it moves",
        ),
        Some(StallEvent::Persisting { frame, waited }) => tracing::warn!(
            frame,
            materialized = ?advance.materialized,
            head,
            waited_s = waited.as_secs(),
            cause = stall_cause(frame, advance.materialized),
            "explorer production index still waits for a GLOBAL frame",
        ),
        Some(StallEvent::Ended { frame, waited }) => tracing::info!(
            frame,
            waited_s = waited.as_secs(),
            through = ?tick.through,
            "explorer production index moves again",
        ),
        None => {}
    }
    match (&advance.error, &*failing) {
        (Some(e), previous) if previous.as_ref() != Some(e) => tracing::warn!(
            frame = tick.next,
            error = %e,
            "explorer production index cannot read a GLOBAL frame; retrying every tick",
        ),
        (None, Some(_)) => tracing::info!("explorer production index reads GLOBAL frames again"),
        _ => {}
    }
    *failing = advance.error.clone();
    if let Some((timings, live)) = &tick.build {
        builds.record(timings, *live, Instant::now());
    }
}

/// Index new GLOBAL frames every [`TICK`] after rebuilding the last
/// [`REBUILD_FRAMES`], and rebuild the snapshot the handlers serve. Store
/// reads and the snapshot build run on blocking workers, so a failed read or
/// a panic there is logged and retried. Never returns: the caller drops it
/// on shutdown.
pub async fn run_indexer<E>(state: crate::ExplorerState) -> Result<(), E> {
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut indexer: Option<Indexer> = None;
    let mut failing: Option<String> = None;
    let mut builds =
        BuildLog { since: Instant::now(), count: 0, total: Duration::ZERO, max: Duration::ZERO, last_slow: None };
    loop {
        ticker.tick().await;
        let head = state.current_frame.load(std::sync::atomic::Ordering::Relaxed);
        if head == 0 {
            continue;
        }
        let mut working = indexer.take().unwrap_or_default();
        let st = state.clone();
        let started = Instant::now();
        let result = tokio::task::spawn_blocking(move || {
            let tick = working.tick(&st, head);
            (working, tick)
        })
        .await;
        match result {
            Ok((working, tick)) => {
                log_tick(&tick, head, started.elapsed(), &mut failing, &mut builds);
                indexer = Some(working);
            }
            Err(e) => tracing::warn!(error = %e, "explorer production index task failed; rebuilding"),
        }
    }
}

#[cfg(test)]
mod tests;
