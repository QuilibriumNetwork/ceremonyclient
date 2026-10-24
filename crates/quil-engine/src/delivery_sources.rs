//! The certified frames a shard's pending deliveries read their bytes from,
//! fetched off the engine's select loop.
//!
//! A split application's outputs are delivered by the shard owning their
//! block, which is rarely the shard that executed them, so a member fetches
//! the executing shard's frame from an archive before it can propose those
//! deliveries. A fetch dials an archive and can take tens of seconds, and a
//! frame no archive returns stays missing. Awaited inline on the engine's
//! select loop, every ten seconds, such fetches held off votes and finalized
//! frames for as long as they took. Here at most one sweep runs at a time,
//! in its own task; each fetch has a deadline; and a frame that could not be
//! obtained is asked for again only after a backoff that doubles up to
//! [`MAX_RETRY`]. A delivery that keeps waiting is reported as an
//! [`Outage`].

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

use quil_types::{proto::global::AppShardFrame, store::ClockStore};
use tokio::time::Instant;
use tracing::{debug, info, warn};

use crate::{
    app_engine::DeliveryFrameSource,
    outage::{Outage, OutageEvent},
};

/// How long one fetch may take before it counts as failed.
const FETCH_DEADLINE: Duration = Duration::from_secs(30);
/// The wait before a source frame that could not be obtained is asked for
/// again; it doubles with each further failure.
const FIRST_RETRY: Duration = Duration::from_secs(20);
/// The longest wait between two requests for one source frame.
const MAX_RETRY: Duration = Duration::from_secs(300);
/// Consecutive sweeps (one per engine tick, ten seconds apart) that find a
/// delivery waiting on a source frame that could not be obtained before the
/// wait is reported: about a minute.
const REPORT_AFTER_SWEEPS: u64 = 6;

/// A source frame: the executing shard's filter and its frame number.
type Source = (Vec<u8>, u64);

/// A source frame whose fetch failed.
struct Waiting {
    since: Instant,
    failures: u32,
    retry_at: Instant,
}

type Unobtained = Arc<Mutex<HashMap<Source, Waiting>>>;

/// One engine's delivery source fetches; see the module docs.
pub(crate) struct DeliverySources {
    unobtained: Unobtained,
    sweep: Option<tokio::task::JoinHandle<()>>,
    outage: Outage,
}

impl Default for DeliverySources {
    fn default() -> Self {
        Self {
            unobtained: Unobtained::default(),
            sweep: None,
            outage: Outage::begin_after(REPORT_AFTER_SWEEPS),
        }
    }
}

impl Drop for DeliverySources {
    fn drop(&mut self) {
        if let Some(sweep) = self.sweep.take() {
            sweep.abort();
        }
    }
}

impl DeliverySources {
    /// Start fetching the due frames of `missing`: the source frames of the
    /// shard `filter`'s pending deliveries that this node does not hold, in
    /// delivery order. Returns without waiting for the network; a fetched
    /// frame lands in `clock_store`. Nothing starts while an earlier sweep
    /// still runs.
    pub(crate) async fn sweep(
        &mut self,
        filter: &[u8],
        missing: Vec<Source>,
        fetch: DeliveryFrameSource,
        clock_store: Arc<dyn ClockStore>,
    ) {
        let now = Instant::now();
        let unobtained = self.unobtained.clone();
        let due: Vec<Source> = {
            let mut unobtained = unobtained.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            // A source no longer missing was delivered or obtained.
            unobtained.retain(|source, _| missing.contains(source));
            self.report(filter, &missing, &unobtained, now);
            missing
                .into_iter()
                .filter(|source| unobtained.get(source).is_none_or(|waiting| waiting.retry_at <= now))
                .collect()
        };
        if due.is_empty() || self.sweep.as_ref().is_some_and(|sweep| !sweep.is_finished()) {
            return;
        }
        self.sweep = Some(tokio::spawn(fetch_due(due, fetch, clock_store, unobtained)));
    }

    /// Log the start, bounded repeats and end of a wait for a source frame
    /// that could not be obtained. The first such frame in delivery order
    /// holds up every later delivery of the shard, so the line names it.
    fn report(&mut self, filter: &[u8], missing: &[Source], unobtained: &HashMap<Source, Waiting>, now: Instant) {
        let first = missing.iter().find_map(|source| unobtained.get(source).map(|waiting| (source, waiting)));
        let event = self.outage.observe(now.into_std(), first.is_none());
        let filter = hex::encode(filter);
        match (event, first) {
            (Some(OutageEvent::Began), Some(((source_filter, source_frame), waiting))) => warn!(
                filter = %filter, source_filter = %hex::encode(source_filter), source_frame,
                waiting_sources = unobtained.len(), failures = waiting.failures,
                waited_secs = now.duration_since(waiting.since).as_secs(), scope = "network", action = "report",
                "this shard's deliveries wait for another shard's frame that no archive returned; the outputs \
                 executed in it, and every later delivery of this shard, are not proposed until an archive \
                 serves it; report this line if it persists"),
            (Some(OutageEvent::Continues { secs, .. }), Some(((source_filter, source_frame), waiting))) => warn!(
                filter = %filter, source_filter = %hex::encode(source_filter), source_frame,
                waiting_sources = unobtained.len(), failures = waiting.failures, secs,
                scope = "network", action = "report",
                "this shard's deliveries still wait for another shard's frame that no archive returned"),
            (Some(OutageEvent::Ended { secs, .. }), _) => info!(filter = %filter, secs,
                "this shard's deliveries no longer wait for another shard's frame"),
            _ => {}
        }
    }
}

/// Fetch `due` in order, each within [`FETCH_DEADLINE`], storing what
/// arrives and scheduling the retry of what does not.
async fn fetch_due(due: Vec<Source>, fetch: DeliveryFrameSource, clock_store: Arc<dyn ClockStore>, unobtained: Unobtained) {
    for (filter, frame_number) in due {
        let fetched = tokio::time::timeout(FETCH_DEADLINE, fetch(filter.clone(), frame_number)).await.ok().flatten();
        let stored = match fetched {
            Some(frame) => store(clock_store.as_ref(), &filter, frame_number, &frame),
            None => {
                debug!(filter = hex::encode(&filter), frame = frame_number, "delivery source frame not available yet");
                false
            }
        };
        let now = Instant::now();
        let mut unobtained = unobtained.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let source = (filter, frame_number);
        if stored {
            let earlier = unobtained.remove(&source);
            info!(filter = hex::encode(&source.0), frame = frame_number,
                failures = earlier.as_ref().map_or(0, |waiting| waiting.failures),
                waited_secs = earlier.map_or(0, |waiting| now.duration_since(waiting.since).as_secs()),
                "fetched a delivery's source frame");
        } else {
            let waiting = unobtained.entry(source).or_insert(Waiting { since: now, failures: 0, retry_at: now });
            waiting.failures += 1;
            waiting.retry_at = now + retry_after(waiting.failures);
        }
    }
}

/// The wait after the `failures`-th failed fetch of one source frame.
fn retry_after(failures: u32) -> Duration {
    FIRST_RETRY.saturating_mul(1 << failures.saturating_sub(1).min(16)).min(MAX_RETRY)
}

/// Store `frame`, fetched as frame `frame_number` of `filter`; false if it is
/// another frame or the store fails.
fn store(clock_store: &dyn ClockStore, filter: &[u8], frame_number: u64, frame: &AppShardFrame) -> bool {
    let Some(header) = frame.header.as_ref() else { return false };
    if header.address != filter || header.frame_number != frame_number {
        warn!(filter = hex::encode(filter), frame = frame_number, "delivery source frame is not the one requested");
        return false;
    }
    let selector = quil_crypto::poseidon::hash_bytes_to_32(&header.output)
        .map(|hash| hash.to_vec())
        .unwrap_or_default();
    let stored = clock_store.new_transaction(false).ok().and_then(|txn| {
        clock_store.stage_shard_clock_frame(&selector, frame, txn.as_ref()).ok()?;
        txn.commit().ok()?;
        let txn = clock_store.new_transaction(false).ok()?;
        clock_store.commit_shard_clock_frame(filter, frame_number, &selector, txn.as_ref(), true).ok()?;
        txn.commit().ok()
    });
    if stored.is_none() {
        warn!(filter = hex::encode(filter), frame = frame_number, "storing a delivery's source frame failed");
    }
    stored.is_some()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use quil_types::proto::global::FrameHeader;

    use super::*;
    use crate::outage::test_logs::CapturedLogs;

    const FILTER: [u8; 35] = [0x11; 35];
    const SOURCE: [u8; 35] = [0x22; 35];
    const TICK: Duration = Duration::from_secs(10);

    struct Directory(std::path::PathBuf);

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn clock() -> (Directory, quil_store::RocksDb, Arc<dyn ClockStore>) {
        let path = std::env::temp_dir().join(format!(
            "quil-delivery-sources-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir(&path).unwrap();
        let directory = Directory(path);
        let db = quil_store::RocksDb::open(&directory.0).unwrap();
        let clock: Arc<dyn ClockStore> = Arc::new(quil_store::RocksClockStore::new(db.inner()));
        (directory, db, clock)
    }

    fn frame(filter: &[u8], frame_number: u64) -> AppShardFrame {
        AppShardFrame {
            header: Some(FrameHeader {
                address: filter.to_vec(),
                frame_number,
                output: vec![5; 64],
                ..Default::default()
            }),
            requests: Vec::new(),
            storage_attestation: None,
        }
    }

    /// A source answering `answer`, counting requests.
    fn source(calls: Arc<AtomicUsize>, answer: Option<AppShardFrame>) -> DeliveryFrameSource {
        Arc::new(move |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            let answer = answer.clone();
            Box::pin(async move { answer })
        })
    }

    /// A source that never answers, counting requests.
    fn hung(calls: Arc<AtomicUsize>) -> DeliveryFrameSource {
        Arc::new(move |_, _| {
            calls.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::pending::<Option<AppShardFrame>>())
        })
    }

    /// One engine tick: a sweep for frame 7 of `SOURCE` (bounded, so a sweep
    /// that waits for the network fails the test instead of hanging it),
    /// then the wait for the next tick. True if the sweep returned at once.
    async fn tick(
        sources: &mut DeliverySources,
        missing: &[Source],
        fetch: &DeliveryFrameSource,
        clock: &Arc<dyn ClockStore>,
    ) -> bool {
        let swept = tokio::time::timeout(
            Duration::from_secs(1),
            sources.sweep(&FILTER, missing.to_vec(), fetch.clone(), clock.clone()),
        )
        .await
        .is_ok();
        tokio::time::sleep(TICK).await;
        swept
    }

    /// A fetch that does not answer must not hold the engine's select loop,
    /// and a sweep still running is not started again.
    #[tokio::test(start_paused = true)]
    async fn a_sweep_returns_while_its_fetch_hangs() {
        let (_directory, _db, clock) = clock();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch = hung(calls.clone());
        let missing = vec![(SOURCE.to_vec(), 7)];
        let mut sources = DeliverySources::default();
        assert!(tick(&mut sources, &missing, &fetch, &clock).await, "the sweep waited for the network");
        assert!(tick(&mut sources, &missing, &fetch, &clock).await, "the sweep waited for the network");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "a second fetch started beside the running one");
    }

    /// A fetch that never answers is abandoned at its deadline, and the frame
    /// is asked for again after the first backoff.
    #[tokio::test(start_paused = true)]
    async fn a_hung_fetch_is_abandoned_at_its_deadline() {
        let (_directory, _db, clock) = clock();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch = hung(calls.clone());
        let missing = vec![(SOURCE.to_vec(), 7)];
        let mut sources = DeliverySources::default();
        // Ticks at 0..=60 s: the fetch from 0 s fails at 30 s, so the next
        // is due at 50 s.
        for _ in 0..7 {
            tick(&mut sources, &missing, &fetch, &clock).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// A frame no archive returns is asked for again with a doubling
    /// backoff, not on every tick.
    #[tokio::test(start_paused = true)]
    async fn an_unavailable_source_is_asked_for_with_backoff() {
        let (_directory, _db, clock) = clock();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch = source(calls.clone(), None);
        let missing = vec![(SOURCE.to_vec(), 7)];
        let mut sources = DeliverySources::default();
        // Ten minutes of ticks: asked at 0, 20, 60, 140 and 300 s.
        for _ in 0..60 {
            tick(&mut sources, &missing, &fetch, &clock).await;
        }
        assert_eq!(calls.load(Ordering::SeqCst), 5);
    }

    /// A fetched frame lands in the clock store under its own filter.
    #[tokio::test(start_paused = true)]
    async fn a_fetched_source_frame_is_stored() {
        let (_directory, _db, clock) = clock();
        let calls = Arc::new(AtomicUsize::new(0));
        let fetch = source(calls.clone(), Some(frame(&SOURCE, 7)));
        let mut sources = DeliverySources::default();
        tick(&mut sources, &[(SOURCE.to_vec(), 7)], &fetch, &clock).await;
        let stored = clock.get_shard_clock_frame(&SOURCE, 7, false).expect("the fetched frame is stored");
        assert_eq!(stored.header.map(|header| header.frame_number), Some(7));
        // Another frame than the one asked for is not stored.
        tick(&mut sources, &[(SOURCE.to_vec(), 8)], &fetch, &clock).await;
        assert!(clock.get_shard_clock_frame(&SOURCE, 8, false).is_err());
    }

    /// A delivery that keeps waiting for a frame no archive returns is
    /// reported once, naming the frame, and its end is logged.
    #[tokio::test(start_paused = true)]
    async fn a_delivery_waiting_on_an_unobtainable_frame_is_reported() {
        let logs = CapturedLogs::default();
        let _logging = logs.install();
        let (_directory, _db, clock) = clock();
        let fetch = source(Arc::new(AtomicUsize::new(0)), None);
        let missing = vec![(SOURCE.to_vec(), 7)];
        let mut sources = DeliverySources::default();
        for _ in 0..8 {
            tick(&mut sources, &missing, &fetch, &clock).await;
        }
        let reported = logs.lines_with("no archive returned");
        assert_eq!(reported.len(), 1, "{reported:?}");
        assert!(reported[0].contains(&format!("source_filter={}", hex::encode(SOURCE))), "{}", reported[0]);
        assert!(reported[0].contains("source_frame=7"), "{}", reported[0]);
        assert!(reported[0].contains(&format!("filter={}", hex::encode(FILTER))), "{}", reported[0]);
        // The delivery no longer needs it.
        tick(&mut sources, &[], &fetch, &clock).await;
        assert_eq!(logs.lines_with("no longer wait").len(), 1);
    }
}
