//! Archive shard recovery turns: the few recoveries a node's workers run at
//! once. A node's workers share its archive identity and so its per-peer
//! read slots; a few recover at a time rather than all failing busy
//! together. Turns go in arrival order, except that a worker replaying frames
//! onto those it holds goes before checkpoint installs, and a worker whose
//! successor session cannot start until its recovery lands goes first: both
//! reorder the queue and add no concurrent recovery. A blocked successor also
//! keeps its turn for further replay batches, for at most
//! [`BLOCKED_TURN_BUDGET`].

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

/// Archive shard recoveries this process runs at once.
pub(crate) const RECOVERY_TURNS: usize = 2;

/// Turns in a row that may go past the longest waiter to replays and
/// blocked successors, so other recoveries still progress meanwhile.
const PRIORITY_RUN: usize = 2;

/// How long a blocked successor keeps its turn, replaying batch after batch
/// while it stays blocked. Its session cannot start until the replay reaches
/// the predecessor's seal; handing the turn back after each batch re-queued
/// it behind every waiter, and with 90 to 180 waiting a turn came round every
/// 1.5 to 3 hours for 32 frames while its shard advanced 30 to 50 an hour.
/// Holding the turn adds no concurrent archive reads; it delays the waiters
/// by at most this, plus the batch running when it runs out.
pub(crate) const BLOCKED_TURN_BUDGET: Duration = Duration::from_secs(5 * 60);

/// How long a worker waits for a turn before the queue counts as saturated.
const SATURATED_AFTER: Duration = Duration::from_secs(60);

/// How often saturated turns warn again.
const SATURATED_REPEAT: Duration = Duration::from_secs(10 * 60);

/// How often a waiting worker re-evaluates saturation while no turn moves.
const SATURATION_TICK: Duration = Duration::from_secs(60);

pub(crate) static SHARD_RECOVERY_TURNS: RecoveryTurns = RecoveryTurns::new(RECOVERY_TURNS);

/// Whether a turn held for `held` replays another batch: only while the
/// holder's successor-blocked flag (`None`: a recovery holding no turn) is
/// set, and within [`BLOCKED_TURN_BUDGET`].
pub(crate) fn holds_turn(blocked: Option<&AtomicBool>, held: Duration) -> bool {
    held < BLOCKED_TURN_BUDGET && blocked.is_some_and(|blocked| blocked.load(Ordering::Relaxed))
}

/// A queued worker; `blocked` is its successor-blocked flag, read when a
/// turn is granted rather than when it queued. `replay`: it holds frames of
/// its shard, so its turn replays at most a few batches onto them (or
/// re-anchors at a fence) rather than installing a checkpoint, about half
/// an hour per million leaves.
#[derive(Debug)]
struct Waiter<T> {
    id: u64,
    blocked: Arc<AtomicBool>,
    replay: bool,
    since: Instant,
    grant: T,
}

impl<T> Waiter<T> {
    /// Turn order past the longest waiter, lowest first: a blocked
    /// successor's replay, a replay, a blocked successor's install, an
    /// install.
    fn rank(&self) -> u8 {
        match (self.replay, self.blocked.load(Ordering::Relaxed)) {
            (true, true) => 0,
            (true, false) => 1,
            (false, true) => 2,
            (false, false) => 3,
        }
    }
}

/// The waiting workers in arrival order.
#[derive(Debug)]
struct TurnQueue<T> {
    free: usize,
    next_id: u64,
    /// Turns granted in a row past the longest waiter.
    bypassed: usize,
    waiters: VecDeque<Waiter<T>>,
}

impl<T> TurnQueue<T> {
    const fn new(turns: usize) -> Self {
        Self { free: turns, next_id: 0, bypassed: 0, waiters: VecDeque::new() }
    }

    /// Take a free turn when nobody waits; otherwise queue `grant` and
    /// return its id.
    fn take_or_queue(&mut self, blocked: Arc<AtomicBool>, replay: bool, now: Instant, grant: T) -> Result<(), u64> {
        if self.free > 0 && self.waiters.is_empty() {
            self.free -= 1;
            return Ok(());
        }
        let id = self.next_id;
        self.next_id += 1;
        self.waiters.push_back(Waiter { id, blocked, replay, since: now, grant });
        Err(id)
    }

    /// A turn ended: the waiter it goes to, or none (the turn is free). The
    /// first waiter of the lowest [`Waiter::rank`] goes first, unless
    /// [`PRIORITY_RUN`] turns in a row already went past the longest waiter.
    fn next(&mut self) -> Option<T> {
        if self.waiters.is_empty() {
            self.free += 1;
            return None;
        }
        let pick = if self.bypassed < PRIORITY_RUN {
            self.waiters.iter().enumerate().min_by_key(|(_, w)| w.rank()).map_or(0, |(at, _)| at)
        } else {
            0
        };
        self.bypassed = if pick == 0 { 0 } else { self.bypassed + 1 };
        self.waiters.remove(pick).map(|w| w.grant)
    }

    /// Withdraw waiter `id`; false when it already got its turn.
    fn withdraw(&mut self, id: u64) -> bool {
        let Some(at) = self.waiters.iter().position(|w| w.id == id) else { return false };
        self.waiters.remove(at);
        true
    }

    /// Waiting workers, of them blocked successors and replays, and the
    /// longest wait.
    fn load(&self, now: Instant) -> QueueLoad {
        QueueLoad {
            waiting: self.waiters.len(),
            blocked_successors: self.waiters.iter().filter(|w| w.blocked.load(Ordering::Relaxed)).count(),
            replays: self.waiters.iter().filter(|w| w.replay).count(),
            longest_wait: self.waiters.iter().map(|w| now.saturating_duration_since(w.since)).max().unwrap_or_default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct QueueLoad {
    waiting: usize,
    blocked_successors: usize,
    replays: usize,
    longest_wait: Duration,
}

/// What a [`Saturation`] change logs.
#[derive(Debug, PartialEq, Eq)]
enum SaturationLog {
    /// Saturated for `duration`: at the first wait past [`SATURATED_AFTER`],
    /// then at most every [`SATURATED_REPEAT`].
    Saturated { duration: Duration },
    /// The queue drained after a warned saturation of `duration`.
    Cleared { duration: Duration },
}

/// A period with workers waiting for a recovery turn, from the first
/// queued worker to the queue's drain.
#[derive(Debug)]
struct Saturation {
    since: Option<Instant>,
    /// When it was last warned about.
    warned: Option<Instant>,
}

impl Saturation {
    const fn new() -> Self {
        Self { since: None, warned: None }
    }

    fn observe(&mut self, now: Instant, load: QueueLoad) -> Option<SaturationLog> {
        if load.waiting == 0 {
            let since = self.since.take();
            return self.warned.take().map(|_| SaturationLog::Cleared {
                duration: since.map_or(Duration::ZERO, |since| now.saturating_duration_since(since)),
            });
        }
        let since = *self.since.get_or_insert_with(|| now.checked_sub(load.longest_wait).unwrap_or(now));
        if load.longest_wait < SATURATED_AFTER
            || self.warned.is_some_and(|at| now.saturating_duration_since(at) < SATURATED_REPEAT)
        {
            return None;
        }
        self.warned = Some(now);
        Some(SaturationLog::Saturated { duration: now.saturating_duration_since(since) })
    }
}

struct State {
    queue: TurnQueue<oneshot::Sender<()>>,
    saturation: Saturation,
}

impl State {
    /// Re-evaluate saturation after a queue change or a tick at `now`.
    fn observe(&mut self, now: Instant) -> Option<(SaturationLog, QueueLoad)> {
        let load = self.queue.load(now);
        Some((self.saturation.observe(now, load)?, load))
    }
}

/// A fixed number of turns, granted in [`TurnQueue`] order.
pub(crate) struct RecoveryTurns {
    turns: usize,
    state: Mutex<State>,
}

/// A held turn; dropping it hands it to the next waiter.
pub(crate) struct Turn<'a>(&'a RecoveryTurns);

impl Drop for Turn<'_> {
    fn drop(&mut self) {
        self.0.release();
    }
}

/// A queued request for a turn; dropped unanswered, it leaves the queue,
/// and dropped answered, it passes the turn on.
struct Queued<'a> {
    turns: &'a RecoveryTurns,
    id: u64,
    granted: oneshot::Receiver<()>,
    /// The turn was received and is now held by a [`Turn`].
    taken: bool,
}

impl Drop for Queued<'_> {
    fn drop(&mut self) {
        if self.taken {
            return;
        }
        let (withdrawn, logged) = {
            let mut state = self.turns.lock();
            let withdrawn = state.queue.withdraw(self.id);
            (withdrawn, state.observe(Instant::now()))
        };
        self.turns.log(logged);
        if !withdrawn && self.granted.try_recv().is_ok() {
            self.turns.release();
        }
    }
}

impl RecoveryTurns {
    pub(crate) const fn new(turns: usize) -> Self {
        Self { turns, state: Mutex::new(State { queue: TurnQueue::new(turns), saturation: Saturation::new() }) }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Wait for a turn. `blocked` is the worker's successor-blocked flag,
    /// `replay` whether it holds frames of its shard: replays go before
    /// checkpoint installs, and a worker whose flag is set when a turn frees
    /// up before others of its kind.
    pub(crate) async fn acquire(&self, blocked: Arc<AtomicBool>, replay: bool) -> Turn<'_> {
        let (grant, granted) = oneshot::channel();
        let (mut queued, logged) = {
            let mut state = self.lock();
            let now = Instant::now();
            match state.queue.take_or_queue(blocked, replay, now, grant) {
                Ok(()) => return Turn(self),
                Err(id) => (Queued { turns: self, id, granted, taken: false }, state.observe(now)),
            }
        };
        self.log(logged);
        // The sender is dropped only after it granted the turn.
        while tokio::time::timeout(SATURATION_TICK, &mut queued.granted).await.is_err() {
            let logged = self.lock().observe(Instant::now());
            self.log(logged);
        }
        queued.taken = true;
        Turn(self)
    }

    fn release(&self) {
        let logged = {
            let mut state = self.lock();
            while let Some(grant) = state.queue.next() {
                if grant.send(()).is_ok() {
                    break;
                }
            }
            state.observe(Instant::now())
        };
        self.log(logged);
    }

    fn log(&self, logged: Option<(SaturationLog, QueueLoad)>) {
        match logged {
            Some((SaturationLog::Saturated { duration }, load)) => tracing::warn!(
                waiting_workers = load.waiting, blocked_successors_waiting = load.blocked_successors,
                replays_waiting = load.replays,
                longest_wait_secs = load.longest_wait.as_secs(), permits = self.turns,
                saturated_secs = duration.as_secs(), scope = "this node",
                action = "this node recovers at most this many shards from archives at once to bound their load; \
                    workers wait their turn, frame replays before checkpoint installs and blocked successor sessions first; \
                    with 'archive recovery failing' warnings check those first, otherwise it ends as the queue drains",
                "archive recovery turns saturated"),
            Some((SaturationLog::Cleared { duration }, _)) => tracing::info!(
                permits = self.turns, saturated_secs = duration.as_secs(),
                "archive recovery turns no longer saturated"),
            None => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    fn flag(blocked: bool) -> Arc<AtomicBool> { Arc::new(AtomicBool::new(blocked)) }

    /// Free turns are taken in arrival order; a blocked successor takes the
    /// next turn, judged when the turn frees up, not when it queued.
    #[test]
    fn a_successor_blocked_after_it_queued_takes_the_next_turn() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(2);
        assert_eq!(queue.take_or_queue(flag(false), false, now, "a"), Ok(()));
        assert_eq!(queue.take_or_queue(flag(false), false, now, "b"), Ok(()));
        let later = flag(false);
        queue.take_or_queue(flag(false), false, now, "c").unwrap_err();
        queue.take_or_queue(later.clone(), false, now, "blocked later").unwrap_err();
        queue.take_or_queue(flag(true), false, now, "blocked").unwrap_err();
        assert_eq!(queue.load(now).blocked_successors, 1);
        later.store(true, Ordering::Relaxed);
        assert_eq!(queue.load(now).blocked_successors, 2);
        let order: Vec<_> = std::iter::from_fn(|| queue.next()).collect();
        assert_eq!(order, ["blocked later", "blocked", "c"]);
        // Once nobody waits, a released turn is free again.
        assert_eq!(queue.free, 1);
        assert_eq!(queue.take_or_queue(flag(true), false, now, "e"), Ok(()));
        queue.take_or_queue(flag(true), false, now, "f").unwrap_err();
    }

    /// Blocked successors take at most [`PRIORITY_RUN`] turns in a row past
    /// the longest waiter, so it is not starved.
    #[test]
    fn blocked_successors_do_not_starve_the_longest_waiter() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(0);
        queue.take_or_queue(flag(false), false, now, "regular").unwrap_err();
        for name in ["b1", "b2", "b3", "b4"] {
            queue.take_or_queue(flag(true), false, now, name).unwrap_err();
        }
        let order: Vec<_> = std::iter::from_fn(|| queue.next()).collect();
        assert_eq!(order, ["b1", "b2", "regular", "b3", "b4"]);
    }

    /// A replay, a few batches at most, goes before checkpoint installs that
    /// queued earlier, a blocked successor's first; the longest waiter still
    /// gets a turn after [`PRIORITY_RUN`] in a row went past it.
    #[test]
    fn replays_go_before_checkpoint_installs() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(0);
        queue.take_or_queue(flag(true), false, now, "blocked install").unwrap_err();
        queue.take_or_queue(flag(false), false, now, "install").unwrap_err();
        queue.take_or_queue(flag(false), true, now, "replay").unwrap_err();
        queue.take_or_queue(flag(true), true, now, "blocked replay").unwrap_err();
        queue.take_or_queue(flag(false), true, now, "replay 2").unwrap_err();
        assert_eq!(queue.load(now).replays, 3);
        let order: Vec<_> = std::iter::from_fn(|| queue.next()).collect();
        assert_eq!(order, ["blocked replay", "replay", "blocked install", "replay 2", "install"]);
    }

    /// A blocked successor replays further batches in its turn until the
    /// budget runs out or it is no longer blocked; others hand it back.
    #[test]
    fn only_a_blocked_successor_holds_its_turn_and_only_within_the_budget() {
        let blocked = flag(true);
        assert!(holds_turn(Some(&*blocked), Duration::ZERO));
        assert!(holds_turn(Some(&*blocked), BLOCKED_TURN_BUDGET - Duration::from_millis(1)));
        assert!(!holds_turn(Some(&*blocked), BLOCKED_TURN_BUDGET));
        blocked.store(false, Ordering::Relaxed);
        assert!(!holds_turn(Some(&*blocked), Duration::ZERO));
        assert!(!holds_turn(None, Duration::ZERO));
    }

    #[test]
    fn a_withdrawn_waiter_leaves_the_queue() {
        let now = Instant::now();
        let mut queue = TurnQueue::new(1);
        queue.take_or_queue(flag(false), false, now, 1).unwrap();
        let id = queue.take_or_queue(flag(false), false, now, 2).unwrap_err();
        queue.take_or_queue(flag(true), false, now + MINUTE, 3).unwrap_err();
        assert_eq!(queue.load(now + MINUTE * 2),
            QueueLoad { waiting: 2, blocked_successors: 1, replays: 0, longest_wait: MINUTE * 2 });
        assert!(queue.withdraw(id));
        assert!(!queue.withdraw(id));
        assert_eq!(queue.next(), Some(3));
    }

    /// Saturation warns once a worker waited the threshold, then at most
    /// every repeat interval, and its end only after a warning.
    #[test]
    fn saturation_warns_at_a_bounded_rate_and_names_its_end() {
        let start = Instant::now();
        let load = |waiting, longest_wait| QueueLoad { waiting, blocked_successors: 0, replays: 0, longest_wait };
        let mut saturation = Saturation::new();
        assert_eq!(saturation.observe(start, load(1, Duration::ZERO)), None);
        assert_eq!(saturation.observe(start + MINUTE / 2, load(0, Duration::ZERO)), None, "brief waits are not named");
        assert_eq!(saturation.observe(start + MINUTE, load(3, Duration::ZERO)), None);
        assert_eq!(saturation.observe(start + MINUTE * 2, load(3, MINUTE)),
            Some(SaturationLog::Saturated { duration: MINUTE }));
        assert_eq!(saturation.observe(start + MINUTE * 11, load(9, MINUTE * 10)), None);
        assert_eq!(saturation.observe(start + MINUTE * 12, load(9, MINUTE * 11)),
            Some(SaturationLog::Saturated { duration: MINUTE * 11 }));
        assert_eq!(saturation.observe(start + MINUTE * 13, load(0, Duration::ZERO)),
            Some(SaturationLog::Cleared { duration: MINUTE * 12 }));
        assert_eq!(saturation.observe(start + MINUTE * 14, load(0, Duration::ZERO)), None);
        assert_eq!(saturation.observe(start + MINUTE * 15, load(1, MINUTE)),
            Some(SaturationLog::Saturated { duration: MINUTE }), "a later saturation warns afresh");
    }

    /// With every turn taken, a blocked successor that queued last runs
    /// next; a waiter dropped while queued neither holds nor loses a turn,
    /// and the drained queue ends the saturation period.
    #[tokio::test]
    async fn turns_go_to_blocked_successors_first() {
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
        let held = turns.acquire(flag(false), false).await;
        let order = Arc::new(Mutex::new(Vec::new()));
        let run = |name: &'static str, blocked: bool| {
            let order = order.clone();
            tokio::spawn(async move {
                let _turn = turns.acquire(flag(blocked), false).await;
                order.lock().unwrap().push(name);
            })
        };
        let dropped = run("dropped", false);
        tokio::task::yield_now().await;
        let regular = run("regular", false);
        tokio::task::yield_now().await;
        let blocked = run("blocked", true);
        tokio::task::yield_now().await;
        assert_eq!(turns.lock().queue.waiters.len(), 3);
        dropped.abort();
        assert!(dropped.await.unwrap_err().is_cancelled());
        assert_eq!(turns.lock().queue.waiters.len(), 2);
        drop(held);
        regular.await.unwrap();
        blocked.await.unwrap();
        assert_eq!(*order.lock().unwrap(), ["blocked", "regular"]);
        let state = turns.lock();
        assert_eq!((state.queue.free, state.queue.waiters.len()), (1, 0));
        assert!(state.saturation.since.is_none(), "the drained queue ends the period");
    }

    /// A waiter dropped after its turn was granted, before it ran, passes
    /// the turn on rather than losing it.
    #[tokio::test]
    async fn a_turn_granted_to_a_dropped_waiter_passes_on() {
        let turns: &'static RecoveryTurns = Box::leak(Box::new(RecoveryTurns::new(1)));
        let held = turns.acquire(flag(false), false).await;
        let ran = Arc::new(Mutex::new(Vec::new()));
        let run = |name: &'static str| {
            let ran = ran.clone();
            tokio::spawn(async move {
                let _turn = turns.acquire(flag(false), false).await;
                ran.lock().unwrap().push(name);
            })
        };
        let first = run("first");
        tokio::task::yield_now().await;
        let second = run("second");
        tokio::task::yield_now().await;
        // Grants the turn to `first`, which is dropped before it runs.
        drop(held);
        assert_eq!(turns.lock().queue.waiters.len(), 1);
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(5), second).await.expect("the turn passed on").unwrap();
        assert_eq!(*ran.lock().unwrap(), ["second"]);
        let state = turns.lock();
        assert_eq!((state.queue.free, state.queue.waiters.len()), (1, 0));
    }
}
