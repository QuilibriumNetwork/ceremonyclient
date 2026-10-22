//! Whether this node's workers host the committee sessions their seats sit in.
//!
//! A seat is renewed only while its worker takes part in the shard's
//! consensus (decided 2026-10-18). A worker bound to a seat whose current
//! session counts it as a member, but that cannot host that session (its
//! start is refused, its data is not staged, its engine stopped), sends
//! nothing: its committee carries a member that never votes, and enough of
//! them keep the committee below quorum (2026-10-18, regular-node workers
//! refused their predecessors' state for hours while their seats renewed).
//! Once such a seat has gone an epoch without its worker hosting, it is not
//! renewed: it lapses to `ExpiredEpoch`, which removes it from committee
//! eligibility, so the shard's next session is drawn without it.
//!
//! Lapsing takes the seat out of its session, which owes it no hosting, so
//! the withheld renewal stays withheld through it (2026-10-21: a lapsed seat
//! renewed three frames after it lapsed, its worker still failing recovery).
//! Outside its session the worker cannot host; it is able to once its start
//! passes every check of the shard's state and is refused only because no
//! session seats it. Until then the seat stays lapsed: the allocator
//! releases its worker after the recovery epoch and the orphan sweep leaves
//! it.
//!
//! The record is in memory, and a restart cannot tell for how long a worker
//! has not hosted (2026-10-21: three such seats renewed 55 s after a
//! restart). A member or lapsed seat whose worker is seen unable to host
//! within a settle period after the start waits; if the worker still cannot
//! host when the period ends, its renewal is withheld as above. Only the
//! worker's current state lifts it, so a restart that fixed the worker
//! renews the seat. A seat not yet seated owes no hosting and renews.
//!
//! Only this node's own observations count, and only against its own seats.
//! A standalone worker that does not answer its report request, or that the
//! node holds no connection to, hosts nothing (2026-10-21: provers silent in
//! every committee that seated them reconfirmed all their seats each epoch,
//! while a worker that does not answer gave no report, and no report held no
//! seat back). A worker that cannot report (a build without the call) or
//! whose report is stale is not observed and never held against its seat.

use std::collections::{HashMap, HashSet};

use quil_types::proto::node::WorkerExecution;

/// A report older than this says nothing about the worker now. Engines
/// refresh their report on every state change and start attempt, and a
/// standalone worker's report is fetched every few seconds.
const FRESH_MS: u64 = 2 * 60 * 1000;

/// The blocker a worker reports once its start passed every check of the
/// shard's state and only the committee refused its key
/// (`worker_execution::BLOCKERS`): seated, it would host.
const REFUSED_FOR_SEAT_ONLY: &str = "committee admission unavailable";

/// How long after a start a worker seen unable to host may still be
/// starting: a twelfth of an epoch, 60 frames on mainnet.
pub(crate) fn settle_frames(epoch_frames: u64) -> u64 {
    (epoch_frames / 12).max(1)
}

/// What one report says about the worker hosting its session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Hosting {
    /// It hosts the session (`serving` or `closing`), or saw it sealed and
    /// awaits its successor (`handoff`).
    Hosting,
    /// It does not: startup refused or stopped, or the host is up but gated
    /// on unstaged data, so it neither proposes nor votes.
    Absent { state: String, blocker: String },
    /// No usable report.
    Unknown,
}

/// Classify the latest `execution` report of a worker at `now_ms`.
pub(crate) fn classify(execution: Option<&WorkerExecution>, now_ms: u64) -> Hosting {
    let Some(execution) = execution else { return Hosting::Unknown };
    if execution.observed_unix_ms == 0 || now_ms.saturating_sub(execution.observed_unix_ms) > FRESH_MS {
        return Hosting::Unknown;
    }
    match execution.state.as_str() {
        // "running" is the name builds before the lifecycle phases reported.
        "serving" | "closing" | "handoff" | "running" => Hosting::Hosting,
        "" | "unknown" => Hosting::Unknown,
        state => Hosting::Absent { state: state.to_string(), blocker: execution.blocker.clone() },
    }
}

impl Hosting {
    /// Whether the worker can host the session of a seat standing at `seat`:
    /// it hosts, or, outside the session, its start passed every check of
    /// the shard's state and only the committee refused its key. A worker
    /// still syncing or recovering the shard has not passed those checks.
    pub(crate) fn able(&self, seat: Seat) -> bool {
        match self {
            Hosting::Hosting => true,
            Hosting::Absent { blocker, .. } => seat != Seat::Member && blocker == REFUSED_FOR_SEAT_ONLY,
            Hosting::Unknown => false,
        }
    }

    /// Whether the report shows the worker unable to host at `seat`. An
    /// unknown report is never held against its seat.
    pub(crate) fn seen_unable(&self, seat: Seat) -> bool {
        matches!(self, Hosting::Absent { .. }) && !self.able(seat)
    }
}

/// A standalone worker that did not answer its report request for `reason`.
pub(crate) fn unanswered(reason: &str) -> Hosting {
    Hosting::Absent { state: "unreachable".into(), blocker: reason.into() }
}

/// Where a seat stands with its shard's current committee session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Seat {
    /// The session counts this prover.
    Member,
    /// It does not, and the seat missed its epoch renewal (`ExpiredEpoch`).
    Lapsed,
    /// It does not, and the seat is current: not yet seated, or its
    /// session is closed.
    Outside,
}

/// Since when a seat's worker has failed to host the session that counts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unhosted {
    pub core_id: u32,
    /// The GLOBAL frame of the first observation in this run.
    pub since: u64,
    /// The latest observation.
    pub state: String,
    pub blocker: String,
    /// First seen within the settle period after this process started: the
    /// run may have begun before the start.
    pub from_start: bool,
    /// Whether this run has withheld its seat's renewal.
    withheld: bool,
}

/// Per seat (by filter), how long its bound worker has not hosted the
/// session that counts this prover. In memory: after a restart, see
/// [`settle_frames`].
#[derive(Debug, Default)]
pub(crate) struct SessionHosting {
    unhosted: HashMap<Vec<u8>, Unhosted>,
    /// The GLOBAL frame of this process's first observation.
    started: Option<u64>,
    /// Whether renewals waiting for the settle period have been reported.
    settling_reported: bool,
}

impl SessionHosting {
    /// Record the observation at GLOBAL `frame` of the worker `core_id`
    /// bound to `filter`, whose seat stands at `seat`. A seat outside its
    /// session owes no hosting, unless the run already withheld its renewal
    /// or began within the settle period; a worker able to host ends the
    /// run; an unknown report leaves it as it is. Returns the run it ends
    /// when that run had withheld the renewal.
    pub fn observe(
        &mut self, frame: u64, epoch_frames: u64, filter: &[u8], core_id: u32, seat: Seat, hosting: Hosting,
    ) -> Option<Unhosted> {
        let started = *self.started.get_or_insert(frame);
        // Another worker took the seat: its run starts over.
        if self.unhosted.get(filter).is_some_and(|run| run.core_id != core_id) {
            self.unhosted.remove(filter);
        }
        if hosting.able(seat) {
            return self.unhosted.remove(filter).filter(|run| run.withheld);
        }
        if seat != Seat::Member && self.unhosted.get(filter).is_some_and(|run| !run.withheld && !run.from_start) {
            self.unhosted.remove(filter);
        }
        let Hosting::Absent { state, blocker } = hosting else { return None };
        let from_start = frame < started.saturating_add(settle_frames(epoch_frames));
        match self.unhosted.get_mut(filter) {
            Some(run) => {
                run.state = state;
                run.blocker = blocker;
            }
            None if seat == Seat::Member || (from_start && seat == Seat::Lapsed) => {
                self.unhosted.insert(filter.to_vec(), Unhosted {
                    core_id, since: frame, state, blocker, from_start, withheld: false,
                });
            }
            None => {}
        }
        None
    }

    /// Forget seats no worker is bound to any more.
    pub fn retain_bound(&mut self, bound: &HashSet<Vec<u8>>) {
        self.unhosted.retain(|filter, _| bound.contains(filter));
    }

    /// Whether `filter`'s renewal is held back at GLOBAL `frame`: withheld
    /// once its worker's run has lasted `epoch_frames`, or, for a run from
    /// this process's start, the settle period, which it waits out first.
    /// A withheld run stays withheld until [`Self::observe`] ends it.
    pub fn withhold(&mut self, filter: &[u8], frame: u64, epoch_frames: u64) -> Option<Hold> {
        let settled = self.started.get_or_insert(frame).saturating_add(settle_frames(epoch_frames));
        let run = self.unhosted.get_mut(filter)?;
        let due = if run.from_start { frame >= settled } else { frame.saturating_sub(run.since) >= epoch_frames };
        if !run.withheld && !due {
            return run.from_start.then_some(Hold::Settling { until: settled });
        }
        let first = !run.withheld;
        run.withheld = true;
        Some(Hold::Withheld(Withheld { run: run.clone(), first }))
    }

    /// True the first time renewals wait for the settle period, for the
    /// caller to report it once.
    pub fn report_settling(&mut self) -> bool {
        !std::mem::replace(&mut self.settling_reported, true)
    }
}

/// A renewal [`SessionHosting::withhold`] holds back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Hold {
    /// Its worker was seen unable to host within the settle period after
    /// this process started, which lasts until GLOBAL frame `until`.
    Settling { until: u64 },
    Withheld(Withheld),
}

/// A renewal withheld because its seat's worker cannot host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Withheld {
    pub run: Unhosted,
    /// The first time this run withholds a renewal.
    pub first: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCH: u64 = 720;

    fn report(state: &str, observed_unix_ms: u64) -> WorkerExecution {
        WorkerExecution { state: state.into(), blocker: "predecessor state".into(), observed_unix_ms, ..Default::default() }
    }

    /// Serving, closing and handoff host the session; a refused start, a
    /// host gated on unstaged data and a stopped engine do not; a missing or
    /// stale report says nothing.
    #[test]
    fn reports_classify_by_phase_and_age() {
        let now = 10 * FRESH_MS;
        for state in ["serving", "closing", "handoff", "running"] {
            assert_eq!(classify(Some(&report(state, now)), now), Hosting::Hosting, "{state}");
        }
        for state in ["blocked", "syncing", "starting", "stopped", "waiting"] {
            assert!(matches!(classify(Some(&report(state, now)), now), Hosting::Absent { .. }), "{state}");
        }
        assert_eq!(classify(None, now), Hosting::Unknown);
        assert_eq!(classify(Some(&report("blocked", now - FRESH_MS - 1)), now), Hosting::Unknown);
        assert_eq!(classify(Some(&report("blocked", 0)), now), Hosting::Unknown);
        assert_eq!(classify(Some(&report("unknown", now)), now), Hosting::Unknown);
    }

    /// A worker is able to host when it hosts, or, outside its session, is
    /// refused only for its seat; only a report of another blocker shows it
    /// unable, and an unknown one shows nothing.
    #[test]
    fn a_worker_refused_only_for_its_seat_is_able_outside_its_session() {
        for seat in [Seat::Member, Seat::Lapsed, Seat::Outside] {
            assert!(Hosting::Hosting.able(seat) && !Hosting::Hosting.seen_unable(seat), "{seat:?}");
            assert!(!absent().able(seat) && absent().seen_unable(seat), "{seat:?}");
            assert!(!Hosting::Unknown.able(seat) && !Hosting::Unknown.seen_unable(seat), "{seat:?}");
            let outside = seat != Seat::Member;
            assert_eq!((refused_for_seat_only().able(seat), refused_for_seat_only().seen_unable(seat)),
                (outside, !outside), "{seat:?}");
        }
    }

    /// Engines report the seat-only refusal under this name.
    #[test]
    fn the_seat_only_refusal_is_a_reported_blocker() {
        assert!(crate::worker_execution::BLOCKERS.contains(&REFUSED_FOR_SEAT_ONLY));
    }

    fn absent() -> Hosting {
        Hosting::Absent { state: "blocked".into(), blocker: "predecessor state".into() }
    }

    fn refused_for_seat_only() -> Hosting {
        Hosting::Absent { state: "blocked".into(), blocker: REFUSED_FOR_SEAT_ONLY.into() }
    }

    /// Hosting that started long before the frames observed below.
    fn running() -> SessionHosting {
        let mut hosting = SessionHosting::default();
        hosting.observe(0, EPOCH, &[0; 32], 0, Seat::Member, Hosting::Hosting);
        hosting
    }

    fn withheld(hold: Option<Hold>) -> Option<Withheld> {
        match hold {
            Some(Hold::Withheld(withheld)) => Some(withheld),
            _ => None,
        }
    }

    /// A member seat is withheld only after a full epoch without its worker
    /// hosting; hosting, leaving the session before that, rebinding or
    /// unbinding resets it, and an unknown report neither starts nor ends
    /// the run.
    #[test]
    fn a_member_seat_is_withheld_after_an_epoch_unhosted() {
        let filter = vec![1; 32];
        let mut hosting = running();
        hosting.observe(100, EPOCH, &filter, 1, Seat::Member, Hosting::Unknown);
        assert!(hosting.withhold(&filter, 2_000, EPOCH).is_none(), "unknown starts nothing");
        hosting.observe(100, EPOCH, &filter, 1, Seat::Member, absent());
        hosting.observe(500, EPOCH, &filter, 1, Seat::Member, Hosting::Unknown);
        assert!(hosting.withhold(&filter, 819, EPOCH).is_none());
        let first = withheld(hosting.withhold(&filter, 820, EPOCH)).expect("an epoch unhosted");
        assert_eq!((first.run.core_id, first.run.since, first.run.state.as_str()), (1, 100, "blocked"));
        assert!(first.first && !first.run.from_start);
        assert!(!withheld(hosting.withhold(&filter, 821, EPOCH)).unwrap().first, "reported once per run");

        let ended = hosting.observe(830, EPOCH, &filter, 1, Seat::Member, Hosting::Hosting);
        assert_eq!(ended.map(|run| run.since), Some(100), "the withheld run is returned as it ends");
        assert!(hosting.withhold(&filter, 5_000, EPOCH).is_none(), "hosting ends the run");

        hosting.observe(900, EPOCH, &filter, 1, Seat::Member, absent());
        hosting.observe(1_000, EPOCH, &filter, 2, Seat::Member, absent());
        assert!(hosting.withhold(&filter, 1_700, EPOCH).is_none(), "a rebound seat starts over");
        assert!(hosting.withhold(&filter, 1_720, EPOCH).is_some());

        hosting.observe(1_800, EPOCH, &filter, 3, Seat::Member, absent());
        hosting.observe(1_900, EPOCH, &filter, 3, Seat::Outside, absent());
        hosting.observe(1_900, EPOCH, &filter, 3, Seat::Lapsed, absent());
        assert!(hosting.withhold(&filter, 5_000, EPOCH).is_none(),
            "a seat that leaves its session before its renewal is withheld owes no hosting");

        hosting.observe(2_000, EPOCH, &filter, 3, Seat::Member, absent());
        hosting.retain_bound(&HashSet::new());
        assert!(hosting.withhold(&filter, 5_000, EPOCH).is_none(), "an unbound seat is forgotten");
    }

    /// A withheld renewal stays withheld when the seat lapses and leaves its
    /// session, until the worker passes its state checks and is refused only
    /// for its seat; another worker bound to the seat starts over.
    #[test]
    fn a_withheld_seat_stays_withheld_after_it_lapses() {
        let filter = vec![1; 32];
        let mut hosting = running();
        hosting.observe(100, EPOCH, &filter, 1, Seat::Member, absent());
        assert!(withheld(hosting.withhold(&filter, 820, EPOCH)).unwrap().first);
        for (frame, seat, observed) in [(1_440, Seat::Lapsed, absent()), (1_450, Seat::Lapsed, Hosting::Unknown),
            (1_460, Seat::Outside, absent()), (1_470, Seat::Member, refused_for_seat_only())]
        {
            assert!(hosting.observe(frame, EPOCH, &filter, 1, seat, observed).is_none());
            let still = withheld(hosting.withhold(&filter, frame, EPOCH)).expect("still withheld");
            assert!(!still.first && still.run.since == 100, "{frame}");
        }
        let ended = hosting.observe(1_480, EPOCH, &filter, 1, Seat::Lapsed, refused_for_seat_only());
        assert_eq!(ended.map(|run| run.since), Some(100), "refused only for its seat, it can host again");
        assert!(hosting.withhold(&filter, 1_480, EPOCH).is_none());

        hosting.observe(1_500, EPOCH, &filter, 1, Seat::Member, absent());
        assert!(hosting.withhold(&filter, 2_220, EPOCH).is_some());
        hosting.observe(2_400, EPOCH, &filter, 1, Seat::Lapsed, absent());
        hosting.observe(2_410, EPOCH, &filter, 2, Seat::Lapsed, absent());
        assert!(hosting.withhold(&filter, 2_410, EPOCH).is_none(), "a newly bound worker starts over");
    }

    /// After a start, a member or lapsed seat whose worker is seen unable to
    /// host waits out the settle period and is then withheld until the
    /// worker can host; a seat not yet seated, an unobservable worker, one
    /// that hosts and a seat first seen after the period renew as before.
    #[test]
    fn after_a_start_a_seat_whose_worker_cannot_host_waits_then_is_withheld() {
        let settled = 1_000 + settle_frames(EPOCH);
        let [member, lapsed, outside, unknown, hosts, late] = [1u8, 2, 3, 4, 5, 6].map(|b| vec![b; 32]);
        let mut hosting = SessionHosting::default();
        hosting.observe(1_000, EPOCH, &member, 1, Seat::Member, absent());
        hosting.observe(1_000, EPOCH, &lapsed, 2, Seat::Lapsed, absent());
        hosting.observe(1_000, EPOCH, &outside, 3, Seat::Outside, absent());
        hosting.observe(1_000, EPOCH, &unknown, 4, Seat::Lapsed, Hosting::Unknown);
        hosting.observe(1_000, EPOCH, &hosts, 5, Seat::Member, Hosting::Hosting);
        for frame in [1_000, settled - 1] {
            for filter in [&member, &lapsed] {
                assert_eq!(hosting.withhold(filter, frame, EPOCH), Some(Hold::Settling { until: settled }));
            }
            for filter in [&outside, &unknown, &hosts] {
                assert!(hosting.withhold(filter, frame, EPOCH).is_none());
            }
        }
        assert!(hosting.report_settling() && !hosting.report_settling(), "reported once");
        for filter in [&member, &lapsed] {
            let first = withheld(hosting.withhold(filter, settled, EPOCH)).expect("withheld once settled");
            assert!(first.first && first.run.from_start && first.run.since == 1_000);
        }
        assert!(hosting.observe(settled, EPOCH, &member, 1, Seat::Member, Hosting::Hosting).is_some());
        assert!(hosting.observe(settled, EPOCH, &lapsed, 2, Seat::Lapsed, refused_for_seat_only()).is_some());
        for filter in [&member, &lapsed] {
            assert!(hosting.withhold(filter, settled, EPOCH).is_none(), "the worker's current state lifts it");
        }

        hosting.observe(settled, EPOCH, &late, 6, Seat::Lapsed, absent());
        assert!(hosting.withhold(&late, settled, EPOCH).is_none(), "first seen after the settle period");
        hosting.observe(settled, EPOCH, &late, 6, Seat::Member, absent());
        assert!(hosting.withhold(&late, settled + EPOCH - 1, EPOCH).is_none());
        assert!(hosting.withhold(&late, settled + EPOCH, EPOCH).is_some());
    }
}
