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
//! Only this node's own observations count, and only against its own seats.
//! A worker the node cannot observe (no report, or a stale one) is never
//! held against its seat.

use std::collections::{HashMap, HashSet};

use quil_types::proto::node::WorkerExecution;

/// A report older than this says nothing about the worker now. Engines
/// refresh their report on every state change and start attempt, and a
/// standalone worker's report is fetched every few seconds.
const FRESH_MS: u64 = 2 * 60 * 1000;

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

/// Since when a seat's worker has failed to host the session that counts it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Unhosted {
    pub core_id: u32,
    /// The GLOBAL frame of the first observation in this run.
    pub since: u64,
    /// The latest observation.
    pub state: String,
    pub blocker: String,
    /// Whether the withheld renewal has been reported for this run.
    reported: bool,
}

/// Per seat (by filter), how long its bound worker has not hosted the
/// session that counts this prover. In memory: a restart observes for a
/// full epoch again before any seat is held back.
#[derive(Debug, Default)]
pub(crate) struct SessionHosting {
    unhosted: HashMap<Vec<u8>, Unhosted>,
}

impl SessionHosting {
    /// Record the observation at GLOBAL `frame` of the worker `core_id`
    /// bound to `filter`. `member`: the shard's current session counts this
    /// prover. A seat outside its session owes no hosting; a hosting worker
    /// ends the run; an unknown report leaves it as it is.
    pub fn observe(&mut self, frame: u64, filter: &[u8], core_id: u32, member: bool, hosting: Hosting) {
        if !member {
            self.unhosted.remove(filter);
            return;
        }
        match hosting {
            Hosting::Hosting => {
                self.unhosted.remove(filter);
            }
            Hosting::Absent { state, blocker } => {
                let entry = self.unhosted.entry(filter.to_vec()).or_insert_with(|| Unhosted {
                    core_id, since: frame, state: String::new(), blocker: String::new(), reported: false,
                });
                // Another worker took the seat: its run starts now.
                if entry.core_id != core_id {
                    entry.core_id = core_id;
                    entry.since = frame;
                    entry.reported = false;
                }
                entry.state = state;
                entry.blocker = blocker;
            }
            Hosting::Unknown => {}
        }
    }

    /// Forget seats no worker is bound to any more.
    pub fn retain_bound(&mut self, bound: &HashSet<Vec<u8>>) {
        self.unhosted.retain(|filter, _| bound.contains(filter));
    }

    /// The run of `filter`'s worker not hosting, once it has lasted
    /// `epoch_frames` at GLOBAL `frame`: the seat is not to be renewed.
    /// `first` is set once per run, for the caller to report it.
    pub fn withhold(&mut self, filter: &[u8], frame: u64, epoch_frames: u64) -> Option<Withheld> {
        let run = self.unhosted.get_mut(filter)
            .filter(|run| frame.saturating_sub(run.since) >= epoch_frames)?;
        let first = !run.reported;
        run.reported = true;
        Some(Withheld { run: run.clone(), first })
    }
}

/// A renewal [`SessionHosting::withhold`] holds back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Withheld {
    pub run: Unhosted,
    /// The first time this run withholds a renewal.
    pub first: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn absent() -> Hosting {
        Hosting::Absent { state: "blocked".into(), blocker: "predecessor state".into() }
    }

    /// A member seat is withheld only after a full epoch without its worker
    /// hosting; hosting, leaving the session, rebinding or unbinding resets
    /// it, and an unknown report neither starts nor ends the run.
    #[test]
    fn a_member_seat_is_withheld_after_an_epoch_unhosted() {
        let filter = vec![1; 32];
        let mut hosting = SessionHosting::default();
        hosting.observe(100, &filter, 1, true, Hosting::Unknown);
        assert!(hosting.withhold(&filter, 2_000, 720).is_none(), "unknown starts nothing");
        hosting.observe(100, &filter, 1, true, absent());
        hosting.observe(500, &filter, 1, true, Hosting::Unknown);
        assert!(hosting.withhold(&filter, 819, 720).is_none());
        let withheld = hosting.withhold(&filter, 820, 720).expect("an epoch unhosted");
        assert_eq!((withheld.run.core_id, withheld.run.since, withheld.run.state.as_str()), (1, 100, "blocked"));
        assert!(withheld.first);
        assert!(!hosting.withhold(&filter, 821, 720).unwrap().first, "reported once per run");

        hosting.observe(830, &filter, 1, true, Hosting::Hosting);
        assert!(hosting.withhold(&filter, 5_000, 720).is_none(), "hosting ends the run");

        hosting.observe(900, &filter, 1, true, absent());
        hosting.observe(1_000, &filter, 2, true, absent());
        assert!(hosting.withhold(&filter, 1_700, 720).is_none(), "a rebound seat starts over");
        assert!(hosting.withhold(&filter, 1_720, 720).is_some());

        hosting.observe(1_800, &filter, 2, false, absent());
        assert!(hosting.withhold(&filter, 5_000, 720).is_none(), "a seat outside its session owes no hosting");

        hosting.observe(2_000, &filter, 2, true, absent());
        hosting.retain_bound(&HashSet::new());
        assert!(hosting.withhold(&filter, 5_000, 720).is_none(), "an unbound seat is forgotten");
    }
}
