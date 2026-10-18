//! Which build each member of a served app committee runs, read from its
//! verified PeerInfo: one line per committee when its session changes and
//! every thirty minutes, so members that accept or reject proposals can be
//! matched to builds.

use std::collections::{BTreeMap, HashMap};
use std::time::{Duration, Instant};

/// How often a committee's member builds are logged again.
pub(super) const REPEAT: Duration = Duration::from_secs(1800);

/// A member's build as its PeerInfo states it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Build {
    /// The first four bytes of its build fingerprint.
    Known([u8; 4]),
    /// PeerInfo without a fingerprint (an older build).
    NoFingerprint,
    /// No PeerInfo from it yet.
    NoPeerInfo,
    /// This node, which holds no PeerInfo of its own.
    ThisNode,
}

impl Build {
    pub(super) fn of(fingerprint: Option<Option<[u8; 32]>>) -> Self {
        match fingerprint {
            Some(Some(fingerprint)) => Build::Known([fingerprint[0], fingerprint[1], fingerprint[2], fingerprint[3]]),
            Some(None) => Build::NoFingerprint,
            None => Build::NoPeerInfo,
        }
    }
}

/// Member indices grouped by build, the largest known build first and
/// members without a fingerprint or PeerInfo, then this node, last, e.g.
/// `6d91a5e8: 0,1,3; fca80080: 2; no peer info: 4; this node: 5`.
pub(super) fn groups(builds: &[Build]) -> String {
    let mut by_build: BTreeMap<Build, Vec<usize>> = BTreeMap::new();
    for (index, build) in builds.iter().enumerate() {
        by_build.entry(*build).or_default().push(index);
    }
    let mut groups: Vec<_> = by_build.into_iter().collect();
    groups.sort_by_key(|(build, members)| (!matches!(build, Build::Known(_)), std::cmp::Reverse(members.len()), *build));
    groups
        .iter()
        .map(|(build, members)| {
            let name = match build {
                Build::Known(prefix) => hex::encode(prefix),
                Build::NoFingerprint => "no fingerprint".to_string(),
                Build::NoPeerInfo => "no peer info".to_string(),
                Build::ThisNode => "this node".to_string(),
            };
            let members: Vec<String> = members.iter().map(usize::to_string).collect();
            format!("{name}: {}", members.join(","))
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// Per committee, the session last seen and when its builds were logged.
#[derive(Default)]
pub(super) struct CommitteeBuilds {
    seen: HashMap<Vec<u8>, ([u8; 32], Instant)>,
}

impl CommitteeBuilds {
    /// Whether to log `filter`'s committee now: its session changed or
    /// [`REPEAT`] passed. A committee seen for the first time is only
    /// recorded, so the first line comes once peers had time to announce
    /// their PeerInfo.
    pub(super) fn due(&mut self, filter: &[u8], session: [u8; 32], now: Instant) -> bool {
        match self.seen.get_mut(filter) {
            None => {
                self.seen.insert(filter.to_vec(), (session, now));
                false
            }
            Some((seen, logged)) if *seen != session || now.duration_since(*logged) >= REPEAT => {
                *seen = session;
                *logged = now;
                true
            }
            Some(_) => false,
        }
    }

    /// Forget committees this node no longer serves.
    pub(super) fn retain(&mut self, served: &std::collections::BTreeSet<Vec<u8>>) {
        self.seen.retain(|filter, _| served.contains(filter));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn members_are_grouped_by_build_largest_first() {
        let (a, b) = ([0x6d, 0x91, 0xa5, 0xe8], [0xfc, 0xa8, 0x00, 0x80]);
        let builds = [Build::Known(a), Build::Known(b), Build::ThisNode, Build::Known(a), Build::NoPeerInfo, Build::NoFingerprint, Build::Known(a)];
        assert_eq!(
            groups(&builds),
            "6d91a5e8: 0,3,6; fca80080: 1; no fingerprint: 5; no peer info: 4; this node: 2"
        );
        assert_eq!(Build::of(Some(Some([0xab; 32]))), Build::Known([0xab; 4]));
        assert_eq!(Build::of(Some(None)), Build::NoFingerprint);
        assert_eq!(Build::of(None), Build::NoPeerInfo);
    }

    #[test]
    fn a_committee_is_logged_on_a_new_session_and_every_half_hour() {
        let mut builds = CommitteeBuilds::default();
        let start = Instant::now();
        assert!(!builds.due(b"f", [1; 32], start), "first sight only records");
        assert!(!builds.due(b"f", [1; 32], start + Duration::from_secs(60)));
        assert!(builds.due(b"f", [2; 32], start + Duration::from_secs(120)), "new session");
        assert!(!builds.due(b"f", [2; 32], start + Duration::from_secs(1800)));
        assert!(builds.due(b"f", [2; 32], start + Duration::from_secs(1920)), "half an hour later");
        builds.retain(&std::collections::BTreeSet::new());
        assert!(!builds.due(b"f", [2; 32], start + Duration::from_secs(1980)), "forgotten once unserved");
    }
}
