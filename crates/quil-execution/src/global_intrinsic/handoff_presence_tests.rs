//! Presence report validation ([`crate::global_intrinsic::handoff::presence`]).

use super::*;
use crate::global_intrinsic::frame_header::FrameHeader;
use crate::global_intrinsic::handoff::presence::{
    NotarizeVote, PresenceProposal, PresenceReport, MAX_PRESENCE_PROPOSALS, MAX_PRESENCE_VOTES,
};
use crate::global_intrinsic::intrinsic::GlobalIntrinsic;
use quil_types::store::ClockStore as _;

fn anchor_output(frame: u64) -> Vec<u8> {
    vec![(frame % 251) as u8 + 1; 516]
}

fn put_anchor(clock: &quil_store::RocksClockStore, frame: u64) {
    let txn = clock.new_transaction(false).unwrap();
    clock
        .put_global_clock_frame(
            &quil_types::proto::global::GlobalFrame {
                header: Some(quil_types::proto::global::GlobalFrameHeader {
                    frame_number: frame,
                    output: anchor_output(frame),
                    ..Default::default()
                }),
                ..Default::default()
            },
            txn.as_ref(),
        )
        .unwrap();
    txn.commit().unwrap();
}

/// The producer's output stamp (`porep::deterministic_app_frame_output`).
fn stamp(header: &mut FrameHeader, anchor_output: &[u8]) {
    let rho_n = quil_crypto::porep::derive_storage_beacon(header.global_frame_number, anchor_output);
    header.output = quil_crypto::porep::deterministic_app_frame_output(
        &header.parent_selector, &header.requests_root, &header.state_roots, &rho_n,
        header.frame_number, header.rank, &header.prover, header.difficulty,
        header.fee_multiplier_vote as u64, header.timestamp, &header.storage_attestation_root,
        header.fee_total_value(), &header.settlements, &header.accumulator, &header.spends,
    );
}

fn refused(result: Result<()>) {
    assert!(matches!(result, Err(QuilError::InvalidArgument(_))), "{result:?}");
}

fn refused_for(result: Result<()>, reason: &str) {
    match result {
        Err(QuilError::InvalidArgument(message)) => assert!(message.contains(reason), "{message}"),
        other => panic!("expected refusal for {reason}, got {other:?}"),
    }
}

/// A committed four-member session, an anchor in the clock store, and an
/// inclusion frame later in the anchor's epoch. Reports are active.
struct Fixture {
    state: HypergraphState,
    clock: Arc<quil_store::RocksClockStore>,
    keys: Vec<FalconPrivateKey>,
    session: Session,
    frame: u64,
    anchor: u64,
    _db: quil_store::RocksDb,
}

fn fixture() -> Fixture {
    set_presence_report_frame_for_thread(Some(0));
    let db = quil_store::RocksDb::open_in_memory().unwrap();
    let (_, state) = make_state(&db);
    let keys = keys();
    let session = initial(vec![0x61; 32], &keys);
    initialize(&state, 1, &session).unwrap();
    commit(&state, 1);
    let clock = Arc::new(quil_store::RocksClockStore::new(db.inner()));
    let anchor = 3 * quil_types::consensus::epoch_length_frames() + 5;
    put_anchor(&clock, anchor);
    Fixture { state, clock, keys, session, frame: anchor + 6, anchor, _db: db }
}

impl Fixture {
    fn intrinsic(&self) -> GlobalIntrinsic {
        GlobalIntrinsic::new(Arc::new(crate::testing::NoopKeyManager))
            .with_clock_store(self.clock.clone())
            .with_hypergraph(self.state.crdt().clone())
    }

    fn verify(&self, report: &PresenceReport) -> Result<()> {
        self.intrinsic().verify_presence_report(self.frame, report, &self.state)
    }

    fn report(&self, proposals: Vec<PresenceProposal>) -> PresenceReport {
        PresenceReport { session: self.session.id().unwrap(), filter: self.session.filter.clone(), proposals }
    }

    /// A proposal at `view` anchored to `anchor`, notarized by `signers`
    /// (indexes into `keys`).
    fn proposal(&self, view: u64, anchor: u64, signers: &[usize]) -> PresenceProposal {
        let header = FrameHeader {
            address: self.session.filter.clone(),
            frame_number: view + 1,
            rank: view,
            difficulty: 100,
            parent_selector: vec![0x31; 32],
            global_frame_number: anchor,
            ..Default::default()
        };
        let mut proposal = PresenceProposal {
            header, epoch: self.session.generation, view, parent: view - 1, payload: [0; 32], votes: Vec::new(),
        };
        self.reissue(&mut proposal, signers);
        proposal
    }

    /// Restamp the header's output, take its digest as the payload, and
    /// notarize the result by `signers`.
    fn reissue(&self, proposal: &mut PresenceProposal, signers: &[usize]) {
        let anchor = anchor_output(proposal.header.global_frame_number);
        stamp(&mut proposal.header, &anchor);
        proposal.payload = quil_crypto::poseidon::hash_bytes_to_32(&proposal.header.output).unwrap();
        self.sign(proposal, signers);
    }

    /// Replace the votes by notarizes of `signers` over the proposal as it is.
    fn sign(&self, proposal: &mut PresenceProposal, signers: &[usize]) {
        let participants: Set<_> = self
            .keys
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let subject = Proposal::new(
            Round::new(Epoch::new(proposal.epoch), View::new(proposal.view)),
            View::new(proposal.parent),
            Digest(proposal.payload),
        );
        let mut votes: Vec<NotarizeVote> = signers
            .iter()
            .map(|&signer| {
                let scheme: Generic<Namespace> = Generic::signer(
                    &self.session.namespace().unwrap(), participants.clone(), self.keys[signer].clone(),
                )
                .unwrap();
                let vote = scheme
                    .sign::<SimplexFalconScheme, Digest>(Subject::Notarize { proposal: &subject })
                    .unwrap();
                NotarizeVote { signer: vote.signer.get(), signature: vote.signature.get().unwrap().to_vec() }
            })
            .collect();
        votes.sort_by_key(|vote| vote.signer);
        proposal.votes = votes;
    }
}

#[test]
fn valid_presence_report_is_accepted_and_writes_nothing() {
    let f = fixture();
    let report = f.report(vec![f.proposal(5, f.anchor, &[0, 1]), f.proposal(6, f.anchor, &[2])]);
    f.verify(&report).unwrap();
    let bytes = report.to_canonical_bytes().unwrap();
    assert_eq!(&bytes[..4], &TYPE_PRESENCE_REPORT.to_be_bytes());
    assert_eq!(PresenceReport::from_canonical_bytes(&bytes).unwrap(), report);
    for n in 0..bytes.len() {
        assert!(PresenceReport::from_canonical_bytes(&bytes[..n]).is_err());
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(PresenceReport::from_canonical_bytes(&trailing).is_err());
    let intrinsic = f.intrinsic();
    assert!(intrinsic.validate(f.frame, &bytes, None, None).unwrap());
    assert_eq!(f.state.changeset_len(), 0);
    intrinsic.invoke_step(f.frame, &bytes, &f.state).unwrap();
    assert_eq!(f.state.changeset_len(), 0, "a validated report writes nothing");
}

#[test]
fn forged_presence_votes_are_refused() {
    let f = fixture();
    let valid = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    f.verify(&valid).unwrap();
    let mut flipped = valid.clone();
    flipped.proposals[0].votes[0].signature[20] ^= 1;
    refused(f.verify(&flipped));
    // Two members' votes, each under the other's index.
    let mut swapped = valid.clone();
    swapped.proposals[0].votes[0].signature = valid.proposals[0].votes[1].signature.clone();
    swapped.proposals[0].votes[1].signature = valid.proposals[0].votes[0].signature.clone();
    refused(f.verify(&swapped));
    // Votes for another parent view than the one carried.
    let mut parent = valid.clone();
    parent.proposals[0].parent -= 1;
    refused(f.verify(&parent));
}

#[test]
fn presence_anchor_outside_the_inclusion_epoch_is_refused_before_lookup() {
    let f = fixture();
    let epoch = quil_types::consensus::epoch_length_frames();
    // Another earlier frame of the epoch is a valid anchor.
    put_anchor(&f.clock, f.frame - 1);
    f.verify(&f.report(vec![f.proposal(5, f.frame - 1, &[0, 1])])).unwrap();
    // Stale: the last frame of the previous epoch, held or not.
    let stale = 3 * epoch - 1;
    put_anchor(&f.clock, stale);
    refused_for(f.verify(&f.report(vec![f.proposal(5, stale, &[0, 1])])), "inclusion epoch");
    refused_for(f.verify(&f.report(vec![f.proposal(5, stale - 1, &[0, 1])])), "inclusion epoch");
    // Future: the inclusion frame itself, held or not, and a later one.
    put_anchor(&f.clock, f.frame);
    refused_for(f.verify(&f.report(vec![f.proposal(5, f.frame, &[0, 1])])), "inclusion epoch");
    refused_for(f.verify(&f.report(vec![f.proposal(5, f.frame + 1, &[0, 1])])), "inclusion epoch");
    // One out-of-epoch proposal refuses the report.
    let mixed = f.report(vec![f.proposal(5, f.anchor, &[0]), f.proposal(6, stale, &[1])]);
    refused_for(f.verify(&mixed), "inclusion epoch");
    // An in-epoch anchor this node does not hold is unavailable, not refused.
    let missing = f.report(vec![f.proposal(5, f.anchor + 1, &[0, 1])]);
    assert!(matches!(f.verify(&missing), Err(QuilError::ExecutionUnavailable(_))));
}

#[test]
fn presence_report_of_a_foreign_session_or_filter_is_refused() {
    let f = fixture();
    let other = initial(vec![0x62; 32], &keys());
    initialize(&f.state, 2, &other).unwrap();
    commit(&f.state, 2);
    let valid = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    f.verify(&valid).unwrap();
    let mut unknown = valid.clone();
    unknown.session = [0x77; 32];
    refused_for(f.verify(&unknown), "unknown session");
    let mut filter = valid.clone();
    filter.filter = other.filter.clone();
    refused_for(f.verify(&filter), "another filter");
    let mut foreign = valid.clone();
    foreign.session = other.id().unwrap();
    foreign.filter = other.filter.clone();
    refused_for(f.verify(&foreign), "header belongs to another filter");
    // Votes for a header of the other filter.
    let mut header = valid.clone();
    header.proposals[0].header.address = other.filter.clone();
    f.reissue(&mut header.proposals[0], &[0, 1]);
    refused_for(f.verify(&header), "header belongs to another filter");
}

#[test]
fn presence_report_of_a_superseded_session_is_refused() {
    let f = fixture();
    let filter = f.session.filter.clone();
    let request = schedule(&f.state, 2, vec![filter.clone()], vec![desired(&filter, &f.keys)]).unwrap();
    commit(&f.state, 2);
    // A closing session still votes.
    let report = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    f.verify(&report).unwrap();
    apply_submission(&f.state, 3, &submission(&request, 0, &f.keys, 2)).unwrap();
    commit(&f.state, 3);
    assert_ne!(head(&f.state, &filter).unwrap().unwrap(), f.session);
    refused_for(f.verify(&report), "not the current head");
}

#[test]
fn presence_round_epoch_must_be_the_session_generation() {
    let f = fixture();
    let mut report = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    f.verify(&report).unwrap();
    // Valid votes over the wrong epoch.
    report.proposals[0].epoch += 1;
    f.sign(&mut report.proposals[0], &[0, 1]);
    refused_for(f.verify(&report), "round epoch");
}

#[test]
fn presence_proposal_must_match_its_header() {
    let f = fixture();
    f.verify(&f.report(vec![f.proposal(5, f.anchor, &[0, 1])])).unwrap();
    let mut rank = f.proposal(5, f.anchor, &[0, 1]);
    rank.header.rank = 6;
    f.reissue(&mut rank, &[0, 1]);
    refused_for(f.verify(&f.report(vec![rank])), "header rank");
    let mut base = f.proposal(5, f.anchor, &[0, 1]);
    base.header.frame_number = f.session.base_frame;
    f.reissue(&mut base, &[0, 1]);
    refused_for(f.verify(&f.report(vec![base])), "session base");
    // A changed header field no longer reproduces the voted output.
    let mut output = f.proposal(5, f.anchor, &[0, 1]);
    output.header.timestamp = 9;
    refused_for(f.verify(&f.report(vec![output])), "header output");
    // Valid votes over a payload that is not the header's output digest.
    let mut payload = f.proposal(5, f.anchor, &[0, 1]);
    payload.payload[0] ^= 1;
    f.sign(&mut payload, &[0, 1]);
    refused_for(f.verify(&f.report(vec![payload])), "payload");
    // A header carrying its certificate.
    let mut certified = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    certified.proposals[0].header.public_key_signature_bls48581 = vec![1; 8];
    refused(f.verify(&certified));
    assert!(certified.to_canonical_bytes().is_err());
}

#[test]
fn presence_vote_of_a_non_member_index_is_refused() {
    let f = fixture();
    let mut report = f.report(vec![f.proposal(5, f.anchor, &[0])]);
    f.verify(&report).unwrap();
    report.proposals[0].votes[0].signer = f.session.members.len() as u32;
    refused_for(f.verify(&report), "notarize");
}

#[test]
fn presence_duplicate_signer_is_refused() {
    let f = fixture();
    f.verify(&f.report(vec![f.proposal(5, f.anchor, &[0]), f.proposal(6, f.anchor, &[1])])).unwrap();
    let mut within = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    let bytes = within.to_canonical_bytes().unwrap();
    within.proposals[0].votes[1] = within.proposals[0].votes[0].clone();
    refused_for(f.verify(&within), "duplicate signer");
    assert!(within.to_canonical_bytes().is_err());
    // The same bytes with the second vote's signer index replaced by the first's.
    let mut patched = bytes.clone();
    let vote = 4 + quil_crypto::FALCON_SIGNATURE_LEN;
    let first = patched[patched.len() - 2 * vote..patched.len() - 2 * vote + 4].to_vec();
    let len = patched.len();
    patched[len - vote..len - vote + 4].copy_from_slice(&first);
    assert!(PresenceReport::from_canonical_bytes(&patched).is_err());
    // One member's votes on two proposals.
    let across = f.report(vec![f.proposal(5, f.anchor, &[0]), f.proposal(6, f.anchor, &[0])]);
    refused_for(f.verify(&across), "duplicate signer");
    assert!(across.to_canonical_bytes().is_err());
}

#[test]
fn oversize_presence_report_is_refused() {
    let f = fixture();
    // More votes than the session has members (checked before any signature).
    let mut members = f.report(vec![f.proposal(5, f.anchor, &[0, 1, 2, 3])]);
    f.verify(&members).unwrap();
    let signature = members.proposals[0].votes[0].signature.clone();
    members.proposals[0].votes.push(NotarizeVote { signer: 4, signature: signature.clone() });
    refused_for(f.verify(&members), "more votes than session members");
    // More votes than any report carries.
    let mut votes = f.report(vec![f.proposal(5, f.anchor, &[0])]);
    votes.proposals[0].votes = (0..=MAX_PRESENCE_VOTES as u32)
        .map(|signer| NotarizeVote { signer, signature: signature.clone() })
        .collect();
    refused_for(f.verify(&votes), "too many votes");
    assert!(votes.to_canonical_bytes().is_err());
    // More proposals than a report carries.
    let proposals = f.report(
        (0..=MAX_PRESENCE_PROPOSALS as u64).map(|i| f.proposal(5 + i, f.anchor, &[0])).collect(),
    );
    refused_for(f.verify(&proposals), "proposal count");
    assert!(proposals.to_canonical_bytes().is_err());
}

#[test]
fn presence_proposal_without_votes_is_refused() {
    let f = fixture();
    let mut report = f.report(vec![f.proposal(5, f.anchor, &[0]), f.proposal(6, f.anchor, &[1])]);
    f.verify(&report).unwrap();
    report.proposals[1].votes.clear();
    refused_for(f.verify(&report), "no votes");
    assert!(report.to_canonical_bytes().is_err());
}

#[test]
fn presence_report_is_refused_before_its_activation_frame() {
    let f = fixture();
    let report = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    let bytes = report.to_canonical_bytes().unwrap();
    f.verify(&report).unwrap();
    set_presence_report_frame_for_thread(Some(f.frame + 1));
    refused_for(f.verify(&report), "presence report frame");
    // Refused before any state is needed, as an older build would.
    let bare = GlobalIntrinsic::new(Arc::new(crate::testing::NoopKeyManager));
    assert!(matches!(bare.validate(f.frame, &bytes, None, None), Err(QuilError::InvalidArgument(_))));
    assert!(f.intrinsic().invoke_step(f.frame, &bytes, &f.state).is_err());
    set_presence_report_frame_for_thread(Some(f.frame));
    f.verify(&report).unwrap();
    // Without a setting, never (assumes QUIL_PRESENCE_REPORT_FRAME is unset).
    set_presence_report_frame_for_thread(None);
    refused_for(f.verify(&report), "presence report frame");
    assert_eq!(MAINNET_PRESENCE_REPORT_FRAME, None);
    assert_eq!(presence_report_frame_for(0, None), u64::MAX);
    assert_eq!(presence_report_frame_for(0, Some("7")), u64::MAX);
    assert_eq!(presence_report_frame_for(1, Some("7")), 7);
    assert_eq!(presence_report_frame_for(1, Some("soon")), u64::MAX);
    assert_eq!(presence_report_frame_for(1, None), u64::MAX);
}

#[test]
fn engine_validates_a_lone_presence_report_and_refuses_it_beside_other_requests() {
    use crate::{
        engines::GlobalExecutionEngine,
        message_envelope::{CanonicalMessageBundle, CanonicalMessageRequest},
    };
    use quil_types::execution::ShardExecutionEngine as _;
    let f = fixture();
    let report = f.report(vec![f.proposal(5, f.anchor, &[0, 1])]);
    let request = || Some(CanonicalMessageRequest::wrap(report.to_canonical_bytes().unwrap()).unwrap());
    let bundle = |requests| CanonicalMessageBundle { timestamp: 0, requests }.to_canonical_bytes().unwrap();
    let lone = bundle(vec![request()]);
    let engine = GlobalExecutionEngine::new_with_intrinsic(
        Arc::new(StubProver),
        Arc::new(crate::testing::NoopKeyManager),
        f.state.crdt().clone(),
        f.clock.clone(),
        None,
        None,
    );
    engine.validate_message(f.frame, &GLOBAL_INTRINSIC_ADDRESS, &lone).unwrap();
    engine.process_message(f.frame, &BigInt::from(0), &GLOBAL_INTRINSIC_ADDRESS, &lone).unwrap();
    for other in [bundle(vec![request(), request()]), bundle(vec![request(), None]), bundle(vec![None, request()])] {
        assert!(matches!(
            engine.validate_message(f.frame, &GLOBAL_INTRINSIC_ADDRESS, &other),
            Err(QuilError::InvalidArgument(_))
        ));
    }
    let stateless = GlobalExecutionEngine::new(Arc::new(StubProver));
    assert!(matches!(
        stateless.validate_message(f.frame, &GLOBAL_INTRINSIC_ADDRESS, &lone),
        Err(QuilError::ExecutionUnavailable(_))
    ));
    // Before activation every engine refuses it, with or without state.
    set_presence_report_frame_for_thread(Some(f.frame + 1));
    for engine in [&engine, &stateless] {
        assert!(matches!(
            engine.validate_message(f.frame, &GLOBAL_INTRINSIC_ADDRESS, &lone),
            Err(QuilError::InvalidArgument(_))
        ));
    }
}
