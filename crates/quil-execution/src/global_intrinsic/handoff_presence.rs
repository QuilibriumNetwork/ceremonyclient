//! Presence reports: the notarize votes of an app-shard session's members,
//! carried to GLOBAL as evidence of who votes.
//!
//! A session below quorum finalizes nothing, so no certificate shows which of
//! its members are present. A notarize vote does: it signs a real proposal
//! (round, parent view and payload) under the session namespace, and the
//! payload is Poseidon of the frame's output, which binds the GLOBAL frame
//! anchoring the frame's storage beacon. A report carries the proposal's
//! header, so GLOBAL recomputes that output: a vote it accepts was signed
//! after its anchor, in the inclusion frame's epoch. A nullify vote signs only
//! a round and can be signed ahead for every view; it is not evidence, and the
//! codec cannot carry one.
//!
//! GLOBAL only validates reports, from [`super::presence_report_frame`]; an
//! accepted report changes no state yet.

use std::collections::BTreeSet;

use quil_cw_consensus::handoff::{put_bytes, Cursor, SessionVotes, MAX_FILTER_BYTES, MAX_RECORD_BYTES};
use quil_types::error::{QuilError, Result};

use super::{head, presence_report_frame, session, status, Records, Status, TYPE_PRESENCE_REPORT};
use crate::global_intrinsic::frame_header::FrameHeader;

/// Proposals one report may carry.
pub const MAX_PRESENCE_PROPOSALS: usize = 4;

/// Votes one report may carry over all its proposals, whatever its session's
/// size. It also carries at most one vote per session member.
pub const MAX_PRESENCE_VOTES: usize = 64;

const VERSION: u8 = 1;
const SIGNATURE_BYTES: usize = quil_crypto::FALCON_SIGNATURE_LEN;

fn invalid(message: &str) -> QuilError {
    QuilError::InvalidArgument(format!("presence report: {message}"))
}

/// One member's notarize vote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotarizeVote {
    /// The member's index in the session's sorted members.
    pub signer: u32,
    /// Its Falcon signature of the proposal's notarize subject.
    pub signature: Vec<u8>,
}

/// A proposal of the session and the notarize votes it received.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceProposal {
    /// The proposed app frame, without its certificate and its storage
    /// attestation openings: neither enters the frame's output.
    pub header: FrameHeader,
    /// The Simplex round: the session generation, and the view, which is the
    /// header's rank.
    pub epoch: u64,
    pub view: u64,
    pub parent: u64,
    /// Poseidon of the header's output.
    pub payload: [u8; 32],
    /// In ascending signer order.
    pub votes: Vec<NotarizeVote>,
}

/// Notarize votes of one session, the GLOBAL operation [`TYPE_PRESENCE_REPORT`].
///
/// Encoding: type prefix ‖ version ‖ session ID ‖ filter ‖ proposal count
/// (u32) ‖ per proposal: canonical header bytes ‖ epoch ‖ view ‖ parent ‖
/// payload ‖ vote count (u32) ‖ per vote: signer (u32) ‖ signature. Proposals
/// are in ascending view order, and each member votes at most once per report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresenceReport {
    pub session: [u8; 32],
    pub filter: Vec<u8>,
    pub proposals: Vec<PresenceProposal>,
}

impl PresenceReport {
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut out = TYPE_PRESENCE_REPORT.to_be_bytes().to_vec();
        out.push(VERSION);
        out.extend_from_slice(&self.session);
        put_bytes(&mut out, &self.filter)?;
        out.extend_from_slice(&(self.proposals.len() as u32).to_be_bytes());
        for proposal in &self.proposals {
            put_bytes(&mut out, &proposal.header.to_canonical_bytes()?)?;
            out.extend_from_slice(&proposal.epoch.to_be_bytes());
            out.extend_from_slice(&proposal.view.to_be_bytes());
            out.extend_from_slice(&proposal.parent.to_be_bytes());
            out.extend_from_slice(&proposal.payload);
            out.extend_from_slice(&(proposal.votes.len() as u32).to_be_bytes());
            for vote in &proposal.votes {
                out.extend_from_slice(&vote.signer.to_be_bytes());
                out.extend_from_slice(&vote.signature);
            }
            if out.len() > MAX_RECORD_BYTES {
                return Err(invalid("report exceeds size limit"));
            }
        }
        Ok(out)
    }

    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self> {
        let mut c = Cursor::new(bytes)?;
        c.magic(&TYPE_PRESENCE_REPORT.to_be_bytes())?;
        if c.u8()? != VERSION {
            return Err(invalid("unknown version"));
        }
        let session = c.array()?;
        let filter = c.bytes(MAX_FILTER_BYTES)?;
        let n = c.count(MAX_PRESENCE_PROPOSALS, 4 + 3 * 8 + 32 + 4)?;
        let mut proposals = Vec::with_capacity(n);
        for _ in 0..n {
            let encoded = c.bytes(MAX_RECORD_BYTES)?;
            let header = FrameHeader::from_canonical_bytes(&encoded)?;
            // The header decoder tolerates trailing and legacy layouts; a
            // report admits exactly one encoding of each header.
            if header.to_canonical_bytes()? != encoded {
                return Err(invalid("noncanonical frame header"));
            }
            let epoch = c.u64()?;
            let view = c.u64()?;
            let parent = c.u64()?;
            let payload = c.array()?;
            let m = c.count(MAX_PRESENCE_VOTES, 4 + SIGNATURE_BYTES)?;
            let mut votes = Vec::with_capacity(m);
            for _ in 0..m {
                let signer = c.u32()?;
                let signature = c.take(SIGNATURE_BYTES)?.to_vec();
                votes.push(NotarizeVote { signer, signature });
            }
            proposals.push(PresenceProposal { header, epoch, view, parent, payload, votes });
        }
        c.finish()?;
        let report = Self { session, filter, proposals };
        report.validate()?;
        Ok(report)
    }

    /// The votes the report carries over all its proposals.
    pub fn vote_count(&self) -> usize {
        self.proposals.iter().map(|proposal| proposal.votes.len()).sum()
    }

    fn validate(&self) -> Result<()> {
        if !(32..=MAX_FILTER_BYTES).contains(&self.filter.len()) {
            return Err(invalid("invalid full shard filter length"));
        }
        if self.proposals.is_empty() || self.proposals.len() > MAX_PRESENCE_PROPOSALS {
            return Err(invalid("proposal count out of range"));
        }
        if self.proposals.windows(2).any(|pair| pair[0].view >= pair[1].view) {
            return Err(invalid("proposals must be in ascending view order"));
        }
        if self.vote_count() > MAX_PRESENCE_VOTES {
            return Err(invalid("too many votes"));
        }
        let mut signers = BTreeSet::new();
        for proposal in &self.proposals {
            if proposal.votes.is_empty() {
                return Err(invalid("proposal carries no votes"));
            }
            if !proposal.header.public_key_signature_bls48581.is_empty()
                || !proposal.header.storage_attestation.is_empty()
            {
                return Err(invalid("header carries a certificate or storage openings"));
            }
            for vote in &proposal.votes {
                if vote.signature.len() != SIGNATURE_BYTES {
                    return Err(invalid("vote signature has the wrong length"));
                }
                if !signers.insert(vote.signer) {
                    return Err(invalid("duplicate signer"));
                }
            }
            if proposal.votes.windows(2).any(|pair| pair[0].signer >= pair[1].signer) {
                return Err(invalid("votes must be in ascending signer order"));
            }
        }
        Ok(())
    }
}

/// Refuse every report before [`presence_report_frame`].
pub fn require_active(frame: u64) -> Result<()> {
    if frame < presence_report_frame() {
        return Err(invalid("not accepted before the presence report frame"));
    }
    Ok(())
}

/// Validate `report` for inclusion in GLOBAL frame `frame`, without writing.
///
/// `anchor_output` returns a GLOBAL frame's output from this node's clock
/// store. It is asked only for anchors already checked to be earlier frames
/// of `frame`'s epoch, which every node materializing `frame` holds: a report
/// must not make a node look up a frame it may lack, since a missing anchor
/// stops materialization rather than refusing the report.
pub fn verify(
    state: &impl Records,
    frame: u64,
    report: &PresenceReport,
    anchor_output: impl Fn(u64) -> Result<Vec<u8>>,
) -> Result<()> {
    require_active(frame)?;
    report.validate()?;
    let epoch = quil_types::consensus::epoch_for_frame(frame);
    for proposal in &report.proposals {
        let anchor = proposal.header.global_frame_number;
        if anchor == 0 || anchor >= frame || quil_types::consensus::epoch_for_frame(anchor) != epoch {
            return Err(invalid("anchor is not an earlier frame of the inclusion epoch"));
        }
    }
    let session = session(state, &report.session)?.ok_or_else(|| invalid("unknown session"))?;
    if session.filter != report.filter {
        return Err(invalid("session belongs to another filter"));
    }
    if head(state, &report.filter)?.as_ref() != Some(&session) {
        return Err(invalid("session is not the current head of its filter"));
    }
    // A closing session still votes until its seal or fence; a closed one
    // no longer does.
    if matches!(status(state, &report.session)?, Status::Closed(_)) {
        return Err(invalid("session is closed"));
    }
    if report.vote_count() > session.members.len() {
        return Err(invalid("more votes than session members"));
    }
    for proposal in &report.proposals {
        let header = &proposal.header;
        if header.address != session.filter {
            return Err(invalid("header belongs to another filter"));
        }
        if proposal.epoch != session.generation {
            return Err(invalid("round epoch is not the session generation"));
        }
        if header.rank != proposal.view || proposal.view == 0 || proposal.parent >= proposal.view {
            return Err(invalid("proposal view differs from the header rank or follows no parent"));
        }
        if header.frame_number <= session.base_frame {
            return Err(invalid("header frame is not above the session base"));
        }
    }
    let votes = SessionVotes::new(&session)?;
    for proposal in &report.proposals {
        let output = anchor_output(proposal.header.global_frame_number)?;
        crate::global_intrinsic::prover_shard_update::verify_app_frame_output(&proposal.header, &output)
            .map_err(|_| invalid("header output does not match its fields and anchor"))?;
        if quil_crypto::poseidon::hash_bytes_to_32(&proposal.header.output)? != proposal.payload {
            return Err(invalid("payload is not the digest of the header output"));
        }
        for vote in &proposal.votes {
            if !votes.verify_notarize(
                proposal.epoch,
                proposal.view,
                proposal.parent,
                proposal.payload,
                vote.signer,
                &vote.signature,
            ) {
                return Err(invalid("vote is not a session member's notarize of the proposal"));
            }
        }
    }
    Ok(())
}
