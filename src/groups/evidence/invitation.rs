//! Signed invitations, admission decisions, and proposal inboxes.

use super::proof::CarriedProof;
use super::wire::CertificateRef;
use super::{
    AdmissionError, AdmissionUpdate, DirectVoucher, Error, Installation, Key, MAX_LIFETIME_MS,
    RosterHistory, VouchedGroup, parse_verifying_key, random_id,
};
use crate::groups::{MemberLocalState, Proposal, Vote};
use crate::session::installation::{
    group_admission_consent_message, group_admission_vote_message,
    group_invitation_cancellation_message, group_invitation_message,
};
use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

// Group, parent, nonce, inviter, candidate, and deadline, in that order.
pub const INVITATION_BODY_LEN: usize = 144;
const INVITATION_FRAME_HEADER: [u8; 4] = *b"MSHI";
const INVITATION_FRAME_LEN: usize = 5 + INVITATION_BODY_LEN + 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum InvitationFrameVersion {
    V1 = 1,
    V2 = 2,
}

impl InvitationFrameVersion {
    fn signature_binding(self, body: &[u8; INVITATION_BODY_LEN]) -> [u8; 32] {
        match self {
            // V1 uses the existing invitation-only signing domain and bytes.
            Self::V1 => Sha256::digest(body).into(),
            Self::V2 => Sha256::new()
                .chain_update(INVITATION_FRAME_HEADER)
                .chain_update([self as u8])
                .chain_update(body)
                .finalize()
                .into(),
        }
    }
}

pub struct SignedInvitation {
    body: [u8; INVITATION_BODY_LEN],
    signature: [u8; 64],
}

impl SignedInvitation {
    /// The transported invitation must have an explicit deadline.
    pub fn new(proposal: &VouchedProposal, inviter: &Installation) -> Result<Self, AdmissionError> {
        Self::sign(proposal, inviter, InvitationFrameVersion::V1)
    }

    fn sign(
        proposal: &VouchedProposal,
        inviter: &Installation,
        version: InvitationFrameVersion,
    ) -> Result<Self, AdmissionError> {
        if inviter.selected() != proposal.inviter {
            return Err(Error::Ineligible.into());
        }
        let deadline = proposal.expires_at.ok_or(AdmissionError::InvalidExpiry)?;
        let body = proposal.invitation_body(deadline);
        let signature = inviter
            .sign_group_invitation(version.signature_binding(&body))
            .map_err(|e| super::agreement::roster_signing_error(e, Error::Ineligible))?;
        Ok(Self { body, signature })
    }

    /// Encode an invitation for the versioned transport. The legacy raw
    /// encoding remains available through `new` and `to_bytes`.
    pub fn encode_frame(
        proposal: &VouchedProposal,
        inviter: &Installation,
        version: InvitationFrameVersion,
    ) -> Result<[u8; INVITATION_FRAME_LEN], AdmissionError> {
        let signed = Self::sign(proposal, inviter, version)?;
        let mut frame = [0; INVITATION_FRAME_LEN];
        frame[..4].copy_from_slice(&INVITATION_FRAME_HEADER);
        frame[4] = version as u8;
        frame[5..].copy_from_slice(&signed.to_bytes());
        Ok(frame)
    }

    pub fn to_bytes(&self) -> [u8; INVITATION_BODY_LEN + 64] {
        let mut bytes = [0; INVITATION_BODY_LEN + 64];
        bytes[..INVITATION_BODY_LEN].copy_from_slice(&self.body);
        bytes[INVITATION_BODY_LEN..].copy_from_slice(&self.signature);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; INVITATION_BODY_LEN + 64] =
            bytes.try_into().map_err(|_| Error::Ineligible)?;
        Ok(Self {
            body: bytes[..INVITATION_BODY_LEN].try_into().unwrap(),
            signature: bytes[INVITATION_BODY_LEN..].try_into().unwrap(),
        })
    }

    fn decode_frame(
        frame: &[u8],
        supported: InvitationFrameVersion,
    ) -> Result<(Self, InvitationFrameVersion), AdmissionError> {
        let Some(payload) = frame.strip_prefix(&INVITATION_FRAME_HEADER) else {
            return Err(AdmissionError::MalformedInvitationFrame);
        };
        let Some((&version, payload)) = payload.split_first() else {
            return Err(AdmissionError::MalformedInvitationFrame);
        };
        let version = match version {
            1 => InvitationFrameVersion::V1,
            2 if supported == InvitationFrameVersion::V2 => InvitationFrameVersion::V2,
            version => return Err(AdmissionError::UnsupportedInvitationVersion(version)),
        };
        let signed =
            Self::from_bytes(payload).map_err(|_| AdmissionError::MalformedInvitationFrame)?;
        Ok((signed, version))
    }
}

/// What a candidate learns from a verified invitation frame, without holding the group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvitationFacts {
    pub group: u64,
    pub parent: [u8; 32],
    pub id: [u8; 32],
    pub inviter: Key,
    pub candidate: Key,
    pub deadline: u64,
    /// The binding that consent, votes and the voucher refer to.
    pub binding: [u8; 32],
}

impl SignedInvitation {
    /// Check the inviter's signature on a version-1 frame and read its fields. The caller
    /// decides whether it trusts the inviter and whether the deadline is acceptable.
    pub fn inspect_frame(frame: &[u8]) -> Result<InvitationFacts, AdmissionError> {
        let (signed, version) = Self::decode_frame(frame, InvitationFrameVersion::V1)?;
        let body = &signed.body;
        let inviter: Key = body[72..104].try_into().unwrap();
        let deadline = u64::from_be_bytes(body[136..].try_into().unwrap());
        if deadline == 0 {
            return Err(AdmissionError::InvalidExpiry);
        }
        parse_verifying_key(&inviter)?
            .verify_strict(
                &group_invitation_message(version.signature_binding(body)),
                &Signature::from_bytes(&signed.signature),
            )
            .map_err(|_| Error::Ineligible)?;
        let candidate: Key = body[104..136].try_into().unwrap();
        parse_verifying_key(&candidate)?;
        Ok(InvitationFacts {
            group: u64::from_be_bytes(body[..8].try_into().unwrap()),
            parent: body[8..40].try_into().unwrap(),
            id: body[40..72].try_into().unwrap(),
            inviter,
            candidate,
            deadline,
            binding: Sha256::digest(body).into(),
        })
    }
}

impl SignedAdmissionConsent {
    /// Consent for an inspected invitation. The candidate needs no copy of the group.
    pub fn for_invitation(
        facts: &InvitationFacts,
        candidate: &Installation,
    ) -> Result<Self, Error> {
        if candidate.selected() != facts.candidate {
            return Err(Error::Ineligible);
        }
        Ok(Self(
            candidate
                .sign_group_admission_consent(
                    facts.group,
                    facts.parent,
                    facts.binding,
                    facts.inviter,
                )
                .map_err(|e| super::agreement::roster_signing_error(e, Error::Ineligible))?,
        ))
    }
}

impl VouchedGroup {
    /// Rebuild the proposal for a version-1 invitation frame against this roster.
    pub fn receive_invitation_frame(
        &self,
        frame: &[u8],
    ) -> Result<VouchedProposal, AdmissionError> {
        let (signed, version) = SignedInvitation::decode_frame(frame, InvitationFrameVersion::V1)?;
        let proposal = self.decode_invitation(&signed, version)?;
        self.check_invitation(&proposal)?;
        Ok(proposal)
    }
}

/// A cancellation travels alongside the original signed invitation.
pub struct SignedInvitationCancellation([u8; 64]);

impl SignedInvitationCancellation {
    pub fn new(invitation: &SignedInvitation, inviter: &Installation) -> Result<Self, Error> {
        if invitation.body[72..104] != inviter.selected() {
            return Err(Error::Ineligible);
        }
        Ok(Self(
            inviter
                .sign_group_invitation_cancellation(Sha256::digest(invitation.body).into())
                .map_err(|e| super::agreement::roster_signing_error(e, Error::Ineligible))?,
        ))
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(bytes.try_into().map_err(|_| Error::Ineligible)?))
    }
}

/// Peer-local pending proposals. Reuse one inbox per group view so retries
/// preserve the votes and candidate consent already recorded.
#[derive(Default)]
pub struct InvitationInbox {
    pending: BTreeMap<[u8; 32], VouchedProposal>,
}

impl InvitationInbox {
    pub const MAX_PENDING: usize = 64;
    pub const MAX_PER_INVITER: usize = 8;

    fn is_active(group: &VouchedGroup, proposal: &VouchedProposal) -> bool {
        !proposal.cancelled
            && !proposal.declined
            && !group
                .cancelled_invitations
                .contains_key(&proposal.decision_binding())
    }

    pub fn receive(
        &mut self,
        group: &VouchedGroup,
        signed: &SignedInvitation,
    ) -> Result<&mut VouchedProposal, AdmissionError> {
        self.prune(group);
        let proposal = group.receive_invitation(signed)?;
        self.store(group, proposal)
    }

    /// Decode before touching the inbox, including when an upgrade is needed.
    pub fn receive_frame(
        &mut self,
        group: &VouchedGroup,
        frame: &[u8],
        supported: InvitationFrameVersion,
    ) -> Result<&mut VouchedProposal, AdmissionError> {
        let (signed, version) = SignedInvitation::decode_frame(frame, supported)?;
        let proposal = group.decode_invitation(&signed, version)?;
        group.check_invitation(&proposal)?;
        self.prune(group);
        self.store(group, proposal)
    }

    fn prune(&mut self, group: &VouchedGroup) {
        self.pending.retain(|_, proposal| {
            proposal.parent.id == group.history.id
                && proposal
                    .expires_at
                    .is_some_and(|deadline| deadline > group.now)
        });
    }

    fn store(
        &mut self,
        group: &VouchedGroup,
        proposal: VouchedProposal,
    ) -> Result<&mut VouchedProposal, AdmissionError> {
        let binding = proposal.decision_binding();
        if !self.pending.contains_key(&binding) {
            // Bound what a single member (or a flood of members) can make a peer remember.
            let from_inviter = self
                .pending
                .values()
                .filter(|existing| {
                    existing.inviter == proposal.inviter && Self::is_active(group, existing)
                })
                .count();
            if from_inviter >= Self::MAX_PER_INVITER {
                return Err(AdmissionError::InboxFull);
            }
            if self.pending.len() >= Self::MAX_PENDING {
                let inactive_key = self
                    .pending
                    .iter()
                    .find(|(_, p)| !Self::is_active(group, p))
                    .map(|(k, _)| *k);
                if let Some(key) = inactive_key {
                    self.pending.remove(&key);
                } else {
                    // Full of active entries: make room by dropping the soonest-expiring entry
                    // of whichever inviter holds the most, but only if that inviter holds
                    // more than the newcomer's, so a flooder cannot evict honest entries.
                    let mut counts: BTreeMap<Key, usize> = BTreeMap::new();
                    for p in self.pending.values() {
                        *counts.entry(p.inviter).or_default() += 1;
                    }
                    let mine = counts.get(&proposal.inviter).copied().unwrap_or(0);
                    let victim = self
                        .pending
                        .iter()
                        .filter(|(_, p)| counts[&p.inviter] > mine + 1)
                        .max_by_key(|(_, p)| (counts[&p.inviter], std::cmp::Reverse(p.expires_at)))
                        .map(|(k, _)| *k);
                    match victim {
                        Some(key) => {
                            self.pending.remove(&key);
                        }
                        None => return Err(AdmissionError::InboxFull),
                    }
                }
            }
            group.check_invitation(&proposal)?;
            self.pending.insert(binding, proposal);
        }
        let pending = self.pending.get_mut(&binding).unwrap();
        group.check_invitation(pending)?;
        Ok(pending)
    }

    pub fn pending(&self) -> impl Iterator<Item = &VouchedProposal> {
        self.pending.values()
    }

    pub fn remove(&mut self, binding: &[u8; 32]) -> Option<VouchedProposal> {
        self.pending.remove(binding)
    }
}

/// Acceptance signed by the identity named on the invitation.
pub struct SignedAdmissionConsent([u8; 64]);

impl SignedAdmissionConsent {
    pub fn new(proposal: &VouchedProposal, candidate: &Installation) -> Result<Self, Error> {
        if candidate.selected() != proposal.candidate {
            return Err(Error::Ineligible);
        }
        Ok(Self(
            candidate
                .sign_group_admission_consent(
                    proposal.proposal.group,
                    proposal.parent.id,
                    proposal.decision_binding(),
                    proposal.inviter,
                )
                .map_err(|e| super::agreement::roster_signing_error(e, Error::Ineligible))?,
        ))
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }

    /// Decode a consent signature. Application verifies it against the invitation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(bytes.try_into().map_err(|_| Error::Ineligible)?))
    }
}

/// An explicit decision from one identity on a single invitation.
pub struct SignedAdmissionVote {
    voter: Key,
    decision: Vote,
    signature: [u8; 64],
}

fn admission_decision_code(decision: Vote) -> u8 {
    match decision {
        Vote::Approve => 1,
        Vote::Object => 2,
        Vote::Abstain => 3,
    }
}

impl SignedAdmissionVote {
    pub fn new(
        proposal: &VouchedProposal,
        voter: &Installation,
        decision: Vote,
    ) -> Result<Self, Error> {
        Ok(Self {
            voter: voter.selected(),
            decision,
            signature: voter
                .sign_group_admission_vote(
                    proposal.proposal.group,
                    proposal.parent.id,
                    proposal.decision_binding(),
                    admission_decision_code(decision),
                )
                .map_err(|e| super::agreement::roster_signing_error(e, Error::Ineligible))?,
        })
    }

    pub fn to_bytes(&self) -> [u8; 97] {
        let mut bytes = [0; 97];
        bytes[..32].copy_from_slice(&self.voter);
        bytes[32] = admission_decision_code(self.decision);
        bytes[33..].copy_from_slice(&self.signature);
        bytes
    }

    /// Decode a vote. Application verifies the signature and voting eligibility.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 97] = bytes.try_into().map_err(|_| Error::Ineligible)?;
        let decision = match bytes[32] {
            1 => Vote::Approve,
            2 => Vote::Object,
            3 => Vote::Abstain,
            _ => return Err(Error::Ineligible),
        };
        Ok(Self {
            voter: bytes[..32].try_into().unwrap(),
            decision,
            signature: bytes[33..].try_into().unwrap(),
        })
    }
}

/// Admission progress available to a member or the invited identity.
#[derive(Debug, PartialEq, Eq)]
pub struct InvitationProgress {
    pub candidate_accepted: bool,
    pub approvals: usize,
    pub required: usize,
    pub objections: usize,
    pub abstentions: usize,
    pub unanswered: usize,
    pub viewer_vote: Option<Vote>,
}

pub struct VouchedProposal {
    invitation_id: [u8; 32],
    parent: Arc<RosterHistory>,
    proposal: Proposal,
    candidate: Key,
    inviter: Key,
    declined: bool,
    cancelled: bool,
    expires_at: Option<u64>,
}

impl VouchedProposal {
    fn invitation_body(&self, deadline: u64) -> [u8; INVITATION_BODY_LEN] {
        let mut body = [0; INVITATION_BODY_LEN];
        body[..8].copy_from_slice(&self.proposal.group.to_be_bytes());
        body[8..40].copy_from_slice(&self.parent.id);
        body[40..72].copy_from_slice(&self.invitation_id);
        body[72..104].copy_from_slice(&self.inviter);
        body[104..136].copy_from_slice(&self.candidate);
        body[136..].copy_from_slice(&deadline.to_be_bytes());
        body
    }

    pub(crate) fn bind_parent(&mut self, nonce: [u8; 32], parent_digest: [u8; 32]) {
        self.invitation_id = Self::parent_binding(nonce, parent_digest);
    }

    pub(crate) fn parent_binding(nonce: [u8; 32], parent_digest: [u8; 32]) -> [u8; 32] {
        Sha256::new()
            .chain_update(b"mesh/handle/invitation-parent/v1\0")
            .chain_update(nonce)
            .chain_update(parent_digest)
            .finalize()
            .into()
    }

    pub fn decision_binding(&self) -> [u8; 32] {
        // Zero cannot be the deadline of a live invitation.
        Sha256::digest(self.invitation_body(self.expires_at.unwrap_or(0))).into()
    }

    pub fn candidate(&self) -> Key {
        self.candidate
    }

    pub fn inviter(&self) -> Key {
        self.inviter
    }

    pub fn decline(&mut self, candidate: Key) -> Result<(), Error> {
        if candidate != self.candidate {
            return Err(Error::Ineligible);
        }
        self.declined = true;
        Ok(())
    }

    pub fn accept(&mut self, candidate: Key) -> Result<(), Error> {
        if candidate != self.candidate || self.declined || self.cancelled {
            return Err(Error::Ineligible);
        }
        self.proposal.accept(self.proposal.candidate)
    }
}

fn admission_child_id(binding: [u8; 32], voucher: &DirectVoucher) -> [u8; 32] {
    Sha256::new()
        .chain_update(b"mesh/group-admission/admission-child/v2\0")
        .chain_update(binding)
        .chain_update(Sha256::digest(voucher.admission_body()))
        .finalize()
        .into()
}

impl VouchedGroup {
    /// Sign an admission vote through the local membership and backup gates.
    pub fn sign_admission_vote(
        &self,
        local: &MemberLocalState,
        proposal: &VouchedProposal,
        voter: &Installation,
        decision: Vote,
    ) -> Result<SignedAdmissionVote, AdmissionError> {
        self.check_invitation(proposal)?;
        self.check_local_voter(local, voter)?;
        Ok(SignedAdmissionVote::new(proposal, voter, decision)?)
    }

    /// Current approval progress for a live invitation on this roster.
    pub fn approval_counts(
        &self,
        proposal: &VouchedProposal,
    ) -> Result<(usize, usize), AdmissionError> {
        self.check_invitation(proposal)?;
        Ok(self.group.approval_counts(&proposal.proposal))
    }

    pub fn invitation_progress(
        &self,
        proposal: &VouchedProposal,
        viewer: Key,
    ) -> Result<InvitationProgress, AdmissionError> {
        self.check_invitation(proposal)?;
        let member = self.membership(viewer);
        if member.is_none() && viewer != proposal.candidate {
            return Err(Error::Ineligible.into());
        }
        let (approvals, required) = self.group.approval_counts(&proposal.proposal);
        let votes = &proposal.proposal.votes;
        let answered = votes
            .keys()
            .filter(|&&id| self.group.is_eligible_voter(id))
            .count();
        Ok(InvitationProgress {
            candidate_accepted: proposal.proposal.accepted,
            approvals,
            required,
            objections: votes
                .iter()
                .filter(|&(&id, &vote)| vote == Vote::Object && self.group.is_eligible_voter(id))
                .count(),
            abstentions: votes
                .iter()
                .filter(|&(&id, &vote)| vote == Vote::Abstain && self.group.is_eligible_voter(id))
                .count(),
            unanswered: self.group.electorate_size().saturating_sub(answered),
            viewer_vote: member.and_then(|member| votes.get(&member.identity).copied()),
        })
    }

    pub fn invite(&self, inviter: Key, candidate: Key) -> Result<VouchedProposal, Error> {
        if self.retired.contains(&candidate) || self.is_barred(&inviter) {
            return Err(Error::Ineligible);
        }
        let inviter_id = *self.identities.get(&inviter).ok_or(Error::Ineligible)?;
        if self.group.membership(inviter_id).is_none() {
            return Err(Error::Ineligible);
        }
        let next = crate::groups::Identity(
            self.identities
                .values()
                .map(|i| i.0)
                .max()
                .map_or(0, |m| m + 1),
        );
        let candidate_id = self.identities.get(&candidate).copied().unwrap_or(next);
        Ok(VouchedProposal {
            invitation_id: random_id(),
            parent: Arc::clone(&self.history),
            proposal: self.group.invite(inviter_id, candidate_id)?,
            candidate,
            inviter,
            declined: false,
            cancelled: false,
            expires_at: None,
        })
    }

    /// Reconstruct an initial proposal against a parent the receiver already knows.
    pub fn receive_invitation(
        &self,
        signed: &SignedInvitation,
    ) -> Result<VouchedProposal, AdmissionError> {
        let proposal = self.decode_invitation(signed, InvitationFrameVersion::V1)?;
        self.check_invitation(&proposal)?;
        Ok(proposal)
    }

    /// Record an inviter-signed cancellation even if the invitation has not
    /// yet reached the local inbox.
    pub fn apply_invitation_cancellation(
        &mut self,
        invitation: &SignedInvitation,
        cancellation: &SignedInvitationCancellation,
    ) -> Result<bool, AdmissionError> {
        self.apply_cancellation(invitation, cancellation, InvitationFrameVersion::V1)
    }

    /// Process cancellation for the invitation carried in a versioned frame.
    /// The cancellation itself still targets the same proposal across versions.
    pub fn apply_invitation_frame_cancellation(
        &mut self,
        frame: &[u8],
        cancellation: &SignedInvitationCancellation,
        supported: InvitationFrameVersion,
    ) -> Result<bool, AdmissionError> {
        let (signed, version) = SignedInvitation::decode_frame(frame, supported)?;
        self.apply_cancellation(&signed, cancellation, version)
    }

    fn apply_cancellation(
        &mut self,
        invitation: &SignedInvitation,
        cancellation: &SignedInvitationCancellation,
        version: InvitationFrameVersion,
    ) -> Result<bool, AdmissionError> {
        let body = &invitation.body;
        let group = u64::from_be_bytes(body[..8].try_into().unwrap());
        if group != self.group.id || body[8..40] != self.history.id {
            return Err(Error::StaleProposal.into());
        }
        let inviter = body[72..104].try_into().unwrap();
        let deadline = u64::from_be_bytes(body[136..].try_into().unwrap());
        if deadline == 0 {
            return Err(AdmissionError::InvalidExpiry);
        }
        if !self.identities.contains_key(&inviter) && !self.retired.contains(&inviter) {
            return Err(Error::Ineligible.into());
        }
        let key = parse_verifying_key(&inviter)?;
        let binding = Sha256::digest(body).into();
        key.verify_strict(
            &group_invitation_message(version.signature_binding(body)),
            &Signature::from_bytes(&invitation.signature),
        )
        .map_err(|_| Error::Ineligible)?;
        key.verify_strict(
            &group_invitation_cancellation_message(binding),
            &Signature::from_bytes(&cancellation.0),
        )
        .map_err(|_| Error::Ineligible)?;
        if deadline.saturating_sub(self.now) > MAX_LIFETIME_MS {
            return Err(AdmissionError::InvalidExpiry);
        }
        if deadline <= self.now {
            return Err(AdmissionError::InvitationExpired);
        }
        Ok(self
            .cancelled_invitations
            .insert(binding, deadline)
            .is_none())
    }

    fn decode_invitation(
        &self,
        signed: &SignedInvitation,
        version: InvitationFrameVersion,
    ) -> Result<VouchedProposal, AdmissionError> {
        let body = &signed.body;
        let group = u64::from_be_bytes(body[..8].try_into().unwrap());
        if group != self.group.id || body[8..40] != self.history.id {
            return Err(Error::StaleProposal.into());
        }
        let inviter = body[72..104].try_into().unwrap();
        let candidate = body[104..136].try_into().unwrap();
        let deadline = u64::from_be_bytes(body[136..].try_into().unwrap());
        let key = parse_verifying_key(&inviter)?;
        key.verify_strict(
            &group_invitation_message(version.signature_binding(body)),
            &Signature::from_bytes(&signed.signature),
        )
        .map_err(|_| Error::Ineligible)?;
        if deadline <= self.now {
            return Err(AdmissionError::InvitationExpired);
        }
        let mut proposal = self.invite_until(inviter, candidate, deadline)?;
        proposal.invitation_id = body[40..72].try_into().unwrap();
        Ok(proposal)
    }

    pub fn invite_until(
        &self,
        inviter: Key,
        candidate: Key,
        expires_at: u64,
    ) -> Result<VouchedProposal, AdmissionError> {
        if expires_at <= self.now || expires_at - self.now > MAX_LIFETIME_MS {
            return Err(AdmissionError::InvalidExpiry);
        }
        let mut proposal = self.invite(inviter, candidate)?;
        proposal.expires_at = Some(expires_at);
        Ok(proposal)
    }

    /// The original inviter can withdraw a pending invitation under the agreed
    /// roster order. The caller supplies the authenticated inviter identity.
    pub fn cancel_invitation(
        &self,
        proposal: &mut VouchedProposal,
        inviter: Key,
    ) -> Result<(), AdmissionError> {
        self.check_invitation(proposal)?;
        if inviter != proposal.inviter {
            return Err(Error::Ineligible.into());
        }
        proposal.cancelled = true;
        Ok(())
    }

    pub(super) fn check_invitation(
        &self,
        proposal: &VouchedProposal,
    ) -> Result<(), AdmissionError> {
        self.group.check_parent(&proposal.proposal)?;
        if self.history.id != proposal.parent.id {
            return Err(Error::StaleProposal.into());
        }
        if proposal.cancelled
            || self
                .cancelled_invitations
                .contains_key(&proposal.decision_binding())
        {
            return Err(AdmissionError::InvitationCancelled);
        }
        if proposal.declined {
            return Err(AdmissionError::InvitationDeclined);
        }
        if proposal.expires_at.is_some_and(|expiry| self.now >= expiry) {
            return Err(AdmissionError::InvitationExpired);
        }
        Ok(())
    }

    pub fn apply_admission_consent(
        &self,
        proposal: &mut VouchedProposal,
        consent: &SignedAdmissionConsent,
    ) -> Result<(), AdmissionError> {
        self.check_invitation(proposal)?;
        let message = group_admission_consent_message(
            proposal.proposal.group,
            proposal.parent.id,
            proposal.decision_binding(),
            proposal.inviter,
            proposal.candidate,
        );
        let candidate = parse_verifying_key(&proposal.candidate)?;
        candidate
            .verify_strict(&message, &Signature::from_bytes(&consent.0))
            .map_err(|_| Error::Ineligible)?;
        Ok(proposal.accept(proposal.candidate)?)
    }

    pub fn apply_admission_vote(
        &self,
        proposal: &mut VouchedProposal,
        signed: &SignedAdmissionVote,
    ) -> Result<(), AdmissionError> {
        let message = group_admission_vote_message(
            proposal.proposal.group,
            proposal.parent.id,
            proposal.decision_binding(),
            admission_decision_code(signed.decision),
        );
        let voter = parse_verifying_key(&signed.voter)?;
        voter
            .verify_strict(&message, &Signature::from_bytes(&signed.signature))
            .map_err(|_| Error::Ineligible)?;
        self.vote(proposal, signed.voter, signed.decision)
    }

    pub(crate) fn vote(
        &self,
        proposal: &mut VouchedProposal,
        voter: Key,
        vote: Vote,
    ) -> Result<(), AdmissionError> {
        self.check_invitation(proposal)?;
        if self.is_barred(&voter) {
            return Err(Error::Ineligible.into());
        }
        let id = *self.identities.get(&voter).ok_or(Error::Ineligible)?;
        Ok(self.group.vote(&mut proposal.proposal, id, vote)?)
    }

    pub(crate) fn admit(
        &mut self,
        proposal: &VouchedProposal,
        voucher: Option<DirectVoucher>,
    ) -> Result<AdmissionUpdate, AdmissionError> {
        self.check_invitation(proposal)?;
        let voucher = voucher.ok_or(AdmissionError::VoucherRequired)?;
        let child = self.admission_child(proposal, &voucher)?;
        self.commit_admission(proposal, voucher, child, Vec::new())
    }

    pub fn admission_child(
        &self,
        proposal: &VouchedProposal,
        voucher: &DirectVoucher,
    ) -> Result<[u8; 32], AdmissionError> {
        self.check_invitation(proposal)?;
        self.check_admission_evidence(proposal, voucher)?;
        self.group.check_admission(&proposal.proposal)?;
        Ok(admission_child_id(proposal.decision_binding(), voucher))
    }

    /// Whether this roster is the one the admission of `candidate` produced from this
    /// invitation binding and voucher: its head is the child they determine, and it records the
    /// candidate as a member admitted on that voucher. A candidate checks a snapshot with this.
    pub fn admitted_by(&self, candidate: Key, binding: [u8; 32], voucher: &DirectVoucher) -> bool {
        self.history.id == admission_child_id(binding, voucher)
            && self.membership(candidate).is_some()
            && self.admission_evidence.get(&candidate) == Some(&voucher.id)
    }

    pub fn apply_certified_admission<'c>(
        &mut self,
        proposal: &VouchedProposal,
        voucher: DirectVoucher,
        certificate: impl Into<CertificateRef<'c>>,
    ) -> Result<AdmissionUpdate, AdmissionError> {
        let child = self.admission_child(proposal, &voucher)?;
        let carried = self.verify_certificate(child, certificate.into())?;
        self.commit_admission(proposal, voucher, child, carried)
    }

    fn commit_admission(
        &mut self,
        proposal: &VouchedProposal,
        voucher: DirectVoucher,
        child: [u8; 32],
        carried: Vec<CarriedProof>,
    ) -> Result<AdmissionUpdate, AdmissionError> {
        self.group.admit(&proposal.proposal)?;
        self.record_roster_child_carrying(child, carried);
        self.admission_evidence
            .insert(proposal.candidate, voucher.id);
        self.identities
            .insert(proposal.candidate, proposal.proposal.candidate);
        Ok(AdmissionUpdate {
            group: self.clone(),
            voucher,
        })
    }
}
