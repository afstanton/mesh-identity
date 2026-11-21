//! Roster certificates, round changes, and freshness observations.

use super::electorate::{
    ElectorateQuorumCheck, QuorumRejection, QuorumSatisfied, check_electorate_quorum,
};
use super::proof::{CarriedProof, ProofContext, verify_equivocation};
use super::wire::{CertificateRef, CertificateV1, chain_digest_with_reports};
use super::{CatchUp, Error, Installation, Key, VouchedGroup, parse_verifying_key, random_id};
use crate::groups::{MemberLocalState, Membership};
use crate::session::installation::{
    Error as InstallationError, group_roster_freshness_message, group_roster_vote_message,
};
use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

pub(super) fn roster_signing_error(error: InstallationError, fallback: Error) -> Error {
    match error {
        InstallationError::RosterSigningStateUnconfirmed => Error::RosterSigningStateUnconfirmed,
        InstallationError::NotVotingDevice => Error::NotVotingDevice,
        InstallationError::RosterCheckpointWriteFailed
        | InstallationError::InvalidRosterCheckpoint => Error::RosterCheckpointFailed,
        _ => fallback,
    }
}

/// Most signatures one certificate or prepare proof carries. Larger electorates need a wider
/// encoding.
pub const MAX_CERTIFICATE_SIGNERS: usize = 128;

/// A member signature over a prepare or commit statement.
#[derive(Clone, Copy)]
pub struct RosterVote {
    pub signer: Key,
    pub signature: [u8; 64],
}

impl RosterVote {
    const WIRE_LEN: usize = 96;

    pub fn to_bytes(&self) -> [u8; Self::WIRE_LEN] {
        let mut bytes = [0; Self::WIRE_LEN];
        bytes[..32].copy_from_slice(&self.signer);
        bytes[32..].copy_from_slice(&self.signature);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; Self::WIRE_LEN] = bytes.try_into().map_err(|_| Error::Ineligible)?;
        Ok(Self::from_wire(bytes))
    }

    fn from_wire(bytes: &[u8; Self::WIRE_LEN]) -> Self {
        Self {
            signer: bytes[..32].try_into().unwrap(),
            signature: bytes[32..].try_into().unwrap(),
        }
    }
}

/// Request for an observation of the current head of a known group.
#[derive(Clone, Copy)]
pub struct RosterFreshnessQuery {
    pub group: u64,
    pub nonce: [u8; 32],
}

impl RosterFreshnessQuery {
    pub fn to_bytes(&self) -> [u8; 40] {
        let mut bytes = [0; 40];
        bytes[..8].copy_from_slice(&self.group.to_be_bytes());
        bytes[8..].copy_from_slice(&self.nonce);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 40] = bytes.try_into().map_err(|_| Error::Ineligible)?;
        Ok(Self {
            group: u64::from_be_bytes(bytes[..8].try_into().unwrap()),
            nonce: bytes[8..].try_into().unwrap(),
        })
    }
}

/// The requester retains the challenge and checks the response on its own clock.
pub struct RosterFreshnessChallenge {
    query: RosterFreshnessQuery,
    started: Instant,
}

impl RosterFreshnessChallenge {
    pub const WINDOW: Duration = Duration::from_secs(30);

    pub fn new(group: u64, now: Instant) -> Self {
        Self {
            query: RosterFreshnessQuery {
                group,
                nonce: random_id(),
            },
            started: now,
        }
    }

    pub fn query(&self) -> RosterFreshnessQuery {
        self.query
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RosterFreshnessError {
    ExpiredChallenge,
    Unconfirmed,
}

#[derive(Clone, Copy)]
#[repr(u8)]
pub enum RosterVotePhase {
    Prepare = 1,
    Commit = 2,
}

pub struct RosterVoteRequest {
    pub parent: [u8; 32],
    pub child: [u8; 32],
    pub round: u32,
    pub phase: RosterVotePhase,
}

/// Prepare and commit signatures checked against the eligible parent members.
pub struct RosterCertificate {
    pub group: u64,
    pub parent: [u8; 32],
    pub child: [u8; 32],
    pub round: u32,
    pub prepares: Vec<RosterVote>,
    pub commits: Vec<RosterVote>,
}

/// Compatibility name for the roster certificate used by recovery.
pub type RecoveryCertificate = RosterCertificate;

impl RosterCertificate {
    const HEADER_LEN: usize = 76;

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let count = self.prepares.len();
        if !(1..=MAX_CERTIFICATE_SIGNERS).contains(&count) || self.commits.len() != count {
            return Err(Error::Ineligible);
        }
        let mut bytes = vec![0; Self::HEADER_LEN + count * 2 * RosterVote::WIRE_LEN];
        bytes[..8].copy_from_slice(&self.group.to_be_bytes());
        bytes[8..40].copy_from_slice(&self.parent);
        bytes[40..72].copy_from_slice(&self.child);
        bytes[72..76].copy_from_slice(&self.round.to_be_bytes());
        for (slot, vote) in bytes[Self::HEADER_LEN..]
            .chunks_exact_mut(RosterVote::WIRE_LEN)
            .zip(self.prepares.iter().chain(&self.commits))
        {
            slot.copy_from_slice(&vote.to_bytes());
        }
        Ok(bytes)
    }

    /// Decode a supported certificate size. The receiving roster determines the required quorum.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(Error::Ineligible);
        }
        let payload = bytes.len() - Self::HEADER_LEN;
        if payload % (2 * RosterVote::WIRE_LEN) != 0 {
            return Err(Error::Ineligible);
        }
        let count = payload / (2 * RosterVote::WIRE_LEN);
        if !(1..=MAX_CERTIFICATE_SIGNERS).contains(&count) {
            return Err(Error::Ineligible);
        }
        let (prepares, commits) = bytes[Self::HEADER_LEN..].split_at(count * RosterVote::WIRE_LEN);
        let decode = |votes: &[u8]| {
            votes
                .chunks_exact(RosterVote::WIRE_LEN)
                .map(|chunk| RosterVote::from_wire(chunk.try_into().unwrap()))
                .collect()
        };
        Ok(Self {
            group: u64::from_be_bytes(bytes[..8].try_into().unwrap()),
            parent: bytes[8..40].try_into().unwrap(),
            child: bytes[40..72].try_into().unwrap(),
            round: u32::from_be_bytes(bytes[72..76].try_into().unwrap()),
            prepares: decode(prepares),
            commits: decode(commits),
        })
    }
}

/// A prepare quorum for a child in an earlier round of the same parent.
#[derive(Clone)]
pub struct RosterPrepareProof {
    pub round: u32,
    pub child: [u8; 32],
    pub votes: Vec<RosterVote>,
}

/// A member's signed claim about its prepared state when requesting a new round.
pub struct RosterRoundChange {
    group: u64,
    parent: [u8; 32],
    round: u32,
    vote: RosterVote,
    prepared: Option<RosterPrepareProof>,
}

impl RosterRoundChange {
    const BASE_LEN: usize = 140;
    const PROOF_HEADER_LEN: usize = 36;
    const PHASE: u8 = 3;

    /// Sign a round-change report. An identity that already signed a different claim for this
    /// round (or voted in a later one) is refused, so it cannot equivocate by accident.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new(
        context: (u64, [u8; 32]),
        round: u32,
        prepared: Option<RosterPrepareProof>,
        member: &Installation,
    ) -> Result<Self, Error> {
        let (group, parent) = context;
        let signature = member
            .sign_group_roster_vote(
                group,
                parent,
                Self::claim(prepared.as_ref()),
                round,
                Self::PHASE,
            )
            .map_err(|error| roster_signing_error(error, Error::AlreadyVoted))?;
        Ok(Self::assemble(
            context,
            round,
            prepared,
            member.selected(),
            signature,
        ))
    }

    /// Byzantine fixtures only: report without the self-consistency locks.
    #[cfg(any(test, feature = "test-support"))]
    pub fn new_unchecked(
        context: (u64, [u8; 32]),
        round: u32,
        prepared: Option<RosterPrepareProof>,
        member: &Installation,
    ) -> Self {
        let (group, parent) = context;
        let signature = member.sign_group_roster_vote_unchecked(
            group,
            parent,
            Self::claim(prepared.as_ref()),
            round,
            Self::PHASE,
        );
        Self::assemble(context, round, prepared, member.selected(), signature)
    }

    fn assemble(
        context: (u64, [u8; 32]),
        round: u32,
        prepared: Option<RosterPrepareProof>,
        signer: Key,
        signature: [u8; 64],
    ) -> Self {
        let (group, parent) = context;
        Self {
            group,
            parent,
            round,
            prepared,
            vote: RosterVote { signer, signature },
        }
    }

    fn claim(prepared: Option<&RosterPrepareProof>) -> [u8; 32] {
        let mut hash = Sha256::new();
        if let Some(proof) = prepared {
            hash.update([1]);
            hash.update(proof.round.to_be_bytes());
            hash.update(proof.child);
        } else {
            hash.update([0]);
        }
        hash.finalize().into()
    }

    fn prepared_claim(&self) -> Option<(u32, [u8; 32])> {
        self.prepared
            .as_ref()
            .map(|proof| (proof.round, proof.child))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut bytes = Vec::with_capacity(Self::BASE_LEN);
        bytes.extend_from_slice(&self.group.to_be_bytes());
        bytes.extend_from_slice(&self.parent);
        bytes.extend_from_slice(&self.round.to_be_bytes());
        bytes.extend_from_slice(&self.vote.to_bytes());
        if let Some(proof) = &self.prepared {
            if !(1..=MAX_CERTIFICATE_SIGNERS).contains(&proof.votes.len()) {
                return Err(Error::Ineligible);
            }
            bytes.extend_from_slice(&proof.round.to_be_bytes());
            bytes.extend_from_slice(&proof.child);
            for vote in &proof.votes {
                bytes.extend_from_slice(&vote.to_bytes());
            }
        }
        Ok(bytes)
    }

    /// Decode either a bare report or one carrying a bounded prepare proof.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let prepared = match bytes.len() {
            Self::BASE_LEN => None,
            len if len >= Self::BASE_LEN + Self::PROOF_HEADER_LEN + RosterVote::WIRE_LEN
                && (len - Self::BASE_LEN - Self::PROOF_HEADER_LEN) % RosterVote::WIRE_LEN == 0 =>
            {
                let count = (len - Self::BASE_LEN - Self::PROOF_HEADER_LEN) / RosterVote::WIRE_LEN;
                if !(1..=MAX_CERTIFICATE_SIGNERS).contains(&count) {
                    return Err(Error::Ineligible);
                }
                let proof = &bytes[Self::BASE_LEN..];
                Some(RosterPrepareProof {
                    round: u32::from_be_bytes(proof[..4].try_into().unwrap()),
                    child: proof[4..36].try_into().unwrap(),
                    votes: proof[Self::PROOF_HEADER_LEN..]
                        .chunks_exact(RosterVote::WIRE_LEN)
                        .map(|chunk| RosterVote::from_wire(chunk.try_into().unwrap()))
                        .collect(),
                })
            }
            _ => return Err(Error::Ineligible),
        };
        Ok(Self {
            group: u64::from_be_bytes(bytes[..8].try_into().unwrap()),
            parent: bytes[8..40].try_into().unwrap(),
            round: u32::from_be_bytes(bytes[40..44].try_into().unwrap()),
            vote: RosterVote::from_bytes(&bytes[44..Self::BASE_LEN])?,
            prepared,
        })
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RoundReportDelivery {
    Recorded,
    Duplicate,
    Conflicting,
}

/// Collects authenticated reports for one parent and target round.
pub struct RoundChangeCollector {
    context: (u64, [u8; 32]),
    round: u32,
    reports: BTreeMap<Key, RosterRoundChange>,
    conflicting: BTreeSet<Key>,
}

impl RoundChangeCollector {
    pub fn new(group: &VouchedGroup, round: u32) -> Result<Self, Error> {
        group.roster_quorum()?;
        if round == 0 {
            return Err(Error::Ineligible);
        }
        Ok(Self {
            context: group.rotation_context(),
            round,
            reports: BTreeMap::new(),
            conflicting: BTreeSet::new(),
        })
    }

    pub fn record(
        &mut self,
        group: &VouchedGroup,
        report: RosterRoundChange,
    ) -> Result<RoundReportDelivery, Error> {
        self.check_parent(group)?;
        group.verify_round_change(self.round, &report)?;
        let signer = report.vote.signer;
        if self.conflicting.contains(&signer) {
            return Ok(RoundReportDelivery::Conflicting);
        }
        if let Some(previous) = self.reports.get(&signer) {
            if previous.prepared_claim() == report.prepared_claim() {
                return Ok(RoundReportDelivery::Duplicate);
            }
            self.reports.remove(&signer);
            self.conflicting.insert(signer);
            return Ok(RoundReportDelivery::Conflicting);
        }
        self.reports.insert(signer, report);
        Ok(RoundReportDelivery::Recorded)
    }

    /// Two eligible reports are enough to request a later round in the
    /// one-equivocator profile. Entering the round still requires a quorum.
    pub fn catch_up_round(
        &self,
        group: &VouchedGroup,
        current_round: u32,
    ) -> Result<Option<u32>, Error> {
        self.check_parent(group)?;
        let eligible = self
            .reports
            .keys()
            .filter(|&&key| group.membership(key).is_some() && !group.is_barred(&key))
            .count();
        let max_equivocators = (group.group.electorate_size().saturating_sub(1)) / 3;
        let catch_up_threshold = max_equivocators + 1;
        Ok((self.round > current_round && eligible >= catch_up_threshold).then_some(self.round))
    }

    /// Evaluate the reports collected so far. The caller retains any vote or
    /// lock it has already issued, even if later arrivals alter this quorum.
    pub fn prepared_child(&self, group: &VouchedGroup) -> Result<Option<[u8; 32]>, Error> {
        self.check_parent(group)?;
        group.check_report_quorum(&self.reports.keys().copied().collect())?;
        let eligible: Vec<_> = self
            .reports
            .iter()
            .filter(|&(&key, _)| group.membership(key).is_some() && !group.is_barred(&key))
            .map(|(_, report)| report)
            .collect();
        VouchedGroup::select_round_change_child(eligible)
    }

    fn check_parent(&self, group: &VouchedGroup) -> Result<(), Error> {
        if self.context != group.rotation_context() {
            return Err(Error::StaleProposal);
        }
        Ok(())
    }
}

impl VouchedGroup {
    /// Verify recent quorum observations against an already authenticated
    /// roster. This does not authenticate the supplied roster's history.
    pub fn verify_roster_freshness(
        &self,
        challenge: &RosterFreshnessChallenge,
        responses: &[RosterVote],
        now: Instant,
    ) -> Result<(), RosterFreshnessError> {
        let elapsed = now
            .checked_duration_since(challenge.started)
            .ok_or(RosterFreshnessError::ExpiredChallenge)?;
        if elapsed >= RosterFreshnessChallenge::WINDOW {
            return Err(RosterFreshnessError::ExpiredChallenge);
        }
        if challenge.query.group != self.group.id || responses.len() > MAX_CERTIFICATE_SIGNERS {
            return Err(RosterFreshnessError::Unconfirmed);
        }
        self.verify_freshness_votes(responses, &self.freshness_message(challenge.query.nonce))
            .map_err(|_| RosterFreshnessError::Unconfirmed)
    }

    /// Number of distinct current voters required to confirm this roster.
    /// Groups with fewer than four eligible voters require every voter.
    pub fn required_roster_freshness_votes(&self) -> Result<usize, Error> {
        self.roster_quorum()
    }

    fn verify_freshness_votes(&self, votes: &[RosterVote], message: &[u8]) -> Result<(), Error> {
        if votes.len() < self.required_roster_freshness_votes()?
            || votes.len() > self.group.electorate_size()
        {
            return Err(Error::Ineligible);
        }
        let mut signers = BTreeSet::new();
        for vote in votes {
            if !signers.insert(vote.signer)
                || !self.group.is_eligible_voter(
                    self.identities
                        .get(&vote.signer)
                        .copied()
                        .ok_or(Error::Ineligible)?,
                )
            {
                return Err(Error::Ineligible);
            }
            self.verify_roster_vote(vote, message)?;
        }
        Ok(())
    }

    /// Confirm whether the selected identity belongs to a recently observed,
    /// authenticated roster. Call after validating any admission transition.
    pub fn confirmed_membership(
        &self,
        candidate: &Installation,
        challenge: &RosterFreshnessChallenge,
        responses: &[RosterVote],
        now: Instant,
    ) -> Result<Option<Membership>, RosterFreshnessError> {
        self.verify_roster_freshness(challenge, responses, now)?;
        Ok(self.membership(candidate.selected()))
    }

    /// Reconcile with an authenticated roster and a recent quorum observation.
    /// A failure leaves the backup gate and roster unchanged.
    pub fn reconcile_backup_with_freshness(
        &mut self,
        local: &mut MemberLocalState,
        authenticated: &Self,
        challenge: RosterFreshnessChallenge,
        responses: &[RosterVote],
        now: Instant,
    ) -> Result<CatchUp, RosterFreshnessError> {
        authenticated.verify_roster_freshness(&challenge, responses, now)?;
        Ok(self.reconcile_backup_unchecked(local, authenticated))
    }

    fn freshness_message(&self, nonce: [u8; 32]) -> Vec<u8> {
        group_roster_freshness_message(self.group.id, self.history.id, self.revision(), nonce)
    }

    /// Respond from the member's active, authenticated group roster.
    pub fn attest_roster_freshness(
        &self,
        local: &MemberLocalState,
        query: RosterFreshnessQuery,
        member: &Installation,
    ) -> Result<RosterVote, Error> {
        if query.group != self.group.id {
            return Err(Error::Ineligible);
        }
        self.required_roster_freshness_votes()?;
        let signer = self.check_local_roster_signer(local, member)?;
        let signature = member
            .sign_group_roster_freshness(
                self.group.id,
                self.history.id,
                self.revision(),
                query.nonce,
            )
            .map_err(|error| roster_signing_error(error, Error::Ineligible))?;
        Ok(RosterVote { signer, signature })
    }

    fn check_local_roster_signer(
        &self,
        local: &MemberLocalState,
        voter: &Installation,
    ) -> Result<Key, Error> {
        let key = self.check_local_voter(local, voter)?;
        if local.backup_rosters.is_some() {
            return Err(Error::RosterSigningStateUnconfirmed);
        }
        Ok(key)
    }

    /// Sign a prepare or commit for a child already validated by the caller
    /// against this exact parent.
    #[cfg(any(test, feature = "test-support"))]
    pub fn sign_roster_vote(
        &self,
        local: &MemberLocalState,
        parent: [u8; 32],
        child: [u8; 32],
        round: u32,
        phase: RosterVotePhase,
        voter: &Installation,
    ) -> Result<RosterVote, Error> {
        if self.history.id != parent {
            return Err(Error::StaleProposal);
        }
        self.roster_quorum()?;
        let signer = self.check_local_roster_signer(local, voter)?;
        let signature = voter
            .sign_group_roster_vote(self.group.id, parent, child, round, phase as u8)
            .map_err(|error| roster_signing_error(error, Error::AlreadyVoted))?;
        Ok(RosterVote { signer, signature })
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn sign_roster_round_change(
        &self,
        local: &MemberLocalState,
        round: u32,
        prepared: Option<RosterPrepareProof>,
        voter: &Installation,
    ) -> Result<RosterRoundChange, Error> {
        self.roster_quorum()?;
        self.check_local_roster_signer(local, voter)?;
        if let Some(proof) = &prepared {
            self.verify_round_change_proof(round, proof)?;
        }
        RosterRoundChange::new(self.rotation_context(), round, prepared, voter)
    }

    /// Persist the lock and outbound vote together before returning the vote.
    /// The callback receives the checkpoint and the wire vote for this request.
    pub fn sign_roster_vote_durable(
        &self,
        local: &MemberLocalState,
        request: RosterVoteRequest,
        voter: &mut Installation,
        persist: impl FnOnce(&[u8], &[u8]) -> std::io::Result<()>,
    ) -> Result<RosterVote, Error> {
        if self.history.id != request.parent {
            return Err(Error::StaleProposal);
        }
        self.roster_quorum()?;
        let signer = self.check_local_roster_signer(local, voter)?;
        let signature = voter
            .sign_group_roster_vote_durable(
                self.group.id,
                request.parent,
                request.child,
                request.round,
                request.phase as u8,
                |checkpoint, signature| {
                    let vote = RosterVote {
                        signer,
                        signature: *signature,
                    };
                    persist(checkpoint, &vote.to_bytes())
                },
            )
            .map_err(|error| roster_signing_error(error, Error::AlreadyVoted))?;
        Ok(RosterVote { signer, signature })
    }

    /// Publish a round-change report only after its bytes and lock are durable.
    pub fn sign_roster_round_change_durable(
        &self,
        local: &MemberLocalState,
        round: u32,
        prepared: Option<RosterPrepareProof>,
        voter: &mut Installation,
        persist: impl FnOnce(&[u8], &[u8]) -> std::io::Result<()>,
    ) -> Result<RosterRoundChange, Error> {
        self.roster_quorum()?;
        let signer = self.check_local_roster_signer(local, voter)?;
        if let Some(proof) = &prepared {
            self.verify_round_change_proof(round, proof)?;
        }
        let context = self.rotation_context();
        let claim = RosterRoundChange::claim(prepared.as_ref());
        let signature = voter
            .sign_group_roster_vote_durable(
                context.0,
                context.1,
                claim,
                round,
                RosterRoundChange::PHASE,
                |checkpoint, signature| {
                    let report = RosterRoundChange::assemble(
                        context,
                        round,
                        prepared.clone(),
                        signer,
                        *signature,
                    );
                    let bytes = report
                        .to_bytes()
                        .map_err(|_| std::io::Error::other("invalid round change"))?;
                    persist(checkpoint, &bytes)
                },
            )
            .map_err(|error| roster_signing_error(error, Error::AlreadyVoted))?;
        Ok(RosterRoundChange::assemble(
            context, round, prepared, signer, signature,
        ))
    }

    pub(super) fn verify_roster_certificate(
        &self,
        child: [u8; 32],
        certificate: &RosterCertificate,
    ) -> Result<(), Error> {
        if (certificate.group, certificate.parent) != self.rotation_context() {
            return Err(Error::StaleProposal);
        }
        if certificate.child != child {
            return Err(Error::Ineligible);
        }
        for (phase, votes) in [(1, &certificate.prepares), (2, &certificate.commits)] {
            let message = group_roster_vote_message(
                certificate.group,
                certificate.parent,
                child,
                certificate.round,
                phase,
            );
            self.verify_roster_votes(votes, &message)?;
        }
        Ok(())
    }

    /// Verify either certificate version and return the new proofs it carries (none for
    /// version 0, which carries exactly this chain's inherited set). Changes no state.
    pub(super) fn verify_certificate(
        &self,
        child: [u8; 32],
        certificate: CertificateRef<'_>,
    ) -> Result<Vec<CarriedProof>, Error> {
        if let Some(v1) = certificate.kind_v1() {
            return self.verify_certificate_v1(child, v1);
        }
        let v0 = certificate
            .kind_v0()
            .expect("a certificate is version 0 or 1");
        self.verify_roster_certificate(child, v0)?;
        Ok(Vec::new())
    }

    /// The digest a version-1 certificate for this head must carry: the proof subjects on this
    /// authenticated chain, bound to the group and parent.
    pub fn chain_digest(&self) -> [u8; 32] {
        let (group, parent) = self.rotation_context();
        chain_digest_with_reports(
            group,
            parent,
            self.inherited_proof_keys(),
            self.reported_keys(),
            self.recognitions(),
        )
    }

    /// Verify a version-1 certificate and return the new proofs it carries. Changes no state.
    ///
    /// Order: group and parent, child, chain digest (a mismatch means the receiver should catch
    /// up, not that the certificate is invalid), each new proof against this parent's roster,
    /// then the electorate quorum and signatures per phase with the proofs excluded. A new proof
    /// for a key the chain already carries is refused, so one certificate has one encoding.
    pub(super) fn verify_certificate_v1(
        &self,
        child: [u8; 32],
        v1: &CertificateV1,
    ) -> Result<Vec<CarriedProof>, Error> {
        let certificate = &v1.certificate;
        if (certificate.group, certificate.parent) != self.rotation_context() {
            return Err(Error::StaleProposal);
        }
        if certificate.child != child {
            return Err(Error::Ineligible);
        }
        let inherited = self.inherited_proof_keys();
        if v1.chain_digest != self.chain_digest() {
            return Err(Error::ChainMismatch);
        }
        let roster: BTreeSet<Key> = self
            .identities
            .keys()
            .copied()
            .filter(|key| self.membership(*key).is_some())
            .collect();
        let context = ProofContext {
            group: certificate.group,
            parent: certificate.parent,
            roster: &roster,
        };
        let mut carried = inherited.clone();
        for proof in &v1.proofs {
            let subject = verify_equivocation(proof, &context).map_err(|_| Error::Ineligible)?;
            if !carried.insert(subject) {
                // Already inherited, or proven twice in this certificate.
                return Err(Error::Ineligible);
            }
        }
        for (phase, votes) in [(1, &certificate.prepares), (2, &certificate.commits)] {
            let mut signers = BTreeSet::new();
            for vote in votes {
                if !signers.insert(vote.signer) {
                    return Err(Error::Ineligible);
                }
            }
            check_electorate_quorum(&ElectorateQuorumCheck {
                roster: &roster,
                inherited,
                carried: &carried,
                reported: self.reported_keys(),
                signers: &signers,
            })
            .map_err(|_| Error::Ineligible)?;
            let message = group_roster_vote_message(
                certificate.group,
                certificate.parent,
                child,
                certificate.round,
                phase,
            );
            for vote in votes {
                self.verify_roster_vote(vote, &message)?;
            }
        }
        Ok(v1
            .proofs
            .iter()
            .cloned()
            .map(|proof| CarriedProof::Equivocation(Box::new(proof)))
            .collect())
    }

    /// Verify an eligible round-change quorum and return its highest prepared child.
    /// The caller selects a fresh proposal when the quorum contains no prepare proof.
    pub fn round_change_child(
        &self,
        round: u32,
        reports: &[RosterRoundChange],
    ) -> Result<Option<[u8; 32]>, Error> {
        if round == 0 {
            return Err(Error::Ineligible);
        }
        let reporters: Vec<Key> = reports.iter().map(|report| report.vote.signer).collect();
        self.check_vote_quorum(&reporters)?;
        for report in reports {
            self.verify_round_change(round, report)?;
        }
        Self::select_round_change_child(reports)
    }

    fn verify_round_change(&self, round: u32, report: &RosterRoundChange) -> Result<(), Error> {
        let (group, parent) = self.rotation_context();
        if (report.group, report.parent, report.round) != (group, parent, round) {
            return Err(Error::Ineligible);
        }
        let claim = RosterRoundChange::claim(report.prepared.as_ref());
        let message =
            group_roster_vote_message(group, parent, claim, round, RosterRoundChange::PHASE);
        self.verify_roster_vote(&report.vote, &message)?;
        if let Some(proof) = &report.prepared {
            self.verify_round_change_proof(round, proof)?;
        }
        Ok(())
    }

    fn verify_round_change_proof(
        &self,
        round: u32,
        proof: &RosterPrepareProof,
    ) -> Result<(), Error> {
        if proof.round >= round {
            return Err(Error::Ineligible);
        }
        let (group, parent) = self.rotation_context();
        let message = group_roster_vote_message(group, parent, proof.child, proof.round, 1);
        self.verify_roster_votes(&proof.votes, &message)
    }

    fn select_round_change_child<'a>(
        reports: impl IntoIterator<Item = &'a RosterRoundChange>,
    ) -> Result<Option<[u8; 32]>, Error> {
        let mut highest = None;
        let mut conflict = false;
        for (round, child) in reports
            .into_iter()
            .filter_map(RosterRoundChange::prepared_claim)
        {
            match highest {
                Some((previous, _)) if previous > round => {}
                Some((previous, selected)) if previous == round => {
                    conflict |= selected != child;
                }
                _ => {
                    highest = Some((round, child));
                    conflict = false;
                }
            }
        }
        if conflict {
            return Err(Error::Ineligible);
        }
        Ok(highest.map(|(_, child)| child))
    }

    /// Signers each phase of a roster certificate needs on the current roster.
    pub fn roster_vote_quorum(&self) -> Result<usize, Error> {
        self.roster_quorum()
    }

    /// Check one prepare or commit vote for `child` on the current head: the signer is an
    /// eligible member and the signature covers exactly this parent, child, round and phase.
    pub fn check_roster_vote(
        &self,
        vote: &RosterVote,
        child: [u8; 32],
        round: u32,
        phase: RosterVotePhase,
    ) -> Result<(), Error> {
        let (group, parent) = self.rotation_context();
        let message = group_roster_vote_message(group, parent, child, round, phase as u8);
        self.verify_roster_vote(vote, &message)
    }

    pub(super) fn roster_quorum(&self) -> Result<usize, Error> {
        let eligible = self.group.electorate_size();
        match eligible {
            0 => Err(Error::Ineligible),
            1..=3 => Ok(eligible),
            _ => {
                let max_equivocators = (eligible - 1) / 3;
                Ok((eligible + max_equivocators) / 2 + 1)
            }
        }
    }

    /// Counting layer of `verify_roster_votes`: distinct signers, all eligible, at least the
    /// quorum for the electorate. Today a certificate carries no proofs, so the proof subjects
    /// it carries are exactly the parent's suspect keys (inherited and carried coincide); this
    /// keeps the behaviour of the previous arithmetic. See
    /// Roster certificate validation and state transitions.
    fn check_vote_quorum(&self, signers: &[Key]) -> Result<(), Error> {
        let mut distinct = BTreeSet::new();
        for signer in signers {
            if !distinct.insert(*signer) {
                return Err(Error::Ineligible);
            }
        }
        self.electorate_quorum(&distinct)
            .map(|_| ())
            .map_err(|_| Error::Ineligible)
    }

    /// Quorum on round-change reports gathered by a collector. Only reporters that are current,
    /// non-suspect members count, as before; a shortfall is `ApprovalRequired`, and an empty
    /// electorate is `Ineligible`.
    fn check_report_quorum(&self, reporters: &BTreeSet<Key>) -> Result<(), Error> {
        let eligible: BTreeSet<Key> = reporters
            .iter()
            .copied()
            .filter(|key| self.membership(*key).is_some() && !self.is_barred(key))
            .collect();
        match self.electorate_quorum(&eligible) {
            Ok(_) => Ok(()),
            Err(QuorumRejection::BelowQuorum { .. }) => Err(Error::ApprovalRequired),
            Err(_) => Err(Error::Ineligible),
        }
    }

    fn electorate_quorum(
        &self,
        signers: &BTreeSet<Key>,
    ) -> Result<QuorumSatisfied, QuorumRejection> {
        let roster: BTreeSet<Key> = self
            .identities
            .keys()
            .copied()
            .filter(|key| self.membership(*key).is_some())
            .collect();
        check_electorate_quorum(&ElectorateQuorumCheck {
            roster: &roster,
            inherited: &self.suspect,
            carried: &self.suspect,
            reported: self.reported_keys(),
            signers,
        })
    }

    fn verify_roster_votes(&self, votes: &[RosterVote], message: &[u8]) -> Result<(), Error> {
        // At least a quorum; extra valid signatures from distinct eligible members are fine.
        let signers: Vec<Key> = votes.iter().map(|vote| vote.signer).collect();
        self.check_vote_quorum(&signers)?;
        for vote in votes {
            self.verify_roster_vote(vote, message)?;
        }
        Ok(())
    }

    pub(super) fn verify_roster_vote(
        &self,
        vote: &RosterVote,
        message: &[u8],
    ) -> Result<(), Error> {
        if self.membership(vote.signer).is_none() || self.is_barred(&vote.signer) {
            return Err(Error::Ineligible);
        }
        parse_verifying_key(&vote.signer)?
            .verify_strict(message, &Signature::from_bytes(&vote.signature))
            .map_err(|_| Error::Ineligible)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> Key {
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes()
    }

    /// The counting arithmetic exactly as it was before slice W1: a length window from
    /// `roster_quorum()` and `electorate_size()`, distinct signers, each a current member that
    /// is not suspect. Kept here as the oracle for the differential test below.
    fn previous_counting(group: &VouchedGroup, signers: &[Key]) -> bool {
        let Ok(quorum) = group.roster_quorum() else {
            return false;
        };
        if signers.len() < quorum || signers.len() > group.group.electorate_size() {
            return false;
        }
        let mut distinct = BTreeSet::new();
        signers.iter().all(|signer| {
            distinct.insert(*signer)
                && group.membership(*signer).is_some()
                && !group.suspect.contains(signer)
        })
    }

    /// The collector's report-counting arithmetic as it was before slice W2.
    fn previous_report_counting(
        group: &VouchedGroup,
        reporters: &BTreeSet<Key>,
    ) -> Result<(), Error> {
        let eligible = reporters
            .iter()
            .filter(|key| group.membership(**key).is_some() && !group.suspect.contains(*key))
            .count();
        if eligible < group.roster_quorum()? {
            return Err(Error::ApprovalRequired);
        }
        Ok(())
    }

    /// Differential test for slices W1 and W2: the helper-based counting accepts exactly the signer
    /// sets the previous arithmetic accepted, over every reachable small state (any suspect
    /// subset, optionally one key replacement, optionally one departure) and every signer
    /// subset, including retired and foreign keys and repeated signers.
    #[test]
    fn helper_counting_matches_previous_arithmetic() {
        let mut compared = 0u64;
        let mut accepted = 0u64;
        for n in 2usize..=6 {
            let base: Vec<Key> = (0..n as u8).map(|i| key(10 + i)).collect();
            let fresh = key(100);
            let foreign = key(101);
            for suspect_mask in 0u32..1 << n {
                for replaced in 0..=n {
                    for departed in 0..=n {
                        let mut group = VouchedGroup::new(
                            7,
                            base.iter().copied(),
                            crate::groups::Policy::InviterOnly,
                        );
                        for (i, k) in base.iter().enumerate() {
                            if suspect_mask >> i & 1 == 1 {
                                group.mark_suspect(*k).unwrap();
                            }
                        }
                        let mut current = base.clone();
                        if replaced < n {
                            let child = group.derived_child(b"test-replace", &[&base[replaced]]);
                            group
                                .replace_key(group.revision(), base[replaced], fresh, child)
                                .unwrap();
                            current[replaced] = fresh;
                        }
                        if departed < n {
                            let who = current[departed];
                            if let Some(tenure) = group.membership(who) {
                                group.apply_departure(who, tenure).unwrap();
                            }
                        }
                        let mut universe = base.clone();
                        universe.push(fresh);
                        universe.push(foreign);
                        for mask in 0u32..1 << universe.len() {
                            let signers: Vec<Key> = (0..universe.len())
                                .filter(|i| mask >> i & 1 == 1)
                                .map(|i| universe[i])
                                .collect();
                            for repeated in [false, true] {
                                let mut signers = signers.clone();
                                if repeated {
                                    match signers.first().copied() {
                                        Some(first) => signers.push(first),
                                        None => continue,
                                    }
                                }
                                let old = previous_counting(&group, &signers);
                                let new = group.check_vote_quorum(&signers).is_ok();
                                assert_eq!(
                                    new, old,
                                    "n {n} suspects {suspect_mask:b} replaced {replaced} \
                                     departed {departed} signers {signers:?}"
                                );
                                let reporters: BTreeSet<Key> = signers.iter().copied().collect();
                                assert_eq!(
                                    group.check_report_quorum(&reporters),
                                    previous_report_counting(&group, &reporters),
                                    "reports: n {n} suspects {suspect_mask:b} replaced {replaced} \
                                     departed {departed} reporters {reporters:?}"
                                );
                                compared += 1;
                                accepted += u64::from(new);
                            }
                        }
                    }
                }
            }
        }
        assert!(
            compared > 100_000 && accepted > 1_000,
            "{compared} {accepted}"
        );
    }
}
