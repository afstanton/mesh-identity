//! Departures, ejections, key rotation, and membership replacement.

use super::proof::CarriedProof;
use super::wire::CertificateRef;
use super::{
    Error, Installation, Key, RosterHistory, RosterVote, VouchedGroup, parse_verifying_key,
    random_id,
};
use crate::groups::{LocalInstallation, Membership, Policy};
use crate::session::installation::{
    group_departure_message, group_ejection_message, group_rotation_message,
};
use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::sync::Arc;

/// A signed departure for one membership tenure.
pub struct SignedDeparture {
    context: (u64, [u8; 32]),
    member: Key,
    signature: [u8; 64],
}

impl SignedDeparture {
    pub fn new(context: (u64, [u8; 32]), member: &Installation) -> Result<Self, Error> {
        Ok(Self {
            context,
            member: member.selected(),
            signature: member
                .sign_group_departure(context.0, context.1)
                .map_err(|e| super::agreement::roster_signing_error(e, Error::Ineligible))?,
        })
    }

    pub fn to_bytes(&self) -> [u8; 136] {
        let mut bytes = [0; 136];
        bytes[..8].copy_from_slice(&self.context.0.to_be_bytes());
        bytes[8..40].copy_from_slice(&self.context.1);
        bytes[40..72].copy_from_slice(&self.member);
        bytes[72..].copy_from_slice(&self.signature);
        bytes
    }

    /// Decode the frame. The receiving roster verifies the signature and tenure.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 136] = bytes.try_into().map_err(|_| Error::Ineligible)?;
        Ok(Self {
            context: (
                u64::from_be_bytes(bytes[..8].try_into().unwrap()),
                bytes[8..40].try_into().unwrap(),
            ),
            member: bytes[40..72].try_into().unwrap(),
            signature: bytes[72..].try_into().unwrap(),
        })
    }

    pub fn context(&self) -> (u64, [u8; 32]) {
        self.context
    }

    pub fn member(&self) -> Key {
        self.member
    }

    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }
}

/// Fixed-width encoding of both identity approvals for one roster transition.
pub struct SignedRotation {
    context: (u64, [u8; 32]),
    old: Key,
    new: Key,
    signatures: [[u8; 64]; 2],
}

impl SignedRotation {
    pub fn new(context: (u64, [u8; 32]), old: Key, new: Key, signatures: [[u8; 64]; 2]) -> Self {
        Self {
            context,
            old,
            new,
            signatures,
        }
    }

    pub fn to_bytes(&self) -> [u8; 232] {
        let mut bytes = [0; 232];
        bytes[..8].copy_from_slice(&self.context.0.to_be_bytes());
        bytes[8..40].copy_from_slice(&self.context.1);
        bytes[40..72].copy_from_slice(&self.old);
        bytes[72..104].copy_from_slice(&self.new);
        bytes[104..168].copy_from_slice(&self.signatures[0]);
        bytes[168..].copy_from_slice(&self.signatures[1]);
        bytes
    }

    /// Decode the frame. Authorization is verified against the receiving roster.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 232] = bytes.try_into().map_err(|_| Error::Ineligible)?;
        Ok(Self {
            context: (
                u64::from_be_bytes(bytes[..8].try_into().unwrap()),
                bytes[8..40].try_into().unwrap(),
            ),
            old: bytes[40..72].try_into().unwrap(),
            new: bytes[72..104].try_into().unwrap(),
            signatures: [
                bytes[104..168].try_into().unwrap(),
                bytes[168..].try_into().unwrap(),
            ],
        })
    }
}

/// Approval for a signed ejection proposal already known to the receiver.
pub struct SignedEjectionVote(RosterVote);

impl SignedEjectionVote {
    pub fn new(proposal: &RemovalProposal, voter: &Installation) -> Result<Self, Error> {
        let binding = proposal.signed_binding.ok_or(Error::Ineligible)?;
        Ok(Self(RosterVote {
            signer: voter.selected(),
            signature: voter
                .sign_group_ejection(binding)
                .map_err(|e| super::agreement::roster_signing_error(e, Error::Ineligible))?,
        }))
    }

    pub fn to_bytes(&self) -> [u8; 96] {
        self.0.to_bytes()
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        RosterVote::from_bytes(bytes).map(Self)
    }
}

/// Proposed removal under an exact roster state.
pub struct RemovalProposal {
    signed_binding: Option<[u8; 32]>,
    required: usize,
    parent: Arc<RosterHistory>,
    target: Key,
    tenure: Membership,
    approvals: BTreeSet<Key>,
}

impl VouchedGroup {
    /// Return the group and the roster state in which this tenure began.
    pub fn departure_context(&self, member: Key) -> Option<(u64, [u8; 32])> {
        let tenure = self.membership(member)?;
        let mut joined = &self.history;
        for _ in tenure.joined_at..self.revision() {
            joined = joined.parent.as_ref()?;
        }
        Some((self.group.id, joined.id))
    }

    pub(crate) fn apply_departure_message(
        &mut self,
        departure: &SignedDeparture,
    ) -> Result<bool, Error> {
        self.apply_signed_departure(departure.member, departure.context, departure.signature)
    }

    /// Apply a signed departure for the current tenure in the agreed order.
    pub(crate) fn apply_signed_departure(
        &mut self,
        member: Key,
        context: (u64, [u8; 32]),
        signature: [u8; 64],
    ) -> Result<bool, Error> {
        let message = group_departure_message(context.0, context.1, member);
        let key = parse_verifying_key(&member)?;
        key.verify_strict(&message, &Signature::from_bytes(&signature))
            .map_err(|_| Error::Ineligible)?;
        if self.departure_context(member) != Some(context) {
            return Ok(false);
        }
        let tenure = self.membership(member).ok_or(Error::Ineligible)?;
        let child = self.departure_child(member, context, signature)?;
        self.remove_tenure_at_child(member, tenure, child)
    }

    /// Derive the canonical consensus child for a voluntary departure.
    pub fn departure_child(
        &self,
        member: Key,
        context: (u64, [u8; 32]),
        signature: [u8; 64],
    ) -> Result<[u8; 32], Error> {
        let message = group_departure_message(context.0, context.1, member);
        let key = parse_verifying_key(&member)?;
        key.verify_strict(&message, &Signature::from_bytes(&signature))
            .map_err(|_| Error::Ineligible)?;
        if self.departure_context(member) != Some(context) {
            return Err(Error::Ineligible);
        }
        Ok(Sha256::new()
            .chain_update(b"mesh/group-admission/departure-child/v1\0")
            .chain_update(message)
            .chain_update(signature)
            .finalize()
            .into())
    }

    /// Apply a voluntary departure verified by a consensus certificate.
    pub fn apply_certified_departure<'c>(
        &mut self,
        member: Key,
        context: (u64, [u8; 32]),
        signature: [u8; 64],
        certificate: impl Into<CertificateRef<'c>>,
    ) -> Result<(), Error> {
        let child = self.departure_child(member, context, signature)?;
        let carried = self.verify_certificate(child, certificate.into())?;
        let tenure = self.membership(member).ok_or(Error::Ineligible)?;
        self.remove_tenure_at_child_carrying(member, tenure, child, carried)?;
        Ok(())
    }

    pub fn signed_departure_child(&self, departure: &SignedDeparture) -> Result<[u8; 32], Error> {
        self.departure_child(departure.member, departure.context, departure.signature)
    }

    pub fn apply_certified_signed_departure<'c>(
        &mut self,
        departure: &SignedDeparture,
        certificate: impl Into<CertificateRef<'c>>,
    ) -> Result<(), Error> {
        self.apply_certified_departure(
            departure.member,
            departure.context,
            departure.signature,
            certificate,
        )
    }

    /// Apply a departure authenticated as the current key of this tenure.
    pub(crate) fn apply_departure(
        &mut self,
        sender: Key,
        tenure: Membership,
    ) -> Result<bool, Error> {
        if self.membership(sender) != Some(tenure) {
            return Ok(false);
        }
        self.remove_tenure(sender, tenure)
    }

    fn remove_tenure(&mut self, key: Key, tenure: Membership) -> Result<bool, Error> {
        let child = self.derived_child(b"remove", &[&key, &tenure.joined_at.to_be_bytes()]);
        self.remove_tenure_at_child(key, tenure, child)
    }

    fn remove_tenure_at_child(
        &mut self,
        key: Key,
        tenure: Membership,
        child: [u8; 32],
    ) -> Result<bool, Error> {
        self.remove_tenure_at_child_carrying(key, tenure, child, Vec::new())
    }

    /// As `remove_tenure_at_child`, recording the proofs the certified transition carried.
    fn remove_tenure_at_child_carrying(
        &mut self,
        key: Key,
        tenure: Membership,
        child: [u8; 32],
        carried: Vec<CarriedProof>,
    ) -> Result<bool, Error> {
        if self.group.apply_departure(tenure)? {
            self.record_roster_child_carrying(child, carried);
            self.admission_evidence.remove(&key);
            self.recovery_witnesses.remove(&tenure.identity());
            self.recovery_commitments.remove(&tenure.identity());
            self.recovery_salts.remove(&tenure.identity());
            self.degraded_recovery.remove(&tenure.identity());
            // An owner whose witness left keeps no working arrangement, but is told so rather
            // than silently losing recovery: `recovery_status` reports it as degraded.
            let orphaned: Vec<_> = self
                .recovery_witnesses
                .iter()
                .filter(|(_, witnesses)| witnesses.contains(&key))
                .map(|(owner, _)| *owner)
                .collect();
            for owner in orphaned {
                self.recovery_witnesses.remove(&owner);
                self.recovery_salts.remove(&owner);
                self.degraded_recovery.insert(owner);
            }
            self.identities.remove(&key);
            // A proof carried by this very transition may have excluded the departing identity
            // after it left the roster; its number can be reused, so clear it.
            self.group.include(tenure.identity());
            // A key removed while suspect is never admitted again; a returning member needs a
            // fresh key.
            let reported = self.history.reported.contains(&key);
            if self.suspect.remove(&key) || reported {
                self.retired.insert(key);
            }
            return Ok(true);
        }
        Ok(false)
    }

    /// Any current, eligible peer can propose removal. Removal
    /// requires a strict majority of the current roster excluding the target.
    pub(crate) fn propose_removal(
        &self,
        proposer: Key,
        target: Key,
    ) -> Result<RemovalProposal, Error> {
        let others = self.eligible_electorate_excluding(target);
        self.removal_proposal(proposer, target, others / 2 + 1)
    }

    /// Propose ejection under the complementary admission threshold.
    /// The admission rule applies to feasible numeric policies.
    pub(crate) fn propose_ejection(
        &self,
        proposer: Key,
        target: Key,
    ) -> Result<RemovalProposal, Error> {
        let required = self.required_ejection_votes(target)?;
        self.removal_proposal(proposer, target, required)
    }

    pub fn propose_signed_ejection(
        &self,
        proposer: &Installation,
        target: Key,
    ) -> Result<RemovalProposal, Error> {
        let required = self.required_ejection_votes(target)?;
        let mut proposal = self.new_removal(target, required)?;
        let binding = Sha256::new()
            .chain_update(self.group.id.to_be_bytes())
            .chain_update(self.history.id)
            .chain_update(target)
            .chain_update(proposal.tenure.joined_at.to_be_bytes())
            .chain_update(random_id())
            .finalize()
            .into();
        proposal.signed_binding = Some(binding);
        let vote = SignedEjectionVote::new(&proposal, proposer)?;
        self.apply_ejection_vote(&mut proposal, &vote)?;
        Ok(proposal)
    }

    fn required_ejection_votes(&self, target: Key) -> Result<usize, Error> {
        let others = self.eligible_electorate_excluding(target);
        let retain = self.group.policy.required_approvals(others);
        if self.group.policy == Policy::InviterOnly || retain == 0 || retain > others {
            return Err(Error::Ineligible);
        }
        Ok((others - retain + 1).max(others / 2 + 1))
    }

    fn removal_proposal(
        &self,
        proposer: Key,
        target: Key,
        required: usize,
    ) -> Result<RemovalProposal, Error> {
        let mut proposal = self.new_removal(target, required)?;
        self.approve_removal(&mut proposal, proposer)?;
        Ok(proposal)
    }

    fn new_removal(&self, target: Key, required: usize) -> Result<RemovalProposal, Error> {
        Ok(RemovalProposal {
            signed_binding: None,
            required,
            parent: Arc::clone(&self.history),
            target,
            tenure: self.membership(target).ok_or(Error::Ineligible)?,
            approvals: BTreeSet::new(),
        })
    }

    pub fn apply_ejection_vote(
        &self,
        proposal: &mut RemovalProposal,
        vote: &SignedEjectionVote,
    ) -> Result<(), Error> {
        let binding = proposal.signed_binding.ok_or(Error::Ineligible)?;
        parse_verifying_key(&vote.0.signer)?
            .verify_strict(
                &group_ejection_message(binding),
                &Signature::from_bytes(&vote.0.signature),
            )
            .map_err(|_| Error::Ineligible)?;
        self.record_removal_vote(proposal, vote.0.signer)
    }

    pub(crate) fn approve_removal(
        &self,
        proposal: &mut RemovalProposal,
        voter: Key,
    ) -> Result<(), Error> {
        if proposal.signed_binding.is_some() {
            return Err(Error::Ineligible);
        }
        self.record_removal_vote(proposal, voter)
    }

    fn record_removal_vote(&self, proposal: &mut RemovalProposal, voter: Key) -> Result<(), Error> {
        self.check_removal_parent(proposal)?;
        if voter == proposal.target || self.membership(voter).is_none() || self.is_barred(&voter) {
            return Err(Error::Ineligible);
        }
        if !proposal.approvals.insert(voter) {
            return Err(Error::AlreadyVoted);
        }
        Ok(())
    }

    pub(crate) fn apply_removal(&mut self, proposal: &RemovalProposal) -> Result<(), Error> {
        self.check_removal_approval(proposal)?;
        self.remove_tenure(proposal.target, proposal.tenure)?;
        Ok(())
    }

    pub fn ejection_child(&self, proposal: &RemovalProposal) -> Result<[u8; 32], Error> {
        self.check_removal_approval(proposal)?;
        let binding = proposal.signed_binding.ok_or(Error::Ineligible)?;
        Ok(Sha256::new()
            .chain_update(b"mesh/group-admission/ejection-child/v1\0")
            .chain_update(binding)
            .finalize()
            .into())
    }

    pub fn apply_certified_ejection<'c>(
        &mut self,
        proposal: &RemovalProposal,
        certificate: impl Into<CertificateRef<'c>>,
    ) -> Result<(), Error> {
        let child = self.ejection_child(proposal)?;
        let carried = self.verify_certificate(child, certificate.into())?;
        self.remove_tenure_at_child_carrying(proposal.target, proposal.tenure, child, carried)?;
        Ok(())
    }

    fn check_removal_approval(&self, proposal: &RemovalProposal) -> Result<(), Error> {
        self.check_removal_parent(proposal)?;
        if proposal.approvals.len() < proposal.required {
            return Err(Error::ApprovalRequired);
        }
        Ok(())
    }

    fn check_removal_parent(&self, proposal: &RemovalProposal) -> Result<(), Error> {
        if self.history.id != proposal.parent.id
            || self.membership(proposal.target) != Some(proposal.tenure)
        {
            return Err(Error::StaleProposal);
        }
        Ok(())
    }

    pub fn sign_ejection_vote(
        &self,
        local: &LocalInstallation,
        proposal: &RemovalProposal,
        voter: &Installation,
    ) -> Result<SignedEjectionVote, Error> {
        self.check_removal_parent(proposal)?;
        if self.check_local_voter(local, voter)? == proposal.target {
            return Err(Error::Ineligible);
        }
        SignedEjectionVote::new(proposal, voter)
    }

    /// Apply a decoded authorization in the fixture's agreed roster order.
    pub(crate) fn apply_rotation_message(
        &mut self,
        rotation: &SignedRotation,
    ) -> Result<(), Error> {
        self.apply_signed_rotation(
            rotation.context,
            rotation.old,
            rotation.new,
            rotation.signatures,
        )
    }

    /// Verify consent from both keys before applying an agreed rotation.
    pub(crate) fn apply_signed_rotation(
        &mut self,
        context: (u64, [u8; 32]),
        old: Key,
        new: Key,
        signatures: [[u8; 64]; 2],
    ) -> Result<(), Error> {
        self.verify_rotation_consent(context, old, new, signatures)?;
        self.rotate_key(self.revision(), old, new)
    }

    /// Verify both keys and derive the successor before members vote.
    pub fn rotation_child(&self, rotation: &SignedRotation) -> Result<[u8; 32], Error> {
        self.verify_rotation_consent(
            rotation.context,
            rotation.old,
            rotation.new,
            rotation.signatures,
        )?;
        if self.membership(rotation.old).is_none() || self.is_barred(&rotation.old) {
            return Err(Error::Ineligible);
        }
        if self.identities.contains_key(&rotation.new) || self.retired.contains(&rotation.new) {
            return Err(Error::AlreadyMember);
        }
        Ok(self.rotation_child_id(rotation.old, rotation.new))
    }

    /// Apply a dual-key-authorized rotation certified by the parent roster.
    pub fn apply_certified_rotation<'c>(
        &mut self,
        rotation: &SignedRotation,
        certificate: impl Into<CertificateRef<'c>>,
    ) -> Result<(), Error> {
        let child = self.rotation_child(rotation)?;
        let carried = self.verify_certificate(child, certificate.into())?;
        // A proof introduced by this certificate also disqualifies ordinary rotation.
        // Do not let the old key acquire a clean successor or planned continuity while
        // the same transition establishes that it has equivocated.
        if carried.iter().any(|proof| proof.subject() == rotation.old) {
            return Err(Error::Ineligible);
        }
        self.replace_key_carrying(self.revision(), rotation.old, rotation.new, child, carried)?;
        self.predecessors.insert(rotation.new, rotation.old);
        Ok(())
    }

    /// Catch up through an ordered chain of certified rotations.
    /// Publish the new roster only after every step verifies against its own parent.
    ///
    /// Each step's certificate may be version 0 or version 1 (anything convertible to a
    /// `CertificateRef`); mix versions by converting each step to `CertificateRef` first.
    pub fn apply_certified_rotation_chain<'c, C>(
        &mut self,
        chain: &[(&SignedRotation, C)],
    ) -> Result<(), Error>
    where
        C: Copy + Into<CertificateRef<'c>>,
    {
        let mut next = self.clone();
        for &(rotation, certificate) in chain {
            next.apply_certified_rotation(rotation, certificate)?;
        }
        *self = next;
        Ok(())
    }

    fn verify_rotation_consent(
        &self,
        context: (u64, [u8; 32]),
        old: Key,
        new: Key,
        signatures: [[u8; 64]; 2],
    ) -> Result<(), Error> {
        if context != self.rotation_context() {
            return Err(Error::StaleProposal);
        }
        let message = group_rotation_message(context.0, context.1, old, new);
        for (key, signature) in [old, new].into_iter().zip(signatures) {
            let key = parse_verifying_key(&key)?;
            key.verify_strict(&message, &Signature::from_bytes(&signature))
                .map_err(|_| Error::Ineligible)?;
        }
        Ok(())
    }

    /// Apply an ordered key transition after the caller has authenticated both
    /// keys and accepted the old key as a continuity authority.
    pub(crate) fn rotate_key(
        &mut self,
        parent_revision: u64,
        old: Key,
        new: Key,
    ) -> Result<(), Error> {
        parse_verifying_key(&new)?; // a weak or invalid replacement key is never accepted
        if self.is_barred(&old) {
            return Err(Error::Ineligible);
        }
        let child = self.rotation_child_id(old, new);
        self.replace_key(parent_revision, old, new, child)?;
        self.predecessors.insert(new, old);
        Ok(())
    }

    fn rotation_child_id(&self, old: Key, new: Key) -> [u8; 32] {
        let statement = group_rotation_message(self.group.id, self.history.id, old, new);
        Sha256::new()
            .chain_update(b"mesh/group-admission/rotation-child/v1\0")
            .chain_update(statement)
            .finalize()
            .into()
    }

    /// Apply a report already accepted by the simulation's roster authority.
    pub(crate) fn mark_suspect(&mut self, key: Key) -> Result<(), Error> {
        if self.membership(key).is_none() {
            return Err(Error::Ineligible);
        }
        if !self.suspect.contains(&key) {
            self.group.advance()?;
            let child = self.derived_child(b"suspect", &[&key]);
            self.record_roster_child_carrying(child, vec![CarriedProof::SimulationReport(key)]);
        }
        Ok(())
    }

    /// Apply a replacement already accepted through independent recovery.
    /// The pending recovery decision conveys no continuity from the suspect key.
    pub(crate) fn apply_recovered_key(
        &mut self,
        parent_revision: u64,
        old: Key,
        new: Key,
    ) -> Result<(), Error> {
        if !self.is_barred(&old) {
            return Err(Error::Ineligible);
        }
        let child = self.derived_child(b"recovered-key", &[&old, &new]);
        self.replace_key(parent_revision, old, new, child)
    }

    pub(super) fn replace_key(
        &mut self,
        parent_revision: u64,
        old: Key,
        new: Key,
        child: [u8; 32],
    ) -> Result<(), Error> {
        self.replace_key_carrying(parent_revision, old, new, child, Vec::new())
    }

    /// As `replace_key`, recording the proofs the certified transition carried.
    pub(super) fn replace_key_carrying(
        &mut self,
        parent_revision: u64,
        old: Key,
        new: Key,
        child: [u8; 32],
        carried: Vec<CarriedProof>,
    ) -> Result<(), Error> {
        parse_verifying_key(&new)?;
        if parent_revision != self.group.revision {
            return Err(Error::StaleProposal);
        }
        let id = self.membership(old).ok_or(Error::Ineligible)?.identity;
        if self.identities.contains_key(&new) || self.retired.contains(&new) {
            return Err(Error::AlreadyMember);
        }
        self.group.advance()?;
        self.record_roster_child_carrying(child, carried);
        self.identities.remove(&old);
        self.identities.insert(new, id);
        // The replacement key is a fresh voter; the suspect key's exclusion lapses with it.
        self.group.include(id);
        // Witness lists name keys: follow a witness that rotated.
        for witnesses in self.recovery_witnesses.values_mut() {
            for w in witnesses.iter_mut() {
                if *w == old {
                    *w = new;
                }
            }
        }
        self.retired.insert(old);
        self.key_replacements.insert(new, old);
        Ok(())
    }
}
