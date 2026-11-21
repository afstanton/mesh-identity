//! Trusted roster operations used by the simulation fixtures.

use super::{
    AdmissionError, AdmissionUpdate, DirectVoucher, Error, Key, RecoveryRequest, RemovalProposal,
    SignedDeparture, SignedRotation, VouchedGroup, VouchedProposal,
};
use crate::groups::{Membership, Policy, Vote};

/// Roster changes that this simulation applies on trust, with no signature check: the caller
/// stands in for an agreed, authenticated roster authority. They are deliberately separate from
/// the signed entry points (`apply_signed_*`, `apply_admission_*`, `apply_withdrawal`), and a
/// production implementation must not expose them. Import this trait to use them, so every
/// call site that relies on trusted input is visible. The trait exists only with the
/// `simulation-authority` feature (enabled for this crate's own tests), so a build without it
/// has no way to apply an uncertified roster change.
pub trait SimulatedAuthority {
    fn recover_lost_key(&mut self, request: &RecoveryRequest) -> Result<(), Error>;
    fn mark_suspect(&mut self, key: Key) -> Result<(), Error>;
    fn apply_policy_change(&mut self, parent: u64, policy: Policy) -> Result<bool, Error>;
    fn rotate_key(&mut self, parent_revision: u64, old: Key, new: Key) -> Result<(), Error>;
    fn apply_recovered_key(
        &mut self,
        parent_revision: u64,
        old: Key,
        new: Key,
    ) -> Result<(), Error>;
    fn apply_departure(&mut self, sender: Key, tenure: Membership) -> Result<bool, Error>;
    fn withdraw(&mut self, issuer: Key, voucher: &DirectVoucher) -> Result<(), Error>;
    fn enroll_recovery(&mut self, owner: Key, witnesses: [Key; 2]) -> Result<(), Error>;
    fn admit(
        &mut self,
        proposal: &VouchedProposal,
        voucher: Option<DirectVoucher>,
    ) -> Result<AdmissionUpdate, AdmissionError>;
    fn vote(
        &self,
        proposal: &mut VouchedProposal,
        voter: Key,
        vote: Vote,
    ) -> Result<(), AdmissionError>;
    fn apply_removal(&mut self, proposal: &RemovalProposal) -> Result<(), Error>;
    fn approve_removal(&self, proposal: &mut RemovalProposal, voter: Key) -> Result<(), Error>;
    fn apply_signed_rotation(
        &mut self,
        context: (u64, [u8; 32]),
        old: Key,
        new: Key,
        signatures: [[u8; 64]; 2],
    ) -> Result<(), Error>;
    fn apply_rotation_message(&mut self, rotation: &SignedRotation) -> Result<(), Error>;
    fn apply_signed_departure(
        &mut self,
        member: Key,
        context: (u64, [u8; 32]),
        signature: [u8; 64],
    ) -> Result<bool, Error>;
    fn apply_departure_message(&mut self, departure: &SignedDeparture) -> Result<bool, Error>;
    fn propose_removal(&self, proposer: Key, target: Key) -> Result<RemovalProposal, Error>;
    fn propose_ejection(&self, proposer: Key, target: Key) -> Result<RemovalProposal, Error>;
}

impl SimulatedAuthority for VouchedGroup {
    fn recover_lost_key(&mut self, request: &RecoveryRequest) -> Result<(), Error> {
        VouchedGroup::recover_lost_key(self, request)
    }
    fn mark_suspect(&mut self, key: Key) -> Result<(), Error> {
        VouchedGroup::mark_suspect(self, key)
    }
    fn apply_policy_change(&mut self, parent: u64, policy: Policy) -> Result<bool, Error> {
        VouchedGroup::apply_policy_change(self, parent, policy)
    }
    fn rotate_key(&mut self, parent_revision: u64, old: Key, new: Key) -> Result<(), Error> {
        VouchedGroup::rotate_key(self, parent_revision, old, new)
    }
    fn apply_recovered_key(
        &mut self,
        parent_revision: u64,
        old: Key,
        new: Key,
    ) -> Result<(), Error> {
        VouchedGroup::apply_recovered_key(self, parent_revision, old, new)
    }
    fn apply_departure(&mut self, sender: Key, tenure: Membership) -> Result<bool, Error> {
        VouchedGroup::apply_departure(self, sender, tenure)
    }
    fn withdraw(&mut self, issuer: Key, voucher: &DirectVoucher) -> Result<(), Error> {
        VouchedGroup::withdraw(self, issuer, voucher)
    }
    fn enroll_recovery(&mut self, owner: Key, witnesses: [Key; 2]) -> Result<(), Error> {
        VouchedGroup::enroll_recovery(self, owner, witnesses)
    }
    fn admit(
        &mut self,
        proposal: &VouchedProposal,
        voucher: Option<DirectVoucher>,
    ) -> Result<AdmissionUpdate, AdmissionError> {
        VouchedGroup::admit(self, proposal, voucher)
    }
    fn vote(
        &self,
        proposal: &mut VouchedProposal,
        voter: Key,
        vote: Vote,
    ) -> Result<(), AdmissionError> {
        VouchedGroup::vote(self, proposal, voter, vote)
    }
    fn apply_removal(&mut self, proposal: &RemovalProposal) -> Result<(), Error> {
        VouchedGroup::apply_removal(self, proposal)
    }
    fn approve_removal(&self, proposal: &mut RemovalProposal, voter: Key) -> Result<(), Error> {
        VouchedGroup::approve_removal(self, proposal, voter)
    }
    fn apply_signed_rotation(
        &mut self,
        context: (u64, [u8; 32]),
        old: Key,
        new: Key,
        signatures: [[u8; 64]; 2],
    ) -> Result<(), Error> {
        VouchedGroup::apply_signed_rotation(self, context, old, new, signatures)
    }
    fn apply_rotation_message(&mut self, rotation: &SignedRotation) -> Result<(), Error> {
        VouchedGroup::apply_rotation_message(self, rotation)
    }
    fn apply_signed_departure(
        &mut self,
        member: Key,
        context: (u64, [u8; 32]),
        signature: [u8; 64],
    ) -> Result<bool, Error> {
        VouchedGroup::apply_signed_departure(self, member, context, signature)
    }
    fn apply_departure_message(&mut self, departure: &SignedDeparture) -> Result<bool, Error> {
        VouchedGroup::apply_departure_message(self, departure)
    }
    fn propose_removal(&self, proposer: Key, target: Key) -> Result<RemovalProposal, Error> {
        VouchedGroup::propose_removal(self, proposer, target)
    }
    fn propose_ejection(&self, proposer: Key, target: Key) -> Result<RemovalProposal, Error> {
        VouchedGroup::propose_ejection(self, proposer, target)
    }
}
