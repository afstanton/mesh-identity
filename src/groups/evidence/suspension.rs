//! Agreed suspension: a certified transition that stops a key voting without removing it or
//! shrinking the count (`docs/architecture/step2-agreed-suspension-plan.md`). A report proves
//! nothing, so the key stays in the denominator (AS-1), and a guard stops the group from
//! suspending itself into a stall.

use super::electorate::quorum_for;
use super::proof::CarriedProof;
use super::wire::CertificateRef;
use super::{Error, Key, VouchedGroup, parse_verifying_key};
use crate::session::installation::group_suspension_message;
use ed25519_dalek::Signature;
use std::collections::BTreeSet;

/// How many offline members the group must still be able to tolerate after a suspension.
/// Reports spend the same budget as outages (`m - Q(m)`), so a group refuses a suspension
/// that would use it all. A fixed constant, not application policy.
pub const SUSPENSION_RESERVED_OFFLINE: usize = 1;

/// A member's signed proposal to suspend `target`. It binds the exact parent and proposer, so a
/// report is attributable; the authority is the roster certificate over the derived child.
pub struct SignedSuspension {
    context: (u64, [u8; 32]),
    proposer: Key,
    target: Key,
    signature: [u8; 64],
}

impl SignedSuspension {
    pub fn new(context: (u64, [u8; 32]), proposer: Key, target: Key, signature: [u8; 64]) -> Self {
        Self {
            context,
            proposer,
            target,
            signature,
        }
    }

    pub fn to_bytes(&self) -> [u8; 168] {
        let mut bytes = [0; 168];
        bytes[..8].copy_from_slice(&self.context.0.to_be_bytes());
        bytes[8..40].copy_from_slice(&self.context.1);
        bytes[40..72].copy_from_slice(&self.proposer);
        bytes[72..104].copy_from_slice(&self.target);
        bytes[104..].copy_from_slice(&self.signature);
        bytes
    }

    /// Decode the frame. Authorization is verified against the receiving roster.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 168] = bytes.try_into().map_err(|_| Error::Ineligible)?;
        Ok(Self {
            context: (
                u64::from_be_bytes(bytes[..8].try_into().unwrap()),
                bytes[8..40].try_into().unwrap(),
            ),
            proposer: bytes[40..72].try_into().unwrap(),
            target: bytes[72..104].try_into().unwrap(),
            signature: bytes[104..].try_into().unwrap(),
        })
    }
}

impl VouchedGroup {
    /// Check a suspension proposal against the current head and derive its consensus child:
    /// the exact parent, a current unbarred proposer and target, the proposer's signature, and
    /// the stall guard. The child depends only on the target, so two proposals for one key are
    /// one operation.
    pub fn suspension_child(&self, suspension: &SignedSuspension) -> Result<[u8; 32], Error> {
        if suspension.context != self.rotation_context() {
            return Err(Error::StaleProposal);
        }
        if suspension.proposer == suspension.target {
            return Err(Error::Ineligible);
        }
        for key in [&suspension.proposer, &suspension.target] {
            if self.membership(*key).is_none() || self.is_barred(key) {
                return Err(Error::Ineligible);
            }
        }
        let message = group_suspension_message(
            suspension.context.0,
            suspension.context.1,
            suspension.proposer,
            suspension.target,
        );
        parse_verifying_key(&suspension.proposer)?
            .verify_strict(&message, &Signature::from_bytes(&suspension.signature))
            .map_err(|_| Error::Ineligible)?;
        self.check_suspension_headroom(&[])?;
        Ok(self.derived_child(b"suspend", &[&suspension.target]))
    }

    /// One more report must leave at least the quorum plus the reserved offline allowance among
    /// the members who can still vote.
    fn check_suspension_headroom(&self, carried: &[CarriedProof]) -> Result<(), Error> {
        let proven: BTreeSet<_> = self
            .suspect
            .iter()
            .copied()
            .chain(carried.iter().map(CarriedProof::subject))
            .collect();
        let electorate = self
            .identities
            .keys()
            .filter(|key| self.membership(**key).is_some() && !proven.contains(*key))
            .count();
        let required = quorum_for(electorate).ok_or(Error::WouldStall)?;
        let reported = self
            .reported_keys()
            .iter()
            .filter(|key| self.membership(**key).is_some() && !proven.contains(*key))
            .count();
        let voters_after = electorate.saturating_sub(reported + 1);
        if voters_after < required + SUSPENSION_RESERVED_OFFLINE {
            return Err(Error::WouldStall);
        }
        Ok(())
    }

    /// Suspend a key under a roster certificate (version 0 or 1). Nobody is removed and the
    /// count does not shrink; the key stops voting, rotating, vouching, inviting and vetoing.
    pub fn apply_certified_suspension<'c>(
        &mut self,
        suspension: &SignedSuspension,
        certificate: impl Into<CertificateRef<'c>>,
    ) -> Result<(), Error> {
        let child = self.suspension_child(suspension)?;
        let carried = self.verify_certificate(child, certificate.into())?;
        // A proof against the target in the same transition makes the report redundant: the key
        // is proven, and the proof, not a report, should be what the group records.
        if carried
            .iter()
            .any(|proof| proof.subject() == suspension.target)
        {
            return Err(Error::Ineligible);
        }
        // Certificate proofs change both the available voters and the required quorum.
        // Check the resulting state before recording either the proofs or the report.
        self.check_suspension_headroom(&carried)?;
        self.group.advance()?;
        self.record_roster_child_reporting(child, carried, vec![suspension.target]);
        Ok(())
    }
}
