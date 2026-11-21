//! Recognizing a replacement device: a certified roster operation that records which device
//! may sign for an identity in this group (`docs/architecture/step3-voting-device-handoff-plan.md`,
//! H3; `TakeoverRecognition.tla`).
//!
//! A takeover without the old device starts gated everywhere. The new device signs a statement
//! `(identity, counter, device nonce)`; each group certifies it as a roster child, and the chain
//! then records the latest recognized counter and nonce per identity. Only the device whose
//! counter and nonce match the chain's record may sign for that identity in this group, so
//! "created after recognition" is ancestry, and two devices at one counter cannot both match.

use super::electorate::{ElectorateQuorumCheck, QuorumRejection, check_electorate_quorum};
use super::proof::CarriedProof;
use super::wire::CertificateRef;
use super::{Error, Key, VouchedGroup, parse_verifying_key};
use crate::session::installation::{
    Installation, TakeoverStatement, VotingState, handoff_statement_message,
};
use ed25519_dalek::Signature;
use std::collections::BTreeSet;

/// A takeover statement addressed to one group head. Its signature is the identity's own, over
/// `(identity, counter, nonce)` only: the certificate over the derived child binds the parent.
pub struct SignedRecognition {
    context: (u64, [u8; 32]),
    identity: Key,
    counter: u64,
    nonce: [u8; 32],
    signature: [u8; 64],
}

impl SignedRecognition {
    pub fn new(context: (u64, [u8; 32]), statement: &TakeoverStatement) -> Self {
        Self {
            context,
            identity: statement.identity,
            counter: statement.counter,
            nonce: statement.nonce,
            signature: statement.signature,
        }
    }

    pub fn identity(&self) -> Key {
        self.identity
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    pub fn to_bytes(&self) -> [u8; 176] {
        let mut bytes = [0; 176];
        bytes[..8].copy_from_slice(&self.context.0.to_be_bytes());
        bytes[8..40].copy_from_slice(&self.context.1);
        bytes[40..72].copy_from_slice(&self.identity);
        bytes[72..80].copy_from_slice(&self.counter.to_be_bytes());
        bytes[80..112].copy_from_slice(&self.nonce);
        bytes[112..].copy_from_slice(&self.signature);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 176] = bytes.try_into().map_err(|_| Error::Ineligible)?;
        Ok(Self {
            context: (
                u64::from_be_bytes(bytes[..8].try_into().unwrap()),
                bytes[8..40].try_into().unwrap(),
            ),
            identity: bytes[40..72].try_into().unwrap(),
            counter: u64::from_be_bytes(bytes[72..80].try_into().unwrap()),
            nonce: bytes[80..112].try_into().unwrap(),
            signature: bytes[112..].try_into().unwrap(),
        })
    }
}

impl VouchedGroup {
    /// Check a takeover statement against the current head and derive its consensus child. The
    /// identity must be a current, unbarred member, the counter must rise above the chain's
    /// record for it (so a statement recognizes at most once and an older one never returns),
    /// and the statement must carry the identity's signature. The child binds the counter and
    /// nonce, so two devices at one counter are two different operations.
    pub fn recognition_child(&self, recognition: &SignedRecognition) -> Result<[u8; 32], Error> {
        if recognition.context != self.rotation_context() {
            return Err(Error::StaleProposal);
        }
        let identity = recognition.identity;
        if self.membership(identity).is_none() || self.is_barred(&identity) {
            return Err(Error::Ineligible);
        }
        if recognition.counter == 0
            || self
                .recognized_device(&identity)
                .is_some_and(|(counter, _)| recognition.counter <= counter)
        {
            return Err(Error::Ineligible);
        }
        let message = handoff_statement_message(identity, recognition.counter, recognition.nonce);
        parse_verifying_key(&identity)?
            .verify_strict(&message, &Signature::from_bytes(&recognition.signature))
            .map_err(|_| Error::Ineligible)?;
        Ok(self.derived_child(
            b"recognize",
            &[
                &identity,
                &recognition.counter.to_be_bytes(),
                &recognition.nonce,
            ],
        ))
    }

    /// Recognize the device under a roster certificate (version 0 or 1) whose quorum does not
    /// include the identity's own vote: the identity stays in the denominator but cannot sign
    /// for itself. If the others cannot reach the quorum without it, this refuses (`Ineligible`,
    /// like any short certificate) and the group does not manufacture progress; recovery or a
    /// new group is the exit.
    pub fn apply_certified_recognition<'c>(
        &mut self,
        recognition: &SignedRecognition,
        certificate: impl Into<CertificateRef<'c>>,
    ) -> Result<(), Error> {
        let child = self.recognition_child(recognition)?;
        let certificate = certificate.into();
        let carried = self.verify_certificate(child, certificate)?;
        if carried
            .iter()
            .any(|proof| proof.subject() == recognition.identity)
        {
            return Err(Error::Ineligible);
        }
        self.check_quorum_without(recognition.identity, certificate, &carried)?;
        self.group.advance()?;
        self.record_roster_child_full(
            child,
            carried,
            Vec::new(),
            vec![(recognition.identity, recognition.counter, recognition.nonce)],
        );
        Ok(())
    }

    /// The certificate's quorum with `excluded` treated like a reported key: its signature is
    /// refused and it still counts in the denominator.
    fn check_quorum_without(
        &self,
        excluded: Key,
        certificate: CertificateRef<'_>,
        carried: &[CarriedProof],
    ) -> Result<(), Error> {
        let roster: BTreeSet<Key> = self
            .identities
            .keys()
            .copied()
            .filter(|key| self.membership(*key).is_some())
            .collect();
        let mut reported = self.reported_keys().clone();
        reported.insert(excluded);
        let (base, inherited, carried_set) = match certificate.kind_v1() {
            Some(v1) => {
                let inherited = self.inherited_proof_keys().clone();
                let mut all = inherited.clone();
                all.extend(carried.iter().map(CarriedProof::subject));
                (&v1.certificate, inherited, all)
            }
            None => (
                certificate
                    .kind_v0()
                    .expect("a certificate is version 0 or 1"),
                self.suspect.clone(),
                self.suspect.clone(),
            ),
        };
        for votes in [&base.prepares, &base.commits] {
            let signers: BTreeSet<Key> = votes.iter().map(|vote| vote.signer).collect();
            check_electorate_quorum(&ElectorateQuorumCheck {
                roster: &roster,
                inherited: &inherited,
                carried: &carried_set,
                reported: &reported,
                signers: &signers,
            })
            .map_err(|rejection| match rejection {
                QuorumRejection::BelowQuorum { .. } => Error::ApprovalRequired,
                _ => Error::Ineligible,
            })?;
        }
        Ok(())
    }

    /// Whether this device may sign for its identity in this group, given what the chain
    /// recognizes. Called before any group signature.
    ///
    /// - No recognition on the chain: the device's own voting state decides.
    /// - Recognized counter and nonce match this device: permit it here (a gated takeover device
    ///   signs in this group only).
    /// - A different grant, including a higher acknowledged counter, needs recognition
    ///   of its own; a larger number alone is not continuity from this chain.
    /// - Anything else is refused: another device holds the recognition.
    pub(super) fn check_voting_role(&self, voter: &Installation) -> Result<(), Error> {
        let key = voter.selected();
        // An older view must not reuse a permission installed by a newer view.
        voter.revoke_group(self.group.id);
        let Some((counter, nonce)) = self.recognized_device(&key) else {
            return Ok(());
        };
        let record = voter.voting_record(key);
        let matches = record.state != VotingState::Stopped
            && record.counter == counter
            && record.holder == Some(nonce)
            && voter.current_device_nonce() == Some(nonce);
        if matches {
            voter.permit_group(self.group.id, self.history.id);
            return Ok(());
        }
        voter.revoke_group(self.group.id);
        Err(Error::NotVotingDevice)
    }
}
