//! Signed recovery requests, witness approvals, and holder vetoes.

use super::wire::CertificateRef;
use super::{
    Error, Installation, Key, RosterHistory, VouchedGroup, parse_verifying_key, random_id,
    verified_contact,
};
use crate::groups::MemberLocalState;
use crate::session::installation::{group_recovery_enrollment_message, group_recovery_message};
use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// The replacement key's signed consent to take over a lost member key's membership.
pub struct SignedRecoveryConsent([u8; 64]);

impl SignedRecoveryConsent {
    pub fn to_bytes(&self) -> [u8; 64] {
        self.0
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(bytes.try_into().map_err(|_| Error::Ineligible)?))
    }
}

/// The owner's signed recovery commitment. It carries neither the witnesses nor the salt:
/// those stay with the owner and the witnesses, and only the commitment is replicated.
pub struct SignedRecoveryEnrollment {
    context: (u64, [u8; 32]),
    owner: Key,
    commitment: [u8; 32],
    signature: [u8; 64],
}

impl SignedRecoveryEnrollment {
    pub fn new(
        context: (u64, [u8; 32]),
        owner: Key,
        commitment: [u8; 32],
        signature: [u8; 64],
    ) -> Self {
        Self {
            context,
            owner,
            commitment,
            signature,
        }
    }

    pub fn to_bytes(&self) -> [u8; 168] {
        let mut bytes = [0; 168];
        bytes[..8].copy_from_slice(&self.context.0.to_be_bytes());
        bytes[8..40].copy_from_slice(&self.context.1);
        bytes[40..72].copy_from_slice(&self.owner);
        bytes[72..104].copy_from_slice(&self.commitment);
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
            owner: bytes[40..72].try_into().unwrap(),
            commitment: bytes[72..104].try_into().unwrap(),
            signature: bytes[104..].try_into().unwrap(),
        })
    }
}

/// How long the current holder of a key can veto a witness-approved replacement unless the
/// key is already marked suspect (a lost or compromised key cannot veto, and is not waited on).
pub const RECOVERY_VETO_WINDOW_MS: u64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryStatus {
    NotEnrolled,
    Enrolled,
    /// A witness left or was removed; the owner has no working recovery until they re-enroll.
    Degraded,
}

/// Recovery request issued under one exact roster state.
pub struct RecoveryRequest {
    nonce: [u8; 32],
    opened_at: u64,
    vetoed: bool,
    /// The replacement key has signed its own consent to take over this membership.
    consented: bool,
    parent: Arc<RosterHistory>,
    old: Key,
    new: Key,
    witnesses: [Key; 2],
    enrollment_salt: [u8; 32],
    approvals: BTreeSet<Key>,
}

impl RecoveryRequest {
    pub fn old(&self) -> Key {
        self.old
    }

    pub fn new_key(&self) -> Key {
        self.new
    }

    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
}

/// A portable request carrying the replacement key's signed consent.
pub struct SignedRecoveryRequest {
    group: u64,
    parent: [u8; 32],
    old: Key,
    new: Key,
    nonce: [u8; 32],
    consent: SignedRecoveryConsent,
}

impl SignedRecoveryRequest {
    pub fn to_bytes(&self) -> [u8; 200] {
        let mut bytes = [0; 200];
        bytes[..8].copy_from_slice(&self.group.to_be_bytes());
        bytes[8..40].copy_from_slice(&self.parent);
        bytes[40..72].copy_from_slice(&self.old);
        bytes[72..104].copy_from_slice(&self.new);
        bytes[104..136].copy_from_slice(&self.nonce);
        bytes[136..].copy_from_slice(&self.consent.to_bytes());
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 200] = bytes.try_into().map_err(|_| Error::Ineligible)?;
        Ok(Self {
            group: u64::from_be_bytes(bytes[..8].try_into().unwrap()),
            parent: bytes[8..40].try_into().unwrap(),
            old: bytes[40..72].try_into().unwrap(),
            new: bytes[72..104].try_into().unwrap(),
            nonce: bytes[104..136].try_into().unwrap(),
            consent: SignedRecoveryConsent::from_bytes(&bytes[136..])?,
        })
    }

    pub fn old(&self) -> Key {
        self.old
    }

    pub fn new_key(&self) -> Key {
        self.new
    }

    pub fn nonce(&self) -> [u8; 32] {
        self.nonce
    }
}

/// Peer-local recovery state for one group view. A peer only keeps requests it can act on: its
/// own key being replaced, or a request naming it as an enrolled witness whose replacement key it
/// has verified in person. Everything else is dropped before it takes any space.
#[derive(Default)]
pub struct RecoveryInbox {
    pending: BTreeMap<([u8; 32], Key, Key), RecoveryRequest>,
}

impl RecoveryInbox {
    pub const MAX_PENDING: usize = 32;
    pub const MAX_PER_OLD_KEY: usize = 4;

    fn is_active(group: &VouchedGroup, request: &RecoveryRequest) -> bool {
        !request.vetoed
            && group.now
                < request
                    .opened_at
                    .saturating_add(2 * RECOVERY_VETO_WINDOW_MS)
    }

    pub fn receive(
        &mut self,
        group: &VouchedGroup,
        signed: &SignedRecoveryRequest,
        viewer: &Installation,
    ) -> Result<&mut RecoveryRequest, Error> {
        if group.group.id != signed.group || group.history.id != signed.parent {
            return Err(Error::StaleProposal);
        }
        let mut request =
            group.request_recovery_with_nonce(signed.old, signed.new, signed.nonce)?;
        let me = viewer.selected();
        let is_owner = request.old == me;
        if !is_owner && !(request.witnesses.contains(&me) && verified_contact(viewer, request.new))
        {
            return Err(Error::Ineligible);
        }
        group.apply_recovery_consent(&mut request, &signed.consent)?;
        self.pending.retain(|_, pending| {
            pending.parent.id == group.history.id
                && group.now
                    < pending
                        .opened_at
                        .saturating_add(2 * RECOVERY_VETO_WINDOW_MS)
        });
        let key = (signed.nonce, signed.old, signed.new);
        if !self.pending.contains_key(&key) {
            let for_old = self
                .pending
                .values()
                .filter(|pending| pending.old == signed.old && Self::is_active(group, pending))
                .count();
            if for_old >= Self::MAX_PER_OLD_KEY {
                return Err(Error::Ineligible);
            }
            if self.pending.len() >= Self::MAX_PENDING {
                let inactive_key = self
                    .pending
                    .iter()
                    .find(|(_, p)| !Self::is_active(group, p))
                    .map(|(k, _)| *k);
                if let Some(ik) = inactive_key {
                    self.pending.remove(&ik);
                } else {
                    // Same fairness rule as the invitation inbox, keyed by the old key.
                    let mut counts: BTreeMap<Key, usize> = BTreeMap::new();
                    for p in self.pending.values() {
                        *counts.entry(p.old).or_default() += 1;
                    }
                    let mine = counts.get(&signed.old).copied().unwrap_or(0);
                    let victim = self
                        .pending
                        .iter()
                        .filter(|(_, p)| counts[&p.old] > mine + 1)
                        .max_by_key(|(_, p)| (counts[&p.old], std::cmp::Reverse(p.opened_at)))
                        .map(|(k, _)| *k);
                    match victim {
                        Some(k) => {
                            self.pending.remove(&k);
                        }
                        None => return Err(Error::Ineligible),
                    }
                }
            }
            self.pending.insert(key, request);
        }
        Ok(self.pending.get_mut(&key).unwrap())
    }

    pub fn pending(&self) -> impl Iterator<Item = &RecoveryRequest> {
        self.pending.values()
    }

    pub fn remove(&mut self, nonce: [u8; 32], old: Key, new: Key) -> Option<RecoveryRequest> {
        self.pending.remove(&(nonce, old, new))
    }
}

const RECOVERY_CONSENT: u8 = 1;
const RECOVERY_APPROVAL: u8 = 2;
const RECOVERY_VETO: u8 = 3;

/// A response to an already-known recovery request.
pub struct SignedRecoveryDecision {
    signer: Key,
    kind: u8,
    signature: [u8; 64],
}

impl SignedRecoveryDecision {
    pub fn to_bytes(&self) -> [u8; 97] {
        let mut bytes = [0; 97];
        bytes[..32].copy_from_slice(&self.signer);
        bytes[32] = self.kind;
        bytes[33..].copy_from_slice(&self.signature);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 97] = bytes.try_into().map_err(|_| Error::Ineligible)?;
        if !matches!(bytes[32], RECOVERY_APPROVAL | RECOVERY_VETO) {
            return Err(Error::Ineligible);
        }
        Ok(Self {
            signer: bytes[..32].try_into().unwrap(),
            kind: bytes[32],
            signature: bytes[33..].try_into().unwrap(),
        })
    }
}

impl VouchedGroup {
    pub fn sign_recovery_approval(
        &self,
        local: &MemberLocalState,
        request: &RecoveryRequest,
        witness: &Installation,
    ) -> Result<SignedRecoveryDecision, Error> {
        self.check_local_voter(local, witness)?;
        self.recovery_approval(request, witness)
    }

    pub fn sign_recovery_veto(
        &self,
        local: &MemberLocalState,
        request: &RecoveryRequest,
        holder: &Installation,
    ) -> Result<SignedRecoveryDecision, Error> {
        let key = holder.selected();
        let tenure = self.membership(key).ok_or(Error::Ineligible)?;
        if !self.may_present(local, key, tenure) {
            return Err(Error::Ineligible);
        }
        self.recovery_veto(request, holder)
    }

    /// Enroll two distinct current member keys while the member can still act.
    /// The simulation supplies authenticated enrollment and witness consent.
    pub(crate) fn enroll_recovery(&mut self, owner: Key, witnesses: [Key; 2]) -> Result<(), Error> {
        let salt = random_id();
        let commitment = self.enrollment_commitment(owner, witnesses, salt)?;
        let child = self.enrollment_child_of(owner, commitment);
        self.set_enrollment_at_child(owner, commitment, child, Vec::new())?;
        self.install_recovery_opening(owner, witnesses, salt)
    }

    /// Validate an arrangement against this roster and return its commitment. The owner runs
    /// this to build the commitment it signs; nothing is stored.
    pub fn enrollment_commitment(
        &self,
        owner: Key,
        witnesses: [Key; 2],
        salt: [u8; 32],
    ) -> Result<[u8; 32], Error> {
        if self.is_barred(&owner) {
            return Err(Error::Ineligible);
        }
        self.recovery_opening_commitment(owner, witnesses, salt)
    }

    // Installing an existing opening is not a new enrollment: a suspended owner still
    // needs its witnesses to recover it. Witness eligibility and tenure remain mandatory.
    fn recovery_opening_commitment(
        &self,
        owner: Key,
        witnesses: [Key; 2],
        salt: [u8; 32],
    ) -> Result<[u8; 32], Error> {
        let owner_id = self.membership(owner).ok_or(Error::Ineligible)?.identity;
        if witnesses[0] == witnesses[1]
            || witnesses.contains(&owner)
            || witnesses
                .iter()
                .any(|&key| self.membership(key).is_none() || self.is_barred(&key))
        {
            return Err(Error::Ineligible);
        }
        self.recovery_commitment(owner_id, witnesses, salt)
    }

    fn enrollment_child_of(&self, owner: Key, commitment: [u8; 32]) -> [u8; 32] {
        self.derived_child(b"enroll-recovery", &[&owner, &commitment])
    }

    /// Replicate a commitment. Any opening held for an earlier commitment is dropped: it no
    /// longer matches, and the owner and witnesses install the new one locally.
    fn set_enrollment_at_child(
        &mut self,
        owner: Key,
        commitment: [u8; 32],
        child: [u8; 32],
        carried: Vec<super::CarriedProof>,
    ) -> Result<(), Error> {
        let owner_id = self.membership(owner).ok_or(Error::Ineligible)?.identity;
        self.group.advance()?;
        self.record_roster_child_carrying(child, carried);
        self.recovery_commitments.insert(owner_id, commitment);
        self.recovery_salts.remove(&owner_id);
        self.recovery_witnesses.remove(&owner_id);
        self.degraded_recovery.remove(&owner_id);
        Ok(())
    }

    /// Keep the private opening of the replicated commitment. Used locally by the owner and
    /// the two witnesses; it changes no roster state and is checked against the commitment.
    /// Witness order is canonicalized so openings match independently of array order.
    pub fn install_recovery_opening(
        &mut self,
        owner: Key,
        witnesses: [Key; 2],
        salt: [u8; 32],
    ) -> Result<(), Error> {
        let owner_id = self.membership(owner).ok_or(Error::Ineligible)?.identity;
        let commitment = self.recovery_opening_commitment(owner, witnesses, salt)?;
        if self.recovery_commitments.get(&owner_id) != Some(&commitment) {
            return Err(Error::Ineligible);
        }
        let mut canonical_witnesses = witnesses;
        canonical_witnesses
            .sort_unstable_by_key(|w| self.membership(*w).map(|t| (t.identity.0, t.joined_at)));
        self.recovery_salts.insert(owner_id, salt);
        self.recovery_witnesses
            .insert(owner_id, canonical_witnesses);
        Ok(())
    }

    /// Check an enrollment's frame and owner signature against the current head and derive
    /// its consensus child. Members cannot see the witnesses, so only the owner is checked.
    pub fn enrollment_child(
        &self,
        enrollment: &SignedRecoveryEnrollment,
    ) -> Result<[u8; 32], Error> {
        if enrollment.context != self.rotation_context() {
            return Err(Error::StaleProposal);
        }
        if self.membership(enrollment.owner).is_none() || self.is_barred(&enrollment.owner) {
            return Err(Error::Ineligible);
        }
        let message = group_recovery_enrollment_message(
            enrollment.context.0,
            enrollment.context.1,
            enrollment.owner,
            enrollment.commitment,
        );
        parse_verifying_key(&enrollment.owner)?
            .verify_strict(&message, &Signature::from_bytes(&enrollment.signature))
            .map_err(|_| Error::Ineligible)?;
        Ok(self.enrollment_child_of(enrollment.owner, enrollment.commitment))
    }

    /// Replicate a recovery commitment under a roster certificate. The owner and witnesses
    /// then call `install_recovery_opening` locally.
    pub fn apply_certified_enrollment<'c>(
        &mut self,
        enrollment: &SignedRecoveryEnrollment,
        certificate: impl Into<CertificateRef<'c>>,
    ) -> Result<(), Error> {
        let child = self.enrollment_child(enrollment)?;
        let carried = self.verify_certificate(child, certificate.into())?;
        if carried
            .iter()
            .any(|proof| proof.subject() == enrollment.owner)
        {
            return Err(Error::Ineligible);
        }
        self.set_enrollment_at_child(enrollment.owner, enrollment.commitment, child, carried)
    }

    pub fn recovery_status(&self, owner: Key) -> RecoveryStatus {
        match self.identities.get(&owner) {
            Some(id) if self.degraded_recovery.contains(id) => RecoveryStatus::Degraded,
            Some(id) => match self.recovery_witnesses.get(id) {
                Some(witnesses) => {
                    if witnesses
                        .iter()
                        .any(|&key| self.membership(key).is_none() || self.is_barred(&key))
                    {
                        RecoveryStatus::Degraded
                    } else {
                        RecoveryStatus::Enrolled
                    }
                }
                None => RecoveryStatus::NotEnrolled,
            },
            _ => RecoveryStatus::NotEnrolled,
        }
    }

    pub fn request_recovery(&self, old: Key, new: Key) -> Result<RecoveryRequest, Error> {
        self.request_recovery_with_nonce(old, new, random_id())
    }

    fn request_recovery_with_nonce(
        &self,
        old: Key,
        new: Key,
        nonce: [u8; 32],
    ) -> Result<RecoveryRequest, Error> {
        parse_verifying_key(&new)?;
        let owner = self.membership(old).ok_or(Error::Ineligible)?.identity;
        if self.identities.contains_key(&new) || self.retired.contains(&new) {
            return Err(Error::AlreadyMember);
        }
        let &witnesses = self
            .recovery_witnesses
            .get(&owner)
            .ok_or(Error::Ineligible)?;
        if witnesses
            .iter()
            .any(|&w| self.membership(w).is_none() || self.is_barred(&w))
        {
            return Err(Error::Ineligible);
        }
        Ok(RecoveryRequest {
            nonce,
            opened_at: self.now,
            vetoed: false,
            consented: false,
            parent: Arc::clone(&self.history),
            old,
            new,
            witnesses,
            enrollment_salt: *self.recovery_salts.get(&owner).ok_or(Error::Ineligible)?,
            approvals: BTreeSet::new(),
        })
    }

    pub fn sign_recovery_request(
        &self,
        request: &RecoveryRequest,
        replacement: &Installation,
    ) -> Result<SignedRecoveryRequest, Error> {
        let consent = self.recovery_consent(request, replacement)?;
        Ok(SignedRecoveryRequest {
            group: self.group.id,
            parent: request.parent.id,
            old: request.old,
            new: request.new,
            nonce: request.nonce,
            consent,
        })
    }

    fn check_recovery_parent(&self, request: &RecoveryRequest) -> Result<(), Error> {
        if self.history.id != request.parent.id {
            return Err(Error::StaleProposal);
        }
        Ok(())
    }

    fn eligible_recovery_witness(&self, request: &RecoveryRequest, key: Key) -> bool {
        request.witnesses.contains(&key) && self.membership(key).is_some() && !self.is_barred(&key)
    }

    fn sign_recovery(
        &self,
        request: &RecoveryRequest,
        signer: &Installation,
        kind: u8,
    ) -> Result<[u8; 64], Error> {
        signer
            .sign_group_recovery(
                self.group.id,
                request.parent.id,
                request.old,
                request.new,
                request.nonce,
                kind,
            )
            .map_err(|e| super::agreement::roster_signing_error(e, Error::Ineligible))
    }

    fn verify_recovery(
        &self,
        request: &RecoveryRequest,
        signer: Key,
        kind: u8,
        signature: [u8; 64],
    ) -> Result<(), Error> {
        let message = group_recovery_message(
            self.group.id,
            request.parent.id,
            request.old,
            request.new,
            request.nonce,
            kind,
        );
        parse_verifying_key(&signer)?
            .verify_strict(&message, &Signature::from_bytes(&signature))
            .map_err(|_| Error::Ineligible)
    }

    /// Sign explicit witness approval based on an Encounter with the replacement.
    pub fn recovery_approval(
        &self,
        request: &RecoveryRequest,
        witness: &Installation,
    ) -> Result<SignedRecoveryDecision, Error> {
        self.check_recovery_parent(request)?;
        let signer = witness.selected();
        if !self.eligible_recovery_witness(request, signer)
            || !verified_contact(witness, request.new)
        {
            return Err(Error::Ineligible);
        }
        Ok(SignedRecoveryDecision {
            signer,
            kind: RECOVERY_APPROVAL,
            signature: self.sign_recovery(request, witness, RECOVERY_APPROVAL)?,
        })
    }

    pub fn approve_recovery(
        &self,
        request: &mut RecoveryRequest,
        witness: &Installation,
    ) -> Result<bool, Error> {
        let approval = self.recovery_approval(request, witness)?;
        self.apply_recovery_decision(request, &approval)
    }

    /// The replacement key signs its own consent for exactly this request.
    pub fn recovery_consent(
        &self,
        request: &RecoveryRequest,
        new_key: &Installation,
    ) -> Result<SignedRecoveryConsent, Error> {
        self.check_recovery_parent(request)?;
        if new_key.selected() != request.new {
            return Err(Error::Ineligible);
        }
        Ok(SignedRecoveryConsent(self.sign_recovery(
            request,
            new_key,
            RECOVERY_CONSENT,
        )?))
    }

    pub fn apply_recovery_consent(
        &self,
        request: &mut RecoveryRequest,
        consent: &SignedRecoveryConsent,
    ) -> Result<(), Error> {
        self.check_recovery_parent(request)?;
        self.verify_recovery(request, request.new, RECOVERY_CONSENT, consent.0)?;
        request.consented = true;
        Ok(())
    }

    pub fn recovery_veto(
        &self,
        request: &RecoveryRequest,
        holder: &Installation,
    ) -> Result<SignedRecoveryDecision, Error> {
        self.check_recovery_parent(request)?;
        if holder.selected() != request.old
            || self.membership(request.old).is_none()
            || self.is_barred(&request.old)
        {
            return Err(Error::Ineligible);
        }
        Ok(SignedRecoveryDecision {
            signer: request.old,
            kind: RECOVERY_VETO,
            signature: self.sign_recovery(request, holder, RECOVERY_VETO)?,
        })
    }

    pub fn veto_recovery(
        &self,
        request: &mut RecoveryRequest,
        holder: &Installation,
    ) -> Result<(), Error> {
        let veto = self.recovery_veto(request, holder)?;
        self.apply_recovery_decision(request, &veto)?;
        Ok(())
    }

    /// Apply the verified decision in the fixture's agreed order.
    /// A witness signature attests to its own Encounter.
    pub fn apply_recovery_decision(
        &self,
        request: &mut RecoveryRequest,
        decision: &SignedRecoveryDecision,
    ) -> Result<bool, Error> {
        self.check_recovery_parent(request)?;
        self.verify_recovery(request, decision.signer, decision.kind, decision.signature)?;
        match decision.kind {
            RECOVERY_APPROVAL if self.eligible_recovery_witness(request, decision.signer) => {
                Ok(request.approvals.insert(decision.signer))
            }
            RECOVERY_VETO
                if decision.signer == request.old
                    && self.membership(request.old).is_some()
                    && !self.is_barred(&request.old) =>
            {
                let first = !request.vetoed;
                request.vetoed = true;
                Ok(first)
            }
            _ => Err(Error::Ineligible),
        }
    }

    /// Apply a recovery only after verifying both certificate quorums.
    /// Round selection and honest voter locks are supplied by the agreement fixture.
    pub fn apply_certified_recovery<'c>(
        &mut self,
        request: &RecoveryRequest,
        certificate: impl Into<CertificateRef<'c>>,
    ) -> Result<(), Error> {
        let child = self.recovery_child(request)?;
        let carried = self.verify_certificate(child, certificate.into())?;
        self.replace_key_carrying(self.revision(), request.old, request.new, child, carried)
    }

    pub(crate) fn recover_lost_key(&mut self, request: &RecoveryRequest) -> Result<(), Error> {
        let child = self.recovery_child(request)?;
        self.replace_key(self.revision(), request.old, request.new, child)
    }

    /// Commit to stable membership IDs so authorized key replacement preserves
    /// enrollment without granting a departed witness's replacement tenure access.
    /// Witness order is canonicalized by identity tenure so commitment is order-independent.
    pub(super) fn recovery_commitment(
        &self,
        owner: crate::groups::Identity,
        witnesses: [Key; 2],
        salt: [u8; 32],
    ) -> Result<[u8; 32], Error> {
        let mut hash = Sha256::new()
            .chain_update(b"mesh/group-admission/recovery-enrollment/v1\0")
            .chain_update(self.group.id.to_be_bytes())
            .chain_update(owner.0.to_be_bytes())
            .chain_update(
                self.group
                    .membership(owner)
                    .ok_or(Error::Ineligible)?
                    .joined_at
                    .to_be_bytes(),
            )
            .chain_update(salt);
        let mut canonical_witnesses = witnesses;
        canonical_witnesses
            .sort_unstable_by_key(|w| self.membership(*w).map(|t| (t.identity.0, t.joined_at)));
        for witness in canonical_witnesses {
            let tenure = self.membership(witness).ok_or(Error::Ineligible)?;
            hash.update(tenure.identity.0.to_be_bytes());
            hash.update(tenure.joined_at.to_be_bytes());
        }
        Ok(hash.finalize().into())
    }

    /// Validate recovery authorization and derive the exact child to be voted on.
    pub fn recovery_child(&self, request: &RecoveryRequest) -> Result<[u8; 32], Error> {
        parse_verifying_key(&request.new)?;
        if self.history.id != request.parent.id {
            return Err(Error::StaleProposal);
        }
        let owner = self
            .membership(request.old)
            .ok_or(Error::Ineligible)?
            .identity;
        if self.identities.contains_key(&request.new) || self.retired.contains(&request.new) {
            return Err(Error::AlreadyMember);
        }
        let commitment =
            self.recovery_commitment(owner, request.witnesses, request.enrollment_salt)?;
        if self.recovery_commitments.get(&owner) != Some(&commitment)
            || request.witnesses[0] == request.witnesses[1]
            || request.witnesses.contains(&request.old)
        {
            return Err(Error::Ineligible);
        }
        if request.vetoed {
            return Err(Error::Ineligible);
        }
        if request.approvals.len() != request.witnesses.len() {
            return Err(Error::ApprovalRequired);
        }
        if !request
            .approvals
            .iter()
            .all(|&w| self.eligible_recovery_witness(request, w))
        {
            return Err(Error::Ineligible);
        }
        if !request.consented {
            return Err(Error::AcceptanceRequired);
        }
        // Two witnesses must not be able to silently replace a healthy member's key: unless the
        // key is already suspect, the holder gets a veto window first.
        if !self.is_barred(&request.old)
            && self.now < request.opened_at.saturating_add(RECOVERY_VETO_WINDOW_MS)
        {
            return Err(Error::ApprovalRequired);
        }
        Ok(Sha256::new()
            .chain_update(b"mesh/group-admission/recovery-child/v1\0")
            .chain_update(self.group.id.to_be_bytes())
            .chain_update(request.parent.id)
            .chain_update(request.old)
            .chain_update(request.new)
            .chain_update(request.nonce)
            .finalize()
            .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    #[test]
    fn recovery_commitment_follows_rotation_but_not_a_new_tenure() {
        let keys =
            [11, 12, 13, 14].map(|n| SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes());
        let mut group = VouchedGroup::new(
            1,
            keys[..3].iter().copied(),
            crate::groups::Policy::InviterOnly,
        );
        let owner = group.membership(keys[0]).unwrap().identity;
        let salt = [42; 32];
        let before = group
            .recovery_commitment(owner, [keys[1], keys[2]], salt)
            .unwrap();
        let child = group.derived_child(b"test-rotation", &[&keys[1], &keys[3]]);
        group
            .replace_key(group.revision(), keys[1], keys[3], child)
            .unwrap();
        assert_eq!(
            group
                .recovery_commitment(owner, [keys[3], keys[2]], salt)
                .unwrap(),
            before
        );
        // Reuse exactly the same internal ID in a later tenure: the old opening
        // must still fail, even on a peer that never knew the witness names.
        let tenure = group.membership(keys[3]).unwrap();
        group.group.apply_departure(tenure).unwrap();
        let mut proposal = group.group.invite(owner, tenure.identity).unwrap();
        proposal.accept(tenure.identity).unwrap();
        group.group.admit(&proposal).unwrap();
        assert_ne!(
            group
                .recovery_commitment(owner, [keys[3], keys[2]], salt)
                .unwrap(),
            before
        );
    }

    #[test]
    fn recovery_commitment_rejects_wrong_witnesses_and_opening() {
        let keys =
            [1, 2, 3, 4, 5].map(|n| SigningKey::from_bytes(&[n; 32]).verifying_key().to_bytes());
        let mut group = VouchedGroup::new(
            1,
            keys[..4].iter().copied(),
            crate::groups::Policy::InviterOnly,
        );
        group.enroll_recovery(keys[0], [keys[1], keys[2]]).unwrap();
        let mut request = group.request_recovery(keys[0], keys[4]).unwrap();
        request.consented = true;
        request.approvals = request.witnesses.into_iter().collect();
        group.advance_time(RECOVERY_VETO_WINDOW_MS);
        // Match the state of a peer that received only the opaque enrollment.
        group.recovery_witnesses.clear();
        group.recovery_salts.clear();
        assert!(group.recovery_child(&request).is_ok());
        request.enrollment_salt[0] ^= 1;
        assert_eq!(group.recovery_child(&request), Err(Error::Ineligible));
        request.enrollment_salt[0] ^= 1;
        request.witnesses[1] = keys[3];
        request.approvals = request.witnesses.into_iter().collect();
        assert_eq!(group.recovery_child(&request), Err(Error::Ineligible));
    }

    #[test]
    fn barred_holders_cannot_sign_or_deliver_a_veto_but_healthy_holders_can() {
        use super::super::SignedSuspension;
        use super::super::apply_v1_tests::{cert, v1};
        use super::super::certificate_v1_tests::{group, key, proof_at_head, signing};
        use crate::session::installation::group_suspension_message;
        use ed25519_dalek::Signer;

        // 0: healthy control, 1: agreed report, 2: cryptographic proof.
        for standing in 0..3 {
            let mut g = group();
            g.enroll_recovery(key(16), [key(11), key(12)]).unwrap();
            let signers = [10, 11, 12, 13, 14];
            if standing == 1 {
                let (gid, parent) = g.rotation_context();
                let s = SignedSuspension::new(
                    (gid, parent),
                    key(10),
                    key(16),
                    signing(10)
                        .sign(&group_suspension_message(gid, parent, key(10), key(16)))
                        .to_bytes(),
                );
                let child = g.suspension_child(&s).unwrap();
                g.apply_certified_suspension(&s, &cert(&g, child, &signers))
                    .unwrap();
            } else if standing == 2 {
                let child = g.policy_child(crate::groups::Policy::Majority).unwrap();
                let certificate = v1(&g, child, &signers, vec![proof_at_head(&g, 16)]);
                g.apply_certified_policy_change(crate::groups::Policy::Majority, &certificate)
                    .unwrap();
            }
            let mut request = g.request_recovery(key(16), key(60)).unwrap();
            let holder = Installation::new(signing(16));
            let replacement = Installation::new(signing(60));
            let consent = g.recovery_consent(&request, &replacement).unwrap();
            g.apply_recovery_consent(&mut request, &consent).unwrap();
            for seed in [11, 12] {
                let approval = SignedRecoveryDecision {
                    signer: key(seed),
                    kind: RECOVERY_APPROVAL,
                    signature: signing(seed)
                        .sign(&group_recovery_message(
                            g.group.id,
                            request.parent.id,
                            request.old,
                            request.new,
                            request.nonce,
                            RECOVERY_APPROVAL,
                        ))
                        .to_bytes(),
                };
                g.apply_recovery_decision(&mut request, &approval).unwrap();
            }
            if standing == 0 {
                assert_eq!(g.recovery_child(&request), Err(Error::ApprovalRequired));
                let veto = g.recovery_veto(&request, &holder).unwrap();
                assert_eq!(g.apply_recovery_decision(&mut request, &veto), Ok(true));
                g.advance_time(RECOVERY_VETO_WINDOW_MS);
                assert_eq!(g.recovery_child(&request), Err(Error::Ineligible));
            } else {
                assert!(matches!(
                    g.recovery_veto(&request, &holder),
                    Err(Error::Ineligible)
                ));
                // A hostile holder bypasses the signing helper; reception must also refuse it.
                let veto = SignedRecoveryDecision {
                    signer: key(16),
                    kind: RECOVERY_VETO,
                    signature: signing(16)
                        .sign(&group_recovery_message(
                            g.group.id,
                            request.parent.id,
                            request.old,
                            request.new,
                            request.nonce,
                            RECOVERY_VETO,
                        ))
                        .to_bytes(),
                };
                assert_eq!(
                    g.apply_recovery_decision(&mut request, &veto),
                    Err(Error::Ineligible)
                );
                assert!(!request.vetoed);
                let child = g.recovery_child(&request).unwrap();
                let certificate = cert(&g, child, &signers);
                g.apply_certified_recovery(&request, &certificate).unwrap();
                assert!(g.membership(key(60)).is_some());
                assert!(g.membership(key(16)).is_none());
            }
        }
    }
}
