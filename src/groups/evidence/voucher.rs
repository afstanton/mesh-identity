//! Admission vouchers, audience-scoped disclosure, and withdrawals.

use super::{
    AdmissionError, Error, Installation, Key, MAX_LIFETIME_MS, VouchedGroup, VouchedProposal,
    VoucherId, parse_verifying_key, random_id,
};
use crate::contact::{ContactStatus, VerificationStatus};
use crate::session::installation::{admission_voucher_message, voucher_withdrawal_message};
use ed25519_dalek::Signature;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// An issuer-authorized withdrawal for one voucher in the simulation.
pub struct VoucherWithdrawal {
    group: u64,
    voucher: VoucherId,
    issuer: Key,
    signature: [u8; 64],
}

impl VoucherWithdrawal {
    pub fn to_bytes(&self) -> [u8; 136] {
        let mut bytes = [0; 136];
        bytes[..8].copy_from_slice(&self.group.to_be_bytes());
        bytes[8..40].copy_from_slice(&self.voucher);
        bytes[40..72].copy_from_slice(&self.issuer);
        bytes[72..].copy_from_slice(&self.signature);
        bytes
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 136] = bytes.try_into().map_err(|_| Error::Ineligible)?;
        let group = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        let voucher = bytes[8..40].try_into().unwrap();
        let issuer = bytes[40..72].try_into().unwrap();
        let signature = bytes[72..].try_into().unwrap();
        let key = parse_verifying_key(&issuer)?;
        key.verify_strict(
            &voucher_withdrawal_message(group, voucher),
            &Signature::from_bytes(&signature),
        )
        .map_err(|_| Error::Ineligible)?;
        Ok(Self {
            group,
            voucher,
            issuer,
            signature,
        })
    }
}

/// Outbound routing metadata stays with the sender and off the signed payload.
pub struct WithdrawalDelivery {
    withdrawal: VoucherWithdrawal,
    audience: BTreeSet<Key>,
}

impl WithdrawalDelivery {
    pub fn deliver_to(&self, recipient: Key) -> Option<[u8; 136]> {
        self.audience
            .contains(&recipient)
            .then(|| self.withdrawal.to_bytes())
    }
}

#[derive(Clone)]
pub struct DirectVoucher {
    pub(super) id: VoucherId,
    invitation_binding: [u8; 32],
    expires_at: u64,
    group: u64,
    revision: u64,
    issuer: Key,
    candidate: Key,
    audience: BTreeSet<Key>,
    forwarding_allowed: bool,
}

impl DirectVoucher {
    pub(super) fn admission_body(&self) -> [u8; 152] {
        let mut bytes = [0; 152];
        bytes[..32].copy_from_slice(&self.id);
        bytes[32..64].copy_from_slice(&self.invitation_binding);
        bytes[64..72].copy_from_slice(&self.expires_at.to_be_bytes());
        bytes[72..80].copy_from_slice(&self.group.to_be_bytes());
        bytes[80..88].copy_from_slice(&self.revision.to_be_bytes());
        bytes[88..120].copy_from_slice(&self.issuer);
        bytes[120..152].copy_from_slice(&self.candidate);
        bytes
    }

    /// Sign the admission claim for transfer to the candidate. Private audience
    /// and forwarding permissions are absent from this representation.
    pub fn admission_wire(&self, issuer: &Installation) -> Result<[u8; 216], Error> {
        if issuer.selected() != self.issuer {
            return Err(Error::Ineligible);
        }
        let mut bytes = [0; 216];
        bytes[..152].copy_from_slice(&self.admission_body());
        let binding = Sha256::digest(&bytes[..152]).into();
        bytes[152..].copy_from_slice(
            &issuer
                .sign_admission_voucher(binding)
                .map_err(|e| super::agreement::roster_signing_error(e, Error::Ineligible))?,
        );
        Ok(bytes)
    }

    pub fn from_admission_wire(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 216] = bytes.try_into().map_err(|_| Error::Ineligible)?;
        let issuer = bytes[88..120].try_into().unwrap();
        parse_verifying_key(&issuer)?
            .verify_strict(
                &admission_voucher_message(Sha256::digest(&bytes[..152]).into()),
                &Signature::from_bytes(bytes[152..].try_into().unwrap()),
            )
            .map_err(|_| Error::Ineligible)?;
        let candidate = bytes[120..152].try_into().unwrap();
        parse_verifying_key(&candidate)?;
        Ok(Self {
            id: bytes[..32].try_into().unwrap(),
            invitation_binding: bytes[32..64].try_into().unwrap(),
            expires_at: u64::from_be_bytes(bytes[64..72].try_into().unwrap()),
            group: u64::from_be_bytes(bytes[72..80].try_into().unwrap()),
            revision: u64::from_be_bytes(bytes[80..88].try_into().unwrap()),
            issuer,
            candidate,
            audience: BTreeSet::new(),
            forwarding_allowed: false,
        })
    }

    pub fn invitation_binding(&self) -> [u8; 32] {
        self.invitation_binding
    }

    pub fn issuer(&self) -> Key {
        self.issuer
    }

    pub fn candidate(&self) -> Key {
        self.candidate
    }

    pub fn authorize_withdrawal(&self, issuer: &Installation) -> Result<VoucherWithdrawal, Error> {
        if issuer.selected() != self.issuer {
            return Err(Error::Ineligible);
        }
        Ok(VoucherWithdrawal {
            group: self.group,
            voucher: self.id,
            issuer: self.issuer,
            signature: issuer
                .sign_voucher_withdrawal(self.group, self.id)
                .map_err(|e| super::agreement::roster_signing_error(e, Error::Ineligible))?,
        })
    }

    pub fn authorize_withdrawal_by(
        &self,
        issuer: &Installation,
        group: &VouchedGroup,
    ) -> Result<VoucherWithdrawal, Error> {
        let signer = issuer.selected();
        if !group.is_key_or_successor(signer, self.issuer) || self.group != group.group.id {
            return Err(Error::Ineligible);
        }
        Ok(VoucherWithdrawal {
            group: self.group,
            voucher: self.id,
            issuer: signer,
            signature: issuer
                .sign_voucher_withdrawal(self.group, self.id)
                .map_err(|e| super::agreement::roster_signing_error(e, Error::Ineligible))?,
        })
    }

    /// Route a withdrawal using the issuer's original voucher audience.
    pub fn prepare_withdrawal_delivery(
        &self,
        issuer: &Installation,
    ) -> Result<WithdrawalDelivery, Error> {
        Ok(WithdrawalDelivery {
            withdrawal: self.authorize_withdrawal(issuer)?,
            audience: self.audience.clone(),
        })
    }

    /// Opt in before sharing the voucher. Recipients can then explicitly
    /// report it to other current members of this group.
    pub fn allow_forwarding(mut self, issuer: &Installation) -> Result<Self, Error> {
        if issuer.selected() != self.issuer {
            return Err(Error::Ineligible);
        }
        self.id = random_id();
        self.forwarding_allowed = true;
        Ok(self)
    }
}

/// A recipient-scoped report of a voucher. The original voucher is carried as
/// private simulation evidence and is never exposed as the forwarder's claim.
pub struct ForwardedVoucher {
    forwarders: Vec<Key>,
    recipient: Key,
    source: DirectVoucher,
}

#[derive(PartialEq, Eq)]
pub struct ReportedVoucher {
    pub sender: Key,
    pub forwarders: Vec<Key>,
    pub original_issuer: Key,
    pub candidate: Key,
}

impl std::fmt::Debug for ReportedVoucher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ReportedVoucher").finish_non_exhaustive()
    }
}

/// Local assessment of the immediate sender of a relayed report.
#[derive(Debug, PartialEq, Eq)]
pub enum ReportedReliance {
    SenderUnverified,
    Declined,
    Accepted,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AssessedReport {
    pub report: ReportedVoucher,
    pub reliance: ReportedReliance,
}

/// The viewer's local decision on whether to rely on a known introducer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntroducerReliance {
    Rely,
    Decline,
}

/// A view of evidence delivered specifically to one participating identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verification {
    NoEvidence,
    VoucherExpired,
    VoucherWithdrawn,
    VoucherFromUnverifiedIssuer(Key),
    VoucherFromSuspectIssuer(Key),
    VouchedForByVerifiedIssuer(Key),
    VoucherFromDeclinedIntroducer(Key),
    VerifiedInPerson,
    KeyContinuity { verified_key: Key },
}

pub(crate) fn verified_contact(installation: &Installation, peer: Key) -> bool {
    installation
        .contacts(installation.selected())
        .and_then(|store| store.get(&peer))
        .is_some_and(|record| {
            record.verification_status == VerificationStatus::Verified
                && record.status == ContactStatus::Active
        })
}

/// A committed roster snapshot with audience-filtered evidence delivery.
pub struct AdmissionUpdate {
    pub(super) group: VouchedGroup,
    pub(super) voucher: DirectVoucher,
}

impl AdmissionUpdate {
    pub fn deliver_to(&self, recipient: Key) -> Option<(VouchedGroup, Option<DirectVoucher>)> {
        self.group.membership(recipient)?;
        let voucher = self
            .voucher
            .audience
            .contains(&recipient)
            .then(|| DirectVoucher {
                audience: BTreeSet::from([recipient]),
                ..self.voucher.clone()
            });
        let mut snapshot = self.group.clone();
        snapshot.withdrawn.clear();
        // Recovery arrangements are private to the owner and their witnesses.
        let me = snapshot.identities.get(&recipient).copied();
        snapshot
            .recovery_witnesses
            .retain(|owner, witnesses| Some(*owner) == me || witnesses.contains(&recipient));
        snapshot
            .recovery_salts
            .retain(|owner, _| snapshot.recovery_witnesses.contains_key(owner));
        snapshot
            .degraded_recovery
            .retain(|owner| Some(*owner) == me);
        Some((snapshot, voucher))
    }
}

impl VouchedGroup {
    pub fn verification(
        &self,
        viewer: &Installation,
        candidate: Key,
        voucher: Option<&DirectVoucher>,
        reliance: IntroducerReliance,
    ) -> Verification {
        if verified_contact(viewer, candidate) {
            return Verification::VerifiedInPerson;
        }
        let mut key = candidate;
        while let Some(&previous) = self.predecessors.get(&key) {
            if self.is_barred(&previous) {
                break;
            }
            if verified_contact(viewer, previous) {
                return Verification::KeyContinuity {
                    verified_key: previous,
                };
            }
            key = previous;
        }
        let Some(voucher) = voucher.filter(|voucher| {
            voucher.group == self.group.id
                && voucher.revision < self.group.revision
                && voucher.candidate == candidate
                && self
                    .admission_evidence
                    .get(&candidate)
                    .is_some_and(|id| *id == voucher.id)
                && self.membership(candidate).is_some()
                && voucher.audience.contains(&viewer.selected())
        }) else {
            return Verification::NoEvidence;
        };
        match self.check_voucher_lifetime(voucher) {
            Err(AdmissionError::VoucherWithdrawn) => return Verification::VoucherWithdrawn,
            Err(AdmissionError::VoucherExpired) => return Verification::VoucherExpired,
            Err(AdmissionError::IssuerKeySuspect) => {
                return Verification::VoucherFromSuspectIssuer(voucher.issuer);
            }
            _ => {}
        }
        if !verified_contact(viewer, voucher.issuer) {
            return Verification::VoucherFromUnverifiedIssuer(voucher.issuer);
        }

        match reliance {
            IntroducerReliance::Rely => Verification::VouchedForByVerifiedIssuer(voucher.issuer),
            IntroducerReliance::Decline => {
                Verification::VoucherFromDeclinedIntroducer(voucher.issuer)
            }
        }
    }

    /// Explicitly share a received voucher with another current member.
    pub fn forward_voucher(
        &self,
        sender: &Installation,
        recipient: Key,
        voucher: &DirectVoucher,
    ) -> Result<ForwardedVoucher, AdmissionError> {
        let sender = sender.selected();
        if !voucher.forwarding_allowed
            || self.membership(sender).is_none()
            || self.membership(recipient).is_none()
            || !voucher.audience.contains(&sender)
            || !self.is_committed_voucher(voucher)
        {
            return Err(Error::Ineligible.into());
        }
        self.check_voucher_lifetime(voucher)?;
        if sender == recipient {
            return Err(Error::Ineligible.into());
        }
        Ok(ForwardedVoucher {
            forwarders: vec![sender],
            recipient,
            source: voucher.clone(),
        })
    }

    /// Relay a report as its selected recipient, keeping all prior attribution.
    pub fn relay_voucher(
        &self,
        sender: &Installation,
        recipient: Key,
        report: &ForwardedVoucher,
    ) -> Result<ForwardedVoucher, AdmissionError> {
        self.validate_forwarded_recipient(sender, report)?;
        if self.membership(recipient).is_none()
            || recipient == report.recipient
            || report.forwarders.contains(&recipient)
        {
            return Err(Error::Ineligible.into());
        }
        let mut forwarders = report.forwarders.clone();
        forwarders.push(report.recipient);
        Ok(ForwardedVoucher {
            forwarders,
            recipient,
            source: report.source.clone(),
        })
    }

    fn validate_forwarded_recipient(
        &self,
        recipient: &Installation,
        report: &ForwardedVoucher,
    ) -> Result<(), AdmissionError> {
        if recipient.selected() != report.recipient
            || self.membership(report.recipient).is_none()
            || !self.is_committed_voucher(&report.source)
        {
            return Err(Error::Ineligible.into());
        }
        self.check_voucher_lifetime(&report.source)
    }

    /// Pass an issuer-signed withdrawal along one previously delivered report.
    pub fn relay_withdrawal(
        &self,
        sender: &Installation,
        report: &ForwardedVoucher,
        withdrawal: VoucherWithdrawal,
    ) -> Result<WithdrawalDelivery, Error> {
        if report.forwarders.last() != Some(&sender.selected())
            || withdrawal.group != self.group.id
            || withdrawal.group != report.source.group
            || !self.is_key_or_successor(withdrawal.issuer, report.source.issuer)
            || withdrawal.voucher != report.source.id
        {
            return Err(Error::Ineligible);
        }
        Ok(WithdrawalDelivery {
            withdrawal,
            audience: BTreeSet::from([report.recipient]),
        })
    }

    pub fn read_forwarded_voucher(
        &self,
        recipient: &Installation,
        report: &ForwardedVoucher,
    ) -> Result<ReportedVoucher, AdmissionError> {
        self.validate_forwarded_recipient(recipient, report)?;
        Ok(ReportedVoucher {
            sender: *report.forwarders.last().expect("a report has a forwarder"),
            forwarders: report.forwarders.clone(),
            original_issuer: report.source.issuer,
            candidate: report.source.candidate,
        })
    }

    /// Decide whether to rely on the immediate sender as a reporter.
    /// Earlier hops remain visible without inheriting that reliance.
    pub fn assess_forwarded_voucher(
        &self,
        recipient: &Installation,
        report: &ForwardedVoucher,
        reliance: IntroducerReliance,
    ) -> Result<AssessedReport, AdmissionError> {
        let report = self.read_forwarded_voucher(recipient, report)?;
        let reliance = match reliance {
            IntroducerReliance::Decline => ReportedReliance::Declined,
            IntroducerReliance::Rely if verified_contact(recipient, report.sender) => {
                ReportedReliance::Accepted
            }
            IntroducerReliance::Rely => ReportedReliance::SenderUnverified,
        };
        Ok(AssessedReport { report, reliance })
    }

    fn is_committed_voucher(&self, voucher: &DirectVoucher) -> bool {
        voucher.group == self.group.id
            && self
                .admission_evidence
                .get(&voucher.candidate)
                .is_some_and(|id| *id == voucher.id)
            && self.membership(voucher.candidate).is_some()
    }

    /// Apply an authenticated withdrawal in the experiment's agreed order.
    pub(crate) fn withdraw(&mut self, issuer: Key, voucher: &DirectVoucher) -> Result<(), Error> {
        if !self.is_key_or_successor(issuer, voucher.issuer) || voucher.group != self.group.id {
            return Err(Error::Ineligible);
        }
        self.check_withdrawal_signer(issuer)?;
        self.withdrawn.insert((issuer, voucher.id));
        Ok(())
    }

    /// Apply a typed withdrawal even if its voucher has not arrived yet.
    pub fn apply_withdrawal(&mut self, withdrawal: &VoucherWithdrawal) -> Result<(), Error> {
        if withdrawal.group != self.group.id {
            return Err(Error::Ineligible);
        }
        self.check_withdrawal_signer(withdrawal.issuer)?;
        self.withdrawn
            .insert((withdrawal.issuer, withdrawal.voucher));
        Ok(())
    }

    /// Only keys this roster knows (current or retired members) may record a withdrawal, so a
    /// stranger cannot grow the withdrawn set with validly signed junk.
    fn check_withdrawal_signer(&self, issuer: Key) -> Result<(), Error> {
        if self.identities.contains_key(&issuer) || self.retired.contains(&issuer) {
            Ok(())
        } else {
            Err(Error::Ineligible)
        }
    }

    fn check_voucher_lifetime(&self, voucher: &DirectVoucher) -> Result<(), AdmissionError> {
        if self.is_barred(&voucher.issuer) {
            return Err(AdmissionError::IssuerKeySuspect);
        }
        let is_withdrawn = self.withdrawn.iter().any(|&(withdrawer, id)| {
            id == voucher.id && self.is_key_or_successor(withdrawer, voucher.issuer)
        });
        if is_withdrawn {
            return Err(AdmissionError::VoucherWithdrawn);
        }
        if self.now >= voucher.expires_at {
            return Err(AdmissionError::VoucherExpired);
        }
        if voucher.expires_at - self.now > MAX_LIFETIME_MS {
            return Err(AdmissionError::InvalidExpiry);
        }
        Ok(())
    }

    /// Show the exact evidence disclosure to its issuer before sending.
    pub fn disclosure_audience<'a>(
        &self,
        issuer: &Installation,
        proposal: &VouchedProposal,
        voucher: &'a DirectVoucher,
    ) -> Result<impl Iterator<Item = Key> + 'a, AdmissionError> {
        self.check_invitation(proposal)?;
        if issuer.selected() != voucher.issuer
            || voucher.invitation_binding != proposal.decision_binding()
        {
            return Err(Error::Ineligible.into());
        }
        self.check_voucher_lifetime(voucher)?;
        Ok(voucher.audience.iter().copied())
    }

    pub fn vouch(
        &mut self,
        proposal: &VouchedProposal,
        issuer: &Installation,
        audience: impl IntoIterator<Item = Key>,
        expires_at: u64,
    ) -> Result<DirectVoucher, AdmissionError> {
        self.check_invitation(proposal)?;
        if issuer.selected() != proposal.inviter()
            || !verified_contact(issuer, proposal.candidate())
        {
            return Err(AdmissionError::VoucherRequired);
        }
        let audience: BTreeSet<_> = audience.into_iter().collect();
        if audience.iter().any(|&key| self.membership(key).is_none()) {
            return Err(Error::Ineligible.into());
        }
        if expires_at <= self.now || expires_at - self.now > MAX_LIFETIME_MS {
            return Err(AdmissionError::InvalidExpiry);
        }
        Ok(DirectVoucher {
            id: random_id(),
            invitation_binding: proposal.decision_binding(),
            expires_at,
            group: self.group.id,
            revision: self.group.revision,
            issuer: proposal.inviter(),
            candidate: proposal.candidate(),
            audience,
            forwarding_allowed: false,
        })
    }

    pub(super) fn check_admission_evidence(
        &self,
        proposal: &VouchedProposal,
        voucher: &DirectVoucher,
    ) -> Result<(), AdmissionError> {
        if voucher.invitation_binding != proposal.decision_binding()
            || voucher.group != self.group.id
            || voucher.revision != self.group.revision
            || voucher.issuer != proposal.inviter()
            || voucher.candidate != proposal.candidate()
        {
            return Err(AdmissionError::VoucherRequired);
        }
        self.check_voucher_lifetime(voucher)
    }
}
