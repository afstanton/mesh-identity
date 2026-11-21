//! Public replay proofs for joining. Local saved-state snapshots are never network authority.
use super::*;
use crate::groups::evidence::{InvitationFacts, VersionedCertificate, VouchedProposal};

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct History {
    genesis: Vec<u8>,
    steps: Vec<Admission>,
}

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Admission {
    pub nonce: [u8; 32],
    pub invitation: Vec<u8>,
    pub voucher: Vec<u8>,
    pub consent: Vec<u8>,
    pub certificate: Vec<u8>,
}

pub(super) fn parent_digest(group: &VouchedGroup) -> Result<[u8; 32], Reason> {
    Ok(Sha256::digest(group.public_bytes().map_err(|_| Reason::Invalid)?).into())
}

pub(super) fn check_parent(
    facts: &InvitationFacts,
    nonce: [u8; 32],
    group: &VouchedGroup,
) -> Result<(), Reason> {
    if facts.group != group.id()
        || facts.parent != group.rotation_context().1
        || facts.id != VouchedProposal::parent_binding(nonce, parent_digest(group)?)
    {
        return Err(Reason::Invalid);
    }
    Ok(())
}

impl History {
    pub fn new(genesis: Vec<u8>) -> Self {
        Self {
            genesis,
            steps: Vec::new(),
        }
    }

    /// The founding roster, sorted. A formed group's binding is recomputed from it.
    pub fn founders(&self) -> Result<Vec<Key>, Reason> {
        let group = VouchedGroup::from_authenticated_genesis(&self.genesis, self.genesis_digest())
            .map_err(|_| Reason::Invalid)?;
        let mut keys: Vec<Key> = group
            .current_members()
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        keys.sort();
        Ok(keys)
    }

    pub fn genesis_digest(&self) -> [u8; 32] {
        Sha256::digest(&self.genesis).into()
    }

    pub fn has_genesis(&self, genesis: &[u8]) -> bool {
        self.genesis == genesis
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Reason> {
        if bytes.len() > MAX_FRAME_BYTES {
            return Err(Reason::TooLarge);
        }
        let mut input = bytes;
        let history: Self = ciborium::from_reader(&mut input).map_err(|_| Reason::Malformed)?;
        if !input.is_empty() {
            return Err(Reason::Malformed);
        }
        Ok(history)
    }

    pub fn replay(&self) -> Result<VouchedGroup, Reason> {
        // The initial roster is introduced by the verified inviter (or independently
        // authenticated through import_genesis). The invitation commits to this exact
        // history's resulting state before the candidate consents.
        let mut group = VouchedGroup::from_authenticated_genesis(
            &self.genesis,
            Sha256::digest(&self.genesis).into(),
        )
        .map_err(|_| Reason::Invalid)?;
        for admission in &self.steps {
            admission.apply(&mut group)?;
        }
        Ok(group)
    }

    pub fn append(&mut self, admission: Admission) {
        self.steps.push(admission);
    }

    pub fn has_admission(&self, binding: [u8; 32]) -> bool {
        self.steps.iter().any(|step| {
            SignedInvitation::inspect_frame(&step.invitation)
                .map(|f| f.binding == binding)
                .unwrap_or(false)
        })
    }
}

impl Admission {
    pub fn apply(&self, group: &mut VouchedGroup) -> Result<(), Reason> {
        let facts =
            SignedInvitation::inspect_frame(&self.invitation).map_err(|_| Reason::Invalid)?;
        check_parent(&facts, self.nonce, group)?;
        // Historical certificates are replayed at a valid time in their invitation window.
        group.set_replay_time(facts.deadline.saturating_sub(MAX_LIFETIME_MS));
        let mut proposal = group
            .receive_invitation_frame(&self.invitation)
            .map_err(|_| Reason::Invalid)?;
        let consent =
            SignedAdmissionConsent::from_bytes(&self.consent).map_err(|_| Reason::Invalid)?;
        group
            .apply_admission_consent(&mut proposal, &consent)
            .map_err(|_| Reason::Invalid)?;
        let voucher =
            DirectVoucher::from_admission_wire(&self.voucher).map_err(|_| Reason::Invalid)?;
        let certificate =
            VersionedCertificate::from_bytes(&self.certificate).map_err(|_| Reason::Invalid)?;
        group
            .apply_certified_admission(&proposal, voucher, &certificate)
            .map_err(|_| Reason::Invalid)?;
        Ok(())
    }
}
