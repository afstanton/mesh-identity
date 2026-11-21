//! Step 5, G2: explicit, unanimous, opt-in formation of a new group.
//!
//! A formation is a proposal plus a final roster. Each member of the final roster signs the exact
//! pair; the group exists once every one of them has. Changing the roster, rules, disclosure,
//! context or any source head gives a different binding, so no earlier consent carries over. The
//! new group's id and history id come from the binding, so every participant builds the same group
//! and a replay cannot make a second one. No source group is read or changed here.

use super::{Key, MAX_MEMBERS, Proposal, SourceView};
use crate::groups::Policy;
use crate::groups::evidence::VouchedGroup;
use crate::session::installation::{Installation, group_formation_consent_message};
use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormationError {
    /// The final roster is empty or over the 192-member genesis cap.
    BadRoster,
    /// A final-roster key is not a candidate of the proposal.
    NotCandidate,
    /// The consent is from a key outside the final roster.
    NotInRoster,
    /// The signature does not verify for this exact formation and signer.
    BadSignature,
    /// Not every final-roster key has signed.
    Incomplete,
    /// None of the participant's local sources is named, exactly, by the proposal.
    StaleSource,
    /// This identity cannot sign now (not in the roster, or signing is gated).
    Cannot,
    Malformed,
}

/// One participant's signature over one exact formation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormationConsent {
    pub signer: Key,
    pub signature: [u8; 64],
}

impl FormationConsent {
    pub const LEN: usize = 96;

    pub fn to_bytes(&self) -> [u8; 96] {
        let mut out = [0; 96];
        out[..32].copy_from_slice(&self.signer);
        out[32..].copy_from_slice(&self.signature);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FormationError> {
        let bytes: &[u8; 96] = bytes.try_into().map_err(|_| FormationError::Malformed)?;
        Ok(Self {
            signer: bytes[..32].try_into().unwrap(),
            signature: bytes[32..].try_into().unwrap(),
        })
    }
}

/// The new group, built identically by every participant.
pub struct FormedGroup {
    pub group: VouchedGroup,
    /// SHA-256 of the genesis bytes: what a participant can pin out of band.
    pub genesis_digest: [u8; 32],
}

pub struct Formation {
    proposal: Proposal,
    roster: Vec<Key>,
    binding: [u8; 32],
    pub(super) consents: BTreeMap<Key, FormationConsent>,
}

fn roster_digest(roster: &[Key]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"MSF1 roster");
    hash.update((roster.len() as u32).to_be_bytes());
    for key in roster {
        hash.update(key);
    }
    hash.finalize().into()
}

/// The signed value for one proposal and final roster (sorted, deduplicated).
pub(crate) fn binding_for(proposal_digest: [u8; 32], roster: &[Key]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"MSF1 binding");
    hash.update(proposal_digest);
    hash.update(roster_digest(roster));
    hash.finalize().into()
}

pub(crate) fn group_id_for(binding: [u8; 32]) -> u64 {
    let mut hash = Sha256::new();
    hash.update(b"MSF1 group id");
    hash.update(binding);
    u64::from_be_bytes(hash.finalize()[..8].try_into().unwrap())
}

pub(crate) fn history_id_for(binding: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"MSF1 history");
    hash.update(binding);
    hash.finalize().into()
}

fn group_for(binding: [u8; 32], roster: &[Key], rules: Policy) -> VouchedGroup {
    VouchedGroup::new_with_history(
        group_id_for(binding),
        roster.iter().copied(),
        rules,
        history_id_for(binding),
    )
}

/// Reconstruct the complete genesis committed by a saved proposal and founding roster.
pub(crate) fn agreed_genesis(proposal: &[u8], roster: &[Key]) -> Option<Vec<u8>> {
    let rules = Proposal::stored_rules(proposal)?;
    if let Policy::Fixed(count) = rules {
        if count.get() > roster.len() {
            return None;
        }
    }
    let binding = binding_for(Sha256::digest(proposal).into(), roster);
    group_for(binding, roster, rules).genesis_bytes().ok()
}

impl Formation {
    /// Open a formation for `final_roster`, a subset of the proposal's candidates. The caller
    /// proposes the subset; nobody is in it until they sign.
    pub fn new(proposal: Proposal, final_roster: &[Key]) -> Result<Self, FormationError> {
        let roster: BTreeSet<Key> = final_roster.iter().copied().collect();
        if roster.is_empty() || roster.len() > MAX_MEMBERS {
            return Err(FormationError::BadRoster);
        }
        if !roster
            .iter()
            .all(|k| proposal.candidates.binary_search(k).is_ok())
        {
            return Err(FormationError::NotCandidate);
        }
        let roster: Vec<Key> = roster.into_iter().collect();
        // Rules that could never make progress for this roster are refused up front.
        if let Policy::Fixed(count) = proposal.terms.rules {
            if count.get() > roster.len() {
                return Err(FormationError::BadRoster);
            }
        }
        Ok(Self {
            binding: binding_for(proposal.digest(), &roster),
            proposal,
            roster,
            consents: BTreeMap::new(),
        })
    }

    /// The value every participant signs (with their own key mixed in by the signing message).
    pub fn binding(&self) -> [u8; 32] {
        self.binding
    }

    pub fn proposal(&self) -> &Proposal {
        &self.proposal
    }

    pub fn roster(&self) -> &[Key] {
        &self.roster
    }

    /// The new group's id, from the binding alone.
    pub fn group_id(&self) -> u64 {
        group_id_for(self.binding)
    }

    /// Consent as the installation's selected identity. `local` are the source views the
    /// participant holds now; at least one must be exactly a source of the proposal, and none may
    /// be a source whose head the proposal does not name (a moved or different group is stale).
    pub fn consent_from(
        &self,
        installation: &Installation,
        local: &[SourceView],
    ) -> Result<FormationConsent, FormationError> {
        let signer = installation.selected();
        if self.roster.binary_search(&signer).is_err() {
            return Err(FormationError::Cannot);
        }
        let named = local
            .iter()
            .filter(|v| self.proposal.names_source(v))
            .count();
        let known_group = |view: &SourceView| {
            self.proposal.sources.iter().any(|s| match s {
                super::SourceRef::Full { group, .. } => *group == view.group,
                super::SourceRef::Hidden(_) => false,
            })
        };
        if named == 0
            || local
                .iter()
                .any(|v| known_group(v) && !self.proposal.names_source(v))
        {
            return Err(FormationError::StaleSource);
        }
        let signature = installation
            .sign_group_formation_consent(self.binding)
            .map_err(|_| FormationError::Cannot)?;
        Ok(FormationConsent { signer, signature })
    }

    /// Record a verified consent. Returns whether it was new; a repeat changes nothing.
    pub fn add_consent(&mut self, consent: FormationConsent) -> Result<bool, FormationError> {
        if self.roster.binary_search(&consent.signer).is_err() {
            return Err(FormationError::NotInRoster);
        }
        let key =
            VerifyingKey::from_bytes(&consent.signer).map_err(|_| FormationError::BadSignature)?;
        key.verify_strict(
            &group_formation_consent_message(self.binding, consent.signer),
            &Signature::from_bytes(&consent.signature),
        )
        .map_err(|_| FormationError::BadSignature)?;
        Ok(self.consents.insert(consent.signer, consent).is_none())
    }

    pub fn missing(&self) -> Vec<Key> {
        self.roster
            .iter()
            .filter(|k| !self.consents.contains_key(*k))
            .copied()
            .collect()
    }

    pub fn is_complete(&self) -> bool {
        self.missing().is_empty()
    }

    /// Build the new group once everyone has signed. The same formation always yields the same
    /// group bytes and genesis digest.
    pub fn complete(&self) -> Result<FormedGroup, FormationError> {
        if !self.is_complete() {
            return Err(FormationError::Incomplete);
        }
        let group = group_for(self.binding, &self.roster, self.proposal.terms.rules);
        let genesis = group
            .genesis_bytes()
            .map_err(|_| FormationError::BadRoster)?;
        Ok(FormedGroup {
            group,
            genesis_digest: Sha256::digest(genesis).into(),
        })
    }
}
