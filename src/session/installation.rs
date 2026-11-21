//! Multiple signing identities sharing one installation-wide Encounter policy.

use super::{Comparison, EncounterController, SessionError};
use crate::contact::{
    AttemptPolicyState, ContactExportV1, ContactRecordV1, ContactStore, StoreError,
};
use ed25519_dalek::SigningKey;
use rand::{CryptoRng, RngCore};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Weak};

mod handoff;
mod roster_locks;
mod snapshot;
pub use handoff::{
    HandoffBundle, HandoffCheckpoint, TakeoverStatement, VotingRecord, VotingState,
    handoff_statement_message,
};
use roster_locks::{RosterLockTable, RosterParentLocks};
pub use snapshot::SnapshotError;

pub fn voucher_withdrawal_message(group: u64, voucher: [u8; 32]) -> Vec<u8> {
    let mut message = b"mesh/group-admission/voucher-withdrawal/v1\0".to_vec();
    message.extend_from_slice(&group.to_be_bytes());
    message.extend_from_slice(&voucher);
    message
}

/// What a participant signs to join a formed group: the exact proposal and final roster
/// (`binding`) and their own key, so the signature verifies for no other formation or signer.
pub fn group_formation_consent_message(binding: [u8; 32], signer: Identity) -> Vec<u8> {
    let mut message = b"mesh/group-admission/formation-consent/v1\0".to_vec();
    message.extend_from_slice(&binding);
    message.extend_from_slice(&signer);
    message
}

pub fn admission_voucher_message(binding: [u8; 32]) -> Vec<u8> {
    let mut message = b"mesh/group-admission/admission-voucher/v1\0".to_vec();
    message.extend_from_slice(&binding);
    message
}

pub fn group_rotation_message(
    group: u64,
    parent: [u8; 32],
    old: Identity,
    new: Identity,
) -> Vec<u8> {
    let mut message = b"mesh/group-admission/key-rotation/v1\0".to_vec();
    message.extend_from_slice(&group.to_be_bytes());
    message.extend_from_slice(&parent);
    message.extend_from_slice(&old);
    message.extend_from_slice(&new);
    message
}

/// What a member signs to enroll a recovery commitment. The witnesses and salt behind the
/// commitment are not part of it: they stay with the owner and the witnesses.
pub fn group_recovery_enrollment_message(
    group: u64,
    parent: [u8; 32],
    owner: Identity,
    commitment: [u8; 32],
) -> Vec<u8> {
    let mut message = b"mesh/group-admission/recovery-enrollment-statement/v1\0".to_vec();
    message.extend_from_slice(&group.to_be_bytes());
    message.extend_from_slice(&parent);
    message.extend_from_slice(&owner);
    message.extend_from_slice(&commitment);
    message
}

/// What a member signs to propose suspending another key. The proposal binds the exact parent
/// and the proposer, so a report is attributable; it carries no authority by itself.
pub fn group_suspension_message(
    group: u64,
    parent: [u8; 32],
    proposer: Identity,
    target: Identity,
) -> Vec<u8> {
    let mut message = b"mesh/group-admission/suspension/v1\0".to_vec();
    message.extend_from_slice(&group.to_be_bytes());
    message.extend_from_slice(&parent);
    message.extend_from_slice(&proposer);
    message.extend_from_slice(&target);
    message
}

pub fn group_departure_message(group: u64, joined_state: [u8; 32], member: Identity) -> Vec<u8> {
    let mut message = b"mesh/group-admission/departure/v1\0".to_vec();
    message.extend_from_slice(&group.to_be_bytes());
    message.extend_from_slice(&joined_state);
    message.extend_from_slice(&member);
    message
}

pub fn group_admission_vote_message(
    group: u64,
    parent: [u8; 32],
    invitation: [u8; 32],
    decision: u8,
) -> Vec<u8> {
    let mut message = b"mesh/group-admission/vote/v1\0".to_vec();
    message.extend_from_slice(&group.to_be_bytes());
    message.extend_from_slice(&parent);
    message.extend_from_slice(&invitation);
    message.push(decision);
    message
}

pub fn group_admission_consent_message(
    group: u64,
    parent: [u8; 32],
    invitation: [u8; 32],
    inviter: Identity,
    candidate: Identity,
) -> Vec<u8> {
    let mut message = b"mesh/group-admission/accept/v1\0".to_vec();
    message.extend_from_slice(&group.to_be_bytes());
    message.extend_from_slice(&parent);
    message.extend_from_slice(&invitation);
    message.extend_from_slice(&inviter);
    message.extend_from_slice(&candidate);
    message
}

pub fn group_recovery_message(
    group: u64,
    parent: [u8; 32],
    old: Identity,
    new: Identity,
    request: [u8; 32],
    decision: u8,
) -> Vec<u8> {
    let mut message = b"mesh/group-admission/recovery/v1\0".to_vec();
    message.extend_from_slice(&group.to_be_bytes());
    message.extend_from_slice(&parent);
    message.extend_from_slice(&old);
    message.extend_from_slice(&new);
    message.extend_from_slice(&request);
    message.push(decision);
    message
}

pub fn group_invitation_message(binding: [u8; 32]) -> Vec<u8> {
    let mut message = b"mesh/group-admission/invite/v1\0".to_vec();
    message.extend_from_slice(&binding);
    message
}

pub fn group_invitation_cancellation_message(binding: [u8; 32]) -> Vec<u8> {
    let mut message = b"mesh/group-admission/cancel-invite/v1\0".to_vec();
    message.extend_from_slice(&binding);
    message
}

pub fn group_ejection_message(binding: [u8; 32]) -> Vec<u8> {
    let mut message = b"mesh/group-admission/eject/v1\0".to_vec();
    message.extend_from_slice(&binding);
    message
}

pub fn group_roster_vote_message(
    group: u64,
    parent: [u8; 32],
    child: [u8; 32],
    round: u32,
    phase: u8,
) -> Vec<u8> {
    let mut message = b"mesh/group-admission/roster-vote/v1\0".to_vec();
    message.extend_from_slice(&group.to_be_bytes());
    message.extend_from_slice(&parent);
    message.extend_from_slice(&child);
    message.extend_from_slice(&round.to_be_bytes());
    message.push(phase);
    message
}

pub fn group_roster_freshness_message(
    group: u64,
    head: [u8; 32],
    revision: u64,
    nonce: [u8; 32],
) -> Vec<u8> {
    let mut message = b"mesh/group-admission/roster-freshness/v1\0".to_vec();
    message.extend_from_slice(&group.to_be_bytes());
    message.extend_from_slice(&head);
    message.extend_from_slice(&revision.to_be_bytes());
    message.extend_from_slice(&nonce);
    message
}

pub const DEFAULT_MAX_IDENTITIES: usize = 16;
pub const MAX_IDENTITIES_CEILING: usize = 2048;
pub const MAX_INSTALLATION_CONTACTS: usize = 100_000;

pub type Identity = [u8; 32];

/// A callback registered for one ceremony on one installation. Deliberately not `Clone`:
/// one handle exists per ceremony, so a stale duplicate cannot act on a later one.
#[derive(Debug)]
pub struct Ceremony(Arc<()>);

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    UnknownIdentity,
    DuplicateIdentity,
    KeyPairMismatch,
    SelectedIdentity,
    CeremonyActive,
    StaleCeremony,
    InvalidContactLink,
    /// A roster signature that would contradict a prior vote or a retired parent.
    ConflictingRosterVote,
    /// Roster lock table has reached MAX_ROSTER_LOCKS capacity.
    RosterLockCapacityExceeded,
    RosterSigningStateUnconfirmed,
    InvalidRosterCheckpoint,
    RosterCheckpointWriteFailed,
    InvalidRosterPhase,
    /// Only a gated device can begin a takeover.
    NotGated,
    /// Number of identities exceeds configured budget or MAX_IDENTITIES_CEILING.
    IdentityLimitExceeded,
    /// Configuration parameter invalid (e.g. setting max_identities below current count or above ceiling).
    InvalidConfiguration,
    /// This device does not hold the voting role for the identity (stopped or gated).
    NotVotingDevice,
    /// A handoff bundle failed authentication or structural checks. Nothing changed.
    InvalidHandoff,
    /// The bundle's counter is not higher than this identity's current one.
    StaleHandoff,
    /// The bundle names a different device nonce.
    WrongHandoffRecipient,
    HandoffWriteFailed,
    /// The identity's counter is at its maximum; recover to a new key.
    CounterExhausted,
    Session(SessionError),
}

impl From<SessionError> for Error {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownIdentity => write!(f, "unknown identity"),
            Self::DuplicateIdentity => write!(f, "duplicate identity"),
            Self::KeyPairMismatch => write!(f, "key pair mismatch"),
            Self::SelectedIdentity => write!(f, "cannot operate on selected identity"),
            Self::CeremonyActive => write!(f, "ceremony already active"),
            Self::StaleCeremony => write!(f, "stale ceremony handle"),
            Self::InvalidContactLink => write!(f, "invalid contact link"),
            Self::ConflictingRosterVote => write!(f, "conflicting roster vote"),
            Self::RosterLockCapacityExceeded => write!(f, "roster lock capacity exceeded"),
            Self::RosterSigningStateUnconfirmed => write!(f, "roster signing state unconfirmed"),
            Self::InvalidRosterCheckpoint => write!(f, "invalid roster checkpoint"),
            Self::RosterCheckpointWriteFailed => write!(f, "roster checkpoint write failed"),
            Self::InvalidRosterPhase => write!(f, "invalid roster phase"),
            Self::NotGated => write!(f, "device is not gated"),
            Self::IdentityLimitExceeded => write!(f, "identity limit exceeded"),
            Self::InvalidConfiguration => write!(f, "invalid configuration parameter"),
            Self::NotVotingDevice => write!(f, "not a voting device"),
            Self::InvalidHandoff => write!(f, "invalid handoff bundle"),
            Self::StaleHandoff => write!(f, "stale handoff bundle"),
            Self::WrongHandoffRecipient => write!(f, "wrong handoff recipient"),
            Self::HandoffWriteFailed => write!(f, "handoff write failed"),
            Self::CounterExhausted => write!(f, "takeover counter exhausted"),
            Self::Session(e) => write!(f, "session error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Session(e) => Some(e),
            _ => None,
        }
    }
}

struct Persona {
    key: SigningKey,
    contacts: ContactStore,
}

/// Local-only collection of contacts recognized as belonging to one person.
pub struct LinkedPersonContacts {
    local: Identity,
    peers: BTreeSet<Identity>,
}

impl LinkedPersonContacts {
    pub fn local_identity(&self) -> Identity {
        self.local
    }

    pub fn peers(&self) -> impl Iterator<Item = Identity> + '_ {
        self.peers.iter().copied()
    }

    /// Dissolve this view and return its constituent contact keys.
    pub fn split(self) -> BTreeSet<Identity> {
        self.peers
    }
}

/// Local application state. Signing keys remain in the caller's key storage.
pub struct InstallationSnapshot {
    selected: Identity,
    contacts: BTreeMap<Identity, ContactStore>,
    policy: AttemptPolicyState,
    #[cfg(feature = "openpgp")]
    pub openpgp_revocations: crate::openpgp::PeerRevocations,
    #[cfg(not(feature = "openpgp"))]
    pub(crate) openpgp_revocations: Option<cbor2::Value>,
    roster_locks: RosterLockTable,
    roster_signing_disabled: bool,
    /// Identities restored without independently current locks.
    roster_unconfirmed: BTreeSet<Identity>,
    handoff_sequence: u64,
    voting: BTreeMap<Identity, VotingRecord>,
    historical_voting: BTreeMap<Identity, VotingRecord>,
    device_nonce: Option<[u8; 32]>,
}

pub struct Installation {
    current: EncounterController,
    inactive: BTreeMap<Identity, Persona>,
    /// Active ceremony weak token and the time it was registered (for idle-scanner expiry).
    ceremony: Option<(Weak<()>, u64)>,
    pending_link: Option<(LinkRequest, u64)>,
    #[cfg(feature = "openpgp")]
    pub(crate) openpgp_preview: Option<crate::openpgp::PendingExport>,
    #[cfg(feature = "openpgp")]
    pub(crate) openpgp_revocations: crate::openpgp::PeerRevocations,
    #[cfg(not(feature = "openpgp"))]
    pub(crate) openpgp_revocations: Option<cbor2::Value>,
    roster_locks: std::sync::Mutex<RosterLockTable>,
    roster_signing_disabled: bool,
    /// Identities restored without independently current locks.
    roster_unconfirmed: BTreeSet<Identity>,
    handoff_sequence: u64,
    voting: BTreeMap<Identity, VotingRecord>,
    historical_voting: BTreeMap<Identity, VotingRecord>,
    device_nonce: Option<[u8; 32]>,
    max_identities: usize,
    /// Groups whose chain recognizes this device's takeover counter, set by the group layer
    /// each time it checks the chain and never persisted.
    group_permits: std::sync::Mutex<BTreeSet<handoff::GroupPermit>>,
}

impl Installation {
    pub fn sign_admission_voucher(&self, binding: [u8; 32]) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;
        self.require_voting()?;
        Ok(self
            .current
            .key
            .sign(&admission_voucher_message(binding))
            .to_bytes())
    }

    pub fn new(key: SigningKey) -> Self {
        Self {
            current: EncounterController::new(key),
            inactive: BTreeMap::new(),
            ceremony: None,
            pending_link: None,
            #[cfg(feature = "openpgp")]
            openpgp_preview: None,
            #[cfg(feature = "openpgp")]
            openpgp_revocations: Default::default(),
            #[cfg(not(feature = "openpgp"))]
            openpgp_revocations: None,
            roster_locks: Default::default(),
            roster_signing_disabled: false,
            roster_unconfirmed: BTreeSet::new(),
            handoff_sequence: 0,
            voting: BTreeMap::new(),
            historical_voting: BTreeMap::new(),
            device_nonce: None,
            max_identities: DEFAULT_MAX_IDENTITIES,
            group_permits: Default::default(),
        }
    }

    /// Capture a restart checkpoint, invalidating live callback handles. An
    /// exposed response without a confirmed outcome counts as incomplete on restore.
    pub fn into_snapshot(mut self, now: u64) -> InstallationSnapshot {
        self.expire(now);
        self.current.sync_policy_to_store(now);
        let selected = self.selected();
        let policy = self.current.contacts.attempt_policy_state();
        let mut contacts: BTreeMap<_, _> = self
            .inactive
            .into_iter()
            .map(|(id, persona)| (id, persona.contacts))
            .collect();
        contacts.insert(selected, self.current.into_contacts());
        InstallationSnapshot {
            selected,
            contacts,
            policy,
            #[cfg(feature = "openpgp")]
            openpgp_revocations: self.openpgp_revocations,
            #[cfg(not(feature = "openpgp"))]
            openpgp_revocations: self.openpgp_revocations,
            roster_locks: self
                .roster_locks
                .into_inner()
                .unwrap_or_else(|error| error.into_inner()),
            roster_signing_disabled: self.roster_signing_disabled,
            roster_unconfirmed: self.roster_unconfirmed,
            handoff_sequence: self.handoff_sequence,
            voting: self.voting,
            historical_voting: self.historical_voting,
            device_nonce: self.device_nonce,
        }
    }

    /// Restart from this installation's latest authenticated checkpoint.
    pub fn restore(
        snapshot: InstallationSnapshot,
        keys: impl IntoIterator<Item = SigningKey>,
    ) -> Result<Self, Error> {
        let InstallationSnapshot {
            selected,
            mut contacts,
            policy,
            #[cfg(feature = "openpgp")]
            openpgp_revocations,
            #[cfg(not(feature = "openpgp"))]
            openpgp_revocations,
            roster_locks,
            roster_signing_disabled,
            roster_unconfirmed,
            handoff_sequence,
            voting,
            historical_voting,
            device_nonce,
        } = snapshot;
        let mut current = None;
        let mut inactive = BTreeMap::new();
        for key in keys {
            let id = key.verifying_key().to_bytes();
            if current.is_some() && id == selected || inactive.contains_key(&id) {
                return Err(Error::DuplicateIdentity);
            }
            let mut store = contacts.remove(&id).ok_or(Error::UnknownIdentity)?;
            if id == selected {
                store.update_attempt_policy_state(policy);
                current =
                    Some(EncounterController::with_store(key, store).map_err(SessionError::Store)?);
            } else {
                inactive.insert(
                    id,
                    Persona {
                        key,
                        contacts: store,
                    },
                );
            }
        }
        if !contacts.is_empty() {
            return Err(Error::UnknownIdentity);
        }
        let total = 1 + inactive.len();
        if total > MAX_IDENTITIES_CEILING {
            return Err(Error::IdentityLimitExceeded);
        }
        Ok(Self {
            current: current.ok_or(Error::UnknownIdentity)?,
            inactive,
            ceremony: None,
            pending_link: None,
            #[cfg(feature = "openpgp")]
            openpgp_preview: None,
            #[cfg(feature = "openpgp")]
            openpgp_revocations,
            #[cfg(not(feature = "openpgp"))]
            openpgp_revocations,
            roster_locks: std::sync::Mutex::new(roster_locks),
            roster_signing_disabled,
            roster_unconfirmed,
            handoff_sequence,
            voting,
            historical_voting,
            device_nonce,
            max_identities: DEFAULT_MAX_IDENTITIES.max(total),
            group_permits: Default::default(),
        })
    }

    /// Restore a backup whose roster locks may predate signatures already
    /// released by this identity. Keep quorum signing disabled after restart.
    pub fn restore_backup(
        snapshot: InstallationSnapshot,
        keys: impl IntoIterator<Item = SigningKey>,
    ) -> Result<Self, Error> {
        let mut installation = Self::restore(snapshot, keys)?;
        installation.roster_unconfirmed.extend(
            std::iter::once(installation.selected()).chain(installation.inactive.keys().copied()),
        );
        // A portable backup is not the old physical device. Generate a fresh recipient
        // nonce on demand, so two restores cannot accept the same transfer.
        installation.device_nonce = None;
        // A backup may predate what this identity signed elsewhere: it may not vote until a
        // handoff (or, later, a recognition) gives it the role.
        installation.gate_voting();
        Ok(installation)
    }

    /// Restart using the latest authenticated roster transaction, which may be
    /// newer than the other local records. Never load these bytes from a backup.
    pub fn restore_with_roster_checkpoint(
        snapshot: InstallationSnapshot,
        keys: impl IntoIterator<Item = SigningKey>,
        checkpoint: &[u8],
    ) -> Result<Self, Error> {
        let mut installation = Self::restore(snapshot, keys)?;
        let mut cursor = std::io::Cursor::new(checkpoint);
        let (version, identity, locks): (u8, Identity, RosterLockTable) =
            cbor2::from_reader(&mut cursor).map_err(|_| Error::InvalidRosterCheckpoint)?;
        let is_owned =
            installation.selected() == identity || installation.inactive.contains_key(&identity);
        if version != 1 || !is_owned || (cursor.position() as usize) != checkpoint.len() {
            return Err(Error::InvalidRosterCheckpoint);
        }
        let conflict = roster_locks::merge_checkpoint(
            installation
                .roster_locks
                .get_mut()
                .unwrap_or_else(|error| error.into_inner()),
            locks,
        )?;
        installation.roster_signing_disabled |= conflict;
        Ok(installation)
    }

    /// The selected identity's signing key, for in-crate issuance that must be bound to this
    /// installation (never exposed publicly).
    #[cfg(feature = "openpgp")]
    #[allow(dead_code)]
    pub(crate) fn selected_signing_key(&self) -> &SigningKey {
        &self.current.key
    }

    pub fn selected(&self) -> Identity {
        self.current.key.verifying_key().to_bytes()
    }

    pub fn max_identities(&self) -> usize {
        self.max_identities
    }

    pub fn total_contacts(&self) -> usize {
        self.current.contacts.count()
            + self
                .inactive
                .values()
                .map(|p| p.contacts.count())
                .sum::<usize>()
    }

    pub fn total_seen_transcripts(&self) -> usize {
        self.current.contacts.seen_transcripts_len()
            + self
                .inactive
                .values()
                .map(|p| p.contacts.seen_transcripts_len())
                .sum::<usize>()
    }

    pub fn set_max_identities(&mut self, limit: usize) -> Result<(), Error> {
        let current_count = self.inactive.len() + 1;
        if limit > MAX_IDENTITIES_CEILING || limit < current_count {
            return Err(Error::InvalidConfiguration);
        }
        self.max_identities = limit;
        Ok(())
    }

    pub fn add_identity(&mut self, key: SigningKey) -> Result<Identity, Error> {
        let identity = key.verifying_key().to_bytes();
        if self.contacts(identity).is_some() {
            return Err(Error::DuplicateIdentity);
        }
        if (self.inactive.len() + 1) >= self.max_identities {
            return Err(Error::IdentityLimitExceeded);
        }
        if let Some(prev) = self.historical_voting.remove(&identity) {
            self.voting.insert(identity, prev);
        }
        self.inactive.insert(
            identity,
            Persona {
                key,
                contacts: ContactStore::for_identity(identity),
            },
        );
        Ok(identity)
    }

    /// Import an owned signing key after checking the supplied public half.
    /// This creates a local identity with an empty contact store.
    pub fn import_identity(
        &mut self,
        key: SigningKey,
        public: Identity,
    ) -> Result<Identity, Error> {
        if key.verifying_key().to_bytes() != public {
            return Err(Error::KeyPairMismatch);
        }
        self.add_identity(key)
    }

    /// Import a peer key into one local relationship context. Verification
    /// requires a separate Encounter. Existing evidence is preserved.
    pub fn import_peer_key(
        &mut self,
        local: Identity,
        public: Identity,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<&ContactRecordV1, Error> {
        if self.contacts(public).is_some() {
            return Err(SessionError::Store(StoreError::SelfContact).into());
        }
        if self.total_contacts() >= MAX_INSTALLATION_CONTACTS
            && self.contacts(local).and_then(|c| c.get(&public)).is_none()
        {
            return Err(SessionError::Store(StoreError::StoreFull).into());
        }
        let export = ContactExportV1 {
            peer_ed25519_pk: public,
            label: None,
        };
        self.contact_store_mut(local)?
            .import_contact(export, rng)
            .map_err(|error| SessionError::Store(error).into())
    }

    pub fn select(&mut self, identity: Identity, now: u64) -> Result<(), Error> {
        if identity == self.selected() {
            return Ok(());
        }
        self.expire(now);
        if self.ceremony.is_some() {
            return Err(Error::CeremonyActive);
        }
        let next = self
            .inactive
            .remove(&identity)
            .ok_or(Error::UnknownIdentity)?;
        let old = self.selected();
        self.inactive.insert(
            old,
            Persona {
                key: std::mem::replace(&mut self.current.key, next.key),
                contacts: std::mem::replace(&mut self.current.contacts, next.contacts),
            },
        );
        // The controller retains its attempt policy when changing identities.
        self.current.sync_policy_to_store(now);
        self.pending_link = None;
        #[cfg(feature = "openpgp")]
        {
            self.openpgp_preview = None;
        }
        Ok(())
    }

    pub fn contacts(&self, identity: Identity) -> Option<&ContactStore> {
        if identity == self.selected() {
            return Some(&self.current.contacts);
        }
        self.inactive
            .get(&identity)
            .map(|persona| &persona.contacts)
    }

    /// Remove an inactive local identity and its private contact store.
    /// Preserves voting and lock history so a re-imported identity cannot
    /// bypass handoff or backup guarantees.
    pub fn remove_identity(&mut self, identity: Identity) -> Result<(), Error> {
        if identity == self.selected() {
            return Err(Error::SelectedIdentity);
        }
        self.inactive
            .remove(&identity)
            .ok_or(Error::UnknownIdentity)?;
        self.roster_unconfirmed.remove(&identity);
        if let Some(record) = self.voting.remove(&identity)
            && (record.state != VotingState::Voting || record.counter > 0)
        {
            self.historical_voting.insert(identity, record);
        }
        self.group_permits
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(owner, ..)| *owner != identity);
        // Voter locks deliberately outlive the identity: dropping them would let a re-imported
        // key contradict votes it already signed. They can be compacted once
        // the group has moved past that parent.
        Ok(())
    }

    pub fn block_contact(&mut self, identity: Identity, peer: Identity) -> Result<(), Error> {
        let store = self.contact_store_mut(identity)?;
        if store.get(&peer).is_none() {
            return Err(SessionError::Store(StoreError::UnknownContact).into());
        }
        store.block(&peer);
        Ok(())
    }

    /// Copy the public key into the destination contact store. An existing
    /// destination record keeps its own verification, alias, and block status.
    pub fn copy_contact(
        &mut self,
        source: Identity,
        destination: Identity,
        peer: Identity,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<&ContactRecordV1, Error> {
        let exported = self
            .contacts(source)
            .ok_or(Error::UnknownIdentity)?
            .export_contact(&peer, None)
            .ok_or(SessionError::Store(StoreError::UnknownContact))?;
        if self.total_contacts() >= MAX_INSTALLATION_CONTACTS
            && self
                .contacts(destination)
                .and_then(|c| c.get(&peer))
                .is_none()
        {
            return Err(SessionError::Store(StoreError::StoreFull).into());
        }
        Ok(self
            .contact_store_mut(destination)?
            .import_contact(exported, rng)
            .map_err(SessionError::Store)?)
    }

    fn contact_store_mut(&mut self, identity: Identity) -> Result<&mut ContactStore, Error> {
        if identity == self.selected() {
            return Ok(&mut self.current.contacts);
        }
        self.inactive
            .get_mut(&identity)
            .map(|persona| &mut persona.contacts)
            .ok_or(Error::UnknownIdentity)
    }

    pub fn linked_person_contacts(
        &self,
        local: Identity,
        peers: impl IntoIterator<Item = Identity>,
    ) -> Result<LinkedPersonContacts, Error> {
        let contacts = self.contacts(local).ok_or(Error::UnknownIdentity)?;
        let peers: BTreeSet<_> = peers.into_iter().collect();
        if peers.len() < 2 || peers.iter().any(|peer| contacts.get(peer).is_none()) {
            return Err(Error::InvalidContactLink);
        }
        Ok(LinkedPersonContacts { local, peers })
    }

    fn expire(&mut self, now: u64) {
        let was_live = self.current.policy.is_live();
        self.current.expire(now);
        if was_live && !self.current.policy.is_live() {
            self.ceremony = None;
        }
        // A scanner opened without ever starting a session lapses immediately if the handle
        // was dropped, or after the session timeout if the handle is retained but idle.
        if let Some((weak, opened)) = &self.ceremony {
            let dropped = weak.upgrade().is_none();
            if dropped {
                self.current.cancel(now);
            }
            if dropped
                || (!self.current.policy.is_live()
                    && now.saturating_sub(*opened) >= super::SESSION_TIMEOUT_MS)
            {
                self.ceremony = None;
            }
        }
    }

    fn register(&mut self, now: u64) -> Result<Ceremony, Error> {
        self.expire(now);
        if self.ceremony.is_some() {
            return Err(Error::CeremonyActive);
        }
        let token = Arc::new(());
        self.ceremony = Some((Arc::downgrade(&token), now));
        Ok(Ceremony(token))
    }

    fn check(&self, ceremony: &Ceremony) -> Result<(), Error> {
        if let Some((weak, _)) = &self.ceremony
            && let Some(active) = weak.upgrade()
            && Arc::ptr_eq(&active, &ceremony.0)
        {
            return Ok(());
        }
        Err(Error::StaleCeremony)
    }

    fn finish_if_idle(&mut self) {
        if !self.current.policy.is_live() {
            self.ceremony = None;
        }
    }

    pub fn start(
        &mut self,
        now: u64,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<(Ceremony, Vec<u8>), Error> {
        let ceremony = self.register(now)?;
        let result = self.current.start(now, rng);
        self.finish_if_idle();
        Ok((ceremony, result?))
    }

    pub fn open_scanner(&mut self, now: u64) -> Result<Ceremony, Error> {
        self.register(now)
    }

    pub fn scan_offer(
        &mut self,
        ceremony: &Ceremony,
        bytes: &[u8],
        now: u64,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<Vec<u8>, Error> {
        self.check(ceremony)?;
        self.expire(now);
        self.check(ceremony)?;
        let result = self.current.scan_offer(bytes, now, rng);
        self.finish_if_idle();
        Ok(result?)
    }

    pub fn scan_response(
        &mut self,
        ceremony: &Ceremony,
        bytes: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, Error> {
        self.check(ceremony)?;
        let result = self.current.scan_response(bytes, now);
        self.finish_if_idle();
        Ok(result?)
    }

    pub fn scan_reveal(
        &mut self,
        ceremony: &Ceremony,
        bytes: &[u8],
        now: u64,
    ) -> Result<(), Error> {
        self.check(ceremony)?;
        let result = self.current.scan_reveal(bytes, now);
        self.finish_if_idle();
        Ok(result?)
    }

    pub fn comparison(
        &mut self,
        ceremony: &Ceremony,
        now: u64,
    ) -> Result<Option<Comparison>, Error> {
        self.check(ceremony)?;
        self.expire(now);
        Ok(self.current.comparison(now))
    }

    pub fn confirm_and_save(
        &mut self,
        ceremony: &Ceremony,
        comparison: Comparison,
        peer_code: u32,
        now: u64,
        timestamp: u64,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Result<ContactRecordV1, Error> {
        self.check(ceremony)?;
        if self.total_contacts() >= MAX_INSTALLATION_CONTACTS {
            if let Some(peer_pk) = self.current.peer_identity_pk() {
                if self.current.contacts.get(&peer_pk).is_none() {
                    return Err(SessionError::Store(StoreError::StoreFull).into());
                }
            }
        }
        while self.total_seen_transcripts() >= crate::contact::MAX_SEEN_TRANSCRIPTS {
            let current_time = self.current.contacts.oldest_transcript_time();
            let mut oldest_inactive: Option<(Identity, u64)> = None;
            for (id, persona) in &self.inactive {
                if let Some(ts) = persona.contacts.oldest_transcript_time() {
                    if oldest_inactive.is_none() || ts < oldest_inactive.unwrap().1 {
                        oldest_inactive = Some((*id, ts));
                    }
                }
            }

            match (current_time, oldest_inactive) {
                (Some(cur_ts), Some((inact_id, inact_ts))) => {
                    if inact_ts <= cur_ts {
                        self.inactive
                            .get_mut(&inact_id)
                            .unwrap()
                            .contacts
                            .evict_oldest_transcript();
                    } else {
                        self.current.contacts.evict_oldest_transcript();
                    }
                }
                (Some(_), None) => {
                    self.current.contacts.evict_oldest_transcript();
                }
                (None, Some((inact_id, _))) => {
                    self.inactive
                        .get_mut(&inact_id)
                        .unwrap()
                        .contacts
                        .evict_oldest_transcript();
                }
                (None, None) => break,
            }
        }
        let result = self
            .current
            .confirm_and_save(comparison, peer_code, now, timestamp, rng);
        self.finish_if_idle();
        Ok(result?)
    }

    pub fn cancel(&mut self, ceremony: &Ceremony, now: u64) -> Result<(), Error> {
        self.check(ceremony)?;
        self.current.cancel(now);
        self.ceremony = None;
        Ok(())
    }

    /// Explicitly cancel an idle scanner without requiring a ceremony handle.
    pub fn cancel_scanner(&mut self) {
        if !self.current.policy.is_live() {
            self.ceremony = None;
        }
    }
}

/// Disclosure request data shared with the signers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct LinkRequest {
    pub recipient: Identity,
    pub nonce: [u8; 32],
}

impl std::fmt::Debug for LinkRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkRequest").finish_non_exhaustive()
    }
}

#[derive(PartialEq, Eq)]
pub struct DisclosedLink {
    pub recipient: Identity,
    pub pair: [Identity; 2],
}

impl std::fmt::Debug for DisclosedLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DisclosedLink").finish_non_exhaustive()
    }
}

#[derive(PartialEq, Eq)]
pub struct LinkPreview {
    pub pair: [Identity; 2],
    pub already_known: [bool; 2],
}

impl std::fmt::Debug for LinkPreview {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LinkPreview").finish_non_exhaustive()
    }
}

pub struct LinkApproval {
    signer: Identity,
    signature: ed25519_dalek::Signature,
}

/// A signer asks the recipient to close a pending disclosure attempt.
pub struct LinkCancellation {
    request: LinkRequest,
    pair: [Identity; 2],
    signer: Identity,
    signature: ed25519_dalek::Signature,
}

fn link_message(domain: &[u8], request: &LinkRequest, mut pair: [Identity; 2]) -> Vec<u8> {
    pair.sort();
    let mut message = domain.to_vec();
    for part in [&request.recipient, &request.nonce, &pair[0], &pair[1]] {
        message.extend_from_slice(part);
    }
    message
}

const LINK_APPROVAL_DOMAIN: &[u8] = b"mesh/experiment/identity-link/v1\0";
const LINK_CANCELLATION_DOMAIN: &[u8] = b"mesh/experiment/identity-link-cancel/v1\0";

impl Installation {
    /// Open a request, superseding any previous request on this installation.
    pub fn request_link(&mut self, now: u64, rng: &mut (impl CryptoRng + RngCore)) -> LinkRequest {
        let mut nonce = [0; 32];
        rng.fill_bytes(&mut nonce);
        let request = LinkRequest {
            recipient: self.selected(),
            nonce,
        };
        self.pending_link = Some((request, now.saturating_add(super::SESSION_TIMEOUT_MS)));
        request
    }

    /// Call only after the owner confirms the displayed pair and recipient as
    /// the currently selected identity. Each identity approves separately.
    pub fn approve_link(&self, request: &LinkRequest, pair: [Identity; 2]) -> Option<LinkApproval> {
        use ed25519_dalek::Signer;
        let signer = self.selected();
        if !self.can_sign_link(pair) {
            return None;
        }
        let signature = self
            .current
            .key
            .sign(&link_message(LINK_APPROVAL_DOMAIN, request, pair));
        Some(LinkApproval { signer, signature })
    }

    /// Approve the exact ejection proposal as the selected identity.
    pub fn sign_group_ejection(&self, binding: [u8; 32]) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;

        self.require_voting()?;
        Ok(self
            .current
            .key
            .sign(&group_ejection_message(binding))
            .to_bytes())
    }

    /// Cancel the exact invitation as the selected identity.
    pub fn sign_group_invitation_cancellation(&self, binding: [u8; 32]) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;

        self.require_voting()?;
        Ok(self
            .current
            .key
            .sign(&group_invitation_cancellation_message(binding))
            .to_bytes())
    }

    /// Sign the hash of a group invitation as its inviter.
    pub fn sign_group_invitation(&self, binding: [u8; 32]) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;

        self.require_voting()?;
        Ok(self
            .current
            .key
            .sign(&group_invitation_message(binding))
            .to_bytes())
    }

    /// Consent to one exact group formation as the selected identity.
    pub fn sign_group_formation_consent(&self, binding: [u8; 32]) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;

        self.require_voting()?;
        Ok(self
            .current
            .key
            .sign(&group_formation_consent_message(binding, self.selected()))
            .to_bytes())
    }

    /// Accept a specific group invitation as the selected identity.
    pub fn sign_group_admission_consent(
        &self,
        group: u64,
        parent: [u8; 32],
        invitation: [u8; 32],
        inviter: Identity,
    ) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;

        self.require_voting_in(group, parent)?;
        let message =
            group_admission_consent_message(group, parent, invitation, inviter, self.selected());
        Ok(self.current.key.sign(&message).to_bytes())
    }

    /// Sign a decision on an exact group invitation as the selected identity.
    pub fn sign_group_admission_vote(
        &self,
        group: u64,
        parent: [u8; 32],
        invitation: [u8; 32],
        decision: u8,
    ) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;

        self.require_voting_in(group, parent)?;
        let message = group_admission_vote_message(group, parent, invitation, decision);
        Ok(self.current.key.sign(&message).to_bytes())
    }

    /// Sign a departure from the selected identity's membership tenure.
    pub fn sign_group_departure(
        &self,
        group: u64,
        joined_state: [u8; 32],
    ) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;

        self.require_voting_for_group(group)?;
        let message = group_departure_message(group, joined_state, self.selected());
        Ok(self.current.key.sign(&message).to_bytes())
    }

    /// Sign a recovery enrollment commitment as the selected identity (the owner).
    pub fn sign_group_recovery_enrollment(
        &self,
        group: u64,
        parent: [u8; 32],
        commitment: [u8; 32],
    ) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;

        self.require_voting_in(group, parent)?;
        let message = group_recovery_enrollment_message(group, parent, self.selected(), commitment);
        Ok(self.current.key.sign(&message).to_bytes())
    }

    /// Sign a suspension proposal as the selected identity.
    pub fn sign_group_suspension(
        &self,
        group: u64,
        parent: [u8; 32],
        target: Identity,
    ) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;

        self.require_voting_in(group, parent)?;
        let message = group_suspension_message(group, parent, self.selected(), target);
        Ok(self.current.key.sign(&message).to_bytes())
    }

    /// Authorize a group key rotation as one of its two selected identities.
    pub fn sign_group_rotation(
        &self,
        group: u64,
        parent: [u8; 32],
        old: Identity,
        new: Identity,
    ) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;

        self.require_voting_in(group, parent)?;
        if old == new || ![old, new].contains(&self.selected()) {
            return Err(Error::UnknownIdentity);
        }
        Ok(self
            .current
            .key
            .sign(&group_rotation_message(group, parent, old, new))
            .to_bytes())
    }

    /// Sign a roster vote as the selected identity, refusing anything that would contradict a
    /// signature this identity has already given for the same parent:
    /// - one prepare, commit and round-change claim per round;
    /// - after a commit, only that child may be prepared or committed;
    /// - after asking to move to a round, no votes in earlier rounds.
    ///
    /// The lock is recorded before the signature is returned.
    pub fn sign_group_roster_vote(
        &self,
        group: u64,
        parent: [u8; 32],
        child: [u8; 32],
        round: u32,
        phase: u8,
    ) -> Result<[u8; 64], Error> {
        self.prepare_roster_signature(group, parent, child, round, phase)
    }

    fn prepare_roster_signature(
        &self,
        group: u64,
        parent: [u8; 32],
        child: [u8; 32],
        round: u32,
        phase: u8,
    ) -> Result<[u8; 64], Error> {
        let signer = self.selected();
        self.require_current_roster_state(signer, group, parent)?;
        if !self.voting_allows_in(signer, group, parent) {
            return Err(Error::NotVotingDevice);
        }
        let mut table = self
            .roster_locks
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        roster_locks::record_vote(&mut table, (group, parent), signer, child, round, phase)?;
        Ok(self.sign_roster_unchecked(group, parent, child, round, phase))
    }

    /// Release a signature only after the application's transaction durably
    /// stores both the updated lock checkpoint and the outbound signature.
    /// A failed write preserves the in-memory lock for a safe retry.
    pub fn sign_group_roster_vote_durable(
        &mut self,
        group: u64,
        parent: [u8; 32],
        child: [u8; 32],
        round: u32,
        phase: u8,
        persist: impl FnOnce(&[u8], &[u8; 64]) -> std::io::Result<()>,
    ) -> Result<[u8; 64], Error> {
        let signature = self.prepare_roster_signature(group, parent, child, round, phase)?;
        let signer = self.selected();
        let locks = self
            .roster_locks
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        let checkpoint =
            cbor2::to_vec(&(1_u8, signer, locks)).map_err(|_| Error::InvalidRosterCheckpoint)?;
        persist(&checkpoint, &signature).map_err(|_| Error::RosterCheckpointWriteFailed)?;
        Ok(signature)
    }

    /// Attest to the selected group's local head. Refuse after committing to a
    /// child, even when that child has yet to be applied to the local roster.
    pub fn sign_group_roster_freshness(
        &self,
        group: u64,
        head: [u8; 32],
        revision: u64,
        nonce: [u8; 32],
    ) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;

        self.require_current_roster_state(self.selected(), group, head)?;
        if !self.voting_allows_in(self.selected(), group, head) {
            return Err(Error::NotVotingDevice);
        }
        let table = self.roster_locks.lock().unwrap_or_else(|e| e.into_inner());
        if roster_locks::blocks_freshness(&table, (group, head), self.selected()) {
            return Err(Error::ConflictingRosterVote);
        }
        let message = group_roster_freshness_message(group, head, revision, nonce);
        Ok(self.current.key.sign(&message).to_bytes())
    }

    /// Compact the voting state after the caller authenticates a successor.
    /// This permanently disables signing for this parent in this installation.
    /// Persist the updated snapshot before relying on retirement after restart.
    /// `head` is the caller's authenticated current roster id; retiring it is refused, since
    /// retirement is permanent and would stop this installation voting on the live roster.
    pub fn retire_roster_parent(
        &self,
        group: u64,
        parent: [u8; 32],
        head: [u8; 32],
    ) -> Result<(), Error> {
        if parent == head {
            return Err(Error::ConflictingRosterVote);
        }
        let mut table = self.roster_locks.lock().unwrap_or_else(|e| e.into_inner());
        if table.len() >= roster_locks::MAX_ROSTER_LOCKS && !table.contains_key(&(group, parent)) {
            return Err(Error::RosterLockCapacityExceeded);
        }
        table.insert((group, parent), RosterParentLocks::Retired);
        Ok(())
    }

    fn sign_roster_unchecked(
        &self,
        group: u64,
        parent: [u8; 32],
        child: [u8; 32],
        round: u32,
        phase: u8,
    ) -> [u8; 64] {
        use ed25519_dalek::Signer;

        let message = group_roster_vote_message(group, parent, child, round, phase);
        self.current.key.sign(&message).to_bytes()
    }

    /// Byzantine fixtures only: sign without the self-consistency locks.
    #[cfg(any(feature = "test-support", test))]
    pub fn sign_group_roster_vote_unchecked(
        &self,
        group: u64,
        parent: [u8; 32],
        child: [u8; 32],
        round: u32,
        phase: u8,
    ) -> [u8; 64] {
        self.sign_roster_unchecked(group, parent, child, round, phase)
    }

    /// Sign a recovery decision as the selected identity.
    pub fn sign_group_recovery(
        &self,
        group: u64,
        parent: [u8; 32],
        old: Identity,
        new: Identity,
        request: [u8; 32],
        decision: u8,
    ) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;

        self.require_voting_in(group, parent)?;
        let message = group_recovery_message(group, parent, old, new, request, decision);
        Ok(self.current.key.sign(&message).to_bytes())
    }

    /// Sign a group voucher withdrawal as the selected identity.
    pub fn sign_voucher_withdrawal(
        &self,
        group: u64,
        voucher: [u8; 32],
    ) -> Result<[u8; 64], Error> {
        use ed25519_dalek::Signer;

        self.require_voting()?;
        Ok(self
            .current
            .key
            .sign(&voucher_withdrawal_message(group, voucher))
            .to_bytes())
    }

    /// Send a cancellation as one of the two selected identities. Once
    /// delivered, it closes the request if it is still pending. Completed
    /// disclosures remain known to the recipient.
    pub fn sign_link_cancellation(
        &self,
        request: LinkRequest,
        pair: [Identity; 2],
    ) -> Option<LinkCancellation> {
        use ed25519_dalek::Signer;

        let signer = self.selected();
        if !self.can_sign_link(pair) {
            return None;
        }
        Some(LinkCancellation {
            request,
            pair,
            signer,
            signature: self.current.key.sign(&link_message(
                LINK_CANCELLATION_DOMAIN,
                &request,
                pair,
            )),
        })
    }

    /// Apply a cancellation for the pair the recipient expects for this operation.
    pub fn receive_link_cancellation(
        &mut self,
        cancellation: &LinkCancellation,
        mut expected_pair: [Identity; 2],
        now: u64,
    ) -> bool {
        let Some((request, deadline)) = self.pending_link else {
            return false;
        };
        if now >= deadline {
            self.pending_link = None;
            return false;
        }

        expected_pair.sort();
        let mut pair = cancellation.pair;
        pair.sort();
        if request != cancellation.request
            || pair != expected_pair
            || pair[0] == pair[1]
            || !pair.contains(&cancellation.signer)
        {
            return false;
        }
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&cancellation.signer) else {
            return false;
        };
        if key.is_weak() {
            return false;
        }
        if key
            .verify_strict(
                &link_message(LINK_CANCELLATION_DOMAIN, &request, pair),
                &cancellation.signature,
            )
            .is_err()
        {
            return false;
        }
        self.pending_link = None;
        true
    }

    fn can_sign_link(&self, pair: [Identity; 2]) -> bool {
        pair[0] != pair[1]
            && pair.contains(&self.selected())
            && pair.iter().all(|&id| self.contacts(id).is_some())
    }

    pub fn cancel_link(&mut self, request: LinkRequest) {
        if self
            .pending_link
            .is_some_and(|(pending, _)| pending == request)
        {
            self.pending_link = None;
        }
    }

    /// Checks the approvals before showing the proposed association. Contact
    /// discovery is scoped to the recipient's selected local identity.
    pub fn preview_link(
        &mut self,
        request: LinkRequest,
        mut pair: [Identity; 2],
        approvals: &[LinkApproval; 2],
        now: u64,
    ) -> Option<LinkPreview> {
        let (pending, deadline) = self.pending_link?;
        if now >= deadline {
            self.pending_link = None;
            return None;
        }
        if pending != request || pair[0] == pair[1] {
            return None;
        }

        pair.sort();
        let mut ordered = [&approvals[0], &approvals[1]];
        ordered.sort_by_key(|approval| approval.signer);
        let message = link_message(LINK_APPROVAL_DOMAIN, &request, pair);
        for (identity, approval) in pair.into_iter().zip(ordered) {
            if identity != approval.signer {
                return None;
            }
            let key = ed25519_dalek::VerifyingKey::from_bytes(&identity).ok()?;
            if key.is_weak() {
                return None;
            }
            key.verify_strict(&message, &approval.signature).ok()?;
        }
        Some(LinkPreview {
            pair,
            already_known: pair.map(|identity| self.current.contacts.get(&identity).is_some()),
        })
    }

    pub fn receive_link(
        &mut self,
        request: LinkRequest,
        pair: [Identity; 2],
        approvals: [LinkApproval; 2],
        now: u64,
    ) -> Option<DisclosedLink> {
        let preview = self.preview_link(request, pair, &approvals, now)?;
        self.pending_link = None;
        Some(DisclosedLink {
            recipient: request.recipient,
            pair: preview.pair,
        })
    }
}
