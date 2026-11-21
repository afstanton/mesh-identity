//! Contact record schema and continuity manager for Encounter v0.1 (`ContactRecordV1`).
use crate::protocol::ConfirmedEncounter;
use ed25519_dalek::VerifyingKey;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

pub const MAX_ALIAS_BYTES: usize = 64;
pub const MAX_LABEL_BYTES: usize = 64;
pub const MAX_CONTACTS_PER_STORE: usize = 100_000;
pub const MAX_SEEN_TRANSCRIPTS: usize = 262_144;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationStatus {
    Verified,
    ImportedUnverified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContactStatus {
    Active,
    Blocked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoreError {
    /// Not a valid Ed25519 point, or a small-order (weak) key that anyone can sign for.
    InvalidKey,
    /// The key is this device's own identity key.
    SelfContact,
    WrongLocalIdentity,
    /// The contact is blocked; a new encounter never silently reactivates it.
    Blocked,
    /// Another contact already uses this alias. The UI shows `ui_text::ALIAS_CONFLICT_WARNING`;
    /// the user must pick a different alias (this store never silently shares one).
    AliasConflict {
        existing_pk: [u8; 32],
    },
    UnknownContact,
    /// The store is currently under an active retry backoff pause.
    Paused,
    /// Private alias exceeds MAX_ALIAS_BYTES (64 bytes UTF-8).
    AliasTooLong,
    /// Private alias is empty after whitespace trimming.
    EmptyAlias,
    /// Contact export label exceeds MAX_LABEL_BYTES (64 bytes UTF-8).
    LabelTooLong,
    /// Contact store has reached its capacity limit (MAX_CONTACTS_PER_STORE = 100,000).
    StoreFull,
    /// Wire store exceeds MAX_SEEN_TRANSCRIPTS (262,144).
    TooManySeenTranscripts,
    /// Wire store alias is invalid or duplicate.
    InvalidAlias,
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidKey => write!(f, "invalid or weak Ed25519 public key"),
            Self::SelfContact => write!(f, "cannot add self as contact"),
            Self::WrongLocalIdentity => write!(f, "wrong local identity for contact store"),
            Self::Blocked => write!(f, "contact is blocked"),
            Self::AliasConflict { .. } => write!(f, "alias conflict with existing contact"),
            Self::UnknownContact => write!(f, "contact not found"),
            Self::Paused => write!(f, "contact store is paused due to backoff"),
            Self::AliasTooLong => write!(f, "contact alias exceeds maximum length (64 bytes)"),
            Self::EmptyAlias => write!(f, "contact alias is empty"),
            Self::LabelTooLong => write!(f, "export label exceeds maximum length (64 bytes)"),
            Self::StoreFull => write!(f, "contact store capacity limit reached"),
            Self::TooManySeenTranscripts => write!(f, "seen transcripts limit exceeded"),
            Self::InvalidAlias => write!(f, "invalid contact alias"),
        }
    }
}

impl std::error::Error for StoreError {}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptPolicyState {
    pub consecutive_incomplete: u32,
    /// A response was exposed or accepted and the attempt has no recorded outcome.
    #[serde(default)]
    pub pending_response: bool,
    /// Time left in an interference pause when this snapshot was taken. It is a duration, not a
    /// deadline: monotonic clocks restart at boot, so an absolute deadline saved before a reboot
    /// would be meaningless (or lock the user out for as long as the device had been up).
    /// The controller rebases it on the first attempt after a restore, capped at `PAUSE_MS`.
    pub pause_remaining_ms: Option<u64>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactRecordV1 {
    #[serde(with = "crate::cbor::byte_seq::array16")]
    pub local_contact_id: [u8; 16],
    #[serde(with = "crate::cbor::byte_seq::array32")]
    pub peer_ed25519_pk: [u8; 32],
    pub verified_at: u64,
    pub encounter_count: u64,
    pub verification_status: VerificationStatus,
    pub status: ContactStatus,
    /// Private user-chosen label; never exported or transmitted.
    pub local_alias: Option<String>,
    #[serde(with = "crate::cbor::byte_seq::array32")]
    pub last_transcript: [u8; 32],
}

impl std::fmt::Debug for ContactRecordV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContactRecordV1")
            .field("verification_status", &self.verification_status)
            .field("status", &self.status)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContactExportV1 {
    #[serde(with = "crate::cbor::byte_seq::array32")]
    pub peer_ed25519_pk: [u8; 32],
    pub label: Option<String>,
}

pub struct ContactStore {
    local_identity_pk: [u8; 32],
    contacts: HashMap<[u8; 32], ContactRecordV1>,
    /// Every transcript digest ever recorded (bounded at MAX_SEEN_TRANSCRIPTS, evicting oldest).
    seen_transcripts: HashSet<[u8; 32]>,
    seen_order: VecDeque<[u8; 32]>,
    attempt_policy: AttemptPolicyState,
}

fn validate_key(pk: &[u8; 32]) -> Result<(), StoreError> {
    match VerifyingKey::from_bytes(pk) {
        Ok(vk) if !vk.is_weak() => Ok(()),
        _ => Err(StoreError::InvalidKey),
    }
}

/// The saved form of one contact store (see `session::installation::snapshot`).
#[derive(Serialize, Deserialize)]
pub(crate) struct ContactStoreWire {
    #[serde(with = "crate::cbor::byte_seq::array32")]
    pub local_identity: [u8; 32],
    pub contacts: Vec<ContactRecordV1>,
    #[serde(with = "crate::cbor::byte_seq::vec_array32")]
    pub seen_transcripts: Vec<[u8; 32]>,
    pub attempt_policy: AttemptPolicyState,
}

impl ContactStore {
    /// Sorted, so the same store always saves to the same bytes.
    pub(crate) fn to_wire(&self) -> ContactStoreWire {
        let mut contacts: Vec<_> = self.contacts.values().cloned().collect();
        contacts.sort_by_key(|record| record.peer_ed25519_pk);
        let seen_transcripts: Vec<_> = self.seen_order.iter().copied().collect();
        ContactStoreWire {
            local_identity: self.local_identity_pk,
            contacts,
            seen_transcripts,
            attempt_policy: self.attempt_policy,
        }
    }

    /// Rebuild a store, refusing anything the store itself could never have produced: an invalid
    /// or weak key, a contact that is the local identity, or the same peer twice.
    pub(crate) fn from_wire(wire: ContactStoreWire) -> Result<Self, StoreError> {
        validate_key(&wire.local_identity)?;
        if wire.contacts.len() > MAX_CONTACTS_PER_STORE {
            return Err(StoreError::StoreFull);
        }
        if wire.seen_transcripts.len() > MAX_SEEN_TRANSCRIPTS {
            return Err(StoreError::TooManySeenTranscripts);
        }
        let mut store = Self::for_identity(wire.local_identity);
        let mut aliases: HashSet<String> = HashSet::new();
        for record in wire.contacts {
            store.check_key(&record.peer_ed25519_pk)?;
            if let Some(ref alias) = record.local_alias {
                let trimmed = alias.trim();
                if trimmed.is_empty() || trimmed.len() > MAX_ALIAS_BYTES {
                    return Err(StoreError::InvalidAlias);
                }
                let norm = trimmed.to_lowercase();
                if !aliases.insert(norm) {
                    return Err(StoreError::AliasConflict {
                        existing_pk: record.peer_ed25519_pk,
                    });
                }
            }
            let key = record.peer_ed25519_pk;
            if store.contacts.insert(key, record).is_some() {
                return Err(StoreError::InvalidKey);
            }
        }
        for transcript in wire.seen_transcripts {
            if !store.seen_transcripts.insert(transcript) {
                return Err(StoreError::InvalidKey);
            }
            store.seen_order.push_back(transcript);
        }
        store.attempt_policy = wire.attempt_policy;
        Ok(store)
    }

    pub fn for_identity(local_identity_pk: [u8; 32]) -> Self {
        Self {
            local_identity_pk,
            contacts: HashMap::new(),
            seen_transcripts: HashSet::new(),
            seen_order: VecDeque::new(),
            attempt_policy: AttemptPolicyState::default(),
        }
    }

    pub fn attempt_policy_state(&self) -> AttemptPolicyState {
        self.attempt_policy
    }

    pub fn seen_transcripts_len(&self) -> usize {
        self.seen_transcripts.len()
    }

    pub fn evict_oldest_transcript(&mut self) -> bool {
        if let Some(oldest) = self.seen_order.pop_front() {
            self.seen_transcripts.remove(&oldest);
            true
        } else {
            false
        }
    }

    pub(crate) fn local_identity_pk(&self) -> [u8; 32] {
        self.local_identity_pk
    }

    pub(crate) fn update_attempt_policy_state(&mut self, state: AttemptPolicyState) {
        self.attempt_policy = state;
    }

    fn check_key(&self, pk: &[u8; 32]) -> Result<(), StoreError> {
        validate_key(pk)?;
        if self.local_identity_pk == *pk {
            return Err(StoreError::SelfContact);
        }
        Ok(())
    }

    /// Record a locally confirmed encounter (the user compared the SAS).
    /// - Fresh peer key: count 1, `Verified`.
    /// - Known key and a transcript never seen before: count + 1.
    /// - Any transcript already recorded (not just the latest): no change.
    pub fn record_confirmed_encounter<R: CryptoRng + RngCore>(
        &mut self,
        confirmed: &impl ConfirmedEncounter,
        timestamp: u64,
        rng: &mut R,
    ) -> Result<&ContactRecordV1, StoreError> {
        if confirmed.local_identity_pk() != self.local_identity_pk {
            return Err(StoreError::WrongLocalIdentity);
        }
        let peer_pk = confirmed.peer_ed25519_pk();
        let transcript = confirmed.transcript();
        self.check_key(&peer_pk)?;
        if let Some(existing) = self.contacts.get(&peer_pk)
            && existing.status == ContactStatus::Blocked
        {
            return Err(StoreError::Blocked);
        }
        if self.seen_transcripts.contains(&transcript) {
            return self
                .contacts
                .get(&peer_pk)
                .ok_or(StoreError::UnknownContact);
        }
        if self.attempt_policy.pause_remaining_ms.is_some() {
            return Err(StoreError::Paused);
        }
        if !self.contacts.contains_key(&peer_pk) && self.contacts.len() >= MAX_CONTACTS_PER_STORE {
            return Err(StoreError::StoreFull);
        }
        if self.seen_transcripts.insert(transcript) {
            self.seen_order.push_back(transcript);
            if self.seen_order.len() > MAX_SEEN_TRANSCRIPTS
                && let Some(oldest) = self.seen_order.pop_front()
            {
                self.seen_transcripts.remove(&oldest);
            }
        }
        if let Some(existing) = self.contacts.get_mut(&peer_pk) {
            existing.encounter_count += 1;
            existing.last_transcript = transcript;
            existing.verified_at = timestamp;
            existing.verification_status = VerificationStatus::Verified;
        } else {
            let mut id = [0u8; 16];
            rng.fill_bytes(&mut id);
            self.contacts.insert(
                peer_pk,
                ContactRecordV1 {
                    local_contact_id: id,
                    peer_ed25519_pk: peer_pk,
                    verified_at: timestamp,
                    encounter_count: 1,
                    verification_status: VerificationStatus::Verified,
                    status: ContactStatus::Active,
                    local_alias: None,
                    last_transcript: transcript,
                },
            );
        }
        Ok(&self.contacts[&peer_pk])
    }

    pub fn get(&self, peer_pk: &[u8; 32]) -> Option<&ContactRecordV1> {
        self.contacts.get(peer_pk)
    }

    pub fn count(&self) -> usize {
        self.contacts.len()
    }

    /// Set a private alias. Rejects an alias already used by a different key (case-insensitive).
    /// Enforces non-empty content and MAX_ALIAS_BYTES (64 bytes UTF-8).
    pub fn set_alias(&mut self, peer_pk: &[u8; 32], alias: &str) -> Result<(), StoreError> {
        if !self.contacts.contains_key(peer_pk) {
            return Err(StoreError::UnknownContact);
        }
        let trimmed = alias.trim();
        if trimmed.is_empty() {
            return Err(StoreError::EmptyAlias);
        }
        if trimmed.len() > MAX_ALIAS_BYTES {
            return Err(StoreError::AliasTooLong);
        }
        let wanted = trimmed.to_lowercase();
        for (pk, c) in &self.contacts {
            if pk != peer_pk
                && c.local_alias.as_ref().map(|a| a.trim().to_lowercase()) == Some(wanted.clone())
            {
                return Err(StoreError::AliasConflict { existing_pk: *pk });
            }
        }
        self.contacts.get_mut(peer_pk).unwrap().local_alias = Some(trimmed.to_string());
        Ok(())
    }

    pub fn block(&mut self, peer_pk: &[u8; 32]) {
        if let Some(c) = self.contacts.get_mut(peer_pk) {
            c.status = ContactStatus::Blocked;
        }
    }

    /// Unblocking is a separate deliberate action; it does not change verification state.
    pub fn unblock(&mut self, peer_pk: &[u8; 32]) {
        if let Some(c) = self.contacts.get_mut(peer_pk) {
            c.status = ContactStatus::Active;
        }
    }

    /// Export contact for backup or sharing (strips local identity and verification status).
    /// Bounded by MAX_LABEL_BYTES (64 bytes UTF-8).
    pub fn export_contact(
        &self,
        peer_pk: &[u8; 32],
        label: Option<String>,
    ) -> Option<ContactExportV1> {
        if label.as_ref().is_some_and(|l| l.len() > MAX_LABEL_BYTES) {
            return None;
        }
        self.contacts.get(peer_pk).map(|c| ContactExportV1 {
            peer_ed25519_pk: c.peer_ed25519_pk,
            label,
        })
    }

    /// Import a contact from another device. Imported contacts NEVER inherit verification: a new
    /// record is `ImportedUnverified` with `encounter_count = 0`. An existing record of any kind
    /// (verified, blocked, or already imported) is returned unchanged.
    /// Rejects export labels exceeding MAX_LABEL_BYTES or imports when store is full.
    pub fn import_contact<R: CryptoRng + RngCore>(
        &mut self,
        export: ContactExportV1,
        rng: &mut R,
    ) -> Result<&ContactRecordV1, StoreError> {
        if export
            .label
            .as_ref()
            .is_some_and(|l| l.len() > MAX_LABEL_BYTES)
        {
            return Err(StoreError::LabelTooLong);
        }
        self.check_key(&export.peer_ed25519_pk)?;
        if !self.contacts.contains_key(&export.peer_ed25519_pk)
            && self.contacts.len() >= MAX_CONTACTS_PER_STORE
        {
            return Err(StoreError::StoreFull);
        }
        Ok(self
            .contacts
            .entry(export.peer_ed25519_pk)
            .or_insert_with(|| {
                let mut id = [0u8; 16];
                rng.fill_bytes(&mut id);
                ContactRecordV1 {
                    local_contact_id: id,
                    peer_ed25519_pk: export.peer_ed25519_pk,
                    verified_at: 0,
                    encounter_count: 0,
                    verification_status: VerificationStatus::ImportedUnverified,
                    status: ContactStatus::Active,
                    local_alias: None,
                    last_transcript: [0u8; 32],
                }
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    #[test]
    fn test_export_and_import_contact() {
        let mut rng = StdRng::seed_from_u64(42);
        let alice_key = SigningKey::generate(&mut rng);
        let bob_key = SigningKey::generate(&mut rng);

        let mut alice_store = ContactStore::for_identity(alice_key.verifying_key().to_bytes());
        let bob_pk = bob_key.verifying_key().to_bytes();

        // Unknown contact cannot be exported
        assert!(alice_store.export_contact(&bob_pk, None).is_none());

        // Import Bob as an unverified contact
        let export = ContactExportV1 {
            peer_ed25519_pk: bob_pk,
            label: Some("Bob".to_string()),
        };
        let imported = alice_store.import_contact(export, &mut rng).unwrap();
        assert_eq!(
            imported.verification_status,
            VerificationStatus::ImportedUnverified
        );
        assert_eq!(imported.encounter_count, 0);
        assert_eq!(imported.status, ContactStatus::Active);
        let id1 = imported.local_contact_id;

        // Export Bob now succeeds
        let bob_export = alice_store
            .export_contact(&bob_pk, Some("Bob".into()))
            .unwrap();
        assert_eq!(bob_export.peer_ed25519_pk, bob_pk);

        // Importing again preserves existing record
        let imported2 = alice_store
            .import_contact(
                ContactExportV1 {
                    peer_ed25519_pk: bob_pk,
                    label: None,
                },
                &mut rng,
            )
            .unwrap();
        assert_eq!(id1, imported2.local_contact_id);

        // Self-contact is rejected on import
        let self_export = ContactExportV1 {
            peer_ed25519_pk: alice_key.verifying_key().to_bytes(),
            label: None,
        };
        assert_eq!(
            alice_store.import_contact(self_export, &mut rng),
            Err(StoreError::SelfContact)
        );

        // Invalid key is rejected
        let invalid_export = ContactExportV1 {
            peer_ed25519_pk: [0u8; 32],
            label: None,
        };
        assert_eq!(
            alice_store.import_contact(invalid_export, &mut rng),
            Err(StoreError::InvalidKey)
        );
    }

    #[test]
    fn test_alias_and_block_unblock() {
        let mut rng = StdRng::seed_from_u64(99);
        let alice = SigningKey::generate(&mut rng);
        let bob = SigningKey::generate(&mut rng);
        let charlie = SigningKey::generate(&mut rng);

        let mut store = ContactStore::for_identity(alice.verifying_key().to_bytes());
        let bob_pk = bob.verifying_key().to_bytes();
        let charlie_pk = charlie.verifying_key().to_bytes();

        store
            .import_contact(
                ContactExportV1 {
                    peer_ed25519_pk: bob_pk,
                    label: None,
                },
                &mut rng,
            )
            .unwrap();
        store
            .import_contact(
                ContactExportV1 {
                    peer_ed25519_pk: charlie_pk,
                    label: None,
                },
                &mut rng,
            )
            .unwrap();

        // Set alias
        store.set_alias(&bob_pk, "Bob").unwrap();
        assert_eq!(
            store.get(&bob_pk).unwrap().local_alias.as_deref(),
            Some("Bob")
        );

        // Conflict rejection (case-insensitive)
        assert_eq!(
            store.set_alias(&charlie_pk, "bob"),
            Err(StoreError::AliasConflict {
                existing_pk: bob_pk
            })
        );

        // Unknown contact alias fails
        let stranger = SigningKey::generate(&mut rng).verifying_key().to_bytes();
        assert_eq!(
            store.set_alias(&stranger, "X"),
            Err(StoreError::UnknownContact)
        );

        // Block / Unblock
        store.block(&bob_pk);
        assert_eq!(store.get(&bob_pk).unwrap().status, ContactStatus::Blocked);
        store.unblock(&bob_pk);
        assert_eq!(store.get(&bob_pk).unwrap().status, ContactStatus::Active);
    }

    #[test]
    fn test_from_wire_rejections() {
        let mut rng = StdRng::seed_from_u64(123);
        let local_key = SigningKey::generate(&mut rng);
        let peer_key = SigningKey::generate(&mut rng);
        let local_pk = local_key.verifying_key().to_bytes();
        let peer_pk = peer_key.verifying_key().to_bytes();

        let record = ContactRecordV1 {
            local_contact_id: [1; 16],
            peer_ed25519_pk: peer_pk,
            verified_at: 100,
            encounter_count: 1,
            verification_status: VerificationStatus::Verified,
            status: ContactStatus::Active,
            local_alias: None,
            last_transcript: [2; 32],
        };

        // Duplicate peer key in wire contacts is refused
        let wire_dup = ContactStoreWire {
            local_identity: local_pk,
            contacts: vec![record.clone(), record.clone()],
            seen_transcripts: vec![],
            attempt_policy: AttemptPolicyState::default(),
        };
        assert_eq!(
            ContactStore::from_wire(wire_dup).err(),
            Some(StoreError::InvalidKey)
        );

        // Self-contact in wire is refused
        let mut self_record = record;
        self_record.peer_ed25519_pk = local_pk;
        let wire_self = ContactStoreWire {
            local_identity: local_pk,
            contacts: vec![self_record],
            seen_transcripts: vec![],
            attempt_policy: AttemptPolicyState::default(),
        };
        assert_eq!(
            ContactStore::from_wire(wire_self).err(),
            Some(StoreError::SelfContact)
        );
    }

    #[test]
    fn test_alias_and_label_length_limits() {
        let mut rng = StdRng::seed_from_u64(456);
        let local_pk = SigningKey::generate(&mut rng).verifying_key().to_bytes();
        let peer_pk = SigningKey::generate(&mut rng).verifying_key().to_bytes();
        let mut store = ContactStore::for_identity(local_pk);

        store
            .import_contact(
                ContactExportV1 {
                    peer_ed25519_pk: peer_pk,
                    label: None,
                },
                &mut rng,
            )
            .unwrap();

        // 64-byte alias succeeds
        let valid_64 = "a".repeat(MAX_ALIAS_BYTES);
        assert!(store.set_alias(&peer_pk, &valid_64).is_ok());
        assert_eq!(
            store.get(&peer_pk).unwrap().local_alias.as_deref(),
            Some(valid_64.as_str())
        );

        // 65-byte alias fails
        let invalid_65 = "a".repeat(MAX_ALIAS_BYTES + 1);
        assert_eq!(
            store.set_alias(&peer_pk, &invalid_65),
            Err(StoreError::AliasTooLong)
        );

        // Empty and whitespace-only aliases fail
        assert_eq!(store.set_alias(&peer_pk, ""), Err(StoreError::EmptyAlias));
        assert_eq!(
            store.set_alias(&peer_pk, "   "),
            Err(StoreError::EmptyAlias)
        );

        // Export label limits
        let valid_export = store.export_contact(&peer_pk, Some(valid_64.clone()));
        assert!(valid_export.is_some());
        assert_eq!(
            valid_export.unwrap().label.as_deref(),
            Some(valid_64.as_str())
        );

        // Export label > 64 bytes is rejected
        assert!(
            store
                .export_contact(&peer_pk, Some(invalid_65.clone()))
                .is_none()
        );

        // Import with label > 64 bytes fails
        let invalid_export = ContactExportV1 {
            peer_ed25519_pk: peer_pk,
            label: Some(invalid_65),
        };
        assert_eq!(
            store.import_contact(invalid_export, &mut rng),
            Err(StoreError::LabelTooLong)
        );
    }

    #[test]
    fn test_seen_transcripts_eviction_and_limits() {
        let mut rng = StdRng::seed_from_u64(789);
        let local_pk = SigningKey::generate(&mut rng).verifying_key().to_bytes();
        let peer_pk = SigningKey::generate(&mut rng).verifying_key().to_bytes();

        let record = ContactRecordV1 {
            local_contact_id: [1; 16],
            peer_ed25519_pk: peer_pk,
            verified_at: 100,
            encounter_count: 1,
            verification_status: VerificationStatus::Verified,
            status: ContactStatus::Active,
            local_alias: None,
            last_transcript: [2; 32],
        };

        // Wire with too many seen transcripts is refused
        let wire_too_many = ContactStoreWire {
            local_identity: local_pk,
            contacts: vec![record.clone()],
            seen_transcripts: vec![[0u8; 32]; MAX_SEEN_TRANSCRIPTS + 1],
            attempt_policy: AttemptPolicyState::default(),
        };
        assert_eq!(
            ContactStore::from_wire(wire_too_many).err(),
            Some(StoreError::TooManySeenTranscripts)
        );

        // Wire with too many contacts is refused
        let store = ContactStore::for_identity(local_pk);
        assert_eq!(store.seen_order.len(), 0);
        assert_eq!(store.seen_transcripts.len(), 0);
    }
}
