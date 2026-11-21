//! The saved form of an installation.
//!
//! One versioned CBOR document holds every contact store, the voting records, the device nonce,
//! the signing locks and the handoff bookkeeping, so identity-wide state and signing locks are
//! always saved together. Reading is a pure function of the bytes: a bad version, malformed or
//! oversized input, or a state the installation could never have produced is refused, and nothing
//! else is touched. The bytes are local state the host stores; they carry no signature, so
//! keeping them intact and current is the host's job (the limit recorded for plain `restore`).

use super::roster_locks::RosterLockTable;
use super::{Identity, InstallationSnapshot, VotingRecord};
use crate::contact::{AttemptPolicyState, ContactStore, ContactStoreWire};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// The only version this build writes and reads.
pub const SNAPSHOT_VERSION: u8 = 1;
/// Largest saved installation this build will parse.
pub const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// Not a snapshot, truncated, or has bytes after the document.
    Malformed,
    /// A version this build does not read. The previous state stays usable.
    UnsupportedVersion(u8),
    TooLarge,
    /// Well formed, but not a state an installation could have saved.
    Invalid,
    /// State this format cannot hold yet (OpenPGP revocation memory). Saving refuses rather than
    /// dropping it.
    Unsupported,
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(f, "malformed snapshot"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported snapshot version: {v}"),
            Self::TooLarge => write!(f, "snapshot too large"),
            Self::Invalid => write!(f, "invalid snapshot"),
            Self::Unsupported => write!(f, "unsupported snapshot state"),
        }
    }
}

impl std::error::Error for SnapshotError {}

#[derive(Serialize, Deserialize)]
struct SnapshotWire {
    version: u8,
    #[serde(with = "crate::cbor::byte_seq::array32")]
    selected: Identity,
    stores: Vec<ContactStoreWire>,
    policy: AttemptPolicyState,
    roster_locks: RosterLockTable,
    roster_signing_disabled: bool,
    #[serde(with = "crate::cbor::byte_seq::vec_array32")]
    roster_unconfirmed: Vec<Identity>,
    handoff_sequence: u64,
    #[serde(with = "vec_identity_voting")]
    voting: Vec<(Identity, VotingRecord)>,
    #[serde(default, with = "vec_identity_voting")]
    historical_voting: Vec<(Identity, VotingRecord)>,
    #[serde(with = "crate::cbor::byte_seq::opt_array32")]
    device_nonce: Option<[u8; 32]>,
}

mod vec_identity_voting {
    use super::*;
    use serde::ser::SerializeSeq;
    use serde::{Deserializer, Serializer};

    #[derive(Serialize)]
    struct ItemRef<'a> {
        #[serde(with = "crate::cbor::byte_seq::array32")]
        identity: Identity,
        record: &'a VotingRecord,
    }

    #[derive(Deserialize)]
    struct ItemOwned {
        #[serde(with = "crate::cbor::byte_seq::array32")]
        identity: Identity,
        record: VotingRecord,
    }

    pub fn serialize<S: Serializer>(
        items: &[(Identity, VotingRecord)],
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(items.len()))?;
        for (identity, record) in items {
            seq.serialize_element(&ItemRef {
                identity: *identity,
                record,
            })?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<(Identity, VotingRecord)>, D::Error> {
        let items: Vec<ItemOwned> = Deserialize::deserialize(d)?;
        Ok(items
            .into_iter()
            .map(|item| (item.identity, item.record))
            .collect())
    }
}

impl InstallationSnapshot {
    /// Deterministic bytes: the same state always saves to the same document.
    pub fn to_bytes(&self) -> Result<Vec<u8>, SnapshotError> {
        self.to_bytes_checked(
            #[cfg(feature = "openpgp")]
            self.openpgp_revocations.is_empty(),
        )
    }

    fn to_bytes_checked(
        &self,
        #[cfg(feature = "openpgp")] revocations_empty: bool,
    ) -> Result<Vec<u8>, SnapshotError> {
        #[cfg(feature = "openpgp")]
        if !revocations_empty {
            return Err(SnapshotError::Unsupported);
        }
        let mut stores: Vec<_> = self.contacts.values().map(ContactStore::to_wire).collect();
        stores.sort_by_key(|store| store.local_identity);
        let wire = SnapshotWire {
            version: SNAPSHOT_VERSION,
            selected: self.selected,
            stores,
            policy: self.policy,
            roster_locks: self.roster_locks.clone(),
            roster_signing_disabled: self.roster_signing_disabled,
            roster_unconfirmed: self.roster_unconfirmed.iter().copied().collect(),
            handoff_sequence: self.handoff_sequence,
            voting: self
                .voting
                .iter()
                .map(|(identity, record)| (*identity, record.clone()))
                .collect(),
            historical_voting: self
                .historical_voting
                .iter()
                .map(|(identity, record)| (*identity, record.clone()))
                .collect(),
            device_nonce: self.device_nonce,
        };
        let bytes = cbor2::to_vec(&wire).map_err(|_| SnapshotError::Invalid)?;
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(SnapshotError::TooLarge);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SnapshotError> {
        if bytes.len() > MAX_SNAPSHOT_BYTES {
            return Err(SnapshotError::TooLarge);
        }
        let mut cursor = std::io::Cursor::new(bytes);
        let wire: SnapshotWire =
            cbor2::from_reader(&mut cursor).map_err(|_| SnapshotError::Malformed)?;
        if (cursor.position() as usize) != bytes.len() {
            return Err(SnapshotError::Malformed);
        }
        if wire.version != SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion(wire.version));
        }
        if wire.stores.is_empty()
            || wire.stores.len() > crate::session::installation::MAX_IDENTITIES_CEILING
        {
            return Err(SnapshotError::Invalid);
        }
        let mut contacts = BTreeMap::new();
        let mut total_contacts = 0usize;
        let mut total_seen_transcripts = 0usize;
        for store in wire.stores {
            let identity = store.local_identity;
            total_contacts = total_contacts.saturating_add(store.contacts.len());
            total_seen_transcripts =
                total_seen_transcripts.saturating_add(store.seen_transcripts.len());
            let store = ContactStore::from_wire(store).map_err(|_| SnapshotError::Invalid)?;
            if contacts.insert(identity, store).is_some() {
                return Err(SnapshotError::Invalid);
            }
        }
        if total_contacts > crate::session::installation::MAX_INSTALLATION_CONTACTS {
            return Err(SnapshotError::Invalid);
        }
        if total_seen_transcripts > crate::contact::MAX_SEEN_TRANSCRIPTS {
            return Err(SnapshotError::Invalid);
        }
        if wire.roster_locks.len() > crate::session::installation::roster_locks::MAX_ROSTER_LOCKS {
            return Err(SnapshotError::Invalid);
        }
        if !contacts.contains_key(&wire.selected) {
            return Err(SnapshotError::Invalid);
        }
        let mut voting = BTreeMap::new();
        for (identity, record) in wire.voting {
            if !contacts.contains_key(&identity) || voting.insert(identity, record).is_some() {
                return Err(SnapshotError::Invalid);
            }
        }
        let mut historical_voting = BTreeMap::new();
        for (identity, record) in wire.historical_voting {
            if contacts.contains_key(&identity)
                || historical_voting.insert(identity, record).is_some()
            {
                return Err(SnapshotError::Invalid);
            }
        }
        if contacts.len() + historical_voting.len()
            > crate::session::installation::MAX_IDENTITIES_CEILING
        {
            return Err(SnapshotError::Invalid);
        }
        let roster_unconfirmed: BTreeSet<Identity> = wire.roster_unconfirmed.into_iter().collect();
        if roster_unconfirmed
            .iter()
            .any(|id| !contacts.contains_key(id))
        {
            return Err(SnapshotError::Invalid);
        }
        Ok(Self {
            selected: wire.selected,
            contacts,
            policy: wire.policy,
            #[cfg(feature = "openpgp")]
            openpgp_revocations: Default::default(),
            roster_locks: wire.roster_locks,
            roster_signing_disabled: wire.roster_signing_disabled,
            roster_unconfirmed,
            handoff_sequence: wire.handoff_sequence,
            voting,
            historical_voting,
            device_nonce: wire.device_nonce,
        })
    }
}

impl super::Installation {
    /// Save without consuming the installation: the same document `into_snapshot(now)` followed
    /// by `to_bytes` would give. The installation stays usable.
    pub fn save_bytes(&mut self, now: u64) -> Result<Vec<u8>, SnapshotError> {
        self.expire(now);
        self.current.sync_policy_to_store(now);
        let copy = |store: &ContactStore| {
            ContactStore::from_wire(store.to_wire()).map_err(|_| SnapshotError::Invalid)
        };
        let mut contacts = BTreeMap::new();
        for (id, persona) in &self.inactive {
            contacts.insert(*id, copy(&persona.contacts)?);
        }
        contacts.insert(self.selected(), copy(&self.current.contacts)?);
        InstallationSnapshot {
            selected: self.selected(),
            contacts,
            policy: self.current.contacts.attempt_policy_state(),
            #[cfg(feature = "openpgp")]
            openpgp_revocations: Default::default(),
            roster_locks: self
                .roster_locks
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .clone(),
            roster_signing_disabled: self.roster_signing_disabled,
            roster_unconfirmed: self.roster_unconfirmed.clone(),
            handoff_sequence: self.handoff_sequence,
            voting: self.voting.clone(),
            historical_voting: self.historical_voting.clone(),
            device_nonce: self.device_nonce,
        }
        .to_bytes_checked(
            #[cfg(feature = "openpgp")]
            self.openpgp_revocations.is_empty(),
        )
    }

    /// Restart from bytes written by `save_bytes` or `to_bytes`. Pure: a refusal changes nothing.
    pub fn restore_bytes(
        bytes: &[u8],
        keys: impl IntoIterator<Item = ed25519_dalek::SigningKey>,
    ) -> Result<Self, SnapshotError> {
        let snapshot = InstallationSnapshot::from_bytes(bytes)?;
        Self::restore(snapshot, keys).map_err(|_| SnapshotError::Invalid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::installation::{Error, Installation};
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// An installation with locks, a voting counter and a second identity, snapshotted.
    fn busy_snapshot() -> InstallationSnapshot {
        let mut i = Installation::new(key(7));
        i.sign_group_roster_vote_durable(1, [1; 32], [11; 32], 1, 1, |_, _| Ok(()))
            .unwrap();
        i.sign_group_roster_vote_durable(2, [2; 32], [12; 32], 1, 1, |_, _| Ok(()))
            .unwrap();
        i.begin_handoff([9; 32], |_, _| Ok(())).unwrap();
        i.into_snapshot(0)
    }

    #[test]
    fn a_snapshot_saves_to_the_same_bytes_every_time_and_round_trips() {
        let snapshot = busy_snapshot();
        let bytes = snapshot.to_bytes().unwrap();
        assert_eq!(bytes, snapshot.to_bytes().unwrap());
        let restored = InstallationSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(bytes, restored.to_bytes().unwrap());
        let mut installation = Installation::restore(restored, [key(7)]).unwrap();
        // The restored locks still refuse a conflicting second vote, and the handoff stop holds.
        assert_eq!(
            installation
                .sign_group_roster_vote_durable(1, [1; 32], [99; 32], 1, 1, |_, _| Ok(()))
                .map(|_| ()),
            Err(Error::NotVotingDevice)
        );
    }

    #[test]
    fn save_bytes_matches_the_consuming_snapshot_and_keeps_the_installation_usable() {
        let mut i = Installation::new(key(7));
        i.sign_group_roster_vote_durable(1, [1; 32], [11; 32], 1, 1, |_, _| Ok(()))
            .unwrap();
        let saved = i.save_bytes(0).unwrap();
        // Still signs; the lock from before the save still refuses a conflicting child.
        assert!(
            i.sign_group_roster_vote_durable(1, [1; 32], [12; 32], 1, 1, |_, _| Ok(()))
                .is_err()
        );
        assert_eq!(saved, i.into_snapshot(0).to_bytes().unwrap());
        assert!(Installation::restore_bytes(&saved, [key(7)]).is_ok());
        assert!(Installation::restore_bytes(&saved, [key(8)]).is_err());
    }

    #[test]
    fn a_failed_write_leaves_the_last_blob_restorable() {
        let first = busy_snapshot().to_bytes().unwrap();
        // The host's write of a newer blob fails; it still holds `first`.
        let held = first.clone();
        assert!(InstallationSnapshot::from_bytes(&held).is_ok());
    }

    #[test]
    fn unknown_versions_trailing_bytes_and_oversize_are_refused() {
        let bytes = busy_snapshot().to_bytes().unwrap();
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            InstallationSnapshot::from_bytes(&trailing).err(),
            Some(SnapshotError::Malformed)
        );
        assert_eq!(
            InstallationSnapshot::from_bytes(&vec![0; MAX_SNAPSHOT_BYTES + 1]).err(),
            Some(SnapshotError::TooLarge)
        );
        // Rewrite the version through the wire type.
        let mut wire: SnapshotWire = cbor2::from_reader(&bytes[..]).unwrap();
        wire.version = 2;
        let future = cbor2::to_vec(&wire).unwrap();
        assert_eq!(
            InstallationSnapshot::from_bytes(&future).err(),
            Some(SnapshotError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn every_truncation_and_bit_flip_is_handled_without_panic() {
        let bytes = busy_snapshot().to_bytes().unwrap();
        for len in 0..bytes.len() {
            assert!(InstallationSnapshot::from_bytes(&bytes[..len]).is_err());
        }
        for index in 0..bytes.len() {
            for bit in 0..8 {
                let mut damaged = bytes.clone();
                damaged[index] ^= 1 << bit;
                if let Ok(snapshot) = InstallationSnapshot::from_bytes(&damaged) {
                    // Whatever parses must itself save and restore cleanly.
                    let again = snapshot.to_bytes().unwrap();
                    assert!(InstallationSnapshot::from_bytes(&again).is_ok());
                }
            }
        }
    }

    #[test]
    fn a_selected_identity_without_a_store_is_invalid() {
        let bytes = busy_snapshot().to_bytes().unwrap();
        let mut wire: SnapshotWire = cbor2::from_reader(&bytes[..]).unwrap();
        wire.selected = [5; 32];
        let out = cbor2::to_vec(&wire).unwrap();
        assert_eq!(
            InstallationSnapshot::from_bytes(&out).err(),
            Some(SnapshotError::Invalid)
        );
    }
}
