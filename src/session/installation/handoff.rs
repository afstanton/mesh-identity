//! Voting-device handoff for one identity across all its groups.
//!
//! One identity may live on several devices, but only one signs at a time. Each identity has a
//! monotonic counter and a state on this device: *Voting*, *Stopped* (handed off) or *Gated*
//! (may not sign). An acknowledged handoff is: the old device durably stops and exports a signed
//! bundle of every group's lock checkpoint; the new device authenticates the whole bundle, merges
//! the locks, and only then becomes *Voting*.
//!
//! The seam to the group layer is deliberately narrow: a participant is a `u64` id (the group)
//! with an opaque, versioned checkpoint. The core signs and verifies the manifest of those
//! checkpoints and never interprets them; only `export_checkpoints` and `import_checkpoints`
//! below know that the participant is the roster lock table.

use super::roster_locks::{self, RosterLockTable, RosterParentLocks};
use super::{Error, Identity, Installation, InstallationSnapshot};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

const STATEMENT_DOMAIN: &[u8] = b"mesh/identity/handoff-statement/v1\0";
const ENVELOPE_DOMAIN: &[u8] = b"mesh/identity/handoff-envelope/v1\0";
const CHECKPOINT_VERSION: u8 = 1;
const RECORD_VERSION: u8 = 2;

pub const MAX_HANDOFF_BUNDLE_BYTES: usize = 5 * 1024 * 1024; // 5 MiB
pub const MAX_CHECKPOINTS_PER_BUNDLE: usize = 2_048;
pub const MAX_CHECKPOINT_BYTES: usize = 64 * 1024; // 64 KiB

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VotingState {
    /// This device signs for the identity.
    Voting,
    /// This device handed the role off and must never sign again at this counter.
    Stopped,
    /// This device may not sign until a handoff or recognition raises its counter.
    Gated,
}

/// What this device knows about one identity's voting role.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VotingRecord {
    pub counter: u64,
    pub state: VotingState,
    /// The device nonce the counter was granted to (`None` before any handoff).
    #[serde(with = "crate::cbor::byte_seq::opt_array32")]
    pub holder: Option<[u8; 32]>,
}

impl Default for VotingRecord {
    /// An identity with no handoff history keeps signing as before the handoff existed.
    fn default() -> Self {
        Self {
            counter: 0,
            state: VotingState::Voting,
            holder: None,
        }
    }
}

/// A takeover claim: this device asks groups to recognize `counter` for its `nonce`. It is the
/// same signed statement a handoff bundle carries, so it proves nothing by itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TakeoverStatement {
    pub identity: Identity,
    pub counter: u64,
    pub nonce: [u8; 32],
    pub signature: [u8; 64],
}

/// One participant's frozen state: an id, a format version and opaque bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffCheckpoint {
    pub participant: u64,
    pub version: u8,
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

/// The signed transfer from the old device to the new one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoffBundle {
    #[serde(with = "crate::cbor::byte_seq::array32")]
    identity: Identity,
    counter: u64,
    #[serde(with = "crate::cbor::byte_seq::array32")]
    recipient: [u8; 32],
    /// Signature over `(identity, counter, recipient)`: the public "play here now" statement.
    #[serde(with = "serde_bytes")]
    statement_signature: Vec<u8>,
    /// Signature over the statement, the recipient and the complete checkpoint manifest.
    #[serde(with = "serde_bytes")]
    envelope_signature: Vec<u8>,
    checkpoints: Vec<HandoffCheckpoint>,
}

impl HandoffBundle {
    pub fn identity(&self) -> Identity {
        self.identity
    }

    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// The public grant statement, suitable for certified recognition in a group.
    /// This only decodes the signature; the receiving group authenticates it.
    pub fn statement(&self) -> Result<TakeoverStatement, Error> {
        Ok(TakeoverStatement {
            identity: self.identity,
            counter: self.counter,
            nonce: self.recipient,
            signature: self
                .statement_signature
                .as_slice()
                .try_into()
                .map_err(|_| Error::InvalidHandoff)?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        cbor2::to_vec(self).expect("bundle encodes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_HANDOFF_BUNDLE_BYTES {
            return Err(Error::InvalidHandoff);
        }
        let mut cursor = std::io::Cursor::new(bytes);
        let bundle: Self = cbor2::from_reader(&mut cursor).map_err(|_| Error::InvalidHandoff)?;
        if (cursor.position() as usize) != bytes.len() {
            return Err(Error::InvalidHandoff);
        }
        if bundle.checkpoints.len() > MAX_CHECKPOINTS_PER_BUNDLE {
            return Err(Error::InvalidHandoff);
        }
        for cp in &bundle.checkpoints {
            if cp.bytes.len() > MAX_CHECKPOINT_BYTES {
                return Err(Error::InvalidHandoff);
            }
        }
        Ok(bundle)
    }
}

/// What the identity key signs to say "play here now" for a device: the statement of a handoff
/// bundle and of a takeover alike. Groups verify it when they recognize a takeover.
pub fn handoff_statement_message(identity: Identity, counter: u64, device: [u8; 32]) -> Vec<u8> {
    statement_message(identity, counter, device)
}

fn statement_message(identity: Identity, counter: u64, recipient: [u8; 32]) -> Vec<u8> {
    let mut message = STATEMENT_DOMAIN.to_vec();
    message.extend_from_slice(&identity);
    message.extend_from_slice(&counter.to_be_bytes());
    message.extend_from_slice(&recipient);
    message
}

/// The signed envelope binds the identity, counter, recipient, statement and the complete
/// manifest: every participant id, version, byte length and hash of the exact bytes, and the
/// number of entries. Removing, replacing, adding or reordering a checkpoint changes it.
fn envelope_message(
    identity: Identity,
    counter: u64,
    recipient: [u8; 32],
    statement_signature: &[u8],
    checkpoints: &[HandoffCheckpoint],
) -> Vec<u8> {
    let mut message = ENVELOPE_DOMAIN.to_vec();
    message.extend_from_slice(&identity);
    message.extend_from_slice(&counter.to_be_bytes());
    message.extend_from_slice(&recipient);
    message.extend_from_slice(statement_signature);
    message.extend_from_slice(&(checkpoints.len() as u32).to_be_bytes());
    for checkpoint in checkpoints {
        message.extend_from_slice(&checkpoint.participant.to_be_bytes());
        message.push(checkpoint.version);
        message.extend_from_slice(&(checkpoint.bytes.len() as u64).to_be_bytes());
        message.extend_from_slice(&Sha256::digest(&checkpoint.bytes));
    }
    message
}

type GroupEntries = Vec<([u8; 32], RosterParentLocks)>;

/// The roster-lock participant: one checkpoint per group, holding only this identity's locks.
fn export_checkpoints(table: &RosterLockTable, identity: Identity) -> Vec<HandoffCheckpoint> {
    let mut by_group: BTreeMap<u64, GroupEntries> = BTreeMap::new();
    for ((group, parent), locks) in table {
        let entry = match locks {
            RosterParentLocks::Retired => RosterParentLocks::Retired,
            RosterParentLocks::Active(identities) => {
                let Some(own) = identities.get(&identity) else {
                    continue;
                };
                RosterParentLocks::Active(BTreeMap::from([(identity, own.clone())]))
            }
        };
        by_group.entry(*group).or_default().push((*parent, entry));
    }
    by_group
        .into_iter()
        .map(|(participant, entries)| {
            let bytes = cbor2::to_vec(&entries).expect("checkpoint encodes");
            HandoffCheckpoint {
                participant,
                version: CHECKPOINT_VERSION,
                bytes,
            }
        })
        .collect()
}

/// Decode and validate every checkpoint before anything is merged.
fn import_checkpoints(
    checkpoints: &[HandoffCheckpoint],
    identity: Identity,
) -> Result<RosterLockTable, Error> {
    if checkpoints.len() > MAX_CHECKPOINTS_PER_BUNDLE {
        return Err(Error::InvalidHandoff);
    }
    let mut table = RosterLockTable::new();
    let mut previous = None;
    for checkpoint in checkpoints {
        if checkpoint.bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(Error::InvalidHandoff);
        }
        if previous.is_some_and(|p| p >= checkpoint.participant) {
            return Err(Error::InvalidHandoff);
        }
        previous = Some(checkpoint.participant);
        if checkpoint.version != CHECKPOINT_VERSION {
            return Err(Error::InvalidHandoff);
        }
        let mut cursor = std::io::Cursor::new(checkpoint.bytes.as_slice());
        let entries: GroupEntries =
            cbor2::from_reader(&mut cursor).map_err(|_| Error::InvalidHandoff)?;
        if (cursor.position() as usize) != checkpoint.bytes.len() {
            return Err(Error::InvalidHandoff);
        }
        for (parent, locks) in entries {
            if let RosterParentLocks::Active(identities) = &locks
                && identities.keys().any(|signer| *signer != identity)
            {
                return Err(Error::InvalidHandoff);
            }
            if table
                .insert((checkpoint.participant, parent), locks)
                .is_some()
            {
                return Err(Error::InvalidHandoff);
            }
        }
    }
    Ok(table)
}

/// A permission names the exact parent and the identity's current counter and holder.
pub(super) type GroupPermit = (Identity, u64, [u8; 32], u64, [u8; 32]);

/// Complete installation-wide signing state. A latest record must recover earlier
/// handoffs of other identities as well as the transaction that wrote this record.
#[derive(Serialize, Deserialize)]
struct HandoffRecord {
    version: u8,
    sequence: u64,
    #[serde(with = "crate::cbor::byte_seq::opt_array32")]
    device_nonce: Option<[u8; 32]>,
    #[serde(with = "handoff_wire_voting")]
    voting: BTreeMap<Identity, VotingRecord>,
    #[serde(with = "crate::cbor::byte_seq::btreeset_array32")]
    unconfirmed: BTreeSet<Identity>,
    conflict: bool,
    locks: RosterLockTable,
}

mod handoff_wire_voting {
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
        map: &BTreeMap<Identity, VotingRecord>,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(map.len()))?;
        for (identity, record) in map {
            seq.serialize_element(&ItemRef {
                identity: *identity,
                record,
            })?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<BTreeMap<Identity, VotingRecord>, D::Error> {
        let items: Vec<ItemOwned> = Deserialize::deserialize(d)?;
        Ok(items
            .into_iter()
            .map(|item| (item.identity, item.record))
            .collect())
    }
}

fn newer(current: &VotingRecord, incoming: &VotingRecord) -> VotingRecord {
    if current.counter != incoming.counter {
        return if incoming.counter > current.counter {
            incoming
        } else {
            current
        }
        .clone();
    }
    // At one counter a stopped grant must never revive. Two different holders are
    // ambiguous, even if both records otherwise say Voting.
    if current.state == VotingState::Stopped {
        return current.clone();
    }
    if incoming.state == VotingState::Stopped {
        return incoming.clone();
    }
    if current.holder != incoming.holder {
        return VotingRecord {
            counter: current.counter,
            state: VotingState::Gated,
            holder: None,
        };
    }
    if current.state == VotingState::Gated {
        current
    } else {
        incoming
    }
    .clone()
}

impl HandoffRecord {
    fn to_bytes(&self) -> Vec<u8> {
        cbor2::to_vec(self).expect("record encodes")
    }
}

impl Installation {
    /// This device's random nonce, created on first use and kept in snapshots. A new device
    /// gives it to the old device so the bundle can be addressed to it alone.
    pub fn device_nonce(&mut self, rng: &mut (impl CryptoRng + RngCore)) -> [u8; 32] {
        *self.device_nonce.get_or_insert_with(|| {
            let mut nonce = [0; 32];
            rng.fill_bytes(&mut nonce);
            nonce
        })
    }

    /// The voting record for an owned or unknown identity (the default is a plain voter).
    pub fn voting_record(&self, identity: Identity) -> VotingRecord {
        self.voting
            .get(&identity)
            .or_else(|| self.historical_voting.get(&identity))
            .cloned()
            .unwrap_or_default()
    }

    pub fn voting_state(&self) -> VotingState {
        self.voting_record(self.selected()).state
    }

    /// Put every owned identity that has no handoff history in *Gated*: this device must be given
    /// the voting role by a handoff before it signs. (Restoring from a backup will call this.)
    pub fn gate_voting(&mut self) {
        self.group_permits
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
        let owned: Vec<Identity> = std::iter::once(self.selected())
            .chain(self.inactive.keys().copied())
            .collect();
        for identity in owned {
            let record = self.voting.entry(identity).or_default();
            if record.state == VotingState::Voting {
                record.state = VotingState::Gated;
            }
        }
    }

    pub(super) fn require_voting(&self) -> Result<(), Error> {
        if self.voting_allows(self.selected()) {
            Ok(())
        } else {
            Err(Error::NotVotingDevice)
        }
    }

    pub(super) fn require_voting_in(&self, group: u64, parent: [u8; 32]) -> Result<(), Error> {
        if self.voting_allows_in(self.selected(), group, parent) {
            Ok(())
        } else {
            Err(Error::NotVotingDevice)
        }
    }

    fn permission(&self, identity: Identity, group: u64, parent: [u8; 32]) -> Option<GroupPermit> {
        let record = self.voting_record(identity);
        if record.state == VotingState::Stopped {
            return None;
        }
        let holder = record.holder?;
        (self.device_nonce == Some(holder)).then_some((
            identity,
            group,
            parent,
            record.counter,
            holder,
        ))
    }

    fn has_parent_permit(&self, identity: Identity, group: u64, parent: [u8; 32]) -> bool {
        self.permission(identity, group, parent)
            .is_some_and(|permit| {
                self.group_permits
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .contains(&permit)
            })
    }

    pub(super) fn voting_allows_in(
        &self,
        identity: Identity,
        group: u64,
        parent: [u8; 32],
    ) -> bool {
        match self.voting_record(identity).state {
            VotingState::Voting => true,
            VotingState::Stopped => false,
            VotingState::Gated => self.has_parent_permit(identity, group, parent),
        }
    }

    // A departure signs a stable membership tenure, not a roster parent. A current
    // grant permission can authorize leaving, but cannot authorize quorum votes elsewhere.
    pub(super) fn require_voting_for_group(&self, group: u64) -> Result<(), Error> {
        let identity = self.selected();
        let record = self.voting_record(identity);
        let allowed = record.state == VotingState::Voting
            || (record.state == VotingState::Gated
                && self
                    .group_permits
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .iter()
                    .any(|permit| {
                        permit.0 == identity
                            && permit.1 == group
                            && permit.3 == record.counter
                            && Some(permit.4) == record.holder
                            && Some(permit.4) == self.device_nonce
                    }));
        if allowed {
            Ok(())
        } else {
            Err(Error::NotVotingDevice)
        }
    }

    pub(super) fn require_current_roster_state(
        &self,
        identity: Identity,
        group: u64,
        parent: [u8; 32],
    ) -> Result<(), Error> {
        if self.roster_signing_disabled
            || (self.roster_unconfirmed.contains(&identity)
                && !self.has_parent_permit(identity, group, parent))
        {
            Err(Error::RosterSigningStateUnconfirmed)
        } else {
            Ok(())
        }
    }

    pub fn current_device_nonce(&self) -> Option<[u8; 32]> {
        self.device_nonce
    }

    /// The group layer must authenticate this exact parent and recognize the current
    /// counter and nonce before calling this. Permissions are never persisted.
    pub fn permit_group(&self, group: u64, parent: [u8; 32]) {
        if let Some(permit) = self.permission(self.selected(), group, parent) {
            self.group_permits
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(permit);
        }
    }

    pub fn revoke_group(&self, group: u64) {
        let identity = self.selected();
        self.group_permits
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(owner, permitted_group, ..)| *owner != identity || *permitted_group != group);
    }

    /// Claim the voting role without the old device. The device must be gated. It picks a
    /// counter above anything it knows (and above `floor`, the highest counter a group has told
    /// it about), keeps it as its own grant, and returns the signed statement for groups to
    /// recognize. It signs nowhere until a group recognizes exactly this counter and nonce.
    pub fn begin_takeover(
        &mut self,
        rng: &mut (impl CryptoRng + RngCore),
        floor: u64,
    ) -> Result<TakeoverStatement, Error> {
        let identity = self.selected();
        let current = self.voting_record(identity);
        if current.state != VotingState::Gated {
            return Err(Error::NotGated);
        }
        let counter = current
            .counter
            .max(floor)
            .checked_add(1)
            .ok_or(Error::CounterExhausted)?;
        let nonce = self.device_nonce(rng);
        let signature = self
            .current
            .key
            .sign(&statement_message(identity, counter, nonce))
            .to_bytes();
        self.voting.insert(
            identity,
            VotingRecord {
                counter,
                state: VotingState::Gated,
                holder: Some(nonce),
            },
        );
        self.group_permits
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .retain(|(owner, ..)| *owner != identity);
        Ok(TakeoverStatement {
            identity,
            counter,
            nonce,
            signature,
        })
    }

    pub(super) fn voting_allows(&self, identity: Identity) -> bool {
        self.voting_record(identity).state == VotingState::Voting
    }

    fn owns(&self, identity: Identity) -> bool {
        self.selected() == identity || self.inactive.contains_key(&identity)
    }

    fn signing_key_for(&self, identity: Identity) -> Option<&SigningKey> {
        if self.selected() == identity {
            Some(&self.current.key)
        } else {
            self.inactive.get(&identity).map(|persona| &persona.key)
        }
    }

    fn handoff_record(
        &self,
        identity: Identity,
        voting: VotingRecord,
        locks: RosterLockTable,
        unconfirmed: BTreeSet<Identity>,
        conflict: bool,
    ) -> Result<HandoffRecord, Error> {
        let mut records: BTreeMap<_, _> = std::iter::once(self.selected())
            .chain(self.inactive.keys().copied())
            .map(|key| (key, self.voting_record(key)))
            .collect();
        records.insert(identity, voting);
        Ok(HandoffRecord {
            version: RECORD_VERSION,
            sequence: self
                .handoff_sequence
                .checked_add(1)
                .ok_or(Error::CounterExhausted)?,
            device_nonce: self.device_nonce,
            voting: records,
            unconfirmed,
            conflict,
            locks,
        })
    }

    /// Hand the selected identity's voting role to the device holding `recipient`.
    ///
    /// One transaction: the signed bundle and the stopped record go to `persist` together. If
    /// the write fails nothing changes and the device keeps voting; if it succeeds the device is
    /// *Stopped* and never signs for this identity again at this counter. Asking again after a
    /// success is refused: re-send the persisted bundle instead.
    pub fn begin_handoff(
        &mut self,
        recipient: [u8; 32],
        persist: impl FnOnce(&HandoffBundle, &[u8]) -> std::io::Result<()>,
    ) -> Result<HandoffBundle, Error> {
        let identity = self.selected();
        let current = self.voting_record(identity);
        if current.state != VotingState::Voting {
            return Err(Error::NotVotingDevice);
        }
        if self.roster_signing_disabled || self.roster_unconfirmed.contains(&identity) {
            return Err(Error::RosterSigningStateUnconfirmed);
        }
        let counter = current
            .counter
            .checked_add(1)
            .ok_or(Error::CounterExhausted)?;
        let key = self
            .signing_key_for(identity)
            .ok_or(Error::UnknownIdentity)?;
        let table = self
            .roster_locks
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let checkpoints = export_checkpoints(&table, identity);
        let statement_signature = key
            .sign(&statement_message(identity, counter, recipient))
            .to_bytes()
            .to_vec();
        let envelope_signature = key
            .sign(&envelope_message(
                identity,
                counter,
                recipient,
                &statement_signature,
                &checkpoints,
            ))
            .to_bytes()
            .to_vec();
        let bundle = HandoffBundle {
            identity,
            counter,
            recipient,
            statement_signature,
            envelope_signature,
            checkpoints,
        };
        let stopped = VotingRecord {
            counter,
            state: VotingState::Stopped,
            holder: Some(recipient),
        };
        let record = self.handoff_record(
            identity,
            stopped.clone(),
            table,
            self.roster_unconfirmed.clone(),
            self.roster_signing_disabled,
        )?;
        persist(&bundle, &record.to_bytes()).map_err(|_| Error::HandoffWriteFailed)?;
        self.handoff_sequence = record.sequence;
        self.voting.insert(identity, stopped);
        self.group_permits
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(owner, ..)| *owner != identity);
        Ok(bundle)
    }

    /// Take the voting role from a bundle addressed to this device.
    ///
    /// Everything is checked before anything changes: both signatures, the recipient, the
    /// counter, and each checkpoint against the signed manifest. Missing, extra, duplicate,
    /// reordered, modified or unsupported checkpoints are refused; a missing checkpoint is never
    /// read as an empty lock table. The merged locks and the new record go to `persist` in one
    /// write; if it fails nothing changes. A lock conflict leaves the device *Gated*.
    /// Importing the same bundle again while voting only re-merges locks.
    pub fn accept_handoff(
        &mut self,
        bundle: &HandoffBundle,
        persist: impl FnOnce(&[u8]) -> std::io::Result<()>,
    ) -> Result<VotingState, Error> {
        let identity = bundle.identity;
        if !self.owns(identity) {
            return Err(Error::InvalidHandoff);
        }
        let verifying = VerifyingKey::from_bytes(&identity).map_err(|_| Error::InvalidHandoff)?;
        let verify = |message: &[u8], signature: &[u8]| -> Result<(), Error> {
            let signature: [u8; 64] = signature.try_into().map_err(|_| Error::InvalidHandoff)?;
            verifying
                .verify(message, &ed25519_dalek::Signature::from_bytes(&signature))
                .map_err(|_| Error::InvalidHandoff)
        };
        verify(
            &statement_message(identity, bundle.counter, bundle.recipient),
            &bundle.statement_signature,
        )?;
        verify(
            &envelope_message(
                identity,
                bundle.counter,
                bundle.recipient,
                &bundle.statement_signature,
                &bundle.checkpoints,
            ),
            &bundle.envelope_signature,
        )?;
        if self.device_nonce != Some(bundle.recipient) {
            return Err(Error::WrongHandoffRecipient);
        }
        let incoming = import_checkpoints(&bundle.checkpoints, identity)?;
        let current = self.voting_record(identity);
        let same_grant = bundle.counter == current.counter
            && current.state == VotingState::Voting
            && current.holder == Some(bundle.recipient);
        if bundle.counter <= current.counter && !same_grant {
            return Err(Error::StaleHandoff);
        }
        let mut table = self
            .roster_locks
            .get_mut()
            .unwrap_or_else(|error| error.into_inner())
            .clone();
        let conflict = roster_locks::merge_checkpoint(&mut table, incoming);
        let voting = VotingRecord {
            counter: bundle.counter,
            state: if conflict {
                VotingState::Gated
            } else {
                VotingState::Voting
            },
            holder: Some(bundle.recipient),
        };
        let mut unconfirmed = self.roster_unconfirmed.clone();
        if !conflict {
            unconfirmed.remove(&identity);
        }
        let disabled = self.roster_signing_disabled || conflict;
        let record = self.handoff_record(
            identity,
            voting.clone(),
            table.clone(),
            unconfirmed.clone(),
            disabled,
        )?;
        persist(&record.to_bytes()).map_err(|_| Error::HandoffWriteFailed)?;
        *self
            .roster_locks
            .get_mut()
            .unwrap_or_else(|e| e.into_inner()) = table;
        self.handoff_sequence = record.sequence;
        self.roster_unconfirmed = unconfirmed;
        self.roster_signing_disabled = disabled;
        self.group_permits
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(owner, ..)| *owner != identity);
        let state = voting.state;
        self.voting.insert(identity, voting);
        Ok(state)
    }

    /// Restart from the latest authenticated local handoff record, never a portable backup.
    /// Version 2 covers every owned identity, local device nonce, backup uncertainty, conflict
    /// block and lock table. Older/incomplete formats and records older than the snapshot's
    /// handoff sequence fail closed. Locks and more restrictive snapshot roles are retained.
    pub fn restore_with_handoff_record(
        snapshot: InstallationSnapshot,
        keys: impl IntoIterator<Item = SigningKey>,
        record: &[u8],
    ) -> Result<Self, Error> {
        let record_bytes = record;
        let mut installation = Self::restore(snapshot, keys)?;
        let mut cursor = std::io::Cursor::new(record_bytes);
        let record: HandoffRecord =
            cbor2::from_reader(&mut cursor).map_err(|_| Error::InvalidHandoff)?;
        let owned: BTreeSet<_> = std::iter::once(installation.selected())
            .chain(installation.inactive.keys().copied())
            .collect();
        if record.version != RECORD_VERSION
            || (cursor.position() as usize) != record_bytes.len()
            || record.sequence < installation.handoff_sequence
            || record.voting.keys().copied().collect::<BTreeSet<_>>() != owned
            || !record.unconfirmed.is_subset(&owned)
            || matches!((installation.device_nonce, record.device_nonce), (Some(a), Some(b)) if a != b)
        {
            return Err(Error::InvalidHandoff);
        }
        let conflict = roster_locks::merge_checkpoint(
            installation
                .roster_locks
                .get_mut()
                .unwrap_or_else(|e| e.into_inner()),
            record.locks,
        );
        let mut unconfirmed = record.unconfirmed;
        for (identity, incoming) in record.voting {
            let current = installation.voting_record(identity);
            let merged = newer(&current, &incoming);
            if merged != incoming && installation.roster_unconfirmed.contains(&identity) {
                unconfirmed.insert(identity);
            }
            installation.voting.insert(identity, merged);
        }
        installation.roster_unconfirmed = unconfirmed;
        installation.roster_signing_disabled |= record.conflict || conflict;
        installation.handoff_sequence = record.sequence;
        if record.device_nonce.is_some() {
            installation.device_nonce = record.device_nonce;
        }
        Ok(installation)
    }
}

#[cfg(test)]
mod tests;
