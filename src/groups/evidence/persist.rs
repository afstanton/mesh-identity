//! The saved form of a group.
//!
//! One versioned CBOR document holds the group, the whole roster chain from its root to its
//! head (`catch_up` walks ancestors, so the chain length must equal the revision), and every
//! side table. Bytes are deterministic. Reading is a pure function that refuses anything the
//! group itself could not have produced. The bytes carry no signature or MAC: they are local
//! state, and keeping them intact and current is the host's job.

use super::{CarriedProof, EquivocationProof, Key, RosterHistory, VouchedGroup, VoucherId};
use crate::groups::{Group, Identity, Policy};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub const GROUP_FORMAT_VERSION: u8 = 1;
/// Largest saved group this build will parse.
pub const MAX_GROUP_BYTES: usize = 32 * 1024 * 1024;
/// Longest roster chain accepted.
const MAX_CHAIN: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupSnapshotError {
    Malformed,
    UnsupportedVersion(u8),
    TooLarge,
    /// Well formed, but not a state a group could have saved.
    Invalid,
}

#[derive(Serialize, Deserialize)]
enum CarriedWire {
    Equivocation {
        signer: Key,
        group: u64,
        parent: [u8; 32],
        round: u32,
        phase: u8,
        first: ([u8; 32], Vec<u8>),
        second: ([u8; 32], Vec<u8>),
    },
    SimulationReport(Key),
}

#[derive(Serialize, Deserialize)]
struct NodeWire {
    id: [u8; 32],
    carried: Vec<CarriedWire>,
    new_reports: Vec<Key>,
    new_recognitions: Vec<(Key, u64, [u8; 32])>,
}

#[derive(Serialize, Deserialize)]
struct GroupWire {
    version: u8,
    id: u64,
    revision: u64,
    roster: Vec<(u64, u64)>,
    policy: Vec<u8>,
    excluded: Vec<u64>,
    /// Root first, head last.
    chain: Vec<NodeWire>,
    identities: Vec<(Key, u64)>,
    now: u64,
    cancelled_invitations: Vec<([u8; 32], u64)>,
    withdrawn: Vec<(Key, VoucherId)>,
    admission_evidence: Vec<(Key, VoucherId)>,
    predecessors: Vec<(Key, Key)>,
    key_replacements: Vec<(Key, Key)>,
    retired: Vec<Key>,
    suspect: Vec<Key>,
    recovery_witnesses: Vec<(u64, [Key; 2])>,
    recovery_commitments: Vec<(u64, [u8; 32])>,
    recovery_salts: Vec<(u64, [u8; 32])>,
    degraded_recovery: Vec<u64>,
}

fn pairs<K: Copy, V: Copy>(map: &BTreeMap<K, V>) -> Vec<(K, V)> {
    map.iter().map(|(k, v)| (*k, *v)).collect()
}

/// Collect into a map and refuse a repeated key.
fn unique<K: Ord, V>(items: Vec<(K, V)>) -> Result<BTreeMap<K, V>, GroupSnapshotError> {
    let count = items.len();
    let map: BTreeMap<K, V> = items.into_iter().collect();
    if map.len() == count {
        Ok(map)
    } else {
        Err(GroupSnapshotError::Invalid)
    }
}

fn unique_set<K: Ord>(items: Vec<K>) -> Result<BTreeSet<K>, GroupSnapshotError> {
    let count = items.len();
    let set: BTreeSet<K> = items.into_iter().collect();
    if set.len() == count {
        Ok(set)
    } else {
        Err(GroupSnapshotError::Invalid)
    }
}

impl VouchedGroup {
    pub fn member_keys(&self) -> Vec<Key> {
        self.identities
            .keys()
            .copied()
            .filter(|key| self.membership(*key).is_some())
            .collect()
    }

    /// Public, deterministic state for comparison with a certificate replay. Never includes
    /// local time, cancellation/withdrawal knowledge or private recovery openings.
    pub(crate) fn public_bytes(&self) -> Result<Vec<u8>, GroupSnapshotError> {
        let mut public = self.clone();
        public.now = 0;
        public.cancelled_invitations.clear();
        public.withdrawn.clear();
        public.recovery_witnesses.clear();
        public.recovery_salts.clear();
        public.degraded_recovery.clear();
        public.to_bytes()
    }

    /// Deterministic bytes: the same group always saves to the same document.
    pub fn to_bytes(&self) -> Result<Vec<u8>, GroupSnapshotError> {
        let mut chain = Vec::new();
        let mut node = Some(&self.history);
        while let Some(current) = node {
            chain.push(NodeWire {
                id: current.id,
                carried: current
                    .carried
                    .iter()
                    .map(|proof| match proof {
                        CarriedProof::Equivocation(p) => CarriedWire::Equivocation {
                            signer: p.signer,
                            group: p.group,
                            parent: p.parent,
                            round: p.round,
                            phase: p.phase,
                            first: (p.first.0, p.first.1.to_vec()),
                            second: (p.second.0, p.second.1.to_vec()),
                        },
                        CarriedProof::SimulationReport(key) => CarriedWire::SimulationReport(*key),
                    })
                    .collect(),
                new_reports: current.new_reports.clone(),
                new_recognitions: current.new_recognitions.clone(),
            });
            node = current.parent.as_ref();
        }
        chain.reverse();
        let ids = |m: &BTreeMap<Identity, [u8; 32]>| -> Vec<(u64, [u8; 32])> {
            m.iter().map(|(k, v)| (k.0, *v)).collect()
        };
        let wire = GroupWire {
            version: GROUP_FORMAT_VERSION,
            id: self.group.id,
            revision: self.group.revision,
            roster: self.group.roster.iter().map(|(k, v)| (k.0, *v)).collect(),
            policy: self.group.policy.encode(),
            excluded: self.group.excluded.iter().map(|k| k.0).collect(),
            chain,
            identities: self.identities.iter().map(|(k, v)| (*k, v.0)).collect(),
            now: self.now,
            cancelled_invitations: pairs(&self.cancelled_invitations),
            withdrawn: self.withdrawn.iter().copied().collect(),
            admission_evidence: pairs(&self.admission_evidence),
            predecessors: pairs(&self.predecessors),
            key_replacements: pairs(&self.key_replacements),
            retired: self.retired.iter().copied().collect(),
            suspect: self.suspect.iter().copied().collect(),
            recovery_witnesses: self
                .recovery_witnesses
                .iter()
                .map(|(k, v)| (k.0, *v))
                .collect(),
            recovery_commitments: ids(&self.recovery_commitments),
            recovery_salts: ids(&self.recovery_salts),
            degraded_recovery: self.degraded_recovery.iter().map(|k| k.0).collect(),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&wire, &mut bytes).map_err(|_| GroupSnapshotError::Invalid)?;
        if bytes.len() > MAX_GROUP_BYTES {
            return Err(GroupSnapshotError::TooLarge);
        }
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, GroupSnapshotError> {
        use GroupSnapshotError::*;
        if bytes.len() > MAX_GROUP_BYTES {
            return Err(TooLarge);
        }
        let mut input = bytes;
        let wire: GroupWire = ciborium::from_reader(&mut input).map_err(|_| Malformed)?;
        if !input.is_empty() {
            return Err(Malformed);
        }
        if wire.version != GROUP_FORMAT_VERSION {
            return Err(UnsupportedVersion(wire.version));
        }
        // The chain must be exactly as deep as the revision says.
        if wire.chain.is_empty()
            || wire.chain.len() > MAX_CHAIN
            || wire.chain.len() as u64 != wire.revision.checked_add(1).ok_or(Invalid)?
        {
            return Err(Invalid);
        }
        let policy = Policy::decode(&wire.policy).ok_or(Invalid)?;
        let roster: BTreeMap<Identity, u64> = unique(
            wire.roster
                .into_iter()
                .map(|(k, v)| (Identity(k), v))
                .collect(),
        )?;
        if roster.values().any(|&joined| joined > wire.revision) {
            return Err(Invalid);
        }
        let excluded: BTreeSet<Identity> =
            unique_set(wire.excluded.into_iter().map(Identity).collect())?;
        if !excluded.iter().all(|id| roster.contains_key(id)) {
            return Err(Invalid);
        }
        let identities: BTreeMap<Key, Identity> = unique(
            wire.identities
                .into_iter()
                .map(|(k, v)| (k, Identity(v)))
                .collect(),
        )?;
        // Each identity number belongs to one key, and every roster member has a key.
        let numbers: BTreeSet<Identity> = identities.values().copied().collect();
        if numbers.len() != identities.len() || !roster.keys().all(|id| numbers.contains(id)) {
            return Err(Invalid);
        }
        let mut history: Option<Arc<RosterHistory>> = None;
        for (index, node) in wire.chain.into_iter().enumerate() {
            let carried = node
                .carried
                .into_iter()
                .map(|proof| match proof {
                    CarriedWire::Equivocation {
                        signer,
                        group,
                        parent,
                        round,
                        phase,
                        first,
                        second,
                    } => Ok(CarriedProof::Equivocation(Box::new(EquivocationProof {
                        signer,
                        group,
                        parent,
                        round,
                        phase,
                        first: (first.0, first.1.try_into().map_err(|_| Invalid)?),
                        second: (second.0, second.1.try_into().map_err(|_| Invalid)?),
                    }))),
                    CarriedWire::SimulationReport(key) => Ok(CarriedProof::SimulationReport(key)),
                })
                .collect::<Result<Vec<_>, GroupSnapshotError>>()?;
            history = Some(match history {
                None if index == 0 => {
                    if !carried.is_empty()
                        || !node.new_reports.is_empty()
                        || !node.new_recognitions.is_empty()
                    {
                        return Err(Invalid);
                    }
                    RosterHistory::root(node.id)
                }
                Some(parent) => RosterHistory::child(
                    &parent,
                    node.id,
                    carried,
                    node.new_reports,
                    node.new_recognitions,
                ),
                None => return Err(Invalid),
            });
        }
        let history = history.ok_or(Invalid)?;
        let by_identity = |items: Vec<(u64, [u8; 32])>| {
            unique(items.into_iter().map(|(k, v)| (Identity(k), v)).collect())
        };
        let group = Group {
            id: wire.id,
            revision: wire.revision,
            roster,
            policy,
            excluded,
        };
        let group = Self {
            group,
            history,
            identities,
            now: wire.now,
            cancelled_invitations: unique(wire.cancelled_invitations)?,
            withdrawn: unique_set(wire.withdrawn)?,
            admission_evidence: unique(wire.admission_evidence)?,
            predecessors: unique(wire.predecessors)?,
            key_replacements: unique(wire.key_replacements)?,
            retired: unique_set(wire.retired)?,
            suspect: unique_set(wire.suspect)?,
            recovery_witnesses: unique(
                wire.recovery_witnesses
                    .into_iter()
                    .map(|(k, v)| (Identity(k), v))
                    .collect(),
            )?,
            recovery_commitments: by_identity(wire.recovery_commitments)?,
            recovery_salts: by_identity(wire.recovery_salts)?,
            degraded_recovery: unique_set(
                wire.degraded_recovery.into_iter().map(Identity).collect(),
            )?,
        };
        Ok(group)
    }
}
