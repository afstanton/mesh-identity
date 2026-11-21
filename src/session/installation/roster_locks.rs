//! Local signing constraints and checkpoint reconciliation for roster votes.

use super::{Error, Identity};
use std::collections::{BTreeMap, btree_map::Entry};

type Parent = (u64, [u8; 32]);

/// What an identity has already signed for one roster parent. These locks make a signer refuse
/// to contradict itself, whatever the caller asks, and must be persisted with the installation
/// before any signature leaves it.
#[derive(Clone, Default, Debug, serde::Serialize, serde::Deserialize)]
pub(super) struct RosterLocks {
    /// (round, phase) -> the child or claim already signed.
    signed: BTreeMap<(u32, u8), [u8; 32]>,
    /// A child this identity has committed to: it may only prepare or commit this one.
    commit: Option<(u32, [u8; 32])>,
    /// The highest round this identity asked to move to; it no longer votes in earlier rounds.
    change_round: u32,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub(super) enum RosterParentLocks {
    Active(BTreeMap<Identity, RosterLocks>),
    Retired,
}

impl Default for RosterParentLocks {
    fn default() -> Self {
        Self::Active(BTreeMap::new())
    }
}

pub(super) type RosterLockTable = BTreeMap<Parent, RosterParentLocks>;

/// Merge all known state. Report conflicting signatures without discarding
/// any locks on the remaining parents or identities.
pub(super) fn merge_checkpoint(current: &mut RosterLockTable, incoming: RosterLockTable) -> bool {
    let mut conflict = false;
    for (parent, incoming) in incoming {
        if let Some(existing) = current.get_mut(&parent) {
            conflict |= existing.merge(incoming);
        } else if current.len() < MAX_ROSTER_LOCKS {
            current.insert(parent, incoming);
        } else {
            conflict = true;
        }
    }
    conflict
}

impl RosterParentLocks {
    fn merge(&mut self, incoming: Self) -> bool {
        match (self, incoming) {
            (Self::Retired, _) => false,
            (slot, Self::Retired) => {
                *slot = Self::Retired;
                false
            }
            (Self::Active(current), Self::Active(incoming)) => {
                let mut conflict = false;
                for (identity, incoming) in incoming {
                    conflict |= current.entry(identity).or_default().merge(incoming);
                }
                conflict
            }
        }
    }
}

impl RosterLocks {
    fn merge(&mut self, incoming: Self) -> bool {
        let mut conflict = false;
        for (slot, child) in incoming.signed {
            match self.signed.entry(slot) {
                Entry::Vacant(entry) => {
                    entry.insert(child);
                }
                Entry::Occupied(entry) => conflict |= *entry.get() != child,
            }
        }
        self.change_round = self.change_round.max(incoming.change_round);
        if let Some((round, child)) = incoming.commit {
            if let Some((_, previous_child)) = self.commit {
                conflict |= previous_child != child;
            }
            if self
                .commit
                .is_none_or(|(previous_round, _)| round > previous_round)
            {
                self.commit = Some((round, child));
            }
        }
        conflict
    }
}

pub const MAX_ROSTER_LOCKS: usize = 8192;

pub(super) fn record_vote(
    table: &mut RosterLockTable,
    parent: Parent,
    signer: Identity,
    child: [u8; 32],
    round: u32,
    phase: u8,
) -> Result<(), Error> {
    if !(1..=3).contains(&phase) {
        return Err(Error::InvalidRosterPhase);
    }
    if round == 0 {
        return Err(Error::ConflictingRosterVote);
    }
    if table.len() >= MAX_ROSTER_LOCKS && !table.contains_key(&parent) {
        return Err(Error::ConflictingRosterVote);
    }
    let RosterParentLocks::Active(identities) = table.entry(parent).or_default() else {
        return Err(Error::ConflictingRosterVote);
    };
    let locks = identities.entry(signer).or_default();
    if round < locks.change_round
        || locks
            .signed
            .get(&(round, phase))
            .is_some_and(|prior| *prior != child)
    {
        return Err(Error::ConflictingRosterVote);
    }
    if phase == 3 {
        locks.change_round = round;
    } else {
        if locks.commit.is_some_and(|(_, locked)| locked != child) {
            return Err(Error::ConflictingRosterVote);
        }
        if phase == 2 && locks.commit.is_none_or(|(prior, _)| round > prior) {
            locks.commit = Some((round, child));
        }
    }
    locks.signed.insert((round, phase), child);
    Ok(())
}

pub(super) fn blocks_freshness(table: &RosterLockTable, parent: Parent, signer: Identity) -> bool {
    match table.get(&parent) {
        Some(RosterParentLocks::Retired) => true,
        Some(RosterParentLocks::Active(identities)) => identities
            .get(&signer)
            .is_some_and(|locks| locks.commit.is_some()),
        None => false,
    }
}
