#![cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
//! Local simulation of ordered roster updates. Inputs represent authenticated
//! identities and decisions supplied by the simulation.

pub mod evidence;
pub mod handle;
pub mod merge;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Public identity in the simulation. Each identity has a separate key.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Identity(pub u64);

/// A specific tenure in a group, scoped to the participating identity.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub struct Membership {
    group: u64,
    identity: Identity,
    joined_at: u64,
}

impl Membership {
    pub fn identity(self) -> Identity {
        self.identity
    }

    /// Revision at which this tenure began (0 for founding members).
    pub(crate) fn joined_at(self) -> u64 {
        self.joined_at
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct LocalInstallation {
    identities: BTreeMap<Identity, String>,
    departures: BTreeSet<Membership>,
    #[serde(default)]
    tombstones: BTreeSet<Membership>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backup_rosters: Option<BTreeMap<u64, BackupRoster>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct BackupRoster {
    revision: u64,
    history: [u8; 32],
}

impl LocalInstallation {
    pub fn add_identity(&mut self, identity: Identity, label: String) -> bool {
        use std::collections::btree_map::Entry;
        match self.identities.entry(identity) {
            Entry::Vacant(entry) => {
                entry.insert(label);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    pub fn identities(&self) -> impl Iterator<Item = (Identity, &str)> {
        self.identities
            .iter()
            .map(|(&id, label)| (id, label.as_str()))
    }

    /// Records local departure. Persist the updated snapshot before acknowledging
    /// the operation, then deliver the membership as a departure intent.
    pub fn leave(&mut self, membership: Membership) -> Result<(), Error> {
        if !self.identities.contains_key(&membership.identity) {
            return Err(Error::Ineligible);
        }
        self.departures.insert(membership);
        self.tombstones.insert(membership);
        Ok(())
    }

    /// Remains available after restart for delivery or an idempotent retry.
    pub fn departure_intents(&self) -> impl Iterator<Item = Membership> + '_ {
        self.departures.iter().copied()
    }

    /// Retire intents only if a later revision in the agreed roster history
    /// supersedes the tenure. Keep tombstones to suppress presentation on old views.
    pub fn prune_departures(&mut self, group: &Group) {
        let (keep, pruned): (BTreeSet<_>, BTreeSet<_>) = std::mem::take(&mut self.departures)
            .into_iter()
            .partition(|m| {
                m.group != group.id
                    || group.revision <= m.joined_at
                    || group.membership(m.identity) == Some(*m)
            });
        // Only retired intents leave a tombstone; pending ones stay in `departures`.
        self.tombstones.extend(pruned);
        self.departures = keep;
    }

    /// Local gate for casting a vote: `Group::vote` cannot see local departure intents, so a
    /// member who has left locally must not vote before the departure is applied. Callers must
    /// check this before `Group::vote`. After restoring a backup, use the checked vote signing
    /// methods on `VouchedGroup`.
    pub fn may_vote(&self, membership: Membership, group: &Group) -> bool {
        self.may_present(membership, group)
    }

    /// Call when a queued envelope would become a message or notification in
    /// a plain simulation group. Backup restores require `VouchedGroup::may_present`,
    /// which checks that the view contains the confirmed history.
    pub fn may_present(&self, membership: Membership, group: &Group) -> bool {
        self.backup_rosters.is_none() && self.permits_tenure(membership, group)
    }

    fn permits_tenure(&self, membership: Membership, group: &Group) -> bool {
        self.identities.contains_key(&membership.identity)
            && !self.departures.contains(&membership)
            && !self.tombstones.contains(&membership)
            && group.membership(membership.identity) == Some(membership)
    }

    pub fn snapshot(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Restart from this installation's own latest checkpoint. Never use it for a backup or
    /// transfer: an older snapshot misses later departures and is not gated. Use
    /// `restore_backup` for those.
    pub fn restore_checkpoint(snapshot: &[u8]) -> Result<Self, serde_json::Error> {
        Self::restore(snapshot)
    }

    /// Same as `restore_checkpoint`; prefer that name so the unsafe case is visible.
    pub fn restore(snapshot: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(snapshot)
    }

    /// Restore a backup or transfer. Each group stays gated until reconciled.
    /// Use `restore` for a normal restart from the current local checkpoint.
    pub fn restore_backup(snapshot: &[u8]) -> Result<Self, serde_json::Error> {
        let mut installation = Self::restore(snapshot)?;
        installation.backup_rosters = Some(BTreeMap::new());
        Ok(installation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Policy {
    InviterOnly,
    Fixed(std::num::NonZeroUsize),
    Majority,
    TwoThirds,
    Supermajority(Supermajority),
    Unanimous,
}

impl Policy {
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        match bytes {
            [0] => Some(Self::InviterOnly),
            [1, count @ ..] => {
                let count = u64::from_be_bytes(count.try_into().ok()?);
                Some(Self::Fixed(std::num::NonZeroUsize::new(
                    count.try_into().ok()?,
                )?))
            }
            [2] => Some(Self::Majority),
            [3] => Some(Self::TwoThirds),
            [4, fraction @ ..] if fraction.len() == 8 => {
                Some(Self::Supermajority(Supermajority::new(
                    u32::from_be_bytes(fraction[..4].try_into().ok()?),
                    u32::from_be_bytes(fraction[4..].try_into().ok()?),
                )?))
            }
            [5] => Some(Self::Unanimous),
            _ => None,
        }
    }

    /// Canonical bytes, so a policy change yields the same roster child on every node.
    pub(crate) fn encode(self) -> Vec<u8> {
        match self {
            Self::InviterOnly => vec![0],
            Self::Fixed(count) => [&[1][..], &(count.get() as u64).to_be_bytes()].concat(),
            Self::Majority => vec![2],
            Self::TwoThirds => vec![3],
            Self::Supermajority(fraction) => [
                &[4][..],
                &fraction.numerator.to_be_bytes(),
                &fraction.denominator.to_be_bytes(),
            ]
            .concat(),
            Self::Unanimous => vec![5],
        }
    }

    fn required_approvals(self, eligible: usize) -> usize {
        match self {
            Self::InviterOnly => 1,
            Self::Fixed(count) => count.get(),
            Self::Majority => eligible / 2 + 1,
            Self::TwoThirds => eligible - eligible / 3,
            Self::Supermajority(fraction) => fraction.required(eligible) as usize,
            Self::Unanimous => eligible,
        }
    }
}

/// A configured fraction strictly above one half, up to unanimity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Supermajority {
    numerator: u32,
    denominator: u32,
}

impl Supermajority {
    pub fn new(numerator: u32, denominator: u32) -> Option<Self> {
        (numerator > denominator / 2 && numerator <= denominator).then_some(Self {
            numerator,
            denominator,
        })
    }

    fn required(self, eligible: usize) -> u128 {
        (eligible as u128 * u128::from(self.numerator)).div_ceil(u128::from(self.denominator))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Vote {
    Approve,
    Object,
    Abstain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Ineligible,
    AlreadyMember,
    StaleProposal,
    AlreadyVoted,
    AcceptanceRequired,
    ApprovalRequired,
    RevisionExhausted,
    RosterSigningStateUnconfirmed,
    RosterCheckpointFailed,
    /// A proof-carrying certificate was built on a different chain of proofs than this one:
    /// the receiver is behind or on another chain and should catch up. Not an invalid
    /// certificate.
    ChainMismatch,
    /// A suspension would leave too few voters to reach the quorum, with the reserved
    /// allowance for offline members. The group refuses to suspend itself into a stall.
    WouldStall,
    /// This device does not hold the voting role for the identity (a handoff stopped it, or it
    /// was restored from a backup and has not been given the role).
    NotVotingDevice,
}

#[derive(Debug)]
pub struct Proposal {
    group: u64,
    revision: u64,
    candidate: Identity,
    accepted: bool,
    votes: BTreeMap<Identity, Vote>,
}

impl Proposal {
    /// Records the candidate's consent. Simulation only: nothing here proves the candidate
    /// controls the key, so a real implementation must verify a signature by the candidate over
    /// the group, revision and proposal.
    pub fn accept(&mut self, candidate: Identity) -> Result<(), Error> {
        if self.candidate != candidate {
            return Err(Error::Ineligible);
        }
        self.accepted = true;
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct Group {
    id: u64,
    revision: u64,
    roster: BTreeMap<Identity, u64>,
    policy: Policy,
    /// Members whose key is suspect: they neither vote nor count toward the thresholds.
    excluded: BTreeSet<Identity>,
}

impl Group {
    pub fn new(id: u64, members: impl IntoIterator<Item = Identity>, policy: Policy) -> Self {
        Self {
            id,
            revision: 0,
            roster: members.into_iter().map(|member| (member, 0)).collect(),
            policy,
            excluded: BTreeSet::new(),
        }
    }

    pub fn membership(&self, identity: Identity) -> Option<Membership> {
        self.roster.get(&identity).map(|&joined_at| Membership {
            group: self.id,
            identity,
            joined_at,
        })
    }

    pub fn invite(&self, inviter: Identity, candidate: Identity) -> Result<Proposal, Error> {
        if !self.roster.contains_key(&inviter) {
            return Err(Error::Ineligible);
        }
        if self.roster.contains_key(&candidate) {
            return Err(Error::AlreadyMember);
        }
        Ok(Proposal {
            group: self.id,
            revision: self.revision,
            candidate,
            accepted: false,
            votes: BTreeMap::from([(inviter, Vote::Approve)]),
        })
    }

    fn check_parent(&self, proposal: &Proposal) -> Result<(), Error> {
        if proposal.group != self.id || proposal.revision != self.revision {
            return Err(Error::StaleProposal);
        }
        Ok(())
    }

    /// Counts one vote per roster identity. Several identities controlled by one person each
    /// vote; a one-person vote needs an enrollment policy outside this simulation.
    pub fn vote(&self, proposal: &mut Proposal, voter: Identity, vote: Vote) -> Result<(), Error> {
        self.check_parent(proposal)?;
        if !self.roster.contains_key(&voter) || self.excluded.contains(&voter) {
            return Err(Error::Ineligible);
        }
        use std::collections::btree_map::Entry;
        match proposal.votes.entry(voter) {
            Entry::Vacant(entry) => {
                entry.insert(vote);
                Ok(())
            }
            Entry::Occupied(_) => Err(Error::AlreadyVoted),
        }
    }

    pub fn admit(&mut self, proposal: &Proposal) -> Result<(), Error> {
        self.check_admission(proposal)?;
        self.advance()?;
        self.roster.insert(proposal.candidate, self.revision);
        Ok(())
    }

    pub fn is_eligible_voter(&self, identity: Identity) -> bool {
        self.roster.contains_key(&identity) && !self.excluded.contains(&identity)
    }

    fn check_admission(&self, proposal: &Proposal) -> Result<(), Error> {
        self.check_parent(proposal)?;
        if !proposal.accepted {
            return Err(Error::AcceptanceRequired);
        }
        let (approvals, required) = self.approval_counts(proposal);
        if approvals < required {
            return Err(Error::ApprovalRequired);
        }
        Ok(())
    }

    pub fn approval_counts(&self, proposal: &Proposal) -> (usize, usize) {
        let approvals = proposal
            .votes
            .iter()
            .filter(|&(&identity, &vote)| vote == Vote::Approve && self.is_eligible_voter(identity))
            .count();
        (
            approvals,
            self.policy.required_approvals(self.electorate_size()),
        )
    }

    /// Applies a self-authorized intent under the agreed update order. A delayed
    /// copy of an old intent cannot remove a subsequent membership.
    pub fn apply_departure(&mut self, member: Membership) -> Result<bool, Error> {
        if self.membership(member.identity) != Some(member) {
            return Ok(false);
        }
        self.advance()?;
        self.roster.remove(&member.identity);
        self.excluded.remove(&member.identity);
        Ok(true)
    }

    pub(crate) fn exclude(&mut self, identity: Identity) {
        self.excluded.insert(identity);
    }

    pub(crate) fn include(&mut self, identity: Identity) {
        self.excluded.remove(&identity);
    }

    /// Members who can currently vote and whose count sets the thresholds.
    pub(crate) fn electorate_size(&self) -> usize {
        self.roster.len()
            - self
                .excluded
                .iter()
                .filter(|id| self.roster.contains_key(id))
                .count()
    }

    fn advance(&mut self) -> Result<(), Error> {
        self.revision = self
            .revision
            .checked_add(1)
            .ok_or(Error::RevisionExhausted)?;
        Ok(())
    }
}
