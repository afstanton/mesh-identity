//! Step 5, G1: the pure merge-proposal calculation.
//!
//! A proposal says which keys *could* form a new group and what evidence travels with them. It
//! authorizes nothing: the final roster is whoever signs the exact proposal (G2), and no source
//! group is read, changed or reached from here. The function takes explicit views and terms, reads
//! no clock, installation, randomness or storage, and gives the same bytes for the same inputs in
//! any order. See `docs/architecture/step5-g0-merge-contract.md`.

use crate::groups::Policy;
use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

mod formation;
#[cfg(test)]
mod formation_tests;
#[cfg(test)]
mod tests;

pub use formation::{Formation, FormationConsent, FormationError, FormedGroup};
pub(crate) use formation::{agreed_genesis, binding_for, group_id_for, history_id_for};

pub type Key = [u8; 32];

/// At most this many sources in one proposal.
pub const MAX_SOURCES: usize = 16;
/// The genesis wire form holds at most 192 members; more is refused, never truncated.
pub const MAX_MEMBERS: usize = 192;
/// Tenure entries accepted from one source view.
pub const MAX_TENURES_PER_VIEW: usize = 1_024;
/// Marks accepted across a whole proposal.
pub const MAX_MARKS: usize = 1_024;

/// Why a membership tenure is over.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TenureEnd {
    Departed,
    Ejected,
    Rotated,
    Retired,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MarkKind {
    Reported,
    Suspect,
}

/// One membership tenure of one key in one source group.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceMember {
    pub key: Key,
    /// Revision at which this tenure began. Tenures of a key are told apart by this alone.
    pub tenure_start: u64,
    /// The key is a member at the source's head. Exactly the tenures with `ended == None`.
    pub current: bool,
    pub ended: Option<TenureEnd>,
    /// Rotation lineage inside this source. Used only to check the view is consistent; it never
    /// links identities across sources.
    pub successor_of: Option<Key>,
}

/// Scoped evidence recorded on a source's roster node. Carried, never enforced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceMark {
    pub key: Key,
    pub kind: MarkKind,
    /// Revision of the node that carried the mark.
    pub at: u64,
}

/// What one source group contributes, built by a member of that source from state it verified.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceView {
    pub group: u64,
    pub history: [u8; 32],
    pub head_revision: u64,
    /// Commits to the operation head and its authenticated proof, report and recognition state.
    pub head_digest: [u8; 32],
    pub members: Vec<SourceMember>,
    pub marks: Vec<SourceMark>,
}

impl SourceView {
    /// A view of a group the caller holds and has verified. This is the minimal adapter: it lists
    /// current members (each with the revision its tenure began) and the reports recorded on the
    /// chain. Ended tenures are not recorded by the group and so are not listed; that does not
    /// change who is a candidate, which depends on current membership alone.
    pub fn from_group(group: &crate::groups::evidence::VouchedGroup) -> Self {
        let mut members: Vec<SourceMember> = group
            .current_members()
            .into_iter()
            .map(|(key, tenure_start)| SourceMember {
                key,
                tenure_start,
                current: true,
                ended: None,
                successor_of: None,
            })
            .collect();
        members.sort_by_key(|m| m.key);
        let mut marks: Vec<SourceMark> = group
            .reports_by_revision()
            .into_iter()
            .map(|(key, at)| SourceMark {
                key,
                kind: MarkKind::Reported,
                at,
            })
            .collect();
        marks.sort_by_key(|m| (m.key, m.at));
        Self {
            group: group.id(),
            history: group.history_root(),
            head_revision: group.revision(),
            head_digest: group.chain_digest(),
            members,
            marks,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Disclosure {
    /// Source group ids and heads are written into the proposal.
    Full,
    /// Each source is a salted hash; only someone who already holds the source can recompute it.
    Minimal,
}

/// Everything the calculation needs beyond the views. Nothing is inherited from a source.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FormationTerms {
    pub rules: Policy,
    pub disclosure: Disclosure,
    /// The proposer's nonce. It binds the proposal to one formation attempt and salts hidden
    /// source references.
    pub context: [u8; 32],
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum SourceRef {
    Full {
        group: u64,
        history: [u8; 32],
        head_revision: u64,
        head_digest: [u8; 32],
    },
    Hidden([u8; 32]),
}

/// A mark with the source that carried it.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct CarriedMark {
    pub source: SourceRef,
    pub key: Key,
    pub kind: MarkKind,
    pub at: u64,
}

/// A key that appears in a source but is a member of none of them. Informational.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Exclusion {
    pub key: Key,
    pub source: SourceRef,
    pub end: TenureEnd,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProposeError {
    NoSources,
    TooManySources,
    DuplicateSource,
    /// A view is inconsistent: bad key, duplicate tenure, a current tenure that is not the latest,
    /// a mark or tenure past the head, or too many tenures.
    BadView,
    NoCandidates,
    TooManyMembers,
    TooManyMarks,
    /// The finished proposal would not fit in one frame.
    TooLarge,
}

/// The candidate roster and its evidence. It is not a group and grants no authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proposal {
    pub sources: Vec<SourceRef>,
    pub candidates: Vec<Key>,
    pub carried: Vec<CarriedMark>,
    pub excluded: Vec<Exclusion>,
    pub terms: FormationTerms,
}

impl Proposal {
    /// Read only the versioned terms prefix of a stored proposal. The remaining proposal stays
    /// opaque; its entire byte string is still committed by the formation binding.
    pub(crate) fn stored_rules(bytes: &[u8]) -> Option<Policy> {
        if bytes.get(..4)? != b"MSP1" || !matches!(bytes.get(4)?, 0 | 1) {
            return None;
        }
        let len = usize::from(*bytes.get(37)?);
        Policy::decode(bytes.get(38..38 + len)?)
    }

    /// Canonical, versioned bytes. Every list is sorted, so argument order never matters.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"MSP1");
        out.push(match self.terms.disclosure {
            Disclosure::Full => 0,
            Disclosure::Minimal => 1,
        });
        out.extend_from_slice(&self.terms.context);
        let rules = self.terms.rules.encode();
        out.push(rules.len() as u8);
        out.extend_from_slice(&rules);
        put_len(&mut out, self.sources.len());
        for source in &self.sources {
            put_source(&mut out, source);
        }
        put_len(&mut out, self.candidates.len());
        for key in &self.candidates {
            out.extend_from_slice(key);
        }
        put_len(&mut out, self.carried.len());
        for mark in &self.carried {
            put_source(&mut out, &mark.source);
            out.extend_from_slice(&mark.key);
            out.push(mark.kind as u8 + 1);
            out.extend_from_slice(&mark.at.to_be_bytes());
        }
        put_len(&mut out, self.excluded.len());
        for gone in &self.excluded {
            out.extend_from_slice(&gone.key);
            put_source(&mut out, &gone.source);
            out.push(gone.end as u8 + 1);
        }
        out
    }

    pub fn digest(&self) -> [u8; 32] {
        Sha256::digest(self.to_bytes()).into()
    }

    /// Whether `view` is exactly one of this proposal's sources: same group, history and head.
    /// A participant whose source moved on, or who holds a different group, gets `false`.
    pub fn names_source(&self, view: &SourceView) -> bool {
        self.sources.contains(&source_ref(view, &self.terms))
    }
}

fn put_len(out: &mut Vec<u8>, len: usize) {
    out.extend_from_slice(&(len as u32).to_be_bytes());
}

fn put_source(out: &mut Vec<u8>, source: &SourceRef) {
    match source {
        SourceRef::Full {
            group,
            history,
            head_revision,
            head_digest,
        } => {
            out.push(0);
            out.extend_from_slice(&group.to_be_bytes());
            out.extend_from_slice(history);
            out.extend_from_slice(&head_revision.to_be_bytes());
            out.extend_from_slice(head_digest);
        }
        SourceRef::Hidden(hash) => {
            out.push(1);
            out.extend_from_slice(hash);
        }
    }
}

fn source_ref(view: &SourceView, terms: &FormationTerms) -> SourceRef {
    match terms.disclosure {
        Disclosure::Full => SourceRef::Full {
            group: view.group,
            history: view.history,
            head_revision: view.head_revision,
            head_digest: view.head_digest,
        },
        Disclosure::Minimal => {
            let mut hash = Sha256::new();
            hash.update(b"MSP1 hidden source");
            hash.update(terms.context);
            hash.update(view.group.to_be_bytes());
            hash.update(view.history);
            hash.update(view.head_revision.to_be_bytes());
            hash.update(view.head_digest);
            SourceRef::Hidden(hash.finalize().into())
        }
    }
}

fn valid_key(key: &Key) -> bool {
    VerifyingKey::from_bytes(key).is_ok()
}

/// Check one view is internally consistent. It cannot show the view is true; that comes from how
/// the builder obtained it.
fn check_view(view: &SourceView) -> Result<(), ProposeError> {
    if view.members.len() > MAX_TENURES_PER_VIEW {
        return Err(ProposeError::BadView);
    }
    if view.marks.len() > MAX_MARKS {
        return Err(ProposeError::TooManyMarks);
    }
    let mut by_key: BTreeMap<Key, Vec<&SourceMember>> = BTreeMap::new();
    for member in &view.members {
        if !valid_key(&member.key)
            || member.tenure_start > view.head_revision
            || member.current != member.ended.is_none()
            || member
                .successor_of
                .is_some_and(|old| old == member.key || !valid_key(&old))
        {
            return Err(ProposeError::BadView);
        }
        by_key.entry(member.key).or_default().push(member);
    }
    for tenures in by_key.values() {
        let starts: BTreeSet<u64> = tenures.iter().map(|t| t.tenure_start).collect();
        if starts.len() != tenures.len() {
            return Err(ProposeError::BadView);
        }
        // A current tenure must be the latest; an older removal never sits after a readmission.
        let latest = tenures.iter().map(|t| t.tenure_start).max().unwrap();
        if tenures
            .iter()
            .any(|t| t.current && t.tenure_start != latest)
        {
            return Err(ProposeError::BadView);
        }
    }
    // A key and its recorded predecessor cannot both be members of one source at once.
    for member in view.members.iter().filter(|m| m.current) {
        if let Some(old) = member.successor_of {
            if by_key
                .get(&old)
                .is_some_and(|tenures| tenures.iter().any(|t| t.current))
            {
                return Err(ProposeError::BadView);
            }
        }
    }
    for mark in &view.marks {
        if !valid_key(&mark.key) || mark.at > view.head_revision {
            return Err(ProposeError::BadView);
        }
    }
    Ok(())
}

/// Compute the proposal. Pure: the same views (in any order) and terms give identical bytes.
///
/// A key is a candidate when it is a current member of at least one source at that source's head.
/// A removal in one source never removes a key another source still has, and an earlier ended
/// tenure never erases a later current one. Marks are carried as evidence and change nothing.
pub fn propose(views: &[SourceView], terms: FormationTerms) -> Result<Proposal, ProposeError> {
    if views.is_empty() {
        return Err(ProposeError::NoSources);
    }
    if views.len() > MAX_SOURCES {
        return Err(ProposeError::TooManySources);
    }
    let mut groups = BTreeSet::new();
    let mut sources = BTreeSet::new();
    let mut candidates: BTreeSet<Key> = BTreeSet::new();
    let mut not_current: BTreeMap<(Key, SourceRef), TenureEnd> = BTreeMap::new();
    let mut carried: BTreeSet<CarriedMark> = BTreeSet::new();
    for view in views {
        if !groups.insert(view.group) {
            return Err(ProposeError::DuplicateSource);
        }
        check_view(view)?;
        let source = source_ref(view, &terms);
        let mut latest: BTreeMap<Key, &SourceMember> = BTreeMap::new();
        for member in &view.members {
            if latest
                .get(&member.key)
                .is_none_or(|held| held.tenure_start < member.tenure_start)
            {
                latest.insert(member.key, member);
            }
        }
        for (key, member) in latest {
            match member.ended {
                None => {
                    candidates.insert(key);
                }
                Some(end) => {
                    not_current.insert((key, source.clone()), end);
                }
            }
        }
        for mark in &view.marks {
            carried.insert(CarriedMark {
                source: source.clone(),
                key: mark.key,
                kind: mark.kind,
                at: mark.at,
            });
        }
        if carried.len() > MAX_MARKS {
            return Err(ProposeError::TooManyMarks);
        }
        if !sources.insert(source) {
            // Two different groups hashed to one reference: refuse rather than merge them.
            return Err(ProposeError::DuplicateSource);
        }
    }
    if candidates.is_empty() {
        return Err(ProposeError::NoCandidates);
    }
    if candidates.len() > MAX_MEMBERS {
        return Err(ProposeError::TooManyMembers);
    }
    let excluded = not_current
        .into_iter()
        .filter(|((key, _), _)| !candidates.contains(key))
        .map(|((key, source), end)| Exclusion { key, source, end })
        .collect();
    let proposal = Proposal {
        sources: sources.into_iter().collect(),
        candidates: candidates.into_iter().collect(),
        carried: carried.into_iter().collect(),
        excluded,
        terms,
    };
    if proposal.to_bytes().len() > crate::groups::handle::MAX_FRAME_BYTES {
        return Err(ProposeError::TooLarge);
    }
    Ok(proposal)
}
