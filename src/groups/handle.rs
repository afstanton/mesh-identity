//! The `GroupHandle` management facade.
//!
//! The handle owns one `Installation` and the groups it takes part in. Every call that changes
//! state stages outgoing bytes and events. Nothing leaves until the host has written the blob
//! from `save()` and called `confirm_saved(token)`, and only then does `take_outgoing()` return
//! the bytes. Restoring is a pure function of the blob and fails closed.
//!
//! F2 built the framing, the operation table, the staged queue, `save`/`restore`, `create` and
//! `import_genesis`. F3a adds `invite` and `accept` and the inbound invitation and consent: the
//! voucher travels inside the invitation frame (one frame, so they cannot arrive apart), and
//! the candidate needs no copy of the group. Votes, certificates, departures and group
//! snapshots are named by the envelope but refused until later slices.
//!
//! F3d adds `leave`: the group disappears from the handle at once, a signed departure is
//! staged for the other members, and they record it. The shared roster does not change yet.
//!
//! F3b adds the members' roster votes, and F3c the end of an admission: the inviter assembles
//! the certificate from the commit votes, applies the admission, and stages the certificate
//! for the members and a group snapshot for the candidate.

use crate::groups::evidence::{
    AdmissionError, DirectVoucher, GroupSnapshotError, InvitationFrameVersion,
    MAX_CERTIFICATE_SIGNERS, MAX_LIFETIME_MS, SignedAdmissionConsent, SignedDeparture,
    SignedInvitation, VouchedGroup,
};
use crate::groups::{LocalInstallation, Policy};

mod forming;
mod joining;
mod leaving;
mod voting;
use crate::session::installation::{Identity as Key, Installation, SnapshotError};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const HANDLE_FORMAT_VERSION: u8 = 3;
/// Largest frame accepted or produced, before parsing. Proposed in F0; fixed here.
pub const MAX_FRAME_BYTES: usize = 128 * 1024;
pub const MAX_PENDING_OPS: usize = 256;
pub const MAX_STAGED_ITEMS: usize = 1024;
pub const MAX_GROUPS: usize = 1024;
/// Finished operations kept so `op_state` can answer; the oldest are forgotten beyond this.
pub const MAX_KEPT_OPS: usize = 1024;
/// Invitations a candidate holds at once, and from one inviter.
pub const MAX_RECEIVED_INVITATIONS: usize = 64;
pub const MAX_RECEIVED_PER_INVITER: usize = 8;
/// Admissions this handle follows as a member, and votes held for ones it does not know yet.
pub const MAX_OBSERVED: usize = 64;
pub const MAX_STRAY_VOTES: usize = 256;
pub const MAX_DEPARTURES: usize = 256;
const INVITATION_FRAME_LEN: usize = 5 + 144 + 64;
const VOUCHER_LEN: usize = 216;
const MAX_OUTSTANDING_TOKENS: usize = 64;
const MAX_HANDLE_BYTES: usize = 256 * 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct OpId(pub u64);
#[derive(Clone, Copy, Debug, PartialEq, Eq, Ord, PartialOrd)]
pub struct SaveToken(pub u64, [u8; 32]);

type GroupScope = (Key, u64);

type LocalBinding = (Key, [u8; 32]);

/// The nine message kinds. The tag byte values are part of the format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Tag {
    Genesis = 1,
    Invitation = 2,
    Consent = 3,
    AdmissionVote = 4,
    Voucher = 5,
    RosterVote = 6,
    Certificate = 7,
    Departure = 8,
    GroupSnapshot = 9,
}

impl Tag {
    fn from_byte(byte: u8) -> Option<Self> {
        Some(match byte {
            1 => Self::Genesis,
            2 => Self::Invitation,
            3 => Self::Consent,
            4 => Self::AdmissionVote,
            5 => Self::Voucher,
            6 => Self::RosterVote,
            7 => Self::Certificate,
            8 => Self::Departure,
            9 => Self::GroupSnapshot,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Reason {
    Malformed,
    TooLarge,
    UnknownTag,
    /// A known kind this build does not handle yet.
    Unsupported,
    /// Genesis bytes only count with a digest from an authenticated channel: use
    /// `import_genesis`.
    NeedsAuthentication,
    Invalid,
    /// A bound is reached.
    Full,
    Expired,
    /// The group moved on from the roster this was built on.
    Stale,
    /// The sender is not a verified contact.
    UnknownContact,
    /// Names an invitation or group this handle does not hold.
    Unknown,
    /// This member already voted for a different child on the same roster, so this admission
    /// cannot go forward in the first round.
    Conflict,
}

/// The first round of one admission, as one member has seen it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmissionProgress {
    pub prepares: usize,
    pub commits: usize,
    pub signed_prepare: bool,
    pub signed_commit: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpState {
    Pending,
    Completed,
    Rejected(Reason),
    Retryable(Reason),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Event {
    GroupCreated(u64),
    GroupImported(u64),
    /// A group formed from agreed source groups is now held (`adopt_formation`).
    GroupFormed(u64),
    InvitationSent(OpId),
    /// A verified invitation is waiting for `accept`. `invitation` is its binding.
    InvitationReceived {
        group: u64,
        invitation: [u8; 32],
    },
    AcceptanceSent(OpId),
    /// The candidate's consent reached the inviter.
    ConsentReceived(OpId),
    /// The inviter applied the certified admission; the members and the candidate have it
    /// staged.
    Admitted(OpId),
    /// This installation is now a member of the group.
    Joined(u64),
    /// A member was added to a group this installation belongs to.
    MemberAdmitted {
        group: u64,
        member: Key,
    },
    /// This installation's departure from the group is durable and staged for the members.
    Left(u64),
    /// A member told us they left. The shared roster is not changed by this alone.
    MemberDeparted {
        group: u64,
        member: Key,
    },
    /// An inbound frame was refused. It carries no keys or labels.
    FrameRejected(Reason),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandleError {
    /// A bound is reached; nothing was dropped silently.
    Full,
    Invalid,
    UnknownOp,
    /// No such group or invitation.
    Unknown,
    /// Only `InviterOnly` groups are supported so far.
    UnsupportedPolicy,
    /// A check on the people involved failed (not a member, not a verified contact, gated).
    Ineligible,
    Installation(SnapshotError),
    Group(GroupSnapshotError),
    /// The blob is not a handle this build can restore.
    Malformed,
    UnsupportedVersion(u8),
    TooLarge,
    /// This identity already holds (or left) a group with that id.
    Duplicate,
    /// A group formation refused this identity's consent.
    Formation(crate::groups::merge::FormationError),
}

/// Bytes the host must carry, ready to send once their save is confirmed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outgoing {
    /// The owned identity that authorized these bytes.
    pub from: Key,
    /// Recipients; empty means the host decides (a genesis goes to the initial members).
    pub to: Vec<Key>,
    pub kind: Tag,
    /// The framed bytes.
    pub bytes: Vec<u8>,
    /// For a genesis: the SHA-256 the host delivers through an authenticated channel.
    pub authenticator: Option<[u8; 32]>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    TooLarge,
    Malformed,
    UnknownTag,
}

/// `tag (1) | body length (u32, big endian) | body`.
pub fn encode_frame(tag: Tag, body: &[u8]) -> Result<Vec<u8>, FrameError> {
    if body.len() + 5 > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let mut bytes = Vec::with_capacity(body.len() + 5);
    bytes.push(tag as u8);
    bytes.extend_from_slice(&(body.len() as u32).to_be_bytes());
    bytes.extend_from_slice(body);
    Ok(bytes)
}

/// The size is checked before anything else is read; the length must match exactly.
pub fn decode_frame(bytes: &[u8]) -> Result<(Tag, &[u8]), FrameError> {
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge);
    }
    let (&tag, rest) = bytes.split_first().ok_or(FrameError::Malformed)?;
    let (len, body) = rest.split_first_chunk::<4>().ok_or(FrameError::Malformed)?;
    if u32::from_be_bytes(*len) as usize != body.len() {
        return Err(FrameError::Malformed);
    }
    let tag = Tag::from_byte(tag).ok_or(FrameError::UnknownTag)?;
    Ok((tag, body))
}

#[derive(Clone, Serialize, Deserialize)]
struct Op {
    owner: Key,
    id: u64,
    state: OpState,
    /// What `resend` stages again: the same signed bytes, never re-signed.
    frames: Vec<Outgoing>,
}

/// An invitation this handle sent, kept until it expires or is superseded by admission.
#[derive(Clone, Serialize, Deserialize)]
struct Sent {
    nonce: [u8; 32],
    op: u64,
    group: u64,
    candidate: Key,
    deadline: u64,
    /// The signed invitation frame, exactly as sent.
    frame: Vec<u8>,
    voucher: Vec<u8>,
    consent: Option<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Accepted {
    op: u64,
    consent: Vec<u8>,
}

/// An invitation this handle received.
#[derive(Clone, Serialize, Deserialize)]
struct Received {
    nonce: [u8; 32],
    history: joining::History,
    group: u64,
    inviter: Key,
    deadline: u64,
    frame: Vec<u8>,
    voucher: Vec<u8>,
    accepted: Option<Accepted>,
}

/// An invitation a member saw for someone else, kept to vote on the admission.
#[derive(Clone, Serialize, Deserialize)]
struct Observed {
    nonce: [u8; 32],
    group: u64,
    inviter: Key,
    deadline: u64,
    frame: Vec<u8>,
    voucher: Vec<u8>,
    consent: Option<Vec<u8>>,
}

/// One saved roster vote.
#[derive(Clone, Serialize, Deserialize)]
struct VoteRec {
    signer: Key,
    signature: Vec<u8>,
}

/// The first round of the roster change for one admission, as this member has seen it.
#[derive(Clone, Serialize, Deserialize)]
struct Round {
    group: u64,
    parent: [u8; 32],
    child: [u8; 32],
    deadline: u64,
    signed_prepare: bool,
    signed_commit: bool,
    prepares: Vec<VoteRec>,
    commits: Vec<VoteRec>,
}

/// A vote that arrived before this member knew its admission.
#[derive(Clone, Serialize, Deserialize)]
struct Stray {
    owner: Key,
    group: u64,
    parent: [u8; 32],
    child: [u8; 32],
    commit: bool,
    vote: VoteRec,
    deadline: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct Item {
    owner: Key,
    seq: u64,
    op: Option<u64>,
    outgoing: Vec<Outgoing>,
    /// Events emitted when this item's save is confirmed.
    events: Vec<Event>,
    /// Marks the op completed at confirmation.
    completes: bool,
    #[serde(skip)]
    released: bool,
}

#[derive(Serialize, Deserialize)]
struct HandleWire {
    version: u8,
    installation: Vec<u8>,
    groups: Vec<(GroupScope, Vec<u8>)>,
    histories: Vec<(GroupScope, joining::History)>,
    next_op: u64,
    next_seq: u64,
    save_counter: u64,
    ops: Vec<Op>,
    staged: Vec<Item>,
    sent: Vec<(LocalBinding, Sent)>,
    received: Vec<(LocalBinding, Received)>,
    local: Vec<u8>,
    observed: Vec<(LocalBinding, Observed)>,
    rounds: Vec<(LocalBinding, Round)>,
    strays: Vec<Stray>,
    left: Vec<(Key, u64)>,
    departures: Vec<(Key, u64, Key, Vec<u8>)>,
    formed: Vec<(GroupScope, FormedFrom)>,
}

/// What a formed group keeps of how it came to be: the exact agreement and the proposal that
/// was signed. Opaque here; the binding is recomputed on restore.
#[derive(Clone, Serialize, Deserialize)]
struct FormedFrom {
    binding: [u8; 32],
    proposal: Vec<u8>,
}

pub struct GroupHandle {
    installation: Installation,
    groups: BTreeMap<GroupScope, VouchedGroup>,
    histories: BTreeMap<GroupScope, joining::History>,
    ops: BTreeMap<u64, Op>,
    next_op: u64,
    staged: Vec<Item>,
    sent: BTreeMap<LocalBinding, Sent>,
    received: BTreeMap<LocalBinding, Received>,
    local: LocalInstallation,
    observed: BTreeMap<LocalBinding, Observed>,
    rounds: BTreeMap<LocalBinding, Round>,
    strays: Vec<Stray>,
    /// Groups this installation left. They are hidden at once and never voted in again.
    left: std::collections::BTreeSet<(Key, u64)>,
    /// Signed departures other members sent us, by group and member.
    departures: BTreeMap<(Key, u64, Key), Vec<u8>>,
    formed: BTreeMap<GroupScope, FormedFrom>,
    next_seq: u64,
    save_counter: u64,
    /// Outstanding tokens and the highest staged sequence each covers. Not persisted: a token
    /// belongs to the handle that issued it.
    tokens: BTreeMap<u64, u64>,
    incarnation: [u8; 32],
}

impl GroupHandle {
    pub fn new(installation: Installation) -> Self {
        Self {
            installation,
            groups: BTreeMap::new(),
            histories: BTreeMap::new(),
            ops: BTreeMap::new(),
            next_op: 1,
            staged: Vec::new(),
            sent: BTreeMap::new(),
            received: BTreeMap::new(),
            local: LocalInstallation::default(),
            observed: BTreeMap::new(),
            rounds: BTreeMap::new(),
            strays: Vec::new(),
            left: std::collections::BTreeSet::new(),
            departures: BTreeMap::new(),
            formed: BTreeMap::new(),
            next_seq: 1,
            save_counter: 0,
            tokens: BTreeMap::new(),
            incarnation: rand::random(),
        }
    }

    pub fn installation(&self) -> &Installation {
        &self.installation
    }

    /// Trusted host access for keys, contacts and identity selection. Direct low-level
    /// signing bypasses this handle's persistence/outbox contract; use handle verbs for
    /// handle-managed group operations.
    pub fn installation_mut(&mut self) -> &mut Installation {
        &mut self.installation
    }

    /// A group this installation belongs to. A group it left is not shown.
    pub fn group(&self, id: u64) -> Option<&VouchedGroup> {
        if self.left.contains(&(self.installation.selected(), id)) {
            return None;
        }
        let me = self.installation.selected();
        self.groups
            .get(&(me, id))
            .or_else(|| {
                if self
                    .received
                    .iter()
                    .any(|((owner, _), r)| *owner == me && r.group == id)
                {
                    return None;
                }
                self.groups
                    .iter()
                    .filter(|((_, group), view)| *group == id && view.membership(me).is_some())
                    .max_by_key(|(_, view)| view.revision())
                    .map(|(_, view)| view)
            })
            .filter(|view| {
                view.membership(me).is_some_and(|tenure| {
                    !self.local.departures.contains(&tenure)
                        && !self.local.tombstones.contains(&tenure)
                })
            })
    }

    pub fn group_ids(&self) -> Vec<u64> {
        self.groups
            .keys()
            .map(|(_, id)| *id)
            .filter(|id| self.group(*id).is_some())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    // Each owned participating identity maintains its own receive/vote view. Fork a
    // public authenticated view for an already-enrolled owned member before any view
    // advances; pending candidates still need their own verified join response.
    fn ensure_local_views(&mut self) -> Result<(), HandleError> {
        let owns = |key: Key| self.installation.contacts(key).is_some();
        self.groups.retain(|(owner, _), _| owns(*owner));
        self.histories.retain(|(owner, _), _| owns(*owner));
        self.formed.retain(|(owner, _), _| owns(*owner));
        self.sent.retain(|(owner, _), _| owns(*owner));
        self.received.retain(|(owner, _), _| owns(*owner));
        self.observed.retain(|(owner, _), _| owns(*owner));
        self.rounds.retain(|(owner, _), _| owns(*owner));
        self.strays.retain(|s| owns(s.owner));
        self.left.retain(|(owner, _)| owns(*owner));
        self.departures.retain(|(owner, _, _), _| owns(*owner));
        self.staged.retain(|s| owns(s.owner));
        self.ops.retain(|_, op| owns(op.owner));
        let mut sources: BTreeMap<GroupScope, GroupScope> = BTreeMap::new();
        for (scope, view) in &self.groups {
            for key in view.member_keys().into_iter().filter(|key| owns(*key)) {
                let target = (key, scope.1);
                if self.left.contains(&target)
                    || self
                        .received
                        .iter()
                        .any(|((owner, _), r)| *owner == key && r.group == scope.1)
                    || self
                        .groups
                        .get(&target)
                        .is_some_and(|prior| prior.revision() >= view.revision())
                {
                    continue;
                }
                if let Some(prior) = self.groups.get(&target) {
                    let Some(prior_history) = self.histories.get(&target) else {
                        return Err(HandleError::Invalid);
                    };
                    let Some(source_history) = self.histories.get(scope) else {
                        return Err(HandleError::Invalid);
                    };
                    // A shared short id and a higher revision do not establish ancestry.
                    // Pin the entire genesis and use the proof-aware catch-up check before
                    // copying a public view across owned identities.
                    if prior_history.genesis_digest() != source_history.genesis_digest()
                        || prior.clone().catch_up(view) != crate::groups::evidence::CatchUp::Applied
                    {
                        continue;
                    }
                }
                let replace = sources
                    .get(&target)
                    .and_then(|prior| self.groups.get(prior))
                    .is_none_or(|prior| prior.revision() < view.revision());
                if replace {
                    sources.insert(target, *scope);
                }
            }
        }
        let new_entries = sources
            .keys()
            .filter(|target| !self.groups.contains_key(target))
            .count();
        if self.groups.len() + new_entries > MAX_GROUPS {
            return Err(HandleError::Full);
        }
        for (target, source) in sources {
            let Some(source_group) = self.groups.get(&source) else {
                continue;
            };
            let Some(source_history) = self.histories.get(&source) else {
                continue;
            };
            let bytes = source_group.public_bytes().map_err(HandleError::Group)?;
            self.groups.insert(
                target,
                VouchedGroup::from_bytes(&bytes).map_err(HandleError::Group)?,
            );
            self.histories.insert(target, source_history.clone());
            if let Some(record) = self.formed.get(&source).cloned() {
                self.formed.insert(target, record);
            }
        }
        Ok(())
    }

    pub fn op_state(&self, op: OpId) -> Option<OpState> {
        self.ops
            .get(&op.0)
            .filter(|op| op.owner == self.installation.selected())
            .map(|op| op.state)
    }

    fn pending_ops(&self) -> usize {
        self.ops
            .values()
            .filter(|op| op.state == OpState::Pending)
            .count()
    }

    /// Room for one more operation and one more staged item, checked before anything changes.
    fn check_room(&self) -> Result<(), HandleError> {
        if self.pending_ops() >= MAX_PENDING_OPS || self.staged.len() >= MAX_STAGED_ITEMS {
            return Err(HandleError::Full);
        }
        Ok(())
    }

    fn new_op(&mut self, frames: &[Outgoing]) -> u64 {
        let id = self.next_op;
        self.next_op += 1;
        self.ops.insert(
            id,
            Op {
                owner: self.installation.selected(),
                id,
                state: OpState::Pending,
                frames: frames.to_vec(),
            },
        );
        // Forget the oldest finished operations beyond the cap.
        while self.ops.len() > MAX_KEPT_OPS {
            let Some(oldest) = self
                .ops
                .values()
                .find(|op| {
                    op.state != OpState::Pending
                        && !self.staged.iter().any(|item| item.op == Some(op.id))
                        && !self.sent.values().any(|s| s.op == op.id)
                        && !self
                            .received
                            .values()
                            .any(|r| r.accepted.as_ref().is_some_and(|a| a.op == op.id))
                })
                .map(|op| op.id)
            else {
                break;
            };
            self.ops.remove(&oldest);
        }
        id
    }

    fn push_item(
        &mut self,
        op: Option<u64>,
        outgoing: Vec<Outgoing>,
        events: Vec<Event>,
        completes: bool,
    ) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.staged.push(Item {
            owner: self.installation.selected(),
            seq,
            op,
            outgoing,
            events,
            completes,
            released: false,
        });
    }

    /// An operation whose effect lands when its save is confirmed.
    fn stage(&mut self, frames: Vec<Outgoing>, events: Vec<Event>) -> OpId {
        let id = self.new_op(&frames);
        self.push_item(Some(id), frames, events, true);
        OpId(id)
    }

    /// Tell the local state which identity number is ours in this group, so the signing gates
    /// can find our tenure. No label is stored.
    fn register_local(&mut self, group: u64) {
        let me = self.installation.selected();
        if let Some(tenure) = self
            .groups
            .get(&(self.installation.selected(), group))
            .and_then(|g| g.membership(me))
        {
            self.local.add_identity(tenure.identity(), String::new());
        }
    }

    /// Operations whose invitations ran out of time can no longer succeed.
    fn expire(&mut self, now: u64) {
        self.expire_voting(now);
        let dead: Vec<LocalBinding> = self
            .sent
            .iter()
            .filter(|(_, s)| s.deadline <= now)
            .map(|(k, _)| *k)
            .collect();
        for binding in dead {
            if let Some(sent) = self.sent.remove(&binding) {
                self.reject_if_pending(sent.op, Reason::Expired);
            }
        }
        let dead: Vec<LocalBinding> = self
            .received
            .iter()
            .filter(|(_, r)| r.deadline <= now)
            .map(|(k, _)| *k)
            .collect();
        for binding in dead {
            if let Some(received) = self.received.remove(&binding) {
                if let Some(accepted) = received.accepted {
                    self.reject_if_pending(accepted.op, Reason::Expired);
                }
            }
        }
    }

    fn expire_voting(&mut self, now: u64) {
        self.observed.retain(|_, o| o.deadline > now);
        self.rounds.retain(|_, r| r.deadline > now);
        self.strays.retain(|s| s.deadline > now);
    }

    fn reject_if_pending(&mut self, op: u64, reason: Reason) {
        if let Some(op) = self.ops.get_mut(&op) {
            if op.state == OpState::Pending {
                op.state = OpState::Rejected(reason);
            }
        }
    }

    /// Start a group of `members` plus this installation's selected identity. The genesis and
    /// its digest are staged for the other members.
    pub fn create(
        &mut self,
        policy: Policy,
        members: &[Key],
        rng: &mut impl RngCore,
    ) -> Result<OpId, HandleError> {
        self.check_room()?;
        if self.groups.len() >= MAX_GROUPS {
            return Err(HandleError::Full);
        }
        let me = self.installation.selected();
        let mut all = vec![me];
        for member in members {
            if !all.contains(member) {
                all.push(*member);
            }
        }
        let mut id = rng.next_u64();
        while self.groups.keys().any(|(_, known)| *known == id) {
            id = rng.next_u64();
        }
        let group = VouchedGroup::new(id, all.iter().copied(), policy);
        let genesis = group.genesis_bytes().map_err(|_| HandleError::Invalid)?;
        let authenticator: [u8; 32] = Sha256::digest(&genesis).into();
        let frame = encode_frame(Tag::Genesis, &genesis).map_err(|_| HandleError::Invalid)?;
        let to = all.into_iter().filter(|key| *key != me).collect();
        self.histories.insert(
            (self.installation.selected(), id),
            joining::History::new(genesis.clone()),
        );
        self.groups
            .insert((self.installation.selected(), id), group);
        self.register_local(id);
        Ok(self.stage(
            vec![Outgoing {
                from: me,
                to,
                kind: Tag::Genesis,
                bytes: frame,
                authenticator: Some(authenticator),
            }],
            vec![Event::GroupCreated(id)],
        ))
    }

    /// Join a group from genesis bytes and the digest that arrived through an authenticated
    /// channel. This installation's selected identity must be on the roster.
    pub fn import_genesis(
        &mut self,
        frame: &[u8],
        expected_digest: [u8; 32],
    ) -> Result<OpId, HandleError> {
        self.check_room()?;
        if self.groups.len() >= MAX_GROUPS {
            return Err(HandleError::Full);
        }
        let (tag, body) = decode_frame(frame).map_err(|_| HandleError::Invalid)?;
        if tag != Tag::Genesis {
            return Err(HandleError::Invalid);
        }
        let group = VouchedGroup::from_authenticated_genesis(body, expected_digest)
            .map_err(|_| HandleError::Invalid)?;
        if group.membership(self.installation.selected()).is_none()
            || self
                .groups
                .contains_key(&(self.installation.selected(), group.id()))
        {
            return Err(HandleError::Invalid);
        }
        let id = group.id();
        self.histories.insert(
            (self.installation.selected(), id),
            joining::History::new(body.to_vec()),
        );
        self.groups
            .insert((self.installation.selected(), id), group);
        self.register_local(id);
        Ok(self.stage(Vec::new(), vec![Event::GroupImported(id)]))
    }

    /// Invite `candidate`, a verified contact, to a group this installation belongs to. The
    /// signed invitation and voucher are staged for the candidate as one frame.
    pub fn invite(
        &mut self,
        group_id: u64,
        candidate: Key,
        lifetime_ms: u64,
        now: u64,
    ) -> Result<OpId, HandleError> {
        self.expire(now);
        self.ensure_local_views()?;
        self.register_local(group_id);
        self.check_room()?;
        let me = self.installation.selected();
        if self
            .left
            .contains(&(self.installation.selected(), group_id))
        {
            return Err(HandleError::Unknown);
        }
        let history = self
            .histories
            .get(&(self.installation.selected(), group_id))
            .cloned()
            .ok_or(HandleError::Unknown)?;
        let group = self
            .groups
            .get_mut(&(self.installation.selected(), group_id))
            .ok_or(HandleError::Unknown)?;
        if group.policy() != Policy::InviterOnly {
            return Err(HandleError::UnsupportedPolicy);
        }
        if lifetime_ms == 0 || lifetime_ms > MAX_LIFETIME_MS {
            return Err(HandleError::Invalid);
        }
        let deadline = now.checked_add(lifetime_ms).ok_or(HandleError::Invalid)?;
        group.advance_time(now);
        let members = group
            .export_roster(&self.installation)
            .map_err(|_| HandleError::Ineligible)?
            .members;
        let mut proposal = group
            .invite_until(me, candidate, deadline)
            .map_err(|_| HandleError::Ineligible)?;
        let nonce = rand::random();
        proposal.bind_parent(
            nonce,
            joining::parent_digest(group).map_err(|_| HandleError::Invalid)?,
        );
        let voucher = group
            .vouch(&proposal, &self.installation, [], deadline)
            .map_err(|_| HandleError::Ineligible)?;
        let frame = SignedInvitation::encode_frame(
            &proposal,
            &self.installation,
            InvitationFrameVersion::V1,
        )
        .map_err(|_| HandleError::Ineligible)?;
        let voucher_wire = voucher
            .admission_wire(&self.installation)
            .map_err(|_| HandleError::Ineligible)?;
        let mut body = frame.to_vec();
        body.extend_from_slice(&voucher_wire);
        body.extend_from_slice(&nonce);
        ciborium::into_writer(&history, &mut body).map_err(|_| HandleError::Invalid)?;
        let envelope = encode_frame(Tag::Invitation, &body).map_err(|_| HandleError::Invalid)?;
        let binding = proposal.decision_binding();
        // The members get the same frame: they vote on the admission once consent arrives.
        let mut to = vec![candidate];
        to.extend(
            members
                .into_iter()
                .filter(|key| *key != me && *key != candidate),
        );
        let outgoing = vec![Outgoing {
            from: me,
            to,
            kind: Tag::Invitation,
            bytes: envelope,
            authenticator: None,
        }];
        let op = self.new_op(&outgoing);
        self.sent.insert(
            (me, binding),
            Sent {
                nonce,
                op,
                group: group_id,
                candidate,
                deadline,
                frame: frame.to_vec(),
                voucher: voucher_wire.to_vec(),
                consent: None,
            },
        );
        self.push_item(
            Some(op),
            outgoing,
            vec![Event::InvitationSent(OpId(op))],
            false,
        );
        Ok(OpId(op))
    }

    /// Accept a received invitation. Signs the candidate's consent and stages it for the
    /// inviter. Accepting twice returns the same operation.
    pub fn accept(&mut self, invitation: [u8; 32], now: u64) -> Result<OpId, HandleError> {
        self.expire(now);
        let received = self
            .received
            .get(&(self.installation.selected(), invitation))
            .ok_or(HandleError::Unknown)?;
        if let Some(accepted) = &received.accepted {
            return Ok(OpId(accepted.op));
        }
        self.check_room()?;
        let facts =
            SignedInvitation::inspect_frame(&received.frame).map_err(|_| HandleError::Invalid)?;
        let consent = SignedAdmissionConsent::for_invitation(&facts, &self.installation)
            .map_err(|_| HandleError::Ineligible)?
            .to_bytes();
        let mut body = invitation.to_vec();
        body.extend_from_slice(&consent);
        let outgoing = vec![Outgoing {
            from: self.installation.selected(),
            to: vec![facts.inviter],
            kind: Tag::Consent,
            bytes: encode_frame(Tag::Consent, &body).map_err(|_| HandleError::Invalid)?,
            authenticator: None,
        }];
        let op = self.new_op(&outgoing);
        if let Some(received) = self
            .received
            .get_mut(&(self.installation.selected(), invitation))
        {
            received.accepted = Some(Accepted {
                op,
                consent: consent.to_vec(),
            });
        }
        self.push_item(
            Some(op),
            outgoing,
            vec![Event::AcceptanceSent(OpId(op))],
            false,
        );
        Ok(OpId(op))
    }

    /// Independently authenticate an introduced group's genesis before consenting. The
    /// ordinary accept path instead relies on the verified inviter for initial introduction.
    pub fn accept_authenticated(
        &mut self,
        invitation: [u8; 32],
        genesis_digest: [u8; 32],
        now: u64,
    ) -> Result<OpId, HandleError> {
        let received = self
            .received
            .get(&(self.installation.selected(), invitation))
            .ok_or(HandleError::Unknown)?;
        if received.history.genesis_digest() != genesis_digest {
            return Err(HandleError::Invalid);
        }
        self.accept(invitation, now)
    }

    /// The invitations waiting for this installation, by binding.
    pub fn pending_invitations(&self) -> Vec<([u8; 32], u64, Key)> {
        self.received
            .iter()
            .filter(|((owner, _), r)| {
                *owner == self.installation.selected() && r.accepted.is_none()
            })
            .map(|((_, binding), r)| (*binding, r.group, r.inviter))
            .collect()
    }

    /// Handle one inbound frame. A refusal comes back at once; an accepted frame's events come
    /// from `confirm_saved`, after the state they describe is durable.
    pub fn receive_bytes(&mut self, from: Key, bytes: &[u8], now: u64) -> Vec<Event> {
        let reject = |reason| vec![Event::FrameRejected(reason)];
        let (tag, body) = match decode_frame(bytes) {
            Err(FrameError::TooLarge) => return reject(Reason::TooLarge),
            Err(FrameError::Malformed) => return reject(Reason::Malformed),
            Err(FrameError::UnknownTag) => return reject(Reason::UnknownTag),
            Ok(parsed) => parsed,
        };
        self.expire(now);
        if self.ensure_local_views().is_err() {
            return reject(Reason::Full);
        }
        for id in self.group_ids() {
            self.register_local(id);
        }
        let result = match tag {
            Tag::Genesis => Err(Reason::NeedsAuthentication),
            Tag::Invitation => self.receive_invitation(from, body, now),
            Tag::Consent => self.receive_consent(from, body, now),
            Tag::RosterVote => self.receive_roster_vote(from, body, now),
            Tag::Certificate => self.receive_certificate(from, body, now),
            Tag::GroupSnapshot => self.receive_snapshot(from, body, now),
            Tag::Departure => self.receive_departure(from, body),
            _ => Err(Reason::Unsupported),
        };
        match result {
            Ok(()) => Vec::new(),
            Err(reason) => reject(reason),
        }
    }

    fn receive_invitation(&mut self, from: Key, body: &[u8], now: u64) -> Result<(), Reason> {
        if body.len() <= INVITATION_FRAME_LEN + VOUCHER_LEN + 32 {
            return Err(Reason::Malformed);
        }
        let (frame, rest) = body.split_at(INVITATION_FRAME_LEN);
        let (voucher_bytes, rest) = rest.split_at(VOUCHER_LEN);
        let nonce: [u8; 32] = rest[..32].try_into().unwrap();
        let history = joining::History::from_bytes(&rest[32..])?;
        let facts = SignedInvitation::inspect_frame(frame).map_err(|_| Reason::Invalid)?;
        let me = self.installation.selected();
        if facts.inviter != from {
            return Err(Reason::Invalid);
        }
        if facts.candidate != me && self.left.contains(&(me, facts.group)) {
            return Ok(());
        }
        if facts.candidate == me {
            if !crate::groups::evidence::verified_contact(&self.installation, from) {
                return Err(Reason::UnknownContact);
            }
        } else if !self
            .group(facts.group)
            .is_some_and(|g| g.membership(from).is_some())
        {
            return Err(Reason::Invalid);
        }
        let parent = history.replay()?;
        joining::check_parent(&facts, nonce, &parent)?;
        if facts.candidate != me
            && facts.inviter == from
            && self
                .groups
                .contains_key(&(self.installation.selected(), facts.group))
        {
            let group = self
                .groups
                .get(&(self.installation.selected(), facts.group))
                .ok_or(Reason::Unknown)?;
            let current_bytes = group.public_bytes().map_err(|_| Reason::Invalid)?;
            let parent_bytes = parent.public_bytes().map_err(|_| Reason::Invalid)?;
            if current_bytes != parent_bytes {
                let history = self
                    .histories
                    .get(&(self.installation.selected(), facts.group));
                if history.is_some_and(|h| h.has_admission(facts.binding)) {
                    return Ok(());
                }
                return Err(Reason::Stale);
            }
            return self.observe_invitation(from, frame, voucher_bytes, &facts, nonce, now);
        }
        if facts.candidate != me || facts.inviter != from || facts.inviter == me {
            return Err(Reason::Invalid);
        }
        if facts.deadline <= now {
            return Err(Reason::Expired);
        }
        if facts.deadline - now > MAX_LIFETIME_MS {
            return Err(Reason::Invalid);
        }
        if !crate::groups::evidence::verified_contact(&self.installation, facts.inviter) {
            return Err(Reason::UnknownContact);
        }
        let voucher =
            DirectVoucher::from_admission_wire(voucher_bytes).map_err(|_| Reason::Invalid)?;
        if voucher.issuer() != facts.inviter
            || voucher.candidate() != me
            || voucher.invitation_binding() != facts.binding
        {
            return Err(Reason::Invalid);
        }
        if self.received.contains_key(&(me, facts.binding)) {
            return Ok(()); // a redelivery
        }
        let from_inviter = self.received.values().filter(|r| r.inviter == from).count();
        if self.received.len() >= MAX_RECEIVED_INVITATIONS
            || from_inviter >= MAX_RECEIVED_PER_INVITER
            || self.staged.len() >= MAX_STAGED_ITEMS
        {
            return Err(Reason::Full);
        }
        self.received.insert(
            (me, facts.binding),
            Received {
                nonce,
                history,
                group: facts.group,
                inviter: from,
                deadline: facts.deadline,
                frame: frame.to_vec(),
                voucher: voucher_bytes.to_vec(),
                accepted: None,
            },
        );
        self.push_item(
            None,
            Vec::new(),
            vec![Event::InvitationReceived {
                group: facts.group,
                invitation: facts.binding,
            }],
            false,
        );
        Ok(())
    }

    fn receive_consent(&mut self, from: Key, body: &[u8], now: u64) -> Result<(), Reason> {
        if body.len() != 32 + 64 {
            return Err(Reason::Malformed);
        }
        let binding: [u8; 32] = body[..32].try_into().unwrap();
        if !self
            .sent
            .contains_key(&(self.installation.selected(), binding))
        {
            return self.observe_consent(from, binding, &body[32..], now);
        }
        let sent = self
            .sent
            .get(&(self.installation.selected(), binding))
            .ok_or(Reason::Unknown)?;
        if sent.candidate != from {
            return Err(Reason::Invalid);
        }
        if sent.consent.is_some() {
            return self.advance_admission(binding, now);
        }
        if self.staged.len() >= MAX_STAGED_ITEMS {
            return Err(Reason::Full);
        }
        let op = sent.op;
        let group = self
            .groups
            .get_mut(&(self.installation.selected(), sent.group))
            .ok_or(Reason::Unknown)?;
        group.advance_time(now);
        let mut proposal =
            group
                .receive_invitation_frame(&sent.frame)
                .map_err(|error| match error {
                    AdmissionError::InvitationExpired => Reason::Expired,
                    AdmissionError::Roster(crate::groups::Error::StaleProposal) => Reason::Stale,
                    _ => Reason::Invalid,
                })?;
        let consent =
            SignedAdmissionConsent::from_bytes(&body[32..]).map_err(|_| Reason::Malformed)?;
        group
            .apply_admission_consent(&mut proposal, &consent)
            .map_err(|_| Reason::Invalid)?;
        let members = group
            .export_roster(&self.installation)
            .map_err(|_| Reason::Invalid)?
            .members;
        let me = self.installation.selected();
        if let Some(sent) = self.sent.get_mut(&(self.installation.selected(), binding)) {
            sent.consent = Some(body[32..].to_vec());
        }
        // The members hear the candidate's consent from the inviter.
        let forward = vec![Outgoing {
            from: self.installation.selected(),
            to: members.into_iter().filter(|key| *key != me).collect(),
            kind: Tag::Consent,
            bytes: encode_frame(Tag::Consent, body).map_err(|_| Reason::Invalid)?,
            authenticator: None,
        }];
        self.push_item(
            Some(op),
            forward,
            vec![Event::ConsentReceived(OpId(op))],
            false,
        );
        self.advance_admission(binding, now)
    }

    /// Stage the same signed bytes of an operation again. Never signs.
    pub fn resend(&mut self, op: OpId) -> Result<(), HandleError> {
        let stored = self.ops.get(&op.0).ok_or(HandleError::UnknownOp)?;
        if stored.owner != self.installation.selected()
            || matches!(stored.state, OpState::Rejected(_))
        {
            return Err(HandleError::Invalid);
        }
        if self.staged.len() >= MAX_STAGED_ITEMS {
            return Err(HandleError::Full);
        }
        let pending = self
            .sent
            .iter()
            .find(|((owner, _), sent)| *owner == self.installation.selected() && sent.op == op.0)
            .map(|((_, binding), _)| *binding);
        if let Some(binding) = pending {
            self.advance_admission(binding, 0).map_err(|r| {
                if r == Reason::Full {
                    HandleError::Full
                } else {
                    HandleError::Invalid
                }
            })?;
        }
        if self.staged.len() >= MAX_STAGED_ITEMS {
            return Err(HandleError::Full);
        }
        let frames = self
            .ops
            .get(&op.0)
            .ok_or(HandleError::UnknownOp)?
            .frames
            .clone();
        let seq = self.next_seq;
        self.next_seq += 1;
        self.staged.push(Item {
            owner: self.installation.selected(),
            seq,
            op: Some(op.0),
            outgoing: frames,
            events: Vec::new(),
            completes: false,
            released: false,
        });
        Ok(())
    }

    /// The blob to write, and the token to confirm once it is durable. Staged bytes covered by
    /// this blob are released only by `confirm_saved` with this token or a later one.
    pub fn save(&mut self, now: u64) -> Result<(SaveToken, Vec<u8>), HandleError> {
        self.ensure_local_views()?;
        self.expire(now);
        let installation = self
            .installation
            .save_bytes(now)
            .map_err(HandleError::Installation)?;
        let mut groups = Vec::new();
        for (id, group) in &self.groups {
            groups.push((*id, group.to_bytes().map_err(HandleError::Group)?));
        }
        let token = self.save_counter + 1;
        let wire = HandleWire {
            version: HANDLE_FORMAT_VERSION,
            installation,
            groups,
            histories: self
                .histories
                .iter()
                .map(|(id, h)| (*id, h.clone()))
                .collect(),
            next_op: self.next_op,
            next_seq: self.next_seq,
            save_counter: token,
            ops: self.ops.values().cloned().collect(),
            staged: self.staged.clone(),
            sent: self.sent.iter().map(|(k, v)| (*k, v.clone())).collect(),
            received: self.received.iter().map(|(k, v)| (*k, v.clone())).collect(),
            local: serde_json::to_vec(&self.local).map_err(|_| HandleError::Invalid)?,
            observed: self.observed.iter().map(|(k, v)| (*k, v.clone())).collect(),
            rounds: self.rounds.iter().map(|(k, v)| (*k, v.clone())).collect(),
            strays: self.strays.clone(),
            left: self.left.iter().copied().collect(),
            departures: self
                .departures
                .iter()
                .map(|((owner, group, member), bytes)| (*owner, *group, *member, bytes.clone()))
                .collect(),
            formed: self.formed.iter().map(|(k, v)| (*k, v.clone())).collect(),
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&wire, &mut bytes).map_err(|_| HandleError::Invalid)?;
        if bytes.len() > MAX_HANDLE_BYTES {
            return Err(HandleError::TooLarge);
        }
        self.save_counter = token;
        self.tokens.insert(token, self.next_seq - 1);
        while self.tokens.len() > MAX_OUTSTANDING_TOKENS {
            self.tokens.pop_first();
        }
        Ok((SaveToken(token, self.incarnation), bytes))
    }

    /// The write of `token`'s blob is durable. Releases what it covered and returns the events.
    /// An unknown or already confirmed token does nothing.
    pub fn confirm_saved(&mut self, token: SaveToken) -> Vec<Event> {
        if token.1 != self.incarnation {
            return Vec::new();
        }
        if let Some(&covered) = self.tokens.get(&token.0) {
            self.tokens.retain(|&t, _| t > token.0);
            for item in &mut self.staged {
                if item.seq <= covered && !item.released {
                    item.released = true;
                    if item.completes {
                        if let Some(op) = item.op.and_then(|id| self.ops.get_mut(&id)) {
                            if op.state == OpState::Pending {
                                op.state = OpState::Completed;
                            }
                        }
                    }
                }
            }
        }
        let mut events = Vec::new();
        for item in &mut self.staged {
            if item.released && item.owner == self.installation.selected() {
                events.append(&mut item.events);
            }
        }
        self.staged
            .retain(|item| !(item.released && item.outgoing.is_empty() && item.events.is_empty()));
        events
    }

    /// Bytes whose save is confirmed. Handing them over removes them from the handle: a crash
    /// after this but before the blob without them is written re-stages them on restore, so the
    /// host may see a frame twice, which every receiver tolerates.
    pub fn take_outgoing(&mut self) -> Vec<Outgoing> {
        let mut out = Vec::new();
        for item in &mut self.staged {
            if item.released && item.owner == self.installation.selected() {
                out.append(&mut item.outgoing);
            }
        }
        self.staged
            .retain(|item| !(item.released && item.outgoing.is_empty() && item.events.is_empty()));
        out
    }

    /// Rebuild a handle from a blob. Pure: a refusal leaves the host's previous handle and blob
    /// as they were. Everything that was staged is staged again.
    pub fn restore(
        blob: &[u8],
        keys: impl IntoIterator<Item = SigningKey>,
    ) -> Result<Self, HandleError> {
        if blob.len() > MAX_HANDLE_BYTES {
            return Err(HandleError::TooLarge);
        }
        let mut input = blob;
        let wire: HandleWire =
            ciborium::from_reader(&mut input).map_err(|_| HandleError::Malformed)?;
        if !input.is_empty() {
            return Err(HandleError::Malformed);
        }
        if wire.version != HANDLE_FORMAT_VERSION {
            return Err(HandleError::UnsupportedVersion(wire.version));
        }
        let installation = Installation::restore_bytes(&wire.installation, keys)
            .map_err(HandleError::Installation)?;
        if wire.groups.len() > MAX_GROUPS
            || wire.histories.len() > MAX_GROUPS
            || wire.formed.len() > MAX_GROUPS
            || wire.staged.len() > MAX_STAGED_ITEMS
            || wire.ops.len() > MAX_KEPT_OPS + MAX_STAGED_ITEMS + MAX_PENDING_OPS
            || wire.left.len() > MAX_GROUPS
        {
            return Err(HandleError::TooLarge);
        }
        let mut groups = BTreeMap::new();
        for (id, bytes) in wire.groups {
            let group = VouchedGroup::from_bytes(&bytes).map_err(HandleError::Group)?;
            if installation.contacts(id.0).is_none()
                || group.id() != id.1
                || group.membership(id.0).is_none()
                || groups.insert(id, group).is_some()
            {
                return Err(HandleError::Invalid);
            }
        }
        let mut histories = BTreeMap::new();
        for (id, history) in wire.histories {
            let replay = history.replay().map_err(|_| HandleError::Invalid)?;
            let saved = groups.get(&id).ok_or(HandleError::Invalid)?;
            if replay.public_bytes().map_err(HandleError::Group)?
                != saved.public_bytes().map_err(HandleError::Group)?
                || histories.insert(id, history).is_some()
            {
                return Err(HandleError::Invalid);
            }
        }
        if histories.len() != groups.len() {
            return Err(HandleError::Invalid);
        }
        if wire.formed.len() > MAX_GROUPS {
            return Err(HandleError::TooLarge);
        }
        let mut formed = BTreeMap::new();
        for (scope, record) in wire.formed {
            let group = groups.get(&scope).ok_or(HandleError::Invalid)?;
            let history = histories.get(&scope).ok_or(HandleError::Invalid)?;
            let founders = history.founders().map_err(|_| HandleError::Invalid)?;
            if record.proposal.len() > MAX_FRAME_BYTES {
                return Err(HandleError::Invalid);
            }
            let genesis = crate::groups::merge::agreed_genesis(&record.proposal, &founders)
                .ok_or(HandleError::Invalid)?;
            let proposal_digest: [u8; 32] = Sha256::digest(&record.proposal).into();
            if !history.has_genesis(&genesis)
                || crate::groups::merge::binding_for(proposal_digest, &founders) != record.binding
                || group.id() != crate::groups::merge::group_id_for(record.binding)
                || group.history_root() != crate::groups::merge::history_id_for(record.binding)
                || formed.insert(scope, record).is_some()
            {
                return Err(HandleError::Invalid);
            }
        }
        let mut ops = BTreeMap::new();
        for op in wire.ops {
            if installation.contacts(op.owner).is_none()
                || op.id >= wire.next_op
                || op
                    .frames
                    .iter()
                    .any(|f| f.from != op.owner || f.bytes.len() > MAX_FRAME_BYTES)
                || ops.insert(op.id, op).is_some()
            {
                return Err(HandleError::Invalid);
            }
        }
        let mut staged = wire.staged;
        for item in &mut staged {
            if installation.contacts(item.owner).is_none()
                || item.seq >= wire.next_seq
                || item
                    .op
                    .is_some_and(|id| !ops.get(&id).is_some_and(|op| op.owner == item.owner))
                || item
                    .outgoing
                    .iter()
                    .any(|f| f.from != item.owner || f.bytes.len() > MAX_FRAME_BYTES)
            {
                return Err(HandleError::Invalid);
            }
            item.released = false;
        }
        if wire.sent.len() > MAX_PENDING_OPS || wire.received.len() > MAX_RECEIVED_INVITATIONS {
            return Err(HandleError::TooLarge);
        }
        let owns = |key: Key| installation.contacts(key).is_some();
        let mut sent = BTreeMap::new();
        for (scope, record) in wire.sent {
            let (owner, binding) = scope;
            if !owns(owner) {
                return Err(HandleError::Invalid);
            }
            let facts =
                SignedInvitation::inspect_frame(&record.frame).map_err(|_| HandleError::Invalid)?;
            let voucher_ok = DirectVoucher::from_admission_wire(&record.voucher)
                .is_ok_and(|v| v.invitation_binding() == binding);
            if facts.binding != binding
                || facts.inviter != owner
                || facts.candidate != record.candidate
                || facts.group != record.group
                || facts.deadline != record.deadline
                || !voucher_ok
                || record.consent.as_ref().is_some_and(|c| c.len() != 64)
                || !ops.get(&record.op).is_some_and(|op| op.owner == owner)
                || !groups.contains_key(&(owner, record.group))
                || joining::check_parent(
                    &facts,
                    record.nonce,
                    &histories
                        .get(&(owner, record.group))
                        .ok_or(HandleError::Invalid)?
                        .replay()
                        .map_err(|_| HandleError::Invalid)?,
                )
                .is_err()
                || sent.insert(scope, record).is_some()
            {
                return Err(HandleError::Invalid);
            }
        }
        let mut received = BTreeMap::new();
        for (scope, record) in wire.received {
            let (owner, binding) = scope;
            if !owns(owner) {
                return Err(HandleError::Invalid);
            }
            let facts =
                SignedInvitation::inspect_frame(&record.frame).map_err(|_| HandleError::Invalid)?;
            let voucher_ok = DirectVoucher::from_admission_wire(&record.voucher)
                .is_ok_and(|v| v.invitation_binding() == binding && v.candidate() == owner);
            if facts.binding != binding
                || facts.candidate != owner
                || facts.inviter != record.inviter
                || facts.group != record.group
                || facts.deadline != record.deadline
                || !voucher_ok
                || record.accepted.as_ref().is_some_and(|a| {
                    a.consent.len() != 64 || !ops.get(&a.op).is_some_and(|op| op.owner == owner)
                })
                || joining::check_parent(
                    &facts,
                    record.nonce,
                    &record.history.replay().map_err(|_| HandleError::Invalid)?,
                )
                .is_err()
                || received.insert(scope, record).is_some()
            {
                return Err(HandleError::Invalid);
            }
        }
        if wire.observed.len() > MAX_OBSERVED
            || wire.rounds.len() > MAX_OBSERVED + MAX_PENDING_OPS
            || wire.strays.len() > MAX_STRAY_VOTES
        {
            return Err(HandleError::TooLarge);
        }
        let local: LocalInstallation =
            serde_json::from_slice(&wire.local).map_err(|_| HandleError::Malformed)?;
        let mut observed = BTreeMap::new();
        for (scope, record) in wire.observed {
            let (owner, binding) = scope;
            if !owns(owner) {
                return Err(HandleError::Invalid);
            }
            let facts =
                SignedInvitation::inspect_frame(&record.frame).map_err(|_| HandleError::Invalid)?;
            let voucher_ok = DirectVoucher::from_admission_wire(&record.voucher)
                .is_ok_and(|v| v.invitation_binding() == binding);
            if facts.binding != binding
                || facts.inviter != record.inviter
                || facts.group != record.group
                || facts.deadline != record.deadline
                || !voucher_ok
                || record.consent.as_ref().is_some_and(|c| c.len() != 64)
                || !groups.contains_key(&(owner, record.group))
                || joining::check_parent(
                    &facts,
                    record.nonce,
                    &histories
                        .get(&(owner, record.group))
                        .ok_or(HandleError::Invalid)?
                        .replay()
                        .map_err(|_| HandleError::Invalid)?,
                )
                .is_err()
                || observed.insert(scope, record).is_some()
            {
                return Err(HandleError::Invalid);
            }
        }
        let vote_ok = |v: &VoteRec| v.signature.len() == 64;
        let mut rounds = BTreeMap::new();
        for (scope, round) in wire.rounds {
            if !owns(scope.0) {
                return Err(HandleError::Invalid);
            }
            if !groups.contains_key(&(scope.0, round.group))
                || !(sent.contains_key(&scope) || observed.contains_key(&scope))
                || !round.prepares.iter().chain(&round.commits).all(vote_ok)
                || round.prepares.len() > MAX_CERTIFICATE_SIGNERS
                || round.commits.len() > MAX_CERTIFICATE_SIGNERS
                || rounds.insert(scope, round).is_some()
            {
                return Err(HandleError::Invalid);
            }
        }
        if wire.strays.iter().any(|s| {
            !owns(s.owner) || !vote_ok(&s.vote) || !groups.contains_key(&(s.owner, s.group))
        }) {
            return Err(HandleError::Invalid);
        }
        if wire.departures.len() > MAX_DEPARTURES
            || wire
                .left
                .iter()
                .any(|(owner, id)| !owns(*owner) || !groups.contains_key(&(*owner, *id)))
        {
            return Err(HandleError::Invalid);
        }
        let mut departures = BTreeMap::new();
        for (owner, group, member, bytes) in wire.departures {
            let ok = SignedDeparture::from_bytes(&bytes).is_ok_and(|d| d.member() == member);
            if !ok
                || !owns(owner)
                || !groups.contains_key(&(owner, group))
                || departures.insert((owner, group, member), bytes).is_some()
            {
                return Err(HandleError::Invalid);
            }
        }
        Ok(Self {
            installation,
            groups,
            histories,
            ops,
            next_op: wire.next_op,
            staged,
            sent,
            received,
            local,
            observed,
            rounds,
            strays: wire.strays,
            left: wire.left.into_iter().collect(),
            departures,
            formed,
            next_seq: wire.next_seq,
            save_counter: wire.save_counter,
            tokens: BTreeMap::new(),
            incarnation: rand::random(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pruning_keeps_operations_referenced_by_staged_output() {
        let mut handle = GroupHandle::new(Installation::new(SigningKey::from_bytes(&[1; 32])));
        let first = handle
            .create(Policy::InviterOnly, &[], &mut rand::rngs::OsRng)
            .unwrap();
        let (token, _) = handle.save(0).unwrap();
        handle.confirm_saved(token);
        for _ in 0..MAX_KEPT_OPS {
            let id = handle.new_op(&[]);
            handle.ops.get_mut(&id).unwrap().state = OpState::Completed;
        }
        assert!(handle.ops.contains_key(&first.0));
        let (_, bytes) = handle.save(0).unwrap();
        assert!(GroupHandle::restore(&bytes, [SigningKey::from_bytes(&[1; 32])]).is_ok());
        handle.take_outgoing();
        handle.new_op(&[]);
        assert!(!handle.ops.contains_key(&first.0));
    }
}
