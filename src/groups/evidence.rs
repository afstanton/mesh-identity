//! Encounter-backed evidence for ordered group admission governance.
//! The public API groups signed evidence and authenticated roster transitions.

use crate::contact::ContactStatus;
use crate::groups::{BackupRoster, Error, Group, MemberLocalState, Membership, Policy};
use crate::session::installation::{Identity as Key, Installation};
use ed25519_dalek::VerifyingKey;
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

mod agreement;
mod electorate;
mod invitation;
mod membership;
// Equivocation proofs: the pure verifier (W4a) and the chain-carried type (W4b).
#[allow(dead_code)]
mod proof;
pub use assembly::AssemblyShortfall;
use proof::CarriedProof;
pub use proof::EquivocationProof;
pub use wire::{
    CertificateRef, CertificateV1, MAX_CERTIFICATE_PROOFS, VersionedCertificate, WireError,
};
#[cfg(test)]
mod apply_v1_tests;
mod assembly;
#[cfg(test)]
mod assembly_tests;
#[cfg(test)]
mod certificate_v1_tests;
#[cfg(test)]
mod chain_tests;
#[cfg(test)]
mod enrollment_tests;
mod persist;
#[cfg(test)]
mod persist_tests;
#[cfg(test)]
mod policy_change_tests;
mod recognition;
#[cfg(test)]
mod recognition_tests;
mod recovery;
#[cfg(test)]
mod reported_tests;
#[cfg(test)]
mod roster_change_tests;
#[cfg(any(test, feature = "test-support"))]
mod simulation;
mod suspension;
#[cfg(test)]
mod suspension_arithmetic_tests;
#[cfg(test)]
mod suspension_tests;
mod voucher;
mod wire;

pub use agreement::{
    MAX_CERTIFICATE_SIGNERS, RecoveryCertificate, RosterCertificate, RosterFreshnessChallenge,
    RosterFreshnessError, RosterFreshnessQuery, RosterPrepareProof, RosterRoundChange, RosterVote,
    RosterVotePhase, RosterVoteRequest, RoundChangeCollector, RoundReportDelivery,
};
pub use invitation::{
    INVITATION_BODY_LEN, InvitationFacts, InvitationFrameVersion, InvitationInbox,
    InvitationProgress, SignedAdmissionConsent, SignedAdmissionVote, SignedInvitation,
    SignedInvitationCancellation, VouchedProposal,
};
pub use membership::{RemovalProposal, SignedDeparture, SignedEjectionVote, SignedRotation};
pub use persist::{GroupSnapshotError, MAX_GROUP_BYTES};
pub use recognition::SignedRecognition;
pub use recovery::{
    RECOVERY_VETO_WINDOW_MS, RecoveryInbox, RecoveryRequest, RecoveryStatus, SignedRecoveryConsent,
    SignedRecoveryDecision, SignedRecoveryEnrollment, SignedRecoveryRequest,
};
#[cfg(any(test, feature = "test-support"))]
pub use simulation::SimulatedAuthority;
pub use suspension::{SUSPENSION_RESERVED_OFFLINE, SignedSuspension};
pub(crate) use voucher::verified_contact;
pub use voucher::{
    AdmissionUpdate, AssessedReport, DirectVoucher, ForwardedVoucher, IntroducerReliance,
    ReportedReliance, ReportedVoucher, Verification, VoucherWithdrawal, WithdrawalDelivery,
};

#[derive(Debug, PartialEq, Eq)]
pub enum AdmissionError {
    Roster(Error),
    MalformedInvitationFrame,
    UnsupportedInvitationVersion(u8),
    VoucherRequired,
    VoucherExpired,
    VoucherWithdrawn,
    InvalidExpiry,
    InvitationExpired,
    InvitationDeclined,
    InvitationCancelled,
    IssuerKeySuspect,
    /// The inbox is at its bound; wait for pending items to expire or resolve.
    InboxFull,
}

impl From<Error> for AdmissionError {
    fn from(error: Error) -> Self {
        Self::Roster(error)
    }
}

type VoucherId = [u8; 32];

fn random_id() -> [u8; 32] {
    let mut id = [0; 32];
    OsRng.fill_bytes(&mut id);
    id
}

fn parse_verifying_key(bytes: &[u8; 32]) -> Result<VerifyingKey, Error> {
    match VerifyingKey::from_bytes(bytes) {
        Ok(vk) if !vk.is_weak() => Ok(vk),
        _ => Err(Error::Ineligible),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CatchUp {
    Applied,
    AlreadyCurrent,
    OlderSnapshot,
    ConflictingHistory,
}

struct RosterHistory {
    id: [u8; 32],
    parent: Option<Arc<RosterHistory>>,
    /// Proofs carried by the transition that created this node. Empty for ordinary nodes.
    #[allow(dead_code)] // read by tests; certificates will read it in W4c
    carried: Vec<CarriedProof>,
    /// Subject keys of every proof on this node and its ancestors. Shared with the parent
    /// when this node carries nothing, so inheritance is structural and forks cannot leak
    /// proofs into one another.
    inherited: Arc<BTreeSet<Key>>,
    /// Keys reported by the transition that created this node. Empty for ordinary nodes.
    #[allow(dead_code)] // read by tests; the certified suspension operation writes it (AS-3)
    new_reports: Vec<Key>,
    /// Every key reported on this node and its ancestors. A reported key loses its vote but
    /// stays in the denominator. Shared like `inherited`.
    reported: Arc<BTreeSet<Key>>,
    /// Recognitions made by the transition that created this node: identity, counter, device
    /// nonce. Empty for ordinary nodes.
    #[allow(dead_code)] // read by tests
    new_recognitions: Vec<Recognition>,
    /// The latest recognized (counter, nonce) per identity on this node and its ancestors: which
    /// device may sign for the identity.
    recognized: Arc<BTreeMap<Key, (u64, [u8; 32])>>,
}

/// One recognition: identity, counter, device nonce.
type Recognition = (Key, u64, [u8; 32]);

impl RosterHistory {
    fn root(id: [u8; 32]) -> Arc<Self> {
        Arc::new(Self {
            id,
            parent: None,
            carried: Vec::new(),
            inherited: Arc::new(BTreeSet::new()),
            new_reports: Vec::new(),
            reported: Arc::new(BTreeSet::new()),
            new_recognitions: Vec::new(),
            recognized: Arc::new(BTreeMap::new()),
        })
    }

    fn child(
        parent: &Arc<Self>,
        id: [u8; 32],
        carried: Vec<CarriedProof>,
        new_reports: Vec<Key>,
        new_recognitions: Vec<Recognition>,
    ) -> Arc<Self> {
        let inherited = if carried.is_empty() {
            Arc::clone(&parent.inherited)
        } else {
            let mut keys = (*parent.inherited).clone();
            keys.extend(carried.iter().map(CarriedProof::subject));
            Arc::new(keys)
        };
        let reported = if new_reports.is_empty() {
            Arc::clone(&parent.reported)
        } else {
            let mut keys = (*parent.reported).clone();
            keys.extend(new_reports.iter().copied());
            Arc::new(keys)
        };
        let recognized = if new_recognitions.is_empty() {
            Arc::clone(&parent.recognized)
        } else {
            let mut map = (*parent.recognized).clone();
            for (key, counter, nonce) in &new_recognitions {
                map.insert(*key, (*counter, *nonce));
            }
            Arc::new(map)
        };
        Arc::new(Self {
            id,
            parent: Some(Arc::clone(parent)),
            carried,
            inherited,
            new_reports,
            reported,
            new_recognitions,
            recognized,
        })
    }
}

impl Drop for RosterHistory {
    /// Unlink iteratively: a long history must not overflow the stack when dropped.
    fn drop(&mut self) {
        let mut next = self.parent.take();
        while let Some(node) = next {
            match Arc::try_unwrap(node) {
                Ok(mut owned) => next = owned.parent.take(),
                Err(_) => break, // another owner keeps the rest alive
            }
        }
    }
}

/// Application export of the current roster, scoped to a participating identity.
#[derive(serde::Serialize)]
pub struct RosterExport {
    pub group: u64,
    pub roster: [u8; 32],
    pub members: Vec<Key>,
}

impl std::fmt::Debug for RosterExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RosterExport")
            .field("member_count", &self.members.len())
            .finish_non_exhaustive()
    }
}

/// Admission policy plus one direct voucher from the inviting identity.
#[derive(Clone)]
pub struct VouchedGroup {
    group: Group,
    history: Arc<RosterHistory>,
    identities: BTreeMap<Key, crate::groups::Identity>,
    now: u64,
    cancelled_invitations: BTreeMap<[u8; 32], u64>,
    withdrawn: BTreeSet<(Key, VoucherId)>,
    admission_evidence: BTreeMap<Key, VoucherId>,
    predecessors: BTreeMap<Key, Key>,
    key_replacements: BTreeMap<Key, Key>,
    retired: BTreeSet<Key>,
    suspect: BTreeSet<Key>,
    recovery_witnesses: BTreeMap<crate::groups::Identity, [Key; 2]>,
    // Every peer retains an opaque commitment. Only the owner and witnesses
    // receive its opening until a recovery is explicitly presented.
    recovery_commitments: BTreeMap<crate::groups::Identity, [u8; 32]>,
    recovery_salts: BTreeMap<crate::groups::Identity, [u8; 32]>,
    /// Owners whose enrolled witness left or was removed; they must enroll again.
    degraded_recovery: BTreeSet<crate::groups::Identity>,
}

/// Longest lifetime accepted for an invitation, cancellation or voucher. An unbounded deadline
/// would let one member keep entries in every peer's state forever.
pub const MAX_LIFETIME_MS: u64 = 30 * 24 * 60 * 60 * 1000;

/// Eligibility for distributing new group material under one agreed roster.
pub struct DistributionPlan {
    history: Arc<RosterHistory>,
    revision: u64,
}

impl VouchedGroup {
    pub fn new(id: u64, members: impl IntoIterator<Item = Key>, policy: Policy) -> Self {
        Self::new_with_history(id, members, policy, random_id())
    }

    /// As `new`, with the history id given. A formed group derives it from its agreed formation
    /// so every participant builds the identical group.
    pub(crate) fn new_with_history(
        id: u64,
        members: impl IntoIterator<Item = Key>,
        policy: Policy,
        history: [u8; 32],
    ) -> Self {
        let mut identities = BTreeMap::new();
        for member in members {
            let next = crate::groups::Identity(identities.len() as u64);
            identities.entry(member).or_insert(next);
        }
        Self {
            group: Group::new(id, identities.values().copied(), policy),
            history: RosterHistory::root(history),
            identities,
            now: 0,
            cancelled_invitations: BTreeMap::new(),
            withdrawn: BTreeSet::new(),
            admission_evidence: BTreeMap::new(),
            predecessors: BTreeMap::new(),
            key_replacements: BTreeMap::new(),
            retired: BTreeSet::new(),
            suspect: BTreeSet::new(),
            recovery_witnesses: BTreeMap::new(),
            recovery_commitments: BTreeMap::new(),
            recovery_salts: BTreeMap::new(),
            degraded_recovery: BTreeSet::new(),
        }
    }

    /// Serialize an initial roster for an introduction. The recipient needs
    /// the SHA-256 digest of these exact bytes from an authenticated source.
    pub fn genesis_bytes(&self) -> Result<Vec<u8>, Error> {
        if self.revision() != 0 || !(1..=192).contains(&self.identities.len()) {
            return Err(Error::Ineligible);
        }
        let policy = self.group.policy.encode();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"MSG1");
        bytes.extend_from_slice(&self.group.id.to_be_bytes());
        bytes.extend_from_slice(&self.history.id);
        bytes.push(policy.len() as u8);
        bytes.extend_from_slice(&policy);
        let mut members: Vec<_> = self.identities.iter().collect();
        members.sort_unstable_by_key(|(_, id)| **id);
        for (&key, _) in members {
            parse_verifying_key(&key)?;
            bytes.extend_from_slice(&key);
        }
        Ok(bytes)
    }

    pub fn from_authenticated_genesis(
        bytes: &[u8],
        expected_digest: [u8; 32],
    ) -> Result<Self, Error> {
        if !(45 + 1 + 32..=45 + 9 + 192 * 32).contains(&bytes.len()) || &bytes[..4] != b"MSG1" {
            return Err(Error::Ineligible);
        }
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if digest != expected_digest {
            return Err(Error::Ineligible);
        }
        let policy_end = 45 + usize::from(bytes[44]);
        let policy = Policy::decode(bytes.get(45..policy_end).ok_or(Error::Ineligible)?)
            .ok_or(Error::Ineligible)?;
        let member_bytes = &bytes[policy_end..];
        if member_bytes.len() % 32 != 0 {
            return Err(Error::Ineligible);
        }
        let member_count = member_bytes.len() / 32;
        if !(1..=192).contains(&member_count) {
            return Err(Error::Ineligible);
        }
        let mut members = Vec::with_capacity(member_count);
        for chunk in member_bytes.chunks_exact(32) {
            let key: [u8; 32] = chunk.try_into().unwrap();
            parse_verifying_key(&key)?;
            members.push(key);
        }
        let mut group = Self::new(
            u64::from_be_bytes(bytes[4..12].try_into().unwrap()),
            members.iter().copied(),
            policy,
        );
        if group.identities.len() != members.len() {
            return Err(Error::Ineligible);
        }
        group.history = RosterHistory::root(bytes[12..44].try_into().unwrap());
        Ok(group)
    }

    /// Export only the current member keys. Contact associations remain local.
    pub fn export_roster(&self, viewer: &Installation) -> Result<RosterExport, Error> {
        self.membership(viewer.selected())
            .ok_or(Error::Ineligible)?;
        let (group, roster) = self.rotation_context();
        Ok(RosterExport {
            group,
            roster,
            members: self
                .identities
                .keys()
                .copied()
                .filter(|key| self.membership(*key).is_some())
                .collect(),
        })
    }

    /// Resolve an exact key within a group the selected identity belongs to.
    pub fn discover_member(&self, viewer: &Installation, key: Key) -> Result<Option<Key>, Error> {
        self.membership(viewer.selected())
            .ok_or(Error::Ineligible)?;
        Ok(self.membership(key).map(|_| key))
    }

    pub fn membership(&self, key: Key) -> Option<Membership> {
        self.group.membership(*self.identities.get(&key)?)
    }

    pub fn is_key_or_successor(&self, current: Key, original: Key) -> bool {
        if current == original {
            return true;
        }
        let mut curr = current;
        while let Some(&pred) = self
            .key_replacements
            .get(&curr)
            .or_else(|| self.predecessors.get(&curr))
        {
            if pred == original {
                return true;
            }
            curr = pred;
        }
        false
    }

    pub fn eligible_electorate_excluding(&self, target: Key) -> usize {
        self.identities
            .keys()
            .filter(|&&key| {
                key != target && self.membership(key).is_some() && !self.is_barred(&key)
            })
            .count()
    }

    /// Capture the agreed state used to authorize a new distribution.
    pub fn plan_distribution(&self) -> DistributionPlan {
        DistributionPlan {
            history: Arc::clone(&self.history),
            revision: self.revision(),
        }
    }

    /// Resolve recipients against the same roster at dispatch time.
    /// The caller supplies the current agreed roster and handles encryption.
    pub fn distribution_recipients(&self, plan: &DistributionPlan) -> Result<Vec<Key>, Error> {
        if self.revision() != plan.revision || self.history.id != plan.history.id {
            return Err(Error::StaleProposal);
        }
        Ok(self
            .identities
            .keys()
            .copied()
            .filter(|key| self.membership(*key).is_some() && !self.is_barred(key))
            .collect())
    }

    pub fn prune_departures(&self, local: &mut MemberLocalState) {
        local.prune_departures(&self.group);
    }

    pub fn may_present(
        &self,
        local: &MemberLocalState,
        recipient: Key,
        tenure: Membership,
    ) -> bool {
        self.membership(recipient) == Some(tenure)
            && self.backup_roster_confirmed(local)
            && local.permits_tenure(tenure, &self.group)
    }

    fn contains_backup_roster(&self, confirmed: &BackupRoster) -> bool {
        if confirmed.revision > self.revision() {
            return false;
        }
        let mut history = &self.history;
        for _ in confirmed.revision..self.revision() {
            let Some(parent) = &history.parent else {
                return false;
            };
            history = parent;
        }
        history.id == confirmed.history
    }

    /// Whether the backup restore gate permits this roster for this group.
    pub fn backup_roster_confirmed(&self, local: &MemberLocalState) -> bool {
        local.backup_rosters.as_ref().is_none_or(|groups| {
            groups
                .get(&self.group.id)
                .is_some_and(|confirmed| self.contains_backup_roster(confirmed))
        })
    }

    /// Reconcile with a snapshot the caller has independently authenticated
    /// and established as current. An old backup alone cannot establish freshness.
    /// Simulation only: nothing here proves `trusted_current` is current. Real callers use
    /// `reconcile_backup_with_freshness`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn reconcile_backup(
        &mut self,
        local: &mut MemberLocalState,
        trusted_current: &Self,
    ) -> CatchUp {
        self.reconcile_backup_unchecked(local, trusted_current)
    }

    fn reconcile_backup_unchecked(
        &mut self,
        local: &mut MemberLocalState,
        trusted_current: &Self,
    ) -> CatchUp {
        if let Some(confirmed) = local
            .backup_rosters
            .as_ref()
            .and_then(|groups| groups.get(&self.group.id))
        {
            if !trusted_current.contains_backup_roster(confirmed) {
                return CatchUp::ConflictingHistory;
            }
        }
        let result = self.catch_up(trusted_current);
        if matches!(result, CatchUp::Applied | CatchUp::AlreadyCurrent) {
            if let Some(groups) = &mut local.backup_rosters {
                groups.insert(
                    self.group.id,
                    BackupRoster {
                        revision: self.revision(),
                        history: self.history.id,
                    },
                );
            }
        }
        result
    }

    fn check_local_voter(
        &self,
        local: &MemberLocalState,
        voter: &Installation,
    ) -> Result<Key, Error> {
        let key = voter.selected();
        let tenure = self.membership(key).ok_or(Error::Ineligible)?;
        if !self.may_present(local, key, tenure) || !self.group.is_eligible_voter(tenure.identity())
        {
            return Err(Error::Ineligible);
        }
        self.check_voting_role(voter)?;
        Ok(key)
    }

    /// Gate application effects for an authenticated sender on the local
    /// recipient's current view. Blocking is private to the selected identity.
    pub fn may_present_from(
        &self,
        local: &MemberLocalState,
        recipient: &Installation,
        tenure: Membership,
        sender: Key,
    ) -> bool {
        self.may_present(local, recipient.selected(), tenure)
            && self.membership(sender).is_some()
            && !recipient
                .contacts(recipient.selected())
                .and_then(|contacts| contacts.get(&sender))
                .is_some_and(|contact| contact.status == ContactStatus::Blocked)
    }

    /// Identify the exact parent whose rotation authorization is requested.
    pub fn rotation_context(&self) -> (u64, [u8; 32]) {
        (self.group.id, self.history.id)
    }

    /// Retire signing state for an ancestor of this authenticated roster.
    /// The current head and unrelated histories cannot authorize pruning.
    #[cfg(any(test, feature = "test-support"))]
    pub fn prune_roster_locks(
        &self,
        installation: &Installation,
        parent: [u8; 32],
    ) -> Result<(), Error> {
        let mut ancestor = self.history.parent.as_deref();
        while let Some(history) = ancestor {
            if history.id == parent {
                installation
                    .retire_roster_parent(self.group.id, parent, self.history.id)
                    .map_err(|_| Error::StaleProposal)?;
                return Ok(());
            }
            ancestor = history.parent.as_deref();
        }
        Err(Error::StaleProposal)
    }

    /// Apply a policy decision authorized by the simulation's roster authority.
    pub(crate) fn apply_policy_change(
        &mut self,
        parent: u64,
        policy: Policy,
    ) -> Result<bool, Error> {
        if parent != self.revision() {
            return Err(Error::StaleProposal);
        }
        if self.is_closed() {
            return Err(Error::Ineligible);
        }
        if policy == self.group.policy {
            return Ok(false);
        }
        let child = self.derived_child(b"policy", &[&policy.encode()]);
        self.set_policy_at_child(policy, child, Vec::new())?;
        Ok(true)
    }

    /// The consensus child for changing the group's admission policy at the current head.
    /// A closed group and a policy equal to the current one have nothing to certify.
    pub fn policy_child(&self, policy: Policy) -> Result<[u8; 32], Error> {
        if self.is_closed() || policy == self.group.policy {
            return Err(Error::Ineligible);
        }
        Ok(self.derived_child(b"policy", &[&policy.encode()]))
    }

    /// Change the admission policy under a roster certificate. The certificate is the whole
    /// authorization: the roster quorum is stricter than any admission policy.
    pub fn apply_certified_policy_change<'c>(
        &mut self,
        policy: Policy,
        certificate: impl Into<CertificateRef<'c>>,
    ) -> Result<(), Error> {
        let child = self.policy_child(policy)?;
        let carried = self.verify_certificate(child, certificate.into())?;
        self.set_policy_at_child(policy, child, carried)
    }

    fn set_policy_at_child(
        &mut self,
        policy: Policy,
        child: [u8; 32],
        carried: Vec<CarriedProof>,
    ) -> Result<(), Error> {
        self.group.advance()?;
        self.group.policy = policy;
        self.record_roster_child_carrying(child, carried);
        Ok(())
    }

    pub fn is_closed(&self) -> bool {
        self.group.roster.is_empty()
    }

    pub fn policy(&self) -> crate::groups::Policy {
        self.group.policy
    }

    pub fn id(&self) -> u64 {
        self.group.id
    }

    pub fn revision(&self) -> u64 {
        self.group.revision
    }

    /// Current members and the revision each tenure began, for a merge view.
    pub(crate) fn current_members(&self) -> Vec<(Key, u64)> {
        self.identities
            .keys()
            .filter_map(|&key| Some((key, self.membership(key)?.joined_at())))
            .collect()
    }

    /// Id of the first node of this group's roster chain.
    pub(crate) fn history_root(&self) -> [u8; 32] {
        let mut node = &self.history;
        while let Some(parent) = &node.parent {
            node = parent;
        }
        node.id
    }

    /// Every report on the chain with the revision of the node that carried it. A node's
    /// revision is its depth from the root.
    pub(crate) fn reports_by_revision(&self) -> Vec<(Key, u64)> {
        let mut reports = Vec::new();
        let mut node = &self.history;
        let mut revision = self.group.revision;
        loop {
            reports.extend(node.new_reports.iter().map(|key| (*key, revision)));
            match &node.parent {
                Some(parent) => {
                    node = parent;
                    revision = revision.saturating_sub(1);
                }
                None => return reports,
            }
        }
    }

    /// A roster child identifier determined by the parent state and the operation, so every
    /// node that applies the same change reaches the same history.
    fn derived_child(&self, kind: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        let mut hash = Sha256::new()
            .chain_update(b"mesh/group-admission/derived-child/v1\0")
            .chain_update(self.group.id.to_be_bytes())
            .chain_update(self.history.id)
            .chain_update((kind.len() as u32).to_be_bytes())
            .chain_update(kind);
        for part in parts {
            hash.update((part.len() as u32).to_be_bytes());
            hash.update(part);
        }
        hash.finalize().into()
    }

    #[cfg(test)]
    fn record_roster_child(&mut self, id: [u8; 32]) {
        self.record_roster_child_carrying(id, Vec::new());
    }

    /// Report a key at a new child with no authorization. Tests only: the certified
    /// suspension operation (AS-3) replaces it.
    #[cfg(test)]
    fn report_key_unauthorized(&mut self, key: Key) {
        self.group.advance().unwrap();
        let child = self.derived_child(b"report", &[&key]);
        self.record_roster_child_reporting(child, Vec::new(), vec![key]);
    }

    /// Record a history child that carries proofs, and derive the suspension mirrors from
    /// them. This is the one place `suspect` and `excluded` gain entries.
    fn record_roster_child_carrying(&mut self, id: [u8; 32], carried: Vec<CarriedProof>) {
        self.record_roster_child_reporting(id, carried, Vec::new());
    }

    /// As `record_roster_child_carrying`, and also record keys reported by this transition.
    /// A report does not exclude anyone from the denominator, so `suspect` and `excluded`
    /// are untouched by it.
    fn record_roster_child_reporting(
        &mut self,
        id: [u8; 32],
        carried: Vec<CarriedProof>,
        reports: Vec<Key>,
    ) {
        self.record_roster_child_full(id, carried, reports, Vec::new());
    }

    /// As `record_roster_child_reporting`, and also record device recognitions.
    fn record_roster_child_full(
        &mut self,
        id: [u8; 32],
        carried: Vec<CarriedProof>,
        reports: Vec<Key>,
        recognitions: Vec<Recognition>,
    ) {
        self.cancelled_invitations.clear();
        for proof in &carried {
            let key = proof.subject();
            if let Some(&identity) = self.identities.get(&key) {
                self.group.exclude(identity);
            }
            self.suspect.insert(key);
        }
        self.history = RosterHistory::child(&self.history, id, carried, reports, recognitions);
    }

    /// Subject keys of every proof carried on this authenticated chain, including keys that
    /// have since left the roster. Chain-borne, so identical on every peer holding the chain.
    #[allow(dead_code)]
    pub(crate) fn inherited_proof_keys(&self) -> &BTreeSet<Key> {
        &self.history.inherited
    }

    /// Keys reported on this authenticated chain, including keys that have since left the
    /// roster. They cannot vote but still count in the denominator.
    #[allow(dead_code)] // used by the certified suspension operation (AS-3) and tests
    pub(crate) fn reported_keys(&self) -> &BTreeSet<Key> {
        &self.history.reported
    }

    /// The device the chain recognizes for `key`: its counter and device nonce.
    pub(crate) fn recognized_device(&self, key: &Key) -> Option<(u64, [u8; 32])> {
        self.history.recognized.get(key).copied()
    }

    pub(crate) fn recognitions(&self) -> &BTreeMap<Key, (u64, [u8; 32])> {
        &self.history.recognized
    }

    /// A key that may not vote: proven or suspect (it also leaves the denominator), or reported
    /// (it stays in the denominator).
    pub(crate) fn is_barred(&self, key: &Key) -> bool {
        self.suspect.contains(key) || self.history.reported.contains(key)
    }

    /// Apply a trusted roster snapshot and retain only locally received withdrawals.
    /// A revision number alone gives no basis for choosing between forks.
    pub fn catch_up(&mut self, remote: &Self) -> CatchUp {
        if self.group.id != remote.group.id {
            return CatchUp::ConflictingHistory;
        }
        let (newer, older) = if remote.revision() >= self.revision() {
            (remote, &*self)
        } else {
            (&*self, remote)
        };
        let mut ancestor = &newer.history;
        for _ in older.revision()..newer.revision() {
            let Some(parent) = &ancestor.parent else {
                return CatchUp::ConflictingHistory;
            };
            ancestor = parent;
        }
        // One operation can have certificates carrying different proof subjects.
        // Matching operation IDs alone therefore does not establish common ancestry.
        // Fail closed rather than replace an accepted chain with one that drops evidence;
        // reconciling proof variants requires a separate authenticated protocol.
        if ancestor.id != older.history.id
            || ancestor.inherited != older.history.inherited
            || ancestor.reported != older.history.reported
            || ancestor.recognized != older.history.recognized
        {
            return CatchUp::ConflictingHistory;
        }
        match remote.revision().cmp(&self.revision()) {
            std::cmp::Ordering::Equal => CatchUp::AlreadyCurrent,
            std::cmp::Ordering::Less => CatchUp::OlderSnapshot,
            std::cmp::Ordering::Greater => {
                // Time is local: a snapshot must not be able to advance this node's clock and
                // expire every pending invitation and voucher.
                let now = self.now;
                let withdrawn = std::mem::take(&mut self.withdrawn);
                // Private recovery openings belong to this node and must not be overwritten.
                // Preserve local openings, while adopting any openings from remote that this
                // node did not already hold.
                let mut recovery_salts = std::mem::take(&mut self.recovery_salts);
                let mut recovery_witnesses = std::mem::take(&mut self.recovery_witnesses);
                let remote_salts = remote.recovery_salts.clone();
                let remote_witnesses = remote.recovery_witnesses.clone();
                *self = remote.clone();
                self.cancelled_invitations.clear();
                self.now = now;
                self.withdrawn = withdrawn;
                for (owner, salt) in remote_salts {
                    recovery_salts.entry(owner).or_insert(salt);
                }
                for (owner, witnesses) in remote_witnesses {
                    recovery_witnesses.entry(owner).or_insert(witnesses);
                }
                self.recovery_salts = recovery_salts;
                self.recovery_witnesses = recovery_witnesses;
                self.prune_stale_recovery_openings();
                CatchUp::Applied
            }
        }
    }

    /// Prune private recovery openings after a catch-up or snapshot adoption.
    /// Retain local openings whose commitment still matches the remote roster;
    /// follow any witness key rotations that occurred along the accepted chain;
    /// and drop openings whose owner re-enrolled with a different commitment or departed.
    fn prune_stale_recovery_openings(&mut self) {
        // Follow key rotations for any enrolled witnesses
        let identities = &self.identities;
        let key_replacements = &self.key_replacements;
        for witnesses in self.recovery_witnesses.values_mut() {
            for w in witnesses.iter_mut() {
                if !identities.contains_key(w) {
                    if let Some((&current_key, _)) = identities.iter().find(|&(&key, _)| {
                        let mut curr = key;
                        while let Some(&prev) = key_replacements.get(&curr) {
                            if prev == *w {
                                return true;
                            }
                            curr = prev;
                        }
                        false
                    }) {
                        *w = current_key;
                    }
                }
            }
        }

        let stale_owners: Vec<crate::groups::Identity> = self
            .recovery_salts
            .iter()
            .filter_map(|(owner_id, &salt)| {
                let Some(&commitment) = self.recovery_commitments.get(owner_id) else {
                    return Some(*owner_id);
                };
                let Some(&witnesses) = self.recovery_witnesses.get(owner_id) else {
                    return Some(*owner_id);
                };
                if self
                    .recovery_commitment(*owner_id, witnesses, salt)
                    .as_ref()
                    == Ok(&commitment)
                {
                    None
                } else {
                    Some(*owner_id)
                }
            })
            .collect();
        for owner_id in stale_owners {
            self.recovery_salts.remove(&owner_id);
            self.recovery_witnesses.remove(&owner_id);
        }
        self.recovery_witnesses
            .retain(|owner_id, _| self.recovery_salts.contains_key(owner_id));
    }

    pub fn advance_time(&mut self, now: u64) {
        self.now = self.now.max(now);
        self.cancelled_invitations
            .retain(|_, deadline| *deadline > self.now);
    }

    pub(crate) fn set_replay_time(&mut self, now: u64) {
        self.now = now;
        self.cancelled_invitations
            .retain(|_, deadline| *deadline > self.now);
    }
}
