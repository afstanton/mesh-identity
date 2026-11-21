#![cfg(all(feature = "groups", feature = "test-support"))]
use mesh_identity::groups::evidence::SimulatedAuthority as _;
#[allow(dead_code)]
mod support;

use ed25519_dalek::SigningKey;
use mesh_identity::groups::{
    Error, Group, MemberLocalState, Policy, Vote,
    evidence::{CatchUp, SignedDeparture, VouchedGroup},
};
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Instant;
use support::{Inbox, Scenario, meet};

struct CheckpointDir(PathBuf);

impl CheckpointDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "mesh-departure-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn save(&self, installation: &MemberLocalState, departure: Option<&[u8; 136]>) -> PathBuf {
        let staged = self.0.join("installation.pending");
        let published = self.0.join("installation.json");
        let mut file = File::create(&staged).unwrap();
        let snapshot = serde_json::json!({
            "installation": installation.snapshot().unwrap(),
            "departure": departure.map(|bytes| bytes.as_slice()),
        });
        file.write_all(&serde_json::to_vec(&snapshot).unwrap())
            .unwrap();
        file.sync_all().unwrap();
        drop(file);
        fs::rename(staged, &published).unwrap();
        #[cfg(unix)]
        File::open(&self.0).unwrap().sync_all().unwrap();
        published
    }
}

impl Drop for CheckpointDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn read_checkpoint(path: &Path) -> (Vec<u8>, Option<Vec<u8>>) {
    let value: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    (
        serde_json::from_value(value["installation"].clone()).unwrap(),
        serde_json::from_value(value["departure"].clone()).unwrap(),
    )
}

#[test]
fn roster_vote_is_retried_from_the_transaction_after_send_before_acknowledgement() {
    use ed25519_dalek::Signature;
    use mesh_identity::groups::evidence::{RosterVotePhase, RosterVoteRequest};
    use mesh_identity::session::installation::{
        Error as SigningError, Installation, group_roster_vote_message,
    };

    let checkpoint_dir = CheckpointDir::new();
    let key = SigningKey::from_bytes(&[88; 32]);
    let mut signer = Installation::new(key.clone());
    let base = Installation::new(key.clone()).into_snapshot(0);
    let roster = VouchedGroup::new(9, [signer.selected()], Policy::InviterOnly);
    let (group, parent) = roster.rotation_context();
    let child = [2; 32];
    let alternative = [3; 32];
    let statement = group_roster_vote_message(group, parent, child, 1, 2);
    let outbound = |vote: &[u8]| [statement.as_slice(), vote].concat();
    let mut local = MemberLocalState::default();
    local.add_identity(
        roster.membership(signer.selected()).unwrap().identity(),
        "Voter".into(),
    );
    let request = || RosterVoteRequest {
        parent,
        child,
        round: 1,
        phase: RosterVotePhase::Commit,
    };
    let pending = checkpoint_dir.0.join("vote.pending");
    let committed = checkpoint_dir.0.join("vote");

    assert!(matches!(
        roster.sign_roster_vote_durable(&local, request(), &mut signer, |_, _| {
            Err(std::io::Error::other("injected disk failure"))
        }),
        Err(Error::RosterCheckpointFailed)
    ));
    assert!(!committed.exists());
    assert_eq!(
        signer.sign_group_roster_vote(group, parent, alternative, 1, 2),
        Err(SigningError::ConflictingRosterVote)
    );
    let sent = roster
        .sign_roster_vote_durable(&local, request(), &mut signer, |locks, vote| {
            let mut file = File::create(&pending)?;
            file.write_all(&outbound(vote))?;
            file.write_all(locks)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&pending, &committed)?;
            #[cfg(unix)]
            File::open(&checkpoint_dir.0)?.sync_all()?;
            Ok(())
        })
        .unwrap();
    drop(signer); // The signature was delivered, but its acknowledgement was lost.

    let sent = outbound(&sent.to_bytes());
    let transaction = fs::read(&committed).unwrap();
    let (retry, locks) = transaction.split_at(sent.len());
    let (message, signed) = retry.split_at(statement.len());
    let (signer_key, signature) = signed.split_at(32);
    assert_eq!(signer_key, key.verifying_key().as_bytes());
    key.verifying_key()
        .verify_strict(message, &Signature::from_slice(signature).unwrap())
        .unwrap();
    let mut signer = Installation::restore_with_roster_checkpoint(base, [key], locks).unwrap();
    assert_eq!(retry, sent);
    assert_eq!(
        signer.sign_group_roster_vote(group, parent, alternative, 2, 2),
        Err(SigningError::ConflictingRosterVote)
    );
    assert!(matches!(
        roster.sign_roster_round_change_durable(&local, 2, None, &mut signer, |_, _| {
            Err(std::io::Error::other("injected disk failure"))
        }),
        Err(Error::RosterCheckpointFailed)
    ));
    let mut outbound_report = Vec::new();
    let report = roster
        .sign_roster_round_change_durable(&local, 2, None, &mut signer, |_, bytes| {
            outbound_report.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();
    assert_eq!(report.to_bytes().unwrap(), outbound_report);
}

#[test]
fn roster_vote_is_retried_when_selected_identity_changed_and_preserves_retired_parents() {
    use mesh_identity::session::installation::{Error as SigningError, Installation};

    let key1 = SigningKey::from_bytes(&[89; 32]);
    let key2 = SigningKey::from_bytes(&[90; 32]);
    let mut signer = Installation::new(key1.clone());
    let id1 = signer.selected();
    let id2 = signer.add_identity(key2.clone()).unwrap();

    let (group, parent, child) = (10, [10; 32], [20; 32]);
    let alternative = [30; 32];
    let mut saved_locks = Vec::new();
    signer
        .sign_group_roster_vote_durable(group, parent, child, 1, 2, |locks, _| {
            saved_locks = locks.to_vec();
            Ok(())
        })
        .unwrap();

    // Switch selected identity to id2
    signer.select(id2, 0).unwrap();
    assert_eq!(signer.selected(), id2);

    // Also retire a parent on another group/parent
    let retired_parent = [40; 32];
    signer
        .retire_roster_parent(group, retired_parent, [0xEE; 32])
        .unwrap();

    // Take snapshot while id2 is selected
    let snapshot = signer.into_snapshot(0);

    // Restore with the checkpoint where id1 was the voter: must succeed and retain locks
    let mut restored =
        Installation::restore_with_roster_checkpoint(snapshot, [key1, key2], &saved_locks).unwrap();

    // id2 was selected on snapshot, so id2 has no locks on parent
    assert_eq!(restored.selected(), id2);

    // Check that the retired parent remains retired for any identity
    assert_eq!(
        restored.sign_group_roster_vote(group, retired_parent, child, 1, 1),
        Err(SigningError::ConflictingRosterVote)
    );

    // Switch to id1: check that id1 cannot contradict its committed vote
    restored.select(id1, 0).unwrap();
    assert_eq!(
        restored.sign_group_roster_vote(group, parent, alternative, 2, 2),
        Err(SigningError::ConflictingRosterVote)
    );
}

fn restore(path: &Path) -> (MemberLocalState, Option<Vec<u8>>) {
    let (installation, departure) = read_checkpoint(path);
    (MemberLocalState::restore(&installation).unwrap(), departure)
}

#[test]
fn restart_after_checkpoint_before_send_retries_without_showing_messages() {
    let checkpoints = CheckpointDir::new();
    let mut s = Scenario::new(150, Policy::InviterOnly);
    let alice = s.alice.selected();
    let sender = s.dave.selected();
    let stale = s.group.clone();
    let membership = s.group.membership(alice).unwrap();
    let mut inbox = Inbox::default();

    let checkpoint = {
        let mut local = MemberLocalState::default();
        local.add_identity(membership.identity(), "Alice".into());
        inbox.deliver(&stale, &local, &s.alice, membership, sender);
        assert_eq!(inbox, Inbox::one_message());
        local.leave(membership).unwrap();
        let context = s.group.departure_context(alice).unwrap();
        let bytes = SignedDeparture::new(context, &s.alice).unwrap().to_bytes();
        checkpoints.save(&local, Some(&bytes))
    };

    assert_eq!(s.group.membership(alice), Some(membership));
    let (local, pending) = restore(&checkpoint);
    inbox.deliver(&stale, &local, &s.alice, membership, sender);
    assert_eq!(local.departure_intents().collect::<Vec<_>>(), [membership]);
    let pending = pending.unwrap();
    assert!(
        s.group
            .apply_departure_message(&SignedDeparture::from_bytes(&pending).unwrap())
            .unwrap()
    );
    assert!(s.group.membership(alice).is_none());
    drop(local);

    // The acknowledgement is lost. Restart again and resend the saved bytes.
    let (mut restarted, retry) = restore(&checkpoint);
    let retry = retry.unwrap();
    assert_eq!(pending, retry);
    assert_eq!(restarted.departure_intents().next(), Some(membership));
    inbox.deliver(&stale, &restarted, &s.alice, membership, sender);
    assert!(
        !s.group
            .apply_departure_message(&SignedDeparture::from_bytes(&retry).unwrap())
            .unwrap()
    );

    s.group.prune_departures(&mut restarted);
    let (acknowledged, outbound) = restore(&checkpoints.save(&restarted, None));
    assert!(outbound.is_none());
    assert_eq!(acknowledged.departure_intents().count(), 0);
    for roster in [&stale, &s.group] {
        inbox.deliver(roster, &acknowledged, &s.alice, membership, sender);
    }
    assert_eq!(inbox, Inbox::one_message());
}

#[test]
fn removing_an_identity_keeps_its_signed_departure_but_cancels_pending_disclosure() {
    let mut s = Scenario::new(151, Policy::InviterOnly);
    let key = SigningKey::from_bytes(&[81; 32]);
    let removed = s.alice.add_identity(key.clone()).unwrap();
    let retained = s.alice.selected();
    let mut group = VouchedGroup::new(151, [removed, retained], Policy::InviterOnly);
    let stale = group.clone();
    let removed_tenure = group.membership(removed).unwrap();
    let retained_tenure = group.membership(retained).unwrap();
    let mut local = MemberLocalState::default();
    local.add_identity(removed_tenure.identity(), "Removed".into());
    local.add_identity(retained_tenure.identity(), "Retained".into());
    s.alice.select(removed, 1).unwrap();
    let request = s.alice.request_link(1, &mut s.rng);
    let first = s.bob.selected();
    let second = s
        .bob
        .add_identity(SigningKey::from_bytes(&[82; 32]))
        .unwrap();
    let pair = [first, second];
    let approval = s.bob.approve_link(&request, pair).unwrap();
    s.bob.select(second, 1).unwrap();
    let approvals = [approval, s.bob.approve_link(&request, pair).unwrap()];
    assert!(s.alice.preview_link(request, pair, &approvals, 1).is_some());
    local.leave(removed_tenure).unwrap();
    let bytes = SignedDeparture::new(group.departure_context(removed).unwrap(), &s.alice)
        .unwrap()
        .to_bytes();

    s.alice.select(retained, 2).unwrap();
    s.alice.remove_identity(removed).unwrap();
    assert!(s.alice.contacts(removed).is_none());
    assert!(group.may_present(&local, retained, retained_tenure));
    let checkpoints = CheckpointDir::new();
    let (mut restored, bytes) = restore(&checkpoints.save(&local, Some(&bytes)));
    let departure = SignedDeparture::from_bytes(&bytes.unwrap()).unwrap();
    assert!(group.apply_departure_message(&departure).unwrap());
    assert!(!group.apply_departure_message(&departure).unwrap());
    group.prune_departures(&mut restored);
    assert_eq!(restored.departure_intents().count(), 0);

    assert_eq!(s.alice.import_identity(key, removed).unwrap(), removed);
    s.alice.select(removed, 3).unwrap();
    assert!(s.alice.receive_link(request, pair, approvals, 3).is_none());
    assert!(!stale.may_present(&restored, removed, removed_tenure));
    assert!(group.may_present(&restored, retained, retained_tenure));
}

#[test]
fn an_older_device_backup_needs_roster_catch_up_before_resuming() {
    let mut s = Scenario::new(152, Policy::InviterOnly);
    let alice = s.alice.selected();
    let tenure = s.group.membership(alice).unwrap();
    let sender = s.dave.selected();
    let mut local = MemberLocalState::default();
    local.add_identity(tenure.identity(), "Alice".into());
    let checkpoints = CheckpointDir::new();
    let backup = checkpoints.save(&local, None);
    let mut restored_roster = s.group.clone();

    local.leave(tenure).unwrap();
    let departure =
        SignedDeparture::new(s.group.departure_context(alice).unwrap(), &s.alice).unwrap();
    assert!(s.group.apply_departure_message(&departure).unwrap());
    let (bytes, _) = read_checkpoint(&backup);
    let mut restored = MemberLocalState::restore_backup(&bytes).unwrap();
    let stale_invitation = restored_roster.invite(alice, s.bob.selected()).unwrap();
    assert!(!restored_roster.may_present(&restored, alice, tenure));
    assert!(
        restored_roster
            .sign_admission_vote(&restored, &stale_invitation, &s.alice, Vote::Approve)
            .is_err()
    );
    assert_eq!(
        restored_roster.reconcile_backup(&mut restored, &s.group),
        CatchUp::Applied
    );
    assert!(restored_roster.backup_roster_confirmed(&restored));
    assert!(!s.alice_offline.backup_roster_confirmed(&restored));
    assert!(restored_roster.membership(alice).is_none());
    let mut inbox = Inbox::default();
    inbox.deliver(&restored_roster, &restored, &s.alice, tenure, sender);
    assert_eq!(inbox, Inbox::default());
    assert_eq!(
        restored_roster.catch_up(&s.alice_offline),
        CatchUp::OlderSnapshot
    );
    assert!(!restored_roster.may_present(&restored, alice, tenure));

    // Another group remains gated until it gets its own current roster.
    let mut other = VouchedGroup::new(2, [alice, sender], Policy::InviterOnly);
    let other_tenure = other.membership(alice).unwrap();
    // The local identity number matches in both fixture rosters.
    assert_eq!(tenure.identity(), other_tenure.identity());
    let invitation = other.invite(sender, s.bob.selected()).unwrap();
    assert!(!other.may_present(&restored, alice, other_tenure));
    assert!(
        other
            .sign_admission_vote(&restored, &invitation, &s.alice, Vote::Approve)
            .is_err()
    );
    let trusted_other = other.clone();
    assert_eq!(
        other.reconcile_backup(&mut restored, &trusted_other),
        CatchUp::AlreadyCurrent
    );
    assert!(other.may_present(&restored, alice, other_tenure));
    assert!(
        other
            .sign_admission_vote(&restored, &invitation, &s.alice, Vote::Approve)
            .is_ok()
    );
    let checkpoint = restored.snapshot().unwrap();
    let restarted = MemberLocalState::restore(&checkpoint).unwrap();
    assert!(other.may_present(&restarted, alice, other_tenure));
    let copied = MemberLocalState::restore_backup(&checkpoint).unwrap();
    assert!(!other.may_present(&copied, alice, other_tenure));

    let fork = VouchedGroup::new(2, [alice, sender], Policy::InviterOnly);
    assert_eq!(fork.revision(), other.revision());
    assert_eq!(fork.membership(alice), Some(other_tenure));
    assert!(!fork.may_present(&restarted, alice, other_tenure));
    let fork_invitation = fork.invite(sender, s.bob.selected()).unwrap();
    assert!(
        fork.sign_admission_vote(&restarted, &fork_invitation, &s.alice, Vote::Approve)
            .is_err()
    );

    // This plain view matches the confirmed group's ID, revision and tenure,
    // but cannot establish which history it represents.
    let mut plain = Group::new(
        2,
        [
            other_tenure.identity(),
            other.membership(sender).unwrap().identity(),
        ],
        Policy::InviterOnly,
    );
    assert_eq!(
        plain.membership(other_tenure.identity()),
        Some(other_tenure)
    );
    assert!(local.may_present(other_tenure, &plain));
    assert!(local.may_vote(other_tenure, &plain));
    assert!(!restarted.may_present(other_tenure, &plain));
    assert!(!restarted.may_vote(other_tenure, &plain));

    let sender_tenure = other.membership(sender).unwrap();
    assert!(plain.apply_departure(sender_tenure).unwrap());
    assert_eq!(
        plain.membership(other_tenure.identity()),
        Some(other_tenure)
    );
    assert!(!restarted.may_present(other_tenure, &plain));
    assert!(!restarted.may_vote(other_tenure, &plain));
}

#[test]
fn restored_member_reconciles_with_a_quorum_and_signs_only_for_the_active_roster() {
    use mesh_identity::groups::evidence::{
        RosterCertificate, RosterFreshnessChallenge, RosterFreshnessError, RosterVotePhase,
    };
    use mesh_identity::session::installation::Installation;

    let mut s = Scenario::new(153, Policy::Majority);
    let extra = Installation::new(SigningKey::from_bytes(&[84; 32]));
    let (alice, carol, bob, dave, eve) = (
        s.alice.selected(),
        s.carol.selected(),
        s.bob.selected(),
        s.dave.selected(),
        s.eve.selected(),
    );
    let mut current = VouchedGroup::new(
        153,
        [alice, carol, dave, eve, extra.selected()],
        Policy::Majority,
    );
    current.enroll_recovery(dave, [alice, eve]).unwrap();
    current.enroll_recovery(alice, [dave, eve]).unwrap();
    meet(&mut s.alice, &mut s.bob, 1, &mut s.rng);

    let active_local = |group: &VouchedGroup, member: &Installation| {
        let tenure = group.membership(member.selected()).unwrap();
        let mut local = MemberLocalState::default();
        local.add_identity(tenure.identity(), "Member".into());
        local
    };
    let mut restored_roster = current.clone();
    let checkpoint = active_local(&current, &s.alice).snapshot().unwrap();
    let mut restored = MemberLocalState::restore_backup(&checkpoint).unwrap();
    let tenure = current.membership(alice).unwrap();
    let departure =
        SignedDeparture::new(current.departure_context(carol).unwrap(), &s.carol).unwrap();
    let child = current.signed_departure_child(&departure).unwrap();
    let (group_id, parent) = current.rotation_context();
    let now = Instant::now();
    let challenge = RosterFreshnessChallenge::new(group_id, now);
    let request = current.request_recovery(dave, bob).unwrap();
    let ejection = current.propose_signed_ejection(&s.dave, eve).unwrap();
    assert!(!current.may_present(&restored, alice, tenure));
    assert!(
        current
            .attest_roster_freshness(&restored, challenge.query(), &s.alice)
            .is_err()
    );
    assert!(
        current
            .sign_roster_vote(
                &restored,
                parent,
                child,
                1,
                RosterVotePhase::Prepare,
                &s.alice
            )
            .is_err()
    );
    assert!(
        current
            .sign_roster_round_change(&restored, 2, None, &s.alice)
            .is_err()
    );
    assert!(
        current
            .sign_ejection_vote(&restored, &ejection, &s.alice)
            .is_err()
    );
    assert!(
        current
            .sign_recovery_approval(&restored, &request, &s.alice)
            .is_err()
    );

    let signers = [&s.alice, &s.dave, &s.eve, &extra];
    let sign_phase = |phase| {
        signers
            .iter()
            .map(|signer| {
                current
                    .sign_roster_vote(
                        &active_local(&current, signer),
                        parent,
                        child,
                        1,
                        phase,
                        signer,
                    )
                    .unwrap()
            })
            .collect()
    };
    let certificate = RosterCertificate {
        group: group_id,
        parent,
        child,
        round: 1,
        prepares: sign_phase(RosterVotePhase::Prepare),
        commits: sign_phase(RosterVotePhase::Commit),
    };
    assert_eq!(
        current.prune_roster_locks(&s.dave, parent),
        Err(Error::StaleProposal)
    );
    // A signer with a commit lock cannot vouch for its old local head.
    assert!(
        current
            .attest_roster_freshness(&active_local(&current, &s.dave), challenge.query(), &s.dave)
            .is_err()
    );
    current
        .apply_certified_signed_departure(&departure, &certificate)
        .unwrap();
    assert!(current.membership(carol).is_none());
    assert_eq!(
        current.prune_roster_locks(&s.dave, child),
        Err(Error::StaleProposal)
    );
    let unrelated = VouchedGroup::new(
        group_id,
        [alice, dave, eve, extra.selected()],
        Policy::Majority,
    );
    assert_eq!(
        unrelated.prune_roster_locks(&s.dave, parent),
        Err(Error::StaleProposal)
    );
    current.prune_roster_locks(&s.dave, parent).unwrap();
    current.prune_roster_locks(&s.dave, parent).unwrap();
    let stale_dave = active_local(&restored_roster, &s.dave);
    assert!(
        restored_roster
            .attest_roster_freshness(&stale_dave, challenge.query(), &s.dave)
            .is_err()
    );
    assert!(
        restored_roster
            .sign_roster_vote(
                &stale_dave,
                parent,
                child,
                1,
                RosterVotePhase::Commit,
                &s.dave
            )
            .is_err()
    );
    let responses = [&s.dave, &s.eve, &extra].map(|signer| {
        current
            .attest_roster_freshness(&active_local(&current, signer), challenge.query(), signer)
            .unwrap()
    });
    assert_eq!(
        current.verify_roster_freshness(&challenge, &responses[..2], now),
        Err(RosterFreshnessError::Unconfirmed)
    );
    assert_eq!(
        current.verify_roster_freshness(&challenge, &[responses[0]; 3], now),
        Err(RosterFreshnessError::Unconfirmed)
    );
    assert_eq!(
        current.verify_roster_freshness(
            &RosterFreshnessChallenge::new(group_id, now),
            &responses,
            now
        ),
        Err(RosterFreshnessError::Unconfirmed)
    );
    assert_eq!(
        current.verify_roster_freshness(
            &challenge,
            &responses,
            now + RosterFreshnessChallenge::WINDOW
        ),
        Err(RosterFreshnessError::ExpiredChallenge)
    );
    assert_eq!(
        restored_roster.verify_roster_freshness(&challenge, &responses, now),
        Err(RosterFreshnessError::Unconfirmed)
    );
    assert_eq!(
        restored_roster.reconcile_backup_with_freshness(
            &mut restored,
            &current,
            RosterFreshnessChallenge::new(group_id, now),
            &responses,
            now,
        ),
        Err(RosterFreshnessError::Unconfirmed)
    );
    assert_eq!(restored_roster.rotation_context(), (group_id, parent));
    assert!(!restored_roster.may_present(&restored, alice, tenure));
    assert_eq!(
        restored_roster.reconcile_backup_with_freshness(
            &mut restored,
            &current,
            challenge,
            &responses,
            now
        ),
        Ok(CatchUp::Applied)
    );
    assert!(restored_roster.may_present(&restored, alice, tenure));
    assert!(
        restored_roster
            .sign_ejection_vote(&restored, &ejection, &s.alice)
            .is_err()
    );
    assert!(
        restored_roster
            .sign_recovery_approval(&restored, &request, &s.alice)
            .is_err()
    );
    let ejection = restored_roster
        .propose_signed_ejection(&s.dave, eve)
        .unwrap();
    assert!(
        restored_roster
            .sign_ejection_vote(&restored, &ejection, &s.alice)
            .is_ok()
    );
    let recovery = restored_roster.request_recovery(dave, bob).unwrap();
    assert!(
        restored_roster
            .sign_recovery_approval(&restored, &recovery, &s.alice)
            .is_ok()
    );
    let holder_recovery = restored_roster.request_recovery(alice, bob).unwrap();
    assert!(
        restored_roster
            .sign_recovery_veto(&restored, &holder_recovery, &s.alice)
            .is_ok()
    );
    assert!(matches!(
        restored_roster.sign_roster_round_change(&restored, 2, None, &s.alice),
        Err(Error::RosterSigningStateUnconfirmed)
    ));
    assert!(
        restored_roster
            .sign_roster_round_change(&restored, 2, None, &s.carol)
            .is_err()
    );
}

#[test]
fn same_head_reconciliation_cannot_recover_lost_roster_signing_locks() {
    use mesh_identity::groups::evidence::{RosterFreshnessChallenge, RosterVotePhase};
    use mesh_identity::session::installation::{Error as SigningError, Installation};

    let s = Scenario::new(155, Policy::InviterOnly);
    let key = SigningKey::from_bytes(&[87; 32]);
    let live = Installation::new(key.clone());
    let roster_keys = [
        live.selected(),
        s.carol.selected(),
        s.dave.selected(),
        s.eve.selected(),
    ];
    let group = VouchedGroup::new(156, roster_keys, Policy::InviterOnly);
    let local_for = |member: &Installation| {
        let mut local = MemberLocalState::default();
        let tenure = group.membership(member.selected()).unwrap();
        local.add_identity(tenure.identity(), "Member".into());
        local
    };
    let local_checkpoint = local_for(&live).snapshot().unwrap();
    let old_signing_checkpoint = Installation::new(key.clone()).into_snapshot(0);
    let (group_id, parent) = group.rotation_context();
    let child = |member: &Installation| {
        let context = group.departure_context(member.selected()).unwrap();
        group
            .signed_departure_child(&SignedDeparture::new(context, member).unwrap())
            .unwrap()
    };
    let committed = child(&s.carol);
    let alternative = child(&s.dave);
    group
        .sign_roster_vote(
            &local_for(&live),
            parent,
            committed,
            1,
            RosterVotePhase::Commit,
            &live,
        )
        .unwrap();

    let mut restored = MemberLocalState::restore_backup(&local_checkpoint).unwrap();
    let voter = Installation::restore_backup(old_signing_checkpoint, [key.clone()]).unwrap();
    let now = Instant::now();
    let challenge = RosterFreshnessChallenge::new(group_id, now);
    let responses = [&s.carol, &s.dave, &s.eve].map(|member| {
        group
            .attest_roster_freshness(&local_for(member), challenge.query(), member)
            .unwrap()
    });
    let mut view = group.clone();
    assert_eq!(
        view.reconcile_backup_with_freshness(&mut restored, &group, challenge, &responses, now),
        Ok(CatchUp::AlreadyCurrent)
    );
    let tenure = view.membership(voter.selected()).unwrap();
    assert!(view.may_present(&restored, voter.selected(), tenure));
    assert!(matches!(
        view.sign_roster_vote(
            &restored,
            parent,
            alternative,
            1,
            RosterVotePhase::Commit,
            &voter
        ),
        Err(Error::RosterSigningStateUnconfirmed)
    ));
    let restarted = Installation::restore(voter.into_snapshot(0), [key]).unwrap();
    assert_eq!(
        restarted.sign_group_roster_vote(group_id, parent, alternative, 1, 2),
        Err(SigningError::RosterSigningStateUnconfirmed)
    );
    assert_eq!(
        restarted.sign_group_roster_freshness(group_id, parent, view.revision(), [1; 32]),
        Err(SigningError::RosterSigningStateUnconfirmed)
    );
}

#[test]
fn small_group_without_a_required_signer_can_start_an_independent_group() {
    use mesh_identity::groups::evidence::{
        AdmissionError, RosterFreshnessChallenge, RosterFreshnessError, SignedInvitation,
    };
    use mesh_identity::session::installation::Installation;

    for size in 1..=3 {
        let s = Scenario::new(154, Policy::InviterOnly);
        let key = SigningKey::from_bytes(&[85; 32]);
        let lost = Installation::new(key.clone());
        let lost_key = lost.selected();
        let surviving = [&s.carol, &s.dave];
        let original = VouchedGroup::new(
            154,
            std::iter::once(lost_key).chain(surviving[..size - 1].iter().map(|s| s.selected())),
            Policy::InviterOnly,
        );
        let original_tenure = original.membership(lost_key).unwrap();
        let local_for = |group: &VouchedGroup, signer: &Installation| {
            let mut local = MemberLocalState::default();
            let tenure = group.membership(signer.selected()).unwrap();
            local.add_identity(tenure.identity(), "Member".into());
            local
        };

        let pending = original
            .invite_until(lost_key, s.bob.selected(), 200)
            .unwrap();
        let old_invitation = SignedInvitation::new(&pending, &lost).unwrap();
        let checkpoint = local_for(&original, &lost).snapshot().unwrap();
        let key_checkpoint = lost.into_snapshot(0);
        let restored_signer = Installation::restore_backup(key_checkpoint, [key]).unwrap();
        let mut restored = MemberLocalState::restore_backup(&checkpoint).unwrap();
        let mut old_view = original.clone();
        let now = Instant::now();
        let challenge = RosterFreshnessChallenge::new(154, now);
        let available: Vec<_> = surviving[..size - 1]
            .iter()
            .map(|member| {
                original
                    .attest_roster_freshness(
                        &local_for(&original, member),
                        challenge.query(),
                        member,
                    )
                    .unwrap()
            })
            .collect();
        assert_eq!(original.required_roster_freshness_votes(), Ok(size));
        assert!(
            original
                .attest_roster_freshness(&restored, challenge.query(), &restored_signer)
                .is_err()
        );
        assert_eq!(
            old_view.reconcile_backup_with_freshness(
                &mut restored,
                &original,
                challenge,
                &available,
                now,
            ),
            Err(RosterFreshnessError::Unconfirmed)
        );
        assert!(!old_view.backup_roster_confirmed(&restored));
        assert!(!old_view.may_present(&restored, lost_key, original_tenure));

        // Participants explicitly form a new group under fresh state. The
        // restored player chooses a fresh key and the old backup stays gated.
        let new_signer = Installation::new(SigningKey::from_bytes(&[86; 32]));
        let selected = [&new_signer, &s.carol, &s.dave];
        let replacement = VouchedGroup::new(
            155,
            selected[..size].iter().map(|s| s.selected()),
            Policy::InviterOnly,
        );
        assert!(replacement.membership(lost_key).is_none());
        assert!(matches!(
            replacement.receive_invitation(&old_invitation),
            Err(AdmissionError::Roster(Error::StaleProposal))
        ));
        assert_eq!(old_view.catch_up(&replacement), CatchUp::ConflictingHistory);

        let challenge = RosterFreshnessChallenge::new(155, now);
        let responses: Vec<_> = selected[..size]
            .iter()
            .map(|member| {
                replacement
                    .attest_roster_freshness(
                        &local_for(&replacement, member),
                        challenge.query(),
                        member,
                    )
                    .unwrap()
            })
            .collect();
        let new_tenure = replacement.membership(new_signer.selected()).unwrap();
        assert_eq!(
            replacement.confirmed_membership(&new_signer, &challenge, &responses, now),
            Ok(Some(new_tenure))
        );
        assert!(replacement.may_present(
            &local_for(&replacement, &new_signer),
            new_signer.selected(),
            new_tenure,
        ));
        assert!(!old_view.may_present(&restored, lost_key, original_tenure));
    }
}
