//! Fault-injection and tamper tests for the acknowledged handoff.

use super::*;
use rand::rngs::OsRng;
use std::io;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

const P1: [u8; 32] = [1; 32];
const P2: [u8; 32] = [2; 32];
const C1: [u8; 32] = [11; 32];
const C2: [u8; 32] = [12; 32];

fn vote(i: &mut Installation, group: u64, parent: [u8; 32], child: [u8; 32]) -> Result<(), Error> {
    i.sign_group_roster_vote_durable(group, parent, child, 1, 1, |_, _| Ok(()))
        .map(|_| ())
}

/// Old device (voting) and new device (gated), same identity, with a nonce and exported bundle.
struct World {
    old: Installation,
    new: Installation,
    nonce: [u8; 32],
}

fn world() -> World {
    let old = Installation::new(key(7));
    let mut new = Installation::new(key(7));
    new.gate_voting();
    let nonce = new.device_nonce(&mut OsRng);
    World { old, new, nonce }
}

fn handoff(w: &mut World) -> HandoffBundle {
    w.old.begin_handoff(w.nonce, |_, _| Ok(())).unwrap()
}

fn accept(w: &mut World, b: &HandoffBundle) -> Result<VotingState, Error> {
    w.new.accept_handoff(b, |_| Ok(()))
}

#[test]
fn the_old_device_stops_and_the_new_one_takes_over_with_the_locks() {
    let mut w = world();
    vote(&mut w.old, 1, P1, C1).unwrap();
    vote(&mut w.old, 2, P2, C1).unwrap();
    assert_eq!(vote(&mut w.new, 1, P1, C2), Err(Error::NotVotingDevice));
    let bundle = handoff(&mut w);
    assert_eq!(vote(&mut w.old, 1, P1, C1), Err(Error::NotVotingDevice));
    assert_eq!(w.old.voting_state(), VotingState::Stopped);
    assert_eq!(accept(&mut w, &bundle), Ok(VotingState::Voting));
    for (group, parent) in [(1, P1), (2, P2)] {
        assert_eq!(
            vote(&mut w.new, group, parent, C2),
            Err(Error::ConflictingRosterVote)
        );
        assert_eq!(vote(&mut w.new, group, parent, C1), Ok(()));
    }
    assert_eq!(w.new.voting_record(w.new.selected()).counter, 1);
}

#[test]
fn a_failed_write_on_begin_keeps_the_old_device_voting() {
    let mut w = world();
    vote(&mut w.old, 1, P1, C1).unwrap();
    let failed = w
        .old
        .begin_handoff(w.nonce, |_, _| Err(io::Error::other("disk")));
    assert_eq!(failed, Err(Error::HandoffWriteFailed));
    assert_eq!(w.old.voting_state(), VotingState::Voting);
    assert_eq!(vote(&mut w.old, 1, P1, C1), Ok(()));
    handoff(&mut w);
    assert_eq!(w.old.voting_state(), VotingState::Stopped);
}

#[test]
fn a_crash_after_the_write_comes_back_stopped_and_the_bundle_still_works() {
    let mut w = world();
    vote(&mut w.old, 1, P1, C1).unwrap();
    let old_snapshot = w.old.into_snapshot(0); // snapshot taken before the handoff
    let mut crashed = Installation::restore(old_snapshot, [key(7)]).unwrap();
    let mut saved: Option<(Vec<u8>, Vec<u8>)> = None;
    let bundle = crashed
        .begin_handoff(w.nonce, |b, r| {
            saved = Some((b.to_bytes(), r.to_vec()));
            Ok(())
        })
        .unwrap();
    drop(crashed); // crash before the host stored a new snapshot
    let (saved_bundle, record) = saved.unwrap();
    let snapshot_before = Installation::new(key(7)).into_snapshot(0);
    let restored =
        Installation::restore_with_handoff_record(snapshot_before, [key(7)], &record).unwrap();
    assert_eq!(restored.voting_state(), VotingState::Stopped);
    // The lock the old device held survives the restore from an empty snapshot.
    let mut restored = restored;
    assert_eq!(vote(&mut restored, 1, P1, C1), Err(Error::NotVotingDevice));
    // Re-sending the persisted bytes is the same bundle, and it still imports.
    let resent = HandoffBundle::from_bytes(&saved_bundle).unwrap();
    assert_eq!(resent, bundle);
    w.old = restored;
    assert_eq!(accept(&mut w, &resent), Ok(VotingState::Voting));
    assert_eq!(
        vote(&mut w.new, 1, P1, C2),
        Err(Error::ConflictingRosterVote)
    );
}

#[test]
fn importing_twice_never_loses_a_lock_the_new_device_took_since() {
    let mut w = world();
    vote(&mut w.old, 1, P1, C1).unwrap();
    let bundle = handoff(&mut w);
    accept(&mut w, &bundle).unwrap();
    vote(&mut w.new, 2, P2, C2).unwrap(); // a lock the bundle does not hold
    assert_eq!(accept(&mut w, &bundle), Ok(VotingState::Voting));
    assert_eq!(
        vote(&mut w.new, 2, P2, C1),
        Err(Error::ConflictingRosterVote)
    );
    assert_eq!(
        vote(&mut w.new, 1, P1, C2),
        Err(Error::ConflictingRosterVote)
    );
}

#[test]
fn a_failed_write_on_accept_changes_nothing() {
    let mut w = world();
    vote(&mut w.old, 1, P1, C1).unwrap();
    let bundle = handoff(&mut w);
    let failed = w
        .new
        .accept_handoff(&bundle, |_| Err(io::Error::other("disk")));
    assert_eq!(failed, Err(Error::HandoffWriteFailed));
    assert_eq!(w.new.voting_state(), VotingState::Gated);
    assert_eq!(vote(&mut w.new, 1, P1, C1), Err(Error::NotVotingDevice));
    assert_eq!(accept(&mut w, &bundle), Ok(VotingState::Voting));
}

fn rejected(w: &mut World, bundle: &HandoffBundle, expected: Error) {
    assert_eq!(accept(w, bundle), Err(expected));
    assert_eq!(w.new.voting_state(), VotingState::Gated);
    assert_eq!(vote(&mut w.new, 1, P1, C1), Err(Error::NotVotingDevice));
}

#[test]
fn a_tampered_bundle_is_refused_without_changing_state() {
    let mut w = world();
    vote(&mut w.old, 1, P1, C1).unwrap();
    vote(&mut w.old, 2, P2, C1).unwrap();
    let good = handoff(&mut w);
    assert_eq!(good.checkpoints.len(), 2);

    let mut stripped = good.clone();
    stripped.checkpoints.remove(0);
    rejected(&mut w, &stripped, Error::InvalidHandoff);

    let mut emptied = good.clone();
    emptied.checkpoints.clear();
    rejected(&mut w, &emptied, Error::InvalidHandoff);

    let mut modified = good.clone();
    *modified.checkpoints[0].bytes.last_mut().unwrap() ^= 1;
    rejected(&mut w, &modified, Error::InvalidHandoff);

    let mut duplicated = good.clone();
    duplicated.checkpoints.push(good.checkpoints[0].clone());
    rejected(&mut w, &duplicated, Error::InvalidHandoff);

    let mut reordered = good.clone();
    reordered.checkpoints.reverse();
    rejected(&mut w, &reordered, Error::InvalidHandoff);

    let mut counter = good.clone();
    counter.counter += 1;
    rejected(&mut w, &counter, Error::InvalidHandoff);

    let mut statement = good.clone();
    statement.statement_signature[0] ^= 1;
    rejected(&mut w, &statement, Error::InvalidHandoff);

    let mut truncated = good.clone();
    truncated.envelope_signature.pop();
    rejected(&mut w, &truncated, Error::InvalidHandoff);

    assert_eq!(accept(&mut w, &good), Ok(VotingState::Voting));
}

/// Re-sign a hand-built bundle as the identity would, to test checks behind the signature.
fn resigned(mut bundle: HandoffBundle, signer: &SigningKey) -> HandoffBundle {
    bundle.statement_signature = signer
        .sign(&statement_message(
            bundle.identity,
            bundle.counter,
            bundle.recipient,
        ))
        .to_bytes()
        .to_vec();
    bundle.envelope_signature = signer
        .sign(&envelope_message(
            bundle.identity,
            bundle.counter,
            bundle.recipient,
            &bundle.statement_signature,
            &bundle.checkpoints,
        ))
        .to_bytes()
        .to_vec();
    bundle
}

#[test]
fn a_validly_signed_but_malformed_bundle_is_still_refused() {
    let mut w = world();
    vote(&mut w.old, 1, P1, C1).unwrap();
    let good = handoff(&mut w);

    let mut version = good.clone();
    version.checkpoints[0].version = 2;
    rejected(&mut w, &resigned(version, &key(7)), Error::InvalidHandoff);

    let mut garbage = good.clone();
    garbage.checkpoints[0].bytes = vec![0xff, 0x00];
    rejected(&mut w, &resigned(garbage, &key(7)), Error::InvalidHandoff);

    let mut trailing = good.clone();
    trailing.checkpoints[0].bytes.push(0);
    rejected(&mut w, &resigned(trailing, &key(7)), Error::InvalidHandoff);

    let mut spliced = good.clone();
    spliced.checkpoints.push(HandoffCheckpoint {
        participant: 1,
        ..good.checkpoints[0].clone()
    });
    rejected(&mut w, &resigned(spliced, &key(7)), Error::InvalidHandoff);
}

#[test]
fn a_bundle_for_another_device_or_identity_is_refused() {
    let mut w = world();
    let other = w.old.begin_handoff([9; 32], |_, _| Ok(())).unwrap();
    rejected(&mut w, &other, Error::WrongHandoffRecipient);

    let mut stranger = Installation::new(key(8));
    let foreign = stranger.begin_handoff(w.nonce, |_, _| Ok(())).unwrap();
    rejected(&mut w, &foreign, Error::InvalidHandoff);

    let signed_by_other_key = resigned(other.clone(), &key(8));
    rejected(&mut w, &signed_by_other_key, Error::InvalidHandoff);

    let mut no_nonce = Installation::new(key(7));
    no_nonce.gate_voting();
    assert_eq!(
        no_nonce.accept_handoff(&other, |_| Ok(())),
        Err(Error::WrongHandoffRecipient)
    );
}

#[test]
fn old_and_equal_counters_are_refused_and_hand_back_works() {
    let mut w = world();
    vote(&mut w.old, 1, P1, C1).unwrap();
    let first = handoff(&mut w);
    accept(&mut w, &first).unwrap();
    // A delayed copy of an older bundle changes nothing.
    assert_eq!(accept(&mut w, &first), Ok(VotingState::Voting)); // same grant: idempotent
    // The new device hands back to the old one at counter 2.
    let old_nonce = w.old.device_nonce(&mut OsRng);
    let back = w.new.begin_handoff(old_nonce, |_, _| Ok(())).unwrap();
    assert_eq!(back.counter(), 2);
    assert_eq!(
        w.old.accept_handoff(&back, |_| Ok(())),
        Ok(VotingState::Voting)
    );
    assert_eq!(
        vote(&mut w.old, 1, P1, C2),
        Err(Error::ConflictingRosterVote)
    );
    // The first bundle must not revive the new device, now stopped at counter 2.
    assert_eq!(accept(&mut w, &first), Err(Error::StaleHandoff));
    assert_eq!(w.new.voting_state(), VotingState::Stopped);
    assert_eq!(vote(&mut w.new, 1, P1, C1), Err(Error::NotVotingDevice));
    // A replay of the hand-back at the device that already took it is idempotent; the earlier
    // handoff bundle is stale for it.
    assert_eq!(
        w.old.accept_handoff(&back, |_| Ok(())),
        Ok(VotingState::Voting)
    );
    assert_eq!(
        w.old.accept_handoff(&first, |_| Ok(())),
        Err(Error::WrongHandoffRecipient)
    );
}

#[test]
fn a_stopped_or_gated_device_cannot_begin_a_handoff() {
    let mut w = world();
    assert_eq!(
        w.new.begin_handoff([5; 32], |_, _| Ok(())).map(|_| ()),
        Err(Error::NotVotingDevice)
    );
    handoff(&mut w);
    assert_eq!(
        w.old.begin_handoff([5; 32], |_, _| Ok(())).map(|_| ()),
        Err(Error::NotVotingDevice)
    );
}

#[test]
fn the_counter_at_its_maximum_cannot_hand_off_again() {
    let mut w = world();
    let id = w.old.selected();
    w.old.voting.insert(
        id,
        VotingRecord {
            counter: u64::MAX,
            state: VotingState::Voting,
            holder: None,
        },
    );
    assert_eq!(
        w.old.begin_handoff(w.nonce, |_, _| Ok(())).map(|_| ()),
        Err(Error::CounterExhausted)
    );
    assert_eq!(w.old.voting_state(), VotingState::Voting);
}

#[test]
fn a_lock_conflict_leaves_the_new_device_gated_and_keeps_every_lock() {
    let mut w = world();
    // The new device signed C2 on a parent while an unrelated copy signed C1: a real conflict.
    w.new
        .voting
        .insert(w.new.selected(), VotingRecord::default());
    vote(&mut w.new, 1, P1, C2).unwrap();
    vote(&mut w.old, 1, P1, C1).unwrap();
    vote(&mut w.old, 2, P2, C1).unwrap();
    let bundle = handoff(&mut w);
    assert_eq!(accept(&mut w, &bundle), Ok(VotingState::Gated));
    assert_eq!(
        vote(&mut w.new, 2, P2, C2),
        Err(Error::RosterSigningStateUnconfirmed)
    );
    assert_eq!(w.new.voting_record(w.new.selected()).counter, 1);
    // A replay cannot clear the conflict block; recovery is required.
    assert_eq!(accept(&mut w, &bundle), Err(Error::StaleHandoff));
}

#[test]
fn state_survives_a_snapshot_and_restore() {
    let mut w = world();
    let bundle = handoff(&mut w);
    accept(&mut w, &bundle).unwrap();
    let snapshot = w.new.into_snapshot(0);
    let restored = Installation::restore(snapshot, [key(7)]).unwrap();
    assert_eq!(restored.voting_state(), VotingState::Voting);
    let snapshot = w.old.into_snapshot(0);
    let restored = Installation::restore(snapshot, [key(7)]).unwrap();
    assert_eq!(restored.voting_state(), VotingState::Stopped);
}

#[test]
fn bundles_round_trip_and_reject_trailing_bytes() {
    let mut w = world();
    vote(&mut w.old, 1, P1, C1).unwrap();
    let bundle = handoff(&mut w);
    let mut bytes = bundle.to_bytes();
    assert_eq!(HandoffBundle::from_bytes(&bytes).unwrap(), bundle);
    bytes.push(0);
    assert_eq!(
        HandoffBundle::from_bytes(&bytes),
        Err(Error::InvalidHandoff)
    );
}

// ---- H2: signing gates and stated outcomes -------------------------------------------------

/// Every group-scoped signing method on a device that is not voting.
fn all_group_signatures(i: &mut Installation) -> Vec<Result<[u8; 64], Error>> {
    let id = i.selected();
    let other = [9; 32];
    vec![
        i.sign_group_ejection([1; 32]),
        i.sign_group_invitation_cancellation([1; 32]),
        i.sign_group_invitation([1; 32]),
        i.sign_group_admission_consent(1, P1, [2; 32], other),
        i.sign_group_admission_vote(1, P1, [2; 32], 1),
        i.sign_group_departure(1, P1),
        i.sign_group_recovery_enrollment(1, P1, [3; 32]),
        i.sign_group_suspension(1, P1, other),
        i.sign_group_rotation(1, P1, id, other),
        i.sign_group_recovery(1, P1, id, other, [4; 32], 1),
        i.sign_voucher_withdrawal(1, [5; 32]),
        i.sign_admission_voucher([6; 32]),
        i.sign_group_roster_vote_durable(1, P1, C1, 1, 1, |_, _| Ok(())),
        i.sign_group_roster_freshness(1, P1, 0, [7; 32]),
    ]
}

#[test]
fn every_group_signature_works_while_voting_and_none_after_stopping() {
    let mut w = world();
    let voting = all_group_signatures(&mut w.old);
    // rotation to a key we do not hold is refused for its own reason, not the gate
    assert!(voting.iter().all(|r| *r != Err(Error::NotVotingDevice)));
    handoff(&mut w);
    for (index, result) in all_group_signatures(&mut w.old).into_iter().enumerate() {
        assert_eq!(
            result,
            Err(Error::NotVotingDevice),
            "method {index} signed while stopped"
        );
    }
    for (index, result) in all_group_signatures(&mut w.new).into_iter().enumerate() {
        assert_eq!(
            result,
            Err(Error::NotVotingDevice),
            "method {index} signed while gated"
        );
    }
}

#[test]
fn a_restored_backup_is_gated_and_a_handoff_lifts_the_block_it_caused() {
    let mut w = world();
    vote(&mut w.old, 1, P1, C1).unwrap();
    // The new device is a backup of an installation with no locks (older than the old device).
    let backup = Installation::new(key(7)).into_snapshot(0);
    let mut restored = Installation::restore_backup(backup, [key(7)]).unwrap();
    assert_eq!(restored.voting_state(), VotingState::Gated);
    assert_eq!(
        restored.sign_group_roster_vote_durable(1, P1, C2, 1, 1, |_, _| Ok(())),
        Err(Error::RosterSigningStateUnconfirmed)
    );
    assert_eq!(
        restored.sign_group_departure(1, P1),
        Err(Error::NotVotingDevice)
    );
    let nonce = restored.device_nonce(&mut OsRng);
    let bundle = w.old.begin_handoff(nonce, |_, _| Ok(())).unwrap();
    assert_eq!(
        restored.accept_handoff(&bundle, |_| Ok(())),
        Ok(VotingState::Voting)
    );
    assert_eq!(
        vote(&mut restored, 1, P1, C2),
        Err(Error::ConflictingRosterVote)
    );
    assert_eq!(vote(&mut restored, 1, P1, C1), Ok(()));
}

#[test]
fn a_conflict_free_handoff_does_not_clear_a_checkpoint_conflict_flag() {
    let mut w = world();
    let id = w.old.selected();
    w.new.voting.insert(id, VotingRecord::default()); // voting, flag set below
    w.new.roster_signing_disabled = true;
    let bundle = handoff(&mut w);
    assert_eq!(accept(&mut w, &bundle), Ok(VotingState::Voting));
    assert_eq!(
        w.new
            .sign_group_roster_vote_durable(1, P1, C1, 1, 1, |_, _| Ok(())),
        Err(Error::RosterSigningStateUnconfirmed)
    );
}

#[test]
fn an_old_device_rolled_back_with_a_backup_restore_cannot_hand_off_again() {
    let mut w = world();
    vote(&mut w.old, 1, P1, C1).unwrap();
    let before = Installation::restore(
        Installation::restore(Installation::new(key(7)).into_snapshot(0), [key(7)])
            .unwrap()
            .into_snapshot(0),
        [key(7)],
    )
    .unwrap()
    .into_snapshot(0);
    handoff(&mut w); // the real handoff; the host then restores a pre-handoff backup
    let mut rolled_back = Installation::restore_backup(before, [key(7)]).unwrap();
    assert_eq!(rolled_back.voting_state(), VotingState::Gated);
    assert_eq!(
        rolled_back
            .begin_handoff([8; 32], |_, _| Ok(()))
            .map(|_| ()),
        Err(Error::NotVotingDevice)
    );
    assert_eq!(
        vote(&mut rolled_back, 1, P1, C2),
        Err(Error::RosterSigningStateUnconfirmed)
    );
}

#[test]
fn a_plain_restore_of_a_pre_handoff_snapshot_is_the_stated_limit() {
    // `restore` trusts the snapshot it is given. A host that restores an old snapshot with
    // `restore` instead of `restore_backup` (or the handoff record) brings the old device back as
    // a voter at the old counter. The API offers the safe paths; it cannot detect a bad choice.
    let mut w = world();
    let snapshot_before = Installation::new(key(7)).into_snapshot(0);
    handoff(&mut w);
    let revived = Installation::restore(snapshot_before, [key(7)]).unwrap();
    assert_eq!(revived.voting_state(), VotingState::Voting);
    // Applying the persisted handoff record is what prevents it.
    let mut record = None;
    let mut second = Installation::new(key(7));
    second
        .begin_handoff(w.nonce, |_, r| {
            record = Some(r.to_vec());
            Ok(())
        })
        .unwrap();
    let snapshot_before = Installation::new(key(7)).into_snapshot(0);
    let safe =
        Installation::restore_with_handoff_record(snapshot_before, [key(7)], &record.unwrap())
            .unwrap();
    assert_eq!(safe.voting_state(), VotingState::Stopped);
}

#[test]
fn a_bundle_at_the_maximum_counter_is_accepted_but_the_new_holder_cannot_hand_off_again() {
    let mut w = world();
    let id = w.old.selected();
    w.old.voting.insert(
        id,
        VotingRecord {
            counter: u64::MAX - 1,
            state: VotingState::Voting,
            holder: None,
        },
    );
    let bundle = handoff(&mut w);
    assert_eq!(bundle.counter(), u64::MAX);
    assert_eq!(accept(&mut w, &bundle), Ok(VotingState::Voting));
    assert_eq!(
        w.new.begin_handoff([5; 32], |_, _| Ok(())).map(|_| ()),
        Err(Error::CounterExhausted)
    );
}

#[test]
fn backup_restores_do_not_share_a_handoff_recipient() {
    let mut old = Installation::new(key(7));
    let saved_nonce = old.device_nonce(&mut OsRng);
    // Two copies of the same initial backup state. Snapshot serialization is not
    // implemented yet, so reproduce the saved nonce in equivalent empty snapshots.
    let backup = || {
        let mut source = Installation::new(key(7));
        source.device_nonce = Some(saved_nonce);
        source.into_snapshot(0)
    };
    let mut first = Installation::restore_backup(backup(), [key(7)]).unwrap();
    let mut second = Installation::restore_backup(backup(), [key(7)]).unwrap();
    let nonce = first.device_nonce(&mut OsRng);
    let transfer = old.begin_handoff(nonce, |_, _| Ok(())).unwrap();
    first.accept_handoff(&transfer, |_| Ok(())).unwrap();
    let accepted_twice = second.accept_handoff(&transfer, |_| Ok(()));
    if accepted_twice.is_ok() {
        vote(&mut first, 1, P1, C1).unwrap();
        vote(&mut second, 1, P1, C2).unwrap();
    }
    assert!(
        accepted_twice.is_err(),
        "the same bundle enabled two restored devices, both could sign conflicting votes"
    );
}

#[test]
fn restart_after_accept_preserves_signing_capability() {
    let mut w = world();
    let backup = Installation::new(key(7)).into_snapshot(0);
    let mut recipient = Installation::restore_backup(backup, [key(7)]).unwrap();
    let nonce = recipient.device_nonce(&mut OsRng);
    let before_accept = recipient.into_snapshot(0);
    let mut recipient = Installation::restore(before_accept, [key(7)]).unwrap();
    let transfer = w.old.begin_handoff(nonce, |_, _| Ok(())).unwrap();
    // Keep a snapshot of the gated backup, as a crash before snapshot update would.
    let before_accept = recipient.into_snapshot(0);
    let mut equivalent =
        Installation::restore_backup(Installation::new(key(7)).into_snapshot(0), [key(7)]).unwrap();
    equivalent.device_nonce = Some(nonce);
    let mut record = Vec::new();
    equivalent
        .accept_handoff(&transfer, |r| {
            record = r.to_vec();
            Ok(())
        })
        .unwrap();
    assert_eq!(vote(&mut equivalent, 1, P1, C1), Ok(()));
    recipient =
        Installation::restore_with_handoff_record(before_accept, [key(7)], &record).unwrap();
    assert_eq!(vote(&mut recipient, 1, P1, C1), Ok(()));
}

#[test]
fn latest_record_preserves_every_identitys_stopped_role() {
    let multi = || {
        let mut i = Installation::new(key(7));
        i.add_identity(key(8)).unwrap();
        i
    };
    let before = multi().into_snapshot(0);
    let mut old = multi();
    let mut recipient = Installation::new(key(7));
    recipient.gate_voting();
    let nonce = recipient.device_nonce(&mut OsRng);
    let first = old.begin_handoff(nonce, |_, _| Ok(())).unwrap();
    recipient.accept_handoff(&first, |_| Ok(())).unwrap();
    old.select(key(8).verifying_key().to_bytes(), 0).unwrap();
    let mut latest = Vec::new();
    old.begin_handoff([9; 32], |_, record| {
        latest = record.to_vec();
        Ok(())
    })
    .unwrap();
    let mut restarted =
        Installation::restore_with_handoff_record(before, [key(7), key(8)], &latest).unwrap();
    restarted
        .select(key(7).verifying_key().to_bytes(), 0)
        .unwrap();
    let result = vote(&mut restarted, 1, P1, C2);
    vote(&mut recipient, 1, P1, C1).unwrap();
    assert!(
        result.is_err(),
        "latest identity-8 record revived stopped identity 7 and let it equivocate"
    );
}

#[test]
fn a_handoff_cannot_clear_a_known_conflict_even_after_gating() {
    let mut w = world();
    w.new.roster_signing_disabled = true;
    let bundle = handoff(&mut w);
    accept(&mut w, &bundle).unwrap();
    assert_eq!(
        vote(&mut w.new, 1, P1, C1),
        Err(Error::RosterSigningStateUnconfirmed)
    );
    // It cannot launder the unsafe state into another device's otherwise valid bundle.
    assert_eq!(
        w.new.begin_handoff([8; 32], |_, _| Ok(())),
        Err(Error::RosterSigningStateUnconfirmed)
    );
}

#[test]
fn accepting_one_identity_does_not_confirm_another_identitys_backup_locks() {
    let mut source = Installation::new(key(7));
    let other = source.add_identity(key(8)).unwrap();
    let mut recipient =
        Installation::restore_backup(source.into_snapshot(0), [key(7), key(8)]).unwrap();
    let nonce = recipient.device_nonce(&mut OsRng);
    let mut old = Installation::new(key(7));
    let transfer = old.begin_handoff(nonce, |_, _| Ok(())).unwrap();
    let mut record = Vec::new();
    recipient
        .accept_handoff(&transfer, |r| {
            record = r.to_vec();
            Ok(())
        })
        .unwrap();
    vote(&mut recipient, 1, P1, C1).unwrap();
    recipient.select(other, 0).unwrap();
    assert_eq!(
        vote(&mut recipient, 1, P1, C2),
        Err(Error::RosterSigningStateUnconfirmed)
    );
    let snapshot = recipient.into_snapshot(0);
    let mut restored =
        Installation::restore_with_handoff_record(snapshot, [key(7), key(8)], &record).unwrap();
    assert_eq!(
        vote(&mut restored, 1, P1, C2),
        Err(Error::RosterSigningStateUnconfirmed)
    );
}

#[test]
fn record_restore_rejects_old_versions_missing_identities_and_older_sequences() {
    let multi = || {
        let mut i = Installation::new(key(7));
        i.add_identity(key(8)).unwrap();
        i
    };
    let mut old = multi();
    let mut bytes = Vec::new();
    old.begin_handoff([8; 32], |_, record| {
        bytes = record.to_vec();
        Ok(())
    })
    .unwrap();
    let decode = || -> HandoffRecord { cbor2::from_reader(bytes.as_slice()).unwrap() };
    let legacy = cbor2::to_vec(&(
        1u8,
        old.selected(),
        old.voting_record(old.selected()),
        RosterLockTable::new(),
    ))
    .unwrap();
    assert!(matches!(
        Installation::restore_with_handoff_record(
            multi().into_snapshot(0),
            [key(7), key(8)],
            &legacy
        ),
        Err(Error::InvalidHandoff)
    ));
    let mut record = decode();
    record.version = 1;
    assert!(matches!(
        Installation::restore_with_handoff_record(
            multi().into_snapshot(0),
            [key(7), key(8)],
            &record.to_bytes()
        ),
        Err(Error::InvalidHandoff)
    ));
    let mut record = decode();
    record.voting.remove(&key(8).verifying_key().to_bytes());
    assert!(matches!(
        Installation::restore_with_handoff_record(
            multi().into_snapshot(0),
            [key(7), key(8)],
            &record.to_bytes()
        ),
        Err(Error::InvalidHandoff)
    ));
    // A later local handoff record supersedes the previous sequence.
    old.select(key(8).verifying_key().to_bytes(), 0).unwrap();
    old.begin_handoff([9; 32], |_, _| Ok(())).unwrap();
    assert!(matches!(
        Installation::restore_with_handoff_record(old.into_snapshot(0), [key(7), key(8)], &bytes),
        Err(Error::InvalidHandoff)
    ));
}

#[test]
fn accepted_record_recovers_the_nonce_even_if_snapshot_predates_nonce_creation() {
    let mut old = Installation::new(key(7));
    let mut recipient =
        Installation::restore_backup(Installation::new(key(7)).into_snapshot(0), [key(7)]).unwrap();
    let snapshot_before_nonce = recipient.into_snapshot(0);
    recipient = Installation::restore(snapshot_before_nonce, [key(7)]).unwrap();
    let before = recipient.into_snapshot(0);
    let mut recipient =
        Installation::restore_backup(Installation::new(key(7)).into_snapshot(0), [key(7)]).unwrap();
    let nonce = recipient.device_nonce(&mut OsRng);
    let transfer = old.begin_handoff(nonce, |_, _| Ok(())).unwrap();
    let mut record = Vec::new();
    recipient
        .accept_handoff(&transfer, |r| {
            record = r.to_vec();
            Ok(())
        })
        .unwrap();
    let mut restored =
        Installation::restore_with_handoff_record(before, [key(7)], &record).unwrap();
    assert_eq!(restored.current_device_nonce(), Some(nonce));
    assert_eq!(restored.device_nonce(&mut OsRng), nonce);
    assert_eq!(vote(&mut restored, 1, P1, C1), Ok(()));
}

#[test]
fn removing_an_identity_cleans_uncertainty_and_permits_handoff_recovery() {
    let mut source = Installation::new(key(7));
    let other = source.add_identity(key(8)).unwrap();
    let backup = source.into_snapshot(0);
    let mut recipient = Installation::restore_backup(backup, [key(7), key(8)]).unwrap();
    // Both identities are unconfirmed after backup restoration.
    // Remove the second identity from the recipient.
    recipient.remove_identity(other).unwrap();
    let nonce = recipient.device_nonce(&mut OsRng);
    let mut old = Installation::new(key(7));
    let transfer = old.begin_handoff(nonce, |_, _| Ok(())).unwrap();
    let mut record = Vec::new();
    recipient
        .accept_handoff(&transfer, |r| {
            record = r.to_vec();
            Ok(())
        })
        .unwrap();
    let snapshot = recipient.into_snapshot(0);
    // Crash recovery: restore with single owned identity and persisted handoff record
    let res = Installation::restore_with_handoff_record(snapshot, [key(7)], &record);
    assert!(
        res.is_ok(),
        "handoff record restore failed after identity removal: {:?}",
        res.err()
    );
    let mut restored = res.unwrap();
    assert_eq!(vote(&mut restored, 1, P1, C1), Ok(()));
}
