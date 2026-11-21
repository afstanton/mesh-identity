//! Certified recognition of a replacement device.

use super::apply_v1_tests::{cert, snapshot, v1};
use super::certificate_v1_tests::{digest_of, group, key, proof_at_head, signing};
use super::{CatchUp, Error, SignedRecognition, VouchedGroup};
use crate::groups::Policy;
use crate::session::installation::{
    Installation, TakeoverStatement, VotingState, handoff_statement_message,
};
use ed25519_dalek::Signer;
use rand::rngs::OsRng;

/// A statement the identity with `seed` signs for a device.
fn statement(identity: u8, counter: u64, nonce: u8) -> TakeoverStatement {
    let nonce = [nonce; 32];
    let signature = signing(identity)
        .sign(&handoff_statement_message(key(identity), counter, nonce))
        .to_bytes();
    TakeoverStatement {
        identity: key(identity),
        counter,
        nonce,
        signature,
    }
}

fn recognition(g: &VouchedGroup, identity: u8, counter: u64, nonce: u8) -> SignedRecognition {
    SignedRecognition::new(g.rotation_context(), &statement(identity, counter, nonce))
}

fn recognized(mut g: VouchedGroup, identity: u8, counter: u64, nonce: u8) -> VouchedGroup {
    let r = recognition(&g, identity, counter, nonce);
    let child = g.recognition_child(&r).unwrap();
    // Seven members, quorum five: everyone but the identity signs.
    let signers: Vec<u8> = (10..17).filter(|seed| *seed != identity).collect();
    g.apply_certified_recognition(&r, &cert(&g, child, &signers))
        .unwrap();
    g
}

#[test]
fn the_frame_round_trips_and_rejects_any_other_length() {
    let g = group();
    let bytes = recognition(&g, 10, 2, 1).to_bytes();
    assert_eq!(
        SignedRecognition::from_bytes(&bytes).unwrap().to_bytes(),
        bytes
    );
    assert!(SignedRecognition::from_bytes(&bytes[..175]).is_err());
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert!(SignedRecognition::from_bytes(&longer).is_err());
}

#[test]
fn a_recognition_records_the_device_and_changes_the_chain_digest_only_then() {
    let base = group();
    assert_eq!(base.chain_digest(), digest_of(&base));
    let g = recognized(base.clone(), 10, 2, 1);
    assert_eq!(g.revision(), base.revision() + 1);
    assert_eq!(g.recognized_device(&key(10)), Some((2, [1; 32])));
    assert_eq!(g.recognized_device(&key(11)), None);
    assert!(g.membership(key(10)).is_some());
    assert_eq!(g.group.electorate_size(), 7);
    assert_ne!(g.chain_digest(), digest_of(&g));
    // A later certificate built on the old digest says "behind", not "invalid".
    let r = recognition(&g, 11, 2, 2);
    let child = g.recognition_child(&r).unwrap();
    let mut stale = v1(&g, child, &[10, 12, 13, 14, 15], Vec::new());
    stale.chain_digest = digest_of(&g);
    let mut h = g.clone();
    assert_eq!(
        h.apply_certified_recognition(&r, &stale),
        Err(Error::ChainMismatch)
    );
}

#[test]
fn the_identitys_own_vote_never_counts_toward_its_recognition() {
    let g = group();
    let r = recognition(&g, 10, 2, 1);
    let child = g.recognition_child(&r).unwrap();
    let before = snapshot(&g);

    // Five signers including the identity: refused, not silently reduced to four.
    let mut h = g.clone();
    assert_eq!(
        h.apply_certified_recognition(&r, &cert(&g, child, &[10, 11, 12, 13, 14])),
        Err(Error::Ineligible)
    );
    // Four others are short of five.
    assert_eq!(
        h.apply_certified_recognition(&r, &cert(&g, child, &[11, 12, 13, 14])),
        Err(Error::Ineligible)
    );
    assert_eq!(snapshot(&h), before);
    assert_eq!(h.recognized_device(&key(10)), None);
    // Five others reach it.
    h.apply_certified_recognition(&r, &cert(&g, child, &[11, 12, 13, 14, 15]))
        .unwrap();
    assert!(h.recognized_device(&key(10)).is_some());
}

#[test]
fn a_group_that_needs_the_identitys_vote_cannot_recognize_it() {
    // Three members need all three, so recognition is out of reach: the deadlock the plan names.
    let g = VouchedGroup::new(7, (10..13).map(key), Policy::InviterOnly);
    let r = recognition(&g, 10, 2, 1);
    let child = g.recognition_child(&r).unwrap();
    let mut h = g.clone();
    let before = snapshot(&h);
    assert_eq!(
        h.apply_certified_recognition(&r, &cert(&g, child, &[11, 12])),
        Err(Error::Ineligible)
    );
    assert_eq!(
        h.apply_certified_recognition(&r, &cert(&g, child, &[10, 11, 12])),
        Err(Error::Ineligible)
    );
    assert_eq!(snapshot(&h), before);
    // Four members need three, and the other three can do it.
    let four = VouchedGroup::new(7, (10..14).map(key), Policy::InviterOnly);
    let r = recognition(&four, 10, 2, 1);
    let child = four.recognition_child(&r).unwrap();
    let mut h = four.clone();
    h.apply_certified_recognition(&r, &cert(&four, child, &[11, 12, 13]))
        .unwrap();
    assert!(h.recognized_device(&key(10)).is_some());
}

#[test]
fn the_counter_must_rise_and_equal_counters_recognize_only_one_device() {
    let fresh = group();
    // Counter 0 is refused even with no prior recognitions.
    assert_eq!(
        fresh.recognition_child(&recognition(&fresh, 10, 0, 1)),
        Err(Error::Ineligible)
    );

    let g = recognized(fresh, 10, 2, 1);
    // The same counter again, another device at it, or an older counter: refused.
    for (counter, nonce) in [(2, 1), (2, 2), (1, 3), (0, 1)] {
        assert_eq!(
            g.recognition_child(&recognition(&g, 10, counter, nonce)),
            Err(Error::Ineligible),
            "counter {counter} nonce {nonce}"
        );
    }
    // A higher counter for another device replaces the record.
    let h = recognized(g.clone(), 10, 3, 2);
    assert_eq!(h.recognized_device(&key(10)), Some((3, [2; 32])));

    // Two devices at one counter propose children that differ, and only one can land.
    let base = group();
    let first = base
        .recognition_child(&recognition(&base, 10, 2, 1))
        .unwrap();
    let second = base
        .recognition_child(&recognition(&base, 10, 2, 2))
        .unwrap();
    assert_ne!(first, second);
}

#[test]
fn a_bad_statement_is_refused_before_any_certificate_matters() {
    let g = group();
    let good = recognition(&g, 10, 2, 1);
    assert!(g.recognition_child(&good).is_ok());

    // Signed by another key.
    let mut forged = statement(10, 2, 1);
    forged.signature = signing(11)
        .sign(&handoff_statement_message(key(10), 2, [1; 32]))
        .to_bytes();
    assert_eq!(
        g.recognition_child(&SignedRecognition::new(g.rotation_context(), &forged)),
        Err(Error::Ineligible)
    );
    // The counter or nonce changed after signing.
    let mut bumped = statement(10, 2, 1);
    bumped.counter = 9;
    assert_eq!(
        g.recognition_child(&SignedRecognition::new(g.rotation_context(), &bumped)),
        Err(Error::Ineligible)
    );
    // Not a member, or the wrong head.
    assert_eq!(
        g.recognition_child(&recognition(&g, 99, 2, 1)),
        Err(Error::Ineligible)
    );
    let moved = recognized(g.clone(), 11, 2, 7);
    assert_eq!(moved.recognition_child(&good), Err(Error::StaleProposal));
}

#[test]
fn a_proven_or_reported_identity_cannot_be_recognized() {
    let g = group();
    let r = recognition(&g, 16, 2, 1);
    let child = g.recognition_child(&r).unwrap();
    // A proof against the identity in the same certificate makes it a suspect: refused.
    let mut h = g.clone();
    let before = snapshot(&h);
    assert_eq!(
        h.apply_certified_recognition(
            &r,
            &v1(
                &g,
                child,
                &[10, 11, 12, 13, 14],
                vec![proof_at_head(&g, 16)]
            )
        ),
        Err(Error::Ineligible)
    );
    assert_eq!(snapshot(&h), before);
    let mut reported = g.clone();
    reported.report_key_unauthorized(key(16));
    assert_eq!(
        reported.recognition_child(&recognition(&reported, 16, 2, 1)),
        Err(Error::Ineligible)
    );
}

#[test]
fn a_version_one_certificate_carries_proofs_alongside_a_recognition() {
    let g = group();
    let r = recognition(&g, 10, 2, 1);
    let child = g.recognition_child(&r).unwrap();
    let mut h = g.clone();
    // A proof against 16 lowers the quorum to four of six; four others sign.
    h.apply_certified_recognition(
        &r,
        &v1(&g, child, &[11, 12, 13, 14], vec![proof_at_head(&g, 16)]),
    )
    .unwrap();
    assert!(h.inherited_proof_keys().contains(&key(16)));
    assert_eq!(h.recognized_device(&key(10)), Some((2, [1; 32])));
}

#[test]
fn a_catch_up_to_a_snapshot_with_a_different_recognition_is_a_conflict() {
    let base = group();
    let left = recognized(base.clone(), 10, 2, 1);
    let right = recognized(base.clone(), 10, 2, 2);
    let mut a = left.clone();
    // Same revision, same ancestry, different records: the chains diverge.
    assert_ne!(left.rotation_context().1, right.rotation_context().1);
    assert_eq!(a.catch_up(&right), CatchUp::ConflictingHistory);
    // A snapshot that adds a recognition applies.
    let mut behind = base.clone();
    assert_eq!(behind.catch_up(&left), CatchUp::Applied);
    assert_eq!(behind.recognized_device(&key(10)), Some((2, [1; 32])));
}

fn installation(seed: u8) -> Installation {
    Installation::new(signing(seed))
}

#[test]
fn only_the_recognized_device_may_sign_and_only_in_the_group_that_recognized_it() {
    let g = group();
    let other = VouchedGroup::new(8, (10..17).map(key), Policy::InviterOnly);
    let old = installation(10);
    let mut new = installation(10);
    new.gate_voting();
    let statement = new.begin_takeover(&mut OsRng, 1).unwrap();
    assert_eq!(statement.counter, 2);
    assert_eq!(new.voting_state(), VotingState::Gated);
    let context = g.rotation_context();
    let sign = |i: &Installation| i.sign_group_departure(context.0, context.1);

    // Before any recognition: the old device signs, the takeover device cannot.
    assert!(g.check_voting_role(&old).is_ok());
    assert!(sign(&old).is_ok());
    assert!(g.check_voting_role(&new).is_ok());
    assert_eq!(
        sign(&new),
        Err(crate::session::installation::Error::NotVotingDevice)
    );

    // The group recognizes the new device.
    let mut h = g.clone();
    let r = SignedRecognition::new(h.rotation_context(), &statement);
    let child = h.recognition_child(&r).unwrap();
    h.apply_certified_recognition(&r, &cert(&g, child, &[11, 12, 13, 14, 15]))
        .unwrap();
    let context = h.rotation_context();
    let sign_in_h = |i: &Installation| i.sign_group_departure(context.0, context.1);

    // The new device signs here, the old one no longer does.
    assert!(h.check_voting_role(&new).is_ok());
    assert!(sign_in_h(&new).is_ok());
    assert_eq!(h.check_voting_role(&old), Err(Error::NotVotingDevice));

    // In another group nothing is recognized: the takeover device is still gated there.
    assert!(other.check_voting_role(&new).is_ok());
    assert_eq!(
        new.sign_group_departure(8, other.rotation_context().1),
        Err(crate::session::installation::Error::NotVotingDevice)
    );
    // A second device at the same counter with another nonce does not match.
    let mut rival = installation(10);
    rival.gate_voting();
    let rival_statement = rival.begin_takeover(&mut OsRng, 1).unwrap();
    assert_eq!(rival_statement.counter, statement.counter);
    assert_ne!(rival_statement.nonce, statement.nonce);
    assert_eq!(h.check_voting_role(&rival), Err(Error::NotVotingDevice));
}

#[test]
fn a_later_recognition_takes_the_role_from_the_earlier_device() {
    let g = group();
    let mut first = installation(10);
    first.gate_voting();
    let one = first.begin_takeover(&mut OsRng, 0).unwrap();
    let mut second = installation(10);
    second.gate_voting();
    let two = second.begin_takeover(&mut OsRng, 1).unwrap();
    assert_eq!((one.counter, two.counter), (1, 2));

    let mut h = g.clone();
    for statement in [&one, &two] {
        let r = SignedRecognition::new(h.rotation_context(), statement);
        let child = h.recognition_child(&r).unwrap();
        let snapshot_h = h.clone();
        h.apply_certified_recognition(&r, &cert(&snapshot_h, child, &[11, 12, 13, 14, 15]))
            .unwrap();
        if statement.counter == 1 {
            assert!(h.check_voting_role(&first).is_ok());
            assert!(
                first
                    .sign_group_departure(7, h.rotation_context().1)
                    .is_ok()
            );
        }
    }
    assert_eq!(h.check_voting_role(&first), Err(Error::NotVotingDevice));
    assert_eq!(
        first.sign_group_departure(7, h.rotation_context().1),
        Err(crate::session::installation::Error::NotVotingDevice)
    );
    assert!(h.check_voting_role(&second).is_ok());
    assert!(
        second
            .sign_group_departure(7, h.rotation_context().1)
            .is_ok()
    );
}

#[test]
fn a_higher_handoff_counter_needs_its_own_recognition() {
    // Counters 1, 2, 3 by acknowledged handoffs; a takeover at 2 is recognized later.
    let mut a = installation(10);
    let mut b = installation(10);
    b.gate_voting();
    let mut c = installation(10);
    c.gate_voting();
    let nonce_b = b.device_nonce(&mut OsRng);
    let bundle = a.begin_handoff(nonce_b, |_, _| Ok(())).unwrap();
    b.accept_handoff(&bundle, |_| Ok(())).unwrap();
    let nonce_c = c.device_nonce(&mut OsRng);
    let bundle = b.begin_handoff(nonce_c, |_, _| Ok(())).unwrap();
    c.accept_handoff(&bundle, |_| Ok(())).unwrap();
    let mut d = installation(10);
    d.gate_voting();
    let nonce_d = d.device_nonce(&mut OsRng);
    let bundle = c.begin_handoff(nonce_d, |_, _| Ok(())).unwrap();
    d.accept_handoff(&bundle, |_| Ok(())).unwrap();

    let mut n = installation(10);
    n.gate_voting();
    let statement = n.begin_takeover(&mut OsRng, 1).unwrap();
    assert_eq!(statement.counter, 2);
    let g = recognized_with(group(), &statement);
    assert_eq!(g.check_voting_role(&d), Err(Error::NotVotingDevice)); // 3 is not grant 2
    assert_eq!(g.check_voting_role(&c), Err(Error::NotVotingDevice)); // stopped
    assert!(g.check_voting_role(&n).is_ok());
    // The authenticated handoff exposes its public statement for the new certificate.
    let updated = recognized_with(g, &bundle.statement().unwrap());
    assert_eq!(updated.check_voting_role(&d), Ok(()));
    assert_eq!(updated.check_voting_role(&n), Err(Error::NotVotingDevice));
}

fn recognized_with(mut g: VouchedGroup, statement: &TakeoverStatement) -> VouchedGroup {
    let r = SignedRecognition::new(g.rotation_context(), statement);
    let child = g.recognition_child(&r).unwrap();
    g.apply_certified_recognition(&r, &cert(&g, child, &[11, 12, 13, 14, 15]))
        .unwrap();
    g
}

fn local_voter(g: &VouchedGroup) -> crate::groups::LocalInstallation {
    let mut local = crate::groups::LocalInstallation::default();
    local.add_identity(g.membership(key(10)).unwrap().identity(), "owner".into());
    local
}

#[test]
fn recognition_permission_cannot_authorize_an_ancestor() {
    use super::RosterVotePhase;
    let base = group();
    let local = local_voter(&base);
    let mut old = installation(10);
    let parent = base.rotation_context().1;
    let first = base.policy_child(Policy::Majority).unwrap();
    base.sign_roster_vote_durable(
        &local,
        super::RosterVoteRequest {
            parent,
            child: first,
            round: 1,
            phase: RosterVotePhase::Prepare,
        },
        &mut old,
        |_, _| Ok(()),
    )
    .unwrap();
    let mut new = installation(10);
    new.gate_voting();
    let statement = new.begin_takeover(&mut OsRng, 0).unwrap();
    let h = recognized_with(base.clone(), &statement);
    let child = h.policy_child(Policy::Majority).unwrap();
    h.sign_roster_vote_durable(
        &local,
        super::RosterVoteRequest {
            parent: h.rotation_context().1,
            child,
            round: 1,
            phase: RosterVotePhase::Prepare,
        },
        &mut new,
        |_, _| Ok(()),
    )
    .unwrap();
    // Even direct core signing cannot reuse a permit on another parent.
    assert_eq!(
        new.sign_group_roster_vote_durable(7, parent, [9; 32], 1, 1, |_, _| Ok(())),
        Err(crate::session::installation::Error::NotVotingDevice)
    );
    // Revisit an authenticated older view after a permit was granted on the new one.
    let second = base.policy_child(Policy::TwoThirds).unwrap();
    let result = base.sign_roster_vote_durable(
        &local,
        super::RosterVoteRequest {
            parent,
            child: second,
            round: 1,
            phase: RosterVotePhase::Prepare,
        },
        &mut new,
        |_, _| Ok(()),
    );
    assert!(
        result.is_err(),
        "replacement signed a second child of the pre-recognition parent"
    );
}

#[test]
fn late_recognition_and_higher_handoff_cannot_both_sign() {
    use super::RosterVotePhase;
    let mut a = installation(10);
    let mut b = installation(10);
    b.gate_voting();
    let nonce = b.device_nonce(&mut OsRng);
    let transfer = a.begin_handoff(nonce, |_, _| Ok(())).unwrap();
    b.accept_handoff(&transfer, |_| Ok(())).unwrap();
    let mut c = installation(10);
    c.gate_voting();
    let nonce = c.device_nonce(&mut OsRng);
    let transfer = b.begin_handoff(nonce, |_, _| Ok(())).unwrap();
    c.accept_handoff(&transfer, |_| Ok(())).unwrap(); // counter 2
    let mut replacement = installation(10);
    replacement.gate_voting();
    let claim = replacement.begin_takeover(&mut OsRng, 0).unwrap(); // counter 1
    let g = recognized_with(group(), &claim);
    let local = local_voter(&g);
    let parent = g.rotation_context().1;
    let first = g.policy_child(Policy::Majority).unwrap();
    let second = g.policy_child(Policy::TwoThirds).unwrap();
    let result = g.sign_roster_vote_durable(
        &local,
        super::RosterVoteRequest {
            parent,
            child: first,
            round: 1,
            phase: RosterVotePhase::Prepare,
        },
        &mut c,
        |_, _| Ok(()),
    );
    assert!(matches!(result, Err(Error::NotVotingDevice)));
    g.sign_roster_vote_durable(
        &local,
        super::RosterVoteRequest {
            parent,
            child: second,
            round: 1,
            phase: RosterVotePhase::Prepare,
        },
        &mut replacement,
        |_, _| Ok(()),
    )
    .unwrap();
}

#[test]
fn recognized_backup_can_vote_only_on_its_authorized_parent() {
    use super::RosterVotePhase;
    let backup = installation(10).into_snapshot(0);
    let mut restored = Installation::restore_backup(backup, [signing(10)]).unwrap();
    let claim = restored.begin_takeover(&mut OsRng, 0).unwrap();
    let g = recognized_with(group(), &claim);
    let local = local_voter(&g);
    let child = g.policy_child(Policy::Majority).unwrap();
    let result = g.sign_roster_vote_durable(
        &local,
        super::RosterVoteRequest {
            parent: g.rotation_context().1,
            child,
            round: 1,
            phase: RosterVotePhase::Prepare,
        },
        &mut restored,
        |_, _| Ok(()),
    );
    assert!(
        result.is_ok(),
        "recognized backup remains blocked: {:?}",
        result.err()
    );
    assert_eq!(
        restored.sign_group_roster_vote_durable(8, [9; 32], child, 1, 1, |_, _| Ok(())),
        Err(crate::session::installation::Error::RosterSigningStateUnconfirmed)
    );
}
