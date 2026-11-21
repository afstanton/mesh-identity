#![cfg(all(feature = "groups", feature = "test-support"))]
use mesh_identity::groups::evidence::SimulatedAuthority as _;
use mesh_identity::groups::evidence::*;
use mesh_identity::groups::{Error, Policy, Vote};

#[allow(dead_code)]
mod support;

fn k(n: u8) -> [u8; 32] {
    [n; 32]
}

#[test]
fn long_roster_history_drops_without_overflowing_the_stack() {
    let mut g = VouchedGroup::new(1, [k(1), k(2)], Policy::Majority);
    for i in 0..300_000u64 {
        let p = if i % 2 == 0 {
            Policy::TwoThirds
        } else {
            Policy::Majority
        };
        g.apply_policy_change(g.revision(), p).unwrap();
    }
    drop(g);
}

#[test]
fn suspect_member_does_not_block_unanimous_admission() {
    let mut g = VouchedGroup::new(1, [k(1), k(2), k(3)], Policy::Unanimous);
    g.mark_suspect(k(3)).unwrap();
    let mut p = g.invite(k(1), k(9)).unwrap();
    g.vote(&mut p, k(2), Vote::Approve).unwrap();
    assert_eq!(g.approval_counts(&p), Ok((2, 2)));
    assert!(g.vote(&mut p, k(3), Vote::Approve).is_err());
}

#[test]
fn ejection_needs_a_strict_majority_of_the_others_under_every_policy() {
    for policy in [Policy::Unanimous, Policy::Majority, Policy::TwoThirds] {
        let mut g = VouchedGroup::new(1, [k(1), k(2), k(3), k(4), k(5)], policy);
        let mut r = g.propose_ejection(k(1), k(5)).unwrap();
        assert_eq!(
            g.apply_removal(&r),
            Err(Error::ApprovalRequired),
            "{policy:?}"
        );
        g.approve_removal(&mut r, k(2)).unwrap();
        assert_eq!(
            g.apply_removal(&r),
            Err(Error::ApprovalRequired),
            "{policy:?}: 2 of 4 is a tie"
        );
        g.approve_removal(&mut r, k(3)).unwrap();
        assert_eq!(g.apply_removal(&r), Ok(()), "{policy:?}");
    }
}

#[test]
fn withdrawals_from_unknown_keys_are_not_recorded() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::session::installation::Installation;
    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(7);
    let stranger = Installation::new(SigningKey::generate(&mut rng));
    let member = Installation::new(SigningKey::generate(&mut rng));
    let mut g = VouchedGroup::new(1, [member.selected()], Policy::InviterOnly);
    let junk = {
        let sig = stranger.sign_voucher_withdrawal(1, [5; 32]).unwrap();
        let mut b = [0u8; 136];
        b[..8].copy_from_slice(&1u64.to_be_bytes());
        b[8..40].copy_from_slice(&[5; 32]);
        b[40..72].copy_from_slice(&stranger.selected());
        b[72..].copy_from_slice(&sig);
        VoucherWithdrawal::from_bytes(&b).unwrap()
    };
    assert_eq!(g.apply_withdrawal(&junk), Err(Error::Ineligible));
}

#[test]
fn a_snapshot_cannot_advance_the_local_clock() {
    let mut local = VouchedGroup::new(1, [k(1), k(2)], Policy::Majority);
    let mut remote = local.clone();
    remote
        .apply_policy_change(remote.revision(), Policy::TwoThirds)
        .unwrap();
    remote.advance_time(u64::MAX / 2);
    assert_eq!(local.catch_up(&remote), CatchUp::Applied);
    assert!(local.invite_until(k(1), k(9), 100).is_ok());
}

#[test]
fn the_current_key_holder_can_veto_a_witness_recovery() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::session::installation::Installation;
    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(8);
    let owner = Installation::new(SigningKey::generate(&mut rng));
    let other = Installation::new(SigningKey::generate(&mut rng));
    let mut g = VouchedGroup::new(1, [owner.selected(), k(2), k(3)], Policy::Majority);
    g.enroll_recovery(owner.selected(), [k(2), k(3)]).unwrap();
    let mut request = g.request_recovery(owner.selected(), k(9)).unwrap();
    assert_eq!(
        g.veto_recovery(&mut request, &other),
        Err(Error::Ineligible)
    );
    g.veto_recovery(&mut request, &owner).unwrap();
    g.advance_time(RECOVERY_VETO_WINDOW_MS);
    assert_eq!(g.recover_lost_key(&request), Err(Error::Ineligible));
}

#[test]
fn rotation_to_a_weak_key_is_refused() {
    let mut g = VouchedGroup::new(1, [k(1), k(2)], Policy::Majority);
    let mut identity_point = [0u8; 32];
    identity_point[0] = 1; // the identity element: a weak, small-order key
    assert_eq!(
        g.rotate_key(g.revision(), k(1), identity_point),
        Err(Error::Ineligible)
    );
}

#[test]
fn suspect_and_departed_members_do_not_count_toward_admission_approvals() {
    use mesh_identity::groups::{Group, Identity};

    let (a, b, c, d, candidate) = (
        Identity(1),
        Identity(2),
        Identity(3),
        Identity(4),
        Identity(9),
    );
    let mut group = Group::new(1, [a, b, c, d], Policy::Unanimous);
    let mut proposal = group.invite(a, candidate).unwrap();
    group.vote(&mut proposal, b, Vote::Approve).unwrap();
    group.vote(&mut proposal, c, Vote::Approve).unwrap();

    // At this point: 3 approvals (a, b, c) of 4 required
    assert_eq!(group.approval_counts(&proposal), (3, 4));

    // Now member c departs
    let tenure_c = group.membership(c).unwrap();
    assert!(group.apply_departure(tenure_c).unwrap());
    // Although revision advanced, if this proposal is evaluated against the group:
    // c is no longer in the roster, so c's approval MUST NOT be counted!
    assert!(!group.is_eligible_voter(c));
    assert_eq!(group.approval_counts(&proposal), (2, 3));
}

#[test]
fn weak_key_rejected_in_apply_recovered_key_and_recovery_child() {
    let mut identity_point = [0u8; 32];
    identity_point[0] = 1; // weak key

    let mut g = VouchedGroup::new(1, [k(1), k(2), k(3)], Policy::Majority);
    g.enroll_recovery(k(1), [k(2), k(3)]).unwrap();
    g.mark_suspect(k(1)).unwrap();

    // apply_recovered_key with weak key
    assert_eq!(
        g.apply_recovered_key(g.revision(), k(1), identity_point),
        Err(Error::Ineligible)
    );

    // request_recovery with weak key
    assert!(matches!(
        g.request_recovery(k(1), identity_point),
        Err(Error::Ineligible)
    ));
}

#[test]
fn witness_departure_invalidates_recovery_arrangement() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::session::installation::Installation;
    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(9);
    let owner = Installation::new(SigningKey::generate(&mut rng));
    let witness1 = Installation::new(SigningKey::generate(&mut rng));
    let witness2 = Installation::new(SigningKey::generate(&mut rng));
    let new_inst = Installation::new(SigningKey::generate(&mut rng));

    let (o, w1, w2, n) = (
        owner.selected(),
        witness1.selected(),
        witness2.selected(),
        new_inst.selected(),
    );
    let mut g = VouchedGroup::new(1, [o, w1, w2], Policy::Majority);
    g.enroll_recovery(o, [w1, w2]).unwrap();

    // Now w2 departs
    let tenure_w2 = g.membership(w2).unwrap();
    assert!(g.apply_departure(w2, tenure_w2).unwrap());

    // Recovery arrangement was cleaned up: requesting recovery fails
    assert!(matches!(g.request_recovery(o, n), Err(Error::Ineligible)));
}

#[test]
fn cancellation_from_unknown_key_is_rejected() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::session::installation::Installation;
    use rand::{SeedableRng, rngs::StdRng};
    use sha2::{Digest, Sha256};
    let mut rng = StdRng::seed_from_u64(10);
    let stranger = Installation::new(SigningKey::generate(&mut rng));
    let member = Installation::new(SigningKey::generate(&mut rng));

    let mut g = VouchedGroup::new(1, [member.selected()], Policy::Majority);
    // Construct a signed invitation from stranger for this group and history
    let mut body = [0u8; INVITATION_BODY_LEN];
    body[..8].copy_from_slice(&1u64.to_be_bytes());
    body[8..40].copy_from_slice(&g.rotation_context().1);
    body[40..72].copy_from_slice(&[42u8; 32]);
    body[72..104].copy_from_slice(&stranger.selected());
    body[104..136].copy_from_slice(&k(9));
    body[136..].copy_from_slice(&100u64.to_be_bytes());
    let binding: [u8; 32] = Sha256::digest(body).into();
    let sig = stranger.sign_group_invitation(binding).unwrap();
    let mut wire = [0u8; INVITATION_BODY_LEN + 64];
    wire[..INVITATION_BODY_LEN].copy_from_slice(&body);
    wire[INVITATION_BODY_LEN..].copy_from_slice(&sig);
    let signed_inv = SignedInvitation::from_bytes(&wire).unwrap();
    let cancellation = SignedInvitationCancellation::new(&signed_inv, &stranger).unwrap();

    // Stranger was never in the roster, so cancellation is rejected
    assert!(matches!(
        g.apply_invitation_cancellation(&signed_inv, &cancellation),
        Err(AdmissionError::Roster(Error::Ineligible))
    ));
}

#[test]
fn round_change_collector_catch_up_scales_with_roster_size() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::session::installation::Installation;
    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(11);
    let nodes: Vec<_> = (0..5)
        .map(|_| Installation::new(SigningKey::generate(&mut rng)))
        .collect();
    let keys: Vec<_> = nodes.iter().map(|n| n.selected()).collect();

    let g = VouchedGroup::new(1, keys.clone(), Policy::Majority);
    let mut collector = RoundChangeCollector::new(&g, 1).unwrap();

    // 1 report is not enough for catch up (needs f+1 = 2)
    let rep0 = RosterRoundChange::new(g.rotation_context(), 1, None, &nodes[0]).unwrap();
    assert_eq!(
        collector.record(&g, rep0).unwrap(),
        RoundReportDelivery::Recorded
    );
    assert_eq!(collector.catch_up_round(&g, 0).unwrap(), None);

    // 2 reports suffice for catch-up
    let rep1 = RosterRoundChange::new(g.rotation_context(), 1, None, &nodes[1]).unwrap();
    assert_eq!(
        collector.record(&g, rep1).unwrap(),
        RoundReportDelivery::Recorded
    );
    assert_eq!(collector.catch_up_round(&g, 0).unwrap(), Some(1));
}

#[test]
fn certified_voluntary_departure_derives_deterministic_child() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::session::installation::Installation;
    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(12);
    let alice = Installation::new(SigningKey::generate(&mut rng));
    let nodes: Vec<_> = (0..4)
        .map(|_| Installation::new(SigningKey::generate(&mut rng)))
        .collect();
    let mut all_keys = vec![alice.selected()];
    all_keys.extend(nodes.iter().map(|n| n.selected()));

    let g1 = VouchedGroup::new(1, all_keys.clone(), Policy::Majority);
    let g2 = g1.clone();

    let context = g1.departure_context(alice.selected()).unwrap();
    let dep = SignedDeparture::new(context, &alice).unwrap();

    let child1 = g1.signed_departure_child(&dep).unwrap();
    let child2 = g2.signed_departure_child(&dep).unwrap();
    assert_eq!(child1, child2);
}

mod voter_locks {
    use ed25519_dalek::SigningKey;
    use mesh_identity::session::installation::{Error, Installation};
    use rand::{SeedableRng, rngs::StdRng};

    const G: u64 = 1;
    const PARENT: [u8; 32] = [7; 32];
    const A: [u8; 32] = [1; 32];
    const B: [u8; 32] = [2; 32];

    fn node(seed: u64) -> (Installation, SigningKey) {
        let mut rng = StdRng::seed_from_u64(seed);
        let key = SigningKey::generate(&mut rng);
        (Installation::new(key.clone()), key)
    }

    #[test]
    fn a_signer_cannot_contradict_itself_within_a_round() {
        let (n, _) = node(1);
        n.sign_group_roster_vote(G, PARENT, A, 1, 1).unwrap();
        // The same statement can be re-sent, but not a different child for that round.
        n.sign_group_roster_vote(G, PARENT, A, 1, 1).unwrap();
        assert_eq!(
            n.sign_group_roster_vote(G, PARENT, B, 1, 1),
            Err(Error::ConflictingRosterVote)
        );
        // A different parent has independent locks.
        n.sign_group_roster_vote(G, [8; 32], B, 1, 1).unwrap();
    }

    #[test]
    fn a_commit_locks_the_signer_to_that_child_in_later_rounds() {
        let (n, _) = node(2);
        n.sign_group_roster_vote(G, PARENT, A, 1, 1).unwrap();
        n.sign_group_roster_vote(G, PARENT, A, 1, 2).unwrap();
        assert_eq!(
            n.sign_group_roster_vote(G, PARENT, B, 2, 1),
            Err(Error::ConflictingRosterVote)
        );
        assert_eq!(
            n.sign_group_roster_vote(G, PARENT, B, 2, 2),
            Err(Error::ConflictingRosterVote)
        );
        n.sign_group_roster_vote(G, PARENT, A, 2, 1).unwrap();
    }

    #[test]
    fn requesting_a_later_round_ends_voting_in_earlier_rounds() {
        let (n, _) = node(3);
        n.sign_group_roster_vote(G, PARENT, A, 3, 3).unwrap();
        assert_eq!(
            n.sign_group_roster_vote(G, PARENT, A, 2, 1),
            Err(Error::ConflictingRosterVote)
        );
        n.sign_group_roster_vote(G, PARENT, A, 3, 1).unwrap();
        assert_eq!(
            n.sign_group_roster_vote(G, PARENT, A, 1, 9),
            Err(Error::InvalidRosterPhase)
        );
    }

    #[test]
    fn locks_survive_a_restart() {
        let (n, key) = node(4);
        n.sign_group_roster_vote(G, PARENT, A, 1, 2).unwrap();
        let snapshot = n.into_snapshot(0);
        let restored = Installation::restore(snapshot, [key]).unwrap();
        assert_eq!(
            restored.sign_group_roster_vote(G, PARENT, B, 5, 1),
            Err(Error::ConflictingRosterVote)
        );
    }

    #[test]
    fn round_zero_is_rejected() {
        let (n, _) = node(10);
        assert_eq!(
            n.sign_group_roster_vote(G, PARENT, A, 0, 1),
            Err(Error::ConflictingRosterVote)
        );
        assert_eq!(
            n.sign_group_roster_vote(G, PARENT, A, 0, 2),
            Err(Error::ConflictingRosterVote)
        );
        assert_eq!(
            n.sign_group_roster_vote(G, PARENT, A, 0, 3),
            Err(Error::ConflictingRosterVote)
        );
    }

    #[test]
    fn regressive_round_change_is_rejected() {
        let (n, _) = node(11);
        n.sign_group_roster_vote(G, PARENT, A, 5, 3).unwrap();
        assert_eq!(
            n.sign_group_roster_vote(G, PARENT, A, 4, 3),
            Err(Error::ConflictingRosterVote)
        );
        n.sign_group_roster_vote(G, PARENT, A, 5, 3).unwrap();
        n.sign_group_roster_vote(G, PARENT, A, 6, 3).unwrap();
    }

    #[test]
    fn remove_identity_keeps_roster_locks() {
        let (mut n, key) = node(12);
        let id = n.selected();
        n.sign_group_roster_vote(G, PARENT, A, 1, 1).unwrap();
        let mut rng = StdRng::seed_from_u64(99);
        let key2 = SigningKey::generate(&mut rng);
        let id2 = n.add_identity(key2).unwrap();
        n.select(id2, 0).unwrap();
        n.remove_identity(id).unwrap();
        let restored_id = n.add_identity(key).unwrap();
        n.select(restored_id, 0).unwrap();
        assert_eq!(
            n.sign_group_roster_vote(G, PARENT, B, 1, 1),
            Err(Error::ConflictingRosterVote)
        );
    }

    #[test]
    fn retired_parent_stays_unsignable_after_reimport_and_restart() {
        let (mut n, key1) = node(12);
        let id1 = n.selected();
        n.sign_group_roster_vote(G, PARENT, A, 1, 1).unwrap();

        let mut rng = StdRng::seed_from_u64(99);
        let key2 = SigningKey::generate(&mut rng);
        let id2 = n.add_identity(key2.clone()).unwrap();
        n.select(id2, 0).unwrap();
        n.sign_group_roster_vote(G, PARENT, A, 1, 1).unwrap();

        n.remove_identity(id1).unwrap();

        n.retire_roster_parent(G, PARENT, [0xEE; 32]).unwrap();
        n.import_identity(key1.clone(), id1).unwrap();
        let checkpoint = n.into_snapshot(0);
        let mut restored = Installation::restore(checkpoint, [key1, key2]).unwrap();

        for id in [id2, id1] {
            restored.select(id, 0).unwrap();
            for phase in [1, 2, 3] {
                assert_eq!(
                    restored.sign_group_roster_vote(G, PARENT, B, 1, phase),
                    Err(Error::ConflictingRosterVote)
                );
            }
            assert_eq!(
                restored.sign_group_roster_freshness(G, PARENT, 0, B),
                Err(Error::ConflictingRosterVote)
            );
        }
        assert!(
            restored
                .sign_group_roster_vote(G + 1, PARENT, B, 1, 1)
                .is_ok()
        );
        assert!(restored.sign_group_roster_vote(G, A, B, 1, 1).is_ok());
    }
}

#[test]
fn invitation_and_voucher_lifetimes_are_bounded() {
    let g = VouchedGroup::new(1, [k(1), k(2)], Policy::Majority);
    assert!(g.invite_until(k(1), k(9), MAX_LIFETIME_MS).is_ok());
    assert!(matches!(
        g.invite_until(k(1), k(9), MAX_LIFETIME_MS + 1),
        Err(AdmissionError::InvalidExpiry)
    ));
    assert!(matches!(
        g.invite_until(k(1), k(9), u64::MAX),
        Err(AdmissionError::InvalidExpiry)
    ));
}

#[test]
fn the_same_roster_change_gives_the_same_history_on_every_node() {
    let a = VouchedGroup::new(1, [k(1), k(2), k(3), k(4)], Policy::Majority);
    let b = a.clone();
    let (mut a, mut b) = (a, b);
    for g in [&mut a, &mut b] {
        g.apply_policy_change(0, Policy::TwoThirds).unwrap();
        g.mark_suspect(k(3)).unwrap();
    }
    assert_eq!(a.rotation_context(), b.rotation_context());
    // Different changes still diverge.
    let mut c = VouchedGroup::new(1, [k(1), k(2), k(3), k(4)], Policy::Majority);
    c.apply_policy_change(0, Policy::Unanimous).unwrap();
    c.mark_suspect(k(3)).unwrap();
    assert_ne!(a.rotation_context(), c.rotation_context());
}

#[test]
fn a_key_removed_while_suspect_cannot_be_readmitted() {
    let mut g = VouchedGroup::new(1, [k(1), k(2), k(3), k(4)], Policy::Majority);
    g.mark_suspect(k(3)).unwrap();
    let tenure = g.membership(k(3)).unwrap();
    assert_eq!(g.apply_departure(k(3), tenure), Ok(true));
    assert!(g.invite(k(1), k(3)).is_err());
    // A benign member removed without suspicion can still return.
    let tenure = g.membership(k(4)).unwrap();
    assert_eq!(g.apply_departure(k(4), tenure), Ok(true));
    assert!(g.invite(k(1), k(4)).is_ok());
}

#[test]
fn recovery_status_reports_degraded_when_enrolled_witness_becomes_suspect() {
    let mut g = VouchedGroup::new(1, [k(1), k(2), k(3)], Policy::Majority);
    g.enroll_recovery(k(1), [k(2), k(3)]).unwrap();
    assert_eq!(g.recovery_status(k(1)), RecoveryStatus::Enrolled);
    g.mark_suspect(k(2)).unwrap();
    assert_eq!(g.recovery_status(k(1)), RecoveryStatus::Degraded);
}

#[test]
fn deliver_to_filters_degraded_recovery_for_privacy() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::session::installation::Installation;
    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(12345);
    let mut carol = Installation::new(SigningKey::generate(&mut rng));
    let mut bob = Installation::new(SigningKey::generate(&mut rng));
    support::meet(&mut carol, &mut bob, 1, &mut rng);
    let mut g = VouchedGroup::new(1, [carol.selected(), k(2), k(3)], Policy::InviterOnly);
    g.enroll_recovery(carol.selected(), [k(2), k(3)]).unwrap();
    let tenure = g.membership(k(2)).unwrap();
    g.apply_departure(k(2), tenure).unwrap();
    assert_eq!(
        g.recovery_status(carol.selected()),
        RecoveryStatus::Degraded
    );

    let mut proposal = g.invite(carol.selected(), bob.selected()).unwrap();
    let voucher = g
        .vouch(&proposal, &carol, [carol.selected(), k(3)], 100)
        .unwrap();
    proposal.accept(bob.selected()).unwrap();
    let update = g.admit(&proposal, Some(voucher)).unwrap();

    let (carol_snapshot, _) = update.deliver_to(carol.selected()).unwrap();
    assert_eq!(
        carol_snapshot.recovery_status(carol.selected()),
        RecoveryStatus::Degraded
    );

    let (other_snapshot, _) = update.deliver_to(k(3)).unwrap();
    assert_eq!(
        other_snapshot.recovery_status(carol.selected()),
        RecoveryStatus::NotEnrolled
    );
}

#[test]
fn invitation_inbox_accessors_and_no_slot_starvation() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::session::installation::Installation;
    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(54321);
    let inviter = Installation::new(SigningKey::generate(&mut rng));
    let candidate = Installation::new(SigningKey::generate(&mut rng));
    let g = VouchedGroup::new(1, [inviter.selected(), k(2)], Policy::Majority);

    let mut inbox = InvitationInbox::default();
    let proposal = g
        .invite_until(inviter.selected(), candidate.selected(), 30)
        .unwrap();
    let signed = SignedInvitation::new(&proposal, &inviter).unwrap();
    let binding = proposal.decision_binding();

    let received = inbox.receive(&g, &signed).unwrap();
    assert_eq!(received.decision_binding(), binding);
    assert_eq!(inbox.pending().count(), 1);

    let removed = inbox.remove(&binding);
    assert!(removed.is_some());
    assert_eq!(inbox.pending().count(), 0);
}

#[test]
fn recovery_inbox_accessors_and_veto_handling() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::session::installation::Installation;
    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(98765);
    let owner = Installation::new(SigningKey::generate(&mut rng));
    let witness1 = Installation::new(SigningKey::generate(&mut rng));
    let witness2 = Installation::new(SigningKey::generate(&mut rng));
    let new_key = Installation::new(SigningKey::generate(&mut rng));

    let mut g = VouchedGroup::new(
        1,
        [owner.selected(), witness1.selected(), witness2.selected()],
        Policy::Majority,
    );
    g.enroll_recovery(owner.selected(), [witness1.selected(), witness2.selected()])
        .unwrap();

    let req = g
        .request_recovery(owner.selected(), new_key.selected())
        .unwrap();
    let signed = g.sign_recovery_request(&req, &new_key).unwrap();

    let mut inbox = RecoveryInbox::default();
    let pending = inbox.receive(&g, &signed, &owner).unwrap();
    assert_eq!(pending.old(), owner.selected());
    assert_eq!(inbox.pending().count(), 1);

    let removed = inbox.remove(signed.nonce(), signed.old(), signed.new_key());
    assert!(removed.is_some());
    assert_eq!(inbox.pending().count(), 0);
}

#[test]
fn removing_and_reimporting_an_identity_keeps_its_voter_locks() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::session::installation::{Error, Installation};
    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(11);
    let key = SigningKey::generate(&mut rng);
    let mut n = Installation::new(SigningKey::generate(&mut rng));
    let id = n.add_identity(key.clone()).unwrap();
    n.select(id, 0).unwrap();
    n.sign_group_roster_vote(1, [7; 32], [1; 32], 1, 2).unwrap();
    let other = n.add_identity(SigningKey::generate(&mut rng)).unwrap();
    n.select(other, 1).unwrap();
    n.remove_identity(id).unwrap();
    n.import_identity(key, id).unwrap();
    n.select(id, 2).unwrap();
    assert_eq!(
        n.sign_group_roster_vote(1, [7; 32], [2; 32], 2, 1),
        Err(Error::ConflictingRosterVote)
    );
}

#[test]
fn full_invitation_inbox_still_admits_an_honest_inviter() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::session::installation::Installation;
    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(777);
    let mut flooders: Vec<Installation> = (0..9)
        .map(|_| Installation::new(SigningKey::generate(&mut rng)))
        .collect();
    let honest = Installation::new(SigningKey::generate(&mut rng));
    let candidate = Installation::new(SigningKey::generate(&mut rng));
    let members: Vec<_> = flooders
        .iter()
        .map(|f| f.selected())
        .chain([honest.selected()])
        .collect();
    let g = VouchedGroup::new(1, members, Policy::Majority);
    let mut inbox = InvitationInbox::default();
    'fill: for f in flooders.iter_mut() {
        for _ in 0..InvitationInbox::MAX_PER_INVITER {
            if inbox.pending().count() >= InvitationInbox::MAX_PENDING {
                break 'fill;
            }
            let target = SigningKey::generate(&mut rng).verifying_key().to_bytes();
            let p = g.invite_until(f.selected(), target, 30).unwrap();
            let signed = SignedInvitation::new(&p, f).unwrap();
            inbox.receive(&g, &signed).unwrap();
        }
    }
    assert_eq!(inbox.pending().count(), InvitationInbox::MAX_PENDING);
    let p = g
        .invite_until(honest.selected(), candidate.selected(), 30)
        .unwrap();
    let signed = SignedInvitation::new(&p, &honest).unwrap();
    assert!(inbox.receive(&g, &signed).is_ok());
    assert_eq!(inbox.pending().count(), InvitationInbox::MAX_PENDING);
}

#[test]
fn a_restored_three_member_group_can_be_reconciled_with_every_member_answering() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::groups::LocalInstallation;
    use mesh_identity::session::installation::Installation;
    use rand::{SeedableRng, rngs::StdRng};
    use std::time::Instant;
    let mut rng = StdRng::seed_from_u64(31337);
    let members: Vec<Installation> = (0..3)
        .map(|_| Installation::new(SigningKey::generate(&mut rng)))
        .collect();
    let group = VouchedGroup::new(1, members.iter().map(|m| m.selected()), Policy::Majority);
    let (group_id, _) = group.rotation_context();
    let local_for = |m: &Installation| {
        let mut local = LocalInstallation::default();
        local.add_identity(
            group.membership(m.selected()).unwrap().identity(),
            "m".into(),
        );
        local
    };
    let now = Instant::now();
    let challenge = RosterFreshnessChallenge::new(group_id, now);
    let responses: Vec<_> = members
        .iter()
        .map(|m| {
            group
                .attest_roster_freshness(&local_for(m), challenge.query(), m)
                .unwrap()
        })
        .collect();
    assert_eq!(
        group.verify_roster_freshness(&challenge, &responses[..2], now),
        Err(RosterFreshnessError::Unconfirmed)
    );
    assert_eq!(
        group.verify_roster_freshness(&challenge, &responses, now),
        Ok(())
    );

    let mut backup =
        LocalInstallation::restore_backup(&local_for(&members[0]).snapshot().unwrap()).unwrap();
    let tenure = group.membership(members[0].selected()).unwrap();
    assert!(!group.may_present(&backup, members[0].selected(), tenure));
    let mut view = group.clone();
    assert!(
        view.reconcile_backup_with_freshness(&mut backup, &group, challenge, &responses, now)
            .is_ok()
    );
    assert!(group.may_present(&backup, members[0].selected(), tenure));
}

#[test]
fn the_live_roster_head_cannot_be_retired() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::session::installation::{Error, Installation};
    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(5);
    let n = Installation::new(SigningKey::generate(&mut rng));
    assert_eq!(
        n.retire_roster_parent(1, [7; 32], [7; 32]),
        Err(Error::ConflictingRosterVote)
    );
    assert!(n.sign_group_roster_vote(1, [7; 32], [1; 32], 1, 1).is_ok());
}

#[test]
fn a_checkpoint_that_contradicts_the_snapshot_disables_signing() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::session::installation::{Error, Installation};
    use rand::{SeedableRng, rngs::StdRng};
    let mut rng = StdRng::seed_from_u64(6);
    let key = SigningKey::generate(&mut rng);
    let mk = || Installation::new(key.clone());
    // Two devices with the same key sign different children for the same slot.
    let a = mk();
    let mut b = mk();
    a.sign_group_roster_vote(1, [7; 32], [1; 32], 1, 1).unwrap();
    let mut checkpoint = Vec::new();
    b.sign_group_roster_vote_durable(1, [7; 32], [2; 32], 1, 1, |bytes, _| {
        checkpoint = bytes.to_vec();
        Ok(())
    })
    .unwrap();
    let restored = Installation::restore_with_roster_checkpoint(
        a.into_snapshot(0),
        [key.clone()],
        &checkpoint,
    )
    .unwrap();
    assert_eq!(
        restored.sign_group_roster_vote(1, [7; 32], [1; 32], 1, 1),
        Err(Error::RosterSigningStateUnconfirmed)
    );
    // A consistent checkpoint leaves signing available.
    let mut c = mk();
    let mut cp = Vec::new();
    c.sign_group_roster_vote_durable(1, [7; 32], [1; 32], 1, 1, |bytes, _| {
        cp = bytes.to_vec();
        Ok(())
    })
    .unwrap();
    let ok =
        Installation::restore_with_roster_checkpoint(mk().into_snapshot(0), [key], &cp).unwrap();
    assert!(ok.sign_group_roster_vote(1, [7; 32], [1; 32], 1, 1).is_ok());
}

#[test]
fn recovery_child_validates_enrolled_witnesses_and_eligible_keys() {
    use ed25519_dalek::SigningKey;
    use mesh_identity::session::installation::Installation;
    use rand::{SeedableRng, rngs::StdRng};
    use support::meet;

    let mut rng = StdRng::seed_from_u64(999);
    let owner = Installation::new(SigningKey::generate(&mut rng));
    let mut w1 = Installation::new(SigningKey::generate(&mut rng));
    let mut w2 = Installation::new(SigningKey::generate(&mut rng));
    let other = Installation::new(SigningKey::generate(&mut rng));
    let mut replacement = Installation::new(SigningKey::generate(&mut rng));

    let mut g = VouchedGroup::new(
        1,
        [
            owner.selected(),
            w1.selected(),
            w2.selected(),
            other.selected(),
        ],
        Policy::Majority,
    );
    g.enroll_recovery(owner.selected(), [w1.selected(), w2.selected()])
        .unwrap();

    let mut request = g
        .request_recovery(owner.selected(), replacement.selected())
        .unwrap();

    // Meet and approve
    meet(&mut w1, &mut replacement, 1, &mut rng);
    meet(&mut w2, &mut replacement, 2, &mut rng);
    g.approve_recovery(&mut request, &w1).unwrap();
    g.approve_recovery(&mut request, &w2).unwrap();
    let consent = g.recovery_consent(&request, &replacement).unwrap();
    g.apply_recovery_consent(&mut request, &consent).unwrap();
    g.advance_time(RECOVERY_VETO_WINDOW_MS);

    // Normal path succeeds
    assert!(g.recovery_child(&request).is_ok());

    // A recovery request for an existing member key is rejected by request_recovery
    assert!(matches!(
        g.request_recovery(owner.selected(), other.selected()),
        Err(Error::AlreadyMember)
    ));

    // A recovery request for a non-member old key is rejected
    let non_member = Installation::new(SigningKey::generate(&mut rng));
    assert!(matches!(
        g.request_recovery(non_member.selected(), replacement.selected()),
        Err(Error::Ineligible)
    ));
}
