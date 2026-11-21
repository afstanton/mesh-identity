#![cfg(all(feature = "groups", feature = "test-support"))]
use mesh_identity::groups::evidence::SimulatedAuthority as _;
mod support;

use ed25519_dalek::SigningKey;
use mesh_identity::groups::{
    Error, Policy, Vote,
    evidence::{AdmissionError, IntroducerReliance, Verification},
};
use support::{Scenario, meet};

#[test]
fn carol_vouches_while_alice_is_offline_then_alice_verifies_bob() {
    let mut s = Scenario::new(101, Policy::InviterOnly);
    let (alice, carol, bob, dave, eve) = (
        s.alice.selected(),
        s.carol.selected(),
        s.bob.selected(),
        s.dave.selected(),
        s.eve.selected(),
    );
    meet(&mut s.alice, &mut s.carol, 1, &mut s.rng);
    // Alice's local roster and contact history stay put until she reconnects.
    meet(&mut s.carol, &mut s.bob, 2, &mut s.rng);
    let mut proposal = s.group.invite(carol, bob).unwrap();
    let voucher = s
        .group
        .vouch(&proposal, &s.carol, [alice, dave], 100)
        .unwrap();
    assert_eq!((voucher.issuer(), voucher.candidate()), (carol, bob));
    assert!(matches!(
        s.group.admit(&proposal, Some(voucher.clone())),
        Err(AdmissionError::Roster(Error::AcceptanceRequired))
    ));
    proposal.accept(bob).unwrap();
    let update = s.group.admit(&proposal, Some(voucher)).unwrap();
    assert!(s.alice_offline.membership(bob).is_none());

    let (alice_group, alice_evidence) = update.deliver_to(alice).unwrap();
    let (dave_group, dave_evidence) = update.deliver_to(dave).unwrap();
    let (eve_group, eve_evidence) = update.deliver_to(eve).unwrap();
    assert!(eve_evidence.is_none());
    assert_eq!(alice_group.membership(bob), s.group.membership(bob));
    assert!(eve_group.membership(bob).is_some());
    assert_eq!(
        alice_group.verification(
            &s.alice,
            bob,
            alice_evidence.as_ref(),
            IntroducerReliance::Rely
        ),
        Verification::VouchedForByVerifiedIssuer(carol)
    );
    assert_eq!(
        dave_group.verification(
            &s.dave,
            bob,
            dave_evidence.as_ref(),
            IntroducerReliance::Rely
        ),
        Verification::VoucherFromUnverifiedIssuer(carol)
    );
    assert_eq!(
        eve_group.verification(
            &s.eve,
            bob,
            alice_evidence.as_ref(),
            IntroducerReliance::Rely
        ),
        Verification::NoEvidence
    );

    assert_eq!(
        alice_group.verification(
            &s.alice,
            bob,
            alice_evidence.as_ref(),
            IntroducerReliance::Decline,
        ),
        Verification::VoucherFromDeclinedIntroducer(carol)
    );
    assert_eq!(alice_group.membership(bob), s.group.membership(bob));

    let other_bob = s
        .bob
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    s.bob.select(other_bob, 3).unwrap();
    meet(&mut s.alice, &mut s.bob, 3, &mut s.rng);
    assert_eq!(
        alice_group.verification(
            &s.alice,
            bob,
            alice_evidence.as_ref(),
            IntroducerReliance::Rely
        ),
        Verification::VouchedForByVerifiedIssuer(carol)
    );
    s.bob.select(bob, 4).unwrap();
    meet(&mut s.alice, &mut s.bob, 4, &mut s.rng);
    assert_eq!(
        alice_group.verification(
            &s.alice,
            bob,
            alice_evidence.as_ref(),
            IntroducerReliance::Rely
        ),
        Verification::VerifiedInPerson
    );
    assert_eq!(
        dave_group.verification(
            &s.dave,
            bob,
            dave_evidence.as_ref(),
            IntroducerReliance::Rely
        ),
        Verification::VoucherFromUnverifiedIssuer(carol)
    );
    assert_eq!(alice_group.membership(bob), s.group.membership(bob));
}

#[test]
fn private_encounter_cannot_supply_a_direct_voucher_for_game_identity() {
    let mut s = Scenario::new(102, Policy::InviterOnly);
    let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    let private = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    s.carol.select(private, 1).unwrap();
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let mut proposal = s.group.invite(carol, bob).unwrap();
    assert!(matches!(
        s.group.vouch(&proposal, &s.carol, [alice], 100),
        Err(AdmissionError::VoucherRequired)
    ));
    s.carol.select(carol, 2).unwrap();
    assert!(matches!(
        s.group.vouch(&proposal, &s.carol, [alice], 100),
        Err(AdmissionError::VoucherRequired)
    ));
    proposal.accept(bob).unwrap();
    assert!(matches!(
        s.group.admit(&proposal, None),
        Err(AdmissionError::VoucherRequired)
    ));
    assert!(s.group.membership(private).is_none());
    assert!(s.group.membership(bob).is_none());
    assert!(s.alice.contacts(alice).unwrap().get(&private).is_none());
}

#[test]
fn majority_admission_can_pass_with_offline_member_and_objection() {
    let mut s = Scenario::new(103, Policy::Majority);
    let (alice, carol, bob, dave, eve) = (
        s.alice.selected(),
        s.carol.selected(),
        s.bob.selected(),
        s.dave.selected(),
        s.eve.selected(),
    );
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let mut proposal = s.group.invite(carol, bob).unwrap();
    proposal.accept(bob).unwrap();
    s.group.vote(&mut proposal, dave, Vote::Approve).unwrap();
    let voucher = s.group.vouch(&proposal, &s.carol, [alice], 100).unwrap();

    // Four members require three approvals, even when Alice has not answered.
    assert!(matches!(
        s.group.admit(&proposal, Some(voucher.clone())),
        Err(AdmissionError::Roster(Error::ApprovalRequired))
    ));
    assert!(s.group.membership(bob).is_none());
    s.group.vote(&mut proposal, eve, Vote::Approve).unwrap();
    // The votes still need qualifying identity evidence.
    assert!(matches!(
        s.group.admit(&proposal, None),
        Err(AdmissionError::VoucherRequired)
    ));

    // Use a separate run of the vote with Alice's objection arriving before commit.
    let mut objected = s.group.invite(carol, bob).unwrap();
    objected.accept(bob).unwrap();
    s.group.vote(&mut objected, dave, Vote::Approve).unwrap();
    s.group.vote(&mut objected, eve, Vote::Approve).unwrap();
    s.group.vote(&mut objected, alice, Vote::Object).unwrap();
    let objected_voucher = s.group.vouch(&objected, &s.carol, [alice], 100).unwrap();

    let mut alternate_order = s.group.clone();
    let update = alternate_order
        .admit(&objected, Some(objected_voucher))
        .unwrap();
    assert!(
        update
            .deliver_to(alice)
            .unwrap()
            .0
            .membership(bob)
            .is_some()
    );

    let update = s.group.admit(&proposal, Some(voucher)).unwrap();
    assert!(s.alice_offline.membership(bob).is_none());
    assert!(
        update
            .deliver_to(alice)
            .unwrap()
            .0
            .membership(bob)
            .is_some()
    );
    assert!(update.deliver_to(dave).unwrap().1.is_none());
}

#[test]
fn expired_or_withdrawn_voucher_requires_fresh_evidence_before_commit() {
    for withdraw in [false, true] {
        let mut s = Scenario::new(104, Policy::InviterOnly);
        let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
        meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
        let mut proposal = s.group.invite(carol, bob).unwrap();
        proposal.accept(bob).unwrap();
        let voucher = s.group.vouch(&proposal, &s.carol, [alice], 10).unwrap();
        s.group.advance_time(9);
        if withdraw {
            assert_eq!(s.group.withdraw(alice, &voucher), Err(Error::Ineligible));
            s.group.withdraw(carol, &voucher).unwrap();
            s.group.withdraw(carol, &voucher).unwrap();
        } else {
            s.group.advance_time(10);
            s.group.advance_time(9);
        }
        let expected = if withdraw {
            AdmissionError::VoucherWithdrawn
        } else {
            AdmissionError::VoucherExpired
        };
        assert_eq!(
            s.group.admit(&proposal, Some(voucher)).err(),
            Some(expected)
        );
        assert!(s.group.membership(bob).is_none());

        let fresh = s.group.vouch(&proposal, &s.carol, [alice], 20).unwrap();
        assert!(s.group.admit(&proposal, Some(fresh)).is_ok());
        assert!(s.group.membership(bob).is_some());
    }
}

#[test]
fn invalidated_voucher_changes_evidence_without_removing_member() {
    for withdraw in [false, true] {
        let mut s = Scenario::new(105, Policy::InviterOnly);
        let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
        meet(&mut s.alice, &mut s.carol, 1, &mut s.rng);
        meet(&mut s.carol, &mut s.bob, 2, &mut s.rng);
        let mut proposal = s.group.invite(carol, bob).unwrap();
        proposal.accept(bob).unwrap();
        let voucher = s.group.vouch(&proposal, &s.carol, [alice], 10).unwrap();
        s.group.advance_time(9);
        let update = s.group.admit(&proposal, Some(voucher.clone())).unwrap();
        let (mut view, evidence) = update.deliver_to(alice).unwrap();
        let membership = view.membership(bob).unwrap();
        assert_eq!(
            view.verification(&s.alice, bob, evidence.as_ref(), IntroducerReliance::Rely),
            Verification::VouchedForByVerifiedIssuer(carol)
        );
        let expected = if withdraw {
            s.group.withdraw(carol, &voucher).unwrap();
            // Simulate Alice applying the ordered withdrawal after reconnect.
            view.withdraw(carol, evidence.as_ref().unwrap()).unwrap();
            Verification::VoucherWithdrawn
        } else {
            view.advance_time(10);
            Verification::VoucherExpired
        };
        assert_eq!(
            view.verification(&s.alice, bob, evidence.as_ref(), IntroducerReliance::Rely),
            expected
        );
        assert_eq!(view.membership(bob), Some(membership));
        meet(&mut s.alice, &mut s.bob, 11, &mut s.rng);
        assert_eq!(
            view.verification(&s.alice, bob, evidence.as_ref(), IntroducerReliance::Rely),
            Verification::VerifiedInPerson
        );
    }
}

#[test]
fn authorized_withdrawal_can_arrive_before_the_voucher() {
    use mesh_identity::groups::evidence::{VouchedGroup, VoucherWithdrawal};

    let mut s = Scenario::new(142, Policy::InviterOnly);
    let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    meet(&mut s.alice, &mut s.carol, 1, &mut s.rng);
    meet(&mut s.carol, &mut s.bob, 2, &mut s.rng);
    let mut proposal = s.group.invite(carol, bob).unwrap();
    let voucher = s.group.vouch(&proposal, &s.carol, [alice], 100).unwrap();
    proposal.accept(bob).unwrap();
    let update = s.group.admit(&proposal, Some(voucher.clone())).unwrap();
    assert!(matches!(
        voucher.authorize_withdrawal(&s.alice),
        Err(Error::Ineligible)
    ));
    let alternate = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    s.carol.select(alternate, 3).unwrap();
    assert!(matches!(
        voucher.authorize_withdrawal(&s.carol),
        Err(Error::Ineligible)
    ));
    s.carol.select(carol, 4).unwrap();
    let delivery = voucher.prepare_withdrawal_delivery(&s.carol).unwrap();
    let bytes = delivery.deliver_to(alice).unwrap();
    assert!(delivery.deliver_to(s.dave.selected()).is_none());
    assert!(delivery.deliver_to(s.eve.selected()).is_none());
    assert!(delivery.deliver_to(bob).is_none());
    assert_eq!(delivery.deliver_to(alice), Some(bytes));
    assert!(VoucherWithdrawal::from_bytes(&bytes[..135]).is_err());
    for offset in [0, 8, 40, 72] {
        let mut modified = bytes;
        modified[offset] ^= 1;
        assert!(VoucherWithdrawal::from_bytes(&modified).is_err());
    }
    let mut other_signer = bytes;
    let voucher_id = bytes[8..40].try_into().unwrap();
    other_signer[40..72].copy_from_slice(&alice);
    other_signer[72..].copy_from_slice(&s.alice.sign_voucher_withdrawal(1, voucher_id).unwrap());
    let unrelated_withdrawal = VoucherWithdrawal::from_bytes(&other_signer).unwrap();
    let (mut view, evidence) = update.deliver_to(alice).unwrap();
    view.apply_withdrawal(&unrelated_withdrawal).unwrap();
    assert_eq!(
        view.verification(&s.alice, bob, evidence.as_ref(), IntroducerReliance::Rely),
        Verification::VouchedForByVerifiedIssuer(carol)
    );

    let withdrawal = VoucherWithdrawal::from_bytes(&bytes).unwrap();
    assert_eq!(withdrawal.to_bytes(), bytes);

    let mut other = VouchedGroup::new(2, [alice, carol], Policy::InviterOnly);
    assert_eq!(other.apply_withdrawal(&withdrawal), Err(Error::Ineligible));
    s.alice_offline.apply_withdrawal(&withdrawal).unwrap();
    s.alice_offline.apply_withdrawal(&withdrawal).unwrap();

    let (snapshot, evidence) = update.deliver_to(alice).unwrap();
    s.alice_offline.catch_up(&snapshot);
    assert_eq!(s.alice_offline.membership(bob), snapshot.membership(bob));
    assert!(s.alice_offline.membership(bob).is_some());
    assert_eq!(
        s.alice_offline
            .verification(&s.alice, bob, evidence.as_ref(), IntroducerReliance::Rely),
        Verification::VoucherWithdrawn
    );
}

#[test]
fn roster_snapshots_do_not_deliver_private_withdrawals() {
    use mesh_identity::groups::evidence::CatchUp;

    let mut s = Scenario::new(143, Policy::InviterOnly);
    let (alice, carol, bob, dave) = (
        s.alice.selected(),
        s.carol.selected(),
        s.bob.selected(),
        s.dave.selected(),
    );
    meet(&mut s.alice, &mut s.carol, 1, &mut s.rng);
    meet(&mut s.carol, &mut s.bob, 2, &mut s.rng);
    let mut invitation = s.group.invite(carol, bob).unwrap();
    invitation.accept(bob).unwrap();
    let voucher = s.group.vouch(&invitation, &s.carol, [alice], 100).unwrap();
    s.group.withdraw(carol, &voucher).unwrap();
    let replacement = s.group.vouch(&invitation, &s.carol, [alice], 100).unwrap();
    let update = s
        .group
        .admit(&invitation, Some(replacement.clone()))
        .unwrap();
    let (mut unrelated, hidden) = update.deliver_to(dave).unwrap();
    assert!(hidden.is_none());

    let (_, evidence) = update.deliver_to(alice).unwrap();
    let withdrawal = replacement.authorize_withdrawal(&s.carol).unwrap();
    s.group.apply_withdrawal(&withdrawal).unwrap();
    assert_eq!(s.alice_offline.catch_up(&s.group), CatchUp::Applied);
    assert_eq!(unrelated.catch_up(&s.group), CatchUp::AlreadyCurrent);
    assert_eq!(s.alice_offline.membership(bob), unrelated.membership(bob));
    assert_eq!(
        s.alice_offline
            .verification(&s.alice, bob, evidence.as_ref(), IntroducerReliance::Rely),
        Verification::VouchedForByVerifiedIssuer(carol)
    );
    s.alice_offline.apply_withdrawal(&withdrawal).unwrap();
    assert_eq!(s.alice_offline.catch_up(&s.group), CatchUp::AlreadyCurrent);
    assert_eq!(
        s.alice_offline
            .verification(&s.alice, bob, evidence.as_ref(), IntroducerReliance::Rely),
        Verification::VoucherWithdrawn
    );
}

#[test]
fn decline_expiry_and_identity_change_require_new_invitation() {
    let mut s = Scenario::new(106, Policy::InviterOnly);
    let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let other = s
        .bob
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    let mut declined = s.group.invite_until(carol, bob, 5).unwrap();
    assert_eq!((declined.inviter(), declined.candidate()), (carol, bob));
    let voucher = s.group.vouch(&declined, &s.carol, [alice], 20).unwrap();
    assert_eq!(declined.accept(other), Err(Error::Ineligible));
    declined.decline(bob).unwrap();
    assert_eq!(declined.accept(bob), Err(Error::Ineligible));
    assert_eq!(
        s.group.admit(&declined, Some(voucher.clone())).err(),
        Some(AdmissionError::InvitationDeclined)
    );

    let mut expired = s.group.invite_until(carol, bob, 5).unwrap();
    expired.accept(bob).unwrap();
    s.group.advance_time(5);
    assert_eq!(
        s.group.vote(&mut expired, alice, Vote::Approve),
        Err(AdmissionError::InvitationExpired)
    );
    assert_eq!(
        s.group.admit(&expired, Some(voucher.clone())).err(),
        Some(AdmissionError::InvitationExpired)
    );

    let mut changed = s.group.invite(carol, other).unwrap();
    changed.accept(other).unwrap();
    assert_eq!(
        s.group.admit(&changed, Some(voucher)).err(),
        Some(AdmissionError::VoucherRequired)
    );
    s.bob.select(other, 6).unwrap();
    meet(&mut s.carol, &mut s.bob, 6, &mut s.rng);
    let fresh = s.group.vouch(&changed, &s.carol, [alice], 20).unwrap();
    s.group.admit(&changed, Some(fresh)).unwrap();
    assert!(s.group.membership(bob).is_none());
    assert!(s.group.membership(other).is_some());
}

#[test]
fn voucher_is_scoped_to_one_invitation_even_for_same_candidate() {
    let mut s = Scenario::new(107, Policy::InviterOnly);
    let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let first = s.group.invite(carol, bob).unwrap();
    let first_voucher = s.group.vouch(&first, &s.carol, [alice], 10).unwrap();
    let mut second = s.group.invite(carol, bob).unwrap();
    second.accept(bob).unwrap();
    assert_eq!(
        s.group.admit(&second, Some(first_voucher.clone())).err(),
        Some(AdmissionError::VoucherRequired)
    );
    let second_voucher = s.group.vouch(&second, &s.carol, [alice], 10).unwrap();
    s.group.withdraw(carol, &first_voucher).unwrap();
    s.group.admit(&second, Some(second_voucher)).unwrap();
    assert!(s.group.membership(bob).is_some());
}

#[test]
fn two_encounter_keys_have_independent_evidence_and_admission() {
    let mut s = Scenario::new(108, Policy::InviterOnly);
    let (alice, carol, first_key) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    let second_key = s
        .bob
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    s.bob.select(second_key, 2).unwrap();
    meet(&mut s.carol, &mut s.bob, 2, &mut s.rng);

    // Both keys can be presented under the same application handle.
    let mut first = s.group.invite(carol, first_key).unwrap();
    let mut second = s.group.invite(carol, second_key).unwrap();
    let first_voucher = s.group.vouch(&first, &s.carol, [alice], 10).unwrap();
    assert_eq!(second.accept(first_key), Err(Error::Ineligible));
    second.accept(second_key).unwrap();
    assert_eq!(
        s.group.admit(&second, Some(first_voucher.clone())).err(),
        Some(AdmissionError::VoucherRequired)
    );

    first.accept(first_key).unwrap();
    let update = s.group.admit(&first, Some(first_voucher)).unwrap();
    let (view, evidence) = update.deliver_to(alice).unwrap();
    assert_eq!(
        view.verification(
            &s.alice,
            second_key,
            evidence.as_ref(),
            IntroducerReliance::Rely
        ),
        Verification::NoEvidence
    );
    assert!(view.membership(second_key).is_none());
}

#[test]
fn rotation_preserves_tenure_and_historical_verification_and_requires_new_votes() {
    let mut s = Scenario::new(109, Policy::Majority);
    let (alice, carol, bob, dave, eve) = (
        s.alice.selected(),
        s.carol.selected(),
        s.bob.selected(),
        s.dave.selected(),
        s.eve.selected(),
    );
    meet(&mut s.alice, &mut s.carol, 1, &mut s.rng);
    meet(&mut s.dave, &mut s.bob, 2, &mut s.rng);
    let tenure = s.group.membership(carol).unwrap();
    let mut pending = s.group.invite(dave, bob).unwrap();
    pending.accept(bob).unwrap();
    s.group.vote(&mut pending, carol, Vote::Approve).unwrap();
    s.group.vote(&mut pending, eve, Vote::Approve).unwrap();
    let old_voucher = s.group.vouch(&pending, &s.dave, [alice], 100).unwrap();

    let replacement = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    let parent = s.group.revision();
    assert_eq!(
        s.group.rotate_key(parent, carol, dave),
        Err(Error::AlreadyMember)
    );
    s.group.rotate_key(parent, carol, replacement).unwrap();
    assert_eq!(
        s.group.rotate_key(parent, carol, replacement),
        Err(Error::StaleProposal)
    );
    assert_eq!(s.group.membership(replacement), Some(tenure));
    assert!(s.group.membership(carol).is_none());
    assert_eq!(s.alice_offline.membership(carol), Some(tenure));
    assert!(s.alice_offline.membership(replacement).is_none());
    assert_eq!(
        s.group
            .verification(&s.alice, replacement, None, IntroducerReliance::Rely),
        Verification::KeyContinuity {
            verified_key: carol
        }
    );
    let alice_contacts = s.alice.contacts(alice).unwrap();
    assert!(alice_contacts.get(&carol).is_some());
    assert!(alice_contacts.get(&replacement).is_none());

    assert_eq!(
        s.group.admit(&pending, Some(old_voucher.clone())).err(),
        Some(AdmissionError::Roster(Error::StaleProposal))
    );
    let mut fresh = s.group.invite(dave, bob).unwrap();
    fresh.accept(bob).unwrap();
    assert_eq!(
        s.group.vote(&mut fresh, carol, Vote::Approve),
        Err(AdmissionError::Roster(Error::Ineligible))
    );
    s.group
        .vote(&mut fresh, replacement, Vote::Approve)
        .unwrap();
    s.group.vote(&mut fresh, eve, Vote::Approve).unwrap();
    assert_eq!(
        s.group.admit(&fresh, Some(old_voucher)).err(),
        Some(AdmissionError::VoucherRequired)
    );
    let voucher = s.group.vouch(&fresh, &s.dave, [alice], 100).unwrap();
    let update = s.group.admit(&fresh, Some(voucher)).unwrap();
    let (caught_up, _) = update.deliver_to(alice).unwrap();
    assert_eq!(caught_up.membership(replacement), Some(tenure));
    assert!(caught_up.membership(bob).is_some());
    assert!(matches!(
        s.group.invite(dave, carol),
        Err(Error::Ineligible)
    ));
}

#[test]
fn signed_rotation_requires_both_keys_and_the_exact_parent() {
    use mesh_identity::groups::evidence::{CatchUp, SignedRotation};

    let mut s = Scenario::new(146, Policy::InviterOnly);
    let old = s.carol.selected();
    let new = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    let tenure = s.group.membership(old);
    let mut fork = s.group.clone();
    let mut lagging = s.group.clone();
    s.group.mark_suspect(s.dave.selected()).unwrap();
    fork.mark_suspect(s.eve.selected()).unwrap();
    let revision = s.group.revision();
    assert_eq!(fork.revision(), revision);

    let queued = s.group.plan_distribution();
    let prior_recipients = s.group.distribution_recipients(&queued).unwrap();
    assert!(prior_recipients.contains(&old));
    assert!(!prior_recipients.contains(&new));
    let context = s.group.rotation_context();
    let old_signature = s
        .carol
        .sign_group_rotation(context.0, context.1, old, new)
        .unwrap();
    assert!(
        s.alice
            .sign_group_rotation(context.0, context.1, old, new)
            .is_err()
    );
    s.carol.select(new, 1).unwrap();
    let new_signature = s
        .carol
        .sign_group_rotation(context.0, context.1, old, new)
        .unwrap();
    let signatures = [old_signature, new_signature];

    for invalid in [
        [old_signature, old_signature],
        [new_signature, old_signature],
    ] {
        assert_eq!(
            s.group.apply_signed_rotation(context, old, new, invalid),
            Err(Error::Ineligible)
        );
        assert_eq!(s.group.revision(), revision);
    }
    assert_eq!(
        fork.apply_signed_rotation(context, old, new, signatures),
        Err(Error::StaleProposal)
    );
    assert_eq!(
        fork.apply_signed_rotation(fork.rotation_context(), old, new, signatures),
        Err(Error::Ineligible)
    );
    assert_eq!(fork.membership(old), tenure);

    let bytes = SignedRotation::new(context, old, new, signatures).to_bytes();
    assert!(SignedRotation::from_bytes(&bytes[..231]).is_err());
    let mut oversized = bytes.to_vec();
    oversized.push(0);
    assert!(SignedRotation::from_bytes(&oversized).is_err());
    for (offset, expected) in [
        (0, Error::StaleProposal),
        (8, Error::StaleProposal),
        (40, Error::Ineligible),
        (72, Error::Ineligible),
        (104, Error::Ineligible),
        (168, Error::Ineligible),
    ] {
        let mut modified = bytes;
        modified[offset] ^= 1;
        let decoded = SignedRotation::from_bytes(&modified).unwrap();
        assert_eq!(s.group.apply_rotation_message(&decoded), Err(expected));
        assert_eq!(s.group.revision(), revision);
        assert_eq!(s.group.membership(old), tenure);
    }

    let decoded = SignedRotation::from_bytes(&bytes).unwrap();
    assert_eq!(decoded.to_bytes(), bytes);
    let previous_revision = lagging.revision();
    assert_eq!(
        lagging.apply_rotation_message(&decoded),
        Err(Error::StaleProposal)
    );
    assert_eq!(lagging.revision(), previous_revision);
    assert_eq!(lagging.membership(old), tenure);
    assert!(lagging.membership(new).is_none());

    assert_eq!(lagging.catch_up(&s.group), CatchUp::Applied);
    assert_eq!(lagging.rotation_context(), context);
    lagging.apply_rotation_message(&decoded).unwrap();
    assert_eq!(lagging.membership(new), tenure);
    assert!(lagging.membership(old).is_none());

    // Each peer applies the same agreed authorization independently.
    s.group.apply_rotation_message(&decoded).unwrap();
    assert_eq!(s.group.rotation_context(), lagging.rotation_context());
    assert_eq!(s.group.catch_up(&lagging), CatchUp::AlreadyCurrent);
    assert_eq!(lagging.catch_up(&s.group), CatchUp::AlreadyCurrent);
    let plan = lagging.plan_distribution();
    let expected: std::collections::BTreeSet<_> = prior_recipients
        .into_iter()
        .map(|key| if key == old { new } else { key })
        .collect();
    for peer in [&s.group, &lagging] {
        assert_eq!(
            peer.distribution_recipients(&queued),
            Err(Error::StaleProposal)
        );
        let recipients = peer.distribution_recipients(&plan).unwrap();
        assert_eq!(recipients.len(), expected.len());
        assert_eq!(
            recipients
                .into_iter()
                .collect::<std::collections::BTreeSet<_>>(),
            expected
        );
    }

    // A later snapshot can descend from either independently applied rotation.
    s.group.mark_suspect(s.eve.selected()).unwrap();
    assert_eq!(lagging.catch_up(&s.group), CatchUp::Applied);
    assert!(s.group.membership(old).is_none());
    assert_eq!(s.group.membership(new), tenure);
    assert_eq!(
        s.group.apply_rotation_message(&decoded),
        Err(Error::StaleProposal)
    );
}

#[test]
fn competing_signed_rotations_require_an_agreed_order() {
    use mesh_identity::groups::evidence::{CatchUp, SignedRotation};

    let mut s = Scenario::new(147, Policy::InviterOnly);
    let old = s.carol.selected();
    let tenure = s.group.membership(old).unwrap();
    let context = s.group.rotation_context();
    let rotations = [1, 2].map(|now| {
        let new = s
            .carol
            .add_identity(SigningKey::generate(&mut s.rng))
            .unwrap();
        s.carol.select(old, now).unwrap();
        let approval = s
            .carol
            .sign_group_rotation(context.0, context.1, old, new)
            .unwrap();
        s.carol.select(new, now).unwrap();
        let consent = s
            .carol
            .sign_group_rotation(context.0, context.1, old, new)
            .unwrap();
        (
            new,
            SignedRotation::new(context, old, new, [approval, consent]),
        )
    });
    let [(first, first_rotation), (second, second_rotation)] = &rotations;
    let mut left = s.group.clone();
    let mut right = s.group.clone();

    // Without an agreed delivery order, each peer can apply a different valid transition.
    left.apply_rotation_message(first_rotation).unwrap();
    right.apply_rotation_message(second_rotation).unwrap();
    assert_eq!(left.revision(), right.revision());
    assert_ne!(left.rotation_context(), right.rotation_context());
    assert_eq!(
        left.apply_rotation_message(second_rotation),
        Err(Error::StaleProposal)
    );
    assert_eq!(
        right.apply_rotation_message(first_rotation),
        Err(Error::StaleProposal)
    );
    assert_eq!(left.catch_up(&right), CatchUp::ConflictingHistory);
    assert_eq!(right.catch_up(&left), CatchUp::ConflictingHistory);
    assert_eq!(left.membership(*first), Some(tenure));
    assert_eq!(right.membership(*second), Some(tenure));
    assert!(left.membership(*second).is_none());
    assert!(right.membership(*first).is_none());
}

#[test]
fn issuer_rotation_requires_fresh_direct_evidence_for_a_new_voucher() {
    let mut s = Scenario::new(110, Policy::InviterOnly);
    let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let mut old = s.group.invite(carol, bob).unwrap();
    old.accept(bob).unwrap();
    let voucher = s.group.vouch(&old, &s.carol, [alice], 100).unwrap();

    let replacement = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    s.group
        .rotate_key(s.group.revision(), carol, replacement)
        .unwrap();
    assert!(matches!(
        s.group.admit(&old, Some(voucher.clone())),
        Err(AdmissionError::Roster(Error::StaleProposal))
    ));
    s.carol.select(replacement, 2).unwrap();
    let mut fresh = s.group.invite(replacement, bob).unwrap();
    fresh.accept(bob).unwrap();
    assert!(matches!(
        s.group.admit(&fresh, Some(voucher)),
        Err(AdmissionError::VoucherRequired)
    ));
    assert!(matches!(
        s.group.vouch(&fresh, &s.carol, [alice], 100),
        Err(AdmissionError::VoucherRequired)
    ));
    meet(&mut s.carol, &mut s.bob, 2, &mut s.rng);
    let voucher = s.group.vouch(&fresh, &s.carol, [alice], 100).unwrap();
    assert_eq!(voucher.issuer(), replacement);
    s.group.admit(&fresh, Some(voucher)).unwrap();
}

#[test]
fn competing_and_out_of_order_rotations_preserve_the_agreed_key_history() {
    let mut s = Scenario::new(111, Policy::InviterOnly);
    let old = s.carol.selected();
    let tenure = s.group.membership(old);
    let first = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    let second = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    let competing = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();

    assert_eq!(
        s.group.rotate_key(1, first, second),
        Err(Error::StaleProposal)
    );
    assert_eq!(s.group.membership(old), tenure);
    s.group.rotate_key(0, old, first).unwrap();
    assert_eq!(
        s.group.rotate_key(0, old, competing),
        Err(Error::StaleProposal)
    );
    s.group.rotate_key(1, first, second).unwrap();
    assert_eq!(s.group.rotate_key(0, old, first), Err(Error::StaleProposal));
    assert_eq!(
        s.group.rotate_key(2, second, old),
        Err(Error::AlreadyMember)
    );
    assert_eq!(s.group.membership(second), tenure);
    assert!(s.group.membership(first).is_none());
    assert!(s.group.membership(competing).is_none());
}

#[test]
fn suspect_key_requires_independent_recovery_without_transferring_verification() {
    let mut s = Scenario::new(112, Policy::InviterOnly);
    let (old, bob) = (s.carol.selected(), s.bob.selected());
    meet(&mut s.alice, &mut s.carol, 1, &mut s.rng);
    let replacement = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    let tenure = s.group.membership(old);
    s.group.mark_suspect(old).unwrap();
    s.group.mark_suspect(old).unwrap();
    assert_eq!(s.group.revision(), 1);
    assert_eq!(
        s.group.rotate_key(1, old, replacement),
        Err(Error::Ineligible)
    );
    assert!(matches!(s.group.invite(old, bob), Err(Error::Ineligible)));
    assert_eq!(s.group.membership(old), tenure);
    assert_eq!(s.group.membership(replacement), None);

    // The fixture supplies an independently accepted recovery decision.
    s.group.apply_recovered_key(1, old, replacement).unwrap();
    assert_eq!(s.group.membership(replacement), tenure);
    assert_eq!(
        s.group
            .verification(&s.alice, replacement, None, IntroducerReliance::Rely),
        Verification::NoEvidence
    );
    let alice = s.alice.selected();
    assert!(s.alice.contacts(alice).unwrap().get(&old).is_some());
    s.carol.select(replacement, 2).unwrap();
    meet(&mut s.alice, &mut s.carol, 2, &mut s.rng);
    assert_eq!(
        s.group
            .verification(&s.alice, replacement, None, IntroducerReliance::Rely),
        Verification::VerifiedInPerson
    );
}

#[test]
fn offline_peer_catches_up_and_rejects_duplicate_stale_and_conflicting_rosters() {
    use mesh_identity::groups::evidence::CatchUp;

    let mut s = Scenario::new(113, Policy::InviterOnly);
    let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let mut invitation = s.group.invite(carol, bob).unwrap();
    invitation.accept(bob).unwrap();
    let voucher = s.group.vouch(&invitation, &s.carol, [alice], 100).unwrap();
    let unused = s.group.vouch(&invitation, &s.carol, [alice], 100).unwrap();
    let update = s.group.admit(&invitation, Some(voucher.clone())).unwrap();
    let (first, evidence) = update.deliver_to(alice).unwrap();

    let old = s.dave.selected();
    let replacement = s
        .dave
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    let competing = s
        .dave
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    let mut fork = first.clone();
    fork.rotate_key(1, old, competing).unwrap();
    s.group.rotate_key(1, old, replacement).unwrap();

    let peer = &mut s.alice_offline;
    assert!(peer.membership(bob).is_none());
    assert_eq!(peer.catch_up(&s.group), CatchUp::Applied);
    assert_eq!(peer.catch_up(&s.group), CatchUp::AlreadyCurrent);
    assert_eq!(peer.catch_up(&first), CatchUp::OlderSnapshot);
    assert_eq!(peer.catch_up(&fork), CatchUp::ConflictingHistory);
    fork.mark_suspect(competing).unwrap();
    assert_eq!(peer.catch_up(&fork), CatchUp::ConflictingHistory);
    assert_eq!(peer.membership(bob), s.group.membership(bob));
    assert!(peer.membership(replacement).is_some());
    assert!(peer.membership(competing).is_none());
    assert_eq!(
        peer.verification(&s.alice, bob, Some(&unused), IntroducerReliance::Rely),
        Verification::NoEvidence
    );

    s.group.withdraw(carol, &voucher).unwrap();
    assert_eq!(peer.catch_up(&s.group), CatchUp::AlreadyCurrent);
    assert_eq!(
        peer.verification(&s.alice, bob, evidence.as_ref(), IntroducerReliance::Rely),
        Verification::VoucherFromUnverifiedIssuer(carol)
    );
    let withdrawal = voucher.authorize_withdrawal(&s.carol).unwrap();
    peer.apply_withdrawal(&withdrawal).unwrap();
    assert_eq!(peer.catch_up(&s.group), CatchUp::AlreadyCurrent);
    assert_eq!(
        peer.verification(&s.alice, bob, evidence.as_ref(), IntroducerReliance::Rely),
        Verification::VoucherWithdrawn
    );
    assert_eq!(peer.membership(bob), s.group.membership(bob));
}

#[test]
fn partitioned_invitations_reconnect_and_renew_against_the_agreed_parent() {
    use mesh_identity::groups::evidence::CatchUp;

    for carol_first in [false, true] {
        let mut s = Scenario::new(114, Policy::InviterOnly);
        let (alice, carol, dave, bob) = (
            s.alice.selected(),
            s.carol.selected(),
            s.dave.selected(),
            s.bob.selected(),
        );
        let second = s
            .bob
            .add_identity(SigningKey::generate(&mut s.rng))
            .unwrap();
        meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
        s.bob.select(second, 2).unwrap();
        meet(&mut s.dave, &mut s.bob, 2, &mut s.rng);

        // Each partition can prepare an invitation using its last agreed roster.
        // The fixture supplies the order in which the proposals are committed.
        let mut peer = s.group.clone();
        let mut carol_offer = s.group.invite(carol, bob).unwrap();
        let mut dave_offer = peer.invite(dave, second).unwrap();
        carol_offer.accept(bob).unwrap();
        dave_offer.accept(second).unwrap();
        let carol_voucher = s.group.vouch(&carol_offer, &s.carol, [alice], 100).unwrap();
        let dave_voucher = peer.vouch(&dave_offer, &s.dave, [alice], 100).unwrap();
        assert_eq!(peer.revision(), 0);
        assert!(peer.membership(bob).is_none());
        assert!(peer.membership(second).is_none());

        let (winner, loser, issuer, pending, old_voucher) = if carol_first {
            s.group.admit(&carol_offer, Some(carol_voucher)).unwrap();
            (bob, second, &s.dave, dave_offer, dave_voucher)
        } else {
            s.group.admit(&dave_offer, Some(dave_voucher)).unwrap();
            (second, bob, &s.carol, carol_offer, carol_voucher)
        };

        assert_eq!(peer.catch_up(&s.group), CatchUp::Applied);
        assert!(peer.membership(winner).is_some());
        assert!(peer.membership(loser).is_none());
        assert!(matches!(
            peer.admit(&pending, Some(old_voucher)),
            Err(AdmissionError::Roster(Error::StaleProposal))
        ));
        let mut renewed = peer.invite(issuer.selected(), loser).unwrap();
        let fresh = peer.vouch(&renewed, issuer, [alice], 100).unwrap();
        assert!(matches!(
            peer.admit(&renewed, Some(fresh.clone())),
            Err(AdmissionError::Roster(Error::AcceptanceRequired))
        ));
        renewed.accept(loser).unwrap();
        // Commit on the agreed history. The reconnected peer then receives it.
        s.group.admit(&renewed, Some(fresh)).unwrap();
        assert_eq!(peer.catch_up(&s.group), CatchUp::Applied);
        assert_eq!(peer.catch_up(&s.group), CatchUp::AlreadyCurrent);
        for candidate in [winner, loser] {
            assert!(peer.membership(candidate).is_some());
            assert_eq!(peer.membership(candidate), s.group.membership(candidate));
        }
    }
}

#[test]
fn offline_departure_suppresses_delayed_presentation_and_preserves_other_identity() {
    use mesh_identity::groups::{MemberLocalState, evidence::CatchUp};

    let mut s = Scenario::new(115, Policy::InviterOnly);
    let (alice, carol) = (s.alice.selected(), s.carol.selected());
    let other = s
        .alice
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();

    // Admit Alice's second identity using only its own encounter evidence.
    s.alice.select(other, 1).unwrap();
    meet(&mut s.carol, &mut s.alice, 1, &mut s.rng);
    let mut invite = s.group.invite(carol, other).unwrap();
    invite.accept(other).unwrap();
    let voucher = s.group.vouch(&invite, &s.carol, [alice], 100).unwrap();
    s.group.admit(&invite, Some(voucher)).unwrap();
    let mut offline = s.group.clone();
    let departing = offline.membership(alice).unwrap();
    let remaining = offline.membership(other).unwrap();

    let mut local = MemberLocalState::default();
    local.add_identity(departing.identity(), "Alice".into());
    local.add_identity(remaining.identity(), "Other persona".into());
    assert!(offline.may_present(&local, alice, departing));

    local.leave(departing).unwrap();
    let mut local = MemberLocalState::restore(&local.snapshot().unwrap()).unwrap();
    assert!(!offline.may_present(&local, alice, departing));
    assert!(offline.may_present(&local, other, remaining));

    // The group advances independently while Alice is offline.
    let dave = s.dave.selected();
    let replacement = s
        .dave
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    s.group
        .rotate_key(s.group.revision(), dave, replacement)
        .unwrap();
    assert_eq!(offline.catch_up(&s.group), CatchUp::Applied);
    offline.prune_departures(&mut local);
    assert_eq!(local.departure_intents().collect::<Vec<_>>(), [departing]);
    assert!(!s.group.apply_departure(other, departing).unwrap());
    assert!(s.group.apply_departure(alice, departing).unwrap());
    assert!(!s.group.apply_departure(alice, departing).unwrap());

    let stale = offline.clone();
    assert_eq!(offline.catch_up(&s.group), CatchUp::Applied);
    offline.prune_departures(&mut local);
    assert_eq!(local.departure_intents().count(), 0);
    assert!(!offline.may_present(&local, alice, departing));
    assert!(!stale.may_present(&local, alice, departing));
    assert!(!stale.may_present(&local, other, departing));
    assert!(offline.may_present(&local, other, remaining));
}

#[test]
fn policy_change_invalidates_pending_admission_and_exposes_new_threshold() {
    use mesh_identity::groups::evidence::CatchUp;

    let mut s = Scenario::new(116, Policy::Majority);
    let (alice, carol, bob, dave, eve) = (
        s.alice.selected(),
        s.carol.selected(),
        s.bob.selected(),
        s.dave.selected(),
        s.eve.selected(),
    );
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let mut pending = s.group.invite(carol, bob).unwrap();
    pending.accept(bob).unwrap();
    s.group.vote(&mut pending, dave, Vote::Approve).unwrap();
    assert_eq!(s.group.approval_counts(&pending), Ok((2, 3)));
    let voucher = s.group.vouch(&pending, &s.carol, [alice], 100).unwrap();

    assert_eq!(s.group.apply_policy_change(0, Policy::Unanimous), Ok(true));
    assert_eq!(
        s.group.apply_policy_change(0, Policy::InviterOnly),
        Err(Error::StaleProposal)
    );
    assert_eq!(s.group.apply_policy_change(1, Policy::Unanimous), Ok(false));
    assert_eq!(
        s.group.admit(&pending, Some(voucher.clone())).err(),
        Some(AdmissionError::Roster(Error::StaleProposal))
    );
    assert_eq!(s.alice_offline.approval_counts(&pending), Ok((2, 3)));
    assert_eq!(s.alice_offline.catch_up(&s.group), CatchUp::Applied);
    assert_eq!(
        s.alice_offline.approval_counts(&pending),
        Err(AdmissionError::Roster(Error::StaleProposal))
    );

    let mut renewed = s.group.invite(carol, bob).unwrap();
    let fresh = s.group.vouch(&renewed, &s.carol, [alice], 100).unwrap();
    assert_eq!(s.group.approval_counts(&renewed), Ok((1, 4)));
    assert_eq!(
        s.group.admit(&renewed, Some(voucher)).err(),
        Some(AdmissionError::VoucherRequired)
    );
    renewed.accept(bob).unwrap();
    for voter in [dave, eve] {
        s.group.vote(&mut renewed, voter, Vote::Approve).unwrap();
    }
    assert_eq!(
        s.group.admit(&renewed, Some(fresh.clone())).err(),
        Some(AdmissionError::Roster(Error::ApprovalRequired))
    );
    s.group.vote(&mut renewed, alice, Vote::Approve).unwrap();
    s.group.admit(&renewed, Some(fresh)).unwrap();
    assert!(s.group.membership(bob).is_some());
}

#[test]
fn last_departure_closes_group_and_stale_updates_cannot_reopen_it() {
    use mesh_identity::groups::evidence::{CatchUp, VouchedGroup};

    let mut s = Scenario::new(117, Policy::InviterOnly);
    let (carol, bob) = (s.carol.selected(), s.bob.selected());
    let mut group = VouchedGroup::new(2, [carol], Policy::InviterOnly);
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let mut pending = group.invite(carol, bob).unwrap();
    pending.accept(bob).unwrap();
    let voucher = group.vouch(&pending, &s.carol, [carol], 100).unwrap();
    let tenure = group.membership(carol).unwrap();
    let stale = group.clone();
    assert!(group.apply_departure(carol, tenure).unwrap());
    assert!(group.is_closed());
    assert!(!group.apply_departure(carol, tenure).unwrap());
    assert_eq!(
        group.admit(&pending, Some(voucher.clone())).err(),
        Some(AdmissionError::Roster(Error::StaleProposal))
    );
    assert!(matches!(group.invite(carol, bob), Err(Error::Ineligible)));
    assert_eq!(
        group.apply_policy_change(1, Policy::Unanimous),
        Err(Error::Ineligible)
    );
    assert_eq!(group.catch_up(&stale), CatchUp::OlderSnapshot);

    let mut competing = stale.clone();
    competing.admit(&pending, Some(voucher)).unwrap();
    assert_eq!(group.catch_up(&competing), CatchUp::ConflictingHistory);
    let mut lagging = stale;
    assert_eq!(lagging.catch_up(&group), CatchUp::Applied);
    assert!(lagging.is_closed());
    assert!(group.is_closed());
    assert!(group.membership(bob).is_none());
}

#[test]
fn two_devices_sharing_an_identity_get_one_vote_and_one_departure() {
    let mut s = Scenario::new(118, Policy::Majority);
    let (carol, dave, bob) = (s.carol.selected(), s.dave.selected(), s.bob.selected());
    let mut pending = s.group.invite(carol, bob).unwrap();

    // Device messages are represented by the same authenticated roster key.
    s.group.vote(&mut pending, dave, Vote::Approve).unwrap();
    assert_eq!(
        s.group.vote(&mut pending, dave, Vote::Approve),
        Err(AdmissionError::Roster(Error::AlreadyVoted))
    );
    assert_eq!(s.group.approval_counts(&pending), Ok((2, 3)));

    let tenure = s.group.membership(dave).unwrap();
    let replacement = s
        .dave
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    s.group.rotate_key(0, dave, replacement).unwrap();
    let mut fresh = s.group.invite(carol, bob).unwrap();
    assert_eq!(
        s.group.vote(&mut fresh, dave, Vote::Approve),
        Err(AdmissionError::Roster(Error::Ineligible))
    );
    assert_eq!(s.group.apply_departure(dave, tenure), Ok(false));
    assert_eq!(s.group.membership(replacement), Some(tenure));
    assert_eq!(s.group.apply_departure(replacement, tenure), Ok(true));
    assert_eq!(s.group.apply_departure(replacement, tenure), Ok(false));
    assert_eq!(s.group.revision(), 2);
}

#[test]
fn invite_and_join_can_finish_after_the_inviter_goes_offline() {
    let mut s = Scenario::new(119, Policy::InviterOnly);
    let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);

    // Invite packages the inviter's approval and the evidence they chose to share.
    let mut invitation = s.group.invite_until(carol, bob, 20).unwrap();
    let voucher = s.group.vouch(&invitation, &s.carol, [alice], 20).unwrap();
    let (inviter, candidate) = (invitation.inviter(), invitation.candidate());
    assert_eq!((inviter, candidate), (carol, bob));
    assert_eq!((voucher.issuer(), voucher.candidate()), (carol, bob));
    assert_eq!(s.group.approval_counts(&invitation), Ok((1, 1)));
    drop(s.carol);

    // Join records the selected identity's consent. Committing requires no new
    // decision from the inviter or any other member under this policy.
    s.group.advance_time(2);
    invitation.accept(s.bob.selected()).unwrap();
    let update = s.group.admit(&invitation, Some(voucher)).unwrap();
    let (view, evidence) = update.deliver_to(alice).unwrap();
    assert!(view.membership(candidate).is_some());
    assert_eq!(evidence.unwrap().issuer(), inviter);
}

#[test]
fn transported_invitation_preserves_the_binding_for_remote_decisions() {
    use mesh_identity::groups::evidence::{
        SignedAdmissionConsent, SignedAdmissionVote, SignedInvitation,
    };

    let mut s = Scenario::new(153, Policy::Fixed(std::num::NonZeroUsize::new(2).unwrap()));
    let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let mut original = s.group.invite_until(carol, bob, 20).unwrap();
    assert!(SignedInvitation::new(&original, &s.alice).is_err());
    let bytes = SignedInvitation::new(&original, &s.carol)
        .unwrap()
        .to_bytes();
    assert!(SignedInvitation::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    for offset in [40, 72, 104, 136, 144] {
        let mut altered = bytes;
        altered[offset] ^= 1;
        assert!(
            s.alice_offline
                .receive_invitation(&SignedInvitation::from_bytes(&altered).unwrap())
                .is_err()
        );
    }

    let message = SignedInvitation::from_bytes(&bytes).unwrap();
    let remote = s.alice_offline.receive_invitation(&message).unwrap();
    assert_eq!((remote.inviter(), remote.candidate()), (carol, bob));
    let vote = SignedAdmissionVote::new(&remote, &s.alice, Vote::Approve).unwrap();
    let consent = SignedAdmissionConsent::new(&remote, &s.bob).unwrap();
    s.group
        .apply_admission_vote(
            &mut original,
            &SignedAdmissionVote::from_bytes(&vote.to_bytes()).unwrap(),
        )
        .unwrap();
    s.group
        .apply_admission_consent(
            &mut original,
            &SignedAdmissionConsent::from_bytes(&consent.to_bytes()).unwrap(),
        )
        .unwrap();
    let voucher = s.group.vouch(&original, &s.carol, [alice], 100).unwrap();
    s.group.admit(&original, Some(voucher)).unwrap();
    assert!(s.group.membership(bob).is_some());
    assert!(matches!(
        s.group.receive_invitation(&message),
        Err(AdmissionError::Roster(Error::StaleProposal))
    ));
    s.alice_offline.advance_time(20);
    assert!(matches!(
        s.alice_offline.receive_invitation(&message),
        Err(AdmissionError::InvitationExpired)
    ));
}

#[test]
fn signed_candidate_consent_requires_the_exact_live_invitation() {
    use mesh_identity::groups::evidence::SignedAdmissionConsent;

    let mut s = Scenario::new(152, Policy::InviterOnly);
    let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let mut live = s.group.invite(carol, bob).unwrap();
    let mut duplicate = s.group.invite(carol, bob).unwrap();
    let mut cancelled = s.group.invite(carol, bob).unwrap();
    let mut expired = s.group.invite_until(carol, bob, 10).unwrap();
    assert!(matches!(
        SignedAdmissionConsent::new(&live, &s.alice),
        Err(Error::Ineligible)
    ));

    let bytes = SignedAdmissionConsent::new(&live, &s.bob)
        .unwrap()
        .to_bytes();
    assert!(SignedAdmissionConsent::from_bytes(&bytes[..63]).is_err());
    assert!(SignedAdmissionConsent::from_bytes(&[0; 65]).is_err());
    let consent = SignedAdmissionConsent::from_bytes(&bytes).unwrap();
    assert_eq!(consent.to_bytes(), bytes);
    let mut invalid = bytes;
    invalid[0] ^= 1;
    let invalid = SignedAdmissionConsent::from_bytes(&invalid).unwrap();
    assert_eq!(
        s.group.apply_admission_consent(&mut live, &invalid),
        Err(AdmissionError::Roster(Error::Ineligible))
    );
    assert_eq!(
        s.group.apply_admission_consent(&mut duplicate, &consent),
        Err(AdmissionError::Roster(Error::Ineligible))
    );
    assert!(
        !s.group
            .invitation_progress(&duplicate, bob)
            .unwrap()
            .candidate_accepted
    );
    let cancelled_consent = SignedAdmissionConsent::new(&cancelled, &s.bob).unwrap();
    s.group.cancel_invitation(&mut cancelled, carol).unwrap();
    assert_eq!(
        s.group
            .apply_admission_consent(&mut cancelled, &cancelled_consent),
        Err(AdmissionError::InvitationCancelled)
    );
    let expired_consent = SignedAdmissionConsent::new(&expired, &s.bob).unwrap();
    s.group.advance_time(10);
    assert_eq!(
        s.group
            .apply_admission_consent(&mut expired, &expired_consent),
        Err(AdmissionError::InvitationExpired)
    );

    let voucher = s.group.vouch(&live, &s.carol, [alice], 100).unwrap();
    assert!(matches!(
        s.group.admit(&live, Some(voucher.clone())),
        Err(AdmissionError::Roster(Error::AcceptanceRequired))
    ));
    s.group
        .apply_admission_consent(&mut live, &consent)
        .unwrap();
    s.group
        .apply_admission_consent(&mut live, &consent)
        .unwrap();
    s.group.admit(&live, Some(voucher)).unwrap();
    assert!(s.group.membership(bob).is_some());
    assert_eq!(
        s.group.apply_admission_consent(&mut live, &consent),
        Err(AdmissionError::Roster(Error::StaleProposal))
    );
}

#[test]
fn signed_admission_decisions_apply_to_only_one_invitation() {
    use mesh_identity::groups::evidence::SignedAdmissionVote;

    let mut s = Scenario::new(151, Policy::Majority);
    let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    let mut invitation = s.group.invite(carol, bob).unwrap();
    let mut duplicate_invitation = s.group.invite(carol, bob).unwrap();
    let bytes = SignedAdmissionVote::new(&invitation, &s.alice, Vote::Approve)
        .unwrap()
        .to_bytes();
    assert!(SignedAdmissionVote::from_bytes(&bytes[..96]).is_err());
    assert!(SignedAdmissionVote::from_bytes(&[0; 98]).is_err());
    let mut unknown = bytes;
    unknown[32] = 0;
    assert!(SignedAdmissionVote::from_bytes(&unknown).is_err());
    for (offset, mask) in [(0, 1), (32, 3), (33, 1)] {
        let mut altered = bytes;
        altered[offset] ^= mask;
        let altered = SignedAdmissionVote::from_bytes(&altered).unwrap();
        assert_eq!(
            s.group.apply_admission_vote(&mut invitation, &altered),
            Err(AdmissionError::Roster(Error::Ineligible))
        );
    }
    let approval = SignedAdmissionVote::from_bytes(&bytes).unwrap();
    assert_eq!(approval.to_bytes(), bytes);
    let objection = SignedAdmissionVote::new(&invitation, &s.dave, Vote::Object).unwrap();
    let abstention = SignedAdmissionVote::new(&invitation, &s.eve, Vote::Abstain).unwrap();
    let outsider = SignedAdmissionVote::new(&invitation, &s.bob, Vote::Approve).unwrap();
    assert_eq!(
        s.group
            .apply_admission_vote(&mut duplicate_invitation, &approval),
        Err(AdmissionError::Roster(Error::Ineligible))
    );
    assert_eq!(s.group.approval_counts(&duplicate_invitation), Ok((1, 3)));
    assert_eq!(
        s.group.apply_admission_vote(&mut invitation, &outsider),
        Err(AdmissionError::Roster(Error::Ineligible))
    );
    for decision in [&approval, &objection, &abstention] {
        let decision = SignedAdmissionVote::from_bytes(&decision.to_bytes()).unwrap();
        s.group
            .apply_admission_vote(&mut invitation, &decision)
            .unwrap();
    }
    let progress = s.group.invitation_progress(&invitation, alice).unwrap();
    assert_eq!(
        (
            progress.approvals,
            progress.objections,
            progress.abstentions
        ),
        (2, 1, 1)
    );
    assert_eq!(
        s.group.apply_admission_vote(&mut invitation, &approval),
        Err(AdmissionError::Roster(Error::AlreadyVoted))
    );

    s.group.mark_suspect(s.eve.selected()).unwrap();
    assert_eq!(
        s.group.apply_admission_vote(&mut invitation, &approval),
        Err(AdmissionError::Roster(Error::StaleProposal))
    );
}

#[test]
fn invitation_progress_keeps_vote_status_separate_from_evidence_disclosure() {
    let mut s = Scenario::new(120, Policy::Majority);
    let (alice, carol, dave, eve, bob) = (
        s.alice.selected(),
        s.carol.selected(),
        s.dave.selected(),
        s.eve.selected(),
        s.bob.selected(),
    );
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let mut invitation = s.group.invite(carol, bob).unwrap();
    let voucher = s.group.vouch(&invitation, &s.carol, [alice], 20).unwrap();

    let recipients: Vec<_> = s
        .group
        .disclosure_audience(&s.carol, &invitation, &voucher)
        .unwrap()
        .collect();
    assert_eq!(recipients, [alice]);
    assert!(matches!(
        s.group.disclosure_audience(&s.dave, &invitation, &voucher),
        Err(AdmissionError::Roster(Error::Ineligible))
    ));

    invitation.accept(bob).unwrap();
    s.group.vote(&mut invitation, dave, Vote::Abstain).unwrap();
    s.group.vote(&mut invitation, eve, Vote::Approve).unwrap();
    let candidate = s.group.invitation_progress(&invitation, bob).unwrap();
    assert!(candidate.candidate_accepted);
    assert_eq!((candidate.approvals, candidate.required), (2, 3));
    assert_eq!((candidate.abstentions, candidate.unanswered), (1, 1));
    assert_eq!(candidate.viewer_vote, None);
    assert_eq!(
        s.group
            .invitation_progress(&invitation, dave)
            .unwrap()
            .viewer_vote,
        Some(Vote::Abstain)
    );
    assert_eq!(
        s.group
            .invitation_progress(&invitation, alice)
            .unwrap()
            .viewer_vote,
        None
    );

    s.group.vote(&mut invitation, alice, Vote::Approve).unwrap();
    let update = s.group.admit(&invitation, Some(voucher)).unwrap();
    assert!(update.deliver_to(alice).unwrap().1.is_some());
    assert!(update.deliver_to(dave).unwrap().1.is_none());
    assert!(update.deliver_to(eve).unwrap().1.is_none());
}

#[test]
fn shared_handle_keeps_invitation_claims_bound_to_their_keys() {
    let mut s = Scenario::new(141, Policy::Majority);
    let (alice, carol, dave, eve, bob) = (
        s.alice.selected(),
        s.carol.selected(),
        s.dave.selected(),
        s.eve.selected(),
        s.bob.selected(),
    );
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let other_bob = s
        .bob
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    s.bob.select(other_bob, 2).unwrap();
    meet(&mut s.dave, &mut s.bob, 2, &mut s.rng);

    let mut first = s.group.invite(carol, bob).unwrap();
    let mut second = s.group.invite(dave, other_bob).unwrap();
    let first_voucher = s.group.vouch(&first, &s.carol, [alice], 100).unwrap();
    let second_voucher = s.group.vouch(&second, &s.dave, [alice], 100).unwrap();

    // The application owns display handles and keys each row by the candidate.
    let rows =
        [&first, &second].map(|invitation| ("Bob", invitation.candidate(), invitation.inviter()));
    assert_eq!(rows, [("Bob", bob, carol), ("Bob", other_bob, dave)]);

    assert_eq!(first.accept(other_bob), Err(Error::Ineligible));
    assert_eq!(second.accept(bob), Err(Error::Ineligible));
    first.accept(bob).unwrap();
    second.accept(other_bob).unwrap();
    s.group.vote(&mut second, eve, Vote::Approve).unwrap();
    assert_eq!(s.group.approval_counts(&first), Ok((1, 3)));
    assert_eq!(s.group.approval_counts(&second), Ok((2, 3)));

    for voter in [alice, eve] {
        s.group.vote(&mut first, voter, Vote::Approve).unwrap();
    }
    assert!(matches!(
        s.group.admit(&first, Some(second_voucher)),
        Err(AdmissionError::VoucherRequired)
    ));
    let update = s.group.admit(&first, Some(first_voucher)).unwrap();
    let (view, evidence) = update.deliver_to(alice).unwrap();
    let evidence = evidence.unwrap();
    assert_eq!((evidence.candidate(), evidence.issuer()), (bob, carol));
    assert!(view.membership(bob).is_some());
    assert!(view.membership(other_bob).is_none());
}

#[test]
fn candidate_replacement_requires_fresh_consent_votes_and_exact_key_evidence() {
    let mut s = Scenario::new(121, Policy::Majority);
    let (alice, carol, old, dave, eve) = (
        s.alice.selected(),
        s.carol.selected(),
        s.bob.selected(),
        s.dave.selected(),
        s.eve.selected(),
    );
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let mut original = s.group.invite(carol, old).unwrap();
    let old_voucher = s.group.vouch(&original, &s.carol, [alice], 100).unwrap();
    original.accept(old).unwrap();
    for voter in [dave, eve] {
        s.group.vote(&mut original, voter, Vote::Approve).unwrap();
    }

    // An authenticated decision closes the old invitation before replacement.
    original.decline(old).unwrap();
    let replacement = s
        .bob
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    s.bob.select(replacement, 2).unwrap();
    let mut renewed = s.group.invite(carol, replacement).unwrap();
    assert_eq!(renewed.accept(old), Err(Error::Ineligible));
    assert_eq!(s.group.approval_counts(&renewed), Ok((1, 3)));
    assert!(matches!(
        s.group.vouch(&renewed, &s.carol, [alice], 100),
        Err(AdmissionError::VoucherRequired)
    ));
    assert!(matches!(
        s.group.admit(&original, Some(old_voucher)),
        Err(AdmissionError::InvitationDeclined)
    ));

    meet(&mut s.carol, &mut s.bob, 2, &mut s.rng);
    let voucher = s.group.vouch(&renewed, &s.carol, [alice], 100).unwrap();
    renewed.accept(replacement).unwrap();
    assert!(matches!(
        s.group.admit(&renewed, Some(voucher.clone())),
        Err(AdmissionError::Roster(Error::ApprovalRequired))
    ));
    for voter in [dave, eve] {
        s.group.vote(&mut renewed, voter, Vote::Approve).unwrap();
    }
    s.group.admit(&renewed, Some(voucher)).unwrap();
    assert!(s.group.membership(old).is_none());
    assert!(s.group.membership(replacement).is_some());
}

#[test]
fn inviter_can_cancel_after_candidate_loses_old_key() {
    let mut s = Scenario::new(122, Policy::InviterOnly);
    let (alice, carol, old) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let mut pending = s.group.invite(carol, old).unwrap();
    pending.accept(old).unwrap();
    let old_voucher = s.group.vouch(&pending, &s.carol, [alice], 100).unwrap();

    let replacement = s
        .bob
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    s.bob.select(replacement, 2).unwrap();
    s.bob.remove_identity(old).unwrap();
    assert_eq!(pending.decline(replacement), Err(Error::Ineligible));
    assert_eq!(
        s.group.cancel_invitation(&mut pending, alice),
        Err(AdmissionError::Roster(Error::Ineligible))
    );
    s.group.cancel_invitation(&mut pending, carol).unwrap();
    assert!(matches!(
        s.group.admit(&pending, Some(old_voucher)),
        Err(AdmissionError::InvitationCancelled)
    ));

    meet(&mut s.carol, &mut s.bob, 2, &mut s.rng);
    let mut fresh = s.group.invite(carol, replacement).unwrap();
    fresh.accept(replacement).unwrap();
    let voucher = s.group.vouch(&fresh, &s.carol, [alice], 100).unwrap();
    s.group.admit(&fresh, Some(voucher)).unwrap();
    assert!(s.group.membership(old).is_none());
    assert!(s.group.membership(replacement).is_some());
}

#[test]
fn imported_public_key_does_not_qualify_for_a_direct_voucher() {
    let mut s = Scenario::new(123, Policy::InviterOnly);
    let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    s.carol.import_peer_key(carol, bob, &mut s.rng).unwrap();
    let mut pending = s.group.invite(carol, bob).unwrap();
    pending.accept(bob).unwrap();
    assert!(matches!(
        s.group.vouch(&pending, &s.carol, [alice], 100),
        Err(AdmissionError::VoucherRequired)
    ));

    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let voucher = s.group.vouch(&pending, &s.carol, [alice], 100).unwrap();
    s.group.admit(&pending, Some(voucher)).unwrap();
    assert!(s.group.membership(bob).is_some());
}

#[test]
fn lost_member_key_requires_two_enrolled_witnesses_and_preserves_tenure() {
    use mesh_identity::groups::evidence::CatchUp;

    let mut s = Scenario::new(124, Policy::InviterOnly);
    let (old, alice, dave) = (s.carol.selected(), s.alice.selected(), s.dave.selected());
    let replacement = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    let tenure = s.group.membership(old).unwrap();
    meet(&mut s.eve, &mut s.carol, 1, &mut s.rng);
    assert!(matches!(
        s.group.request_recovery(old, replacement),
        Err(Error::Ineligible)
    ));
    assert_eq!(
        s.group.enroll_recovery(old, [alice, alice]),
        Err(Error::Ineligible)
    );
    s.group.enroll_recovery(old, [alice, dave]).unwrap();
    s.carol.select(replacement, 2).unwrap();
    s.carol.remove_identity(old).unwrap();
    let mut request = s.group.request_recovery(old, replacement).unwrap();
    let competing_key = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    let competing = s.group.request_recovery(old, competing_key).unwrap();

    assert_eq!(
        s.group.approve_recovery(&mut request, &s.alice),
        Err(Error::Ineligible)
    );
    meet(&mut s.alice, &mut s.carol, 2, &mut s.rng);
    meet(&mut s.eve, &mut s.carol, 3, &mut s.rng);
    assert_eq!(
        s.group.approve_recovery(&mut request, &s.eve),
        Err(Error::Ineligible)
    );
    assert_eq!(s.group.approve_recovery(&mut request, &s.alice), Ok(true));
    assert_eq!(s.group.approve_recovery(&mut request, &s.alice), Ok(false));
    assert_eq!(
        s.group.recover_lost_key(&request),
        Err(Error::ApprovalRequired)
    );
    meet(&mut s.dave, &mut s.carol, 4, &mut s.rng);
    assert_eq!(s.group.approve_recovery(&mut request, &s.dave), Ok(true));
    // Both witnesses agree, but the replacement key has not consented yet.
    assert_eq!(
        s.group.recover_lost_key(&request),
        Err(Error::AcceptanceRequired)
    );
    // Consent is bound to this request: another identity cannot sign it, and a signature for
    // a different replacement does not verify.
    assert!(matches!(
        s.group.recovery_consent(&request, &s.alice),
        Err(Error::Ineligible)
    ));
    let consent = s.group.recovery_consent(&request, &s.carol).unwrap();
    let mut other = s.group.request_recovery(old, competing_key).unwrap();
    assert_eq!(
        s.group.apply_recovery_consent(&mut other, &consent),
        Err(Error::Ineligible)
    );
    s.group
        .apply_recovery_consent(&mut request, &consent)
        .unwrap();
    // The old key is not marked suspect: the holder's veto window must pass first, and a veto
    // from the holder would stop it outright.
    assert_eq!(
        s.group.recover_lost_key(&request),
        Err(Error::ApprovalRequired)
    );
    s.group
        .advance_time(mesh_identity::groups::evidence::RECOVERY_VETO_WINDOW_MS);
    s.group.recover_lost_key(&request).unwrap();

    assert_eq!(
        s.group.recover_lost_key(&competing),
        Err(Error::StaleProposal)
    );
    assert!(s.group.membership(old).is_none());
    assert_eq!(s.group.membership(replacement), Some(tenure));
    assert_eq!(s.alice_offline.catch_up(&s.group), CatchUp::Applied);
    assert_eq!(s.alice_offline.membership(replacement), Some(tenure));
    assert_eq!(
        s.group
            .verification(&s.eve, competing_key, None, IntroducerReliance::Rely),
        Verification::NoEvidence
    );
}

#[test]
fn duplicate_voucher_delivery_does_not_promote_a_chain_to_direct_evidence() {
    use mesh_identity::groups::evidence::VouchedGroup;

    let mut s = Scenario::new(125, Policy::InviterOnly);
    let (alice, carol, bob, dave) = (
        s.alice.selected(),
        s.carol.selected(),
        s.bob.selected(),
        s.dave.selected(),
    );
    meet(&mut s.alice, &mut s.carol, 1, &mut s.rng);
    meet(&mut s.carol, &mut s.bob, 2, &mut s.rng);
    let mut invitation = s.group.invite(carol, bob).unwrap();
    invitation.accept(bob).unwrap();
    let voucher = s.group.vouch(&invitation, &s.carol, [alice], 100).unwrap();
    let update = s.group.admit(&invitation, Some(voucher)).unwrap();

    // Alice hears the same statement twice. It remains attributed to Carol.
    for _ in 0..2 {
        let (view, evidence) = update.deliver_to(alice).unwrap();
        assert_eq!(
            view.verification(&s.alice, bob, evidence.as_ref(), IntroducerReliance::Rely),
            Verification::VouchedForByVerifiedIssuer(carol)
        );
        assert!(s.alice.contacts(alice).unwrap().get(&bob).is_none());
    }

    // Dave knows Alice. That relationship gives Alice no direct evidence of Bob.
    meet(&mut s.dave, &mut s.alice, 3, &mut s.rng);
    let mut second_group = VouchedGroup::new(2, [alice, dave], Policy::InviterOnly);
    let referral = second_group.invite(alice, bob).unwrap();
    assert!(matches!(
        second_group.vouch(&referral, &s.alice, [dave], 100),
        Err(AdmissionError::VoucherRequired)
    ));
    let (_, evidence) = update.deliver_to(alice).unwrap();
    assert_eq!(
        second_group.verification(&s.dave, bob, evidence.as_ref(), IntroducerReliance::Rely),
        Verification::NoEvidence
    );
}

#[test]
fn forwarded_voucher_preserves_attribution_and_tracks_withdrawal() {
    use mesh_identity::groups::evidence::{ReportedReliance, ReportedVoucher};

    let mut s = Scenario::new(126, Policy::InviterOnly);
    let (alice, carol, bob, dave) = (
        s.alice.selected(),
        s.carol.selected(),
        s.bob.selected(),
        s.dave.selected(),
    );
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let mut proposal = s.group.invite(carol, bob).unwrap();
    let voucher = s.group.vouch(&proposal, &s.carol, [alice], 100).unwrap();
    assert!(matches!(
        voucher.clone().allow_forwarding(&s.alice),
        Err(Error::Ineligible)
    ));
    let restricted = voucher.clone();
    let voucher = voucher.allow_forwarding(&s.carol).unwrap();
    proposal.accept(bob).unwrap();
    let update = s.group.admit(&proposal, Some(voucher.clone())).unwrap();
    let (_, evidence) = update.deliver_to(alice).unwrap();
    let evidence = evidence.unwrap();
    assert!(update.deliver_to(dave).unwrap().1.is_none());

    assert!(matches!(
        s.group.forward_voucher(&s.alice, dave, &restricted),
        Err(AdmissionError::Roster(Error::Ineligible))
    ));
    let report = s.group.forward_voucher(&s.alice, dave, &evidence).unwrap();
    assert_eq!(
        s.group.read_forwarded_voucher(&s.dave, &report),
        Ok(ReportedVoucher {
            sender: alice,
            forwarders: vec![alice],
            original_issuer: carol,
            candidate: bob
        })
    );
    assert_eq!(
        s.group.read_forwarded_voucher(&s.eve, &report),
        Err(AdmissionError::Roster(Error::Ineligible))
    );
    assert!(matches!(
        s.group.forward_voucher(&s.dave, alice, &evidence),
        Err(AdmissionError::Roster(Error::Ineligible))
    ));
    assert_eq!(
        s.group
            .verification(&s.dave, bob, Some(&evidence), IntroducerReliance::Rely),
        Verification::NoEvidence
    );
    let eve = s.eve.selected();
    assert!(matches!(
        s.group.relay_voucher(&s.eve, dave, &report),
        Err(AdmissionError::Roster(Error::Ineligible))
    ));
    assert!(matches!(
        s.group.relay_voucher(&s.dave, alice, &report),
        Err(AdmissionError::Roster(Error::Ineligible))
    ));
    let relay = s.group.relay_voucher(&s.dave, eve, &report).unwrap();
    assert_eq!(
        s.group.read_forwarded_voucher(&s.eve, &relay),
        Ok(ReportedVoucher {
            sender: dave,
            forwarders: vec![alice, dave],
            original_issuer: carol,
            candidate: bob,
        })
    );
    let reported = s.group.read_forwarded_voucher(&s.eve, &relay).unwrap();
    assert_eq!(format!("{reported:?}"), "ReportedVoucher { .. }");
    assert_eq!(
        s.group.read_forwarded_voucher(&s.dave, &relay),
        Err(AdmissionError::Roster(Error::Ineligible))
    );
    assert_eq!(
        s.group
            .verification(&s.eve, bob, Some(&evidence), IntroducerReliance::Rely),
        Verification::NoEvidence
    );
    // Knowing the issuer does not establish the immediate sender's identity.
    meet(&mut s.eve, &mut s.carol, 2, &mut s.rng);
    let unverified = s
        .group
        .assess_forwarded_voucher(&s.eve, &relay, IntroducerReliance::Rely)
        .unwrap();
    assert_eq!(unverified.reliance, ReportedReliance::SenderUnverified);
    meet(&mut s.eve, &mut s.dave, 3, &mut s.rng);
    for (choice, expected) in [
        (IntroducerReliance::Rely, ReportedReliance::Accepted),
        (IntroducerReliance::Decline, ReportedReliance::Declined),
    ] {
        let assessed = s
            .group
            .assess_forwarded_voucher(&s.eve, &relay, choice)
            .unwrap();
        assert_eq!(assessed.reliance, expected);
        assert_eq!(assessed.report, unverified.report);
    }
    assert_eq!(
        s.group
            .assess_forwarded_voucher(&s.dave, &relay, IntroducerReliance::Rely),
        Err(AdmissionError::Roster(Error::Ineligible))
    );
    use mesh_identity::groups::evidence::VoucherWithdrawal;

    let mut offline = s.group.clone();
    let delivery = voucher.prepare_withdrawal_delivery(&s.carol).unwrap();
    assert!(delivery.deliver_to(eve).is_none());
    let bytes = delivery.deliver_to(alice).unwrap();
    let decode = || VoucherWithdrawal::from_bytes(&bytes).unwrap();
    assert!(matches!(
        s.group.relay_withdrawal(&s.eve, &report, decode()),
        Err(Error::Ineligible)
    ));
    let first_hop = s
        .group
        .relay_withdrawal(&s.alice, &report, decode())
        .unwrap();
    assert!(first_hop.deliver_to(eve).is_none());
    let received = VoucherWithdrawal::from_bytes(&first_hop.deliver_to(dave).unwrap()).unwrap();
    s.group.apply_withdrawal(&received).unwrap();
    let second_hop = s.group.relay_withdrawal(&s.dave, &relay, received).unwrap();
    assert!(second_hop.deliver_to(alice).is_none());
    assert!(second_hop.deliver_to(bob).is_none());
    assert!(offline.read_forwarded_voucher(&s.eve, &relay).is_ok());
    let final_bytes = second_hop.deliver_to(eve).unwrap();
    assert_eq!(final_bytes, bytes);
    offline
        .apply_withdrawal(&VoucherWithdrawal::from_bytes(&final_bytes).unwrap())
        .unwrap();
    assert_eq!(
        offline.read_forwarded_voucher(&s.eve, &relay),
        Err(AdmissionError::VoucherWithdrawn)
    );
    s.group.withdraw(carol, &voucher).unwrap();
    assert_eq!(
        s.group.read_forwarded_voucher(&s.dave, &report),
        Err(AdmissionError::VoucherWithdrawn)
    );

    assert_eq!(
        s.group.read_forwarded_voucher(&s.eve, &relay),
        Err(AdmissionError::VoucherWithdrawn)
    );
    assert_eq!(
        s.group
            .assess_forwarded_voucher(&s.eve, &relay, IntroducerReliance::Rely),
        Err(AdmissionError::VoucherWithdrawn)
    );
    assert!(matches!(
        s.group.relay_voucher(&s.dave, eve, &report),
        Err(AdmissionError::VoucherWithdrawn)
    ));
}

#[test]
fn voucher_is_audience_only_by_default() {
    let mut s = Scenario::new(127, Policy::InviterOnly);
    let (alice, carol, bob, dave) = (
        s.alice.selected(),
        s.carol.selected(),
        s.bob.selected(),
        s.dave.selected(),
    );
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let mut proposal = s.group.invite(carol, bob).unwrap();
    proposal.accept(bob).unwrap();
    let voucher = s.group.vouch(&proposal, &s.carol, [alice], 100).unwrap();
    let update = s.group.admit(&proposal, Some(voucher)).unwrap();
    let (_, delivered) = update.deliver_to(alice).unwrap();
    assert!(matches!(
        s.group.forward_voucher(&s.alice, dave, &delivered.unwrap()),
        Err(AdmissionError::Roster(Error::Ineligible))
    ));
}

#[test]
fn blocked_member_stays_on_roster_but_cannot_trigger_local_presentation() {
    use mesh_identity::groups::MemberLocalState;

    let mut s = Scenario::new(128, Policy::InviterOnly);
    let alice = s.alice.selected();
    let dave = s.dave.selected();
    let carol = s.carol.selected();
    let bob = s.bob.selected();
    meet(&mut s.alice, &mut s.bob, 1, &mut s.rng);
    meet(&mut s.carol, &mut s.bob, 2, &mut s.rng);
    let mut invitation = s.group.invite(carol, bob).unwrap();
    invitation.accept(bob).unwrap();
    let voucher = s.group.vouch(&invitation, &s.carol, [alice], 100).unwrap();
    s.group.admit(&invitation, Some(voucher)).unwrap();

    let alice_tenure = s.group.membership(alice).unwrap();
    let dave_tenure = s.group.membership(dave).unwrap();
    let bob_tenure = s.group.membership(bob).unwrap();
    let revision = s.group.revision();
    let mut alice_local = MemberLocalState::default();
    alice_local.add_identity(alice_tenure.identity(), "Alice".into());
    let mut dave_local = MemberLocalState::default();
    dave_local.add_identity(dave_tenure.identity(), "Dave".into());

    let mut inbox = support::Inbox::default();
    inbox.deliver(&s.group, &alice_local, &s.alice, alice_tenure, bob);
    s.alice.block_contact(alice, bob).unwrap();
    inbox.deliver(&s.group, &alice_local, &s.alice, alice_tenure, bob);
    assert_eq!(inbox, support::Inbox::one_message());

    let mut other_inbox = support::Inbox::default();
    other_inbox.deliver(&s.group, &dave_local, &s.dave, dave_tenure, bob);
    assert_eq!(other_inbox, support::Inbox::one_message());
    assert_eq!(s.group.revision(), revision);
    assert_eq!(s.group.membership(bob), Some(bob_tenure));
}

#[test]
fn signed_departure_survives_roster_updates_and_cannot_end_a_new_tenure() {
    use mesh_identity::groups::evidence::{CatchUp, SignedDeparture, VouchedGroup};

    let mut s = Scenario::new(149, Policy::InviterOnly);
    let (alice, dave, eve) = (s.alice.selected(), s.dave.selected(), s.eve.selected());
    let context = s.group.departure_context(alice).unwrap();
    let bytes = SignedDeparture::new(context, &s.alice).unwrap().to_bytes();
    assert!(SignedDeparture::from_bytes(&bytes[..135]).is_err());
    let mut oversized = bytes.to_vec();
    oversized.push(0);
    assert!(SignedDeparture::from_bytes(&oversized).is_err());
    let departure = SignedDeparture::from_bytes(&bytes).unwrap();
    assert_eq!(departure.to_bytes(), bytes);
    let original = s.group.membership(alice);
    let mut other = VouchedGroup::new(2, [alice, dave], Policy::InviterOnly);
    assert_eq!(other.apply_departure_message(&departure), Ok(false));
    let wrong = s.dave.sign_group_departure(context.0, context.1).unwrap();
    assert_eq!(
        s.group.apply_signed_departure(alice, context, wrong),
        Err(Error::Ineligible)
    );
    assert_eq!(s.group.membership(alice), original);

    for offset in [0, 8, 40, 72] {
        let mut modified = bytes;
        modified[offset] ^= 1;
        let invalid = SignedDeparture::from_bytes(&modified).unwrap();
        assert_eq!(
            s.group.apply_departure_message(&invalid),
            Err(Error::Ineligible)
        );
        assert_eq!(s.group.membership(alice), original);
    }

    s.group.mark_suspect(eve).unwrap();
    assert_eq!(s.group.departure_context(alice), Some(context));
    assert_eq!(s.group.apply_departure_message(&departure), Ok(true));
    assert_eq!(s.group.apply_departure_message(&departure), Ok(false));
    assert_eq!(s.alice_offline.catch_up(&s.group), CatchUp::Applied);
    assert!(s.alice_offline.membership(alice).is_none());

    meet(&mut s.dave, &mut s.alice, 1, &mut s.rng);
    let mut invite = s.group.invite(dave, alice).unwrap();
    invite.accept(alice).unwrap();
    let voucher = s.group.vouch(&invite, &s.dave, [dave], 100).unwrap();
    s.group.admit(&invite, Some(voucher)).unwrap();
    let new_membership = s.group.membership(alice);
    assert!(new_membership.is_some());
    assert_ne!(new_membership, original);
    assert_ne!(s.group.departure_context(alice), Some(context));
    assert_eq!(s.group.apply_departure_message(&departure), Ok(false));
    assert_eq!(s.group.membership(alice), new_membership);
}

#[test]
fn delayed_delivery_after_leave_has_no_application_side_effects() {
    use mesh_identity::groups::MemberLocalState;

    let mut s = Scenario::new(129, Policy::InviterOnly);
    let alice = s.alice.selected();
    let dave = s.dave.selected();
    let tenure = s.group.membership(alice).unwrap();
    let stale = s.group.clone();
    let mut local = MemberLocalState::default();
    local.add_identity(tenure.identity(), "Alice".into());
    let mut inbox = support::Inbox::default();
    inbox.deliver(&s.group, &local, &s.alice, tenure, dave);
    local.leave(tenure).unwrap();

    inbox.deliver(&stale, &local, &s.alice, tenure, dave);
    assert!(s.group.apply_departure(alice, tenure).unwrap());
    s.group.prune_departures(&mut local);
    inbox.deliver(&s.group, &local, &s.alice, tenure, dave);
    inbox.deliver(&stale, &local, &s.alice, tenure, dave);
    assert_eq!(inbox, support::Inbox::one_message());
}

#[test]
fn encrypted_material_uses_only_current_recipient_channels() {
    use mesh_identity::groups::evidence::{DistributionPlan, VouchedGroup};
    use rand::RngCore;
    use ring::aead::{Aad, CHACHA20_POLY1305, LessSafeKey, Nonce, UnboundKey};
    use std::collections::BTreeMap;

    let mut s = Scenario::new(148, Policy::InviterOnly);
    let leaving = s.alice.selected();
    let retained = s.dave.selected();
    let original = s.carol.selected();
    let replacement = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    let quarantined = s.eve.selected();
    let channels: BTreeMap<_, _> = s
        .group
        .distribution_recipients(&s.group.plan_distribution())
        .unwrap()
        .into_iter()
        .chain([replacement])
        .map(|recipient| {
            let mut key = [0; 32];
            s.rng.fill_bytes(&mut key);
            (
                recipient,
                LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key).unwrap()),
            )
        })
        .collect();

    // Pre-provisioned per-recipient channels model delivery by an up-to-date sender.
    let mut sequence = 0u64;
    let mut distribute = |group: &VouchedGroup, plan: &DistributionPlan, message: &[u8]| {
        let recipients = group.distribution_recipients(plan)?;
        let (id, parent) = group.rotation_context();
        let aad = [id.to_be_bytes().as_slice(), &parent].concat();
        let mut nonce = [0; 12];
        nonce[4..].copy_from_slice(&sequence.to_be_bytes());
        sequence += 1;
        let ciphertexts: BTreeMap<_, _> = recipients
            .into_iter()
            .map(|recipient| {
                let mut ciphertext = message.to_vec();
                channels[&recipient]
                    .seal_in_place_append_tag(
                        Nonce::assume_unique_for_key(nonce),
                        Aad::from(&aad),
                        &mut ciphertext,
                    )
                    .unwrap();
                (recipient, ciphertext)
            })
            .collect();
        Ok((nonce, aad, ciphertexts))
    };

    let (nonce, aad, historical) =
        distribute(&s.group, &s.group.plan_distribution(), b"previous material").unwrap();
    assert_eq!(
        channels[&leaving]
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad),
                &mut historical[&leaving].clone()
            )
            .unwrap(),
        b"previous material"
    );
    let original_tenure = s.group.membership(leaving).unwrap();
    let queued = s.group.plan_distribution();
    let mut fork = s.group.clone();
    fork.mark_suspect(quarantined).unwrap();
    assert!(s.group.apply_departure(leaving, original_tenure).unwrap());
    let current_plan = s.group.plan_distribution();
    assert_eq!(s.group.revision(), fork.revision());
    assert!(matches!(
        distribute(&s.group, &queued, b"new material"),
        Err(Error::StaleProposal)
    ));
    assert!(matches!(
        distribute(&fork, &current_plan, b"new material"),
        Err(Error::StaleProposal)
    ));
    let (nonce, aad, current) = distribute(&s.group, &current_plan, b"new material").unwrap();
    let (fork_id, fork_parent) = fork.rotation_context();
    let fork_aad = [fork_id.to_be_bytes().as_slice(), &fork_parent].concat();
    assert!(
        channels[&retained]
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&fork_aad),
                &mut current[&retained].clone()
            )
            .is_err()
    );
    assert!(!current.contains_key(&leaving));
    assert!(current.values().all(|ciphertext| {
        channels[&leaving]
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad),
                &mut ciphertext.clone(),
            )
            .is_err()
    }));
    assert_eq!(
        channels[&retained]
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad),
                &mut current[&retained].clone()
            )
            .unwrap(),
        b"new material"
    );

    s.group
        .rotate_key(s.group.revision(), original, replacement)
        .unwrap();
    let (nonce, aad, rotated) =
        distribute(&s.group, &s.group.plan_distribution(), b"after rotation").unwrap();
    assert!(!rotated.contains_key(&original));
    assert!(rotated.contains_key(&quarantined));
    assert_eq!(
        channels[&replacement]
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad),
                &mut rotated[&replacement].clone()
            )
            .unwrap(),
        b"after rotation"
    );

    let tenure = s.group.membership(quarantined).unwrap();
    s.group.mark_suspect(quarantined).unwrap();
    assert_eq!(s.group.membership(quarantined), Some(tenure));
    let (nonce, aad, current) =
        distribute(&s.group, &s.group.plan_distribution(), b"after quarantine").unwrap();
    for excluded in [leaving, original, quarantined] {
        assert!(!current.contains_key(&excluded));
        assert!(current.values().all(|ciphertext| {
            channels[&excluded]
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&aad),
                    &mut ciphertext.clone(),
                )
                .is_err()
        }));
    }
    for allowed in [retained, replacement] {
        assert_eq!(
            channels[&allowed]
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&aad),
                    &mut current[&allowed].clone()
                )
                .unwrap(),
            b"after quarantine"
        );
    }

    let absence_plan = s.group.plan_distribution();
    meet(&mut s.dave, &mut s.alice, 1, &mut s.rng);
    let mut rejoin = s.group.invite(retained, leaving).unwrap();
    rejoin.accept(leaving).unwrap();
    let voucher = s.group.vouch(&rejoin, &s.dave, [replacement], 100).unwrap();
    s.group.admit(&rejoin, Some(voucher)).unwrap();
    let new_tenure = s.group.membership(leaving).unwrap();
    assert_ne!(new_tenure, original_tenure);
    assert!(!s.group.apply_departure(leaving, original_tenure).unwrap());
    assert_eq!(s.group.membership(leaving), Some(new_tenure));
    assert!(matches!(
        distribute(&s.group, &absence_plan, b"after readmission"),
        Err(Error::StaleProposal)
    ));

    let (new_nonce, new_aad, rejoined) =
        distribute(&s.group, &s.group.plan_distribution(), b"after readmission").unwrap();
    assert_eq!(
        channels[&leaving]
            .open_in_place(
                Nonce::assume_unique_for_key(new_nonce),
                Aad::from(&new_aad),
                &mut rejoined[&leaving].clone(),
            )
            .unwrap(),
        b"after readmission"
    );
    // Even after readmission, the returning member cannot open the batch
    // addressed to other recipients while they were absent.
    assert!(!current.contains_key(&leaving));
    assert!(
        channels[&leaving]
            .open_in_place(
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&aad),
                &mut current[&retained].clone(),
            )
            .is_err()
    );
}

#[test]
fn new_group_material_follows_the_current_agreed_roster() {
    let mut s = Scenario::new(130, Policy::InviterOnly);
    let (alice, carol, dave) = (s.alice.selected(), s.carol.selected(), s.dave.selected());
    let tenure = s.group.membership(alice).unwrap();
    let queued = s.group.plan_distribution();
    let stale = s.group.clone();
    assert!(
        s.group
            .distribution_recipients(&queued)
            .unwrap()
            .contains(&alice)
    );

    assert!(s.group.apply_departure(alice, tenure).unwrap());
    assert_eq!(
        s.group.distribution_recipients(&queued),
        Err(Error::StaleProposal)
    );
    let after_departure = s.group.plan_distribution();
    let eligible = s.group.distribution_recipients(&after_departure).unwrap();
    assert!(eligible.contains(&carol));
    assert!(!eligible.contains(&alice));
    assert_eq!(
        stale.distribution_recipients(&after_departure),
        Err(Error::StaleProposal)
    );

    // A different branch with the same revision cannot authorize this plan.
    let mut fork = stale;
    fork.mark_suspect(dave).unwrap();
    assert_eq!(fork.revision(), s.group.revision());
    assert_eq!(
        fork.distribution_recipients(&after_departure),
        Err(Error::StaleProposal)
    );

    let new_dave = s
        .dave
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    s.group
        .rotate_key(s.group.revision(), dave, new_dave)
        .unwrap();
    let eligible = s
        .group
        .distribution_recipients(&s.group.plan_distribution())
        .unwrap();
    assert!(!eligible.contains(&dave));
    assert!(eligible.contains(&new_dave));

    s.group.mark_suspect(new_dave).unwrap();
    let eligible = s
        .group
        .distribution_recipients(&s.group.plan_distribution())
        .unwrap();
    assert!(!eligible.contains(&new_dave));
    assert!(s.group.membership(new_dave).is_some());
}

#[test]
fn simultaneous_group_memberships_keep_admission_evidence_and_departure_separate() {
    use mesh_identity::groups::{MemberLocalState, evidence::VouchedGroup};

    let mut s = Scenario::new(131, Policy::InviterOnly);
    let (alice, carol, bob, dave) = (
        s.alice.selected(),
        s.carol.selected(),
        s.bob.selected(),
        s.dave.selected(),
    );
    let mut second = VouchedGroup::new(2, [alice, carol, dave], Policy::Unanimous);
    let mut local = MemberLocalState::default();
    let first_tenure = s.group.membership(alice).unwrap();
    let second_tenure = second.membership(alice).unwrap();
    local.add_identity(first_tenure.identity(), "Alice".into());
    local.add_identity(second_tenure.identity(), "Alice".into());

    meet(&mut s.alice, &mut s.carol, 1, &mut s.rng);
    meet(&mut s.carol, &mut s.bob, 2, &mut s.rng);
    let mut first_proposal = s.group.invite(carol, bob).unwrap();
    first_proposal.accept(bob).unwrap();
    let first_voucher = s
        .group
        .vouch(&first_proposal, &s.carol, [alice], 100)
        .unwrap();
    let mut second_proposal = second.invite(carol, bob).unwrap();
    second_proposal.accept(bob).unwrap();
    assert_eq!(
        second.vote(&mut first_proposal, alice, Vote::Approve),
        Err(AdmissionError::Roster(Error::StaleProposal))
    );
    assert!(matches!(
        second.admit(&second_proposal, Some(first_voucher.clone())),
        Err(AdmissionError::VoucherRequired)
    ));
    let first_update = s
        .group
        .admit(&first_proposal, Some(first_voucher.clone()))
        .unwrap();
    let second_voucher = second
        .vouch(&second_proposal, &s.carol, [alice], 100)
        .unwrap();
    assert_eq!(second.approval_counts(&second_proposal), Ok((1, 3)));
    assert!(matches!(
        second.admit(&second_proposal, Some(second_voucher.clone())),
        Err(AdmissionError::Roster(Error::ApprovalRequired))
    ));
    second
        .vote(&mut second_proposal, alice, Vote::Approve)
        .unwrap();
    second
        .vote(&mut second_proposal, dave, Vote::Approve)
        .unwrap();
    let second_update = second
        .admit(&second_proposal, Some(second_voucher))
        .unwrap();
    let (_, first_evidence) = first_update.deliver_to(alice).unwrap();
    let (_, second_evidence) = second_update.deliver_to(alice).unwrap();
    assert_eq!(
        second.verification(
            &s.alice,
            bob,
            first_evidence.as_ref(),
            IntroducerReliance::Rely
        ),
        Verification::NoEvidence
    );
    assert_eq!(
        second.withdraw(carol, &first_voucher),
        Err(Error::Ineligible)
    );
    s.group.withdraw(carol, &first_voucher).unwrap();
    assert_eq!(
        second.verification(
            &s.alice,
            bob,
            second_evidence.as_ref(),
            IntroducerReliance::Rely
        ),
        Verification::VouchedForByVerifiedIssuer(carol)
    );

    let queued_second = second.plan_distribution();
    assert!(
        second
            .distribution_recipients(&queued_second)
            .unwrap()
            .contains(&alice)
    );
    local.leave(first_tenure).unwrap();
    assert!(!s.group.may_present(&local, alice, first_tenure));
    assert!(second.may_present(&local, alice, second_tenure));
    assert!(!second.apply_departure(alice, first_tenure).unwrap());
    assert!(s.group.apply_departure(alice, first_tenure).unwrap());
    s.group.prune_departures(&mut local);
    assert!(second.may_present(&local, alice, second_tenure));
    assert!(
        second
            .distribution_recipients(&queued_second)
            .unwrap()
            .contains(&alice)
    );
}

#[test]
fn authorized_removal_invalidates_queued_access_and_pending_admission() {
    use mesh_identity::groups::evidence::CatchUp;

    let mut s = Scenario::new(132, Policy::InviterOnly);
    let (alice, carol, bob, dave) = (
        s.alice.selected(),
        s.carol.selected(),
        s.bob.selected(),
        s.dave.selected(),
    );
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let mut invitation = s.group.invite(carol, bob).unwrap();
    invitation.accept(bob).unwrap();
    let voucher = s.group.vouch(&invitation, &s.carol, [alice], 100).unwrap();
    let queued = s.group.plan_distribution();
    let old_tenure = s.group.membership(carol).unwrap();

    let mut removal = s.group.propose_removal(alice, carol).unwrap();
    assert_eq!(
        s.group.apply_removal(&removal),
        Err(Error::ApprovalRequired)
    );
    assert_eq!(
        s.group.approve_removal(&mut removal, carol),
        Err(Error::Ineligible)
    );
    assert_eq!(
        s.group.approve_removal(&mut removal, alice),
        Err(Error::AlreadyVoted)
    );
    s.group.approve_removal(&mut removal, dave).unwrap();
    s.group.apply_removal(&removal).unwrap();
    assert_eq!(s.group.apply_removal(&removal), Err(Error::StaleProposal));
    assert!(s.group.membership(carol).is_none());
    assert_eq!(
        s.group.distribution_recipients(&queued),
        Err(Error::StaleProposal)
    );
    let current = s.group.plan_distribution();
    assert!(
        !s.group
            .distribution_recipients(&current)
            .unwrap()
            .contains(&carol)
    );
    assert!(matches!(
        s.group.admit(&invitation, Some(voucher)),
        Err(AdmissionError::Roster(Error::StaleProposal))
    ));

    assert_eq!(s.alice_offline.membership(carol), Some(old_tenure));
    assert_eq!(s.alice_offline.catch_up(&s.group), CatchUp::Applied);
    assert!(s.alice_offline.membership(carol).is_none());

    meet(&mut s.dave, &mut s.carol, 2, &mut s.rng);
    let mut rejoin = s.group.invite(dave, carol).unwrap();
    rejoin.accept(carol).unwrap();
    let evidence = s.group.vouch(&rejoin, &s.dave, [alice], 100).unwrap();
    s.group.admit(&rejoin, Some(evidence)).unwrap();
    assert_ne!(s.group.membership(carol), Some(old_tenure));
    assert_eq!(s.group.apply_removal(&removal), Err(Error::StaleProposal));
    let eligible = s
        .group
        .distribution_recipients(&s.group.plan_distribution())
        .unwrap();
    assert!(eligible.contains(&carol));
}

#[test]
fn policy_ejection_and_voluntary_leave_cannot_end_a_later_tenure() {
    use mesh_identity::groups::evidence::{CatchUp, SignedEjectionVote};

    for leave_first in [true, false] {
        let mut s = Scenario::new(154, Policy::Majority);
        let (alice, carol, dave, eve) = (
            s.alice.selected(),
            s.carol.selected(),
            s.dave.selected(),
            s.eve.selected(),
        );
        let tenure = s.group.membership(carol).unwrap();
        let mut stale = s.group.propose_ejection(alice, carol).unwrap();
        s.group
            .apply_policy_change(s.group.revision(), Policy::Unanimous)
            .unwrap();
        assert_eq!(
            s.group.approve_removal(&mut stale, dave),
            Err(Error::StaleProposal)
        );
        assert_eq!(s.group.apply_removal(&stale), Err(Error::StaleProposal));

        let mut ejection = s.group.propose_signed_ejection(&s.alice, carol).unwrap();
        assert_eq!(
            s.group.apply_removal(&ejection),
            Err(Error::ApprovalRequired)
        );
        let approval = SignedEjectionVote::new(&ejection, &s.dave).unwrap();
        s.group
            .apply_ejection_vote(&mut ejection, &approval)
            .unwrap();
        let plan = s.group.plan_distribution();
        if leave_first {
            assert!(s.group.apply_departure(carol, tenure).unwrap());
            assert_eq!(s.group.apply_removal(&ejection), Err(Error::StaleProposal));
        } else {
            s.group.apply_removal(&ejection).unwrap();
            assert!(!s.group.apply_departure(carol, tenure).unwrap());
        }
        assert_eq!(
            s.group.distribution_recipients(&plan),
            Err(Error::StaleProposal)
        );
        assert_eq!(s.alice_offline.catch_up(&s.group), CatchUp::Applied);
        assert!(s.alice_offline.membership(carol).is_none());

        meet(&mut s.dave, &mut s.carol, 1, &mut s.rng);
        let mut invitation = s.group.invite(dave, carol).unwrap();
        invitation.accept(carol).unwrap();
        for voter in [alice, eve] {
            s.group.vote(&mut invitation, voter, Vote::Approve).unwrap();
        }
        let voucher = s.group.vouch(&invitation, &s.dave, [alice], 100).unwrap();
        s.group.admit(&invitation, Some(voucher)).unwrap();
        let replacement = s.group.membership(carol).unwrap();
        assert_ne!(replacement, tenure);
        assert_eq!(s.group.apply_removal(&ejection), Err(Error::StaleProposal));
        assert!(!s.group.apply_departure(carol, tenure).unwrap());
        assert_eq!(s.group.membership(carol), Some(replacement));
    }
}

#[test]
fn weak_identity_keys_are_rejected_in_evidence_and_installation() {
    use mesh_identity::groups::evidence::{SignedDeparture, VoucherWithdrawal};

    let weak_pk = {
        let mut k = [0u8; 32];
        k[0] = 1;
        k
    };
    let sig = [0u8; 64];

    // SignedDeparture from weak key is rejected
    let mut departure_bytes = [0u8; 136];
    departure_bytes[..8].copy_from_slice(&1u64.to_be_bytes());
    departure_bytes[40..72].copy_from_slice(&weak_pk);
    departure_bytes[72..].copy_from_slice(&sig);
    let departure = SignedDeparture::from_bytes(&departure_bytes).unwrap();
    let mut s = Scenario::new(160, Policy::InviterOnly);
    assert_eq!(
        s.group.apply_departure_message(&departure),
        Err(Error::Ineligible)
    );

    // VoucherWithdrawal from weak key is rejected at parsing
    let mut withdrawal_bytes = [0u8; 136];
    withdrawal_bytes[..8].copy_from_slice(&1u64.to_be_bytes());
    withdrawal_bytes[40..72].copy_from_slice(&weak_pk);
    withdrawal_bytes[72..].copy_from_slice(&sig);
    assert_eq!(
        VoucherWithdrawal::from_bytes(&withdrawal_bytes).err(),
        Some(Error::Ineligible)
    );
}

#[test]
fn suspect_member_does_not_deadlock_ejection_or_removal() {
    use mesh_identity::groups::evidence::SignedEjectionVote;

    let mut s = Scenario::new(161, Policy::Majority);
    let (carol, eve) = (s.carol.selected(), s.eve.selected());

    // Roster has 4 members: alice, carol, dave, eve.
    // Carol's key becomes suspect (quarantined).
    s.group.mark_suspect(carol).unwrap();

    // Alice proposes ejection of Eve.
    // Eligible non-target electorate is Alice and Dave (Carol is suspect).
    let mut proposal = s.group.propose_signed_ejection(&s.alice, eve).unwrap();
    let suspect = SignedEjectionVote::new(&proposal, &s.carol).unwrap();
    assert_eq!(
        s.group.apply_ejection_vote(&mut proposal, &suspect),
        Err(Error::Ineligible)
    );
    let vote = SignedEjectionVote::new(&proposal, &s.dave).unwrap();
    s.group.apply_ejection_vote(&mut proposal, &vote).unwrap();
    s.group.apply_removal(&proposal).unwrap();
    assert!(s.group.membership(eve).is_none());
}

#[test]
fn departed_member_key_cleaned_up_from_identities() {
    let mut s = Scenario::new(162, Policy::InviterOnly);
    let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    let tenure = s.group.membership(carol).unwrap();
    assert!(s.group.apply_departure(carol, tenure).unwrap());
    assert!(s.group.membership(carol).is_none());

    // Candidate Bob can now be invited and admitted cleanly without identity collision
    meet(&mut s.alice, &mut s.bob, 1, &mut s.rng);
    let mut proposal = s.group.invite(alice, bob).unwrap();
    proposal.accept(bob).unwrap();
    let voucher = s.group.vouch(&proposal, &s.alice, [alice], 100).unwrap();
    let update = s.group.admit(&proposal, Some(voucher)).unwrap();
    assert!(
        update
            .deliver_to(alice)
            .unwrap()
            .0
            .membership(bob)
            .is_some()
    );
}

#[test]
fn remote_invitation_preserves_voucher_admission_by_full_binding() {
    use mesh_identity::groups::evidence::SignedInvitation;

    let mut s = Scenario::new(163, Policy::InviterOnly);
    let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);

    let proposal = s.group.invite_until(carol, bob, 200).unwrap();
    let voucher = s.group.vouch(&proposal, &s.carol, [alice], 200).unwrap();
    let signed_invitation = SignedInvitation::new(&proposal, &s.carol).unwrap();

    // Alice reconstructs the invitation from the signed message.
    let mut alice_proposal = s.group.receive_invitation(&signed_invitation).unwrap();
    alice_proposal.accept(bob).unwrap();

    // Alice admits using Carol's voucher and the matching invitation binding.
    let update = s.group.admit(&alice_proposal, Some(voucher)).unwrap();
    assert!(
        update
            .deliver_to(alice)
            .unwrap()
            .0
            .membership(bob)
            .is_some()
    );
}

#[test]
fn first_join_stays_pending_on_an_authentic_old_roster() {
    use mesh_identity::groups::evidence::{
        CatchUp, SignedAdmissionConsent, SignedInvitation, VouchedGroup,
    };

    for group_stays_open in [true, false] {
        let mut s = Scenario::new(165, Policy::InviterOnly);
        let (carol, bob) = (s.carol.selected(), s.bob.selected());
        let members = [carol, s.alice.selected()];
        let mut current = VouchedGroup::new(
            165,
            members
                .into_iter()
                .take(if group_stays_open { 2 } else { 1 }),
            Policy::InviterOnly,
        );
        let invitation = current.invite_until(carol, bob, 200).unwrap();
        meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
        let voucher = current.vouch(&invitation, &s.carol, [], 200).unwrap();
        let signed = SignedInvitation::new(&invitation, &s.carol).unwrap();
        let mut candidate_view = current.clone();

        let tenure = current.membership(carol).unwrap();
        assert!(current.apply_departure(carol, tenure).unwrap());

        // The fixture supplies authentic snapshots. At first contact, the
        // candidate has no newer checkpoint with which to compare this parent.
        let mut pending = candidate_view.receive_invitation(&signed).unwrap();
        let consent = SignedAdmissionConsent::new(&pending, &s.bob).unwrap();
        candidate_view
            .apply_admission_consent(&mut pending, &consent)
            .unwrap();
        assert!(candidate_view.membership(bob).is_none());
        assert!(candidate_view.export_roster(&s.bob).is_err());

        let stale = candidate_view.clone();
        assert_eq!(candidate_view.catch_up(&current), CatchUp::Applied);
        assert!(candidate_view.membership(carol).is_none());
        assert!(candidate_view.membership(bob).is_none());
        assert!(matches!(
            candidate_view.receive_invitation(&signed),
            Err(AdmissionError::Roster(Error::StaleProposal))
        ));
        assert!(matches!(
            candidate_view.apply_admission_consent(&mut pending, &consent),
            Err(AdmissionError::Roster(Error::StaleProposal))
        ));
        assert!(matches!(
            current.admit(&pending, Some(voucher)),
            Err(AdmissionError::Roster(Error::StaleProposal))
        ));
        assert_eq!(candidate_view.catch_up(&stale), CatchUp::OlderSnapshot);
        assert!(candidate_view.export_roster(&s.bob).is_err());
    }
}

#[test]
fn mixed_invitation_versions_preserve_inbox_and_retry_after_upgrade() {
    use mesh_identity::groups::evidence::{
        InvitationFrameVersion::{V1, V2},
        InvitationInbox, SignedAdmissionConsent, SignedInvitation, SignedInvitationCancellation,
    };

    for parent_remains_current in [true, false] {
        let mut s = Scenario::new(166, Policy::InviterOnly);
        let (carol, bob) = (s.carol.selected(), s.bob.selected());
        meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
        let alternate = s
            .bob
            .add_identity(SigningKey::from_bytes(&[83; 32]))
            .unwrap();
        let legacy = s.group.invite_until(carol, alternate, 200).unwrap();
        let newer = s.group.invite_until(carol, bob, 200).unwrap();
        let old_frame = SignedInvitation::encode_frame(&legacy, &s.carol, V1).unwrap();
        let new_frame = SignedInvitation::encode_frame(&newer, &s.carol, V2).unwrap();
        assert_eq!(
            &old_frame[5..],
            &SignedInvitation::new(&legacy, &s.carol).unwrap().to_bytes()
        );
        let revision = s.group.revision();
        let mut inbox = InvitationInbox::default();
        assert!(matches!(
            inbox.receive_frame(&s.group, &new_frame, V1),
            Err(AdmissionError::UnsupportedInvitationVersion(2))
        ));
        assert_eq!(inbox.pending().count(), 0);
        inbox.receive_frame(&s.group, &old_frame, V1).unwrap();
        assert_eq!(inbox.pending().count(), 1);
        assert_eq!(s.group.revision(), revision);

        assert!(matches!(
            inbox.receive_frame(&s.group, &new_frame[..new_frame.len() - 1], V2),
            Err(AdmissionError::MalformedInvitationFrame)
        ));
        let mut altered = new_frame;
        altered[4] = V1 as u8;
        assert!(matches!(
            inbox.receive_frame(&s.group, &altered, V2),
            Err(AdmissionError::Roster(Error::Ineligible))
        ));
        assert_eq!(inbox.pending().count(), 1);

        let original = SignedInvitation::new(&newer, &s.carol).unwrap();
        let same_invitation_v1 = SignedInvitation::encode_frame(&newer, &s.carol, V1).unwrap();
        let cancellation = SignedInvitationCancellation::new(&original, &s.carol).unwrap();
        let mut cancelled_view = s.group.clone();
        assert!(matches!(
            cancelled_view.apply_invitation_frame_cancellation(&new_frame, &cancellation, V1),
            Err(AdmissionError::UnsupportedInvitationVersion(2))
        ));
        assert!(
            cancelled_view
                .apply_invitation_frame_cancellation(&new_frame, &cancellation, V2)
                .unwrap()
        );
        assert!(matches!(
            InvitationInbox::default().receive_frame(&cancelled_view, &new_frame, V2),
            Err(AdmissionError::InvitationCancelled)
        ));
        assert!(matches!(
            InvitationInbox::default().receive_frame(&cancelled_view, &same_invitation_v1, V1),
            Err(AdmissionError::InvitationCancelled)
        ));

        if !parent_remains_current {
            let dave = s.dave.selected();
            let tenure = s.group.membership(dave).unwrap();
            assert!(s.group.apply_departure(dave, tenure).unwrap());
            assert!(matches!(
                inbox.receive_frame(&s.group, &new_frame, V2),
                Err(AdmissionError::Roster(Error::StaleProposal))
            ));
            assert!(s.group.membership(bob).is_none());
            continue;
        }

        let voucher = s.group.vouch(&newer, &s.carol, [], 200).unwrap();
        let consent = SignedAdmissionConsent::new(&newer, &s.bob).unwrap();
        let pending = inbox.receive_frame(&s.group, &new_frame, V2).unwrap();
        assert_eq!(pending.decision_binding(), newer.decision_binding());
        s.group.apply_admission_consent(pending, &consent).unwrap();
        inbox
            .receive_frame(&s.group, &same_invitation_v1, V2)
            .unwrap();
        assert_eq!(inbox.pending().count(), 2);
        let pending = inbox.receive_frame(&s.group, &new_frame, V2).unwrap();
        s.group.admit(pending, Some(voucher)).unwrap();
        assert!(matches!(
            inbox.receive_frame(&s.group, &new_frame, V2),
            Err(AdmissionError::Roster(Error::StaleProposal))
        ));
        assert_eq!(s.group.revision(), revision + 1);
        assert!(s.group.membership(bob).is_some());
    }
}

#[test]
fn rotated_key_can_withdraw_voucher_issued_under_predecessor_key() {
    use mesh_identity::session::installation::Installation;

    let mut s = Scenario::new(164, Policy::InviterOnly);
    let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    meet(&mut s.alice, &mut s.carol, 1, &mut s.rng);
    meet(&mut s.carol, &mut s.bob, 2, &mut s.rng);

    let mut proposal = s.group.invite(carol, bob).unwrap();
    proposal.accept(bob).unwrap();
    let voucher = s.group.vouch(&proposal, &s.carol, [alice], 100).unwrap();
    let update = s.group.admit(&proposal, Some(voucher.clone())).unwrap();
    let (_, alice_voucher) = update.deliver_to(alice).unwrap();

    // Verify Bob is initially vouched for by verified issuer Carol
    assert_eq!(
        s.group.verification(
            &s.alice,
            bob,
            alice_voucher.as_ref(),
            IntroducerReliance::Rely
        ),
        Verification::VouchedForByVerifiedIssuer(carol)
    );

    // Carol rotates her key to a new key
    let carol2_sk = SigningKey::generate(&mut s.rng);
    let carol2_inst = Installation::new(carol2_sk);
    let carol2 = carol2_inst.selected();
    s.group
        .rotate_key(s.group.revision(), carol, carol2)
        .unwrap();

    // Carol withdraws the voucher using her successor key
    let withdrawal = voucher
        .authorize_withdrawal_by(&carol2_inst, &s.group)
        .unwrap();
    s.group.apply_withdrawal(&withdrawal).unwrap();

    // Verification now reflects that the voucher has been withdrawn by Carol's successor
    assert_eq!(
        s.group.verification(
            &s.alice,
            bob,
            alice_voucher.as_ref(),
            IntroducerReliance::Rely
        ),
        Verification::VoucherWithdrawn
    );
}

#[test]
fn recovered_key_can_withdraw_voucher_issued_under_predecessor_key() {
    use mesh_identity::session::installation::Installation;

    let mut s = Scenario::new(164, Policy::InviterOnly);
    let (alice, carol, bob) = (s.alice.selected(), s.carol.selected(), s.bob.selected());
    meet(&mut s.alice, &mut s.carol, 1, &mut s.rng);
    meet(&mut s.carol, &mut s.bob, 2, &mut s.rng);

    let mut proposal = s.group.invite(carol, bob).unwrap();
    proposal.accept(bob).unwrap();
    let voucher = s.group.vouch(&proposal, &s.carol, [alice], 100).unwrap();
    let update = s.group.admit(&proposal, Some(voucher.clone())).unwrap();
    let (_, alice_voucher) = update.deliver_to(alice).unwrap();

    // Verify Bob is initially vouched for by verified issuer Carol
    assert_eq!(
        s.group.verification(
            &s.alice,
            bob,
            alice_voucher.as_ref(),
            IntroducerReliance::Rely
        ),
        Verification::VouchedForByVerifiedIssuer(carol)
    );

    // Carol enrolls recovery witnesses and recovers her key to carol2
    let carol2_sk = SigningKey::generate(&mut s.rng);
    let mut carol2_inst = Installation::new(carol2_sk);
    let carol2 = carol2_inst.selected();
    meet(&mut s.alice, &mut carol2_inst, 3, &mut s.rng);
    meet(&mut s.bob, &mut carol2_inst, 4, &mut s.rng);
    s.group.enroll_recovery(carol, [alice, bob]).unwrap();
    let mut request = s.group.request_recovery(carol, carol2).unwrap();
    s.group.approve_recovery(&mut request, &s.alice).unwrap();
    s.group.approve_recovery(&mut request, &s.bob).unwrap();
    let consent = s.group.recovery_consent(&request, &carol2_inst).unwrap();
    s.group
        .apply_recovery_consent(&mut request, &consent)
        .unwrap();
    s.group
        .advance_time(mesh_identity::groups::evidence::RECOVERY_VETO_WINDOW_MS);
    s.group.recover_lost_key(&request).unwrap();

    // Dave did not meet Carol's replacement key in person and has no continuity
    assert_eq!(
        s.group
            .verification(&s.dave, carol2, None, IntroducerReliance::Rely),
        Verification::NoEvidence
    );

    // Carol withdraws the voucher using her replacement key
    let withdrawal = voucher
        .authorize_withdrawal_by(&carol2_inst, &s.group)
        .unwrap();
    s.group.apply_withdrawal(&withdrawal).unwrap();

    // Verification now reflects that the voucher has been withdrawn by Carol's successor
    assert_eq!(
        s.group.verification(
            &s.alice,
            bob,
            alice_voucher.as_ref(),
            IntroducerReliance::Rely
        ),
        Verification::VoucherWithdrawn
    );
}

#[test]
fn signed_ejection_votes_are_scoped_and_competing_roster_updates_invalidate_them() {
    use mesh_identity::groups::evidence::SignedEjectionVote;

    for ejection_first in [true, false] {
        let mut s = Scenario::new(165, Policy::Unanimous);
        let (alice, carol, dave, eve, bob) = (
            s.alice.selected(),
            s.carol.selected(),
            s.dave.selected(),
            s.eve.selected(),
            s.bob.selected(),
        );
        meet(&mut s.alice, &mut s.bob, 1, &mut s.rng);
        let mut invite = s.group.invite(alice, bob).unwrap();
        invite.accept(bob).unwrap();
        for voter in [carol, dave, eve] {
            s.group.vote(&mut invite, voter, Vote::Approve).unwrap();
        }
        let voucher = s.group.vouch(&invite, &s.alice, [dave], 100).unwrap();

        let mut removal = s.group.propose_signed_ejection(&s.alice, carol).unwrap();
        let mut duplicate = s.group.propose_signed_ejection(&s.alice, carol).unwrap();
        let mut competing = s.group.propose_signed_ejection(&s.alice, eve).unwrap();
        let bytes = SignedEjectionVote::new(&removal, &s.dave)
            .unwrap()
            .to_bytes();
        assert!(SignedEjectionVote::from_bytes(&bytes[..95]).is_err());
        assert!(SignedEjectionVote::from_bytes(&[0; 97]).is_err());
        let vote = SignedEjectionVote::from_bytes(&bytes).unwrap();
        assert_eq!(vote.to_bytes(), bytes);
        for proposal in [&mut duplicate, &mut competing] {
            assert_eq!(
                s.group.apply_ejection_vote(proposal, &vote),
                Err(Error::Ineligible)
            );
        }
        for offset in [0, 32] {
            let mut altered = bytes;
            altered[offset] ^= 1;
            let altered = SignedEjectionVote::from_bytes(&altered).unwrap();
            assert_eq!(
                s.group.apply_ejection_vote(&mut removal, &altered),
                Err(Error::Ineligible)
            );
        }
        for signer in [&s.carol, &s.bob] {
            let ineligible = SignedEjectionVote::new(&removal, signer).unwrap();
            assert_eq!(
                s.group.apply_ejection_vote(&mut removal, &ineligible),
                Err(Error::Ineligible)
            );
        }
        assert_eq!(
            s.group.approve_removal(&mut removal, dave),
            Err(Error::Ineligible)
        );
        assert_eq!(
            s.group.apply_removal(&removal),
            Err(Error::ApprovalRequired)
        );
        s.group.apply_ejection_vote(&mut removal, &vote).unwrap();
        assert_eq!(
            s.group.apply_ejection_vote(&mut removal, &vote),
            Err(Error::AlreadyVoted)
        );

        let second_vote = SignedEjectionVote::new(&competing, &s.dave).unwrap();
        s.group
            .apply_ejection_vote(&mut competing, &second_vote)
            .unwrap();
        if ejection_first {
            s.group.apply_removal(&removal).unwrap();
            assert!(matches!(
                s.group.admit(&invite, Some(voucher)),
                Err(AdmissionError::Roster(Error::StaleProposal))
            ));
            assert!(s.group.membership(carol).is_none());
            assert!(s.group.membership(bob).is_none());
        } else {
            s.group.admit(&invite, Some(voucher)).unwrap();
            assert_eq!(s.group.apply_removal(&removal), Err(Error::StaleProposal));
            assert!(s.group.membership(carol).is_some());
            assert!(s.group.membership(bob).is_some());
        }
        assert_eq!(s.group.apply_removal(&competing), Err(Error::StaleProposal));
        assert_eq!(
            s.group.apply_ejection_vote(&mut removal, &vote),
            Err(Error::StaleProposal)
        );
        assert!(s.group.membership(eve).is_some());
    }
}

#[test]
fn invitation_retries_preserve_decisions_and_cancellation_wins_in_either_delivery_order() {
    use mesh_identity::groups::evidence::{
        InvitationInbox, SignedAdmissionConsent, SignedAdmissionVote, SignedInvitation,
        SignedInvitationCancellation,
    };

    for cancel_first in [false, true] {
        let mut s = Scenario::new(166, Policy::Majority);
        let (carol, bob) = (s.carol.selected(), s.bob.selected());
        meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
        let original = s.group.invite_until(carol, bob, 20).unwrap();
        let replacement = s.group.invite_until(carol, bob, 30).unwrap();
        let invitation = SignedInvitation::new(&original, &s.carol).unwrap();
        let replacement_wire = SignedInvitation::new(&replacement, &s.carol).unwrap();
        assert!(SignedInvitationCancellation::new(&invitation, &s.alice).is_err());
        let bytes = SignedInvitationCancellation::new(&invitation, &s.carol)
            .unwrap()
            .to_bytes();
        assert!(SignedInvitationCancellation::from_bytes(&bytes[..63]).is_err());
        let cancellation = SignedInvitationCancellation::from_bytes(&bytes).unwrap();
        let mut damaged = bytes;
        damaged[0] ^= 1;
        let damaged = SignedInvitationCancellation::from_bytes(&damaged).unwrap();
        let peer = &mut s.alice_offline;
        assert!(
            peer.apply_invitation_cancellation(&invitation, &damaged)
                .is_err()
        );
        assert!(
            peer.apply_invitation_cancellation(&replacement_wire, &cancellation)
                .is_err()
        );
        let mut inbox = InvitationInbox::default();
        let declined = peer.invite_until(carol, bob, 30).unwrap();
        let declined = SignedInvitation::new(&declined, &s.carol).unwrap();
        inbox
            .receive(peer, &declined)
            .unwrap()
            .decline(bob)
            .unwrap();
        assert!(matches!(
            inbox.receive(peer, &declined),
            Err(AdmissionError::InvitationDeclined)
        ));
        if !cancel_first {
            let proposal = inbox.receive(peer, &invitation).unwrap();
            let vote = SignedAdmissionVote::new(proposal, &s.dave, Vote::Approve).unwrap();
            let consent = SignedAdmissionConsent::new(proposal, &s.bob).unwrap();
            peer.apply_admission_vote(proposal, &vote).unwrap();
            peer.apply_admission_consent(proposal, &consent).unwrap();

            let proposal = inbox.receive(peer, &invitation).unwrap();
            let progress = peer.invitation_progress(proposal, bob).unwrap();
            assert!(progress.candidate_accepted);
            assert_eq!(progress.approvals, 2);
        }

        assert_eq!(
            peer.apply_invitation_cancellation(&invitation, &cancellation),
            Ok(true)
        );
        assert_eq!(
            peer.apply_invitation_cancellation(&invitation, &cancellation),
            Ok(false)
        );
        assert!(matches!(
            inbox.receive(peer, &invitation),
            Err(AdmissionError::InvitationCancelled)
        ));
        let mut original = original;
        let consent = SignedAdmissionConsent::new(&original, &s.bob).unwrap();
        assert_eq!(
            peer.apply_admission_consent(&mut original, &consent),
            Err(AdmissionError::InvitationCancelled)
        );

        let renewed = inbox.receive(peer, &replacement_wire).unwrap();
        let progress = peer.invitation_progress(renewed, bob).unwrap();
        assert!(!progress.candidate_accepted);
        assert_eq!(progress.approvals, 1);
        peer.advance_time(20);
        assert_eq!(
            peer.apply_invitation_cancellation(&invitation, &cancellation),
            Err(AdmissionError::InvitationExpired)
        );
        assert!(matches!(
            inbox.receive(peer, &invitation),
            Err(AdmissionError::InvitationExpired)
        ));
        let renewed = inbox.receive(peer, &replacement_wire).unwrap();
        let consent = SignedAdmissionConsent::new(renewed, &s.bob).unwrap();
        peer.apply_admission_consent(renewed, &consent).unwrap();
        for voter in [&s.alice, &s.dave] {
            let vote = SignedAdmissionVote::new(renewed, voter, Vote::Approve).unwrap();
            peer.apply_admission_vote(renewed, &vote).unwrap();
        }
        let voucher = peer
            .vouch(renewed, &s.carol, [s.alice.selected()], 100)
            .unwrap();
        peer.admit(renewed, Some(voucher)).unwrap();
        let late = SignedInvitationCancellation::new(&replacement_wire, &s.carol).unwrap();
        assert_eq!(
            peer.apply_invitation_cancellation(&replacement_wire, &late),
            Err(AdmissionError::Roster(Error::StaleProposal))
        );
        assert!(peer.membership(bob).is_some());
    }
}

#[test]
fn signed_recovery_decisions_are_bound_to_one_request_and_one_role() {
    use mesh_identity::groups::evidence::{
        CatchUp, RECOVERY_VETO_WINDOW_MS, SignedRecoveryConsent, SignedRecoveryDecision,
    };

    let mut s = Scenario::new(167, Policy::InviterOnly);
    let old = s.carol.selected();
    let replacement = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    s.group
        .enroll_recovery(old, [s.alice.selected(), s.dave.selected()])
        .unwrap();
    let mut allowed = s.group.request_recovery(old, replacement).unwrap();
    let mut vetoed = s.group.request_recovery(old, replacement).unwrap();
    let veto = s.group.recovery_veto(&vetoed, &s.carol).unwrap();
    let veto = SignedRecoveryDecision::from_bytes(&veto.to_bytes()).unwrap();
    assert_eq!(
        s.group.apply_recovery_decision(&mut allowed, &veto),
        Err(Error::Ineligible)
    );
    assert_eq!(
        s.group.apply_recovery_decision(&mut vetoed, &veto),
        Ok(true)
    );
    assert_eq!(
        s.group.apply_recovery_decision(&mut vetoed, &veto),
        Ok(false)
    );

    s.carol.select(replacement, 1).unwrap();
    meet(&mut s.alice, &mut s.carol, 1, &mut s.rng);
    meet(&mut s.dave, &mut s.carol, 2, &mut s.rng);
    let consent = s.group.recovery_consent(&allowed, &s.carol).unwrap();
    let consent = SignedRecoveryConsent::from_bytes(&consent.to_bytes()).unwrap();
    assert_eq!(
        s.group.apply_recovery_consent(&mut vetoed, &consent),
        Err(Error::Ineligible)
    );
    s.group
        .apply_recovery_consent(&mut allowed, &consent)
        .unwrap();

    let approval = s
        .group
        .recovery_approval(&allowed, &s.alice)
        .unwrap()
        .to_bytes();
    assert!(SignedRecoveryDecision::from_bytes(&approval[..96]).is_err());
    assert!(SignedRecoveryDecision::from_bytes(&[0; 98]).is_err());
    let mut unknown = approval;
    unknown[32] = 0;
    assert!(SignedRecoveryDecision::from_bytes(&unknown).is_err());
    for (offset, mask) in [(0, 1), (32, 1), (33, 1)] {
        let mut altered = approval;
        altered[offset] ^= mask;
        let altered = SignedRecoveryDecision::from_bytes(&altered).unwrap();
        assert_eq!(
            s.group.apply_recovery_decision(&mut allowed, &altered),
            Err(Error::Ineligible)
        );
    }
    let approval = SignedRecoveryDecision::from_bytes(&approval).unwrap();
    assert_eq!(
        s.group.apply_recovery_decision(&mut vetoed, &approval),
        Err(Error::Ineligible)
    );
    assert_eq!(
        s.group.apply_recovery_decision(&mut allowed, &approval),
        Ok(true)
    );
    assert_eq!(
        s.group.apply_recovery_decision(&mut allowed, &approval),
        Ok(false)
    );
    let second = s.group.recovery_approval(&allowed, &s.dave).unwrap();
    assert_eq!(
        s.group.apply_recovery_decision(&mut allowed, &second),
        Ok(true)
    );
    let vetoed_consent = s.group.recovery_consent(&vetoed, &s.carol).unwrap();
    s.group
        .apply_recovery_consent(&mut vetoed, &vetoed_consent)
        .unwrap();
    for witness in [&s.alice, &s.dave] {
        let approval = s.group.recovery_approval(&vetoed, witness).unwrap();
        assert_eq!(
            s.group.apply_recovery_decision(&mut vetoed, &approval),
            Ok(true)
        );
    }

    s.group.advance_time(RECOVERY_VETO_WINDOW_MS - 1);
    assert_eq!(
        s.group.recover_lost_key(&allowed),
        Err(Error::ApprovalRequired)
    );
    s.group.advance_time(RECOVERY_VETO_WINDOW_MS);
    assert_eq!(s.group.recover_lost_key(&vetoed), Err(Error::Ineligible));
    let tenure = s.group.membership(old);
    let mut peer = s.group.clone();
    s.group.recover_lost_key(&allowed).unwrap();
    peer.recover_lost_key(&allowed).unwrap();
    assert_eq!(peer.catch_up(&s.group), CatchUp::AlreadyCurrent);
    assert_eq!(peer.membership(replacement), tenure);
    assert_eq!(s.group.membership(replacement), tenure);
    assert!(s.group.membership(old).is_none());
    assert_eq!(
        s.group.apply_recovery_decision(&mut allowed, &approval),
        Err(Error::StaleProposal)
    );
}

#[test]
fn portable_recovery_retries_keep_the_receivers_veto_window_and_decisions() {
    use mesh_identity::groups::evidence::{
        CatchUp, RECOVERY_VETO_WINDOW_MS, RecoveryInbox, SignedRecoveryRequest,
    };

    for veto_first in [false, true] {
        let mut s = Scenario::new(168, Policy::InviterOnly);
        let old = s.carol.selected();
        let new = s
            .carol
            .add_identity(SigningKey::generate(&mut s.rng))
            .unwrap();
        let tenure = s.group.membership(old);
        s.group
            .enroll_recovery(old, [s.alice.selected(), s.dave.selected()])
            .unwrap();
        let request = s.group.request_recovery(old, new).unwrap();
        let veto = s.group.recovery_veto(&request, &s.carol).unwrap();
        s.carol.select(new, 1).unwrap();
        meet(&mut s.alice, &mut s.carol, 1, &mut s.rng);
        meet(&mut s.dave, &mut s.carol, 2, &mut s.rng);
        let bytes = s
            .group
            .sign_recovery_request(&request, &s.carol)
            .unwrap()
            .to_bytes();
        assert!(SignedRecoveryRequest::from_bytes(&bytes[..199]).is_err());
        assert!(SignedRecoveryRequest::from_bytes(&[0; 201]).is_err());
        let signed = SignedRecoveryRequest::from_bytes(&bytes).unwrap();
        assert_eq!(signed.to_bytes(), bytes);
        let mut inbox = RecoveryInbox::default();
        let peer = &mut s.alice_offline;
        assert!(matches!(
            inbox.receive(peer, &signed, &s.alice),
            Err(Error::StaleProposal)
        ));
        assert_eq!(peer.catch_up(&s.group), CatchUp::Applied);
        let received_at = RECOVERY_VETO_WINDOW_MS + 10;
        peer.advance_time(received_at);
        for offset in [0, 8, 40, 72, 104, 136] {
            let mut altered = bytes;
            altered[offset] ^= 1;
            let altered = SignedRecoveryRequest::from_bytes(&altered).unwrap();
            assert!(inbox.receive(peer, &altered, &s.alice).is_err());
        }

        // Peers that are neither the old key nor an enrolled witness who verified the
        // replacement keep nothing.
        assert!(matches!(
            inbox.receive(peer, &signed, &s.eve),
            Err(Error::Ineligible)
        ));
        let pending = inbox.receive(peer, &signed, &s.alice).unwrap();
        let approvals = [&s.alice, &s.dave]
            .map(|witness| s.group.recovery_approval(&request, witness).unwrap());
        for approval in &approvals {
            assert_eq!(peer.apply_recovery_decision(pending, approval), Ok(true));
        }
        if veto_first {
            assert_eq!(peer.apply_recovery_decision(pending, &veto), Ok(true));
        } else {
            assert_eq!(peer.recover_lost_key(pending), Err(Error::ApprovalRequired));
        }

        peer.advance_time(received_at + RECOVERY_VETO_WINDOW_MS);
        let pending = inbox.receive(peer, &signed, &s.alice).unwrap();
        assert_eq!(
            peer.apply_recovery_decision(pending, &approvals[0]),
            Ok(false)
        );
        if veto_first {
            assert_eq!(peer.recover_lost_key(pending), Err(Error::Ineligible));
            assert_eq!(peer.membership(old), tenure);
        } else {
            peer.recover_lost_key(pending).unwrap();
            assert_eq!(peer.membership(new), tenure);
            assert!(matches!(
                inbox.receive(peer, &signed, &s.alice),
                Err(Error::StaleProposal)
            ));
        }
    }
}

#[test]
fn group_exports_and_discovery_stay_independent_of_private_identity_disclosure() {
    let mut s = Scenario::new(176, Policy::InviterOnly);
    let game = s.bob.selected();
    let private = s
        .bob
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    let (alice, carol) = (s.alice.selected(), s.carol.selected());
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    meet(&mut s.alice, &mut s.bob, 2, &mut s.rng);
    let mut invite = s.group.invite(carol, game).unwrap();
    invite.accept(game).unwrap();
    let voucher = s.group.vouch(&invite, &s.carol, [alice], 100).unwrap();
    s.group.admit(&invite, Some(voucher)).unwrap();

    let export = |viewer: &mesh_identity::session::installation::Installation| {
        serde_json::to_value(s.group.export_roster(viewer).unwrap()).unwrap()
    };
    let original = export(&s.alice);
    let mut members = [alice, carol, s.dave.selected(), s.eve.selected(), game];
    members.sort();
    let (group, roster) = s.group.rotation_context();
    assert_eq!(
        original,
        serde_json::json!({ "group": group, "roster": roster, "members": members })
    );

    let request = s.alice.request_link(3, &mut s.rng);
    let pair = [game, private];
    let first = s.bob.approve_link(&request, pair).unwrap();
    s.bob.select(private, 3).unwrap();
    let second = s.bob.approve_link(&request, pair).unwrap();
    let approvals = [first, second];
    assert!(s.eve.preview_link(request, pair, &approvals, 3).is_none());
    let disclosure = s.alice.receive_link(request, pair, approvals, 3).unwrap();
    assert_eq!(disclosure.recipient, alice);
    assert_eq!(format!("{disclosure:?}"), "DisclosedLink { .. }");
    meet(&mut s.alice, &mut s.bob, 4, &mut s.rng);
    let grouped = s.alice.linked_person_contacts(alice, pair).unwrap();
    assert_eq!(grouped.peers().count(), 2);

    assert_eq!(export(&s.alice), original);
    assert_eq!(export(&s.eve), original);
    for member in [&s.alice, &s.eve] {
        assert_eq!(s.group.discover_member(member, game), Ok(Some(game)));
        assert_eq!(s.group.discover_member(member, private), Ok(None));
    }
    let roster = s.group.export_roster(&s.alice).unwrap();
    assert_eq!(
        format!("{roster:?}"),
        "RosterExport { member_count: 5, .. }"
    );
    assert!(matches!(
        s.group.export_roster(&s.bob),
        Err(Error::Ineligible)
    ));
    assert_eq!(
        s.group.discover_member(&s.bob, game),
        Err(Error::Ineligible)
    );
    s.bob.select(game, 5).unwrap();
    assert_eq!(export(&s.bob), original);
}

#[test]
fn filtered_peer_validates_and_applies_certified_recovery_without_prior_witness_disclosure() {
    use mesh_identity::groups::evidence::{RECOVERY_VETO_WINDOW_MS, RecoveryStatus};
    #[path = "support/roster.rs"]
    mod roster;

    let mut s = Scenario::new(909, Policy::InviterOnly);
    let old = s.carol.selected();
    let alice = s.alice.selected();
    let dave = s.dave.selected();
    let eve = s.eve.selected();
    let bob = s.bob.selected();
    s.group.enroll_recovery(old, [alice, dave]).unwrap();
    meet(&mut s.carol, &mut s.bob, 1, &mut s.rng);
    let mut proposal = s.group.invite(old, bob).unwrap();
    let voucher = s.group.vouch(&proposal, &s.carol, [alice], 100).unwrap();
    proposal.accept(bob).unwrap();
    let update = s.group.admit(&proposal, Some(voucher)).unwrap();
    let (mut filtered, _) = update.deliver_to(eve).unwrap();
    assert_eq!(filtered.recovery_status(old), RecoveryStatus::NotEnrolled);

    let replacement = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    assert!(matches!(
        filtered.request_recovery(old, replacement),
        Err(Error::Ineligible)
    ));
    s.carol.select(replacement, 2).unwrap();
    meet(&mut s.carol, &mut s.alice, 2, &mut s.rng);
    meet(&mut s.carol, &mut s.dave, 2, &mut s.rng);
    let mut request = s.group.request_recovery(old, replacement).unwrap();
    for witness in [&s.alice, &s.dave] {
        let approval = filtered.recovery_approval(&request, witness).unwrap();
        filtered
            .apply_recovery_decision(&mut request, &approval)
            .unwrap();
    }
    let consent = filtered.recovery_consent(&request, &s.carol).unwrap();
    filtered
        .apply_recovery_consent(&mut request, &consent)
        .unwrap();
    assert_eq!(
        filtered.recovery_child(&request),
        Err(Error::ApprovalRequired)
    );
    s.group.advance_time(RECOVERY_VETO_WINDOW_MS);
    filtered.advance_time(RECOVERY_VETO_WINDOW_MS);
    let child = s.group.recovery_child(&request).unwrap();
    assert_eq!(filtered.recovery_child(&request), Ok(child));
    let certificate = roster::certify(&s.group, child, &[&s.alice, &s.dave, &s.eve, &s.bob]);
    let tenure = s.group.membership(old).unwrap();
    filtered
        .apply_certified_recovery(&request, &certificate)
        .unwrap();
    s.group
        .apply_certified_recovery(&request, &certificate)
        .unwrap();
    assert_eq!(filtered.rotation_context(), s.group.rotation_context());
    assert_eq!(filtered.membership(replacement), Some(tenure));
    assert_eq!(filtered.membership(old), None);
}
