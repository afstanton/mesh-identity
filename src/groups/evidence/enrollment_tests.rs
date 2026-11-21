//! Certified recovery enrollment. Only the commitment is replicated; the witnesses and
//! salt stay with the owner and the witnesses.

use super::apply_v1_tests::{cert, snapshot, v1};
use super::certificate_v1_tests::{digest_of, group, key, proof_at_head, signing};
use super::{Error, RecoveryStatus, SignedRecoveryEnrollment, VouchedGroup};
use crate::groups::Policy;
use crate::session::installation::group_recovery_enrollment_message;
use ed25519_dalek::Signer;

const FIVE: [u8; 5] = [11, 12, 13, 14, 15];
const SALT: [u8; 32] = [7; 32];

/// `owner` enrolls `witnesses` (seeds); the signature is made by `signer`.
fn enrollment(
    g: &VouchedGroup,
    owner: u8,
    witnesses: [u8; 2],
    salt: [u8; 32],
    signer: u8,
) -> SignedRecoveryEnrollment {
    let context = g.rotation_context();
    let commitment = g
        .enrollment_commitment(key(owner), witnesses.map(key), salt)
        .unwrap();
    let message = group_recovery_enrollment_message(context.0, context.1, key(owner), commitment);
    SignedRecoveryEnrollment::new(
        context,
        key(owner),
        commitment,
        signing(signer).sign(&message).to_bytes(),
    )
}

fn enrolled(mut g: VouchedGroup, owner: u8, witnesses: [u8; 2], salt: [u8; 32]) -> VouchedGroup {
    let e = enrollment(&g, owner, witnesses, salt, owner);
    let child = g.enrollment_child(&e).unwrap();
    g.apply_certified_enrollment(&e, &cert(&g, child, &FIVE))
        .unwrap();
    g
}

#[test]
fn the_frame_round_trips_and_rejects_any_other_length() {
    let g = group();
    let e = enrollment(&g, 10, [12, 13], SALT, 10);
    let bytes = e.to_bytes();
    assert_eq!(
        SignedRecoveryEnrollment::from_bytes(&bytes)
            .unwrap()
            .to_bytes(),
        bytes
    );
    assert!(SignedRecoveryEnrollment::from_bytes(&bytes[..167]).is_err());
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert!(SignedRecoveryEnrollment::from_bytes(&longer).is_err());
}

#[test]
fn only_the_commitment_is_replicated_and_the_opening_stays_local() {
    let base = group();
    let revision = base.revision();
    let (owner, witness, bystander) = (
        enrolled(base.clone(), 10, [12, 13], SALT),
        enrolled(base.clone(), 10, [12, 13], SALT),
        enrolled(base.clone(), 10, [12, 13], SALT),
    );
    let (mut owner, mut witness) = (owner, witness);
    for g in [&owner, &witness, &bystander] {
        assert_eq!(g.revision(), revision + 1);
        assert_eq!(g.recovery_commitments.len(), 1);
        // The operation carried no opening.
        assert!(g.recovery_witnesses.is_empty() && g.recovery_salts.is_empty());
        assert_eq!(g.recovery_status(key(10)), RecoveryStatus::NotEnrolled);
    }
    owner
        .install_recovery_opening(key(10), [key(12), key(13)], SALT)
        .unwrap();
    witness
        .install_recovery_opening(key(10), [key(12), key(13)], SALT)
        .unwrap();
    assert_eq!(owner.recovery_status(key(10)), RecoveryStatus::Enrolled);
    assert_eq!(witness.recovery_status(key(10)), RecoveryStatus::Enrolled);
    assert_eq!(
        bystander.recovery_status(key(10)),
        RecoveryStatus::NotEnrolled
    );
    // Installing the opening is local: roster state and chain are unchanged.
    assert_eq!(digest_of(&owner), digest_of(&bystander));
    assert_eq!(owner.rotation_context(), bystander.rotation_context());
    // A request can now be built from the owner's replica.
    assert!(owner.request_recovery(key(10), key(60)).is_ok());
}

#[test]
fn a_wrong_opening_is_refused_and_changes_nothing() {
    let mut g = enrolled(group(), 10, [12, 13], SALT);
    for (witnesses, salt) in [([12, 14], SALT), ([14, 15], SALT), ([12, 13], [8; 32])] {
        assert!(
            g.install_recovery_opening(key(10), witnesses.map(key), salt)
                .is_err()
        );
    }
    assert!(g.recovery_witnesses.is_empty() && g.recovery_salts.is_empty());
}

#[test]
fn a_version_one_certificate_carries_its_proofs() {
    let mut g = group();
    let e = enrollment(&g, 10, [12, 13], SALT, 10);
    let child = g.enrollment_child(&e).unwrap();
    // Four of seven is short without the proof against 16, and enough with it.
    let mut control = g.clone();
    assert_eq!(
        control.apply_certified_enrollment(&e, &cert(&g, child, &[11, 12, 13, 14])),
        Err(Error::Ineligible)
    );
    assert_eq!(snapshot(&control), snapshot(&g));
    let certificate = v1(&g, child, &[11, 12, 13, 14], vec![proof_at_head(&g, 16)]);
    g.apply_certified_enrollment(&e, &certificate).unwrap();
    assert!(g.inherited_proof_keys().contains(&key(16)));
    assert_eq!(g.recovery_commitments.len(), 1);
}

#[test]
fn rejections_change_nothing() {
    let g = group();
    let e = enrollment(&g, 10, [12, 13], SALT, 10);
    let child = g.enrollment_child(&e).unwrap();
    let before = snapshot(&g);
    let mut h = g.clone();

    // Signed by someone other than the owner.
    let forged = enrollment(&g, 10, [12, 13], SALT, 11);
    assert_eq!(h.enrollment_child(&forged), Err(Error::Ineligible));
    // A non-member owner.
    let mut outsider = e.to_bytes();
    outsider[40..72].copy_from_slice(&key(99));
    let outsider = SignedRecoveryEnrollment::from_bytes(&outsider).unwrap();
    assert_eq!(h.enrollment_child(&outsider), Err(Error::Ineligible));
    // A tampered commitment breaks the owner's signature.
    let mut tampered = e.to_bytes();
    tampered[72] ^= 1;
    let tampered = SignedRecoveryEnrollment::from_bytes(&tampered).unwrap();
    assert_eq!(h.enrollment_child(&tampered), Err(Error::Ineligible));
    // Short quorum.
    assert_eq!(
        h.apply_certified_enrollment(&e, &cert(&g, child, &[11, 12, 13, 14])),
        Err(Error::Ineligible)
    );
    // A certificate built on another chain is told to catch up.
    let mut stale = v1(&g, child, &FIVE, vec![]);
    stale.chain_digest = [9; 32];
    assert_eq!(
        h.apply_certified_enrollment(&e, &stale),
        Err(Error::ChainMismatch)
    );
    assert_eq!(snapshot(&h), before);
    assert!(h.recovery_commitments.is_empty());

    // Applied once: the signed frame names the old head after it applies.
    let certificate = cert(&g, child, &FIVE);
    h.apply_certified_enrollment(&e, &certificate).unwrap();
    let after = snapshot(&h);
    assert_eq!(
        h.apply_certified_enrollment(&e, &certificate),
        Err(Error::StaleProposal)
    );
    assert_eq!(snapshot(&h), after);
}

#[test]
fn an_owner_proven_at_the_head_cannot_enroll() {
    let mut g = group();
    // A policy change whose certificate proves key 16.
    let child = g.policy_child(Policy::Majority).unwrap();
    let c = v1(&g, child, &[11, 12, 13, 14], vec![proof_at_head(&g, 16)]);
    g.apply_certified_policy_change(Policy::Majority, &c)
        .unwrap();
    let context = g.rotation_context();
    let message = group_recovery_enrollment_message(context.0, context.1, key(16), [3; 32]);
    let e = SignedRecoveryEnrollment::new(
        context,
        key(16),
        [3; 32],
        signing(16).sign(&message).to_bytes(),
    );
    assert_eq!(g.enrollment_child(&e), Err(Error::Ineligible));
    // A proven witness cannot be named either.
    assert_eq!(
        g.enrollment_commitment(key(10), [key(12), key(16)], SALT),
        Err(Error::Ineligible)
    );
}

#[test]
fn re_enrolling_drops_the_old_opening_until_the_new_one_is_installed() {
    let mut g = enrolled(group(), 10, [12, 13], SALT);
    g.install_recovery_opening(key(10), [key(12), key(13)], SALT)
        .unwrap();
    assert_eq!(g.recovery_status(key(10)), RecoveryStatus::Enrolled);
    let again = enrollment(&g, 10, [13, 14], [9; 32], 10);
    let child = g.enrollment_child(&again).unwrap();
    g.apply_certified_enrollment(&again, &cert(&g, child, &FIVE))
        .unwrap();
    assert_eq!(g.recovery_status(key(10)), RecoveryStatus::NotEnrolled);
    // The old opening no longer matches.
    assert!(
        g.install_recovery_opening(key(10), [key(12), key(13)], SALT)
            .is_err()
    );
    g.install_recovery_opening(key(10), [key(13), key(14)], [9; 32])
        .unwrap();
    assert_eq!(g.recovery_status(key(10)), RecoveryStatus::Enrolled);
}

#[test]
fn replicas_converge_and_replay_reaches_the_same_state() {
    let ops = |g: VouchedGroup| {
        let mut g = enrolled(g, 10, [12, 13], SALT);
        let child = g.policy_child(Policy::Majority).unwrap();
        g.apply_certified_policy_change(Policy::Majority, &cert(&g, child, &FIVE))
            .unwrap();
        g
    };
    let base = group();
    let (a, b) = (ops(base.clone()), ops(base.clone()));
    assert_eq!(digest_of(&a), digest_of(&b));
    assert_eq!(a.rotation_context(), b.rotation_context());
    assert_eq!(a.recovery_commitments, b.recovery_commitments);
    assert_eq!(a.group.policy, Policy::Majority);
    // A lagging replica catches up across both operations.
    let mut lagging = base;
    assert_eq!(lagging.catch_up(&a), super::CatchUp::Applied);
    assert_eq!(lagging.recovery_commitments, a.recovery_commitments);
}

#[test]
fn a_certificate_proving_the_owner_cannot_replace_its_enrollment() {
    let mut g = enrolled(group(), 10, [11, 12], SALT);
    g.install_recovery_opening(key(10), [key(11), key(12)], SALT)
        .unwrap();
    let owner = g.membership(key(10)).unwrap().identity;
    let before = snapshot(&g);
    let old = g.recovery_commitments[&owner];
    let e = enrollment(&g, 10, [13, 14], [9; 32], 10);
    let child = g.enrollment_child(&e).unwrap();
    let certificate = v1(&g, child, &[11, 12, 13, 14], vec![proof_at_head(&g, 10)]);
    assert_eq!(
        g.apply_certified_enrollment(&e, &certificate),
        Err(Error::Ineligible)
    );
    assert_eq!(snapshot(&g), before);
    assert_eq!(g.recovery_commitments[&owner], old);
    assert_eq!(g.recovery_salts[&owner], SALT);
    assert_eq!(g.recovery_witnesses[&owner], [key(11), key(12)]);
}

#[test]
fn an_existing_opening_can_arrive_after_its_owner_is_reported_or_proven() {
    use super::SignedSuspension;
    use crate::session::installation::group_suspension_message;

    for proven in [false, true] {
        let mut g = enrolled(group(), 10, [12, 13], SALT);
        if proven {
            let child = g.policy_child(Policy::Majority).unwrap();
            let certificate = v1(&g, child, &FIVE, vec![proof_at_head(&g, 10)]);
            g.apply_certified_policy_change(Policy::Majority, &certificate)
                .unwrap();
        } else {
            let context = g.rotation_context();
            let message = group_suspension_message(context.0, context.1, key(11), key(10));
            let s = SignedSuspension::new(
                context,
                key(11),
                key(10),
                signing(11).sign(&message).to_bytes(),
            );
            let child = g.suspension_child(&s).unwrap();
            g.apply_certified_suspension(&s, &cert(&g, child, &FIVE))
                .unwrap();
        }
        let before = snapshot(&g);
        let digest = g.chain_digest();
        assert_eq!(
            g.enrollment_commitment(key(10), [key(12), key(13)], SALT),
            Err(Error::Ineligible)
        );
        // Neither a forged opening nor an ineligible witness becomes acceptable.
        assert_eq!(
            g.install_recovery_opening(key(10), [key(12), key(13)], [8; 32]),
            Err(Error::Ineligible)
        );
        assert_eq!(
            g.install_recovery_opening(key(10), [key(12), key(14)], SALT),
            Err(Error::Ineligible)
        );
        assert!(g.recovery_witnesses.is_empty());
        g.install_recovery_opening(key(10), [key(12), key(13)], SALT)
            .unwrap();
        assert!(g.request_recovery(key(10), key(60)).is_ok());
        assert_eq!(snapshot(&g), before);
        assert_eq!(g.chain_digest(), digest);

        // A separately barred witness still disqualifies the opening, without changing it.
        let child = g.policy_child(Policy::TwoThirds).unwrap();
        let certificate = v1(&g, child, &[11, 13, 14, 15], vec![proof_at_head(&g, 12)]);
        g.apply_certified_policy_change(Policy::TwoThirds, &certificate)
            .unwrap();
        assert_eq!(
            g.install_recovery_opening(key(10), [key(12), key(13)], SALT),
            Err(Error::Ineligible)
        );
        assert_eq!(g.recovery_status(key(10)), RecoveryStatus::Degraded);
    }
}

#[test]
fn witness_order_does_not_affect_commitment_or_opening_installation() {
    let g = group();
    let c1 = g
        .enrollment_commitment(key(10), [key(11), key(12)], SALT)
        .unwrap();
    let c2 = g
        .enrollment_commitment(key(10), [key(12), key(11)], SALT)
        .unwrap();
    assert_eq!(
        c1, c2,
        "canonicalized witnesses must yield identical commitments"
    );

    // Certify enrollment using reversed witness array
    let (gid, parent) = g.rotation_context();
    let signed = SignedRecoveryEnrollment::new(
        (gid, parent),
        key(10),
        c1,
        signing(10)
            .sign(&group_recovery_enrollment_message(gid, parent, key(10), c1))
            .to_bytes(),
    );
    let child = g.enrollment_child(&signed).unwrap();
    let mut replica1 = g.clone();
    replica1
        .apply_certified_enrollment(&signed, &cert(&g, child, &FIVE))
        .unwrap();
    let mut replica2 = replica1.clone();

    // Opening installs successfully with either witness order
    replica1
        .install_recovery_opening(key(10), [key(11), key(12)], SALT)
        .unwrap();
    replica2
        .install_recovery_opening(key(10), [key(12), key(11)], SALT)
        .unwrap();
    assert_eq!(replica1.recovery_witnesses, replica2.recovery_witnesses);
    assert_eq!(replica1.recovery_salts, replica2.recovery_salts);
}

#[test]
fn catch_up_preserves_local_recovery_openings_and_follows_witness_rotation() {
    use super::apply_v1_tests::rotation;

    let base = enrolled(group(), 10, [11, 12], SALT);
    let mut node_b = base.clone();
    node_b
        .install_recovery_opening(key(10), [key(11), key(12)], SALT)
        .unwrap();
    let owner_id = node_b.membership(key(10)).unwrap().identity;
    assert_eq!(node_b.recovery_salts.get(&owner_id), Some(&SALT));

    // Node A (the remote) has NO local opening for member 10
    let mut node_a = base.clone();
    assert!(node_a.recovery_salts.is_empty());
    assert!(node_a.recovery_witnesses.is_empty());

    // Node A advances history: policy change + rotates witness 11 to key 50
    let child1 = node_a.policy_child(Policy::Majority).unwrap();
    node_a
        .apply_certified_policy_change(Policy::Majority, &cert(&node_a, child1, &FIVE))
        .unwrap();

    let rot = rotation(&node_a, 11, 50);
    let child2 = node_a.rotation_child(&rot).unwrap();
    node_a
        .apply_certified_rotation(&rot, &cert(&node_a, child2, &[10, 11, 12, 13, 14]))
        .unwrap();

    // Node B catches up to Node A
    assert_eq!(node_b.catch_up(&node_a), super::CatchUp::Applied);

    // Node B's local opening is preserved across catch-up
    assert_eq!(node_b.recovery_salts.get(&owner_id), Some(&SALT));
    // Witness 11 was updated to rotated key 50 in Node B's local recovery witnesses
    let witnesses = node_b.recovery_witnesses.get(&owner_id).unwrap();
    assert!(witnesses.contains(&key(50)));
    assert!(witnesses.contains(&key(12)));
    assert!(!witnesses.contains(&key(11)));
    assert!(node_b.request_recovery(key(10), key(60)).is_ok());
}

#[test]
fn catch_up_prunes_stale_local_openings_when_remote_re_enrolled() {
    let base = enrolled(group(), 10, [11, 12], SALT);
    let mut node_b = base.clone();
    node_b
        .install_recovery_opening(key(10), [key(11), key(12)], SALT)
        .unwrap();
    let owner_id = node_b.membership(key(10)).unwrap().identity;
    assert_eq!(node_b.recovery_salts.get(&owner_id), Some(&SALT));

    // Node A certifies a NEW enrollment for member 10 with a different salt
    let mut node_a = base.clone();
    let new_salt = [99u8; 32];
    let new_commitment = node_a
        .enrollment_commitment(key(10), [key(12), key(13)], new_salt)
        .unwrap();
    let (gid, parent) = node_a.rotation_context();
    let signed = SignedRecoveryEnrollment::new(
        (gid, parent),
        key(10),
        new_commitment,
        signing(10)
            .sign(&group_recovery_enrollment_message(
                gid,
                parent,
                key(10),
                new_commitment,
            ))
            .to_bytes(),
    );
    let child = node_a.enrollment_child(&signed).unwrap();
    node_a
        .apply_certified_enrollment(&signed, &cert(&node_a, child, &FIVE))
        .unwrap();

    // Node B catches up to Node A
    assert_eq!(node_b.catch_up(&node_a), super::CatchUp::Applied);

    // Because old SALT no longer matches the commitment, Node B pruned the stale opening
    assert!(node_b.recovery_salts.is_empty());
    assert!(node_b.recovery_witnesses.is_empty());
}
