//! Certified agreed suspension.

use super::apply_v1_tests::{cert, departure, rotation, snapshot, v1};
use super::certificate_v1_tests::{digest_of, group, key, proof_at_head, signing};
use super::{CatchUp, Error, SUSPENSION_RESERVED_OFFLINE, SignedSuspension, VouchedGroup};
use crate::groups::Policy;
use crate::session::installation::group_suspension_message;
use ed25519_dalek::Signer;
use std::collections::BTreeSet;

const FIVE: [u8; 5] = [11, 12, 13, 14, 15];

fn suspension(g: &VouchedGroup, proposer: u8, target: u8, signer: u8) -> SignedSuspension {
    let context = g.rotation_context();
    let message = group_suspension_message(context.0, context.1, key(proposer), key(target));
    SignedSuspension::new(
        context,
        key(proposer),
        key(target),
        signing(signer).sign(&message).to_bytes(),
    )
}

fn suspended(mut g: VouchedGroup, proposer: u8, target: u8, signers: &[u8]) -> VouchedGroup {
    let s = suspension(&g, proposer, target, proposer);
    let child = g.suspension_child(&s).unwrap();
    g.apply_certified_suspension(&s, &cert(&g, child, signers))
        .unwrap();
    g
}

/// A larger group: seeds 10 to 19, ten members, quorum seven.
fn ten() -> VouchedGroup {
    VouchedGroup::new(7, (10..20).map(key), Policy::InviterOnly)
}

#[test]
fn the_frame_round_trips_and_rejects_any_other_length() {
    let g = group();
    let bytes = suspension(&g, 10, 16, 10).to_bytes();
    assert_eq!(
        SignedSuspension::from_bytes(&bytes).unwrap().to_bytes(),
        bytes
    );
    assert!(SignedSuspension::from_bytes(&bytes[..167]).is_err());
    let mut longer = bytes.to_vec();
    longer.push(0);
    assert!(SignedSuspension::from_bytes(&longer).is_err());
}

#[test]
fn a_suspension_reports_the_key_without_removing_it_or_shrinking_the_count() {
    let base = ten();
    let before = base.revision();
    let g = suspended(base.clone(), 10, 19, &[10, 11, 12, 13, 14, 15, 16]);
    assert_eq!(g.revision(), before + 1);
    assert_eq!(g.reported_keys(), &BTreeSet::from([key(19)]));
    assert!(g.membership(key(19)).is_some());
    assert!(g.suspect.is_empty());
    assert_eq!(g.group.electorate_size(), 10);
    assert_eq!(g.roster_quorum(), Ok(7));
    assert_ne!(g.chain_digest(), digest_of(&g));
    // Applied once, and the same key cannot be suspended again.
    let again = suspension(&g, 11, 19, 11);
    assert_eq!(g.suspension_child(&again), Err(Error::Ineligible));
    // The proposer's signature is not part of the child: two proposers, one operation.
    let by_other = suspension(&base, 11, 19, 11);
    assert_eq!(
        base.suspension_child(&by_other).unwrap(),
        base.suspension_child(&suspension(&base, 10, 19, 10))
            .unwrap()
    );
}

#[test]
fn a_version_one_certificate_carries_its_proofs_and_one_naming_the_target_is_refused() {
    let g = ten();
    let s = suspension(&g, 10, 19, 10);
    let child = g.suspension_child(&s).unwrap();
    // Six of ten is short for seven required; a proof against 18 lowers the quorum to six.
    let mut control = g.clone();
    assert_eq!(
        control.apply_certified_suspension(&s, &cert(&g, child, &[10, 11, 12, 13, 14, 15])),
        Err(Error::Ineligible)
    );
    let mut h = g.clone();
    h.apply_certified_suspension(
        &s,
        &v1(
            &g,
            child,
            &[10, 11, 12, 13, 14, 15],
            vec![proof_at_head(&g, 18)],
        ),
    )
    .unwrap();
    assert!(h.inherited_proof_keys().contains(&key(18)));
    assert_eq!(h.reported_keys(), &BTreeSet::from([key(19)]));

    // A proof against the target itself makes the report redundant.
    let mut k = g.clone();
    let before = snapshot(&k);
    assert_eq!(
        k.apply_certified_suspension(
            &s,
            &v1(
                &g,
                child,
                &[10, 11, 12, 13, 14, 15],
                vec![proof_at_head(&g, 19)]
            )
        ),
        Err(Error::Ineligible)
    );
    assert_eq!(snapshot(&k), before);
    assert!(k.reported_keys().is_empty());
}

#[test]
fn rejections_change_nothing() {
    let g = ten();
    let s = suspension(&g, 10, 19, 10);
    let child = g.suspension_child(&s).unwrap();
    let seven = [10, 11, 12, 13, 14, 15, 16];
    let mut h = g.clone();
    let before = snapshot(&h);

    // Signed by someone other than the proposer.
    assert_eq!(
        h.suspension_child(&suspension(&g, 10, 19, 11)),
        Err(Error::Ineligible)
    );
    // A non-member target or proposer.
    assert_eq!(
        h.suspension_child(&suspension(&g, 10, 99, 10)),
        Err(Error::Ineligible)
    );
    assert_eq!(
        h.suspension_child(&suspension(&g, 99, 19, 99)),
        Err(Error::Ineligible)
    );
    // A tampered target breaks the proposer's signature.
    let mut bytes = s.to_bytes();
    bytes[72] ^= 1;
    assert!(
        h.suspension_child(&SignedSuspension::from_bytes(&bytes).unwrap())
            .is_err()
    );
    // Short quorum, and a certificate built on another chain.
    assert_eq!(
        h.apply_certified_suspension(&s, &cert(&g, child, &seven[..6])),
        Err(Error::Ineligible)
    );
    let mut stale = v1(&g, child, &seven, vec![]);
    stale.chain_digest = [9; 32];
    assert_eq!(
        h.apply_certified_suspension(&s, &stale),
        Err(Error::ChainMismatch)
    );
    assert_eq!(snapshot(&h), before);
    assert!(h.reported_keys().is_empty());

    // Applied once: the signed frame names the old head after it applies.
    let certificate = cert(&g, child, &seven);
    h.apply_certified_suspension(&s, &certificate).unwrap();
    assert_eq!(
        h.apply_certified_suspension(&s, &certificate),
        Err(Error::StaleProposal)
    );
}

#[test]
fn the_guard_refuses_a_suspension_that_would_stall_the_group() {
    assert_eq!(SUSPENSION_RESERVED_OFFLINE, 1);
    // Ten members need seven. Each report spends the budget of three; one is reserved for an
    // outage, so two reports are allowed and the third is refused.
    let mut g = ten();
    for target in [19, 18] {
        g = suspended(g, 10, target, &[10, 11, 12, 13, 14, 15, 16]);
    }
    let third = suspension(&g, 10, 17, 10);
    assert_eq!(g.suspension_child(&third), Err(Error::WouldStall));
    // The refusal changed nothing and the group can still move.
    let child = g.policy_child(Policy::Majority).unwrap();
    g.apply_certified_policy_change(
        Policy::Majority,
        &cert(&g, child, &[10, 11, 12, 13, 14, 15, 16]),
    )
    .unwrap();

    // Seven members need five: the budget is two, one reserved, so one report only.
    let seven = suspended(group(), 10, 16, &FIVE);
    assert_eq!(
        seven.suspension_child(&suspension(&seven, 10, 15, 10)),
        Err(Error::WouldStall)
    );
    // Groups of five or fewer cannot suspend anyone by agreement: they have no budget to spend.
    for size in 4..=5u8 {
        let small = VouchedGroup::new(7, (10..10 + size).map(key), Policy::InviterOnly);
        assert_eq!(
            small.suspension_child(&suspension(&small, 10, 11, 10)),
            Err(Error::WouldStall),
            "size {size}"
        );
    }
}

#[test]
fn a_reported_key_cannot_rotate_invite_or_serve_as_a_recovery_witness() {
    let g = suspended(group(), 10, 16, &FIVE);
    let r = rotation(&g, 16, 50);
    assert_eq!(g.rotation_child(&r), Err(Error::Ineligible));
    assert_eq!(g.invite(key(16), key(60)).err(), Some(Error::Ineligible));
    assert_eq!(
        g.enrollment_commitment(key(10), [key(11), key(16)], [1; 32]),
        Err(Error::Ineligible)
    );
    assert_eq!(
        g.enrollment_commitment(key(16), [key(11), key(12)], [1; 32]),
        Err(Error::Ineligible)
    );
    // An unreported member still can.
    assert!(g.invite(key(10), key(60)).is_ok());
    assert!(
        g.enrollment_commitment(key(10), [key(11), key(12)], [1; 32])
            .is_ok()
    );
}

#[test]
fn a_reported_key_that_leaves_never_returns() {
    let mut g = suspended(group(), 10, 16, &FIVE);
    let (member, context, signature) = departure(&g, 16);
    let child = g.departure_child(member, context, signature).unwrap();
    g.apply_certified_departure(member, context, signature, &cert(&g, child, &FIVE))
        .unwrap();
    assert!(g.membership(key(16)).is_none());
    assert!(g.retired.contains(&key(16)));
    assert!(g.reported_keys().contains(&key(16)));
    assert_eq!(g.invite(key(10), key(16)).err(), Some(Error::Ineligible));
}

#[test]
fn replicas_converge_and_a_lagging_replica_catches_up() {
    let base = ten();
    let a = suspended(base.clone(), 10, 19, &[10, 11, 12, 13, 14, 15, 16]);
    let b = suspended(base.clone(), 11, 19, &[10, 11, 12, 13, 14, 15, 16]);
    // Two proposers for one target reach the same chain.
    assert_eq!(a.rotation_context(), b.rotation_context());
    assert_eq!(a.chain_digest(), b.chain_digest());
    let mut lagging = base;
    assert_eq!(lagging.catch_up(&a), CatchUp::Applied);
    assert_eq!(lagging.reported_keys(), a.reported_keys());
    assert_eq!(lagging.chain_digest(), a.chain_digest());
}

#[test]
fn carried_proofs_cannot_spend_the_reserved_headroom_or_stall_the_group() {
    // Both certificates are valid for their reduced electorates. The operation must
    // additionally preserve one offline voter after its own report is applied.
    for (size, reports, target, offenders, signers) in [
        (7, vec![], 16, vec![14, 15], vec![10, 11, 12, 13]),
        (
            16,
            vec![25, 24, 23],
            22,
            vec![17, 18, 19, 20, 21],
            vec![10, 11, 12, 13, 14, 15, 16, 22],
        ),
    ] {
        let mut g = VouchedGroup::new(7, (10..10 + size).map(key), Policy::InviterOnly);
        let initial_signers: Vec<u8> = (10..21).collect();
        for report in reports {
            g = suspended(g, 10, report, &initial_signers);
        }
        let s = suspension(&g, 10, target, 10);
        let child = g.suspension_child(&s).unwrap();
        let proofs = offenders
            .into_iter()
            .map(|seed| proof_at_head(&g, seed))
            .collect();
        let certificate = v1(&g, child, &signers, proofs);
        g.verify_certificate_v1(child, &certificate).unwrap();
        let before = snapshot(&g);
        let before_reports = g.reported_keys().clone();
        assert_eq!(
            g.apply_certified_suspension(&s, &certificate),
            Err(Error::WouldStall)
        );
        assert_eq!(snapshot(&g), before);
        assert_eq!(g.reported_keys(), &before_reports);
    }
}

#[test]
fn proving_an_existing_report_does_not_spend_headroom_twice() {
    let mut g = suspended(ten(), 10, 19, &[10, 11, 12, 13, 14, 15, 16]);
    let s = suspension(&g, 10, 18, 10);
    let child = g.suspension_child(&s).unwrap();
    let certificate = v1(
        &g,
        child,
        &[10, 11, 12, 13, 14, 15],
        vec![proof_at_head(&g, 19), proof_at_head(&g, 17)],
    );
    g.apply_certified_suspension(&s, &certificate).unwrap();
    let voters = (10..20).filter(|&seed| !g.is_barred(&key(seed))).count();
    assert_eq!(
        voters,
        g.roster_quorum().unwrap() + SUSPENSION_RESERVED_OFFLINE
    );
}

#[test]
fn self_suspension_proposal_is_rejected() {
    let g = ten();
    let s = suspension(&g, 10, 10, 10);
    assert_eq!(g.suspension_child(&s), Err(Error::Ineligible));
}
