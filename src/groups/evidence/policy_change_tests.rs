//! Certified policy change.

use super::apply_v1_tests::{cert, snapshot, v1};
use super::certificate_v1_tests::{digest_of, group, key, proof_at_head};
use super::{CatchUp, Error, VouchedGroup};
use crate::groups::Policy;

const FIVE: [u8; 5] = [11, 12, 13, 14, 15];

fn changed(mut g: VouchedGroup, policy: Policy) -> VouchedGroup {
    let child = g.policy_child(policy).unwrap();
    g.apply_certified_policy_change(policy, &cert(&g, child, &FIVE))
        .unwrap();
    g
}

#[test]
fn a_version_zero_certificate_changes_the_policy() {
    let base = group();
    let revision = base.revision();
    let context = base.rotation_context();
    let g = changed(base.clone(), Policy::Majority);
    assert_eq!(g.group.policy, Policy::Majority);
    assert_eq!(g.revision(), revision + 1);
    assert_ne!(g.rotation_context(), context);
    // No proofs, so the inherited set and the roster are unchanged.
    assert_eq!(g.group.electorate_size(), base.group.electorate_size());
    assert!(g.inherited_proof_keys().is_empty());
    // Same operation, same child on every replica.
    assert_eq!(
        g.rotation_context(),
        changed(base, Policy::Majority).rotation_context()
    );
}

#[test]
fn a_version_one_certificate_carries_its_proofs() {
    let mut g = group();
    let child = g.policy_child(Policy::TwoThirds).unwrap();
    // Four of seven is short without the proof against 16, and enough with it.
    let mut control = g.clone();
    assert_eq!(
        control
            .apply_certified_policy_change(Policy::TwoThirds, &cert(&g, child, &[11, 12, 13, 14])),
        Err(Error::Ineligible)
    );
    assert_eq!(snapshot(&control), snapshot(&g));
    let certificate = v1(&g, child, &[11, 12, 13, 14], vec![proof_at_head(&g, 16)]);
    g.apply_certified_policy_change(Policy::TwoThirds, &certificate)
        .unwrap();
    assert_eq!(g.group.policy, Policy::TwoThirds);
    assert!(g.inherited_proof_keys().contains(&key(16)));
    assert!(g.suspect.contains(&key(16)));
    assert_eq!(g.group.electorate_size(), 6);
}

#[test]
fn rejections_change_nothing() {
    let g = group();
    let child = g.policy_child(Policy::Majority).unwrap();
    let before = snapshot(&g);
    let mut h = g.clone();

    // The current policy is a no-op: nothing to certify.
    assert_eq!(h.policy_child(Policy::InviterOnly), Err(Error::Ineligible));
    // A certificate for a different policy's child names the wrong child.
    let other = g.policy_child(Policy::Unanimous).unwrap();
    assert_eq!(
        h.apply_certified_policy_change(Policy::Majority, &cert(&g, other, &FIVE)),
        Err(Error::Ineligible)
    );
    // Short quorum.
    assert_eq!(
        h.apply_certified_policy_change(Policy::Majority, &cert(&g, child, &[11, 12, 13, 14])),
        Err(Error::Ineligible)
    );
    // A certificate built on another chain is told to catch up.
    let mut stale = v1(&g, child, &FIVE, vec![]);
    stale.chain_digest = [9; 32];
    assert_eq!(
        h.apply_certified_policy_change(Policy::Majority, &stale),
        Err(Error::ChainMismatch)
    );
    assert_eq!(snapshot(&h), before);
    assert_eq!(h.group.policy, Policy::InviterOnly);

    // Applied once: the same certificate cannot apply again.
    let certificate = cert(&g, child, &FIVE);
    h.apply_certified_policy_change(Policy::Majority, &certificate)
        .unwrap();
    let after = snapshot(&h);
    assert!(
        h.apply_certified_policy_change(Policy::Majority, &certificate)
            .is_err()
    );
    assert_eq!(snapshot(&h), after);
}

#[test]
fn replicas_converge_and_catch_up_across_a_policy_change() {
    let base = group();
    let a = changed(base.clone(), Policy::Majority);
    let b = changed(base.clone(), Policy::Majority);
    assert_eq!(digest_of(&a), digest_of(&b));
    let mut lagging = base;
    assert_eq!(lagging.catch_up(&a), CatchUp::Applied);
    assert_eq!(lagging.group.policy, Policy::Majority);
    assert_eq!(lagging.rotation_context(), a.rotation_context());
}

#[test]
fn a_chain_of_changes() {
    let g = changed(changed(group(), Policy::Majority), Policy::Unanimous);
    assert_eq!(g.group.policy, Policy::Unanimous);
    // Changing back is an ordinary change, not a replay.
    let back = changed(g, Policy::InviterOnly);
    assert_eq!(back.group.policy, Policy::InviterOnly);
}

#[test]
fn formation_consent_distinguishes_authenticated_proof_histories() {
    use super::certificate_v1_tests::signing;
    use crate::groups::merge::{
        Disclosure, Formation, FormationError, FormationTerms, SourceView, propose,
    };
    use crate::session::installation::Installation;

    let base = group();
    let child = base.policy_child(Policy::Majority).unwrap();
    let mut plain = base.clone();
    let mut proven = base.clone();
    plain
        .apply_certified_policy_change(Policy::Majority, &cert(&base, child, &FIVE))
        .unwrap();
    proven
        .apply_certified_policy_change(
            Policy::Majority,
            &v1(&base, child, &FIVE, vec![proof_at_head(&base, 16)]),
        )
        .unwrap();
    assert_eq!(plain.rotation_context(), proven.rotation_context());
    assert_ne!(plain.chain_digest(), proven.chain_digest());
    let old = SourceView::from_group(&plain);
    let current = SourceView::from_group(&proven);
    assert_ne!(old, current);
    let installation = Installation::new(signing(10));
    for disclosure in [Disclosure::Full, Disclosure::Minimal] {
        let terms = FormationTerms {
            rules: Policy::InviterOnly,
            disclosure,
            context: [42; 32],
        };
        let mut original = Formation::new(
            propose(std::slice::from_ref(&old), terms).unwrap(),
            &[key(10)],
        )
        .unwrap();
        let mut revised = Formation::new(
            propose(std::slice::from_ref(&current), terms).unwrap(),
            &[key(10)],
        )
        .unwrap();
        assert_ne!(original.binding(), revised.binding());
        assert_eq!(
            original.consent_from(&installation, std::slice::from_ref(&current)),
            Err(FormationError::StaleSource)
        );
        let consent = original
            .consent_from(&installation, std::slice::from_ref(&old))
            .unwrap();
        assert_eq!(
            revised.add_consent(consent),
            Err(FormationError::BadSignature)
        );
        original.add_consent(consent).unwrap();
        assert!(original.complete().is_ok());
    }
}
