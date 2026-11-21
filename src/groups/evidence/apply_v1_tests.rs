//! W4c-2b: applying version-1 certificates at the certified transitions, with real keys and
//! signatures. Rotation and departure are
//! driven from raw signing keys here; ejection and admission go through the public API in
//! `tests/proof_carrying_certificates.rs`.

use super::certificate_v1_tests::{digest_of, group, key, proof_at_head, signing};
use super::proof::{CarriedProof, EquivocationProof};
use super::wire::CertificateV1;
use super::{Error, Key, RosterCertificate, RosterVote, SignedRotation, VouchedGroup};
use crate::session::installation::{
    group_departure_message, group_roster_vote_message, group_rotation_message,
};
use ed25519_dalek::Signer;
use std::collections::BTreeSet;

pub(super) fn cert(g: &VouchedGroup, child: [u8; 32], seeds: &[u8]) -> RosterCertificate {
    let (group_id, parent) = g.rotation_context();
    let votes = |phase: u8| -> Vec<RosterVote> {
        let message = group_roster_vote_message(group_id, parent, child, 1, phase);
        seeds
            .iter()
            .map(|&seed| RosterVote {
                signer: key(seed),
                signature: signing(seed).sign(&message).to_bytes(),
            })
            .collect()
    };
    RosterCertificate {
        group: group_id,
        parent,
        child,
        round: 1,
        prepares: votes(1),
        commits: votes(2),
    }
}

pub(super) fn v1(
    g: &VouchedGroup,
    child: [u8; 32],
    seeds: &[u8],
    proofs: Vec<EquivocationProof>,
) -> CertificateV1 {
    CertificateV1 {
        certificate: cert(g, child, seeds),
        chain_digest: g.chain_digest(),
        proofs,
    }
}

pub(super) fn rotation(g: &VouchedGroup, old: u8, new: u8) -> SignedRotation {
    let (group_id, parent) = g.rotation_context();
    let message = group_rotation_message(group_id, parent, key(old), key(new));
    SignedRotation::new(
        (group_id, parent),
        key(old),
        key(new),
        [old, new].map(|seed| signing(seed).sign(&message).to_bytes()),
    )
}

/// (departing seed) -> (member, context, signature)
pub(super) fn departure(g: &VouchedGroup, seed: u8) -> (Key, (u64, [u8; 32]), [u8; 64]) {
    let member = key(seed);
    let context = g.departure_context(member).unwrap();
    let message = group_departure_message(context.0, context.1, member);
    (member, context, signing(seed).sign(&message).to_bytes())
}

pub(super) fn snapshot(g: &VouchedGroup) -> (u64, [u8; 32], BTreeSet<Key>, BTreeSet<Key>, usize) {
    (
        g.revision(),
        g.rotation_context().1,
        g.inherited_proof_keys().clone(),
        g.suspect.clone(),
        g.group.electorate_size(),
    )
}

const FOUR: [u8; 4] = [11, 12, 13, 14];

#[test]
fn rotation_applies_a_version_one_certificate_and_records_its_proofs() {
    let mut g = group();
    let proof = proof_at_head(&g, 16);
    let signed = rotation(&g, 10, 50);
    let child = g.rotation_child(&signed).unwrap();

    // Four of seven is short of the quorum without the proof.
    let mut control = g.clone();
    assert_eq!(
        control.apply_certified_rotation(&signed, &cert(&g, child, &FOUR)),
        Err(Error::Ineligible)
    );
    assert_eq!(snapshot(&control), snapshot(&g));

    let certificate = v1(&g, child, &FOUR, vec![proof.clone()]);
    g.apply_certified_rotation(&signed, &certificate).unwrap();
    assert!(g.membership(key(50)).is_some() && g.membership(key(10)).is_none());
    assert_eq!(g.inherited_proof_keys(), &BTreeSet::from([key(16)]));
    assert!(g.suspect.contains(&key(16)));
    assert!(!g.suspect.contains(&key(50)));
    assert_eq!(
        g.history.carried,
        vec![CarriedProof::Equivocation(Box::new(proof))]
    );
    // Seven members, one proven.
    assert_eq!(g.group.electorate_size(), 6);
    // The same operation does not apply twice.
    assert_eq!(
        g.apply_certified_rotation(&signed, &certificate),
        Err(Error::StaleProposal)
    );
}

#[test]
fn departure_applies_a_version_one_certificate_and_records_its_proofs() {
    let mut g = group();
    let (member, context, signature) = departure(&g, 10);
    let child = g.departure_child(member, context, signature).unwrap();
    let proof = proof_at_head(&g, 16);
    g.apply_certified_departure(
        member,
        context,
        signature,
        &v1(&g, child, &FOUR, vec![proof]),
    )
    .unwrap();
    assert!(g.membership(member).is_none());
    assert_eq!(g.inherited_proof_keys(), &BTreeSet::from([key(16)]));
    assert_eq!(g.group.electorate_size(), 5);
}

#[test]
fn a_certificate_that_proves_and_removes_the_same_key_leaves_it_retired_and_not_excluded() {
    let mut g = group();
    let (member, context, signature) = departure(&g, 16);
    let child = g.departure_child(member, context, signature).unwrap();
    let proof = proof_at_head(&g, 16);
    // Key 16 signs only its own departure; the proof removes it from the count.
    let certificate = v1(&g, child, &[10, 11, 12, 13], vec![proof]);
    g.apply_certified_departure(member, context, signature, &certificate)
        .unwrap();
    assert!(g.membership(member).is_none());
    assert!(g.retired.contains(&member));
    assert!(!g.suspect.contains(&member));
    assert!(g.inherited_proof_keys().contains(&member));
    // Its identity number is free to reuse and must not stay excluded.
    assert!(g.group.excluded.is_empty());
    assert_eq!(g.group.electorate_size(), 6);
}

#[test]
fn a_failed_verification_changes_nothing() {
    let mut g = group();
    let signed = rotation(&g, 10, 50);
    let child = g.rotation_child(&signed).unwrap();
    let before = snapshot(&g);
    let proof = proof_at_head(&g, 16);

    let mut mismatched = v1(&g, child, &FOUR, vec![proof.clone()]);
    mismatched.chain_digest = [0; 32];
    assert_eq!(
        g.apply_certified_rotation(&signed, &mismatched),
        Err(Error::ChainMismatch)
    );

    let mut forged = proof_at_head(&g, 16);
    forged.first.1[0] ^= 1;
    assert_eq!(
        g.apply_certified_rotation(&signed, &v1(&g, child, &FOUR, vec![forged])),
        Err(Error::Ineligible)
    );

    let from_a_proven_signer = v1(&g, child, &[11, 12, 13, 16], vec![proof]);
    assert_eq!(
        g.apply_certified_rotation(&signed, &from_a_proven_signer),
        Err(Error::Ineligible)
    );
    assert_eq!(snapshot(&g), before);
    assert!(g.history.carried.is_empty());
}

#[test]
fn two_certificates_for_one_operation_each_apply_once_with_their_own_proof_sets() {
    let g = group();
    let signed = rotation(&g, 10, 50);
    let child = g.rotation_child(&signed).unwrap();
    let rich = v1(&g, child, &FOUR, vec![proof_at_head(&g, 16)]);
    let plain = v1(&g, child, &[11, 12, 13, 14, 15], vec![]);

    let (mut with_proof, mut without) = (g.clone(), g.clone());
    with_proof.apply_certified_rotation(&signed, &rich).unwrap();
    without.apply_certified_rotation(&signed, &plain).unwrap();
    // Same child, different chains.
    assert_eq!(with_proof.rotation_context(), without.rotation_context());
    assert_eq!(
        with_proof.inherited_proof_keys(),
        &BTreeSet::from([key(16)])
    );
    assert!(without.inherited_proof_keys().is_empty());
    for peer in [&mut with_proof, &mut without] {
        assert_eq!(
            peer.apply_certified_rotation(&signed, &rich),
            Err(Error::StaleProposal)
        );
    }
    // The digest distinguishes the proof histories; catch_up rejects their ambiguous ancestry.
    assert_ne!(digest_of(&with_proof), digest_of(&without));
}

#[test]
fn a_descendant_inherits_the_proofs_and_cannot_drop_them() {
    let mut g = group();
    let signed = rotation(&g, 10, 50);
    let child = g.rotation_child(&signed).unwrap();
    g.apply_certified_rotation(&signed, &v1(&g, child, &FOUR, vec![proof_at_head(&g, 16)]))
        .unwrap();

    // The next operation from the new head: key 11 departs.
    let (member, context, signature) = departure(&g, 11);
    let next = g.departure_child(member, context, signature).unwrap();
    // Seven members, one proven: six eligible, quorum 4.
    let on_old_chain = CertificateV1 {
        certificate: cert(&g, next, &[12, 13, 14, 15]),
        chain_digest: super::wire::chain_digest(
            context.0,
            g.rotation_context().1,
            &BTreeSet::new(),
        ),
        proofs: vec![],
    };
    assert_eq!(
        g.apply_certified_departure(member, context, signature, &on_old_chain),
        Err(Error::ChainMismatch)
    );
    // A vote from the inherited offender is still refused.
    let with_offender = v1(&g, next, &[12, 13, 14, 16], vec![]);
    assert_eq!(
        g.apply_certified_departure(member, context, signature, &with_offender),
        Err(Error::Ineligible)
    );
    // Four honest signers on the right chain pass at the smaller quorum.
    let good = v1(&g, next, &[12, 13, 14, 15], vec![]);
    g.apply_certified_departure(member, context, signature, &good)
        .unwrap();
    assert_eq!(g.inherited_proof_keys(), &BTreeSet::from([key(16)]));
    assert_eq!(g.group.electorate_size(), 5);
}

#[test]
fn version_zero_certificates_still_apply_with_an_inherited_proof() {
    let mut g = group();
    g.mark_suspect(key(16)).unwrap();
    let (member, context, signature) = departure(&g, 10);
    let child = g.departure_child(member, context, signature).unwrap();
    // Six eligible, quorum four: a plain version-0 certificate works as before.
    g.apply_certified_departure(member, context, signature, &cert(&g, child, &FOUR))
        .unwrap();
    assert!(g.membership(member).is_none());
}

#[test]
fn rotation_rejects_a_proof_against_its_own_old_key_without_changing_state() {
    let mut g = group();
    let signed = rotation(&g, 16, 50);
    let child = g.rotation_child(&signed).unwrap();
    let certificate = v1(&g, child, &[10, 11, 12, 13], vec![proof_at_head(&g, 16)]);
    // The certificate's signatures, proof and reduced quorum are valid. The operation
    // itself must reject using that very proof to rotate a compromised key clean.
    assert!(g.verify_certificate_v1(child, &certificate).is_ok());
    let before = snapshot(&g);
    let old_tenure = g.membership(key(16));
    assert_eq!(
        g.apply_certified_rotation(&signed, &certificate),
        Err(Error::Ineligible)
    );
    assert_eq!(snapshot(&g), before);
    assert_eq!(g.membership(key(16)), old_tenure);
    assert!(g.membership(key(50)).is_none());
    assert!(g.history.carried.is_empty());
    assert!(g.predecessors.is_empty());
}

/// The same certified operation can produce two valid proof-history variants.
fn certified_rotation_variants() -> (VouchedGroup, VouchedGroup) {
    let base = group();
    let signed = rotation(&base, 10, 50);
    let child = base.rotation_child(&signed).unwrap();
    let mut richer = base.clone();
    let mut poorer = base.clone();
    richer
        .apply_certified_rotation(
            &signed,
            &v1(&base, child, &FOUR, vec![proof_at_head(&base, 16)]),
        )
        .unwrap();
    poorer
        .apply_certified_rotation(&signed, &v1(&base, child, &[11, 12, 13, 14, 15], vec![]))
        .unwrap();
    assert_eq!(richer.rotation_context(), poorer.rotation_context());
    assert_ne!(richer.chain_digest(), poorer.chain_digest());
    (richer, poorer)
}

#[test]
fn equal_operation_heads_with_different_proof_histories_are_not_already_current() {
    let (mut richer, mut poorer) = certified_rotation_variants();
    let before_richer = snapshot(&richer);
    let before_poorer = snapshot(&poorer);
    assert_eq!(richer.catch_up(&poorer), super::CatchUp::ConflictingHistory);
    assert_eq!(poorer.catch_up(&richer), super::CatchUp::ConflictingHistory);
    assert_eq!(snapshot(&richer), before_richer);
    assert_eq!(snapshot(&poorer), before_poorer);
}

#[test]
fn catch_up_rejects_a_descendant_of_a_different_proof_history() {
    let (mut richer, mut poorer) = certified_rotation_variants();
    let poorer_parent = poorer.clone();
    let (member, context, signature) = departure(&poorer, 11);
    let child = poorer.departure_child(member, context, signature).unwrap();
    let certificate = v1(&poorer, child, &[12, 13, 14, 15, 16], vec![]);
    poorer
        .apply_certified_departure(member, context, signature, &certificate)
        .unwrap();
    let before = snapshot(&richer);
    assert_eq!(richer.catch_up(&poorer), super::CatchUp::ConflictingHistory);
    assert_eq!(snapshot(&richer), before);
    assert!(richer.inherited_proof_keys().contains(&key(16)));
    assert!(richer.suspect.contains(&key(16)));
    assert!(richer.membership(key(11)).is_some());

    // Actual descendants on the accepted proof history still catch up normally.
    let mut consistent = richer.clone();
    let (member, context, signature) = departure(&consistent, 11);
    let child = consistent
        .departure_child(member, context, signature)
        .unwrap();
    let certificate = v1(&consistent, child, &[12, 13, 14, 15], vec![]);
    consistent
        .apply_certified_departure(member, context, signature, &certificate)
        .unwrap();
    assert_eq!(
        consistent.catch_up(&poorer_parent),
        super::CatchUp::ConflictingHistory
    );
    assert_eq!(richer.catch_up(&consistent), super::CatchUp::Applied);
    assert!(richer.inherited_proof_keys().contains(&key(16)));
    assert!(richer.suspect.contains(&key(16)));
    assert!(richer.membership(key(11)).is_none());
}

#[test]
fn catch_up_compares_proofs_for_departed_keys_and_preserves_their_retirement() {
    let base = group();
    let (member, context, signature) = departure(&base, 16);
    let child = base.departure_child(member, context, signature).unwrap();
    let mut richer = base.clone();
    let mut poorer = base.clone();
    richer
        .apply_certified_departure(
            member,
            context,
            signature,
            &v1(
                &base,
                child,
                &[10, 11, 12, 13],
                vec![proof_at_head(&base, 16)],
            ),
        )
        .unwrap();
    poorer
        .apply_certified_departure(
            member,
            context,
            signature,
            &v1(&base, child, &[10, 11, 12, 13, 14], vec![]),
        )
        .unwrap();
    assert_eq!(richer.rotation_context(), poorer.rotation_context());
    assert!(richer.membership(member).is_none());
    assert!(poorer.membership(member).is_none());
    assert!(richer.retired.contains(&member));
    assert!(!poorer.retired.contains(&member));
    assert_eq!(richer.catch_up(&poorer), super::CatchUp::ConflictingHistory);
    assert!(richer.retired.contains(&member));
    assert!(richer.inherited_proof_keys().contains(&member));
}

#[test]
fn rotation_chain_accepts_version_one_and_mixed_steps_atomically() {
    use super::CertificateRef;
    let base = group();
    // Step one: a plain version-0 certificate (five of seven).
    let first = rotation(&base, 10, 50);
    let first_child = base.rotation_child(&first).unwrap();
    let first_cert = cert(&base, first_child, &[11, 12, 13, 14, 15]);
    // Step two is built on the state after step one and carries a proof against 16.
    let mut scratch = base.clone();
    scratch
        .apply_certified_rotation(&first, &first_cert)
        .unwrap();
    let second = rotation(&scratch, 11, 51);
    let second_child = scratch.rotation_child(&second).unwrap();
    let second_cert = v1(
        &scratch,
        second_child,
        &[12, 13, 14, 15],
        vec![proof_at_head(&scratch, 16)],
    );

    let mixed = [
        (&first, CertificateRef::from(&first_cert)),
        (&second, CertificateRef::from(&second_cert)),
    ];
    let mut g = base.clone();
    g.apply_certified_rotation_chain(&mixed).unwrap();
    assert!(g.membership(key(50)).is_some() && g.membership(key(51)).is_some());
    assert!(g.inherited_proof_keys().contains(&key(16)));
    assert_eq!(g.chain_digest(), {
        let mut direct = base.clone();
        direct
            .apply_certified_rotation(&first, &first_cert)
            .unwrap();
        direct
            .apply_certified_rotation(&second, &second_cert)
            .unwrap();
        direct.chain_digest()
    });

    // Without its proof the second step is short of quorum; the receiver is left untouched.
    let mut bad_cert = second_cert;
    bad_cert.proofs.clear();
    let mut h = base.clone();
    let before = snapshot(&h);
    assert_eq!(
        h.apply_certified_rotation_chain(&[
            (&first, CertificateRef::from(&first_cert)),
            (&second, CertificateRef::from(&bad_cert)),
        ]),
        Err(Error::Ineligible)
    );
    assert_eq!(snapshot(&h), before);
}
