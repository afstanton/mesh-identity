//! W4c-2a: verification of version-1 certificates with real keys and real signatures
//! Version 1 certificate verification tests. Verification only; nothing is applied.

use super::proof::{CarriedProof, EquivocationProof};
use super::wire::{CertificateV1, VersionedCertificate, chain_digest};
use super::{Error, Key, RosterCertificate, RosterVote, VouchedGroup};
use crate::session::installation::group_roster_vote_message;
use ed25519_dalek::{Signer, SigningKey};
use std::collections::BTreeSet;

const CHILD: [u8; 32] = [5; 32];

pub(super) fn signing(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub(super) fn key(seed: u8) -> Key {
    signing(seed).verifying_key().to_bytes()
}

/// Seven members, seeds 10 to 16. Quorum is 5 of 7, or 4 of 6 with one proven key.
pub(super) fn group() -> VouchedGroup {
    VouchedGroup::new(7, (10..17).map(key), crate::groups::Policy::InviterOnly)
}

fn votes(g: &VouchedGroup, seeds: &[u8], phase: u8) -> Vec<RosterVote> {
    let (group, parent) = g.rotation_context();
    let message = group_roster_vote_message(group, parent, CHILD, 0, phase);
    seeds
        .iter()
        .map(|&seed| RosterVote {
            signer: key(seed),
            signature: signing(seed).sign(&message).to_bytes(),
        })
        .collect()
}

fn base(g: &VouchedGroup, prepare: &[u8], commit: &[u8]) -> RosterCertificate {
    // The codec needs equal counts; the verifier takes whatever it is given.
    let (group, parent) = g.rotation_context();
    RosterCertificate {
        group,
        parent,
        child: CHILD,
        round: 0,
        prepares: votes(g, prepare, 1),
        commits: votes(g, commit, 2),
    }
}

pub(super) fn proof_at_head(g: &VouchedGroup, seed: u8) -> EquivocationProof {
    let (group, parent) = g.rotation_context();
    let sign = |child: [u8; 32]| {
        let message = group_roster_vote_message(group, parent, child, 0, 1);
        (child, signing(seed).sign(&message).to_bytes())
    };
    EquivocationProof::new(key(seed), group, parent, 0, 1, sign([1; 32]), sign([2; 32]))
}

pub(super) fn digest_of(g: &VouchedGroup) -> [u8; 32] {
    let (group, parent) = g.rotation_context();
    chain_digest(group, parent, g.inherited_proof_keys())
}

fn v1(g: &VouchedGroup, seeds: &[u8], proofs: Vec<EquivocationProof>) -> CertificateV1 {
    CertificateV1 {
        certificate: base(g, seeds, seeds),
        chain_digest: digest_of(g),
        proofs,
    }
}

#[test]
fn chain_digest_has_a_fixed_vector_and_depends_only_on_the_set() {
    let set = BTreeSet::from([[1u8; 32], [2u8; 32]]);
    let digest = chain_digest(7, [3; 32], &set);
    // Independently computed with SHA-256 over the documented byte layout.
    assert_eq!(
        digest,
        <[u8; 32]>::try_from(
            (0..32)
                .map(|i| u8::from_str_radix(
                    &"9c1d53775dce0c70c4118b2caa69666a81c7f56def3ed318eb967182d1d644cc"
                        [i * 2..i * 2 + 2],
                    16
                )
                .unwrap())
                .collect::<Vec<_>>()
        )
        .unwrap()
    );
    let reordered = BTreeSet::from([[2u8; 32], [1u8; 32]]);
    assert_eq!(digest, chain_digest(7, [3; 32], &reordered));
    assert_ne!(digest, chain_digest(8, [3; 32], &set));
    assert_ne!(digest, chain_digest(7, [4; 32], &set));
    assert_ne!(
        digest,
        chain_digest(7, [3; 32], &BTreeSet::from([[1u8; 32]]))
    );
    assert_ne!(digest, chain_digest(7, [3; 32], &BTreeSet::new()));
}

#[test]
fn without_proofs_version_one_matches_version_zero() {
    let g = group();
    let quorum = [10, 11, 12, 13, 14];
    assert_eq!(
        g.verify_certificate_v1(CHILD, &v1(&g, &quorum, vec![])),
        Ok(vec![])
    );
    assert_eq!(
        g.verify_roster_certificate(CHILD, &base(&g, &quorum, &quorum)),
        Ok(())
    );
    let short = [10, 11, 12, 13];
    assert_eq!(
        g.verify_certificate_v1(CHILD, &v1(&g, &short, vec![])),
        Err(Error::Ineligible)
    );
    assert_eq!(
        g.verify_roster_certificate(CHILD, &base(&g, &short, &short)),
        Err(Error::Ineligible)
    );
}

#[test]
fn an_inherited_proof_lowers_the_quorum_and_the_digest_must_match() {
    let mut g = group();
    g.mark_suspect(key(16)).unwrap();
    // Six eligible: four reach the quorum.
    let four = [10, 11, 12, 13];
    assert_eq!(
        g.verify_certificate_v1(CHILD, &v1(&g, &four, vec![])),
        Ok(vec![])
    );
    assert_eq!(
        g.verify_roster_certificate(CHILD, &base(&g, &four, &four)),
        Ok(())
    );
    // A certificate built on the empty chain does not match this one.
    let mut stale = v1(&g, &four, vec![]);
    let (group, parent) = g.rotation_context();
    stale.chain_digest = chain_digest(group, parent, &BTreeSet::new());
    assert_eq!(
        g.verify_certificate_v1(CHILD, &stale),
        Err(Error::ChainMismatch)
    );
}

#[test]
fn new_proofs_lower_the_electorate_and_the_same_signers_fail_without_them() {
    let g = group();
    let four = [10, 11, 12, 13];
    // Without the proof four of seven is short of five.
    assert_eq!(
        g.verify_certificate_v1(CHILD, &v1(&g, &four, vec![])),
        Err(Error::Ineligible)
    );
    // With a proof against key 16, six are eligible and four are enough.
    let proof = proof_at_head(&g, 16);
    let carried = g
        .verify_certificate_v1(CHILD, &v1(&g, &four, vec![proof.clone()]))
        .unwrap();
    assert_eq!(carried, vec![CarriedProof::Equivocation(Box::new(proof))]);
}

#[test]
fn a_vote_from_a_newly_proven_key_is_rejected() {
    let g = group();
    let signers = [10, 11, 12, 13, 16];
    let proof = proof_at_head(&g, 16);
    assert_eq!(
        g.verify_certificate_v1(CHILD, &v1(&g, &signers, vec![proof])),
        Err(Error::Ineligible)
    );
}

#[test]
fn each_proof_flaw_is_rejected_and_each_control_passes() {
    let g = group();
    let four = [10, 11, 12, 13];
    let run =
        |proof: EquivocationProof| g.verify_certificate_v1(CHILD, &v1(&g, &four, vec![proof]));
    assert!(run(proof_at_head(&g, 16)).is_ok(), "control");

    let mut wrong_parent = proof_at_head(&g, 16);
    wrong_parent.parent = [0; 32];
    assert_eq!(run(wrong_parent), Err(Error::Ineligible));

    let mut wrong_group = proof_at_head(&g, 16);
    wrong_group.group += 1;
    assert_eq!(run(wrong_group), Err(Error::Ineligible));

    // Signed by a key that is not a member.
    assert_eq!(run(proof_at_head(&g, 99)), Err(Error::Ineligible));

    let mut tampered = proof_at_head(&g, 16);
    tampered.first.1[0] ^= 1;
    assert_eq!(run(tampered), Err(Error::Ineligible));

    let mut same = proof_at_head(&g, 16);
    same.second = same.first;
    assert_eq!(run(same), Err(Error::Ineligible));
}

#[test]
fn a_proof_for_an_already_inherited_key_is_rejected_as_redundant() {
    let mut g = group();
    g.mark_suspect(key(16)).unwrap();
    let four = [10, 11, 12, 13];
    let redundant = proof_at_head(&g, 16);
    assert_eq!(
        g.verify_certificate_v1(CHILD, &v1(&g, &four, vec![redundant])),
        Err(Error::Ineligible)
    );
    // The same proof twice in one certificate is rejected too.
    let g = group();
    let twice = vec![proof_at_head(&g, 16), proof_at_head(&g, 16)];
    assert_eq!(
        g.verify_certificate_v1(CHILD, &v1(&g, &four, twice)),
        Err(Error::Ineligible)
    );
}

#[test]
fn a_digest_mismatch_is_reported_before_proofs_or_votes_are_judged() {
    let g = group();
    let mut bad = v1(&g, &[10], vec![]);
    bad.chain_digest = [0; 32];
    assert_eq!(
        g.verify_certificate_v1(CHILD, &bad),
        Err(Error::ChainMismatch)
    );
    // Wrong scope and wrong child are still checked first.
    let mut other_child = v1(&g, &[10, 11, 12, 13, 14], vec![]);
    other_child.certificate.child = [6; 32];
    assert_eq!(
        g.verify_certificate_v1(CHILD, &other_child),
        Err(Error::Ineligible)
    );
    let mut other_parent = v1(&g, &[10, 11, 12, 13, 14], vec![]);
    other_parent.certificate.parent = [0; 32];
    assert_eq!(
        g.verify_certificate_v1(CHILD, &other_parent),
        Err(Error::StaleProposal)
    );
}

#[test]
fn each_phase_is_judged_on_its_own() {
    let g = group();
    let five = [10, 11, 12, 13, 14];
    let four = [10, 11, 12, 13];
    let mut cert = v1(&g, &five, vec![]);
    cert.certificate.commits = votes(&g, &four, 2);
    assert_eq!(
        g.verify_certificate_v1(CHILD, &cert),
        Err(Error::Ineligible)
    );
    // A prepare signature reused as a commit does not verify.
    let mut reused = v1(&g, &five, vec![]);
    reused.certificate.commits = votes(&g, &five, 1);
    assert_eq!(
        g.verify_certificate_v1(CHILD, &reused),
        Err(Error::Ineligible)
    );
    // A repeated signer is not counted twice.
    let mut repeated = v1(&g, &four, vec![]);
    repeated.certificate.prepares.push(RosterVote {
        signer: key(10),
        signature: signing(10)
            .sign(&group_roster_vote_message(
                g.rotation_context().0,
                g.rotation_context().1,
                CHILD,
                0,
                1,
            ))
            .to_bytes(),
    });
    assert_eq!(
        g.verify_certificate_v1(CHILD, &repeated),
        Err(Error::Ineligible)
    );
}

#[test]
fn verification_changes_no_state() {
    let mut g = group();
    g.mark_suspect(key(16)).unwrap();
    let before = (
        g.revision(),
        g.inherited_proof_keys().clone(),
        g.suspect.clone(),
        g.group.electorate_size(),
        g.rotation_context(),
    );
    let new_proof = proof_at_head(&g, 15);
    let _ = g.verify_certificate_v1(CHILD, &v1(&g, &[10, 11, 12], vec![new_proof]));
    let _ = g.verify_certificate_v1(CHILD, &v1(&g, &[10, 11, 12, 13], vec![]));
    let after = (
        g.revision(),
        g.inherited_proof_keys().clone(),
        g.suspect.clone(),
        g.group.electorate_size(),
        g.rotation_context(),
    );
    assert_eq!(before, after);
}

#[test]
fn a_certificate_survives_the_codec_and_still_verifies() {
    let g = group();
    let four = [10, 11, 12, 13];
    let original = v1(&g, &four, vec![proof_at_head(&g, 16)]);
    let bytes = VersionedCertificate::V1(original).to_bytes().unwrap();
    let VersionedCertificate::V1(decoded) = VersionedCertificate::from_bytes(&bytes).unwrap()
    else {
        panic!("expected version 1");
    };
    assert_eq!(decoded.proofs.len(), 1);
    assert!(g.verify_certificate_v1(CHILD, &decoded).is_ok());
}
