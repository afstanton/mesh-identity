#![cfg(feature = "groups")]
//! Proof-carrying certificates through the public API (W4c-2b): version-1 certificates are
//! accepted by the certified admission and ejection methods, record their proofs on the chain,
//! and survive the versioned wire envelope.

#[allow(dead_code)]
mod support;

use ed25519_dalek::SigningKey;
use mesh_identity::groups::evidence::{
    CertificateV1, EquivocationProof, RECOVERY_VETO_WINDOW_MS, RosterCertificate, RosterVote,
    SignedAdmissionConsent, SignedAdmissionVote, SignedEjectionVote, SimulatedAuthority as _,
    VersionedCertificate,
};
use mesh_identity::groups::{Error, Policy, Vote};
use mesh_identity::session::installation::Installation;
use support::{Scenario, meet};

fn sign(
    member: &Installation,
    group: u64,
    parent: [u8; 32],
    child: [u8; 32],
    round: u32,
    phase: u8,
) -> RosterVote {
    RosterVote {
        signer: member.selected(),
        signature: member.sign_group_roster_vote_unchecked(group, parent, child, round, phase),
    }
}

fn certificate(
    group: u64,
    parent: [u8; 32],
    child: [u8; 32],
    signers: &[&Installation],
) -> RosterCertificate {
    RosterCertificate {
        group,
        parent,
        child,
        round: 1,
        prepares: signers
            .iter()
            .map(|s| sign(s, group, parent, child, 1, 1))
            .collect(),
        commits: signers
            .iter()
            .map(|s| sign(s, group, parent, child, 1, 2))
            .collect(),
    }
}

/// `offender` signed two different children for the same round and phase of this parent.
fn equivocation(offender: &Installation, group: u64, parent: [u8; 32]) -> EquivocationProof {
    let statement = |child: [u8; 32]| {
        (
            child,
            offender.sign_group_roster_vote_unchecked(group, parent, child, 0, 1),
        )
    };
    EquivocationProof::new(
        offender.selected(),
        group,
        parent,
        0,
        1,
        statement([1; 32]),
        statement([2; 32]),
    )
}

/// Send a certificate through the wire envelope and back, as a peer would receive it.
fn over_the_wire(certificate: CertificateV1) -> CertificateV1 {
    let bytes = VersionedCertificate::V1(certificate).to_bytes().unwrap();
    match VersionedCertificate::from_bytes(&bytes).unwrap() {
        VersionedCertificate::V1(received) => received,
        VersionedCertificate::V0(_) => panic!("expected version 1"),
    }
}

#[test]
fn certified_ejection_accepts_a_version_one_certificate_with_a_proof() {
    let mut s = Scenario::new(301, Policy::Majority);
    let target = s.carol.selected();
    let mut ejection = s.group.propose_signed_ejection(&s.alice, target).unwrap();
    let vote = SignedEjectionVote::new(&ejection, &s.dave).unwrap();
    s.group.apply_ejection_vote(&mut ejection, &vote).unwrap();
    let (group, parent) = s.group.rotation_context();
    let child = s.group.ejection_child(&ejection).unwrap();
    let digest_before = s.group.chain_digest();
    // Eve is proven; alice, carol and dave are the three remaining eligible signers.
    let proof = equivocation(&s.eve, group, parent);
    let v1 = over_the_wire(CertificateV1 {
        certificate: certificate(group, parent, child, &[&s.alice, &s.carol, &s.dave]),
        chain_digest: digest_before,
        proofs: vec![proof],
    });

    // A certificate built on another chain is told to catch up, and nothing changes.
    let mut stale = over_the_wire(CertificateV1 {
        certificate: certificate(group, parent, child, &[&s.alice, &s.carol, &s.dave]),
        chain_digest: digest_before,
        proofs: vec![],
    });
    stale.chain_digest = [7; 32];
    assert_eq!(
        s.group.apply_certified_ejection(&ejection, &stale),
        Err(Error::ChainMismatch)
    );
    assert_eq!(s.group.rotation_context(), (group, parent));

    for peer in [&mut s.group, &mut s.alice_offline] {
        peer.apply_certified_ejection(&ejection, &v1).unwrap();
        assert!(peer.membership(target).is_none());
        assert_ne!(peer.chain_digest(), digest_before);
    }
    assert_eq!(s.group.chain_digest(), s.alice_offline.chain_digest());
}

#[test]
fn certified_admission_accepts_a_version_one_certificate_with_a_proof() {
    let mut s = Scenario::new(302, Policy::Majority);
    let (alice, bob) = (s.alice.selected(), s.bob.selected());
    meet(&mut s.alice, &mut s.bob, 1, &mut s.rng);
    let mut invitation = s.group.invite(alice, bob).unwrap();
    let voucher = s.group.vouch(&invitation, &s.alice, [alice], 100).unwrap();
    let consent = SignedAdmissionConsent::new(&invitation, &s.bob).unwrap();
    s.group
        .apply_admission_consent(&mut invitation, &consent)
        .unwrap();
    for voter in [&s.dave, &s.eve] {
        let vote = SignedAdmissionVote::new(&invitation, voter, Vote::Approve).unwrap();
        s.group
            .apply_admission_vote(&mut invitation, &vote)
            .unwrap();
    }
    let (group, parent) = s.group.rotation_context();
    let child = s.group.admission_child(&invitation, &voucher).unwrap();
    let before = s.group.chain_digest();
    let v1 = over_the_wire(CertificateV1 {
        certificate: certificate(group, parent, child, &[&s.alice, &s.carol, &s.dave]),
        chain_digest: before,
        proofs: vec![equivocation(&s.eve, group, parent)],
    });
    s.group
        .apply_certified_admission(&invitation, voucher, &v1)
        .unwrap();
    assert!(s.group.membership(bob).is_some());
    assert_ne!(s.group.chain_digest(), before);
}

/// Recovery shares the verification and recording path with rotation; this runs it end to end.
/// The lost key equivocated, so the certificate that recovers its replacement carries the proof
/// against it: the old key is not counted, the replacement is a fresh voter with no proof.
#[test]
fn certified_recovery_accepts_a_version_one_certificate_with_a_proof_against_the_old_key() {
    let mut s = Scenario::new(303, Policy::InviterOnly);
    let old = s.carol.selected();
    let tenure = s.group.membership(old).unwrap();
    s.group
        .enroll_recovery(old, [s.alice.selected(), s.dave.selected()])
        .unwrap();
    let replacement = s
        .carol
        .add_identity(SigningKey::generate(&mut s.rng))
        .unwrap();
    s.carol.select(replacement, 21).unwrap();
    meet(&mut s.alice, &mut s.carol, 21, &mut s.rng);
    meet(&mut s.dave, &mut s.carol, 21, &mut s.rng);
    let mut request = s.group.request_recovery(old, replacement).unwrap();
    let consent = s.group.recovery_consent(&request, &s.carol).unwrap();
    s.group
        .apply_recovery_consent(&mut request, &consent)
        .unwrap();
    for witness in [&s.alice, &s.dave] {
        let approval = s.group.recovery_approval(&request, witness).unwrap();
        s.group
            .apply_recovery_decision(&mut request, &approval)
            .unwrap();
    }
    s.group.advance_time(RECOVERY_VETO_WINDOW_MS);

    let (group, parent) = s.group.rotation_context();
    let child = s.group.recovery_child(&request).unwrap();
    // The old key signed two different children at this parent.
    s.carol.select(old, 22).unwrap();
    let proof = equivocation(&s.carol, group, parent);
    let digest_before = s.group.chain_digest();
    let honest = [&s.alice, &s.dave, &s.eve];

    // With the old key proven, three eligible members need all three; two do not suffice.
    let two = over_the_wire(CertificateV1 {
        certificate: certificate(group, parent, child, &[&s.alice, &s.dave]),
        chain_digest: digest_before,
        proofs: vec![equivocation(&s.carol, group, parent)],
    });
    let mut short = s.group.clone();
    assert_eq!(
        short.apply_certified_recovery(&request, &two),
        Err(Error::Ineligible)
    );
    assert_eq!(short.rotation_context(), (group, parent));

    let with_proof = over_the_wire(CertificateV1 {
        certificate: certificate(group, parent, child, &honest),
        chain_digest: digest_before,
        proofs: vec![proof],
    });
    let without_proof = over_the_wire(CertificateV1 {
        certificate: certificate(group, parent, child, &honest),
        chain_digest: digest_before,
        proofs: vec![],
    });
    let (mut a, mut b) = (s.group.clone(), s.group.clone());
    a.apply_certified_recovery(&request, &with_proof).unwrap();
    b.apply_certified_recovery(&request, &without_proof)
        .unwrap();
    for peer in [&a, &b] {
        assert_eq!(peer.membership(replacement), Some(tenure));
        assert!(peer.membership(old).is_none());
        assert_eq!(peer.rotation_context(), (group, child));
    }
    // Same child, different chains: only the first recorded the proof against the old key.
    assert_ne!(a.chain_digest(), b.chain_digest());
    assert_eq!(b.chain_digest(), {
        let mut plain = s.group.clone();
        plain
            .apply_certified_recovery(&request, &without_proof)
            .unwrap();
        plain.chain_digest()
    });
    // Applied once.
    assert_eq!(
        a.apply_certified_recovery(&request, &with_proof),
        Err(Error::StaleProposal)
    );
}
