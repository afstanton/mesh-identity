use super::*;
use crate::session::installation::Installation;
use ed25519_dalek::SigningKey;

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn pk(seed: u8) -> Key {
    sk(seed).verifying_key().to_bytes()
}
fn who(seed: u8) -> Installation {
    Installation::new(sk(seed))
}

fn view(group: u64, seeds: &[u8]) -> SourceView {
    SourceView {
        group,
        history: [group as u8; 32],
        head_revision: 3,
        head_digest: [group as u8 + 50; 32],
        members: seeds
            .iter()
            .map(|s| SourceMember {
                key: pk(*s),
                tenure_start: 0,
                current: true,
                ended: None,
                successor_of: None,
            })
            .collect(),
        marks: Vec::new(),
    }
}

fn terms() -> FormationTerms {
    FormationTerms {
        rules: crate::groups::Policy::InviterOnly,
        disclosure: Disclosure::Full,
        context: [4; 32],
    }
}

/// Two sources {1,2,3} and {3,4,5}; a formation of 1, 3 and 4.
fn setup() -> (SourceView, SourceView, Formation) {
    let a = view(1, &[1, 2, 3]);
    let b = view(2, &[3, 4, 5]);
    let p = propose(&[a.clone(), b.clone()], terms()).unwrap();
    let f = Formation::new(p, &[pk(1), pk(3), pk(4)]).unwrap();
    (a, b, f)
}

fn sign_all(f: &mut Formation, a: &SourceView, b: &SourceView) {
    f.add_consent(f.consent_from(&who(1), std::slice::from_ref(a)).unwrap())
        .unwrap();
    f.add_consent(f.consent_from(&who(3), &[a.clone(), b.clone()]).unwrap())
        .unwrap();
    f.add_consent(f.consent_from(&who(4), std::slice::from_ref(b)).unwrap())
        .unwrap();
}

#[test]
fn the_group_exists_only_when_everyone_in_the_final_roster_has_signed() {
    let (a, b, mut f) = setup();
    assert_eq!(f.complete().err(), Some(FormationError::Incomplete));
    assert_eq!(f.missing().len(), 3);
    assert!(
        f.add_consent(f.consent_from(&who(1), std::slice::from_ref(&a)).unwrap())
            .unwrap()
    );
    assert!(
        f.add_consent(f.consent_from(&who(3), std::slice::from_ref(&b)).unwrap())
            .unwrap()
    );
    assert_eq!(f.missing(), vec![pk(4)]);
    assert_eq!(f.complete().err(), Some(FormationError::Incomplete));
    assert!(
        f.add_consent(f.consent_from(&who(4), &[b]).unwrap())
            .unwrap()
    );
    let formed = f.complete().unwrap();
    assert_eq!(formed.group.id(), f.group_id());
    assert_eq!(formed.group.revision(), 0);
    for seed in [1, 3, 4] {
        assert!(formed.group.membership(pk(seed)).is_some());
    }
    // Candidates who did not make the final roster are not in the group.
    for seed in [2, 5] {
        assert!(formed.group.membership(pk(seed)).is_none());
    }
}

#[test]
fn every_participant_builds_the_identical_group_and_a_replay_adds_nothing() {
    let (a, b, mut f) = setup();
    sign_all(&mut f, &a, &b);
    // A second participant opens the same formation from the same bytes and gathers the
    // consents in another order.
    let p = propose(&[b.clone(), a.clone()], terms()).unwrap();
    let mut g = Formation::new(p, &[pk(4), pk(3), pk(1), pk(1)]).unwrap();
    for seed in [4u8, 1, 3] {
        let consent = f.consents_for_test(seed);
        assert!(g.add_consent(consent).unwrap());
        // Redelivery changes nothing.
        assert!(!g.add_consent(consent).unwrap());
    }
    let one = f.complete().unwrap();
    let two = g.complete().unwrap();
    assert_eq!(f.binding(), g.binding());
    assert_eq!(one.group.id(), two.group.id());
    assert_eq!(one.genesis_digest, two.genesis_digest);
    assert_eq!(one.group.to_bytes().unwrap(), two.group.to_bytes().unwrap());
    // Completing again gives the same group, not another.
    let again = f.complete().unwrap();
    assert_eq!(
        again.group.to_bytes().unwrap(),
        one.group.to_bytes().unwrap()
    );
}

#[test]
fn consent_to_one_formation_is_useless_for_any_other() {
    let (a, b, mut f) = setup();
    sign_all(&mut f, &a, &b);
    let old = f.consents_for_test(1);
    let proposal = f.proposal().clone();
    // A decliner is dropped: same proposal, smaller roster.
    let mut smaller = Formation::new(proposal.clone(), &[pk(1), pk(3)]).unwrap();
    assert_ne!(smaller.binding(), f.binding());
    assert_ne!(smaller.group_id(), f.group_id());
    assert_eq!(smaller.add_consent(old), Err(FormationError::BadSignature));
    // New rules, new context, other disclosure, a moved source: each is a fresh formation.
    let changes: Vec<FormationTerms> = vec![
        FormationTerms {
            rules: crate::groups::Policy::Majority,
            ..terms()
        },
        FormationTerms {
            context: [5; 32],
            ..terms()
        },
        FormationTerms {
            disclosure: Disclosure::Minimal,
            ..terms()
        },
    ];
    for changed in changes {
        let p = propose(&[a.clone(), b.clone()], changed).unwrap();
        let mut g = Formation::new(p, &[pk(1), pk(3), pk(4)]).unwrap();
        assert_eq!(g.add_consent(old), Err(FormationError::BadSignature));
    }
    let mut moved = a.clone();
    moved.head_revision += 1;
    let p = propose(&[moved, b.clone()], terms()).unwrap();
    let mut g = Formation::new(p, &[pk(1), pk(3), pk(4)]).unwrap();
    assert_eq!(g.add_consent(old), Err(FormationError::BadSignature));
}

#[test]
fn forged_misattributed_and_foreign_consents_are_refused() {
    let (a, _b, mut f) = setup();
    let good = f.consent_from(&who(1), std::slice::from_ref(&a)).unwrap();
    // Someone else's signature under this signer's name.
    let other = f.consent_from(&who(3), std::slice::from_ref(&a)).unwrap();
    let forged = FormationConsent {
        signer: pk(1),
        signature: other.signature,
    };
    assert_eq!(f.add_consent(forged), Err(FormationError::BadSignature));
    // A damaged signature.
    let mut bytes = good.to_bytes();
    bytes[40] ^= 1;
    assert_eq!(
        f.add_consent(FormationConsent::from_bytes(&bytes).unwrap()),
        Err(FormationError::BadSignature)
    );
    // A signer outside the final roster, even with a valid signature of its own.
    let outsider = {
        let p = propose(&[view(1, &[1, 2, 3]), view(2, &[3, 4, 5])], terms()).unwrap();
        let all = Formation::new(p, &[pk(1), pk(2), pk(3), pk(4)]).unwrap();
        all.consent_from(&who(2), std::slice::from_ref(&a)).unwrap()
    };
    assert_eq!(f.add_consent(outsider), Err(FormationError::NotInRoster));
    assert_eq!(
        f.consent_from(&who(2), std::slice::from_ref(&a)).err(),
        Some(FormationError::Cannot)
    );
    assert_eq!(
        FormationConsent::from_bytes(&bytes[..95]),
        Err(FormationError::Malformed)
    );
    assert!(f.missing().len() == 3);
    // The honest one still goes through.
    assert_eq!(f.add_consent(good), Ok(true));
}

#[test]
fn the_roster_must_be_a_nonempty_subset_of_the_candidates_within_the_cap() {
    let (a, b, _) = setup();
    let p = propose(&[a, b], terms()).unwrap();
    assert_eq!(
        Formation::new(p.clone(), &[]).err(),
        Some(FormationError::BadRoster)
    );
    assert_eq!(
        Formation::new(p.clone(), &[pk(1), pk(9)]).err(),
        Some(FormationError::NotCandidate)
    );
    assert!(Formation::new(p, &[pk(5)]).is_ok());
}

#[test]
fn a_stale_or_foreign_source_is_declined_not_signed() {
    let (a, b, f) = setup();
    let mut moved = a.clone();
    moved.head_revision += 1;
    // The participant's own group moved on since the proposal was made.
    assert_eq!(
        f.consent_from(&who(1), &[moved.clone()]).err(),
        Some(FormationError::StaleSource)
    );
    // Holding the right source as well as a moved copy of another named group still fails.
    assert_eq!(
        f.consent_from(&who(3), &[b.clone(), moved]).err(),
        Some(FormationError::StaleSource)
    );
    // No source at all, or an unrelated group.
    assert_eq!(
        f.consent_from(&who(1), &[]).err(),
        Some(FormationError::StaleSource)
    );
    assert_eq!(
        f.consent_from(&who(1), &[view(77, &[1])]).err(),
        Some(FormationError::StaleSource)
    );
    assert!(f.consent_from(&who(1), &[a]).is_ok());
}

#[test]
fn hidden_sources_still_bind_the_participants_exact_source() {
    let a = view(1, &[1, 2]);
    let b = view(2, &[3]);
    let t = FormationTerms {
        disclosure: Disclosure::Minimal,
        ..terms()
    };
    let p = propose(&[a.clone(), b.clone()], t).unwrap();
    let mut f = Formation::new(p, &[pk(1), pk(3)]).unwrap();
    f.add_consent(f.consent_from(&who(1), std::slice::from_ref(&a)).unwrap())
        .unwrap();
    let mut moved = b.clone();
    moved.head_digest = [0; 32];
    assert_eq!(
        f.consent_from(&who(3), &[moved]).err(),
        Some(FormationError::StaleSource)
    );
    f.add_consent(f.consent_from(&who(3), &[b]).unwrap())
        .unwrap();
    assert!(f.complete().is_ok());
}

#[test]
fn a_gated_device_cannot_consent() {
    let (a, _b, f) = setup();
    let mut gated = who(1);
    gated.gate_voting();
    assert_eq!(
        f.consent_from(&gated, &[a]).err(),
        Some(FormationError::Cannot)
    );
}

#[test]
fn the_formed_group_uses_exactly_the_agreed_rules_and_ids() {
    let (a, b, mut f) = setup();
    sign_all(&mut f, &a, &b);
    let formed = f.complete().unwrap();
    // Neither source's id is reused, and a different binding gives a different id.
    assert_ne!(formed.group.id(), 1);
    assert_ne!(formed.group.id(), 2);
    let majority = FormationTerms {
        rules: crate::groups::Policy::Majority,
        ..terms()
    };
    let p = propose(&[a, b], majority).unwrap();
    let other = Formation::new(p, &[pk(1), pk(3), pk(4)]).unwrap();
    assert_ne!(other.group_id(), f.group_id());
    assert_eq!(formed.group.policy(), crate::groups::Policy::InviterOnly);
}

impl Formation {
    fn consents_for_test(&self, seed: u8) -> FormationConsent {
        self.consents[&pk(seed)]
    }
}

#[test]
fn rules_that_could_never_make_progress_for_the_roster_are_refused() {
    let a = view(1, &[1, 2, 3]);
    let fixed = |n: usize| FormationTerms {
        rules: crate::groups::Policy::Fixed(std::num::NonZeroUsize::new(n).unwrap()),
        ..terms()
    };
    let p = propose(std::slice::from_ref(&a), fixed(3)).unwrap();
    assert!(Formation::new(p.clone(), &[pk(1), pk(2), pk(3)]).is_ok());
    assert_eq!(
        Formation::new(p, &[pk(1), pk(2)]).err(),
        Some(FormationError::BadRoster)
    );
    let p = propose(&[a], fixed(1)).unwrap();
    assert!(Formation::new(p, &[pk(1)]).is_ok());
}

#[test]
fn stored_terms_reconstruct_the_agreed_genesis_for_every_policy() {
    use crate::groups::{Policy, Supermajority};
    use std::num::NonZeroUsize;
    let a = view(1, &[1, 2, 3]);
    for rules in [
        Policy::InviterOnly,
        Policy::Fixed(NonZeroUsize::new(3).unwrap()),
        Policy::Majority,
        Policy::TwoThirds,
        Policy::Supermajority(Supermajority::new(3, 4).unwrap()),
        Policy::Unanimous,
    ] {
        for disclosure in [Disclosure::Full, Disclosure::Minimal] {
            let p = propose(
                std::slice::from_ref(&a),
                FormationTerms {
                    rules,
                    disclosure,
                    ..terms()
                },
            )
            .unwrap();
            let encoded = p.to_bytes();
            let mut f = Formation::new(p, &[pk(1), pk(2), pk(3)]).unwrap();
            for seed in 1..=3 {
                let c = f
                    .consent_from(&who(seed), std::slice::from_ref(&a))
                    .unwrap();
                f.add_consent(c).unwrap();
            }
            assert_eq!(
                agreed_genesis(&encoded, f.roster()).unwrap(),
                f.complete().unwrap().group.genesis_bytes().unwrap()
            );
            let prefix_len = 38 + rules.encode().len();
            for end in 0..prefix_len {
                assert_eq!(Proposal::stored_rules(&encoded[..end]), None);
            }
            for (offset, invalid) in [(0, b'X'), (4, 2), (37, 255), (38, 255)] {
                let mut malformed = encoded.clone();
                malformed[offset] = invalid;
                assert_eq!(Proposal::stored_rules(&malformed), None);
            }
        }
    }
}
