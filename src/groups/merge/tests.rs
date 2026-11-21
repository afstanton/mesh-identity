use super::*;
use ed25519_dalek::SigningKey;

fn k(seed: u16) -> Key {
    let mut bytes = [7u8; 32];
    bytes[0] = seed as u8;
    bytes[1] = (seed >> 8) as u8;
    SigningKey::from_bytes(&bytes).verifying_key().to_bytes()
}

fn terms() -> FormationTerms {
    FormationTerms {
        rules: Policy::InviterOnly,
        disclosure: Disclosure::Full,
        context: [9; 32],
    }
}

fn member(seed: u16, start: u64) -> SourceMember {
    SourceMember {
        key: k(seed),
        tenure_start: start,
        current: true,
        ended: None,
        successor_of: None,
    }
}

fn gone(seed: u16, start: u64, end: TenureEnd) -> SourceMember {
    SourceMember {
        current: false,
        ended: Some(end),
        ..member(seed, start)
    }
}

fn view(group: u64, members: Vec<SourceMember>) -> SourceView {
    SourceView {
        group,
        history: [group as u8; 32],
        head_revision: 10,
        head_digest: [group as u8 + 100; 32],
        members,
        marks: Vec::new(),
    }
}

fn keys(seeds: &[u16]) -> Vec<Key> {
    let mut keys: Vec<Key> = seeds.iter().map(|s| k(*s)).collect();
    keys.sort();
    keys
}

#[test]
fn candidates_are_the_union_of_current_members() {
    let a = view(1, vec![member(1, 0), member(2, 0)]);
    let b = view(2, vec![member(2, 0), member(3, 4)]);
    let p = propose(&[a, b], terms()).unwrap();
    assert_eq!(p.candidates, keys(&[1, 2, 3]));
    assert_eq!(p.sources.len(), 2);
    assert!(p.excluded.is_empty() && p.carried.is_empty());
}

#[test]
fn a_removal_in_one_source_does_not_remove_a_key_another_still_has() {
    let a = view(1, vec![member(1, 0), gone(2, 0, TenureEnd::Ejected)]);
    let b = view(2, vec![member(2, 0)]);
    let p = propose(&[a, b], terms()).unwrap();
    assert_eq!(p.candidates, keys(&[1, 2]));
    // Not excluded either: it is a candidate through the second source.
    assert!(p.excluded.is_empty());
}

#[test]
fn a_key_removed_everywhere_is_excluded_and_listed_with_its_sources() {
    let a = view(1, vec![member(1, 0), gone(2, 0, TenureEnd::Departed)]);
    let b = view(2, vec![member(3, 0), gone(2, 3, TenureEnd::Ejected)]);
    let p = propose(&[a, b], terms()).unwrap();
    assert_eq!(p.candidates, keys(&[1, 3]));
    assert_eq!(p.excluded.len(), 2);
    assert!(p.excluded.iter().all(|e| e.key == k(2)));
    let ends: BTreeSet<_> = p.excluded.iter().map(|e| e.end).collect();
    assert_eq!(
        ends,
        BTreeSet::from([TenureEnd::Departed, TenureEnd::Ejected])
    );
}

#[test]
fn a_later_readmission_is_not_erased_by_an_earlier_removal() {
    let a = view(
        1,
        vec![gone(2, 1, TenureEnd::Ejected), member(2, 6), member(1, 0)],
    );
    let p = propose(&[a], terms()).unwrap();
    assert_eq!(p.candidates, keys(&[1, 2]));
    assert!(p.excluded.is_empty());
    // The reverse order is a removal after readmission: the key is not a member.
    let b = view(
        2,
        vec![member(2, 1), gone(2, 6, TenureEnd::Departed), member(1, 0)],
    );
    // A current tenure that is not the latest is an inconsistent view.
    assert_eq!(propose(&[b], terms()), Err(ProposeError::BadView));
    let c = view(
        3,
        vec![
            gone(2, 1, TenureEnd::Departed),
            gone(2, 6, TenureEnd::Ejected),
            member(1, 0),
        ],
    );
    let p = propose(&[c], terms()).unwrap();
    assert_eq!(p.candidates, keys(&[1]));
    assert_eq!(p.excluded.len(), 1);
    assert_eq!(p.excluded[0].end, TenureEnd::Ejected);
}

#[test]
fn rotation_never_links_identities_across_sources() {
    let mut new = member(11, 5);
    new.successor_of = Some(k(1));
    let a = view(1, vec![gone(1, 0, TenureEnd::Rotated), new]);
    let b = view(2, vec![member(1, 0)]);
    let p = propose(&[a, b], terms()).unwrap();
    // Both keys are current somewhere, so both are candidates; nothing ties them together.
    assert_eq!(p.candidates, keys(&[1, 11]));
}

#[test]
fn a_key_and_its_predecessor_cannot_both_be_current_in_one_source() {
    let mut new = member(11, 5);
    new.successor_of = Some(k(1));
    let a = view(1, vec![member(1, 0), new]);
    assert_eq!(propose(&[a], terms()), Err(ProposeError::BadView));
}

#[test]
fn marks_are_carried_as_evidence_and_remove_no_one() {
    let mut a = view(1, vec![member(1, 0), member(2, 0)]);
    a.marks = vec![
        SourceMark {
            key: k(2),
            kind: MarkKind::Suspect,
            at: 4,
        },
        SourceMark {
            key: k(2),
            kind: MarkKind::Suspect,
            at: 4,
        },
        SourceMark {
            key: k(8),
            kind: MarkKind::Reported,
            at: 2,
        },
    ];
    let p = propose(&[a], terms()).unwrap();
    assert_eq!(p.candidates, keys(&[1, 2]));
    // Duplicates collapse; a mark on a non-candidate is still shown.
    assert_eq!(p.carried.len(), 2);
    assert!(
        p.carried
            .iter()
            .any(|m| m.key == k(8) && m.kind == MarkKind::Reported)
    );
}

#[test]
fn inconsistent_views_are_refused() {
    let head = |m: Vec<SourceMember>| view(1, m);
    // Duplicate tenure.
    assert_eq!(
        propose(&[head(vec![member(1, 0), member(1, 0)])], terms()),
        Err(ProposeError::BadView)
    );
    // Tenure past the head.
    assert_eq!(
        propose(&[head(vec![member(1, 11)])], terms()),
        Err(ProposeError::BadView)
    );
    // current flag and end disagree.
    let mut bad = member(1, 0);
    bad.ended = Some(TenureEnd::Departed);
    assert_eq!(
        propose(&[head(vec![bad])], terms()),
        Err(ProposeError::BadView)
    );
    // Not a key.
    let mut bad = member(1, 0);
    bad.key = (0u8..=255)
        .map(|n| [n; 32])
        .find(|key| VerifyingKey::from_bytes(key).is_err())
        .expect("some 32-byte string is not a curve point");
    assert_eq!(
        propose(&[head(vec![bad])], terms()),
        Err(ProposeError::BadView)
    );
    // Mark past the head.
    let mut v = head(vec![member(1, 0)]);
    v.marks = vec![SourceMark {
        key: k(1),
        kind: MarkKind::Suspect,
        at: 11,
    }];
    assert_eq!(propose(&[v], terms()), Err(ProposeError::BadView));
    // Too many tenure entries.
    let many: Vec<_> = (0..=MAX_TENURES_PER_VIEW as u64)
        .map(|i| gone(1, i, TenureEnd::Departed))
        .collect();
    let mut v = head(many);
    v.head_revision = 5000;
    assert_eq!(propose(&[v], terms()), Err(ProposeError::BadView));
}

#[test]
fn bounds_refuse_and_never_truncate() {
    let at_cap: Vec<_> = (0..MAX_MEMBERS as u16).map(|i| member(i, 0)).collect();
    assert_eq!(
        propose(&[view(1, at_cap.clone())], terms())
            .unwrap()
            .candidates
            .len(),
        192
    );
    let mut over = at_cap;
    over.push(member(500, 0));
    assert_eq!(
        propose(&[view(1, over)], terms()),
        Err(ProposeError::TooManyMembers)
    );
    // Two sources that together exceed the cap.
    let a: Vec<_> = (0..100).map(|i| member(i, 0)).collect();
    let b: Vec<_> = (100..200).map(|i| member(i, 0)).collect();
    assert_eq!(
        propose(&[view(1, a), view(2, b)], terms()),
        Err(ProposeError::TooManyMembers)
    );

    assert_eq!(propose(&[], terms()), Err(ProposeError::NoSources));
    let sources: Vec<_> = (0..=MAX_SOURCES as u64)
        .map(|g| view(g, vec![member(1, 0)]))
        .collect();
    assert_eq!(
        propose(&sources, terms()),
        Err(ProposeError::TooManySources)
    );
    assert_eq!(
        propose(
            &[view(1, vec![member(1, 0)]), view(1, vec![member(2, 0)])],
            terms()
        ),
        Err(ProposeError::DuplicateSource)
    );
    assert_eq!(
        propose(&[view(1, vec![gone(1, 0, TenureEnd::Departed)])], terms()),
        Err(ProposeError::NoCandidates)
    );
    let mut v = view(1, vec![member(1, 0)]);
    v.marks = (0..=MAX_MARKS as u64)
        .map(|i| SourceMark {
            key: k(1),
            kind: MarkKind::Suspect,
            at: i % 11,
        })
        .collect();
    v.marks.extend((0..=MAX_MARKS as u16).map(|i| SourceMark {
        key: k(i),
        kind: MarkKind::Reported,
        at: 1,
    }));
    assert_eq!(propose(&[v], terms()), Err(ProposeError::TooManyMarks));
}

#[test]
fn the_result_does_not_depend_on_the_order_of_anything() {
    let mut a = view(
        1,
        vec![member(3, 0), member(1, 0), gone(5, 0, TenureEnd::Ejected)],
    );
    a.marks = vec![
        SourceMark {
            key: k(3),
            kind: MarkKind::Suspect,
            at: 3,
        },
        SourceMark {
            key: k(1),
            kind: MarkKind::Reported,
            at: 2,
        },
    ];
    let b = view(
        2,
        vec![member(2, 0), gone(5, 2, TenureEnd::Departed), member(1, 1)],
    );
    let forward = propose(&[a.clone(), b.clone()], terms()).unwrap();
    let mut a2 = a.clone();
    a2.members.reverse();
    a2.marks.reverse();
    let mut b2 = b.clone();
    b2.members.reverse();
    let reversed = propose(&[b2, a2], terms()).unwrap();
    assert_eq!(forward.to_bytes(), reversed.to_bytes());
    assert_eq!(forward.digest(), reversed.digest());
    assert_eq!(
        propose(&[a, b], terms()).unwrap().digest(),
        forward.digest()
    );
}

#[test]
fn any_change_to_what_was_agreed_changes_the_digest() {
    let a = view(1, vec![member(1, 0), member(2, 0)]);
    let base = propose(std::slice::from_ref(&a), terms()).unwrap().digest();
    let differs = |t: FormationTerms, v: SourceView| propose(&[v], t).unwrap().digest() != base;
    assert!(differs(
        FormationTerms {
            rules: Policy::Majority,
            ..terms()
        },
        a.clone()
    ));
    assert!(differs(
        FormationTerms {
            context: [8; 32],
            ..terms()
        },
        a.clone()
    ));
    assert!(differs(
        FormationTerms {
            disclosure: Disclosure::Minimal,
            ..terms()
        },
        a.clone()
    ));
    let mut moved = a.clone();
    moved.head_revision += 1;
    assert!(differs(terms(), moved));
    let mut other_head = a.clone();
    other_head.head_digest = [0; 32];
    assert!(differs(terms(), other_head));
    let mut fewer = a.clone();
    fewer.members.pop();
    assert!(differs(terms(), fewer));
}

#[test]
fn minimal_disclosure_hides_the_source_and_is_salted_by_the_context() {
    let a = view(0x0102_0304_0506_0708, vec![member(1, 0)]);
    let full = propose(std::slice::from_ref(&a), terms())
        .unwrap()
        .to_bytes();
    let hidden_terms = FormationTerms {
        disclosure: Disclosure::Minimal,
        ..terms()
    };
    let hidden = propose(std::slice::from_ref(&a), hidden_terms).unwrap();
    let contains =
        |haystack: &[u8], needle: &[u8]| haystack.windows(needle.len()).any(|w| w == needle);
    assert!(contains(&full, &a.group.to_be_bytes()));
    assert!(!contains(&hidden.to_bytes(), &a.group.to_be_bytes()));
    assert!(!contains(&hidden.to_bytes(), &a.history));
    assert!(!contains(&hidden.to_bytes(), &a.head_digest));
    // A holder of the source recomputes the same reference; a different context gives another.
    let again = propose(std::slice::from_ref(&a), hidden_terms).unwrap();
    assert_eq!(hidden.sources, again.sources);
    let salted = propose(
        &[a],
        FormationTerms {
            context: [1; 32],
            ..hidden_terms
        },
    )
    .unwrap();
    assert_ne!(hidden.sources, salted.sources);
}

#[test]
fn one_source_is_a_proposal_too() {
    let p = propose(&[view(1, vec![member(1, 0), member(2, 0)])], terms()).unwrap();
    assert_eq!(p.candidates, keys(&[1, 2]));
    assert_eq!(&p.to_bytes()[..4], b"MSP1");
}

#[test]
fn the_encoding_is_pinned() {
    let a = view(1, vec![member(1, 0), member(2, 0)]);
    let p = propose(&[a], terms()).unwrap();
    let hex: String = p.digest().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "d5ca69422cd2de066f4b2a9564c6a6a93439976c08244ceae901fbc825fafcd4"
    );
}

#[test]
fn check_view_rejects_more_than_max_marks() {
    let mut v = view(1, vec![member(1, 0)]);
    for _ in 0..=MAX_MARKS {
        v.marks.push(SourceMark {
            key: k(1),
            kind: MarkKind::Reported,
            at: 1,
        });
    }
    assert_eq!(
        propose(&[v], terms()).err(),
        Some(ProposeError::TooManyMarks)
    );
}

#[test]
fn propose_rejects_proposals_exceeding_max_frame_bytes() {
    let mut views = Vec::new();
    for g in 1..=16u64 {
        let mut members = vec![member(1, 0)];
        for s in 100..180u16 {
            members.push(gone(s + (g as u16) * 1000, 0, TenureEnd::Departed));
        }
        views.push(view(g, members));
    }
    assert_eq!(propose(&views, terms()).err(), Some(ProposeError::TooLarge));
}
