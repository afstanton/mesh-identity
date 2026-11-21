#![cfg(feature = "groups")]
//! G3b-3: what formation reveals. Nothing is sent by the library, identities stay apart, hidden
//! sources stay hidden in what the handle keeps, and events and errors carry no keys.

mod support;
use support::world::*;

use mesh_identity::groups::Policy;
use mesh_identity::groups::handle::*;
use mesh_identity::groups::merge::*;

fn terms(disclosure: Disclosure) -> FormationTerms {
    FormationTerms {
        rules: Policy::InviterOnly,
        disclosure,
        context: [8; 32],
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// A formation of 1 and 2 over group A {1,2,3}; both consent.
fn formed(w: &mut World, disclosure: Disclosure) -> (Formation, SourceView) {
    let group = w.group;
    let view = w.h(1).source_view(group).unwrap();
    let mut f = Formation::new(
        propose(std::slice::from_ref(&view), terms(disclosure)).unwrap(),
        &[pk(1), pk(2)],
    )
    .unwrap();
    for seed in [1u8, 2] {
        let c = w.h(seed).consent_to_formation(&f).unwrap();
        f.add_consent(c).unwrap();
    }
    (f, view)
}

#[test]
fn the_library_sends_nothing_for_a_formation() {
    let mut w = World::new(&[2, 3]);
    let (f, _) = formed(&mut w, Disclosure::Full);
    for seed in [1u8, 2] {
        w.h(seed).adopt_formation(&f).unwrap();
        let (token, _) = w.h(seed).save(30).unwrap();
        w.h(seed).confirm_saved(token);
        assert!(w.h(seed).take_outgoing().is_empty());
    }
}

#[test]
fn a_second_local_identity_neither_sees_nor_can_use_the_formed_group() {
    let mut w = World::new(&[2, 3]);
    let (f, _) = formed(&mut w, Disclosure::Full);
    w.h(2).adopt_formation(&f).unwrap();
    let id = f.group_id();
    // The same handle holds another identity of the same person's device.
    let other = w.h(2).installation_mut().add_identity(sk(20)).unwrap();
    w.h(2).installation_mut().select(other, 40).unwrap();
    assert!(w.h(2).group(id).is_none());
    assert!(w.h(2).source_view(id).is_none());
    assert_eq!(
        w.h(2).consent_to_formation(&f),
        Err(HandleError::Formation(FormationError::Cannot))
    );
    assert_eq!(w.h(2).adopt_formation(&f), Err(HandleError::Ineligible));
    assert!(w.h(2).formed_from(id).is_none());
    w.h(2).installation_mut().select(pk(2), 41).unwrap();
    assert!(w.h(2).group(id).is_some());
}

#[test]
fn hidden_sources_stay_hidden_in_what_the_handle_keeps() {
    let mut w = World::new(&[2, 3]);
    let (f, source) = formed(&mut w, Disclosure::Minimal);
    w.h(2).adopt_formation(&f).unwrap();
    let kept = w.h(2).formed_from(f.group_id()).unwrap().to_vec();
    assert!(!contains(&kept, &source.group.to_be_bytes()));
    assert!(!contains(&kept, &source.history));
    assert!(!contains(&kept, &source.head_digest));
    // The same agreement with full disclosure does name the source.
    let (full, _) = formed(&mut w, Disclosure::Full);
    assert!(contains(
        &full.proposal().to_bytes(),
        &source.group.to_be_bytes()
    ));
    // Hidden or not, the group saves and restores.
    let (token, blob) = w.h(2).save(30).unwrap();
    w.h(2).confirm_saved(token);
    assert!(GroupHandle::restore(&blob, [sk(2)]).is_ok());
}

#[test]
fn events_and_errors_from_formation_carry_no_keys() {
    let mut w = World::new(&[2, 3]);
    let (f, _) = formed(&mut w, Disclosure::Full);
    let mut shown = Vec::new();
    w.h(1).adopt_formation(&f).unwrap();
    let (token, _) = w.h(1).save(30).unwrap();
    shown.push(format!("{:?}", w.h(1).confirm_saved(token)));
    shown.push(format!("{:?}", w.h(1).adopt_formation(&f)));
    shown.push(format!("{:?}", w.h(3).adopt_formation(&f)));
    shown.push(format!("{:?}", w.h(3).consent_to_formation(&f)));
    let source = w.group;
    w.h(1).leave(source, 40).unwrap();
    shown.push(format!("{:?}", w.h(1).consent_to_formation(&f)));
    for text in shown {
        for seed in [1u8, 2, 3, 9] {
            assert!(!text.contains(&format!("{:?}", pk(seed))), "{text}");
        }
    }
}
