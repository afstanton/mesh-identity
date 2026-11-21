#![cfg(feature = "groups")]
//! G3b-1: views and consents come from the handle's own groups and change nothing.

mod support;
use support::world::*;

use mesh_identity::groups::Policy;
use mesh_identity::groups::handle::*;
use mesh_identity::groups::merge::*;

fn terms() -> FormationTerms {
    FormationTerms {
        rules: Policy::InviterOnly,
        disclosure: Disclosure::Full,
        context: [6; 32],
    }
}

/// Group A {1,2,3}, group B {1,5,6}, and a formation of 1, 2, 5, 6 over their views.
fn setup() -> (World, World, Formation) {
    let mut a = World::new(&[2, 3]);
    let mut b = World::new(&[5, 6]);
    let (ga, gb) = (a.group, b.group);
    let va = a.h(1).source_view(ga).unwrap();
    let vb = b.h(1).source_view(gb).unwrap();
    let f = Formation::new(
        propose(&[va, vb], terms()).unwrap(),
        &[pk(1), pk(2), pk(5), pk(6)],
    )
    .unwrap();
    (a, b, f)
}

#[test]
fn a_view_exists_only_for_a_group_the_identity_holds() {
    let mut a = World::new(&[2, 3]);
    let group = a.group;
    let view = a.h(2).source_view(group).unwrap();
    assert_eq!(view.members.len(), 3);
    assert_eq!(view.group, group);
    assert!(a.h(2).source_view(group + 1).is_none());
    // The candidate has been invited to nothing yet, so it holds nothing.
    assert!(a.h(9).source_view(group).is_none());
    a.h(3).leave(group, 5).unwrap();
    assert!(a.h(3).source_view(group).is_none());
}

#[test]
fn every_participant_consents_from_its_own_groups_and_the_group_can_form() {
    let (mut a, mut b, mut f) = setup();
    for seed in [1u8, 2] {
        let consent = a.h(seed).consent_to_formation(&f).unwrap();
        assert!(f.add_consent(consent).unwrap());
    }
    for seed in [5u8, 6] {
        let consent = b.h(seed).consent_to_formation(&f).unwrap();
        assert!(f.add_consent(consent).unwrap());
    }
    assert!(f.is_complete());
    assert!(f.complete().is_ok());
}

#[test]
fn consenting_changes_nothing_and_stages_nothing() {
    let (mut a, _b, f) = setup();
    let group = a.group;
    let before = a.h(2).group(group).unwrap().to_bytes().unwrap();
    let ops = a.h(2).group_ids();
    let first = a.h(2).consent_to_formation(&f).unwrap();
    // Signing is repeatable and gives the same bytes; nothing is queued for the host.
    assert_eq!(a.h(2).consent_to_formation(&f).unwrap(), first);
    assert!(a.h(2).take_outgoing().is_empty());
    assert_eq!(a.h(2).group(group).unwrap().to_bytes().unwrap(), before);
    assert_eq!(a.h(2).group_ids(), ops);
}

#[test]
fn a_source_that_moved_on_is_declined() {
    let (mut a, _b, f) = setup();
    // Group A admits 9 after the proposal was made.
    a.invite_and_accept(20);
    assert!(a.pump(21, &mut Vec::new(), None).is_empty());
    assert_eq!(
        a.h(2).consent_to_formation(&f),
        Err(HandleError::Formation(FormationError::StaleSource))
    );
}

#[test]
fn a_member_who_left_the_source_cannot_consent_through_it() {
    let (mut a, _b, f) = setup();
    let group = a.group;
    a.h(2).leave(group, 5).unwrap();
    assert_eq!(
        a.h(2).consent_to_formation(&f),
        Err(HandleError::Formation(FormationError::StaleSource))
    );
}

#[test]
fn outsiders_and_gated_devices_cannot_consent() {
    let (mut a, _b, f) = setup();
    // 3 is in group A but not in the final roster.
    assert_eq!(
        a.h(3).consent_to_formation(&f),
        Err(HandleError::Formation(FormationError::Cannot))
    );
    a.h(2).installation_mut().gate_voting();
    assert_eq!(
        a.h(2).consent_to_formation(&f),
        Err(HandleError::Formation(FormationError::Cannot))
    );
}
