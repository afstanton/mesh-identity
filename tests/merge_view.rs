#![cfg(feature = "groups")]
//! G3a: a merge view built from real groups, and a formation across two of them signed by the
//! handles' own installations.

mod support;
use support::world::*;

use mesh_identity::groups::Policy;
use mesh_identity::groups::merge::*;

fn view_of(w: &mut World, seed: u8) -> SourceView {
    let group = w.group;
    SourceView::from_group(w.h(seed).group(group).unwrap())
}

#[test]
fn a_view_lists_current_members_with_the_revision_each_tenure_began() {
    let mut w = World::new(&[2, 3]);
    let before = view_of(&mut w, 1);
    assert_eq!(before.head_revision, 0);
    assert_eq!(before.members.len(), 3);
    assert!(
        before
            .members
            .iter()
            .all(|m| m.current && m.tenure_start == 0 && m.ended.is_none())
    );
    assert!(before.marks.is_empty());

    w.invite_and_accept(20);
    assert!(w.pump(21, &mut Vec::new(), None).is_empty());
    let after = view_of(&mut w, 1);
    assert_eq!(after.head_revision, 1);
    assert_eq!(after.members.len(), 4);
    let joined = after.members.iter().find(|m| m.key == pk(9)).unwrap();
    assert_eq!(joined.tenure_start, 1);
    assert!(
        after
            .members
            .iter()
            .filter(|m| m.key != pk(9))
            .all(|m| m.tenure_start == 0)
    );
    // The same group, same head: every member, and the newcomer, builds the identical view.
    for seed in [2, 3, 9] {
        assert_eq!(view_of(&mut w, seed), after, "member {seed}");
    }
    // The head moved, so the earlier view no longer names this group at its head.
    assert_ne!(before.head_digest, after.head_digest);
    assert_eq!(before.history, after.history);
    assert_eq!(before.group, after.group);
}

#[test]
fn two_real_groups_form_a_third_that_touches_neither() {
    let mut a = World::new(&[2, 3]);
    let mut b = World::new(&[5, 6]);
    let (va, vb) = (view_of(&mut a, 1), view_of(&mut b, 1));
    assert_ne!(va.group, vb.group);
    let ga = a.group;
    let a_before = a.h(1).group(ga).unwrap().to_bytes().unwrap();
    let terms = FormationTerms {
        rules: Policy::InviterOnly,
        disclosure: Disclosure::Full,
        context: [3; 32],
    };
    let proposal = propose(&[va.clone(), vb.clone()], terms).unwrap();
    // First group {1,2,3}, second {1,5,6}: five candidates; 3 stays out of the final roster.
    assert_eq!(proposal.candidates.len(), 5);
    let roster = [pk(1), pk(2), pk(5), pk(6)];
    let mut f = Formation::new(proposal, &roster).unwrap();
    // Each signs with its own handle's installation and the views of the groups it is in.
    for (seed, views) in [
        (1u8, vec![va.clone(), vb.clone()]),
        (2, vec![va.clone()]),
        (5, vec![vb.clone()]),
        (6, vec![vb.clone()]),
    ] {
        let installation = if seed >= 5 {
            b.h(seed).installation()
        } else {
            a.h(seed).installation()
        };
        let consent = f.consent_from(installation, &views).unwrap();
        assert!(f.add_consent(consent).unwrap());
    }
    let formed = f.complete().unwrap();
    assert_eq!(formed.group.revision(), 0);
    for key in roster {
        assert!(formed.group.membership(key).is_some());
    }
    assert!(formed.group.membership(pk(3)).is_none());
    // The source group is exactly as it was.
    assert_eq!(a.h(1).group(ga).unwrap().to_bytes().unwrap(), a_before);
}
