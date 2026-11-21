#![cfg(feature = "groups")]
//! G3b-2: a formed group is adopted through the handle like an imported genesis, with its
//! proposal kept, and survives save and restore.

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

struct Setup {
    a: World,
    b: World,
    views: Vec<SourceView>,
}

/// Group A {1,2,3}, group B {1,5,6}. The formation is of 1, 2, 5, 6.
fn setup() -> Setup {
    let mut a = World::new(&[2, 3]);
    let mut b = World::new(&[5, 6]);
    let (ga, gb) = (a.group, b.group);
    let views = vec![
        a.h(1).source_view(ga).unwrap(),
        b.h(1).source_view(gb).unwrap(),
    ];
    Setup { a, b, views }
}

const ROSTER: [u8; 4] = [1, 2, 5, 6];

fn open(views: &[SourceView], roster: &[u8]) -> Formation {
    let keys: Vec<_> = roster.iter().map(|s| pk(*s)).collect();
    Formation::new(propose(views, terms()).unwrap(), &keys).unwrap()
}

fn consent_of(s: &mut Setup, seed: u8, f: &Formation) -> FormationConsent {
    if seed >= 5 {
        s.b.h(seed).consent_to_formation(f).unwrap()
    } else {
        s.a.h(seed).consent_to_formation(f).unwrap()
    }
}

/// Every participant's own copy of the completed formation.
fn completed(s: &mut Setup) -> Formation {
    let mut f = open(&s.views, &ROSTER);
    for seed in ROSTER {
        let c = consent_of(s, seed, &f);
        f.add_consent(c).unwrap();
    }
    f
}

fn handle(s: &mut Setup, seed: u8) -> &mut GroupHandle {
    if seed >= 5 { s.b.h(seed) } else { s.a.h(seed) }
}

#[test]
fn every_participant_adopts_the_same_group_and_its_event_waits_for_the_save() {
    let mut s = setup();
    let f = completed(&mut s);
    let id = f.group_id();
    let mut bytes = Vec::new();
    for seed in ROSTER {
        let h = handle(&mut s, seed);
        let op = h.adopt_formation(&f).unwrap();
        // Held in memory at once; the event waits for the confirmed write.
        assert!(h.group_ids().contains(&id));
        let (token, _) = h.save(30).unwrap();
        assert!(h.take_outgoing().is_empty());
        assert_eq!(h.confirm_saved(token), vec![Event::GroupFormed(id)]);
        assert_eq!(h.op_state(op), Some(OpState::Completed));
        assert_eq!(h.formed_from(id).unwrap(), &f.proposal().to_bytes()[..]);
        bytes.push(h.group(id).unwrap().to_bytes().unwrap());
    }
    assert!(bytes.windows(2).all(|pair| pair[0] == pair[1]));
    // Roster is exactly the final roster, at revision 0.
    let group = handle(&mut s, 1).group(id).unwrap();
    assert_eq!(group.revision(), 0);
    assert!(group.membership(pk(3)).is_none());
    for seed in ROSTER {
        assert!(group.membership(pk(seed)).is_some());
    }
}

#[test]
fn the_source_groups_are_untouched_and_leaving_the_new_group_leaves_them_alone() {
    let mut s = setup();
    let f = completed(&mut s);
    let (ga, gb) = (s.a.group, s.b.group);
    let before_a = s.a.h(1).group(ga).unwrap().to_bytes().unwrap();
    let before_b = s.b.h(1).group(gb).unwrap().to_bytes().unwrap();
    s.a.h(1).adopt_formation(&f).unwrap();
    assert_eq!(s.a.h(1).group(ga).unwrap().to_bytes().unwrap(), before_a);
    s.a.h(1).leave(f.group_id(), 40).unwrap();
    assert!(s.a.h(1).group(f.group_id()).is_none());
    assert_eq!(s.a.h(1).group(ga).unwrap().to_bytes().unwrap(), before_a);
    assert_eq!(s.b.h(1).group(gb).unwrap().to_bytes().unwrap(), before_b);
}

#[test]
fn adopting_twice_or_after_leaving_is_refused_and_never_makes_a_second_group() {
    let mut s = setup();
    let f = completed(&mut s);
    let h = s.a.h(2);
    h.adopt_formation(&f).unwrap();
    assert_eq!(h.adopt_formation(&f), Err(HandleError::Duplicate));
    assert_eq!(h.group_ids().len(), 2);
    h.leave(f.group_id(), 40).unwrap();
    assert_eq!(h.adopt_formation(&f), Err(HandleError::Duplicate));
}

#[test]
fn an_incomplete_formation_and_a_non_member_cannot_adopt() {
    let mut s = setup();
    let mut partial = open(&s.views, &ROSTER);
    let c = consent_of(&mut s, 1, &partial);
    partial.add_consent(c).unwrap();
    assert_eq!(
        s.a.h(1).adopt_formation(&partial),
        Err(HandleError::Formation(FormationError::Incomplete))
    );
    // 3 holds source A but is not in the final roster of a completed formation.
    let f = completed(&mut s);
    assert_eq!(s.a.h(3).adopt_formation(&f), Err(HandleError::Ineligible));
    assert_eq!(s.a.h(3).group_ids().len(), 1);
}

#[test]
fn a_crash_before_the_save_loses_the_adoption_and_a_repeat_gives_the_same_group() {
    let mut s = setup();
    let f = completed(&mut s);
    let id = f.group_id();
    let (token, before) = s.a.h(2).save(30).unwrap();
    s.a.h(2).confirm_saved(token);
    s.a.h(2).adopt_formation(&f).unwrap();
    let first = s.a.h(2).group(id).unwrap().to_bytes().unwrap();
    let (_unwritten, _) = s.a.h(2).save(31).unwrap();
    // The write failed: the host restores the last blob it holds.
    let restored = GroupHandle::restore(&before, [sk(2)]).unwrap();
    let slot = s.a.handles.iter().position(|(seed, _)| *seed == 2).unwrap();
    s.a.handles[slot].1 = restored;
    assert!(s.a.h(2).group(id).is_none());
    s.a.h(2).adopt_formation(&f).unwrap();
    assert_eq!(s.a.h(2).group(id).unwrap().to_bytes().unwrap(), first);
}

#[test]
fn a_restart_after_the_save_keeps_the_group_and_where_it_came_from() {
    let mut s = setup();
    let f = completed(&mut s);
    let id = f.group_id();
    s.a.h(2).adopt_formation(&f).unwrap();
    let (token, blob) = s.a.h(2).save(30).unwrap();
    s.a.h(2).confirm_saved(token);
    let again = GroupHandle::restore(&blob, [sk(2)]).unwrap();
    assert_eq!(
        again.group(id).unwrap().to_bytes().unwrap(),
        s.a.h(2).group(id).unwrap().to_bytes().unwrap()
    );
    assert_eq!(again.formed_from(id).unwrap(), &f.proposal().to_bytes()[..]);
    assert_eq!(again.group_ids().len(), 2);
}

/// Edit a field of the first `formed` record in a saved blob.
fn tamper(blob: &[u8], edit: impl Fn(&mut cbor2::Value)) -> Vec<u8> {
    let mut value: cbor2::Value = cbor2::from_reader(blob).unwrap();
    let cbor2::Value::Map(entries) = &mut value else {
        panic!("a handle blob is a map")
    };
    for (key, val) in entries.iter_mut() {
        if key.as_text() == Some("formed") {
            edit(val);
        }
    }
    let mut out = Vec::new();
    cbor2::to_writer(&value, &mut out).unwrap();
    out
}

#[test]
fn a_saved_formed_record_that_does_not_match_its_group_is_refused() {
    let mut s = setup();
    let f = completed(&mut s);
    s.a.h(2).adopt_formation(&f).unwrap();
    let (_, blob) = s.a.h(2).save(30).unwrap();
    assert!(GroupHandle::restore(&blob, [sk(2)]).is_ok());
    let field = |which: &'static str| {
        move |formed: &mut cbor2::Value| {
            let cbor2::Value::Array(records) = formed else {
                panic!()
            };
            let cbor2::Value::Array(pair) = &mut records[0] else {
                panic!()
            };
            let cbor2::Value::Map(fields) = &mut pair[1] else {
                panic!()
            };
            for (key, val) in fields.iter_mut() {
                if key.as_text() == Some(which) {
                    match val {
                        cbor2::Value::Bytes(bytes) => bytes[0] ^= 1,
                        cbor2::Value::Array(items) => {
                            let cbor2::Value::Integer(n) = &items[0] else {
                                panic!()
                            };
                            let n: i128 = (*n).into();
                            items[0] = cbor2::Value::Integer(((n ^ 1) as i64).into());
                        }
                        _ => panic!("unexpected field shape"),
                    }
                }
            }
        }
    };
    for which in ["binding", "proposal"] {
        let bad = tamper(&blob, field(which));
        assert_eq!(
            GroupHandle::restore(&bad, [sk(2)]).err(),
            Some(HandleError::Invalid),
            "{which}"
        );
    }
}

#[test]
fn an_older_blob_format_is_refused() {
    let mut s = setup();
    let (_, blob) = s.a.h(2).save(30).unwrap();
    let mut value: cbor2::Value = cbor2::from_reader(&blob[..]).unwrap();
    let cbor2::Value::Map(entries) = &mut value else {
        panic!()
    };
    for (key, val) in entries.iter_mut() {
        if key.as_text() == Some("version") {
            *val = cbor2::Value::Integer(2.into());
        }
    }
    let mut old = Vec::new();
    cbor2::to_writer(&value, &mut old).unwrap();
    assert_eq!(
        GroupHandle::restore(&old, [sk(2)]).err(),
        Some(HandleError::UnsupportedVersion(2))
    );
}

#[test]
fn a_formed_group_works_like_any_other_and_can_invite() {
    // A formation of 1 and 2, both in world A, then 1 invites 9 (who has met 1) into it.
    let mut w = World::new(&[2, 3]);
    let ga = w.group;
    let view = w.h(1).source_view(ga).unwrap();
    let mut f = Formation::new(propose(&[view], terms()).unwrap(), &[pk(1), pk(2)]).unwrap();
    for seed in [1u8, 2] {
        let c = w.h(seed).consent_to_formation(&f).unwrap();
        f.add_consent(c).unwrap();
    }
    let id = f.group_id();
    for seed in [1u8, 2] {
        w.h(seed).adopt_formation(&f).unwrap();
        let (token, _) = w.h(seed).save(30).unwrap();
        w.h(seed).confirm_saved(token);
    }
    let op = w.h(1).invite(id, pk(9), DAY, 31).unwrap();
    assert!(w.pump(31, &mut Vec::new(), None).is_empty());
    let invitation = w
        .h(9)
        .pending_invitations()
        .into_iter()
        .find(|(_, g, _)| *g == id)
        .unwrap()
        .0;
    w.h(9).accept(invitation, 32).unwrap();
    let refused = w.pump(33, &mut Vec::new(), None);
    assert!(refused.is_empty(), "{refused:?}");
    assert_eq!(w.h(1).op_state(op), Some(OpState::Completed));
    for seed in [1u8, 2, 9] {
        assert_eq!(w.h(seed).group(id).unwrap().revision(), 1, "member {seed}");
    }
    // The first group never moved.
    assert_eq!(w.h(1).group(ga).unwrap().revision(), 0);
}

#[test]
fn removing_a_formed_groups_owner_keeps_the_handle_restorable() {
    let mut s = setup();
    let f = completed(&mut s);
    let h = s.a.h(2);
    h.adopt_formation(&f).unwrap();
    h.installation_mut().add_identity(sk(10)).unwrap();
    h.installation_mut().select(pk(10), 40).unwrap();
    h.installation_mut().remove_identity(pk(2)).unwrap();
    let (_, blob) = h.save(41).unwrap();
    assert!(GroupHandle::restore(&blob, [sk(10)]).is_ok());
}

fn saved_field<'a>(v: &'a mut cbor2::Value, name: &str) -> &'a mut cbor2::Value {
    let cbor2::Value::Map(fields) = v else {
        panic!()
    };
    &mut fields
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some(name))
        .unwrap()
        .1
}
fn saved_bytes(v: &cbor2::Value) -> Vec<u8> {
    match v {
        cbor2::Value::Bytes(b) => b.clone(),
        cbor2::Value::Array(a) => a
            .iter()
            .map(|i| u8::try_from(i.as_integer().unwrap()).unwrap())
            .collect(),
        _ => panic!(),
    }
}
fn set_saved_bytes(v: &mut cbor2::Value, b: Vec<u8>) {
    *v = cbor2::Value::Array(
        b.into_iter()
            .map(|x| cbor2::Value::Integer(x.into()))
            .collect(),
    );
}

#[test]
fn restore_rejects_genesis_rules_that_differ_from_the_formation() {
    let mut s = setup();
    let f = completed(&mut s);
    let id = f.group_id();
    let h = s.a.h(2);
    h.adopt_formation(&f).unwrap();
    let (_, blob) = h.save(30).unwrap();
    let mut v: cbor2::Value = cbor2::from_reader(&blob[..]).unwrap();
    // Change both the cache and replay genesis, leaving agreed proposal and binding untouched.
    let cbor2::Value::Array(entries) = saved_field(&mut v, "groups") else {
        panic!()
    };
    for entry in entries {
        let cbor2::Value::Array(pair) = entry else {
            panic!()
        };
        let cbor2::Value::Array(scope) = &pair[0] else {
            panic!()
        };
        if u64::try_from(scope[1].as_integer().unwrap()).unwrap() != id {
            continue;
        }
        let mut group: cbor2::Value = cbor2::from_reader(&saved_bytes(&pair[1])[..]).unwrap();
        set_saved_bytes(saved_field(&mut group, "policy"), vec![2]);
        let mut bytes = vec![];
        cbor2::to_writer(&group, &mut bytes).unwrap();
        set_saved_bytes(&mut pair[1], bytes);
    }
    let cbor2::Value::Array(entries) = saved_field(&mut v, "histories") else {
        panic!()
    };
    for entry in entries {
        let cbor2::Value::Array(pair) = entry else {
            panic!()
        };
        let cbor2::Value::Array(scope) = &pair[0] else {
            panic!()
        };
        if u64::try_from(scope[1].as_integer().unwrap()).unwrap() != id {
            continue;
        }
        let genesis = saved_field(&mut pair[1], "genesis");
        let mut bytes = saved_bytes(genesis);
        assert_eq!(&bytes[..4], b"MSG1");
        assert_eq!(bytes[44], 1);
        assert_eq!(bytes[45], 0);
        bytes[45] = 2;
        set_saved_bytes(genesis, bytes);
    }
    let mut bad = vec![];
    cbor2::to_writer(&v, &mut bad).unwrap();
    assert!(
        GroupHandle::restore(&bad, [sk(2)]).is_err(),
        "rules not agreed in the signed proposal were accepted"
    );
}

#[test]
fn a_colliding_group_cannot_replace_the_agreed_formation() {
    use mesh_identity::session::installation::Installation;
    use rand::SeedableRng;
    use rand::rngs::{StdRng, mock::StepRng};
    let mut s = setup();
    let f = completed(&mut s);
    let id = f.group_id();
    let mut b = GroupHandle::new(Installation::new(sk(2)));
    let mut a = GroupHandle::new(Installation::new(sk(1)));
    let mut candidate = GroupHandle::new(Installation::new(sk(9)));
    support::meet(
        b.installation_mut(),
        candidate.installation_mut(),
        1,
        &mut StdRng::seed_from_u64(55),
    );
    b.create(Policy::InviterOnly, &[pk(1)], &mut StepRng::new(id, 0))
        .unwrap();
    flush(&mut b);
    let genesis = b.take_outgoing().remove(0);
    a.import_genesis(&genesis.bytes, genesis.authenticator.unwrap())
        .unwrap();
    flush(&mut a);
    let mut network = World {
        handles: vec![(2, b), (1, a), (9, candidate)],
        group: id,
        events: vec![],
    };
    network.h(2).invite(id, pk(9), DAY, 20).unwrap();
    assert!(network.pump(20, &mut vec![], None).is_empty());
    let invitation = network.h(9).pending_invitations()[0].0;
    network.h(9).accept(invitation, 20).unwrap();
    assert!(network.pump(20, &mut vec![], None).is_empty());
    assert_eq!(network.h(2).group(id).unwrap().revision(), 1);
    let b = network.h(2);
    b.installation_mut().add_identity(sk(1)).unwrap();
    b.installation_mut().select(pk(1), 30).unwrap();
    b.adopt_formation(&f).unwrap();
    assert!(b.group(id).unwrap().membership(pk(9)).is_none());
    let (_, blob) = b.save(31).unwrap();
    assert!(
        b.group(id).unwrap().membership(pk(9)).is_none(),
        "unrelated higher-revision group replaced the agreed roster"
    );
    assert!(GroupHandle::restore(&blob, [sk(1), sk(2)]).is_ok());
}

#[test]
fn formed_group_provenance_is_preserved_across_owned_identities() {
    let mut s = setup();
    let f = completed(&mut s);
    let id = f.group_id();
    let h = s.a.h(2);
    // Identity 2's handle also holds identity 1. Both were in the formation roster.
    h.installation_mut().add_identity(sk(1)).unwrap();
    h.installation_mut().select(pk(1), 30).unwrap();
    h.adopt_formation(&f).unwrap();
    let (token, _blob) = h.save(31).unwrap();
    h.confirm_saved(token);

    // Selected identity 1 has the provenance.
    assert_eq!(h.formed_from(id).unwrap(), f.proposal().to_bytes());

    // Switch to identity 2: ensure_local_views synced the group and its formation provenance.
    h.installation_mut().select(pk(2), 32).unwrap();
    assert!(h.group(id).is_some());
    assert_eq!(
        h.formed_from(id).unwrap(),
        f.proposal().to_bytes(),
        "formation provenance not synchronized to co-founding identity 2"
    );

    // Removing identity 1 retains provenance for remaining co-founder identity 2.
    h.installation_mut().remove_identity(pk(1)).unwrap();
    let (token2, blob2) = h.save(33).unwrap();
    h.confirm_saved(token2);
    assert_eq!(h.formed_from(id).unwrap(), f.proposal().to_bytes());

    let restored = GroupHandle::restore(&blob2, [sk(2)]).unwrap();
    assert_eq!(
        restored.formed_from(id).unwrap(),
        f.proposal().to_bytes(),
        "formation provenance not preserved in restored blob for identity 2"
    );
}

#[test]
fn adopt_formation_syncs_local_views_before_duplicate_check() {
    let mut s = setup();
    let f = completed(&mut s);
    let id = f.group_id();
    let h = s.a.h(2);
    h.installation_mut().add_identity(sk(1)).unwrap();
    h.installation_mut().select(pk(1), 30).unwrap();
    h.adopt_formation(&f).unwrap();
    let (token, _) = h.save(31).unwrap();
    h.confirm_saved(token);

    // Identity 2 now holds the group via synced local views. Attempting to adopt again fails as Duplicate.
    h.installation_mut().select(pk(2), 32).unwrap();
    assert!(h.group(id).is_some());
    assert_eq!(
        h.adopt_formation(&f),
        Err(HandleError::Duplicate),
        "adopt_formation did not detect duplicate across owned identities"
    );
}

#[test]
fn restore_rejects_oversized_histories_or_formed_lists_upfront() {
    let mut s = setup();
    let f = completed(&mut s);
    let h = s.a.h(2);
    h.adopt_formation(&f).unwrap();
    let (_, blob) = h.save(30).unwrap();

    // Oversized formed list
    let bad_formed = tamper(&blob, |formed| {
        let cbor2::Value::Array(records) = formed else {
            panic!()
        };
        let first = records[0].clone();
        for _ in 0..MAX_GROUPS + 5 {
            records.push(first.clone());
        }
    });
    assert_eq!(
        GroupHandle::restore(&bad_formed, [sk(2)]).err(),
        Some(HandleError::TooLarge),
        "restore did not reject oversized formed list with TooLarge"
    );

    // Oversized histories list
    let mut value: cbor2::Value = cbor2::from_reader(&blob[..]).unwrap();
    let cbor2::Value::Map(entries) = &mut value else {
        panic!()
    };
    for (key, val) in entries.iter_mut() {
        if key.as_text() == Some("histories") {
            let cbor2::Value::Array(records) = val else {
                panic!()
            };
            let first = records[0].clone();
            for _ in 0..MAX_GROUPS + 5 {
                records.push(first.clone());
            }
        }
    }
    let mut bad_histories = Vec::new();
    cbor2::to_writer(&value, &mut bad_histories).unwrap();
    assert_eq!(
        GroupHandle::restore(&bad_histories, [sk(2)]).err(),
        Some(HandleError::TooLarge),
        "restore did not reject oversized histories list with TooLarge"
    );
}
