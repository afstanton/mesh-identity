#![cfg(feature = "groups")]
//! F3d: leaving takes effect at once, becomes durable and reported only after a confirmed save,
//! and the other members record the signed departure.

mod support;
use support::world::*;

use mesh_identity::groups::handle::*;

fn events_of(w: &World, seed: u8) -> Vec<Event> {
    w.events
        .iter()
        .filter(|(s, _)| *s == seed)
        .map(|(_, e)| e.clone())
        .collect()
}

#[test]
fn a_group_vanishes_at_once_and_the_departure_follows_the_confirmed_save() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    let op = w.h(2).leave(group, 20).unwrap();
    // Hidden now, before any save; nothing has left the handle.
    assert!(w.h(2).group(group).is_none());
    assert!(w.h(2).group_ids().is_empty());
    assert!(w.h(2).take_outgoing().is_empty());
    assert_eq!(w.h(2).op_state(op), Some(OpState::Pending));
    let (token, _) = w.h(2).save(20).unwrap();
    assert!(w.h(2).take_outgoing().is_empty());
    assert_eq!(w.h(2).confirm_saved(token), vec![Event::Left(group)]);
    assert_eq!(w.h(2).op_state(op), Some(OpState::Completed));
    let out = w.h(2).take_outgoing();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind, Tag::Departure);
    assert_eq!(out[0].to.len(), 2);
    assert!(!out[0].to.contains(&pk(2)));
}

#[test]
fn members_record_the_departure_without_changing_the_roster() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.h(2).leave(group, 20).unwrap();
    assert!(w.pump(21, &mut Vec::new(), None).is_empty());
    for seed in [1, 3] {
        assert!(events_of(&w, seed).contains(&Event::MemberDeparted {
            group,
            member: pk(2)
        }));
        let g = w.h(seed).group(group).unwrap();
        assert_eq!(g.revision(), 0);
        assert!(g.membership(pk(2)).is_some());
    }
}

#[test]
fn a_member_who_left_neither_votes_nor_invites_nor_leaves_twice() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.h(2).leave(group, 20).unwrap();
    w.pump(20, &mut Vec::new(), None);
    assert_eq!(w.h(2).leave(group, 21), Err(HandleError::Unknown));
    assert_eq!(
        w.h(2).invite(group, pk(9), DAY, 21),
        Err(HandleError::Unknown)
    );
    // An admission now reaches the leaver and is ignored: it signs nothing and says nothing.
    w.h(1).invite(group, pk(9), DAY, 22).unwrap();
    let invitation = {
        let refused = w.pump(22, &mut Vec::new(), None);
        assert!(refused.is_empty(), "{refused:?}");
        w.h(9).pending_invitations()[0].0
    };
    w.h(9).accept(invitation, 23).unwrap();
    // The forwarded consent names an admission the leaver never recorded: it says Unknown.
    let refused = w.pump(24, &mut Vec::new(), None);
    assert!(
        refused
            .iter()
            .all(|e| *e == Event::FrameRejected(Reason::Unknown)),
        "{refused:?}"
    );
    assert!(w.h(2).admission_progress(invitation).is_none());
    // The two remaining members are two of three eligible, so the roster cannot change: the
    // leaver's departure is not yet agreed, and the quorum still counts it.
    assert!(w.h(9).group(group).is_none());
}

#[test]
fn a_crash_before_the_write_loses_the_leave_and_a_confirmed_leave_survives_restarts() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    let (token, before) = w.h(2).save(19).unwrap();
    w.h(2).confirm_saved(token);
    w.h(2).leave(group, 20).unwrap();
    assert!(w.h(2).group(group).is_none());
    // The write never happened: the last blob still shows the group (the stated limit).
    let lost = GroupHandle::restore(&before, [sk(2)]).unwrap();
    assert!(lost.group(group).is_some());
    // After a confirmed write the leave survives a restart.
    let (token, blob) = w.h(2).save(21).unwrap();
    w.h(2).confirm_saved(token);
    let kept = GroupHandle::restore(&blob, [sk(2)]).unwrap();
    assert!(kept.group(group).is_none() && kept.group_ids().is_empty());
    // And its unsent departure is staged again after the restart.
    let mut kept = kept;
    let (token, _) = kept.save(22).unwrap();
    kept.confirm_saved(token);
    assert_eq!(kept.take_outgoing().len(), 1);
}

#[test]
fn leaving_ends_the_invitations_this_member_sent() {
    let mut w = World::new(&[2]);
    let group = w.group;
    let invite = w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    w.h(1).leave(group, 21).unwrap();
    assert_eq!(
        w.h(1).op_state(invite),
        Some(OpState::Rejected(Reason::Stale))
    );
}

#[test]
fn forged_misdirected_and_unknown_departures_are_refused() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.h(2).leave(group, 20).unwrap();
    flush(w.h(2));
    let frame = w.h(2).take_outgoing().remove(0);
    let reject = |r| vec![Event::FrameRejected(r)];
    // Sent by someone other than the member it names.
    assert_eq!(
        w.h(1).receive_bytes(pk(3), &frame.bytes, 21),
        reject(Reason::Invalid)
    );
    // Truncated.
    assert_eq!(
        w.h(1)
            .receive_bytes(pk(2), &frame.bytes[..frame.bytes.len() - 3], 21),
        reject(Reason::Malformed)
    );
    // Signature damaged.
    let mut bad = frame.bytes.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(w.h(1).receive_bytes(pk(2), &bad, 21), reject(Reason::Stale));
    // A group we do not know.
    let mut other = frame.bytes.clone();
    other[5] ^= 1;
    assert_eq!(
        w.h(1).receive_bytes(pk(2), &other, 21),
        reject(Reason::Unknown)
    );
    // The real one, then a repeat.
    assert!(w.h(1).receive_bytes(pk(2), &frame.bytes, 21).is_empty());
    assert!(w.h(1).receive_bytes(pk(2), &frame.bytes, 21).is_empty());
    assert_eq!(
        flush(w.h(1)),
        vec![Event::MemberDeparted {
            group,
            member: pk(2)
        }]
    );
}

#[test]
fn a_gated_device_cannot_leave() {
    let mut w = World::new(&[2]);
    let group = w.group;
    w.h(2).installation_mut().gate_voting();
    assert_eq!(w.h(2).leave(group, 20), Err(HandleError::Ineligible));
    assert!(w.h(2).group(group).is_some());
}
