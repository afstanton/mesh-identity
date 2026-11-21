#![cfg(feature = "groups")]
//! F3c: the inviter assembles the certificate, applies the admission, and the members and the
//! candidate follow, each only after their own confirmed save.

mod support;
use support::world::*;

use mesh_identity::groups::Policy;
use mesh_identity::groups::handle::*;
use mesh_identity::session::installation::Installation;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn events_of(w: &World, seed: u8) -> Vec<Event> {
    w.events
        .iter()
        .filter(|(s, _)| *s == seed)
        .map(|(_, e)| e.clone())
        .collect()
}

#[test]
fn an_admission_completes_for_everyone_and_every_event_follows_a_confirmed_save() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    let op = w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    w.pump(20, &mut Vec::new(), None);
    let inv = w.h(9).pending_invitations()[0].0;
    let accept = w.h(9).accept(inv, 21).unwrap();
    assert!(w.pump(22, &mut Vec::new(), None).is_empty());

    assert!(events_of(&w, 1).contains(&Event::Admitted(op)));
    assert!(events_of(&w, 9).contains(&Event::Joined(group)));
    for seed in [2, 3] {
        assert!(events_of(&w, seed).contains(&Event::MemberAdmitted {
            group,
            member: pk(9)
        }));
    }
    assert_eq!(w.h(1).op_state(op), Some(OpState::Completed));
    assert_eq!(w.h(9).op_state(accept), Some(OpState::Completed));
    // All four hold the same roster head, and the candidate's copy has no one else's secrets.
    let heads: Vec<_> = [1, 2, 3, 9]
        .iter()
        .map(|s| w.h(*s).group(group).unwrap().rotation_context())
        .collect();
    assert!(heads.windows(2).all(|pair| pair[0] == pair[1]));
    assert_eq!(w.h(9).group(group).unwrap().revision(), 1);
    assert!(w.h(9).pending_invitations().is_empty());
}

#[test]
fn the_certificate_and_the_snapshot_wait_for_the_inviters_confirmed_save() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    w.pump(20, &mut Vec::new(), None);
    let inv = w.h(9).pending_invitations()[0].0;
    w.h(9).accept(inv, 21).unwrap();
    // Everything moves except the inviter's last flush: hold every vote for the inviter.
    let mut held = Vec::new();
    w.pump(22, &mut held, Some((1, Tag::RosterVote)));
    assert!(!held.is_empty());
    for (_, _, bytes) in &held {
        // Votes come from members 2 and 3; any order works.
        let from = if w.h(1).group(group).is_some() {
            [pk(2), pk(3)]
        } else {
            unreachable!()
        };
        for sender in from {
            w.h(1).receive_bytes(sender, bytes, 23);
        }
    }
    // Applied in memory, nothing released.
    assert_eq!(w.h(1).group(group).unwrap().revision(), 1);
    assert!(w.h(1).take_outgoing().is_empty());
    let (token, _) = w.h(1).save(23).unwrap();
    assert!(w.h(1).take_outgoing().is_empty());
    w.h(1).confirm_saved(token);
    let out = w.h(1).take_outgoing();
    let kinds: Vec<_> = out.iter().map(|o| o.kind).collect();
    assert!(kinds.contains(&Tag::Certificate) && kinds.contains(&Tag::GroupSnapshot));
    // The snapshot goes to the candidate alone; the certificate to the other members.
    for o in &out {
        match o.kind {
            Tag::GroupSnapshot => assert_eq!(o.to, vec![pk(9)]),
            Tag::Certificate => assert_eq!(o.to.len(), 2),
            _ => {}
        }
    }
}

#[test]
fn a_failed_write_after_assembly_loses_nothing_and_the_votes_can_be_replayed() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    let op = w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    w.pump(20, &mut Vec::new(), None);
    let inv = w.h(9).pending_invitations()[0].0;
    w.h(9).accept(inv, 21).unwrap();
    let mut held = Vec::new();
    w.pump(22, &mut held, Some((1, Tag::RosterVote)));
    let (token, before) = w.h(1).save(22).unwrap();
    w.h(1).confirm_saved(token);
    let senders = [pk(2), pk(3)];
    for (_, _, bytes) in &held {
        for sender in senders {
            w.h(1).receive_bytes(sender, bytes, 23);
        }
    }
    assert_eq!(w.h(1).group(group).unwrap().revision(), 1);
    // The write of the completed state fails; the host restores the last blob it holds.
    let (_lost, _unwritten) = w.h(1).save(23).unwrap();
    assert!(w.h(1).take_outgoing().is_empty());
    let slot = w.handles.iter().position(|(s, _)| *s == 1).unwrap();
    w.handles[slot].1 = GroupHandle::restore(&before, [sk(1)]).unwrap();
    assert_eq!(w.h(1).group(group).unwrap().revision(), 0);
    for (_, _, bytes) in &held {
        for sender in senders {
            w.h(1).receive_bytes(sender, bytes, 24);
        }
    }
    assert_eq!(w.h(1).group(group).unwrap().revision(), 1);
    assert!(w.pump(25, &mut Vec::new(), None).is_empty());
    assert!(events_of(&w, 1).contains(&Event::Admitted(op)));
    assert!(w.h(9).group(group).is_some());
}

#[test]
fn a_new_member_can_invite_the_next_one() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    w.pump(20, &mut Vec::new(), None);
    let inv = w.h(9).pending_invitations()[0].0;
    w.h(9).accept(inv, 21).unwrap();
    w.pump(22, &mut Vec::new(), None);
    // A fifth person meets the new member, who invites them; all four members vote.
    let mut rng = StdRng::seed_from_u64(11);
    let mut fifth = GroupHandle::new(Installation::new(sk(11)));
    support::meet(
        w.h(9).installation_mut(),
        fifth.installation_mut(),
        30,
        &mut rng,
    );
    w.handles.push((11, fifth));
    let op = w.h(9).invite(group, pk(11), DAY, 31).unwrap();
    let refused = w.pump(31, &mut Vec::new(), None);
    assert!(refused.is_empty(), "{refused:?}");
    let inv = w.h(11).pending_invitations()[0].0;
    w.h(11).accept(inv, 32).unwrap();
    let refused = w.pump(33, &mut Vec::new(), None);
    assert!(refused.is_empty(), "{refused:?}");
    assert_eq!(w.h(9).op_state(op), Some(OpState::Completed));
    for seed in [1, 2, 3, 9, 11] {
        assert_eq!(
            w.h(seed).group(group).unwrap().revision(),
            2,
            "member {seed}"
        );
    }
}

#[test]
fn an_invitation_on_a_roster_that_moved_on_is_rejected_as_stale() {
    let mut w = World::new(&[]);
    let group = w.group;
    // A second candidate, invited on the same roster as the first.
    let mut rng = StdRng::seed_from_u64(12);
    let mut d = GroupHandle::new(Installation::new(sk(10)));
    support::meet(w.h(1).installation_mut(), d.installation_mut(), 2, &mut rng);
    w.handles.push((10, d));
    let first = w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    let second = w.h(1).invite(group, pk(10), DAY, 20).unwrap();
    w.pump(20, &mut Vec::new(), None);
    let inv9 = w.h(9).pending_invitations()[0].0;
    w.h(9).accept(inv9, 21).unwrap();
    w.pump(22, &mut Vec::new(), None);
    assert_eq!(w.h(1).op_state(first), Some(OpState::Completed));
    assert_eq!(
        w.h(1).op_state(second),
        Some(OpState::Rejected(Reason::Stale))
    );
    // The second candidate's consent now has nothing to attach to.
    let inv10 = w.h(10).pending_invitations()[0].0;
    w.h(10).accept(inv10, 23).unwrap();
    let refused = w.pump(24, &mut Vec::new(), None);
    assert_eq!(refused, vec![Event::FrameRejected(Reason::Unknown)]);
    assert!(w.h(10).group(group).is_none());
}

#[test]
fn a_snapshot_is_refused_unless_it_is_exactly_what_the_candidate_agreed_to() {
    let mut w = World::new(&[2]);
    let group = w.group;
    w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    w.pump(20, &mut Vec::new(), None);
    let inv = w.h(9).pending_invitations()[0].0;
    w.h(9).accept(inv, 21).unwrap();
    let mut held = Vec::new();
    w.pump(22, &mut held, Some((9, Tag::GroupSnapshot)));
    let snapshot = held
        .iter()
        .find(|(s, t, _)| *s == 9 && *t == Tag::GroupSnapshot)
        .unwrap()
        .2
        .clone();
    let reject = |r| vec![Event::FrameRejected(r)];
    // Not from the inviter.
    assert_eq!(
        w.h(9).receive_bytes(pk(2), &snapshot, 23),
        reject(Reason::Invalid)
    );
    // Truncated or damaged.
    assert_eq!(
        w.h(9)
            .receive_bytes(pk(1), &snapshot[..snapshot.len() - 1], 23),
        reject(Reason::Malformed)
    );
    // The join response is a certificate, never a trusted local-state snapshot.
    // Damaged responses cannot authorize a different roster; validation must not panic.
    for index in (5..snapshot.len()).step_by(11) {
        let mut damaged = snapshot.clone();
        damaged[index] ^= 1;
        let mut fresh = GroupHandle::restore(&w.h(9).save(23).unwrap().1, [sk(9)]).unwrap();
        let _ = fresh.receive_bytes(pk(1), &damaged, 23);
    }
    assert!(w.h(9).group(group).is_none());
    // The real one is accepted, and a redelivery changes nothing.
    assert!(w.h(9).receive_bytes(pk(1), &snapshot, 23).is_empty());
    assert!(w.h(9).group(group).is_some());
    assert_eq!(
        w.h(9).receive_bytes(pk(1), &snapshot, 23),
        reject(Reason::Unknown)
    );
}

#[test]
fn a_restart_after_joining_keeps_the_group_and_forgets_the_invitation() {
    let mut w = World::new(&[]);
    let group = w.group;
    w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    w.pump(20, &mut Vec::new(), None);
    let inv = w.h(9).pending_invitations()[0].0;
    w.h(9).accept(inv, 21).unwrap();
    w.pump(22, &mut Vec::new(), None);
    let (_, blob) = w.h(9).save(23).unwrap();
    let again = GroupHandle::restore(&blob, [sk(9)]).unwrap();
    assert_eq!(again.group_ids(), vec![group]);
    assert!(again.pending_invitations().is_empty());
    assert_eq!(
        again.group(group).unwrap().to_bytes(),
        w.h(9).group(group).unwrap().to_bytes()
    );
    let _ = Policy::InviterOnly;
}
