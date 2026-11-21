#![cfg(feature = "groups")]
//! F3b: members vote on an admission through their handles. Every vote is staged and leaves
//! only after the blob holding its lock is durable.

mod support;
use support::world::*;

use mesh_identity::groups::handle::*;
use mesh_identity::session::installation::Installation;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn admitted(w: &mut World, seed: u8) -> bool {
    let group = w.group;
    w.h(seed)
        .group(group)
        .is_some_and(|g| g.membership(pk(9)).is_some())
}

fn progress(w: &mut World, seed: u8, invitation: [u8; 32]) -> Option<AdmissionProgress> {
    w.h(seed).admission_progress(invitation)
}

#[test]
fn three_members_prepare_and_commit_in_order() {
    let mut w = World::new(&[2, 3]);
    let invitation = w.invite_and_accept(20);
    let refused = w.pump(21, &mut Vec::new(), None);
    assert!(refused.is_empty(), "{refused:?}");
    // Everyone prepared and committed, so the admission went through for all of them.
    for seed in [1, 2, 3, 9] {
        assert!(admitted(&mut w, seed), "member {seed}");
    }
    // The finished round is forgotten; the candidate never followed one.
    assert!(progress(&mut w, 1, invitation).is_none());
    assert!(progress(&mut w, 9, invitation).is_none());
}

#[test]
fn a_one_member_group_prepares_and_commits_at_once() {
    let mut w = World::new(&[]);
    let invitation = w.invite_and_accept(20);
    assert!(w.pump(21, &mut Vec::new(), None).is_empty());
    assert!(admitted(&mut w, 1) && admitted(&mut w, 9));
    assert!(progress(&mut w, 1, invitation).is_none());
}

#[test]
fn a_vote_leaves_only_after_the_blob_with_its_lock_is_confirmed() {
    let mut w = World::new(&[2, 3]);
    let invitation = w.invite_and_accept(20);
    // Deliver everything except the final flush of member 2, then look at its outbox.
    let mut none = Vec::new();
    w.pump(21, &mut none, Some((2, Tag::Consent)));
    let consent = none
        .iter()
        .find(|(s, t, _)| *s == 2 && *t == Tag::Consent)
        .map(|(_, _, b)| b.clone())
        .unwrap();
    assert!(progress(&mut w, 2, invitation).is_none());
    let events = w.h(2).receive_bytes(pk(1), &consent, 22);
    assert!(events.is_empty());
    // Signed in memory, but nothing is released before the confirmed save.
    assert!(progress(&mut w, 2, invitation).unwrap().signed_prepare);
    assert!(w.h(2).take_outgoing().is_empty());
    let (token, _blob) = w.h(2).save(22).unwrap();
    assert!(w.h(2).take_outgoing().is_empty());
    w.h(2).confirm_saved(token);
    // Member 2 already held the other two prepares, so it signed its prepare and its commit.
    let out = w.h(2).take_outgoing();
    assert_eq!(out.len(), 2);
    assert!(
        out.iter()
            .all(|o| o.kind == Tag::RosterVote && o.to.len() == 2)
    );
}

#[test]
fn votes_that_arrive_before_the_consent_are_held_and_counted_later() {
    let mut w = World::new(&[2, 3]);
    let invitation = w.invite_and_accept(20);
    let mut held = Vec::new();
    let refused = w.pump(21, &mut held, Some((3, Tag::Consent)));
    assert!(refused.is_empty());
    // Member 3 has the invitation and two prepares, but not the consent.
    assert!(progress(&mut w, 3, invitation).is_none());
    assert_eq!(held.len(), 1);
    let consent = held.remove(0).2;
    assert!(w.h(3).receive_bytes(pk(1), &consent, 22).is_empty());
    assert!(w.pump(23, &mut Vec::new(), None).is_empty());
    for seed in [1, 2, 3, 9] {
        assert!(admitted(&mut w, seed), "member {seed}");
    }
}

#[test]
fn redelivered_and_forged_votes_change_nothing() {
    let mut w = World::new(&[2, 3]);
    let invitation = w.invite_and_accept(20);
    w.pump(21, &mut Vec::new(), None);
    let group = w.group;
    let before = w.h(1).group(group).unwrap().to_bytes().unwrap();
    // Only refusal paths are checked here, with synthetic frames.
    let mut body = vec![0u8; 8 + 32 + 32 + 4 + 1 + 96];
    body[75] = 1; // round 1
    body[76] = 1;
    let frame = encode_frame(Tag::RosterVote, &body).unwrap();
    let r = w.h(1).receive_bytes(pk(2), &frame, 22);
    assert!(matches!(
        r.as_slice(),
        [Event::FrameRejected(Reason::Invalid | Reason::Unknown)]
    ));
    let mut bad_phase = body.clone();
    bad_phase[76] = 7;
    assert_eq!(
        w.h(1).receive_bytes(
            pk(2),
            &encode_frame(Tag::RosterVote, &bad_phase).unwrap(),
            22
        ),
        vec![Event::FrameRejected(Reason::Malformed)]
    );
    assert_eq!(
        w.h(1).receive_bytes(
            pk(2),
            &encode_frame(Tag::RosterVote, &body[..50]).unwrap(),
            22
        ),
        vec![Event::FrameRejected(Reason::Malformed)]
    );
    assert_eq!(w.h(1).group(group).unwrap().to_bytes().unwrap(), before);
    assert!(progress(&mut w, 1, invitation).is_none());
}

#[test]
fn a_second_admission_on_the_same_roster_cannot_vote_and_is_rejected() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    // Two invitations on the same roster, to two candidates, both accepted.
    let op9 = w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    w.pump(20, &mut Vec::new(), None);
    let inv9 = w.h(9).pending_invitations()[0].0;
    w.h(9).accept(inv9, 21).unwrap();

    let mut rng = StdRng::seed_from_u64(8);
    let mut d = GroupHandle::new(Installation::new(sk(10)));
    support::meet(w.h(1).installation_mut(), d.installation_mut(), 2, &mut rng);
    w.h(1).invite(group, pk(10), DAY, 22).unwrap();
    flush(w.h(1));
    let frame = w.h(1).take_outgoing().remove(0);
    assert!(d.receive_bytes(pk(1), &frame.bytes, 23).is_empty());
    flush(&mut d);
    let inv10 = d.pending_invitations()[0].0;
    d.accept(inv10, 24).unwrap();
    flush(&mut d);
    let consent10 = d.take_outgoing().remove(0);
    // The inviter hears the second candidate first and votes for that child; the first
    // admission's consent then finds the lock taken.
    assert!(
        w.h(1)
            .receive_bytes(pk(10), &consent10.bytes, 25)
            .is_empty()
    );
    let refused = w.pump(26, &mut Vec::new(), None);
    assert!(
        refused.contains(&Event::FrameRejected(Reason::Conflict)),
        "{refused:?}"
    );
    assert_eq!(
        w.h(1).op_state(op9),
        Some(OpState::Rejected(Reason::Conflict))
    );
    assert!(!admitted(&mut w, 1));
}

#[test]
fn a_failed_write_and_a_restart_cannot_make_a_member_vote_twice() {
    let mut w = World::new(&[2, 3]);
    let invitation = w.invite_and_accept(20);
    let mut held = Vec::new();
    w.pump(21, &mut held, Some((2, Tag::Consent)));
    let consent = held.remove(0).2;
    let (token, before) = w.h(2).save(21).unwrap();
    w.h(2).confirm_saved(token);
    // The member signs its prepare, then the write fails: the old blob comes back.
    assert!(w.h(2).receive_bytes(pk(1), &consent, 22).is_empty());
    let (_lost, _unwritten) = w.h(2).save(22).unwrap();
    assert!(w.h(2).take_outgoing().is_empty());
    let restored = GroupHandle::restore(&before, [sk(2)]).unwrap();
    let slot = w.handles.iter().position(|(s, _)| *s == 2).unwrap();
    w.handles[slot].1 = restored;
    assert!(progress(&mut w, 2, invitation).is_none());
    // The consent is redelivered: the same prepare is signed, once, and the admission finishes.
    assert!(w.h(2).receive_bytes(pk(1), &consent, 23).is_empty());
    assert!(w.pump(24, &mut Vec::new(), None).is_empty());
    for seed in [1, 2, 3, 9] {
        assert!(admitted(&mut w, seed), "member {seed}");
    }
    // A restart after the admission keeps the group exactly.
    let group = w.group;
    let (_, blob) = w.h(2).save(25).unwrap();
    let again = GroupHandle::restore(&blob, [sk(2)]).unwrap();
    assert_eq!(
        again.group(group).unwrap().to_bytes(),
        w.h(2).group(group).unwrap().to_bytes()
    );
}
