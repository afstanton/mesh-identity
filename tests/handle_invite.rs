#![cfg(feature = "groups")]
//! F3a: `invite` and `accept` between two handles, with the persist-before-send rule applied
//! to what each side receives as well as what it sends.

mod support;

use ed25519_dalek::SigningKey;
use mesh_identity::groups::Policy;
use mesh_identity::groups::handle::*;
use mesh_identity::session::installation::Installation;
use rand::SeedableRng;
use rand::rngs::{OsRng, StdRng};

const DAY: u64 = 24 * 60 * 60 * 1000;

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn pk(seed: u8) -> [u8; 32] {
    sk(seed).verifying_key().to_bytes()
}

/// Two handles that have met and verified each other, and a group the first created.
struct Pair {
    a: GroupHandle,
    b: GroupHandle,
    group: u64,
}

fn pair() -> Pair {
    let mut a = GroupHandle::new(Installation::new(sk(1)));
    let mut b = GroupHandle::new(Installation::new(sk(2)));
    let mut rng = StdRng::seed_from_u64(5);
    support::meet(a.installation_mut(), b.installation_mut(), 1, &mut rng);
    a.create(Policy::InviterOnly, &[], &mut OsRng).unwrap();
    flush(&mut a);
    a.take_outgoing();
    let group = a.group_ids()[0];
    Pair { a, b, group }
}

fn flush(h: &mut GroupHandle) -> Vec<Event> {
    let (token, _) = h.save(10).unwrap();
    h.confirm_saved(token)
}

/// Move everything released from `from` to `to` and return what `to` refused at once.
fn deliver(from: &mut GroupHandle, to: &mut GroupHandle, now: u64) -> Vec<Event> {
    let sender = from.installation().selected();
    let mut rejected = Vec::new();
    for out in from.take_outgoing() {
        rejected.extend(to.receive_bytes(sender, &out.bytes, now));
    }
    rejected
}

fn invitation_of(events: &[Event]) -> [u8; 32] {
    events
        .iter()
        .find_map(|e| match e {
            Event::InvitationReceived { invitation, .. } => Some(*invitation),
            _ => None,
        })
        .expect("an invitation was received")
}

#[test]
fn invite_accept_and_consent_follow_the_confirmed_saves() {
    let Pair {
        mut a,
        mut b,
        group,
    } = pair();
    let op = a.invite(group, pk(2), DAY, 10).unwrap();
    assert!(a.take_outgoing().is_empty());
    assert_eq!(flush(&mut a), vec![Event::InvitationSent(op)]);
    assert_eq!(a.op_state(op), Some(OpState::Pending));

    assert!(deliver(&mut a, &mut b, 11).is_empty());
    // The receiver's event waits for its own durable write.
    assert!(b.pending_invitations().len() == 1);
    let events = flush(&mut b);
    let invitation = invitation_of(&events);
    assert_eq!(b.pending_invitations(), vec![(invitation, group, pk(1))]);

    let accept = b.accept(invitation, 12).unwrap();
    assert!(b.take_outgoing().is_empty());
    assert_eq!(flush(&mut b), vec![Event::AcceptanceSent(accept)]);
    assert_eq!(b.accept(invitation, 12), Ok(accept));

    assert!(deliver(&mut b, &mut a, 13).is_empty());
    // The inviter is the whole group, so its consent step also completes the admission (F3c).
    assert_eq!(
        flush(&mut a),
        vec![Event::ConsentReceived(op), Event::Admitted(op)]
    );
    assert_eq!(a.op_state(op), Some(OpState::Completed));
}

#[test]
fn redelivery_is_ignored() {
    let Pair {
        mut a,
        mut b,
        group,
    } = pair();
    a.invite(group, pk(2), DAY, 10).unwrap();
    flush(&mut a);
    let out = a.take_outgoing().remove(0);
    assert!(b.receive_bytes(pk(1), &out.bytes, 11).is_empty());
    assert!(b.receive_bytes(pk(1), &out.bytes, 11).is_empty());
    assert_eq!(flush(&mut b).len(), 1);
    let invitation = b.pending_invitations()[0].0;
    b.accept(invitation, 12).unwrap();
    flush(&mut b);
    let consent = b.take_outgoing().remove(0);
    assert!(a.receive_bytes(pk(2), &consent.bytes, 13).is_empty());
    // The admission already finished, so a repeat finds nothing to attach to.
    assert_eq!(
        a.receive_bytes(pk(2), &consent.bytes, 13),
        vec![Event::FrameRejected(Reason::Unknown)]
    );
    assert_eq!(flush(&mut a).len(), 2);
}

#[test]
fn refused_invitations_change_nothing() {
    let Pair {
        mut a,
        mut b,
        group,
    } = pair();
    a.invite(group, pk(2), DAY, 10).unwrap();
    flush(&mut a);
    let out = a.take_outgoing().remove(0);
    let reject = |r| vec![Event::FrameRejected(r)];
    // Wrong sender: the invitation names pk(1).
    assert_eq!(
        b.receive_bytes(pk(9), &out.bytes, 11),
        reject(Reason::Invalid)
    );
    // Past its deadline.
    assert_eq!(
        b.receive_bytes(pk(1), &out.bytes, 10 + DAY),
        reject(Reason::Expired)
    );
    // Damaged anywhere in the signed part.
    for index in 5..out.bytes.len() {
        let mut damaged = out.bytes.clone();
        damaged[index] ^= 1;
        assert!(
            !b.receive_bytes(pk(1), &damaged, 11).is_empty(),
            "byte {index}"
        );
    }
    // Someone the invitation is not addressed to.
    let mut stranger = GroupHandle::new(Installation::new(sk(3)));
    assert_eq!(
        stranger.receive_bytes(pk(1), &out.bytes, 11),
        reject(Reason::Invalid)
    );
    assert!(b.pending_invitations().is_empty());
    assert!(flush(&mut b).is_empty());
}

#[test]
fn an_invitation_is_accepted_only_by_the_identity_it_names() {
    let mut a = GroupHandle::new(Installation::new(sk(1)));
    let mut b = GroupHandle::new(Installation::new(sk(2)));
    let mut rng = StdRng::seed_from_u64(6);
    support::meet(a.installation_mut(), b.installation_mut(), 1, &mut rng);
    let mut c = GroupHandle::new(Installation::new(sk(3)));
    support::meet(a.installation_mut(), c.installation_mut(), 2, &mut rng);
    a.create(Policy::InviterOnly, &[], &mut OsRng).unwrap();
    flush(&mut a);
    a.take_outgoing();
    let group = a.group_ids()[0];
    a.invite(group, pk(3), DAY, 10).unwrap();
    flush(&mut a);
    let out = a.take_outgoing().remove(0);
    // b is not the candidate, so it refuses; c is.
    assert_eq!(
        b.receive_bytes(pk(1), &out.bytes, 11),
        vec![Event::FrameRejected(Reason::Invalid)]
    );
    assert!(c.receive_bytes(pk(1), &out.bytes, 11).is_empty());
}

#[test]
fn the_received_invitation_bounds_refuse_without_dropping() {
    let Pair {
        mut a,
        mut b,
        group,
    } = pair();
    for i in 0..MAX_RECEIVED_PER_INVITER {
        a.invite(group, pk(2), DAY, 10 + i as u64).unwrap();
    }
    flush(&mut a);
    assert!(deliver(&mut a, &mut b, 20).is_empty());
    a.invite(group, pk(2), DAY, 30).unwrap();
    flush(&mut a);
    let rejected = deliver(&mut a, &mut b, 31);
    assert_eq!(rejected, vec![Event::FrameRejected(Reason::Full)]);
    assert_eq!(b.pending_invitations().len(), MAX_RECEIVED_PER_INVITER);
}

#[test]
fn consent_from_the_wrong_party_or_for_an_unknown_invitation_is_refused() {
    let Pair {
        mut a,
        mut b,
        group,
    } = pair();
    a.invite(group, pk(2), DAY, 10).unwrap();
    flush(&mut a);
    deliver(&mut a, &mut b, 11);
    let invitation = invitation_of(&flush(&mut b));
    b.accept(invitation, 12).unwrap();
    flush(&mut b);
    let consent = b.take_outgoing().remove(0);
    assert_eq!(
        a.receive_bytes(pk(9), &consent.bytes, 13),
        vec![Event::FrameRejected(Reason::Invalid)]
    );
    let mut unknown = consent.bytes.clone();
    unknown[5] ^= 1;
    assert_eq!(
        a.receive_bytes(pk(2), &unknown, 13),
        vec![Event::FrameRejected(Reason::Unknown)]
    );
    let mut forged = consent.bytes.clone();
    *forged.last_mut().unwrap() ^= 1;
    assert_eq!(
        a.receive_bytes(pk(2), &forged, 13),
        vec![Event::FrameRejected(Reason::Invalid)]
    );
    assert!(flush(&mut a).is_empty());
}

#[test]
fn invitations_expire_and_their_operations_are_rejected() {
    let Pair { mut a, group, .. } = pair();
    let op = a.invite(group, pk(2), DAY, 10).unwrap();
    flush(&mut a);
    assert_eq!(a.op_state(op), Some(OpState::Pending));
    a.save(10 + DAY).unwrap();
    assert_eq!(a.op_state(op), Some(OpState::Rejected(Reason::Expired)));
}

#[test]
fn a_failed_write_or_a_restart_in_the_middle_loses_nothing_that_was_confirmed() {
    let Pair {
        mut a,
        mut b,
        group,
    } = pair();
    let op = a.invite(group, pk(2), DAY, 10).unwrap();
    flush(&mut a);
    deliver(&mut a, &mut b, 11);
    let (token, received_blob) = b.save(11).unwrap();
    b.confirm_saved(token);
    let invitation = b.pending_invitations()[0].0;

    // b accepts, but the write fails: no consent leaves, and the last blob still has the
    // pending invitation, so a restart can accept again with the same signature.
    b.accept(invitation, 12).unwrap();
    let (_unconfirmed, _blob) = b.save(12).unwrap();
    assert!(b.take_outgoing().is_empty());
    let mut b = GroupHandle::restore(&received_blob, [sk(2)]).unwrap();
    assert_eq!(b.pending_invitations().len(), 1);
    b.accept(invitation, 12).unwrap();
    flush(&mut b);
    let consent = b.take_outgoing().remove(0);

    // a restarts from its blob before the consent arrives.
    let (token, a_blob) = a.save(12).unwrap();
    a.confirm_saved(token);
    let mut a = GroupHandle::restore(&a_blob, [sk(1)]).unwrap();
    assert!(a.receive_bytes(pk(2), &consent.bytes, 13).is_empty());
    assert!(flush(&mut a).contains(&Event::ConsentReceived(op)));
}

#[test]
fn gated_devices_and_other_policies_do_not_invite() {
    let Pair { mut a, group, .. } = pair();
    a.installation_mut().gate_voting();
    assert_eq!(
        a.invite(group, pk(2), DAY, 10),
        Err(HandleError::Ineligible)
    );
    let mut c = GroupHandle::new(Installation::new(sk(4)));
    c.create(Policy::Majority, &[], &mut OsRng).unwrap();
    let id = c.group_ids()[0];
    assert_eq!(
        c.invite(id, pk(2), DAY, 10),
        Err(HandleError::UnsupportedPolicy)
    );
    assert_eq!(c.invite(77, pk(2), DAY, 10), Err(HandleError::Unknown));
    let mut d = GroupHandle::new(Installation::new(sk(5)));
    d.create(Policy::InviterOnly, &[], &mut OsRng).unwrap();
    let id = d.group_ids()[0];
    assert_eq!(d.invite(id, pk(2), 0, 10), Err(HandleError::Invalid));
    assert_eq!(d.invite(id, pk(2), 31 * DAY, 10), Err(HandleError::Invalid));
    // pk(2) is no verified contact of d, so the voucher cannot be issued.
    assert_eq!(d.invite(id, pk(2), DAY, 10), Err(HandleError::Ineligible));
}
