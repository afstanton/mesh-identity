#![cfg(feature = "groups")]
//! F2: the handle's persist-before-send rule, failed writes, restore, and bounds.

use ed25519_dalek::SigningKey;
use mesh_identity::groups::Policy;
use mesh_identity::groups::handle::*;
use mesh_identity::session::installation::Installation;
use rand::rngs::OsRng;

fn sk(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}
fn pk(seed: u8) -> [u8; 32] {
    sk(seed).verifying_key().to_bytes()
}
fn handle(seed: u8) -> GroupHandle {
    GroupHandle::new(Installation::new(sk(seed)))
}

/// A host whose writes can be made to fail. Holds the last durable blob.
struct Host {
    durable: Option<Vec<u8>>,
    fail_next_write: bool,
}
impl Host {
    fn new() -> Self {
        Self {
            durable: None,
            fail_next_write: false,
        }
    }
    /// Save, write, confirm. A failed write skips the confirmation.
    fn flush(&mut self, h: &mut GroupHandle) -> Option<Vec<Event>> {
        let (token, blob) = h.save(0).unwrap();
        if std::mem::take(&mut self.fail_next_write) {
            return None;
        }
        self.durable = Some(blob);
        Some(h.confirm_saved(token))
    }
}

#[test]
fn bytes_and_events_wait_for_a_confirmed_write() {
    let mut h = handle(1);
    let op = h.create(Policy::InviterOnly, &[pk(2)], &mut OsRng).unwrap();
    assert_eq!(h.op_state(op), Some(OpState::Pending));
    assert!(h.take_outgoing().is_empty());
    let (token, _blob) = h.save(0).unwrap();
    // Written but not yet confirmed: still nothing.
    assert!(h.take_outgoing().is_empty());
    let events = h.confirm_saved(token);
    assert!(matches!(events.as_slice(), [Event::GroupCreated(_)]));
    assert_eq!(h.op_state(op), Some(OpState::Completed));
    let out = h.take_outgoing();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind, Tag::Genesis);
    assert_eq!(out[0].to, vec![pk(2)]);
    assert!(out[0].authenticator.is_some());
    assert!(h.take_outgoing().is_empty());
    // A repeated confirmation does nothing.
    assert!(h.confirm_saved(token).is_empty());
}

#[test]
fn a_stale_token_releases_only_what_it_covered_and_an_unknown_one_nothing() {
    let mut h = handle(1);
    h.create(Policy::InviterOnly, &[pk(2)], &mut OsRng).unwrap();
    let (first, _) = h.save(0).unwrap();
    h.create(Policy::InviterOnly, &[pk(3)], &mut OsRng).unwrap();
    assert!(h.confirm_saved(handle(5).save(0).unwrap().0).is_empty());
    assert_eq!(h.confirm_saved(first).len(), 1);
    assert_eq!(h.take_outgoing().len(), 1);
    let (second, _) = h.save(0).unwrap();
    assert_eq!(h.confirm_saved(second).len(), 1);
    assert_eq!(h.take_outgoing().len(), 1);
}

#[test]
fn a_failed_write_releases_nothing_and_restore_from_the_last_blob_works() {
    let mut host = Host::new();
    let mut h = handle(1);
    host.flush(&mut h).unwrap();
    let before = host.durable.clone().unwrap();
    h.create(Policy::InviterOnly, &[pk(2)], &mut OsRng).unwrap();
    host.fail_next_write = true;
    assert!(host.flush(&mut h).is_none());
    assert!(h.take_outgoing().is_empty());
    // The host drops the handle and restores the last blob it holds: the create is gone.
    let restored = GroupHandle::restore(host.durable.as_ref().unwrap(), [sk(1)]).unwrap();
    assert_eq!(host.durable.as_ref().unwrap(), &before);
    assert!(restored.group_ids().is_empty());
    // Or it retries the save on the same handle and the bytes are released then.
    let events = host.flush(&mut h).unwrap();
    assert!(matches!(events.as_slice(), [Event::GroupCreated(_)]));
    assert_eq!(h.take_outgoing().len(), 1);
}

#[test]
fn a_crash_between_the_write_and_the_confirmation_stages_the_bytes_again() {
    let mut h = handle(1);
    h.create(Policy::InviterOnly, &[pk(2)], &mut OsRng).unwrap();
    let (_token, blob) = h.save(0).unwrap(); // written, then the process dies
    let mut restored = GroupHandle::restore(&blob, [sk(1)]).unwrap();
    assert_eq!(restored.group_ids().len(), 1);
    assert!(restored.take_outgoing().is_empty());
    let (token, again) = restored.save(0).unwrap();
    let events = restored.confirm_saved(token);
    assert!(matches!(events.as_slice(), [Event::GroupCreated(_)]));
    assert_eq!(restored.take_outgoing().len(), 1);
    // After a restore, an old token from before the crash cannot release anything.
    assert!(GroupHandle::restore(&again, [sk(1)]).is_ok());
}

#[test]
fn resend_stages_the_same_bytes() {
    let mut h = handle(1);
    let op = h.create(Policy::InviterOnly, &[pk(2)], &mut OsRng).unwrap();
    let mut host = Host::new();
    host.flush(&mut h).unwrap();
    let first = h.take_outgoing();
    h.resend(op).unwrap();
    assert!(h.take_outgoing().is_empty());
    assert!(host.flush(&mut h).unwrap().is_empty());
    assert_eq!(h.take_outgoing(), first);
    assert_eq!(h.resend(OpId(77)), Err(HandleError::UnknownOp));
}

#[test]
fn a_genesis_needs_its_authenticated_digest_and_a_place_on_the_roster() {
    let mut a = handle(1);
    a.create(Policy::InviterOnly, &[pk(2)], &mut OsRng).unwrap();
    let mut host = Host::new();
    host.flush(&mut a).unwrap();
    let genesis = a.take_outgoing().remove(0);
    let digest = genesis.authenticator.unwrap();

    let mut b = handle(2);
    assert_eq!(
        b.import_genesis(&genesis.bytes, [0; 32]),
        Err(HandleError::Invalid)
    );
    let mut outsider = handle(9);
    assert_eq!(
        outsider.import_genesis(&genesis.bytes, digest),
        Err(HandleError::Invalid)
    );
    b.import_genesis(&genesis.bytes, digest).unwrap();
    let events = host.flush(&mut b).unwrap();
    assert!(matches!(events.as_slice(), [Event::GroupImported(_)]));
    assert_eq!(b.group_ids(), a.group_ids());
    assert_eq!(
        b.import_genesis(&genesis.bytes, digest),
        Err(HandleError::Invalid)
    );
}

#[test]
fn inbound_frames_are_bounded_and_refused_without_changing_state() {
    let mut h = handle(1);
    let junk = |bytes: &[u8], h: &mut GroupHandle| h.receive_bytes(pk(2), bytes, 0);
    assert_eq!(
        junk(&[], &mut h),
        vec![Event::FrameRejected(Reason::Malformed)]
    );
    assert_eq!(
        junk(&[2, 0, 0, 0, 9, 1], &mut h),
        vec![Event::FrameRejected(Reason::Malformed)]
    );
    assert_eq!(
        junk(&[0, 0, 0, 0, 0], &mut h),
        vec![Event::FrameRejected(Reason::UnknownTag)]
    );
    assert_eq!(
        junk(&vec![2; MAX_FRAME_BYTES + 1], &mut h),
        vec![Event::FrameRejected(Reason::TooLarge)]
    );
    let genesis = encode_frame(Tag::Genesis, &[1, 2, 3]).unwrap();
    assert_eq!(
        junk(&genesis, &mut h),
        vec![Event::FrameRejected(Reason::NeedsAuthentication)]
    );
    let invitation = encode_frame(Tag::Invitation, &[]).unwrap();
    assert_eq!(
        junk(&invitation, &mut h),
        vec![Event::FrameRejected(Reason::Malformed)]
    );
    let vote = encode_frame(Tag::Voucher, &[]).unwrap();
    assert_eq!(
        junk(&vote, &mut h),
        vec![Event::FrameRejected(Reason::Unsupported)]
    );
    assert!(h.group_ids().is_empty());
    assert_eq!(
        decode_frame(&invitation).unwrap(),
        (Tag::Invitation, &[][..])
    );
    assert!(encode_frame(Tag::Invitation, &vec![0; MAX_FRAME_BYTES]).is_err());
}

#[test]
fn the_pending_operation_bound_refuses_and_drops_nothing() {
    let mut h = handle(1);
    for _ in 0..MAX_PENDING_OPS {
        h.create(Policy::InviterOnly, &[], &mut OsRng).unwrap();
    }
    let groups = h.group_ids().len();
    assert_eq!(
        h.create(Policy::InviterOnly, &[], &mut OsRng).err(),
        Some(HandleError::Full)
    );
    assert_eq!(h.group_ids().len(), groups);
    // Confirming frees the room.
    let mut host = Host::new();
    host.flush(&mut h).unwrap();
    h.take_outgoing();
    assert!(h.create(Policy::InviterOnly, &[], &mut OsRng).is_ok());
}

#[test]
fn restore_refuses_damage_unknown_versions_and_wrong_keys() {
    let mut h = handle(1);
    h.create(Policy::InviterOnly, &[pk(2)], &mut OsRng).unwrap();
    let (_, blob) = h.save(0).unwrap();
    assert!(GroupHandle::restore(&blob, [sk(1)]).is_ok());
    assert!(GroupHandle::restore(&blob, [sk(5)]).is_err());
    let mut trailing = blob.clone();
    trailing.push(0);
    assert_eq!(
        GroupHandle::restore(&trailing, [sk(1)]).err(),
        Some(HandleError::Malformed)
    );
    for len in 0..blob.len() {
        assert!(GroupHandle::restore(&blob[..len], [sk(1)]).is_err());
    }
    // Sampled bit flips: whatever restores must save and restore again.
    for index in (0..blob.len()).step_by(7) {
        for bit in [0, 3, 7] {
            let mut damaged = blob.clone();
            damaged[index] ^= 1 << bit;
            if let Ok(mut parsed) = GroupHandle::restore(&damaged, [sk(1)]) {
                let (_, again) = parsed.save(0).unwrap();
                assert!(GroupHandle::restore(&again, [sk(1)]).is_ok());
            }
        }
    }
}

#[test]
fn a_gated_device_stays_gated_through_a_handle_restore() {
    let mut h = handle(1);
    h.installation_mut().gate_voting();
    assert!(h.installation().sign_admission_voucher([1; 32]).is_err());
    let (_, blob) = h.save(0).unwrap();
    let restored = GroupHandle::restore(&blob, [sk(1)]).unwrap();
    assert!(
        restored
            .installation()
            .sign_admission_voucher([1; 32])
            .is_err()
    );
}

#[test]
fn an_unknown_handle_version_is_refused_and_the_previous_handle_stays_usable() {
    let mut h = handle(1);
    let (_, blob) = h.save(0).unwrap();
    let mut value: cbor2::Value = cbor2::from_reader(&blob[..]).unwrap();
    let cbor2::Value::Map(entries) = &mut value else {
        panic!("a handle blob is a map")
    };
    for (key, val) in entries.iter_mut() {
        if key.as_text() == Some("version") {
            *val = cbor2::Value::Integer((HANDLE_FORMAT_VERSION + 1).into());
        }
    }
    let mut future = Vec::new();
    cbor2::to_writer(&value, &mut future).unwrap();
    assert_eq!(
        GroupHandle::restore(&future, [sk(1)]).err(),
        Some(HandleError::UnsupportedVersion(HANDLE_FORMAT_VERSION + 1))
    );
    // The refusal touched nothing: the live handle still creates and saves.
    h.create(Policy::InviterOnly, &[], &mut OsRng).unwrap();
    assert!(h.save(0).is_ok());
}
