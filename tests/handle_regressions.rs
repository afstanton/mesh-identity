#![cfg(feature = "groups")]
mod support;
use cbor2::Value;
use mesh_identity::groups::Policy;
use mesh_identity::groups::handle::*;
use mesh_identity::session::installation::{Installation, InstallationSnapshot};
use rand::SeedableRng;
use rand::rngs::OsRng;
use support::world::*;

#[test]
fn identity_switch_must_not_make_saved_handle_unrestorable() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    w.pump(20, &mut Vec::new(), None);
    assert_eq!(w.h(9).pending_invitations().len(), 1);
    w.h(9).installation_mut().add_identity(sk(10)).unwrap();
    w.h(9).installation_mut().select(pk(10), 21).unwrap();
    let (_, saved) = w.h(9).save(21).unwrap();
    let restored = GroupHandle::restore(&saved, [sk(9), sk(10)]);
    assert!(
        restored.is_ok(),
        "valid identity switch produced unrestorable blob: {:?}",
        restored.err()
    );
}

#[test]
fn leave_after_roster_change_must_have_valid_tenure_signature() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.invite_and_accept(20);
    assert!(w.pump(21, &mut Vec::new(), None).is_empty());
    assert_eq!(w.h(2).group(group).unwrap().revision(), 1);
    w.h(2).leave(group, 22).unwrap();
    flush(w.h(2));
    let departure = w
        .h(2)
        .take_outgoing()
        .into_iter()
        .find(|o| o.kind == Tag::Departure)
        .unwrap();
    let refused = w.h(1).receive_bytes(pk(2), &departure.bytes, 23);
    assert!(
        refused.is_empty(),
        "legitimate departure rejected: {refused:?}"
    );
}

#[test]
fn another_identity_in_same_group_must_not_inherit_local_leave() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.h(1).installation_mut().add_identity(sk(2)).unwrap();
    w.h(1).leave(group, 20).unwrap();
    w.h(1).installation_mut().select(pk(2), 21).unwrap();
    assert!(
        w.h(1).group(group).is_some(),
        "leaving as identity 1 hides identity 2's active membership"
    );
}

#[test]
fn save_tokens_from_discarded_handles_must_not_confirm_new_state() {
    let mut old = GroupHandle::new(Installation::new(sk(1)));
    let (base_token, base) = old.save(0).unwrap();
    old.confirm_saved(base_token);
    old.create(Policy::InviterOnly, &[pk(2)], &mut OsRng)
        .unwrap();
    let (stale_token, _old_write) = old.save(1).unwrap();
    let mut recovered = GroupHandle::restore(&base, [sk(1)]).unwrap();
    recovered
        .create(Policy::InviterOnly, &[pk(3)], &mut OsRng)
        .unwrap();
    let (_new_token, _unwritten) = recovered.save(2).unwrap();
    assert!(
        recovered.confirm_saved(stale_token).is_empty(),
        "an old handle's token confirmed different unwritten state"
    );
    assert!(recovered.take_outgoing().is_empty());
}

#[test]
fn queue_full_must_not_permanently_lose_a_signed_vote() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    w.pump(20, &mut Vec::new(), None);
    let invitation = w.h(9).pending_invitations()[0].0;
    w.h(9).accept(invitation, 21).unwrap();
    flush(w.h(9));
    let consent = w.h(9).take_outgoing().remove(0);
    for _ in 0..MAX_STAGED_ITEMS - 1 {
        w.h(1).resend(OpId(1)).unwrap();
    }
    assert_eq!(
        w.h(1).receive_bytes(pk(9), &consent.bytes, 22),
        vec![Event::FrameRejected(Reason::Full)]
    );
    assert!(
        !w.h(1)
            .admission_progress(invitation)
            .is_some_and(|p| p.signed_prepare)
    );
    flush(w.h(1));
    let mut outgoing = w.h(1).take_outgoing();
    assert!(w.h(1).receive_bytes(pk(9), &consent.bytes, 23).is_empty());
    flush(w.h(1));
    outgoing.extend(w.h(1).take_outgoing());
    assert!(
        outgoing.iter().any(|o| o.kind == Tag::RosterVote),
        "prepare marked signed but vote was lost permanently at capacity"
    );
}

fn array_key(key: [u8; 32]) -> Value {
    Value::Array(key.into_iter().map(|v| Value::Integer(v.into())).collect())
}
#[test]
fn candidate_must_not_accept_a_rewritten_roster_with_the_same_head() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.invite_and_accept(20);
    let mut held = Vec::new();
    assert!(
        w.pump(21, &mut held, Some((9, Tag::GroupSnapshot)))
            .is_empty()
    );
    // A legacy local snapshot with a genuine head label and modified membership
    // must never be accepted as a network join proof.
    let original = &held[0].2;
    let (tag, body) = decode_frame(original).unwrap();
    let saved = w.h(1).group(group).unwrap().to_bytes().unwrap();
    let mut wire: Value = cbor2::from_reader(saved.as_slice()).unwrap();
    let Value::Map(fields) = &mut wire else {
        panic!()
    };
    let (_, Value::Array(identities)) = fields
        .iter_mut()
        .find(|(name, _)| *name == Value::Text("identities".into()))
        .unwrap()
    else {
        panic!()
    };
    for entry in identities {
        let Value::Array(pair) = entry else { panic!() };
        if pair[0] == array_key(pk(2)) {
            pair[0] = array_key(pk(8));
        }
    }
    let mut modified_body = body[..32].to_vec();
    cbor2::to_writer(&wire, &mut modified_body).unwrap();
    let modified = encode_frame(tag, &modified_body).unwrap();
    let refused = w.h(9).receive_bytes(pk(1), &modified, 22);
    assert!(
        !refused.is_empty(),
        "candidate accepted inviter-supplied roster with key 2 replaced by unauthorized key 8"
    );
    assert!(w.h(9).group(group).is_none());
}

#[test]
fn resend_completed_admission_must_recover_a_lost_join_snapshot() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    let op = w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    w.pump(20, &mut Vec::new(), None);
    let binding = w.h(9).pending_invitations()[0].0;
    w.h(9).accept(binding, 21).unwrap();
    let mut lost = Vec::new();
    w.pump(22, &mut lost, Some((9, Tag::GroupSnapshot)));
    assert_eq!(w.h(1).op_state(op), Some(OpState::Completed));
    assert!(w.h(9).group(group).is_none());
    w.h(1).resend(op).unwrap();
    flush(w.h(1));
    assert!(
        w.h(1)
            .take_outgoing()
            .iter()
            .any(|o| o.kind == Tag::GroupSnapshot),
        "completed op only resends original invitation, not the lost join response"
    );
}

#[test]
fn saving_many_identities_must_not_produce_unreadable_snapshot() {
    let mut i = Installation::new(sk(1));
    i.set_max_identities(1025).unwrap();
    for index in 0..1024u32 {
        let mut seed = [0u8; 32];
        seed[..4].copy_from_slice(&index.to_be_bytes());
        i.add_identity(ed25519_dalek::SigningKey::from_bytes(&seed))
            .unwrap();
    }
    let bytes = i.save_bytes(0).unwrap();
    assert!(
        InstallationSnapshot::from_bytes(&bytes).is_ok(),
        "successful save of 1025 owned identities is rejected on restore"
    );
}

#[test]
fn saves_and_outgoing_events_keep_their_authorizing_identity() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.h(1).installation_mut().add_identity(sk(2)).unwrap();
    let leave = w.h(1).leave(group, 20).unwrap();
    w.h(1).installation_mut().select(pk(2), 21).unwrap();
    let (token, blob) = w.h(1).save(21).unwrap();
    assert!(w.h(1).confirm_saved(token).is_empty());
    assert!(w.h(1).take_outgoing().is_empty());
    let mut restored = GroupHandle::restore(&blob, [sk(1), sk(2)]).unwrap();
    assert!(restored.group(group).is_some());
    assert!(restored.op_state(leave).is_none());
    restored.installation_mut().select(pk(1), 22).unwrap();
    assert!(restored.group(group).is_none());
    let (token, _) = restored.save(22).unwrap();
    assert_eq!(restored.confirm_saved(token), vec![Event::Left(group)]);
    let outgoing = restored.take_outgoing();
    assert_eq!(outgoing.len(), 1);
    assert_eq!(outgoing[0].from, pk(1));
    restored.installation_mut().select(pk(2), 23).unwrap();
    assert!(restored.leave(group, 23).is_ok());
}

#[test]
fn a_join_requires_the_actual_quorum_certificate_and_pinned_parent() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.invite_and_accept(20);
    let (_, before) = w.h(9).save(20).unwrap();
    let mut held = Vec::new();
    w.pump(21, &mut held, Some((9, Tag::GroupSnapshot)));
    let original = &held[0].2;
    // Damage a commit signature, remove a signature, or substitute a different
    // invitation binding: none may enable the candidate's membership.
    let mut bad = original.clone();
    *bad.last_mut().unwrap() ^= 1;
    let mut parsed = GroupHandle::restore(&before, [sk(9)]).unwrap();
    assert!(!parsed.receive_bytes(pk(1), &bad, 22).is_empty());
    assert!(parsed.group(group).is_none());
    let (tag, body) = decode_frame(original).unwrap();
    let mut short =
        mesh_identity::groups::evidence::VersionedCertificate::from_bytes(&body[32..]).unwrap();
    match &mut short {
        mesh_identity::groups::evidence::VersionedCertificate::V1(v1) => {
            v1.certificate.prepares.truncate(1);
            v1.certificate.commits.truncate(1);
        }
        _ => unreachable!(),
    }
    let mut short_body = body[..32].to_vec();
    short_body.extend_from_slice(&short.to_bytes().unwrap());
    let short_frame = encode_frame(tag, &short_body).unwrap();
    assert!(!parsed.receive_bytes(pk(1), &short_frame, 22).is_empty());
    assert!(parsed.group(group).is_none());
    let mut wrong = body.to_vec();
    wrong[0] ^= 1;
    let wrong = encode_frame(tag, &wrong).unwrap();
    assert!(!parsed.receive_bytes(pk(1), &wrong, 22).is_empty());
    assert!(parsed.receive_bytes(pk(1), original, 22).is_empty());
    assert!(parsed.group(group).unwrap().membership(pk(9)).is_some());
}

#[test]
fn independent_genesis_authentication_is_checked_before_consent() {
    use sha2::{Digest, Sha256};
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    let genesis = w.h(1).group(group).unwrap().genesis_bytes().unwrap();
    let digest: [u8; 32] = Sha256::digest(genesis).into();
    w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    w.pump(20, &mut Vec::new(), None);
    let binding = w.h(9).pending_invitations()[0].0;
    assert_eq!(
        w.h(9).accept_authenticated(binding, [0; 32], 21),
        Err(HandleError::Invalid)
    );
    assert!(w.h(9).take_outgoing().is_empty());
    assert!(w.h(9).accept_authenticated(binding, digest, 21).is_ok());
    assert!(w.pump(22, &mut Vec::new(), None).is_empty());
    assert!(w.h(9).group(group).is_some());
}

#[test]
fn two_owned_members_keep_independent_votes_in_the_same_group() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.h(1).installation_mut().add_identity(sk(2)).unwrap();
    w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    flush(w.h(1));
    let invitation = w
        .h(1)
        .take_outgoing()
        .into_iter()
        .find(|o| o.kind == Tag::Invitation)
        .unwrap();
    w.h(9).receive_bytes(pk(1), &invitation.bytes, 20);
    flush(w.h(9));
    let binding = w.h(9).pending_invitations()[0].0;
    w.h(9).accept(binding, 21).unwrap();
    flush(w.h(9));
    let consent = w.h(9).take_outgoing().remove(0);
    assert!(w.h(1).receive_bytes(pk(9), &consent.bytes, 21).is_empty());
    flush(w.h(1));
    let from_first = w.h(1).take_outgoing();
    let first_vote = from_first
        .iter()
        .find(|o| o.kind == Tag::RosterVote)
        .unwrap();
    let forwarded = from_first.iter().find(|o| o.kind == Tag::Consent).unwrap();
    assert_eq!(first_vote.from, pk(1));
    w.h(1).installation_mut().select(pk(2), 22).unwrap();
    assert!(
        w.h(1)
            .receive_bytes(pk(1), &invitation.bytes, 22)
            .is_empty()
    );
    assert!(w.h(1).receive_bytes(pk(1), &forwarded.bytes, 22).is_empty());
    flush(w.h(1));
    let second = w.h(1).take_outgoing();
    assert!(
        second
            .iter()
            .any(|o| o.from == pk(2) && o.kind == Tag::RosterVote)
    );
    assert!(w.h(1).admission_progress(binding).unwrap().signed_prepare);
    let (_, saved) = w.h(1).save(22).unwrap();
    let mut restored = GroupHandle::restore(&saved, [sk(1), sk(2)]).unwrap();
    assert!(restored.admission_progress(binding).unwrap().signed_prepare);
    restored.installation_mut().select(pk(1), 23).unwrap();
    assert!(restored.admission_progress(binding).unwrap().signed_prepare);
}

#[test]
fn invitation_parent_cannot_be_rewritten_under_the_same_signed_binding() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    flush(w.h(1));
    let original = w.h(1).take_outgoing().remove(0);
    let (tag, body) = decode_frame(&original.bytes).unwrap();
    const PREFIX: usize = 213 + 216 + 32;
    let mut history: Value = cbor2::from_reader(&body[PREFIX..]).unwrap();
    let Value::Map(entries) = &mut history else {
        panic!()
    };
    let (_, genesis) = entries
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some("genesis"))
        .unwrap();
    let Value::Array(genesis_items) = genesis else {
        panic!()
    };
    let mut raw: Vec<u8> = genesis_items
        .iter()
        .map(|v| u8::try_from(v.as_integer().unwrap()).unwrap())
        .collect();
    let pos = raw.windows(32).position(|key| key == pk(2)).unwrap();
    raw[pos..pos + 32].copy_from_slice(&pk(8));
    *genesis = Value::Array(raw.into_iter().map(|b| Value::Integer(b.into())).collect());
    let mut changed = body[..PREFIX].to_vec();
    cbor2::to_writer(&history, &mut changed).unwrap();
    let changed = encode_frame(tag, &changed).unwrap();
    assert!(!w.h(9).receive_bytes(pk(1), &changed, 21).is_empty());
    assert!(w.h(9).pending_invitations().is_empty());
    assert!(w.h(9).receive_bytes(pk(1), &original.bytes, 21).is_empty());
}

#[test]
fn confirm_saved_with_different_selected_identity_releases_output_and_completes_op() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.h(1).installation_mut().add_identity(sk(2)).unwrap();
    let leave = w.h(1).leave(group, 20).unwrap();
    // Switch to identity 2 before save and confirm
    w.h(1).installation_mut().select(pk(2), 21).unwrap();
    let (token, _) = w.h(1).save(21).unwrap();
    assert!(w.h(1).confirm_saved(token).is_empty());
    assert!(w.h(1).take_outgoing().is_empty());

    // Switch back to identity 1 on the live handle: operation must not be stranded
    w.h(1).installation_mut().select(pk(1), 22).unwrap();
    assert_eq!(w.h(1).op_state(leave), Some(OpState::Completed));
    let outgoing = w.h(1).take_outgoing();
    assert_eq!(
        outgoing.len(),
        1,
        "outgoing bytes for identity 1 were stranded"
    );
    assert_eq!(outgoing[0].from, pk(1));

    // Confirming token again under identity 1 drains identity 1's events
    let events = w.h(1).confirm_saved(token);
    assert_eq!(events, vec![Event::Left(group)]);
}

#[test]
fn local_group_view_updates_to_latest_revision_across_owned_members() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    w.h(1).installation_mut().add_identity(sk(2)).unwrap();
    // Identity 1 and Identity 2 are both on the initial roster
    w.h(1).installation_mut().select(pk(2), 20).unwrap();
    assert_eq!(w.h(1).group(group).unwrap().revision(), 0);

    // Switch back to Identity 1 and admit candidate 9
    w.h(1).installation_mut().select(pk(1), 21).unwrap();
    w.invite_and_accept(21);
    assert!(w.pump(22, &mut Vec::new(), None).is_empty());
    assert_eq!(w.h(1).group(group).unwrap().revision(), 1);

    // Switch to Identity 2: its local view must update to revision 1
    w.h(1).installation_mut().select(pk(2), 23).unwrap();
    flush(w.h(1));
    assert_eq!(
        w.h(1).group(group).unwrap().revision(),
        1,
        "identity 2 view was not updated to revision 1"
    );
    assert!(
        w.h(1).group(group).unwrap().membership(pk(9)).is_some(),
        "identity 2 view missing newly admitted member 9"
    );
}

#[test]
fn redelivered_certificate_and_snapshot_frames_must_be_ignored_idempotently() {
    let mut w = World::new(&[2, 3]);
    let group = w.group;
    let op = w.h(1).invite(group, pk(9), DAY, 20).unwrap();
    w.pump(20, &mut Vec::new(), None);
    let binding = w.h(9).pending_invitations()[0].0;
    w.h(9).accept(binding, 21).unwrap();
    let mut snapshot_frames = Vec::new();
    w.pump(22, &mut snapshot_frames, Some((9, Tag::GroupSnapshot)));
    let snapshot_frame = &snapshot_frames[0].2;

    // First snapshot delivery admits candidate 9
    let refused = w.h(9).receive_bytes(pk(1), snapshot_frame, 23);
    assert!(refused.is_empty(), "snapshot refused: {refused:?}");
    assert!(w.h(9).group(group).is_some());

    // Duplicate snapshot delivery for an already-consumed invitation safely returns Reason::Unknown
    let redelivered = w.h(9).receive_bytes(pk(1), snapshot_frame, 24);
    assert_eq!(
        redelivered,
        vec![Event::FrameRejected(Reason::Unknown)],
        "duplicate snapshot did not reject as Unknown"
    );

    // Duplicate certificate delivery to member 2
    w.h(1).resend(op).unwrap();
    flush(w.h(1));
    let cert_frame = w
        .h(1)
        .take_outgoing()
        .into_iter()
        .find(|o| o.kind == Tag::Certificate)
        .unwrap();
    let redelivered_cert = w.h(2).receive_bytes(pk(1), &cert_frame.bytes, 25);
    assert_eq!(
        redelivered_cert,
        vec![Event::FrameRejected(Reason::Unknown)],
        "duplicate certificate did not reject as Unknown"
    );
}

#[test]
fn restore_rejects_oversize_ops_or_left_lists() {
    let mut h = GroupHandle::new(Installation::new(sk(1)));
    let (_, blob) = h.save(0).unwrap();
    let mut wire: Value = cbor2::from_reader(blob.as_slice()).unwrap();
    let Value::Map(ref mut fields) = wire else {
        panic!()
    };

    // Inject 3000 dummy ops into wire.ops
    let ops_entry = fields
        .iter_mut()
        .find(|(k, _)| k.as_text() == Some("ops"))
        .unwrap();
    let mut dummy_ops = Vec::new();
    for id in 0..3000u64 {
        dummy_ops.push(Value::Map(vec![
            (Value::Text("owner".into()), array_key(pk(1))),
            (Value::Text("id".into()), Value::Integer(id.into())),
            (Value::Text("state".into()), Value::Text("Completed".into())),
            (Value::Text("frames".into()), Value::Array(Vec::new())),
        ]));
    }
    ops_entry.1 = Value::Array(dummy_ops);

    let mut bad_blob = Vec::new();
    cbor2::to_writer(&wire, &mut bad_blob).unwrap();
    let res = GroupHandle::restore(&bad_blob, [sk(1)]);
    assert_eq!(
        res.err(),
        Some(HandleError::TooLarge),
        "restore did not reject oversized ops list"
    );
}

#[test]
fn historical_replay_with_out_of_order_invitation_deadlines_must_succeed() {
    use mesh_identity::groups::evidence::MAX_LIFETIME_MS;
    let mut w = World::new(&[2, 3]);
    let group = w.group;

    // Step 1: inviter 1 issues invitation with large lifetime at t=500_000_000
    w.h(1)
        .invite(group, pk(9), MAX_LIFETIME_MS, 500_000_000)
        .unwrap();
    w.pump(500_000_000, &mut Vec::new(), None);
    let inv9 = w.h(9).pending_invitations()[0].0;
    w.h(9).accept(inv9, 500_000_000).unwrap();
    assert!(w.pump(500_000_001, &mut Vec::new(), None).is_empty());
    assert!(w.h(9).group(group).is_some());

    // Step 2: candidate 10 is invited at t=500_000_100
    let mut cand10 = GroupHandle::new(Installation::new(sk(10)));
    let mut rng = rand::rngs::StdRng::seed_from_u64(42);
    support::meet(
        w.h(1).installation_mut(),
        cand10.installation_mut(),
        500_000_100,
        &mut rng,
    );
    w.handles.push((10, cand10));
    w.h(1).invite(group, pk(10), 10_000, 500_000_100).unwrap();
    assert!(w.pump(500_000_100, &mut Vec::new(), None).is_empty());
    let inv10 = w.h(10).pending_invitations()[0].0;
    w.h(10).accept(inv10, 500_000_101).unwrap();
    assert!(w.pump(500_000_102, &mut Vec::new(), None).is_empty());
    assert!(w.h(10).group(group).is_some());

    // Step 3: Candidate 11 receives invitation carrying history of Step 1 and Step 2
    let mut cand11 = GroupHandle::new(Installation::new(sk(11)));
    support::meet(
        w.h(1).installation_mut(),
        cand11.installation_mut(),
        500_000_200,
        &mut rng,
    );
    w.handles.push((11, cand11));
    w.h(1).invite(group, pk(11), 10_000, 500_000_200).unwrap();
    assert!(w.pump(500_000_200, &mut Vec::new(), None).is_empty());
    assert_eq!(w.h(11).pending_invitations().len(), 1);
}
