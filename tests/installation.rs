use ed25519_dalek::SigningKey;
use mesh_identity::session::installation::{Ceremony, Error, Installation};
use mesh_identity::session::{AttemptError, PAUSE_MS, SessionError};
use rand::{SeedableRng, rngs::StdRng};

fn exchange(
    alice: &mut Installation,
    bob: &mut Installation,
    now: u64,
    rng: &mut StdRng,
) -> (Ceremony, Ceremony, Vec<u8>) {
    let (a, offer) = alice.start(now, rng).unwrap();
    let b = bob.open_scanner(now).unwrap();
    let response = bob.scan_offer(&b, &offer, now, rng).unwrap();
    let reveal = alice.scan_response(&a, &response, now).unwrap();
    bob.scan_reveal(&b, &reveal, now).unwrap();
    (a, b, reveal)
}

#[test]
fn encounters_are_separate_and_private_grouping_preserves_continuity() {
    let mut rng = StdRng::seed_from_u64(871);
    let mut alice = Installation::new(SigningKey::generate(&mut rng));
    let mut bob = Installation::new(SigningKey::generate(&mut rng));
    let alice_key = alice.selected();
    let game = bob.selected();
    let private = bob.add_identity(SigningKey::generate(&mut rng)).unwrap();
    let mut game_contact = None;
    for (now, identity) in [(1, game), (2, private), (3, game)] {
        bob.select(identity, now).unwrap();
        let (a, b, _) = exchange(&mut alice, &mut bob, now, &mut rng);
        let ac = alice.comparison(&a, now).unwrap().unwrap();
        let bc = bob.comparison(&b, now).unwrap().unwrap();
        let contact = alice
            .confirm_and_save(&a, ac, bc.code, now, now, &mut rng)
            .unwrap();
        bob.confirm_and_save(&b, bc, ac.code, now, now, &mut rng)
            .unwrap();
        assert_eq!(contact.peer_ed25519_pk, identity);
        if identity == game {
            assert_eq!(
                *game_contact.get_or_insert(contact.local_contact_id),
                contact.local_contact_id
            );
        }
    }
    assert_eq!(
        bob.contacts(game)
            .unwrap()
            .get(&alice_key)
            .unwrap()
            .encounter_count,
        2
    );
    assert_eq!(
        bob.contacts(private)
            .unwrap()
            .get(&alice_key)
            .unwrap()
            .encounter_count,
        1
    );
    let export = |installation: &Installation| {
        let contacts = installation.contacts(alice_key).unwrap();
        [game, private].map(|key| contacts.export_contact(&key, Some("Bob".into())).unwrap())
    };
    let before = export(&alice);
    let group = alice.group_contacts(alice_key, [game, private]).unwrap();
    assert_eq!(group.peers().count(), 2);
    let grouped = export(&alice);
    assert_eq!(grouped, before);
    for (contact, key) in grouped.iter().zip([game, private]) {
        assert_eq!(
            serde_json::to_value(contact).unwrap(),
            serde_json::json!({ "peer_ed25519_pk": key, "label": "Bob" })
        );
    }
    assert_eq!(group.split().len(), 2);
    assert_eq!(export(&alice), before);
    assert_eq!(alice.contacts(alice_key).unwrap().count(), 2);
}

#[test]
fn encounter_frames_do_not_depend_on_unselected_identities() {
    fn frames(add_unselected: bool) -> [Vec<u8>; 3] {
        let mut rng = StdRng::seed_from_u64(891);
        let mut alice = Installation::new(SigningKey::generate(&mut rng));
        let mut bob = Installation::new(SigningKey::generate(&mut rng));
        if add_unselected {
            let mut extra_keys = StdRng::seed_from_u64(892);
            for installation in [&mut alice, &mut bob] {
                for _ in 0..3 {
                    installation
                        .add_identity(SigningKey::generate(&mut extra_keys))
                        .unwrap();
                }
            }
        }

        let (a, offer) = alice.start(1, &mut rng).unwrap();
        let b = bob.open_scanner(1).unwrap();
        let response = bob.scan_offer(&b, &offer, 1, &mut rng).unwrap();
        let reveal = alice.scan_response(&a, &response, 1).unwrap();
        bob.scan_reveal(&b, &reveal, 1).unwrap();
        [offer, response, reveal]
    }

    // Hold the selected keys and ceremony randomness constant so a change in
    // any frame can be attributed to the extra identities.
    assert_eq!(frames(false), frames(true));
}

#[test]
fn disclosure_debug_output_omits_identity_keys_and_nonce() {
    use mesh_identity::session::installation::{DisclosedLink, LinkPreview, LinkRequest};

    let recipient = [11; 32];
    let pair = [[22; 32], [33; 32]];
    let request = LinkRequest {
        recipient,
        nonce: [44; 32],
    };
    let link = DisclosedLink { recipient, pair };
    let preview = LinkPreview {
        pair,
        already_known: [true, false],
    };
    assert_eq!(format!("{request:?}"), "LinkRequest { .. }");
    assert_eq!(format!("{link:?}"), "DisclosedLink { .. }");
    assert_eq!(format!("{preview:?}"), "LinkPreview { .. }");
}

#[test]
fn delayed_callbacks_cannot_cross_an_identity_switch() {
    let mut rng = StdRng::seed_from_u64(872);
    let mut alice = Installation::new(SigningKey::generate(&mut rng));
    let mut bob = Installation::new(SigningKey::generate(&mut rng));
    let game = bob.selected();
    let private = bob.add_identity(SigningKey::generate(&mut rng)).unwrap();
    let (a, old, reveal) = exchange(&mut alice, &mut bob, 0, &mut rng);
    let stale = bob.comparison(&old, 0).unwrap().unwrap();
    assert_eq!(bob.select(private, 1), Err(Error::CeremonyActive));
    alice.cancel(&a, 1).unwrap();
    bob.cancel(&old, 1).unwrap();
    bob.select(private, 1).unwrap();
    let (a, fresh, _) = exchange(&mut alice, &mut bob, 2, &mut rng);
    assert_eq!(bob.scan_reveal(&old, &reveal, 2), Err(Error::StaleCeremony));
    assert_eq!(
        bob.confirm_and_save(&old, stale, stale.code, 2, 2, &mut rng),
        Err(Error::StaleCeremony)
    );
    let code = alice.comparison(&a, 2).unwrap().unwrap().code;
    let comparison = bob.comparison(&fresh, 2).unwrap().unwrap();
    bob.confirm_and_save(&fresh, comparison, code, 2, 2, &mut rng)
        .unwrap();
    assert_eq!(bob.contacts(game).unwrap().count(), 0);
    assert_eq!(bob.contacts(private).unwrap().count(), 1);
}

#[test]
fn switching_identities_keeps_the_retry_pause() {
    let mut rng = StdRng::seed_from_u64(873);
    let mut alice = Installation::new(SigningKey::generate(&mut rng));
    let mut bob = Installation::new(SigningKey::generate(&mut rng));
    let private = bob.add_identity(SigningKey::generate(&mut rng)).unwrap();
    for now in 0..3 {
        let (a, b, _) = exchange(&mut alice, &mut bob, now, &mut rng);
        alice.cancel(&a, now).unwrap();
        bob.cancel(&b, now).unwrap();
    }
    bob.select(private, 2).unwrap();
    assert!(
        matches!(bob.start(3, &mut rng), Err(Error::Session(SessionError::Attempt(AttemptError::Paused { until_ms }))) if until_ms == 2 + PAUSE_MS)
    );
    assert!(bob.start(2 + PAUSE_MS, &mut rng).is_ok());
}

#[test]
fn disclosure_requires_both_selected_keys_and_the_original_recipient_request() {
    let mut rng = StdRng::seed_from_u64(874);
    let mut alice = Installation::new(SigningKey::generate(&mut rng));
    let mut carol = Installation::new(SigningKey::generate(&mut rng));
    let mut bob = Installation::new(SigningKey::generate(&mut rng));
    let game = bob.selected();
    let private = bob.add_identity(SigningKey::generate(&mut rng)).unwrap();
    let third = bob.add_identity(SigningKey::generate(&mut rng)).unwrap();
    let pair = [game, private];

    let request = alice.request_link(0, &mut rng);
    let game_approval = bob.approve_link(&request, pair).unwrap();
    let duplicate = bob.approve_link(&request, pair).unwrap();
    assert!(
        alice
            .receive_link(request, pair, [game_approval, duplicate], 0)
            .is_none()
    );

    let request = alice.request_link(0, &mut rng);
    let game_approval = bob.approve_link(&request, pair).unwrap();
    bob.select(private, 0).unwrap();
    let private_approval = bob.approve_link(&request, pair).unwrap();
    assert!(
        carol
            .receive_link(request, pair, [game_approval, private_approval], 0)
            .is_none()
    );

    let request = alice.request_link(0, &mut rng);
    let private_approval = bob.approve_link(&request, pair).unwrap();
    bob.select(game, 0).unwrap();
    let game_approval = bob.approve_link(&request, pair).unwrap();
    let new_request = alice.request_link(0, &mut rng);
    assert!(
        alice
            .receive_link(new_request, pair, [game_approval, private_approval], 0)
            .is_none()
    );
    let game_approval = bob.approve_link(&new_request, pair).unwrap();
    bob.select(private, 0).unwrap();
    let private_approval = bob.approve_link(&new_request, pair).unwrap();
    let link = alice
        .receive_link(
            new_request,
            [private, game],
            [game_approval, private_approval],
            0,
        )
        .unwrap();
    assert_eq!(link.recipient, alice.selected());
    assert!(!link.pair.contains(&third));
    assert_eq!(alice.contacts(alice.selected()).unwrap().count(), 0);
}

#[test]
fn restoration_counts_pending_attempt_once_for_the_whole_installation() {
    let mut rng = StdRng::seed_from_u64(875);
    let mut alice = Installation::new(SigningKey::generate(&mut rng));
    let game_key = SigningKey::generate(&mut rng);
    let private_key = SigningKey::generate(&mut rng);
    let mut bob = Installation::new(game_key.clone());
    let private = bob.add_identity(private_key.clone()).unwrap();
    for now in 0..2 {
        let (a, b, _) = exchange(&mut alice, &mut bob, now, &mut rng);
        alice.cancel(&a, now).unwrap();
        bob.cancel(&b, now).unwrap();
    }
    let (_, old, reveal) = exchange(&mut alice, &mut bob, 2, &mut rng);
    let snapshot = bob.into_snapshot(2);
    let mut bob = Installation::restore(snapshot, [private_key.clone(), game_key.clone()]).unwrap();
    assert_eq!(bob.scan_reveal(&old, &reveal, 0), Err(Error::StaleCeremony));
    bob.select(private, 0).unwrap();
    assert_eq!(
        bob.contacts(private)
            .unwrap()
            .attempt_policy_state()
            .consecutive_incomplete,
        3
    );
    let snapshot = bob.into_snapshot(0);
    let mut bob = Installation::restore(snapshot, [game_key, private_key]).unwrap();
    assert_eq!(bob.selected(), private);
    assert!(matches!(
        bob.start(0, &mut rng),
        Err(Error::Session(SessionError::Attempt(
            AttemptError::Paused { until_ms: PAUSE_MS }
        )))
    ));
    assert!(bob.start(PAUSE_MS, &mut rng).is_ok());
}

#[test]
fn an_abandoned_scanner_lapses_and_a_handle_cannot_be_duplicated() {
    use mesh_identity::session::SESSION_TIMEOUT_MS;
    let mut rng = StdRng::seed_from_u64(875);
    let mut bob = Installation::new(SigningKey::generate(&mut rng));
    let private = bob.add_identity(SigningKey::generate(&mut rng)).unwrap();
    let lost = bob.open_scanner(0).unwrap();
    assert!(matches!(bob.open_scanner(1), Err(Error::CeremonyActive)));
    assert_eq!(bob.select(private, 1), Err(Error::CeremonyActive));
    // The UI never cancels; the idle ceremony lapses on its own.
    bob.select(private, SESSION_TIMEOUT_MS).unwrap();
    assert_eq!(
        bob.cancel(&lost, SESSION_TIMEOUT_MS),
        Err(Error::StaleCeremony)
    );
    assert!(bob.open_scanner(SESSION_TIMEOUT_MS).is_ok());
}

#[test]
fn dropped_scanner_handle_unlocks_installation_immediately() {
    let mut rng = StdRng::seed_from_u64(876);
    let mut bob = Installation::new(SigningKey::generate(&mut rng));
    let private = bob.add_identity(SigningKey::generate(&mut rng)).unwrap();
    let scanner = bob.open_scanner(0).unwrap();
    assert_eq!(bob.select(private, 1), Err(Error::CeremonyActive));
    drop(scanner);
    // As soon as the handle is dropped, persona switching succeeds without waiting for timeout.
    assert!(bob.select(private, 1).is_ok());
}

#[test]
fn dropping_active_handle_accounts_for_exposed_response_before_switch() {
    let mut rng = StdRng::seed_from_u64(877);
    let mut alice = Installation::new(SigningKey::generate(&mut rng));
    let mut bob = Installation::new(SigningKey::generate(&mut rng));
    let game = bob.selected();
    let private = bob.add_identity(SigningKey::generate(&mut rng)).unwrap();
    let (_, offer) = alice.start(0, &mut rng).unwrap();
    let old = bob.open_scanner(0).unwrap();
    bob.scan_offer(&old, &offer, 0, &mut rng).unwrap();
    assert!(
        bob.contacts(game)
            .unwrap()
            .attempt_policy_state()
            .pending_response
    );

    drop(old);
    bob.select(private, 1).unwrap();
    let old_policy = bob.contacts(game).unwrap().attempt_policy_state();
    assert_eq!(old_policy.consecutive_incomplete, 1);
    assert!(!old_policy.pending_response);
    assert!(bob.start(1, &mut rng).is_ok());
}

#[test]
fn disclosure_requires_a_live_unconsumed_local_request() {
    use mesh_identity::session::installation::LinkRequest;

    let mut rng = StdRng::seed_from_u64(878);
    let mut alice = Installation::new(SigningKey::generate(&mut rng));
    let mut bob = Installation::new(SigningKey::generate(&mut rng));
    let game = bob.selected();
    let private = bob.add_identity(SigningKey::generate(&mut rng)).unwrap();
    let pair = [game, private];
    let mut approve = |request: &LinkRequest| {
        bob.select(game, 0).unwrap();
        let first = bob.approve_link(request, pair).unwrap();
        bob.select(private, 0).unwrap();
        [first, bob.approve_link(request, pair).unwrap()]
    };

    let unsolicited = LinkRequest {
        recipient: alice.selected(),
        nonce: [7; 32],
    };
    assert!(
        alice
            .receive_link(unsolicited, pair, approve(&unsolicited), 0)
            .is_none()
    );

    let cancelled = alice.request_link(0, &mut rng);
    alice.cancel_link(cancelled);
    assert!(
        alice
            .receive_link(cancelled, pair, approve(&cancelled), 0)
            .is_none()
    );

    let superseded = alice.request_link(0, &mut rng);
    let live = alice.request_link(0, &mut rng);
    assert!(
        alice
            .receive_link(superseded, pair, approve(&superseded), 0)
            .is_none()
    );
    assert!(alice.receive_link(live, pair, approve(&live), 0).is_some());
    assert!(alice.receive_link(live, pair, approve(&live), 0).is_none());
}

#[test]
fn contact_copy_block_and_identity_removal_are_scoped() {
    use mesh_identity::contact::{ContactStatus, VerificationStatus};

    let mut rng = StdRng::seed_from_u64(879);
    let game_key = SigningKey::generate(&mut rng);
    let private_key = SigningKey::generate(&mut rng);
    let mut local = Installation::new(game_key.clone());
    let game = local.selected();
    let private = local.add_identity(private_key.clone()).unwrap();
    let mut remote = Installation::new(SigningKey::generate(&mut rng));
    let peer = remote.selected();
    let (a, b, _) = exchange(&mut local, &mut remote, 1, &mut rng);
    let ac = local.comparison(&a, 1).unwrap().unwrap();
    let bc = remote.comparison(&b, 1).unwrap().unwrap();
    let verified = local
        .confirm_and_save(&a, ac, bc.code, 1, 1, &mut rng)
        .unwrap();
    remote
        .confirm_and_save(&b, bc, ac.code, 1, 1, &mut rng)
        .unwrap();

    local.block_contact(game, peer).unwrap();
    let copy = local
        .copy_contact(game, private, peer, &mut rng)
        .unwrap()
        .clone();
    assert_eq!(
        copy.verification_status,
        VerificationStatus::ImportedUnverified
    );
    assert_eq!(copy.status, ContactStatus::Active);
    assert_eq!(copy.encounter_count, 0);
    assert_eq!(copy.last_transcript, [0; 32]);
    assert!(copy.local_alias.is_none());
    assert_ne!(copy.local_contact_id, verified.local_contact_id);
    assert_eq!(
        local.contacts(game).unwrap().get(&peer).unwrap().status,
        ContactStatus::Blocked
    );
    assert_eq!(
        local
            .copy_contact(private, game, peer, &mut rng)
            .unwrap()
            .status,
        ContactStatus::Blocked
    );

    let mut restored =
        Installation::restore(local.into_snapshot(2), [game_key, private_key.clone()]).unwrap();
    assert_eq!(restored.contacts(private).unwrap().get(&peer), Some(&copy));
    assert_eq!(restored.remove_identity(game), Err(Error::SelectedIdentity));
    restored.select(private, 2).unwrap();
    restored.remove_identity(game).unwrap();
    let restored = Installation::restore(restored.into_snapshot(2), [private_key]).unwrap();
    assert!(restored.contacts(game).is_none());
    assert_eq!(restored.contacts(private).unwrap().get(&peer), Some(&copy));
}

#[test]
fn disclosure_preview_distinguishes_known_key_from_discovery_and_expires() {
    use mesh_identity::session::SESSION_TIMEOUT_MS;

    let mut rng = StdRng::seed_from_u64(880);
    let mut alice = Installation::new(SigningKey::generate(&mut rng));
    let mut bob = Installation::new(SigningKey::generate(&mut rng));
    let known = bob.selected();
    let unknown = bob.add_identity(SigningKey::generate(&mut rng)).unwrap();
    let pair = [known, unknown];

    let (a, b, _) = exchange(&mut alice, &mut bob, 1, &mut rng);
    let ac = alice.comparison(&a, 1).unwrap().unwrap();
    let bc = bob.comparison(&b, 1).unwrap().unwrap();
    alice
        .confirm_and_save(&a, ac, bc.code, 1, 1, &mut rng)
        .unwrap();
    bob.confirm_and_save(&b, bc, ac.code, 1, 1, &mut rng)
        .unwrap();

    for accept in [false, true] {
        let now = if accept { SESSION_TIMEOUT_MS + 3 } else { 2 };
        bob.select(known, now).unwrap();
        let request = alice.request_link(now, &mut rng);
        let first = bob.approve_link(&request, pair).unwrap();
        bob.select(unknown, now).unwrap();
        let approvals = [first, bob.approve_link(&request, pair).unwrap()];
        let last_valid = now + SESSION_TIMEOUT_MS - 1;
        let preview = alice
            .preview_link(request, pair, &approvals, last_valid)
            .unwrap();
        for (key, already_known) in preview.pair.into_iter().zip(preview.already_known) {
            assert_eq!(already_known, key == known);
        }
        let received_at = last_valid + u64::from(!accept);
        assert_eq!(
            alice
                .receive_link(request, pair, approvals, received_at)
                .is_some(),
            accept
        );
        let contacts = alice.contacts(alice.selected()).unwrap();
        assert!(contacts.get(&known).is_some());
        assert!(contacts.get(&unknown).is_none());
    }
}

#[test]
fn signer_cancellation_closes_only_the_pending_disclosure_it_names() {
    let mut rng = StdRng::seed_from_u64(881);
    let mut alice = Installation::new(SigningKey::generate(&mut rng));
    let mut bob = Installation::new(SigningKey::generate(&mut rng));
    let game = bob.selected();
    let private = bob.add_identity(SigningKey::generate(&mut rng)).unwrap();
    let other = bob.add_identity(SigningKey::generate(&mut rng)).unwrap();
    let pair = [game, private];

    for first_approval_sent in [false, true] {
        bob.select(game, 0).unwrap();
        let request = alice.request_link(0, &mut rng);
        let first = first_approval_sent.then(|| bob.approve_link(&request, pair).unwrap());
        bob.select(private, 0).unwrap();
        let cancellation = bob.sign_link_cancellation(request, pair).unwrap();
        assert!(!alice.receive_link_cancellation(&cancellation, [private, other], 1));
        assert!(alice.receive_link_cancellation(&cancellation, [private, game], 1));
        assert!(!alice.receive_link_cancellation(&cancellation, pair, 1));

        let second = bob.approve_link(&request, pair).unwrap();
        bob.select(game, 1).unwrap();
        let first = first.unwrap_or_else(|| bob.approve_link(&request, pair).unwrap());
        assert!(
            alice
                .receive_link(request, pair, [first, second], 1)
                .is_none()
        );

        let new_request = alice.request_link(2, &mut rng);
        assert!(!alice.receive_link_cancellation(&cancellation, pair, 2));
        let first = bob.approve_link(&new_request, pair).unwrap();
        let after_completion = bob.sign_link_cancellation(new_request, pair).unwrap();
        bob.select(private, 2).unwrap();
        let second = bob.approve_link(&new_request, pair).unwrap();
        let completed = alice
            .receive_link(new_request, pair, [first, second], 2)
            .unwrap();
        assert!(!alice.receive_link_cancellation(&after_completion, pair, 3));
        assert!(completed.pair.contains(&private));
    }
}

#[test]
fn imported_keys_distinguish_ownership_from_encounter_verification() {
    use mesh_identity::contact::{StoreError, VerificationStatus};

    let mut rng = StdRng::seed_from_u64(882);
    let mut alice = Installation::new(SigningKey::generate(&mut rng));
    let local = alice.selected();
    let owned = SigningKey::generate(&mut rng);
    let owned_public = owned.verifying_key().to_bytes();
    let mut bob = Installation::new(SigningKey::generate(&mut rng));
    let peer = bob.selected();

    assert_eq!(
        alice.import_identity(owned.clone(), peer),
        Err(Error::KeyPairMismatch)
    );
    assert!(alice.contacts(owned_public).is_none());
    assert_eq!(
        alice.import_identity(owned.clone(), owned_public),
        Ok(owned_public)
    );
    assert_eq!(
        alice.import_identity(owned, owned_public),
        Err(Error::DuplicateIdentity)
    );
    assert_eq!(
        alice.import_peer_key(local, owned_public, &mut rng),
        Err(Error::Session(SessionError::Store(StoreError::SelfContact)))
    );

    let imported = alice
        .import_peer_key(local, peer, &mut rng)
        .unwrap()
        .clone();
    assert_eq!(
        imported.verification_status,
        VerificationStatus::ImportedUnverified
    );
    assert_eq!(imported.encounter_count, 0);
    assert!(alice.contacts(peer).is_none());
    assert!(alice.contacts(owned_public).unwrap().get(&peer).is_none());

    let (a, b, _) = exchange(&mut alice, &mut bob, 1, &mut rng);
    let a_code = alice.comparison(&a, 1).unwrap().unwrap();
    let b_code = bob.comparison(&b, 1).unwrap().unwrap();
    alice
        .confirm_and_save(&a, a_code, b_code.code, 1, 1, &mut rng)
        .unwrap();
    bob.confirm_and_save(&b, b_code, a_code.code, 1, 1, &mut rng)
        .unwrap();
    let reimported = alice.import_peer_key(local, peer, &mut rng).unwrap();
    assert_eq!(reimported.local_contact_id, imported.local_contact_id);
    assert_eq!(reimported.verification_status, VerificationStatus::Verified);
    assert_eq!(reimported.encounter_count, 1);

    alice.select(owned_public, 2).unwrap();
    let (a, b, _) = exchange(&mut alice, &mut bob, 2, &mut rng);
    let a_code = alice.comparison(&a, 2).unwrap().unwrap();
    let b_code = bob.comparison(&b, 2).unwrap().unwrap();
    bob.confirm_and_save(&b, b_code, a_code.code, 2, 2, &mut rng)
        .unwrap();
    assert!(bob.contacts(peer).unwrap().get(&owned_public).is_some());
}

#[test]
fn contact_record_diagnostics_only_include_status_fields() {
    use mesh_identity::contact::{ContactRecordV1, ContactStatus, VerificationStatus};

    let contact = ContactRecordV1 {
        local_contact_id: [11; 16],
        peer_ed25519_pk: [22; 32],
        verified_at: 3344,
        encounter_count: 5,
        verification_status: VerificationStatus::Verified,
        status: ContactStatus::Active,
        local_alias: Some("private alias".into()),
        last_transcript: [44; 32],
    };
    assert_eq!(
        format!("{contact:?}"),
        "ContactRecordV1 { verification_status: Verified, status: Active, .. }"
    );
}

#[test]
fn test_reimporting_identity_retains_gated_and_stopped_state_and_counter() {
    use mesh_identity::session::installation::VotingState;

    let mut rng = StdRng::seed_from_u64(999);
    let key1 = SigningKey::generate(&mut rng);
    let key2 = SigningKey::generate(&mut rng);
    let key2_id = key2.verifying_key().to_bytes();

    let mut source = Installation::new(key1.clone());
    source.add_identity(key2.clone()).unwrap();

    // Take backup snapshot and restore as a backup (which gates voting)
    let backup = source.into_snapshot(0);
    let mut recipient = Installation::restore_backup(backup, [key1.clone(), key2.clone()]).unwrap();
    assert_eq!(recipient.voting_record(key2_id).state, VotingState::Gated);

    // Remove key2 from recipient
    recipient.remove_identity(key2_id).unwrap();
    assert!(recipient.contacts(key2_id).is_none());
    // Voting record survives in historical_voting
    assert_eq!(recipient.voting_record(key2_id).state, VotingState::Gated);

    // Re-adding key2 restores its Gated status instead of defaulting to Voting
    recipient.add_identity(key2.clone()).unwrap();
    assert_eq!(recipient.voting_record(key2_id).state, VotingState::Gated);

    // Test persistence across snapshot save and restore
    recipient.remove_identity(key2_id).unwrap();
    let snapshot_bytes = recipient.save_bytes(0).unwrap();
    let mut restored = Installation::restore_bytes(&snapshot_bytes, [key1]).unwrap();

    // Re-importing into restored installation still recovers Gated
    assert_eq!(restored.voting_record(key2_id).state, VotingState::Gated);
    restored.import_identity(key2, key2_id).unwrap();
    assert_eq!(restored.voting_record(key2_id).state, VotingState::Gated);
}

#[test]
fn test_handoff_bundle_bounds_rejection() {
    use mesh_identity::session::installation::HandoffBundle;

    // Bundle exceeding 5 MiB is rejected immediately without allocating
    let oversized = vec![0u8; 5 * 1024 * 1024 + 1];
    assert_eq!(
        HandoffBundle::from_bytes(&oversized).err(),
        Some(Error::InvalidHandoff)
    );
}
