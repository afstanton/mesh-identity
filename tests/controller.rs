use ed25519_dalek::SigningKey;
use mesh_identity::contact::{ContactStore, StoreError};
use mesh_identity::protocol::{EncounterError, Initiator, Responder};
use mesh_identity::session::{
    AttemptError, Comparison, EncounterController, PAUSE_MS, SESSION_TIMEOUT_MS, SessionError,
};
use rand::{SeedableRng, rngs::StdRng};

fn pair(rng: &mut StdRng) -> (EncounterController, EncounterController) {
    (
        EncounterController::new(SigningKey::generate(rng)),
        EncounterController::new(SigningKey::generate(rng)),
    )
}

fn exchange(
    alice: &mut EncounterController,
    bob: &mut EncounterController,
    now: u64,
    rng: &mut StdRng,
) -> (Comparison, Comparison) {
    let offer = alice.start(now, rng).unwrap();
    let response = bob.scan_offer(&offer, now, rng).unwrap();
    let reveal = alice.scan_response(&response, now).unwrap();
    bob.scan_reveal(&reveal, now).unwrap();
    (alice.comparison(now).unwrap(), bob.comparison(now).unwrap())
}

#[test]
fn deadline_and_duplicate_callbacks_cannot_save() {
    let mut rng = StdRng::seed_from_u64(17);
    let (mut alice, mut bob) = pair(&mut rng);
    let (a, b) = exchange(&mut alice, &mut bob, 0, &mut rng);
    assert_eq!(
        alice.confirm_and_save(a, b.code, SESSION_TIMEOUT_MS, 1, &mut rng),
        Err(SessionError::NoLiveSession)
    );
    assert_eq!(alice.contacts().count(), 0);
    assert_eq!(
        bob.confirm_and_save(b, a.code, SESSION_TIMEOUT_MS - 1, 1, &mut rng)
            .unwrap()
            .encounter_count,
        1
    );
    assert_eq!(
        bob.confirm_and_save(b, a.code, SESSION_TIMEOUT_MS - 1, 2, &mut rng),
        Err(SessionError::NoLiveSession)
    );

    let (fresh, other) = exchange(&mut alice, &mut bob, SESSION_TIMEOUT_MS + 1, &mut rng);
    assert_eq!(
        alice.confirm_and_save(a, other.code, SESSION_TIMEOUT_MS + 1, 3, &mut rng),
        Err(SessionError::StaleComparison)
    );
    assert_eq!(
        alice
            .confirm_and_save(fresh, other.code, SESSION_TIMEOUT_MS + 1, 3, &mut rng)
            .unwrap()
            .encounter_count,
        1
    );
}

#[test]
fn responder_rescan_and_abandonment_use_one_attempt() {
    let mut rng = StdRng::seed_from_u64(19);
    let (mut alice, mut bob) = pair(&mut rng);
    for now in 0..4 {
        let offer = alice.start(now, &mut rng).unwrap();
        if now < 3 {
            let response = bob.scan_offer(&offer, now, &mut rng).unwrap();
            assert_eq!(bob.scan_offer(&offer, now, &mut rng), Ok(response));
            assert_eq!(
                bob.start(now, &mut rng),
                Err(SessionError::Attempt(AttemptError::SessionAlreadyLive))
            );
            bob.cancel(now);
            assert_eq!(bob.warning_active(), now == 2);
            alice.cancel(now);
        } else {
            assert_eq!(
                bob.scan_offer(&offer, 2 + PAUSE_MS - 1, &mut rng),
                Err(SessionError::Attempt(AttemptError::Paused {
                    until_ms: 2 + PAUSE_MS
                }))
            );
            assert!(bob.scan_offer(&offer, 2 + PAUSE_MS, &mut rng).is_ok());
        }
    }
}

#[test]
fn store_rejects_confirmation_from_another_identity() {
    let mut rng = StdRng::seed_from_u64(23);
    let alice = SigningKey::generate(&mut rng);
    let bob = SigningKey::generate(&mut rng);
    let other = SigningKey::generate(&mut rng);
    let (a, offer) = Initiator::start(alice.clone(), &mut rng);
    let (b, response) = Responder::handle_offer(bob, &offer.to_bytes(), &mut rng).unwrap();
    let (a, reveal) = a.handle_response(&response.to_bytes()).unwrap();
    let b = b.handle_reveal(&reveal.to_bytes()).unwrap();
    let token = a.confirm(b.sas_code()).unwrap();
    let mut wrong = ContactStore::for_identity(other.verifying_key().to_bytes());
    assert_eq!(
        wrong.record_confirmed_encounter(&token, 1, &mut rng),
        Err(StoreError::WrongLocalIdentity)
    );
    assert_eq!(wrong.count(), 0);
    let mut right = ContactStore::for_identity(alice.verifying_key().to_bytes());
    assert!(
        right
            .record_confirmed_encounter(&token, 1, &mut rng)
            .is_ok()
    );
}

#[test]
fn mismatched_comparison_cannot_save_or_be_retried() {
    let mut rng = StdRng::seed_from_u64(27);
    let (mut alice, mut bob) = pair(&mut rng);
    let (a, b) = exchange(&mut alice, &mut bob, 0, &mut rng);
    assert_eq!(
        alice.confirm_and_save(b, b.code, 1, 1, &mut rng),
        Err(SessionError::StaleComparison)
    );
    assert!(matches!(
        alice.confirm_and_save(a, (b.code + 1) % 1_000_000, 1, 1, &mut rng),
        Err(SessionError::Protocol(_))
    ));
    assert_eq!(
        alice.confirm_and_save(a, b.code, 2, 2, &mut rng),
        Err(SessionError::NoLiveSession)
    );
    assert_eq!(alice.contacts().count(), 0);
}

#[test]
fn scans_at_the_deadline() {
    let mut rng = StdRng::seed_from_u64(31);

    // Subcase 1: Initiator scan_response at deadline - 1 (succeeds)
    {
        let (mut alice, mut bob) = pair(&mut rng);
        let t0 = 100;
        let offer = alice.start(t0, &mut rng).unwrap();
        let response = bob.scan_offer(&offer, t0 + 10, &mut rng).unwrap();
        assert!(
            alice
                .scan_response(&response, t0 + SESSION_TIMEOUT_MS - 1)
                .is_ok()
        );
    }

    // Subcase 2: Initiator scan_response at exact deadline (fails due to timeout expiration)
    {
        let (mut alice, mut bob) = pair(&mut rng);
        let t1 = 1_000;
        let offer1 = alice.start(t1, &mut rng).unwrap();
        let response1 = bob.scan_offer(&offer1, t1 + 10, &mut rng).unwrap();
        assert_eq!(
            alice.scan_response(&response1, t1 + SESSION_TIMEOUT_MS),
            Err(SessionError::NoLiveSession)
        );
    }

    // Subcase 3: Responder scan_reveal at deadline - 1 (succeeds)
    {
        let (mut alice, mut bob) = pair(&mut rng);
        let t2 = 5_000;
        let offer2 = alice.start(t2, &mut rng).unwrap();
        let bob_start = t2 + 10;
        let response2 = bob.scan_offer(&offer2, bob_start, &mut rng).unwrap();
        let reveal2 = alice.scan_response(&response2, bob_start + 10).unwrap();
        assert!(
            bob.scan_reveal(&reveal2, bob_start + SESSION_TIMEOUT_MS - 1)
                .is_ok()
        );
    }

    // Subcase 4: Responder scan_reveal at exact deadline (fails due to timeout expiration)
    {
        let (mut alice, mut bob) = pair(&mut rng);
        let t3 = 10_000;
        let offer3 = alice.start(t3, &mut rng).unwrap();
        let bob_start3 = t3 + 10;
        let response3 = bob.scan_offer(&offer3, bob_start3, &mut rng).unwrap();
        let reveal3 = alice.scan_response(&response3, bob_start3 + 10).unwrap();
        assert_eq!(
            bob.scan_reveal(&reveal3, bob_start3 + SESSION_TIMEOUT_MS),
            Err(SessionError::NoLiveSession)
        );
    }
}

#[test]
fn third_timeout_triggers_pause_and_warning() {
    let mut rng = StdRng::seed_from_u64(37);
    let (mut alice, mut bob) = pair(&mut rng);

    let mut t = 1_000;
    // Run two incomplete sessions that see QR2 and then time out
    for i in 1..=2 {
        let offer = alice.start(t, &mut rng).unwrap();
        let resp = bob.scan_offer(&offer, t + 10, &mut rng).unwrap();
        let _reveal = alice.scan_response(&resp, t + 20).unwrap();
        assert!(!alice.warning_active());
        // Advance time past timeout
        t += SESSION_TIMEOUT_MS + 10;
        alice.expire(t);
        assert!(
            !alice.warning_active(),
            "attempt {i} should not trigger warning yet"
        );
        bob.cancel(t);
    }

    // Third session that sees QR2 and times out
    let offer = alice.start(t, &mut rng).unwrap();
    let resp = bob.scan_offer(&offer, t + 10, &mut rng).unwrap();
    let _reveal = alice.scan_response(&resp, t + 20).unwrap();
    t += SESSION_TIMEOUT_MS + 10;
    alice.expire(t);

    // A third timeout MUST trigger warning and pause!
    assert!(alice.warning_active());
    let pause_expiry = t + PAUSE_MS;
    assert_eq!(
        alice.start(t + 10, &mut rng),
        Err(SessionError::Attempt(AttemptError::Paused {
            until_ms: pause_expiry
        }))
    );

    // After pause elapses, next attempt can proceed
    let resume_t = pause_expiry + 1;
    assert!(alice.start(resume_t, &mut rng).is_ok());
}

#[test]
fn delayed_callbacks_leave_new_session_and_history_intact() {
    let mut rng = StdRng::seed_from_u64(43);
    let (mut alice, mut bob) = pair(&mut rng);

    // Session 1: Both exchange frames and display comparisons
    let (a1, b1) = exchange(&mut alice, &mut bob, 1_000, &mut rng);

    // Bob confirms and saves session 1 -> Bob's contact history has 1 record
    let b1_record = bob
        .confirm_and_save(b1, a1.code, 1_050, 1_050, &mut rng)
        .unwrap();
    assert_eq!(b1_record.encounter_count, 1);
    assert_eq!(bob.contacts().count(), 1);

    // Alice abandons session 1 before confirming
    alice.cancel(1_100);
    assert_eq!(alice.contacts().count(), 0);

    // Session 2: A fresh exchange takes place
    let (a2, b2) = exchange(&mut alice, &mut bob, 2_000, &mut rng);
    assert_ne!(a1.code, a2.code);

    // Delayed callback for Session 1 arrives at Alice while Session 2 comparison is on screen!
    let stale_res = alice.confirm_and_save(a1, b1.code, 2_050, 2_050, &mut rng);
    assert_eq!(stale_res, Err(SessionError::StaleComparison));

    // CRUCIAL CHECK: The rejected delayed callback must leave the new session and contact history intact!
    assert_eq!(
        alice.comparison(2_060),
        Some(a2),
        "Session 2 must remain live and valid after rejecting stale callback"
    );
    assert_eq!(
        alice.contacts().count(),
        0,
        "Alice's contact store must remain intact without corrupted records"
    );
    assert_eq!(
        bob.contacts().count(),
        1,
        "Bob's contact store from session 1 must remain intact"
    );

    // Alice now confirms the valid Session 2 comparison
    let a2_record = alice
        .confirm_and_save(a2, b2.code, 2_070, 2_070, &mut rng)
        .unwrap();
    assert_eq!(a2_record.encounter_count, 1);
    assert_eq!(alice.contacts().count(), 1);

    // Bob also confirms Session 2 -> continuity counter increments to 2 on his existing contact
    let b2_record = bob
        .confirm_and_save(b2, a2.code, 2_080, 2_080, &mut rng)
        .unwrap();
    assert_eq!(b2_record.encounter_count, 2);
    assert_eq!(bob.contacts().count(), 1);
}

#[test]
fn restart_persists_attempt_policy_and_pause() {
    let mut rng = StdRng::seed_from_u64(47);
    let alice_key = SigningKey::generate(&mut rng);
    let (mut bob, _) = pair(&mut rng);

    // Instance 1 of Alice's controller: experiences 2 incomplete sessions
    let mut alice1 = EncounterController::new(alice_key.clone());
    for now in [1_000, 2_000] {
        let offer = alice1.start(now, &mut rng).unwrap();
        let resp = bob.scan_offer(&offer, now + 10, &mut rng).unwrap();
        let _reveal = alice1.scan_response(&resp, now + 20).unwrap();
        alice1.cancel(now + 30);
        bob.cancel(now + 30);
    }
    assert_eq!(
        alice1
            .contacts()
            .attempt_policy_state()
            .consecutive_incomplete,
        2
    );
    assert!(!alice1.warning_active());

    // Simulate process termination and restart: store is preserved and passed to new controller
    let store_after_crash = alice1.into_contacts();
    let mut alice2 = EncounterController::with_store(alice_key.clone(), store_after_crash).unwrap();

    // Controller 2 should inherit the exact 2 incomplete attempts
    assert_eq!(
        alice2
            .contacts()
            .attempt_policy_state()
            .consecutive_incomplete,
        2
    );
    assert!(!alice2.warning_active());

    // Third incomplete attempt on Controller 2 triggers pause!
    let t_fail = 3_000;
    let offer = alice2.start(t_fail, &mut rng).unwrap();
    let resp = bob.scan_offer(&offer, t_fail + 10, &mut rng).unwrap();
    let _reveal = alice2.scan_response(&resp, t_fail + 20).unwrap();
    alice2.cancel(t_fail + 30);
    bob.cancel(t_fail + 30);

    assert!(alice2.warning_active());
    let pause_expiry = t_fail + 30 + PAUSE_MS;
    assert_eq!(
        alice2.start(t_fail + 40, &mut rng),
        Err(SessionError::Attempt(AttemptError::Paused {
            until_ms: pause_expiry
        }))
    );

    // Simulate another process crash while actively paused
    let store_during_pause = alice2.into_contacts();
    let mut alice3 =
        EncounterController::with_store(alice_key.clone(), store_during_pause).unwrap();

    // Controller 3 MUST STILL BE PAUSED after restart. The saved pause is a duration that is
    // anchored to the clock of the first attempt after the restore (here t_fail + 50).
    assert!(alice3.warning_active());
    let rebased_expiry = t_fail + 50 + PAUSE_MS;
    assert_eq!(
        alice3.start(t_fail + 50, &mut rng),
        Err(SessionError::Attempt(AttemptError::Paused {
            until_ms: rebased_expiry
        }))
    );

    // After pause duration elapses, Controller 3 allows fresh sessions
    let t_resume = rebased_expiry + 1;
    let fresh_offer = alice3.start(t_resume, &mut rng).unwrap();
    let resp = bob
        .scan_offer(&fresh_offer, t_resume + 10, &mut rng)
        .unwrap();
    let _rev = alice3.scan_response(&resp, t_resume + 20).unwrap();
    bob.scan_reveal(&_rev, t_resume + 30).unwrap();

    let cmp_a = alice3.comparison(t_resume + 40).unwrap();
    let cmp_b = bob.comparison(t_resume + 40).unwrap();

    // Confirming resets incomplete attempts back to 0 in both controller and store
    let rec = alice3
        .confirm_and_save(cmp_a, cmp_b.code, t_resume + 50, t_resume + 50, &mut rng)
        .unwrap();
    assert_eq!(rec.encounter_count, 1);
    assert_eq!(
        alice3
            .contacts()
            .attempt_policy_state()
            .consecutive_incomplete,
        0
    );
    assert_eq!(
        alice3.contacts().attempt_policy_state().pause_remaining_ms,
        None
    );
    assert!(!alice3.warning_active());
}

// ---- Regressions from the second fresh-eyes review ----

#[test]
fn pause_survives_reboot_as_a_duration_not_a_deadline() {
    let mut rng = StdRng::seed_from_u64(91);
    let key = SigningKey::generate(&mut rng);
    let mut c = EncounterController::new(key.clone());
    let mut now = 10_000_000_000u64; // ~115 days of uptime
    for _ in 0..3 {
        let (mut bob, _) = pair(&mut rng);
        let q1 = c.start(now, &mut rng).unwrap();
        let q2 = bob.scan_offer(&q1, now + 1, &mut rng).unwrap();
        c.scan_response(&q2, now + 2).unwrap();
        c.cancel(now + 1000);
        now += 2000;
    }
    let state = c.contacts().attempt_policy_state();
    assert!(state.pause_remaining_ms.unwrap() <= PAUSE_MS);
    // Device reboots: the monotonic clock restarts near zero.
    let mut c2 = EncounterController::with_store(key, c.into_contacts()).unwrap();
    assert_eq!(
        c2.start(5_000, &mut rng),
        Err(SessionError::Attempt(AttemptError::Paused {
            until_ms: 5_000 + PAUSE_MS
        }))
    );
    assert!(c2.start(5_000 + PAUSE_MS, &mut rng).is_ok());
}

#[test]
fn stray_frames_do_not_end_or_count_against_a_live_session() {
    let mut rng = StdRng::seed_from_u64(92);
    let (mut alice, mut bob) = pair(&mut rng);
    let (mut eve, _) = pair(&mut rng);
    let q1 = alice.start(1_000, &mut rng).unwrap();
    let q2 = bob.scan_offer(&q1, 1_010, &mut rng).unwrap();
    // Three stray QR1 scans at Bob.
    for i in 0..3u64 {
        let stray = eve.start(2_000 + i * 10, &mut rng).unwrap();
        assert_eq!(
            bob.scan_offer(&stray, 2_005 + i * 10, &mut rng),
            Err(SessionError::Protocol(EncounterError::SessionMismatch))
        );
        eve.cancel(2_006 + i * 10);
    }
    assert!(!bob.warning_active());
    // A stray, different QR2 at Alice does not end her session either.
    let mut mallory = EncounterController::new(SigningKey::generate(&mut rng));
    let q1m = mallory.start(3_000, &mut rng).unwrap();
    let (mut bob2, _) = pair(&mut rng);
    let other_q2 = bob2.scan_offer(&q1m, 3_001, &mut rng).unwrap();
    let q3 = alice.scan_response(&q2, 3_010).unwrap();
    assert_eq!(
        alice.scan_response(&other_q2, 3_020),
        Err(SessionError::Protocol(EncounterError::SessionMismatch))
    );
    assert!(!alice.warning_active());
    // The original session still completes.
    bob.scan_reveal(&q3, 3_030).unwrap();
    let ca = alice.comparison(3_040).unwrap();
    let cb = bob.comparison(3_040).unwrap();
    alice
        .confirm_and_save(ca, cb.code, 3_050, 3_050, &mut rng)
        .unwrap();
    bob.confirm_and_save(cb, ca.code, 3_050, 3_050, &mut rng)
        .unwrap();
}

#[test]
fn invalid_first_qr2_and_qr3_are_ignored_and_the_session_survives() {
    let mut rng = StdRng::seed_from_u64(93);
    let (mut alice, mut bob) = pair(&mut rng);
    let q1 = alice.start(1_000, &mut rng).unwrap();
    let q2 = bob.scan_offer(&q1, 1_010, &mut rng).unwrap();

    // Garbage and a tampered (bad signature) QR2 reach Alice first.
    assert!(
        alice
            .scan_response(&[0xde, 0xad, 0xbe, 0xef], 1_020)
            .is_err()
    );
    let mut tampered = q2.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    assert!(alice.scan_response(&tampered, 1_030).is_err());
    assert!(!alice.warning_active());
    // The genuine QR2 is still accepted afterwards.
    let q3 = alice.scan_response(&q2, 1_040).unwrap();

    // Same for Bob and QR3.
    assert!(bob.scan_reveal(&[1, 2, 3], 1_050).is_err());
    let mut bad_q3 = q3.clone();
    let l = bad_q3.len() - 1;
    bad_q3[l] ^= 1;
    assert!(bob.scan_reveal(&bad_q3, 1_060).is_err());
    bob.scan_reveal(&q3, 1_070).unwrap();

    let ca = alice.comparison(1_080).unwrap();
    let cb = bob.comparison(1_080).unwrap();
    assert_eq!(ca.code, cb.code);
    alice
        .confirm_and_save(ca, cb.code, 1_090, 1_090, &mut rng)
        .unwrap();
    bob.confirm_and_save(cb, ca.code, 1_090, 1_090, &mut rng)
        .unwrap();
}

#[test]
fn a_successful_response_still_locks_the_session_to_one_reveal() {
    // Safety property behind the retry: once a QR2 is accepted and QR3 produced, a second,
    // different valid QR2 cannot yield another reveal for the same commitment.
    let mut rng = StdRng::seed_from_u64(94);
    let (mut alice, mut bob) = pair(&mut rng);
    let (_, mut bob2) = pair(&mut rng);
    let q1 = alice.start(1_000, &mut rng).unwrap();
    let q2_first = bob.scan_offer(&q1, 1_010, &mut rng).unwrap();
    let q2_second = bob2.scan_offer(&q1, 1_011, &mut rng).unwrap();
    let q3 = alice.scan_response(&q2_first, 1_020).unwrap();
    assert_eq!(
        alice.scan_response(&q2_second, 1_030),
        Err(SessionError::Protocol(EncounterError::SessionMismatch))
    );
    // Rescanning the same QR2 returns the identical QR3 (no new randomness, no second reveal).
    assert_eq!(alice.scan_response(&q2_first, 1_040).unwrap(), q3);
}

#[test]
fn restoring_after_comparison_counts_the_unfinished_attempt_once() {
    let mut rng = StdRng::seed_from_u64(101);
    let key = SigningKey::generate(&mut rng);
    let mut alice = EncounterController::new(key.clone());
    for now in 0..3 {
        let (mut bob, _) = pair(&mut rng);
        exchange(&mut alice, &mut bob, now, &mut rng);
        let store = alice.into_contacts();
        assert!(store.attempt_policy_state().pending_response);
        alice = EncounterController::with_store(key.clone(), store).unwrap();
        let state = alice.contacts().attempt_policy_state();
        assert_eq!(state.consecutive_incomplete, now as u32 + 1);
        assert!(!state.pending_response);
        alice = EncounterController::with_store(key.clone(), alice.into_contacts()).unwrap();
        assert_eq!(alice.contacts().attempt_policy_state(), state);
    }
    assert_eq!(
        alice.start(10, &mut rng),
        Err(SessionError::Attempt(AttemptError::Paused {
            until_ms: 10 + PAUSE_MS
        }))
    );
}

#[test]
fn store_restore_rejects_another_identity() {
    let mut rng = StdRng::seed_from_u64(102);
    let owner = SigningKey::generate(&mut rng);
    let wrong = SigningKey::generate(&mut rng);
    let store = ContactStore::for_identity(owner.verifying_key().to_bytes());
    assert!(matches!(
        EncounterController::with_store(wrong, store),
        Err(StoreError::WrongLocalIdentity)
    ));
}

#[test]
fn replayed_confirmation_preserves_pending_pause() {
    let mut rng = StdRng::seed_from_u64(103);
    let key = SigningKey::generate(&mut rng);
    let peer = SigningKey::generate(&mut rng);
    let (alice, offer) = Initiator::start(key.clone(), &mut rng);
    let (bob, response) = Responder::handle_offer(peer, &offer.to_bytes(), &mut rng).unwrap();
    let (alice, reveal) = alice.handle_response(&response.to_bytes()).unwrap();
    let bob = bob.handle_reveal(&reveal.to_bytes()).unwrap();
    let token = alice.confirm(bob.sas_code()).unwrap();
    let mut store = ContactStore::for_identity(key.verifying_key().to_bytes());
    let saved = store
        .record_confirmed_encounter(&token, 1, &mut rng)
        .unwrap()
        .clone();
    let mut controller = EncounterController::with_store(key.clone(), store).unwrap();
    for now in 0..3 {
        let (mut peer, _) = pair(&mut rng);
        exchange(&mut controller, &mut peer, now, &mut rng);
        controller.cancel(now);
    }
    let mut store = controller.into_contacts();
    let policy = store.attempt_policy_state();
    assert_eq!(policy.pause_remaining_ms, Some(PAUSE_MS));
    assert_eq!(
        store.record_confirmed_encounter(&token, 10, &mut rng),
        Ok(&saved)
    );
    assert_eq!(store.attempt_policy_state(), policy);

    // A fresh, unseen encounter cannot be recorded while the store is paused.
    let peer2 = SigningKey::generate(&mut rng);
    let (alice2, offer2) = Initiator::start(key, &mut rng);
    let (bob2, response2) = Responder::handle_offer(peer2, &offer2.to_bytes(), &mut rng).unwrap();
    let (alice2, reveal2) = alice2.handle_response(&response2.to_bytes()).unwrap();
    let bob2 = bob2.handle_reveal(&reveal2.to_bytes()).unwrap();
    let token2 = alice2.confirm(bob2.sas_code()).unwrap();
    assert_eq!(
        store.record_confirmed_encounter(&token2, 10, &mut rng),
        Err(StoreError::Paused)
    );
}
