//! Adversarial test vectors for Encounter v0.1.
//!
//! Each vector returns `Ok(details)` or `Err(reason)`; `passed` is computed, never hard-coded.
//! Sessions are driven by a seeded RNG (`StdRng`, pinned by `Cargo.lock`) so failures reproduce
//! from the printed seed. Frames that attackers craft are built here from the specification text,
//! independently of the production code paths, so a deviation in either shows up as a failure.
//! All keys are throwaway test identities.

use crate::cbor::cbor_det_bytes;
use crate::contact::{ContactExportV1, ContactStore, StoreError, VerificationStatus};
use crate::machine::{InitiatorMachine, ResponderMachine};
use crate::protocol::*;
use crate::session::*;
use crate::transport::*;
use cbor2::Value;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::StdRng;
use rand::{Rng, RngCore, SeedableRng};
use sha2::{Digest, Sha256};

pub struct VectorReport {
    pub name: &'static str,
    pub passed: bool,
    pub details: String,
}

type VResult = Result<String, String>;
type Vector = (&'static str, fn() -> VResult);
type CarryFrame = Box<dyn FnMut(&[u8], bool) -> Result<Vec<u8>, String>>;

macro_rules! check {
    ($cond:expr, $($msg:tt)+) => {
        if !$cond {
            return Err(format!($($msg)+));
        }
    };
}

pub fn run_all_vectors() -> Vec<VectorReport> {
    let vectors: Vec<Vector> = vec![
        (
            "Vector 1: Happy Path & Key Continuity",
            v1_happy_path_and_continuity,
        ),
        ("Vector 2: Replay Resistance", v2_replay),
        (
            "Vector 3: Exhaustive Tamper & Relay-MITM SAS",
            v3_tamper_and_mitm,
        ),
        ("Vector 4: Unknown-Key-Share", v4_unknown_key_share),
        (
            "Vector 5: Downgrade, Malformed Input & Weak Keys",
            v5_malformed_and_weak,
        ),
        ("Vector 6: Relay Limitation", v6_relay_limitation),
        (
            "Vector 7: Multi-Transport Equivalence",
            v7_transport_equivalence,
        ),
        ("Vector 8: Trust & Export Boundaries", v8_trust_boundaries),
        (
            "Vector 9: State, Local Confirmation & Abort-and-Retry",
            v9_state_and_retry,
        ),
        (
            "Vector 10: Self-Reflection (QR1, QR2, QR3)",
            v10_self_reflection,
        ),
        (
            "Vector 11: Spec Conformance of Frames & Role Confusion",
            v11_conformance_and_roles,
        ),
        (
            "Vector 12: State Machines, Rescan, Crash/Restart, Asymmetric Cancel",
            v12_state_machines,
        ),
        (
            "Vector 13: Zeroization, Alias Conflict, UI Strings",
            v13_zeroize_alias_ui,
        ),
        (
            "Vector 14: SAS Attack Regression Traces (3a-a)",
            v14_sas_attack_traces,
        ),
    ];
    vectors
        .into_iter()
        .map(|(name, f)| match f() {
            Ok(details) => VectorReport {
                name,
                passed: true,
                details,
            },
            Err(details) => VectorReport {
                name,
                passed: false,
                details,
            },
        })
        .collect()
}

// ----------------- Helpers -----------------

fn rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

struct Sess {
    alice_sk: SigningKey,
    bob_sk: SigningKey,
    offer: Vec<u8>,
    resp: Vec<u8>,
    reveal: Vec<u8>,
    alice: InitiatorAwaitingConfirmation,
    bob: ResponderAwaitingConfirmation,
}

fn session(seed: u64) -> Sess {
    let mut r = rng(seed);
    let alice_sk = SigningKey::generate(&mut r);
    let bob_sk = SigningKey::generate(&mut r);
    let (ai, offer) = Initiator::start(alice_sk.clone(), &mut r);
    let offer = offer.to_bytes();
    let (bs, resp) = Responder::handle_offer(bob_sk.clone(), &offer, &mut r).unwrap();
    let resp = resp.to_bytes();
    let (alice, reveal) = ai.handle_response(&resp).unwrap();
    let reveal = reveal.to_bytes();
    let bob = bs.handle_reveal(&reveal).unwrap();
    Sess {
        alice_sk,
        bob_sk,
        offer,
        resp,
        reveal,
        alice,
        bob,
    }
}

/// Replays session `seed` with one frame optionally replaced. Returns Err at the first rejection.
fn drive(
    seed: u64,
    frame: usize,
    edit: &dyn Fn(&[u8]) -> Vec<u8>,
) -> Result<(u32, u32), EncounterError> {
    let mut r = rng(seed);
    let alice_sk = SigningKey::generate(&mut r);
    let bob_sk = SigningKey::generate(&mut r);
    let (ai, offer) = Initiator::start(alice_sk, &mut r);
    let mut offer = offer.to_bytes();
    if frame == 0 {
        offer = edit(&offer);
    }
    let (bs, resp) = Responder::handle_offer(bob_sk, &offer, &mut r)?;
    let mut resp = resp.to_bytes();
    if frame == 1 {
        resp = edit(&resp);
    }
    let (alice, reveal) = ai.handle_response(&resp)?;
    let mut reveal = reveal.to_bytes();
    if frame == 2 {
        reveal = edit(&reveal);
    }
    let bob = bs.handle_reveal(&reveal)?;
    Ok((alice.sas_code(), bob.sas_code()))
}

pub(crate) fn spec_offer_digest(offer: &[u8]) -> [u8; 32] {
    Sha256::digest(cbor_det_bytes(vec![
        Value::Text("mesh.encounter.v1.offer".into()),
        Value::Bytes(offer.to_vec()),
    ]))
    .into()
}

pub(crate) fn spec_commit(epk: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    Sha256::digest(cbor_det_bytes(vec![
        Value::Text("mesh.encounter.v1.commit".into()),
        Value::Bytes(epk.to_vec()),
        Value::Bytes(nonce.to_vec()),
    ]))
    .into()
}

pub(crate) fn spec_resp_payload(
    od: &[u8; 32],
    alice_pk: &[u8; 32],
    bob_pk: &[u8; 32],
    epk: &[u8; 32],
    nonce: &[u8; 16],
) -> Vec<u8> {
    cbor_det_bytes(vec![
        Value::Text("mesh.encounter.v1.resp".into()),
        Value::Text(PROTO_V1.into()),
        Value::Bytes(od.to_vec()),
        Value::Bytes(alice_pk.to_vec()),
        Value::Bytes(bob_pk.to_vec()),
        Value::Bytes(epk.to_vec()),
        Value::Bytes(nonce.to_vec()),
    ])
}

pub(crate) fn spec_transcript(
    q1: &[u8],
    q2: &[u8],
    epk_a: &[u8; 32],
    nonce_a: &[u8; 16],
) -> [u8; 32] {
    Sha256::digest(cbor_det_bytes(vec![
        Value::Text("mesh.encounter.v1.transcript".into()),
        Value::Bytes(q1.to_vec()),
        Value::Bytes(q2.to_vec()),
        Value::Bytes(epk_a.to_vec()),
        Value::Bytes(nonce_a.to_vec()),
    ]))
    .into()
}

pub(crate) fn spec_reveal_payload(transcript: &[u8; 32]) -> Vec<u8> {
    cbor_det_bytes(vec![
        Value::Text("mesh.encounter.v1.reveal".into()),
        Value::Bytes(transcript.to_vec()),
    ])
}

/// A properly signed response from a (possibly malicious) holder of `bob_sk` for `offer`.
fn forge_response(
    bob_sk: &SigningKey,
    offer: &[u8],
    bob_pk_field: [u8; 32],
    epk: [u8; 32],
    sig_override: Option<[u8; 64]>,
) -> Vec<u8> {
    let offer_frame = EncounterOfferV1::from_bytes(offer).unwrap();
    let od = spec_offer_digest(offer);
    let nonce_b = [0x42u8; 16];
    let payload = spec_resp_payload(
        &od,
        &offer_frame.alice_ed25519_pk,
        &bob_pk_field,
        &epk,
        &nonce_b,
    );
    let sig_b = sig_override.unwrap_or_else(|| bob_sk.sign(&payload).to_bytes());
    EncounterResponseV1 {
        role: "response".into(),
        proto: PROTO_V1.into(),
        sig_b,
        nonce_b,
        offer_digest: od,
        bob_ed25519_pk: bob_pk_field,
        bob_x25519_epk: epk,
    }
    .to_bytes()
}

const IDENTITY_POINT: [u8; 32] = {
    let mut k = [0u8; 32];
    k[0] = 1;
    k
};

/// Signature (R = identity, S = 0): valid under a non-strict verifier for the identity-point key.
fn identity_sig() -> [u8; 64] {
    let mut s = [0u8; 64];
    s[0] = 1;
    s
}

// ----------------- Vectors -----------------

fn v1_happy_path_and_continuity() -> VResult {
    let s1 = session(101);
    check!(
        s1.alice.sas_code() == s1.bob.sas_code(),
        "SAS differs between devices"
    );
    check!(
        s1.alice.sas_code() < 1_000_000,
        "SAS out of six-digit range"
    );
    let mut r = rng(1);
    let mut alice_store = ContactStore::for_identity(s1.alice_sk.verifying_key().to_bytes());
    let alice_confirmed = s1
        .alice
        .clone()
        .confirm(s1.bob.sas_code())
        .map_err(|e| format!("{e:?}"))?;
    let rec = alice_store
        .record_confirmed_encounter(&alice_confirmed, 1000, &mut r)
        .map_err(|e| format!("{e:?}"))?;
    check!(
        rec.encounter_count == 1 && rec.verification_status == VerificationStatus::Verified,
        "first encounter not recorded as 1/Verified"
    );
    // duplicate confirmation / double tap
    let dup = alice_store
        .record_confirmed_encounter(&alice_confirmed, 1001, &mut r)
        .map_err(|e| format!("{e:?}"))?;
    check!(
        dup.encounter_count == 1,
        "duplicate confirmation changed the count"
    );

    // Second distinct encounter between the same identities (different randomness).
    let mut r2 = rng(202);
    let (ai, offer) = Initiator::start(s1.alice_sk.clone(), &mut r2);
    let (bs, resp) =
        Responder::handle_offer(s1.bob_sk.clone(), &offer.to_bytes(), &mut r2).unwrap();
    let (a2, rev) = ai.handle_response(&resp.to_bytes()).unwrap();
    let b2 = bs.handle_reveal(&rev.to_bytes()).unwrap();
    check!(a2.sas_code() == b2.sas_code(), "second session SAS differs");
    let c2 = a2.confirm(b2.sas_code()).unwrap();
    let rec2 = alice_store
        .record_confirmed_encounter(&c2, 2000, &mut r)
        .map_err(|e| format!("{e:?}"))?;
    check!(
        rec2.encounter_count == 2,
        "second distinct encounter did not give count 2"
    );

    // Replay of the FIRST (older, not latest) confirmation must not count again.
    let replay = alice_store
        .record_confirmed_encounter(&alice_confirmed, 3000, &mut r)
        .map_err(|e| format!("{e:?}"))?;
    check!(
        replay.encounter_count == 2,
        "replaying an older confirmed session changed the count to {}",
        replay.encounter_count
    );

    // Export/import on a fresh install gives an unverified candidate; first new ceremony gives count 1.
    let export = alice_store
        .export_contact(&s1.bob_sk.verifying_key().to_bytes(), Some("Bob".into()))
        .unwrap();
    let mut fresh = ContactStore::for_identity(s1.alice_sk.verifying_key().to_bytes());
    let imported = fresh
        .import_contact(export, &mut r)
        .map_err(|e| format!("{e:?}"))?;
    check!(
        imported.verification_status == VerificationStatus::ImportedUnverified
            && imported.encounter_count == 0,
        "import inherited assurance"
    );
    let promoted = fresh
        .record_confirmed_encounter(&c2, 4000, &mut r)
        .map_err(|e| format!("{e:?}"))?;
    check!(
        promoted.encounter_count == 1
            && promoted.verification_status == VerificationStatus::Verified,
        "first local ceremony after import must give count 1"
    );
    Ok(format!(
        "SAS {:06} matched; duplicate and older-session replay ignored; second encounter = 2; import then local ceremony = 1",
        s1.alice.sas_code()
    ))
}

fn v2_replay() -> VResult {
    let s1 = session(111);
    // (a) old QR2 shown to Alice in a fresh session
    let mut r = rng(112);
    let (ai, _o) = Initiator::start(s1.alice_sk.clone(), &mut r);
    let e = ai.handle_response(&s1.resp).unwrap_err();
    check!(
        e == EncounterError::SessionMismatch,
        "stale QR2: expected SessionMismatch, got {e:?}"
    );
    // (b) old QR3 shown to Bob in a fresh session with a different offer
    let (_ai2, offer2) = Initiator::start(s1.alice_sk.clone(), &mut r);
    let (bs2, _) = Responder::handle_offer(s1.bob_sk.clone(), &offer2.to_bytes(), &mut r).unwrap();
    let e = bs2.handle_reveal(&s1.reveal).unwrap_err();
    check!(
        e == EncounterError::InvalidCommitment,
        "stale QR3: expected InvalidCommitment, got {e:?}"
    );
    // (c) old QR1 replayed to Bob, replayer also holds the matching old QR3: fails at the signature, nothing saved
    let (bs3, _) = Responder::handle_offer(s1.bob_sk.clone(), &s1.offer, &mut r).unwrap();
    let e = bs3.handle_reveal(&s1.reveal).unwrap_err();
    check!(
        e == EncounterError::InvalidSignature,
        "replayed QR1 + matching old QR3: expected InvalidSignature, got {e:?}"
    );
    // (d) Bob's signature from session 1 cannot be spliced into another offer's response
    let spliced = {
        let mut resp = EncounterResponseV1::from_bytes(&s1.resp).unwrap();
        resp.offer_digest = spec_offer_digest(&offer2.to_bytes());
        resp.to_bytes()
    };
    let mut r4 = rng(113);
    let (ai4, offer4) = Initiator::start(s1.alice_sk.clone(), &mut r4);
    let _ = offer4;
    let e = ai4.handle_response(&spliced).unwrap_err();
    check!(
        matches!(e, EncounterError::SessionMismatch),
        "spliced digest: got {e:?}"
    );
    Ok("stale QR2 -> SessionMismatch; stale QR3 -> InvalidCommitment; replayed QR1 + old QR3 -> InvalidSignature; spliced digest rejected".into())
}

fn v3_tamper_and_mitm() -> VResult {
    let seed = 131;
    let mut tried = 0usize;
    let mut accepted = Vec::new();
    for frame in 0..3 {
        let len = [
            session(seed).offer.len(),
            session(seed).resp.len(),
            session(seed).reveal.len(),
        ][frame];
        for pos in 0..len {
            for bit in 0..8u8 {
                tried += 1;
                let edit = move |b: &[u8]| {
                    let mut m = b.to_vec();
                    m[pos] ^= 1 << bit;
                    m
                };
                if drive(seed, frame, &edit).is_ok() {
                    accepted.push((frame, pos, bit));
                }
            }
        }
    }
    check!(
        accepted.is_empty(),
        "{} of {} single-bit mutations completed a session, e.g. {:?}",
        accepted.len(),
        tried,
        &accepted[..accepted.len().min(5)]
    );

    // Full relay MITM that re-signs under its own key: it completes with each victim, but the two SAS values must differ.
    let mut matches = 0;
    let trials = 300u64;
    for t in 0..trials {
        let mut r = rng(1000 + t);
        let alice_sk = SigningKey::generate(&mut r);
        let bob_sk = SigningKey::generate(&mut r);
        let mallory_sk = SigningKey::generate(&mut r);
        // Alice <-> Mallory
        let (ai, a_offer) = Initiator::start(alice_sk, &mut r);
        let (m_as_bob, resp_to_alice) =
            Responder::handle_offer(mallory_sk.clone(), &a_offer.to_bytes(), &mut r).unwrap();
        let (alice_conf, a_reveal) = ai.handle_response(&resp_to_alice.to_bytes()).unwrap();
        let _ = m_as_bob.handle_reveal(&a_reveal.to_bytes()).unwrap();
        // Mallory <-> Bob (her own, independent session)
        let (mi, m_offer) = Initiator::start(mallory_sk, &mut r);
        let (bs, b_resp) = Responder::handle_offer(bob_sk, &m_offer.to_bytes(), &mut r).unwrap();
        let (_mc, m_reveal) = mi.handle_response(&b_resp.to_bytes()).unwrap();
        let bob_conf = bs.handle_reveal(&m_reveal.to_bytes()).unwrap();
        if alice_conf.sas_code() == bob_conf.sas_code() {
            matches += 1;
        }
    }
    check!(
        matches == 0,
        "relay MITM produced {} matching SAS pairs in {} fixed-seed trials (chance is 1e-6 each)",
        matches,
        trials
    );
    Ok(format!(
        "{tried} single-bit mutations across all three frames: 0 completed; {trials} re-signing relay MITM traces: 0 SAS matches (seeds 1000..{}); NOT a bound on attacker guessing, see spec 3a",
        1000 + trials - 1
    ))
}

fn v4_unknown_key_share() -> VResult {
    let s = session(141);
    let mut r = rng(142);
    let mallory = SigningKey::generate(&mut r);
    // (a) swap Bob's identity key, keep the rest
    let (ai, offer) = Initiator::start(s.alice_sk.clone(), &mut r);
    let (_bs, resp) = Responder::handle_offer(s.bob_sk.clone(), &offer.to_bytes(), &mut r).unwrap();
    let mut t = resp;
    t.bob_ed25519_pk = mallory.verifying_key().to_bytes();
    let e = ai.handle_response(&t.to_bytes()).unwrap_err();
    check!(e == EncounterError::InvalidSignature, "(a) got {e:?}");
    // (b) Mallory relays Alice's commitment under Mallory's identity key; Bob's reply is bound to that offer, so Alice rejects it
    let (ai, offer) = Initiator::start(s.alice_sk.clone(), &mut r);
    let mut swapped = offer.clone();
    swapped.alice_ed25519_pk = mallory.verifying_key().to_bytes();
    let (_bs, resp) =
        Responder::handle_offer(s.bob_sk.clone(), &swapped.to_bytes(), &mut r).unwrap();
    let e = ai.handle_response(&resp.to_bytes()).unwrap_err();
    check!(e == EncounterError::SessionMismatch, "(b) got {e:?}");
    // (c) Bob's response to one Alice shown to a different Alice
    let (_a1, o1) = Initiator::start(s.alice_sk.clone(), &mut r);
    let (_bs, resp1) = Responder::handle_offer(s.bob_sk.clone(), &o1.to_bytes(), &mut r).unwrap();
    let other_alice = SigningKey::generate(&mut r);
    let (a2, _o2) = Initiator::start(other_alice, &mut r);
    let e = a2.handle_response(&resp1.to_bytes()).unwrap_err();
    check!(e == EncounterError::SessionMismatch, "(c) got {e:?}");
    Ok("key swap -> InvalidSignature; re-keyed offer -> SessionMismatch; response shown to a different Alice -> SessionMismatch".into())
}

fn v5_malformed_and_weak() -> VResult {
    let s = session(151);
    // Downgrade
    let mut r = rng(152);
    let mut off = EncounterOfferV1::from_bytes(&s.offer).unwrap();
    off.proto = "mesh.encounter.v0".into();
    let e = Responder::handle_offer(s.bob_sk.clone(), &off.to_bytes(), &mut r).unwrap_err();
    check!(
        e == EncounterError::ProtocolDowngrade,
        "downgrade got {e:?}"
    );

    // Non-canonical / malformed variants of a valid offer must all be MalformedPayload
    let valid = Value::Map(
        match cbor2::from_reader::<Value, _>(&s.offer[..]).unwrap() {
            Value::Map(m) => m,
            _ => unreachable!(),
        },
    );
    let enc = |v: &Value| cbor2::to_vec(v).unwrap();
    let mut cases: Vec<(&str, Vec<u8>)> = Vec::new();
    let mut trailing = s.offer.clone();
    trailing.push(0);
    cases.push(("trailing byte", trailing));
    if let Value::Map(m) = &valid {
        let mut extra = m.clone();
        extra.push((Value::Text("zz".into()), Value::Integer(1.into())));
        cases.push(("unknown field", enc(&Value::Map(extra))));
        let mut rev = m.clone();
        rev.reverse();
        cases.push(("reordered map", enc(&Value::Map(rev))));
        let mut indef = vec![0xBFu8];
        for (k, v) in m {
            indef.extend(enc(k));
            indef.extend(enc(v));
        }
        indef.push(0xFF);
        cases.push(("indefinite map", indef));
        let mut sq = m.clone();
        sq[2].1 = Value::Array((0..32).map(|i| Value::Integer(i.into())).collect());
        cases.push(("keys as integer arrays", enc(&Value::Map(sq))));
        let mut short = m.clone();
        short[2].1 = Value::Bytes(vec![0; 31]);
        cases.push(("short commit", enc(&Value::Map(short))));
    }
    // non-minimal length: rewrite the 4-entry map header 0xA4 as 0xB8 0x04
    let mut nonmin = vec![0xB8, 0x04];
    nonmin.extend_from_slice(&s.offer[1..]);
    cases.push(("non-minimal map header", nonmin));
    cases.push(("oversize", vec![0u8; MAX_FRAME_BYTES + 1]));
    cases.push(("empty", vec![]));
    for (name, bytes) in &cases {
        let e = Responder::handle_offer(s.bob_sk.clone(), bytes, &mut r).err();
        check!(
            matches!(e, Some(EncounterError::MalformedPayload(_))),
            "{name}: expected MalformedPayload, got {e:?}"
        );
    }

    // Mutate each frame inside a matching deterministic handshake and record the rejection reason.
    let mut panics = 0;
    let mut accepted_nonidentical = 0;
    let mut rejection_counts = std::collections::BTreeMap::new();
    let valid_frames = [s.offer.clone(), s.resp.clone(), s.reveal.clone()];
    for i in 0..10_000u64 {
        let mut fr = rng(10_000 + i);
        let frame = (i % 3) as usize;
        let mut buf = valid_frames[frame].clone();
        match fr.gen_range(0..5) {
            0 => {
                let p = fr.gen_range(0..buf.len());
                buf[p] ^= 1 << fr.gen_range(0..8);
            }
            1 => buf.truncate(fr.gen_range(0..buf.len())),
            2 => buf.extend((0..fr.gen_range(1..40)).map(|_| fr.r#gen::<u8>())),
            3 => {
                let p = fr.gen_range(0..buf.len());
                buf.insert(p, fr.r#gen::<u8>());
            }
            _ => {
                buf = (0..fr.gen_range(0..300))
                    .map(|_| fr.r#gen::<u8>())
                    .collect();
            }
        }
        if buf == valid_frames[frame] {
            continue;
        }
        let out = std::panic::catch_unwind(|| drive(151, frame, &|_| buf.clone()));
        match out {
            Err(_) => panics += 1,
            Ok(Ok(_)) => accepted_nonidentical += 1,
            Ok(Err(error)) => {
                *rejection_counts
                    .entry(format!("{error:?}").split('(').next().unwrap().to_owned())
                    .or_insert(0) += 1;
            }
        }
    }
    check!(panics == 0, "{panics} panics in 10,000 inputs");
    check!(
        accepted_nonidentical == 0,
        "{accepted_nonidentical} mutated inputs completed"
    );

    // All-zero X25519 points from properly signing peers
    for low in [[0u8; 32], {
        let mut p = [0u8; 32];
        p[0] = 1;
        p
    }] {
        let mut r3 = rng(153);
        let (ai, offer) = Initiator::start(s.alice_sk.clone(), &mut r3);
        let forged = forge_response(
            &s.bob_sk,
            &offer.to_bytes(),
            s.bob_sk.verifying_key().to_bytes(),
            low,
            None,
        );
        let e = ai.handle_response(&forged).unwrap_err();
        check!(
            e == EncounterError::InvalidDiffieHellman,
            "low-order epk {:?} from signing Bob: got {e:?}",
            &low[..2]
        );
    }
    // Malicious Alice commits to a low-order epk and reveals it with a valid signature
    {
        let mut r3 = rng(154);
        let zero = [0u8; 32];
        let nonce_a = [9u8; 16];
        let offer = EncounterOfferV1 {
            role: "offer".into(),
            proto: PROTO_V1.into(),
            commit_a: spec_commit(&zero, &nonce_a),
            alice_ed25519_pk: s.alice_sk.verifying_key().to_bytes(),
        }
        .to_bytes();
        let (bs, resp) = Responder::handle_offer(s.bob_sk.clone(), &offer, &mut r3).unwrap();
        let t = spec_transcript(&offer, &resp.to_bytes(), &zero, &nonce_a);
        let sig_a = s.alice_sk.sign(&spec_reveal_payload(&t)).to_bytes();
        let rev = EncounterRevealV1 {
            role: "reveal".into(),
            proto: PROTO_V1.into(),
            sig_a,
            nonce_a,
            alice_x25519_epk: zero,
        }
        .to_bytes();
        let e = bs.handle_reveal(&rev).unwrap_err();
        check!(
            e == EncounterError::InvalidDiffieHellman,
            "zero epk in QR3: got {e:?}"
        );
    }
    // Weak (small-order) identity keys with signatures that need no secret
    {
        let mut r3 = rng(155);
        let (ai, offer) = Initiator::start(s.alice_sk.clone(), &mut r3);
        let forged = forge_response(
            &s.bob_sk,
            &offer.to_bytes(),
            IDENTITY_POINT,
            [9u8; 32],
            Some(identity_sig()),
        );
        let e = ai.handle_response(&forged).unwrap_err();
        check!(e == EncounterError::WeakKey, "weak Bob key: got {e:?}");
        let weak_offer = EncounterOfferV1 {
            role: "offer".into(),
            proto: PROTO_V1.into(),
            commit_a: [1; 32],
            alice_ed25519_pk: IDENTITY_POINT,
        }
        .to_bytes();
        let e = Responder::handle_offer(s.bob_sk.clone(), &weak_offer, &mut r3).err();
        check!(
            e == Some(EncounterError::WeakKey),
            "weak Alice key: got {e:?}"
        );
    }
    Ok(format!(
        "{} malformed-frame classes -> MalformedPayload; 10,000 matching-session mutations: 0 panics, 0 completions; rejection stages {rejection_counts:?}; zero/low-order X25519 -> InvalidDiffieHellman (both sides); small-order identity keys -> WeakKey (both sides)",
        cases.len()
    ))
}

fn v6_relay_limitation() -> VResult {
    let s = session(161);
    // Every frame is forwarded verbatim through an arbitrary relay; the ceremony still completes.
    check!(
        s.alice.sas_code() == s.bob.sas_code(),
        "relayed ceremony did not complete"
    );
    check!(
        PROXIMITY_DISCLAIMER.contains("does not prove physical proximity"),
        "UI disclaimer text missing"
    );
    Ok("ceremony completes across a verbatim relay, so the crate exports PROXIMITY_DISCLAIMER for UIs; no proximity claim is made. The UI itself is out of scope here".into())
}

fn v7_transport_equivalence() -> VResult {
    // Same seed => same frames. Each transport must deliver them byte-for-byte and yield identical SAS and transcript.
    let seed = 171;
    let base = session(seed);
    let via = |name: &str, mut carry: CarryFrame| -> Result<(u32, u32), String> {
        let mut r = rng(seed);
        let a_sk = SigningKey::generate(&mut r);
        let b_sk = SigningKey::generate(&mut r);
        let (ai, offer) = Initiator::start(a_sk, &mut r);
        let q1 = carry(&offer.to_bytes(), true).map_err(|e| format!("{name}: {e}"))?;
        let (bs, resp) =
            Responder::handle_offer(b_sk, &q1, &mut r).map_err(|e| format!("{name}: {e:?}"))?;
        let q2 = carry(&resp.to_bytes(), false).map_err(|e| format!("{name}: {e}"))?;
        let (a, rev) = ai
            .handle_response(&q2)
            .map_err(|e| format!("{name}: {e:?}"))?;
        let q3 = carry(&rev.to_bytes(), true).map_err(|e| format!("{name}: {e}"))?;
        let b = bs
            .handle_reveal(&q3)
            .map_err(|e| format!("{name}: {e:?}"))?;
        if a.transcript() != base.alice.transcript() || b.transcript() != base.bob.transcript() {
            return Err(format!("{name}: transcript differs from the reference run"));
        }
        Ok((a.sas_code(), b.sas_code()))
    };
    // QR: each frame goes through a text URI
    let qr = via(
        "QR",
        Box::new(|bytes, _| {
            let mut tx = QrTransport::new();
            let mut rx = QrTransport::new();
            tx.send(bytes).map_err(|e| e.to_string())?;
            rx.scan_from_peer(tx.display_screen.as_ref().unwrap());
            rx.receive().map_err(|e| e.to_string())
        }),
    )?;
    // BLE: queue pair
    let ble = via(
        "BLE",
        Box::new(|bytes, _| {
            let (mut a, mut b) = BleTransport::create_pair();
            a.send(bytes).map_err(|e| e.to_string())?;
            BleTransport::pump(&mut a, &mut b).map_err(|e| e.to_string())?;
            b.receive().map_err(|e| e.to_string())
        }),
    )?;
    // Hybrid: QR1 only through the bootstrap URI, other frames over BLE
    let mut hybrid_calls = 0;
    let hybrid = via(
        "Hybrid",
        Box::new(move |bytes, _| {
            use base64::Engine;
            hybrid_calls += 1;
            if hybrid_calls == 1 {
                let h = HybridBootstrapQr {
                    ble_service_uuid: [7; 16],
                    offer_payload_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
                };
                let d = HybridBootstrapQr::decode(&h.encode()).map_err(|e| e.to_string())?;
                base64::engine::general_purpose::STANDARD
                    .decode(d.offer_payload_b64)
                    .map_err(|e| e.to_string())
            } else {
                Ok(bytes.to_vec())
            }
        }),
    )?;
    let want = (base.alice.sas_code(), base.bob.sas_code());
    check!(
        qr == want && ble == want && hybrid == want,
        "SAS differs across transports: {qr:?} {ble:?} {hybrid:?} vs {want:?}"
    );
    // Corrupt QR text and wrong prefixes are rejected, not panics
    let mut rx = QrTransport::new();
    rx.scan_from_peer("mesh:encounter:!!!not-base64");
    check!(rx.receive().is_err(), "corrupt base64 accepted");
    rx.scan_from_peer("http://example.com/x");
    check!(rx.receive().is_err(), "foreign URI accepted");
    check!(
        HybridBootstrapQr::decode("mesh:hybrid:AAAA:xx").is_err(),
        "short hybrid UUID accepted"
    );
    Ok("identical frames, transcript and SAS over QR, BLE (in-memory queue) and Hybrid carriage; transports are byte pipes and are not tested for MTU, fragmentation or radio behaviour".into())
}

fn v8_trust_boundaries() -> VResult {
    let s = session(181);
    let mut r = rng(182);
    let bob_pk = s.bob_sk.verifying_key().to_bytes();
    let alice_pk = s.alice_sk.verifying_key().to_bytes();
    let mut store = ContactStore::for_identity(alice_pk);
    let confirmed = s.alice.clone().confirm(s.alice.sas_code()).unwrap();
    store
        .record_confirmed_encounter(&confirmed, 10, &mut r)
        .unwrap();

    // Export carries only the key and label
    let export = store.export_contact(&bob_pk, Some("Bob".into())).unwrap();
    let json = format!("{export:?}");
    check!(
        !json.contains("local_contact_id")
            && !json.contains("encounter_count")
            && !json.contains("transcript"),
        "export leaks local fields"
    );

    // Forged / hostile imports
    let mut third = ContactStore::for_identity([0xEE; 32]);
    check!(
        third.import_contact(
            ContactExportV1 {
                peer_ed25519_pk: IDENTITY_POINT,
                label: None
            },
            &mut r
        ) == Err(StoreError::InvalidKey),
        "weak key import accepted"
    );
    check!(
        third
            .import_contact(
                ContactExportV1 {
                    peer_ed25519_pk: [0xEE; 32],
                    label: None
                },
                &mut r
            )
            .is_err(),
        "self import accepted"
    );
    let imported = third
        .import_contact(export.clone(), &mut r)
        .map_err(|e| format!("{e:?}"))?
        .clone();
    check!(
        imported.verification_status == VerificationStatus::ImportedUnverified
            && imported.encounter_count == 0
            && imported.last_transcript == [0; 32],
        "import not unverified/zero"
    );
    let again = third
        .import_contact(export.clone(), &mut r)
        .map_err(|e| format!("{e:?}"))?;
    check!(
        again.local_contact_id == imported.local_contact_id,
        "re-import replaced the local record"
    );

    // Import cannot downgrade or overwrite a verified contact
    let before = store.get(&bob_pk).unwrap().clone();
    let after = store
        .import_contact(export.clone(), &mut r)
        .map_err(|e| format!("{e:?}"))?
        .clone();
    check!(before == after, "import changed a verified contact");

    // Own key cannot be saved as a contact even through a (forged) confirmation path
    check!(
        store.import_contact(
            ContactExportV1 {
                peer_ed25519_pk: alice_pk,
                label: None
            },
            &mut r
        ) == Err(StoreError::SelfContact),
        "own key import accepted"
    );

    // Blocked contacts are not silently reactivated by a new encounter or by import
    store.block(&bob_pk);
    let mut r2 = rng(183);
    let (ai, offer) = Initiator::start(s.alice_sk.clone(), &mut r2);
    let (bs, resp) = Responder::handle_offer(s.bob_sk.clone(), &offer.to_bytes(), &mut r2).unwrap();
    let (a2, rev) = ai.handle_response(&resp.to_bytes()).unwrap();
    let b2 = bs.handle_reveal(&rev.to_bytes()).unwrap();
    let c2 = a2.confirm(b2.sas_code()).unwrap();
    let blocked = store.record_confirmed_encounter(&c2, 20, &mut r).err();
    check!(
        blocked == Some(StoreError::Blocked),
        "blocked contact accepted a new encounter: {blocked:?}"
    );
    check!(
        store.get(&bob_pk).unwrap().encounter_count == 1,
        "blocked contact count changed"
    );
    Ok("export strips local fields; weak/self/duplicate/hostile imports rejected or unchanged; verified and blocked records survive import and new encounters".into())
}

fn v9_state_and_retry() -> VResult {
    // Local confirmation boundary: wrong code aborts and saves nothing
    let s = session(191);
    let mut r = rng(192);
    let mut store = ContactStore::for_identity(s.bob_sk.verifying_key().to_bytes());
    let wrong = (s.alice.sas_code() + 1) % 1_000_000;
    check!(
        s.alice.clone().confirm(wrong) == Err(EncounterError::SasMismatch),
        "SAS mismatch not detected"
    );
    check!(store.count() == 0, "store changed without confirmation");
    let ok = s.bob.clone().confirm(s.alice.sas_code()).unwrap();
    store.record_confirmed_encounter(&ok, 1, &mut r).unwrap();
    store.record_confirmed_encounter(&ok, 2, &mut r).unwrap();
    check!(
        store
            .get(&s.alice_sk.verifying_key().to_bytes())
            .unwrap()
            .encounter_count
            == 1,
        "double tap counted twice"
    );

    // 9a: each restart uses fresh randomness
    let mut commits = std::collections::HashSet::new();
    let mut rr = rng(193);
    for _ in 0..200 {
        let (_, offer) = Initiator::start(s.alice_sk.clone(), &mut rr);
        commits.insert(offer.commit_a);
    }
    check!(commits.len() == 200, "restarts reused randomness");

    // Attempt policy: scripted attacker abandons every half-session
    let mut p = AttemptPolicy::new();
    let mut now = 0u64;
    for i in 0..MAX_CONSECUTIVE_INCOMPLETE {
        p.begin(now).map_err(|e| format!("attempt {i}: {e:?}"))?;
        check!(
            p.begin(now) == Err(AttemptError::SessionAlreadyLive),
            "second live session allowed"
        );
        now += 1000;
        p.record_incomplete(now);
    }
    check!(
        p.warning_active(),
        "warning not shown after {} incomplete sessions",
        MAX_CONSECUTIVE_INCOMPLETE
    );
    check!(
        matches!(p.begin(now), Err(AttemptError::Paused { .. })),
        "no pause after repeated aborts"
    );
    check!(
        matches!(
            p.begin(now + PAUSE_MS - 1),
            Err(AttemptError::Paused { .. })
        ),
        "pause ended early"
    );
    p.begin(now + PAUSE_MS)
        .map_err(|e| format!("pause did not end: {e:?}"))?;
    p.record_complete();
    check!(
        p.consecutive_incomplete() == 0 && !p.warning_active(),
        "completion did not reset the count"
    );

    // Timeout counts as incomplete and frees the slot
    let mut q = AttemptPolicy::new();
    q.begin(0).unwrap();
    q.expire(SESSION_TIMEOUT_MS - 1);
    check!(q.is_live(), "expired early");
    q.expire(SESSION_TIMEOUT_MS);
    check!(
        !q.is_live() && q.consecutive_incomplete() == 1,
        "timeout not counted"
    );
    Ok("wrong SAS saves nothing; double tap counts once; 200 restarts all fresh; warning and 60 s pause after 3 incompletes; one live session; timeout counts; completion resets".into())
}

fn v10_self_reflection() -> VResult {
    let s = session(201);
    let mut r = rng(202);
    // QR1: Bob receives an offer carrying his own identity key
    let own = EncounterOfferV1 {
        role: "offer".into(),
        proto: PROTO_V1.into(),
        commit_a: [3; 32],
        alice_ed25519_pk: s.bob_sk.verifying_key().to_bytes(),
    }
    .to_bytes();
    let e = Responder::handle_offer(s.bob_sk.clone(), &own, &mut r).err();
    check!(
        e == Some(EncounterError::SelfReflectionRejected),
        "QR1: got {e:?}"
    );
    // QR2: Alice receives a response carrying her own identity key (signed by her, as a reflected device would)
    let (ai, offer) = Initiator::start(s.alice_sk.clone(), &mut r);
    let f = forge_response(
        &s.alice_sk,
        &offer.to_bytes(),
        s.alice_sk.verifying_key().to_bytes(),
        [9u8; 32],
        None,
    );
    let e = ai.handle_response(&f).err();
    check!(
        e == Some(EncounterError::SelfReflectionRejected),
        "QR2 identity: got {e:?}"
    );
    // QR2: response carrying Alice's own ephemeral key
    let mut epk_rng = r.clone();
    let (ai, offer) = Initiator::start(s.alice_sk.clone(), &mut r);
    let own_epk =
        *x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::random_from_rng(&mut epk_rng))
            .as_bytes();
    let f = forge_response(
        &s.bob_sk,
        &offer.to_bytes(),
        s.bob_sk.verifying_key().to_bytes(),
        own_epk,
        None,
    );
    let e = ai.handle_response(&f).err();
    check!(
        e == Some(EncounterError::SelfReflectionRejected),
        "QR2 ephemeral: got {e:?}"
    );
    // QR3: reveal carrying Bob's own ephemeral key
    let (ai, offer) = Initiator::start(s.alice_sk.clone(), &mut r);
    let (bs, resp) = Responder::handle_offer(s.bob_sk.clone(), &offer.to_bytes(), &mut r).unwrap();
    let (_a, mut rev) = ai.handle_response(&resp.to_bytes()).unwrap();
    rev.alice_x25519_epk = resp.bob_x25519_epk;
    let e = bs.handle_reveal(&rev.to_bytes()).err();
    check!(
        e == Some(EncounterError::SelfReflectionRejected),
        "QR3: got {e:?}"
    );
    Ok("own identity key in QR1 and QR2, own ephemeral key in QR2 and QR3 -> SelfReflectionRejected before DH or signature acceptance".into())
}

fn v11_conformance_and_roles() -> VResult {
    let s = session(211);
    // Independent re-derivation from the specification text must match the production values
    let offer = EncounterOfferV1::from_bytes(&s.offer).unwrap();
    let resp = EncounterResponseV1::from_bytes(&s.resp).unwrap();
    let rev = EncounterRevealV1::from_bytes(&s.reveal).unwrap();
    check!(
        spec_commit(&rev.alice_x25519_epk, &rev.nonce_a) == offer.commit_a,
        "commit_a differs from spec derivation"
    );
    check!(
        spec_offer_digest(&s.offer) == resp.offer_digest,
        "offer_digest differs from spec derivation"
    );
    let payload = spec_resp_payload(
        &resp.offer_digest,
        &offer.alice_ed25519_pk,
        &resp.bob_ed25519_pk,
        &resp.bob_x25519_epk,
        &resp.nonce_b,
    );
    let bob_vk = ed25519_dalek::VerifyingKey::from_bytes(&resp.bob_ed25519_pk).unwrap();
    check!(
        bob_vk
            .verify_strict(&payload, &ed25519_dalek::Signature::from_bytes(&resp.sig_b))
            .is_ok(),
        "sig_b does not verify over the spec payload"
    );
    let t = spec_transcript(&s.offer, &s.resp, &rev.alice_x25519_epk, &rev.nonce_a);
    check!(
        t == s.alice.transcript() && t == s.bob.transcript(),
        "transcript differs from spec derivation"
    );
    let alice_vk = ed25519_dalek::VerifyingKey::from_bytes(&offer.alice_ed25519_pk).unwrap();
    check!(
        alice_vk
            .verify_strict(
                &spec_reveal_payload(&t),
                &ed25519_dalek::Signature::from_bytes(&rev.sig_a)
            )
            .is_ok(),
        "sig_a does not verify over the spec payload"
    );
    check!(
        s.offer.len() <= MAX_FRAME_BYTES
            && s.resp.len() <= MAX_FRAME_BYTES
            && s.reveal.len() <= MAX_FRAME_BYTES,
        "frame over {MAX_FRAME_BYTES} bytes"
    );
    // Frames have fixed lengths across sessions (no variable-width byte encoding)
    let lens: Vec<usize> = (0..20).map(|i| session(300 + i).resp.len()).collect();
    check!(
        lens.iter().all(|l| *l == lens[0]),
        "response length varies: {lens:?}"
    );

    // Cross-role confusion: every frame fed to every wrong handler is rejected
    let mut r = rng(212);
    for (name, bytes) in [("QR2", &s.resp), ("QR3", &s.reveal)] {
        check!(
            Responder::handle_offer(s.bob_sk.clone(), bytes, &mut r).is_err(),
            "{name} accepted as QR1"
        );
    }
    for (name, bytes) in [("QR1", &s.offer), ("QR3", &s.reveal)] {
        let (ai, _) = Initiator::start(s.alice_sk.clone(), &mut r);
        check!(ai.handle_response(bytes).is_err(), "{name} accepted as QR2");
    }
    for (name, bytes) in [("QR1", &s.offer), ("QR2", &s.resp)] {
        let (_a, o) = Initiator::start(s.alice_sk.clone(), &mut r);
        let (bs, _) = Responder::handle_offer(s.bob_sk.clone(), &o.to_bytes(), &mut r).unwrap();
        check!(bs.handle_reveal(bytes).is_err(), "{name} accepted as QR3");
    }
    // Wrong role string inside an otherwise valid frame
    let mut wrong_role = offer.clone();
    wrong_role.role = "response".into();
    check!(
        Responder::handle_offer(s.bob_sk.clone(), &wrong_role.to_bytes(), &mut r).is_err(),
        "wrong role accepted"
    );
    Ok(format!(
        "commit, digest, both signatures, transcript match an independent spec derivation; frames {}/{}/{} bytes (<= {MAX_FRAME_BYTES}, fixed length); all cross-role feeds rejected",
        s.offer.len(),
        s.resp.len(),
        s.reveal.len()
    ))
}

fn v12_state_machines() -> VResult {
    let mut r = rng(221);
    let a_sk = SigningKey::generate(&mut r);
    let b_sk = SigningKey::generate(&mut r);

    // Rescan idempotence on both machines
    let mut am = InitiatorMachine::new();
    let mut bm = ResponderMachine::new();
    let q1 = am
        .start(a_sk.clone(), &mut r)
        .map_err(|e| format!("{e:?}"))?;
    check!(
        am.start(a_sk.clone(), &mut r) == Err(EncounterError::OutOfOrder),
        "second start allowed"
    );
    let q2 = bm
        .on_offer(b_sk.clone(), &q1, &mut r)
        .map_err(|e| format!("{e:?}"))?;
    let q2_again = bm
        .on_offer(b_sk.clone(), &q1, &mut r)
        .map_err(|e| format!("{e:?}"))?;
    check!(
        q2 == q2_again,
        "identical QR1 rescan produced a different QR2 (new randomness)"
    );
    let q3 = am.on_response(&q2).map_err(|e| format!("{e:?}"))?;
    let sas = am.sas_code().ok_or("no SAS after QR2")?;
    let q3_again = am.on_response(&q2).map_err(|e| format!("{e:?}"))?;
    check!(
        q3 == q3_again && am.sas_code() == Some(sas),
        "identical QR2 rescan changed QR3 or SAS"
    );
    bm.on_reveal(&q3).map_err(|e| format!("{e:?}"))?;
    bm.on_reveal(&q3).map_err(|e| format!("{e:?}"))?;
    check!(bm.sas_code() == Some(sas), "SAS differs between machines");
    // out-of-order and changed earlier frames
    check!(
        bm.on_offer(b_sk.clone(), &s_other_offer(&a_sk, &mut r), &mut r)
            == Err(EncounterError::SessionMismatch),
        "changed QR1 after acceptance not rejected"
    );
    check!(bm.is_terminal(), "changed QR1 did not abort Bob");
    check!(
        bm.on_reveal(&q3) == Err(EncounterError::SessionClosed),
        "aborted machine accepted a frame"
    );
    // Alice: changed QR2 after QR3 aborts
    let mut am2 = InitiatorMachine::new();
    let mut bm2 = ResponderMachine::new();
    let o = am2.start(a_sk.clone(), &mut r).unwrap();
    let rsp = bm2.on_offer(b_sk.clone(), &o, &mut r).unwrap();
    am2.on_response(&rsp).unwrap();
    let mut bm3 = ResponderMachine::new();
    let o3 = InitiatorMachine::new().start(a_sk.clone(), &mut r).unwrap();
    let other_rsp = bm3.on_offer(b_sk.clone(), &o3, &mut r).unwrap();
    check!(
        am2.on_response(&other_rsp) == Err(EncounterError::SessionMismatch),
        "changed QR2 after reveal not rejected"
    );
    check!(
        am2.on_response(&rsp) == Err(EncounterError::SessionClosed),
        "aborted Alice accepted a frame"
    );
    // out-of-order frames
    let mut fresh_a = InitiatorMachine::new();
    check!(
        fresh_a.on_response(&rsp) == Err(EncounterError::OutOfOrder),
        "QR2 before start accepted"
    );
    check!(
        fresh_a.confirm(0) == Err(EncounterError::OutOfOrder),
        "confirm before QR2 accepted"
    );
    let mut fresh_b = ResponderMachine::new();
    check!(
        fresh_b.on_reveal(&q3) == Err(EncounterError::OutOfOrder),
        "QR3 before QR1 accepted"
    );

    // Confirmation: wrong code aborts; double tap returns the same value; cancel after confirm keeps it
    let mut am4 = InitiatorMachine::new();
    let mut bm4 = ResponderMachine::new();
    let o4 = am4.start(a_sk.clone(), &mut r).unwrap();
    let r4 = bm4.on_offer(b_sk.clone(), &o4, &mut r).unwrap();
    let rv4 = am4.on_response(&r4).unwrap();
    bm4.on_reveal(&rv4).unwrap();
    let code = am4.sas_code().unwrap();
    check!(
        am4.confirm((code + 1) % 1_000_000) == Err(EncounterError::SasMismatch),
        "wrong code accepted"
    );
    check!(
        am4.confirm(code) == Err(EncounterError::SessionClosed),
        "mismatch did not abort"
    );
    let c1 = bm4.confirm(code).map_err(|e| format!("{e:?}"))?;
    let c2 = bm4.confirm(code).map_err(|e| format!("{e:?}"))?;
    check!(c1 == c2, "double tap returned a different confirmation");
    bm4.cancel();
    check!(
        bm4.confirm(code).is_ok(),
        "cancel after confirm retracted a local save"
    );

    // Crash/restart at each cut point: nothing saved, prior contact survives, old frames fail a new session
    let mut store = ContactStore::for_identity(a_sk.verifying_key().to_bytes());
    let prior = {
        let (waiting, offer) = Initiator::start(a_sk.clone(), &mut r);
        let (responder, response) =
            Responder::handle_offer(b_sk.clone(), &offer.to_bytes(), &mut r).unwrap();
        let (awaiting, reveal) = waiting.handle_response(&response.to_bytes()).unwrap();
        let remote = responder.handle_reveal(&reveal.to_bytes()).unwrap();
        let c = awaiting.confirm(remote.sas_code()).unwrap();
        store
            .record_confirmed_encounter(&c, 1, &mut r)
            .cloned()
            .map_err(|e| format!("{e:?}"))?
    };
    let snapshot = store.count();
    for cut in 0..4 {
        let mut am = InitiatorMachine::new();
        let mut bm = ResponderMachine::new();
        let o = am.start(a_sk.clone(), &mut r).unwrap();
        if cut >= 1 {
            let rsp = bm.on_offer(b_sk.clone(), &o, &mut r).unwrap();
            if cut >= 2 {
                let rv = am.on_response(&rsp).unwrap();
                if cut >= 3 {
                    bm.on_reveal(&rv).unwrap();
                }
            }
        }
        drop(am);
        drop(bm); // crash: process state lost, nothing was confirmed
        check!(
            store.count() == snapshot && store.get(&prior.peer_ed25519_pk) == Some(&prior),
            "cut {cut}: contact state changed by a crashed session"
        );
    }
    // a fresh attempt after a crash completes normally and old frames cannot complete it
    let mut am5 = InitiatorMachine::new();
    let mut bm5 = ResponderMachine::new();
    let o5 = am5.start(a_sk.clone(), &mut r).unwrap();
    check!(
        bm5.on_offer(b_sk.clone(), &o5, &mut r).is_ok(),
        "fresh attempt failed"
    );
    let rv_old = q3.clone();
    check!(
        bm5.on_reveal(&rv_old).is_err(),
        "old QR3 completed a new session"
    );

    // Asymmetric cancel: Bob confirms and saves; Alice cancels. Neither retracts the other.
    let mut a6 = InitiatorMachine::new();
    let mut b6 = ResponderMachine::new();
    let o6 = a6.start(a_sk.clone(), &mut r).unwrap();
    let r6 = b6.on_offer(b_sk.clone(), &o6, &mut r).unwrap();
    let rv6 = a6.on_response(&r6).unwrap();
    b6.on_reveal(&rv6).unwrap();
    let code6 = b6.sas_code().unwrap();
    let mut bob_store = ContactStore::for_identity(b_sk.verifying_key().to_bytes());
    let bob_confirmed = b6.confirm(code6).map_err(|e| format!("{e:?}"))?;
    bob_store
        .record_confirmed_encounter(&bob_confirmed, 5, &mut r)
        .map_err(|e| format!("{e:?}"))?;
    a6.cancel();
    check!(
        a6.confirm(code6) == Err(EncounterError::SessionClosed),
        "Alice confirmed after cancelling"
    );
    check!(
        bob_store.count() == 1,
        "Alice's cancel retracted Bob's save"
    );
    // Abandoned half-session counts as incomplete in the attempt policy
    let mut pol = AttemptPolicy::new();
    pol.begin(0).unwrap();
    pol.record_incomplete(10);
    check!(
        pol.consecutive_incomplete() == 1,
        "abandoned session not counted"
    );
    Ok("rescans idempotent (no new randomness); changed or out-of-order frames abort; wrong code aborts; double tap and cancel-after-confirm stable; crashes at 4 cut points save nothing and keep the prior contact; asymmetric cancel retracts nothing".into())
}

fn s_other_offer(sk: &SigningKey, r: &mut StdRng) -> Vec<u8> {
    Initiator::start(sk.clone(), r).1.to_bytes()
}

fn v13_zeroize_alias_ui() -> VResult {
    use zeroize::{Zeroize, ZeroizeOnDrop};
    fn assert_zod<T: ZeroizeOnDrop>() {}
    assert_zod::<InitiatorWaitingForResponse>();
    assert_zod::<ResponderAwaitingReveal>();
    let mut r = rng(231);
    let a_sk = SigningKey::generate(&mut r);
    let b_sk = SigningKey::generate(&mut r);
    let (mut ai, offer) = Initiator::start(a_sk, &mut r);
    check!(!ai.opening_buffers_cleared(), "test setup");
    ai.zeroize();
    check!(
        ai.opening_buffers_cleared(),
        "initiator state not wiped by zeroize()"
    );
    let (mut bs, _) = Responder::handle_offer(b_sk, &offer.to_bytes(), &mut r).unwrap();
    bs.zeroize();
    check!(
        bs.transcript_buffers_cleared(),
        "responder state not wiped by zeroize()"
    );

    // Alias conflicts
    let s = session(232);
    let mut store = ContactStore::for_identity(s.alice_sk.verifying_key().to_bytes());
    let alice_conf = s.alice.clone().confirm(s.alice.sas_code()).unwrap();
    store
        .record_confirmed_encounter(&alice_conf, 1, &mut r)
        .map_err(|e| format!("{e:?}"))?;
    let bob_pk = alice_conf.peer_ed25519_pk();
    store
        .set_alias(&bob_pk, "Sam")
        .map_err(|e| format!("{e:?}"))?;
    let other = SigningKey::generate(&mut r).verifying_key().to_bytes();
    store
        .import_contact(
            ContactExportV1 {
                peer_ed25519_pk: other,
                label: Some("Sam".into()),
            },
            &mut r,
        )
        .map_err(|e| format!("{e:?}"))?;
    check!(
        store.get(&other).unwrap().local_alias.is_none(),
        "imported label became an alias"
    );
    let e = store.set_alias(&other, " sam ").err();
    check!(
        e == Some(StoreError::AliasConflict {
            existing_pk: bob_pk
        }),
        "alias conflict not detected: {e:?}"
    );
    check!(
        store.set_alias(&other, "Sam 2").is_ok(),
        "distinct alias rejected"
    );
    check!(
        store.set_alias(&[1u8; 32], "x") == Err(StoreError::UnknownContact),
        "alias on unknown contact"
    );

    // UI strings: required statements present and distinct
    use crate::ui_text::*;
    check!(
        PROXIMITY_DISCLAIMER.contains("does not prove physical proximity"),
        "proximity text"
    );
    check!(
        LOCAL_ONLY_CONFIRMATION.contains("this device only")
            && !LOCAL_ONLY_CONFIRMATION.to_lowercase().contains("mutual"),
        "local-only text"
    );
    check!(
        ALIAS_CONFLICT_WARNING.contains("Different cryptographic identity"),
        "alias warning"
    );
    check!(
        !INTERFERENCE_WARNING.to_lowercase().contains("until")
            && !INTERFERENCE_WARNING.to_lowercase().contains("match"),
        "interference text suggests retrying until codes match"
    );
    check!(
        NOT_IDENTITY_PROOF.contains("not who a person is"),
        "identity text"
    );
    Ok("session state types are ZeroizeOnDrop and wipe fields on zeroize(); alias conflicts rejected case-insensitively; imported labels never become aliases; required UI strings present. Memory-level erasure is not verified".into())
}

/// Fixed deterministic traces of the attacks the commitment is meant to stop (spec vector 3a, part a).
/// The statistical campaign (`--features campaign`) covers the guessing odds; these pin exact behaviour.
fn v14_sas_attack_traces() -> VResult {
    let mut r = rng(241);
    let a_sk = SigningKey::generate(&mut r);
    let b_sk = SigningKey::generate(&mut r);
    let m_sk = SigningKey::generate(&mut r);

    // T1: Mallory forwards Bob's genuine response to HER offer into Alice's session
    let (a_state, q1) = Initiator::start(a_sk.clone(), &mut r);
    let (m_alice, q1m) = Initiator::start(m_sk.clone(), &mut r);
    let (_bs, q2_for_m) = Responder::handle_offer(b_sk.clone(), &q1m.to_bytes(), &mut r).unwrap();
    let e = a_state.handle_response(&q2_for_m.to_bytes()).err();
    check!(e == Some(EncounterError::SessionMismatch), "T1: got {e:?}");
    let _ = (q1, m_alice);

    // T2: Mallory reveals values that do not match her commitment
    let (m_alice, q1m) = Initiator::start(m_sk.clone(), &mut r);
    let (bs, q2) = Responder::handle_offer(b_sk.clone(), &q1m.to_bytes(), &mut r).unwrap();
    let (_c, mut q3) = m_alice.handle_response(&q2.to_bytes()).unwrap();
    q3.nonce_a[0] ^= 1;
    let e = bs.handle_reveal(&q3.to_bytes()).err();
    check!(
        e == Some(EncounterError::InvalidCommitment),
        "T2: got {e:?}"
    );

    // T3: Alice's genuine QR3 forwarded into Mallory's session with Bob
    let (a_state, q1) = Initiator::start(a_sk.clone(), &mut r);
    let (_m_bob, q2_to_a) = Responder::handle_offer(m_sk.clone(), &q1.to_bytes(), &mut r).unwrap();
    let (_a_conf, q3_a) = a_state.handle_response(&q2_to_a.to_bytes()).unwrap();
    let (_m_alice, q1m) = Initiator::start(m_sk.clone(), &mut r);
    let (bs, _q2) = Responder::handle_offer(b_sk.clone(), &q1m.to_bytes(), &mut r).unwrap();
    let e = bs.handle_reveal(&q3_a.to_bytes()).err();
    check!(
        e == Some(EncounterError::InvalidCommitment),
        "T3: got {e:?}"
    );

    // T4: commitment reuse. Mallory repeats Alice's commitment under her own key, then forwards Alice's QR3.
    // The commitment check passes (same values), but Alice signed a transcript that does not contain Mallory's frames.
    let (a_state, q1) = Initiator::start(a_sk.clone(), &mut r);
    let (_m_bob, q2_to_a) = Responder::handle_offer(m_sk.clone(), &q1.to_bytes(), &mut r).unwrap();
    let (_a_conf, q3_a) = a_state.handle_response(&q2_to_a.to_bytes()).unwrap();
    let a_offer = EncounterOfferV1::from_bytes(&q1.to_bytes()).unwrap();
    let reused = EncounterOfferV1 {
        alice_ed25519_pk: m_sk.verifying_key().to_bytes(),
        ..a_offer
    }
    .to_bytes();
    let (bs, _q2) = Responder::handle_offer(b_sk.clone(), &reused, &mut r).unwrap();
    let e = bs.handle_reveal(&q3_a.to_bytes()).err();
    check!(e == Some(EncounterError::InvalidSignature), "T4: got {e:?}");

    // T5: Mallory answers Alice twice (second QR2 after QR3 was shown) -> the machine aborts
    let mut am = InitiatorMachine::new();
    let o = am.start(a_sk.clone(), &mut r).unwrap();
    let mut m1 = ResponderMachine::new();
    let first = m1.on_offer(m_sk.clone(), &o, &mut r).unwrap();
    am.on_response(&first).unwrap();
    let mut m2 = ResponderMachine::new();
    let second = m2.on_offer(m_sk.clone(), &o, &mut r).unwrap();
    check!(
        am.on_response(&second) == Err(EncounterError::SessionMismatch),
        "T5: second QR2 accepted"
    );
    Ok("relayed response to a different offer, commitment-mismatched reveal, forwarded QR3, commitment reuse under another key and a second QR2 after reveal are each rejected with the specific error".into())
}

pub use crate::ui_text::PROXIMITY_DISCLAIMER;

#[allow(dead_code)]
fn _unused(r: &mut impl RngCore) -> u64 {
    r.next_u64()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(f: fn() -> VResult) {
        if let Err(e) = f() {
            panic!("{e}");
        }
    }

    #[test]
    fn vector_1_happy_path() {
        run(v1_happy_path_and_continuity)
    }
    #[test]
    fn vector_2_replay() {
        run(v2_replay)
    }
    #[test]
    fn vector_3_tamper_and_mitm() {
        run(v3_tamper_and_mitm)
    }
    #[test]
    fn vector_4_unknown_key_share() {
        run(v4_unknown_key_share)
    }
    #[test]
    fn vector_5_malformed_and_weak() {
        run(v5_malformed_and_weak)
    }
    #[test]
    fn vector_6_relay_limitation() {
        run(v6_relay_limitation)
    }
    #[test]
    fn vector_7_transport_equivalence() {
        run(v7_transport_equivalence)
    }
    #[test]
    fn vector_8_trust_boundaries() {
        run(v8_trust_boundaries)
    }
    #[test]
    fn vector_9_state_and_retry() {
        run(v9_state_and_retry)
    }
    #[test]
    fn vector_10_self_reflection() {
        run(v10_self_reflection)
    }
    #[test]
    fn vector_11_conformance_and_roles() {
        run(v11_conformance_and_roles)
    }
    #[test]
    fn vector_12_state_machines() {
        run(v12_state_machines)
    }
    #[test]
    fn vector_13_zeroize_alias_ui() {
        run(v13_zeroize_alias_ui)
    }
    #[test]
    fn vector_14_sas_attack_traces() {
        run(v14_sas_attack_traces)
    }

    /// Regression pin, not independent evidence: fixed seed gives fixed transcript and SAS. A change here means
    /// the wire format or derivation changed. Depends on `StdRng` (ChaCha12) as pinned by Cargo.lock.
    #[test]
    fn regression_pin_seed_1() {
        let s = session(1);
        eprintln!(
            "PIN sas={:06} transcript={:02x?}",
            s.alice.sas_code(),
            s.alice.transcript()
        );
        assert_eq!(s.alice.sas_code(), s.bob.sas_code());
        assert_eq!(s.alice.sas_code(), 839_463);
        assert_eq!(&s.alice.transcript()[..4], &[0x73, 0x21, 0x6f, 0x21]);
    }
}
