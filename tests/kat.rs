//! Known-answer tests for Encounter protocol.
//!
//! Verifies that `mesh-identity` reproduces every frame, the transcript,
//! the shared secret's SAS and signatures byte-for-byte against the independent
//! Python implementation vectors and published RFC primitive vectors.

use ed25519_dalek::{Signer, SigningKey};
use hex_literal::hex;
use mesh_identity::protocol::*;
use rand::{CryptoRng, RngCore};
use std::collections::VecDeque;

/// Yields a predetermined byte stream; panics if the protocol draws more than expected.
struct FixedRng(VecDeque<u8>);
impl RngCore for FixedRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for d in dest {
            *d = self
                .0
                .pop_front()
                .expect("protocol drew more randomness than the vector provides");
        }
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl CryptoRng for FixedRng {}

fn h(v: &serde_json::Value) -> Vec<u8> {
    let s = v.as_str().expect("hex string");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[test]
fn rfc_primitive_vectors() {
    use sha2::{Digest, Sha256};
    // FIPS 180-4 "abc"
    assert_eq!(
        Sha256::digest(b"abc")[..],
        hex!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    // RFC 5869 test case 1
    let hk = hkdf::Hkdf::<Sha256>::new(Some(&hex!("000102030405060708090a0b0c")), &[0x0b; 22]);
    let mut okm = [0u8; 42];
    hk.expand(&hex!("f0f1f2f3f4f5f6f7f8f9"), &mut okm).unwrap();
    assert_eq!(
        okm,
        hex!(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        )
    );
    // RFC 7748 section 6.1
    use x25519_dalek::{PublicKey, StaticSecret};
    let a = StaticSecret::from(hex!(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    ));
    let b = StaticSecret::from(hex!(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    ));
    assert_eq!(
        PublicKey::from(&a).to_bytes(),
        hex!("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    assert_eq!(
        a.diffie_hellman(&PublicKey::from(&b)).to_bytes(),
        hex!("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
    );
    // RFC 8032 test 1 (empty message)
    let sk = SigningKey::from_bytes(&hex!(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    ));
    assert_eq!(
        sk.verifying_key().to_bytes(),
        hex!("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );
    assert_eq!(
        sk.sign(b"").to_bytes(),
        hex!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
    );
}

#[test]
fn python_reference_vectors() {
    let doc: serde_json::Value =
        serde_json::from_str(include_str!("../kat/encounter-v1-kat.json")).unwrap();
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 3);
    for c in cases {
        let name = c["name"].as_str().unwrap();
        let i = &c["inputs"];
        let o = &c["outputs"];
        let seed = |k: &str| -> [u8; 32] { h(&i[k]).try_into().unwrap() };
        let a_sk = SigningKey::from_bytes(&seed("alice_ed25519_seed"));
        let b_sk = SigningKey::from_bytes(&seed("bob_ed25519_seed"));
        // draw order in the crate: ephemeral X25519 secret (32 bytes) then nonce (16 bytes)
        let mut a_rng = FixedRng(
            h(&i["alice_x25519_secret"])
                .into_iter()
                .chain(h(&i["nonce_a"]))
                .collect(),
        );
        let mut b_rng = FixedRng(
            h(&i["bob_x25519_secret"])
                .into_iter()
                .chain(h(&i["nonce_b"]))
                .collect(),
        );

        let (ai, offer) = Initiator::start(a_sk, &mut a_rng);
        assert_eq!(
            offer.to_bytes(),
            h(&o["qr1"]),
            "{name}: QR1 differs from the independent reference"
        );
        let (bs, resp) = Responder::handle_offer(b_sk, &offer.to_bytes(), &mut b_rng).unwrap();
        assert_eq!(
            resp.to_bytes(),
            h(&o["qr2"]),
            "{name}: QR2 differs from the independent reference"
        );
        let (a_conf, reveal) = ai.handle_response(&resp.to_bytes()).unwrap();
        assert_eq!(
            reveal.to_bytes(),
            h(&o["qr3"]),
            "{name}: QR3 differs from the independent reference"
        );
        let b_conf = bs.handle_reveal(&reveal.to_bytes()).unwrap();
        assert_eq!(
            a_conf.transcript().to_vec(),
            h(&o["transcript"]),
            "{name}: transcript"
        );
        assert_eq!(b_conf.transcript(), a_conf.transcript());
        assert_eq!(
            a_conf.sas_code() as u64,
            o["sas"].as_u64().unwrap(),
            "{name}: SAS"
        );
        assert_eq!(b_conf.sas_code(), a_conf.sas_code());
    }
}

#[test]
fn known_answer_frames_reject_trailing_bytes_and_changed_signatures() {
    let doc: serde_json::Value =
        serde_json::from_str(include_str!("../kat/encounter-v1-kat.json")).unwrap();
    for case in doc["cases"].as_array().unwrap() {
        let inputs = &case["inputs"];
        let outputs = &case["outputs"];
        let signing_key =
            |field: &str| SigningKey::from_bytes(&h(&inputs[field]).try_into().unwrap());
        let fixed_rng = |secret: &str, nonce: &str| {
            FixedRng(
                h(&inputs[secret])
                    .into_iter()
                    .chain(h(&inputs[nonce]))
                    .collect(),
            )
        };
        let offer = h(&outputs["qr1"]);
        let response = h(&outputs["qr2"]);
        let reveal = h(&outputs["qr3"]);

        let mut extra = response.clone();
        extra.push(0);
        let (alice, _) = Initiator::start(
            signing_key("alice_ed25519_seed"),
            &mut fixed_rng("alice_x25519_secret", "nonce_a"),
        );
        assert!(matches!(
            alice.handle_response(&extra),
            Err(EncounterError::MalformedPayload(_))
        ));

        let (alice, _) = Initiator::start(
            signing_key("alice_ed25519_seed"),
            &mut fixed_rng("alice_x25519_secret", "nonce_a"),
        );
        let mut changed = EncounterResponseV1::from_bytes(&response).unwrap();
        changed.sig_b[0] ^= 1;
        assert_eq!(
            alice.handle_response(&changed.to_bytes()).err(),
            Some(EncounterError::InvalidSignature)
        );

        let (bob, _) = Responder::handle_offer(
            signing_key("bob_ed25519_seed"),
            &offer,
            &mut fixed_rng("bob_x25519_secret", "nonce_b"),
        )
        .unwrap();
        let mut changed = EncounterRevealV1::from_bytes(&reveal).unwrap();
        changed.sig_a[0] ^= 1;
        assert_eq!(
            bob.handle_reveal(&changed.to_bytes()).err(),
            Some(EncounterError::InvalidSignature)
        );
    }
}

#[test]
fn independent_derivation_leading_zero_sas() {
    // Independently derived test vector from Section 3 specification text
    let alice_sk = SigningKey::from_bytes(&[0x02; 32]);
    let bob_sk = SigningKey::from_bytes(&[0x03; 32]);

    let mut a_rng = FixedRng(vec![0x04; 32].into_iter().chain(vec![0x06; 16]).collect());
    let mut b_rng = FixedRng(vec![0x05; 32].into_iter().chain(vec![0x07; 16]).collect());

    // Step 1: Offer
    let (ai, offer) = Initiator::start(alice_sk, &mut a_rng);
    let expected_qr1 = hex!(
        "a464726f6c65656f666665726570726f746f716d6573682e656e636f756e7465722e763168636f6d6d69745f6158209aa0ce369326e61a484c871243f2ecdf09650e670d6319962a24fa049aef4a0470616c6963655f656432353531395f706b58208139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"
    );
    assert_eq!(
        offer.to_bytes(),
        expected_qr1,
        "QR1 bytes mismatch on independently derived vector"
    );
    assert_eq!(
        offer.commit_a,
        hex!("9aa0ce369326e61a484c871243f2ecdf09650e670d6319962a24fa049aef4a04")
    );

    // Step 2: Response
    let (bs, resp) = Responder::handle_offer(bob_sk, &offer.to_bytes(), &mut b_rng).unwrap();
    let expected_qr2 = hex!(
        "a764726f6c6568726573706f6e73656570726f746f716d6573682e656e636f756e7465722e7631657369675f625840fff70dac4e353f36d12d1204cdc0c39aeda975338dc73398c8599d38cb28dc4c35a3465987bdcbcaa338c539ef109c930406315c019ff2b2c56f1b00ce75c302676e6f6e63655f6250070707070707070707070707070707076c6f666665725f6469676573745820c35e5a607b3a6c86f4908a605cafdfcb1700d7a344eeb51c015de2a8e47ab14b6e626f625f656432353531395f706b5820ed4928c628d1c2c6eae90338905995612959273a5c63f93636c14614ac8737d16e626f625f7832353531395f65706b582050a61409b1ddd0325e9b16b700e719e9772c07000b1bd7786e907c653d20495d"
    );
    assert_eq!(
        resp.to_bytes(),
        expected_qr2,
        "QR2 bytes mismatch on independently derived vector"
    );
    assert_eq!(
        resp.offer_digest,
        hex!("c35e5a607b3a6c86f4908a605cafdfcb1700d7a344eeb51c015de2a8e47ab14b")
    );
    assert_eq!(
        resp.sig_b,
        hex!(
            "fff70dac4e353f36d12d1204cdc0c39aeda975338dc73398c8599d38cb28dc4c35a3465987bdcbcaa338c539ef109c930406315c019ff2b2c56f1b00ce75c302"
        )
    );

    // Step 3: Reveal
    let (a_conf, reveal) = ai.handle_response(&resp.to_bytes()).unwrap();
    let expected_qr3 = hex!(
        "a564726f6c656672657665616c6570726f746f716d6573682e656e636f756e7465722e7631657369675f615840a6fe2ceb645f502936d41db4aaeb64f81260274e68ae726371e0cffb5f2a4425b555da8a1fa19d307b8692af789c1bead85caf4aaf97970096789b154cf7de0e676e6f6e63655f61500606060606060606060606060606060670616c6963655f7832353531395f65706b5820ac01b2209e86354fb853237b5de0f4fab13c7fcbf433a61c019369617fecf10b"
    );
    assert_eq!(
        reveal.to_bytes(),
        expected_qr3,
        "QR3 bytes mismatch on independently derived vector"
    );
    assert_eq!(
        reveal.sig_a,
        hex!(
            "a6fe2ceb645f502936d41db4aaeb64f81260274e68ae726371e0cffb5f2a4425b555da8a1fa19d307b8692af789c1bead85caf4aaf97970096789b154cf7de0e"
        )
    );

    // Step 4: Transcript & SAS (with leading zero!)
    let b_conf = bs.handle_reveal(&reveal.to_bytes()).unwrap();
    let expected_transcript =
        hex!("64d7974255de4b77c3ccebc7af0b2b7b909af7cf930bafda177139b47584d9ca");
    assert_eq!(a_conf.transcript(), expected_transcript);
    assert_eq!(b_conf.transcript(), expected_transcript);

    // SAS numerical value and formatted string with leading zero
    let sas_code = a_conf.sas_code();
    assert_eq!(sas_code, 63451);
    assert_eq!(b_conf.sas_code(), 63451);
    let display_str = format!("{:06}", sas_code);
    assert_eq!(
        display_str, "063451",
        "Displayed SAS must format with leading zero as a 6-digit string"
    );
}
