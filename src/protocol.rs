//! Encounter Core Cryptographic State Machine.
//!
//! Transport-agnostic offline two-device peer introduction protocol using:
//! - Ed25519 device identity keys (RFC 8032)
//! - X25519 ephemeral key agreement (RFC 7748)
//! - SHA-256 commitment and transcript hashing (FIPS 180-4)
//! - HKDF-SHA256 short authentication string (SAS) derivation (RFC 5869)
//! - Deterministic CBOR tuple framing (`cbor_det`) via `cbor2`

use crate::cbor::cbor_det_bytes;
use cbor2::Value;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519Secret};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const PROTO_V1: &str = "mesh.encounter.v1";

/// Maximum accepted frame size in bytes.
pub const MAX_FRAME_BYTES: usize = 512;

/// Serde adapter: fixed-size byte arrays are CBOR byte strings of exactly `N` bytes.
pub mod fixed_bytes {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor<const N: usize>;
        impl<'de, const N: usize> serde::de::Visitor<'de> for Visitor<N> {
            type Value = [u8; N];
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a byte string of exactly {} bytes", N)
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                <[u8; N]>::try_from(v).map_err(|_| E::invalid_length(v.len(), &self))
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
                self.visit_bytes(&v)
            }
        }
        deserializer.deserialize_bytes(Visitor::<N>)
    }
}

/// Decode a closed-schema frame and require that it is byte-for-byte the canonical encoding
/// this crate would produce. This rejects trailing data, unknown fields, reordered maps,
/// indefinite-length items and non-minimal integer/length encodings, plus oversize frames.
fn decode_canonical<T>(bytes: &[u8], what: &str) -> Result<T, EncounterError>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    if bytes.len() > MAX_FRAME_BYTES {
        return Err(EncounterError::MalformedPayload(format!(
            "{what} exceeds {MAX_FRAME_BYTES} bytes"
        )));
    }
    let value: T = cbor2::from_slice(bytes)
        .map_err(|e| EncounterError::MalformedPayload(format!("{what} CBOR decode failed: {e}")))?;
    let again = cbor2::to_vec(&value).map_err(|e| {
        EncounterError::MalformedPayload(format!("{what} CBOR re-encode failed: {e}"))
    })?;
    if again != bytes {
        return Err(EncounterError::MalformedPayload(format!(
            "{what} is not canonical"
        )));
    }
    Ok(value)
}

fn parse_peer_identity(pk: &[u8; 32]) -> Result<VerifyingKey, EncounterError> {
    let vk = VerifyingKey::from_bytes(pk).map_err(|_| EncounterError::InvalidSignature)?;
    if vk.is_weak() {
        return Err(EncounterError::WeakKey);
    }
    Ok(vk)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncounterRole {
    Initiator,
    Responder,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum EncounterError {
    SelfReflectionRejected,
    InvalidDiffieHellman,
    InvalidCommitment,
    InvalidSignature,
    WeakKey,
    SasMismatch,
    SessionMismatch,
    /// A frame arrived that this state does not accept.
    OutOfOrder,
    /// The session already ended (confirmed, aborted or timed out).
    SessionClosed,
    MalformedPayload(String),
    ProtocolDowngrade,
}

impl std::fmt::Display for EncounterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for EncounterError {}

// ----------------- Wire Message Types -----------------

// Field order is the RFC 8949 section 4.2.1 map-key order (shorter encoded key first, then bytewise),
// so serde's declaration-order output is the deterministic encoding.

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncounterOfferV1 {
    pub role: String,
    pub proto: String,
    #[serde(with = "fixed_bytes")]
    pub commit_a: [u8; 32],
    #[serde(with = "fixed_bytes")]
    pub alice_ed25519_pk: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncounterResponseV1 {
    pub role: String,
    pub proto: String,
    #[serde(with = "fixed_bytes")]
    pub sig_b: [u8; 64],
    #[serde(with = "fixed_bytes")]
    pub nonce_b: [u8; 16],
    #[serde(with = "fixed_bytes")]
    pub offer_digest: [u8; 32],
    #[serde(with = "fixed_bytes")]
    pub bob_ed25519_pk: [u8; 32],
    #[serde(with = "fixed_bytes")]
    pub bob_x25519_epk: [u8; 32],
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncounterRevealV1 {
    pub role: String,
    pub proto: String,
    #[serde(with = "fixed_bytes")]
    pub sig_a: [u8; 64],
    #[serde(with = "fixed_bytes")]
    pub nonce_a: [u8; 16],
    #[serde(with = "fixed_bytes")]
    pub alice_x25519_epk: [u8; 32],
}

// ----------------- Serialization Helpers -----------------

impl EncounterOfferV1 {
    pub fn to_bytes(&self) -> Vec<u8> {
        cbor2::to_vec(self).expect("cbor serialization cannot fail")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncounterError> {
        let offer: Self = decode_canonical(bytes, "Offer")?;
        if offer.proto != PROTO_V1 {
            return Err(EncounterError::ProtocolDowngrade);
        }
        if offer.role != "offer" {
            return Err(EncounterError::MalformedPayload(
                "Invalid offer role".to_string(),
            ));
        }
        Ok(offer)
    }
}

impl EncounterResponseV1 {
    pub fn to_bytes(&self) -> Vec<u8> {
        cbor2::to_vec(self).expect("cbor serialization cannot fail")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncounterError> {
        let resp: Self = decode_canonical(bytes, "Response")?;
        if resp.proto != PROTO_V1 {
            return Err(EncounterError::ProtocolDowngrade);
        }
        if resp.role != "response" {
            return Err(EncounterError::MalformedPayload(
                "Invalid response role".to_string(),
            ));
        }
        Ok(resp)
    }
}

impl EncounterRevealV1 {
    pub fn to_bytes(&self) -> Vec<u8> {
        cbor2::to_vec(self).expect("cbor serialization cannot fail")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, EncounterError> {
        let rev: Self = decode_canonical(bytes, "Reveal")?;
        if rev.proto != PROTO_V1 {
            return Err(EncounterError::ProtocolDowngrade);
        }
        if rev.role != "reveal" {
            return Err(EncounterError::MalformedPayload(
                "Invalid reveal role".to_string(),
            ));
        }
        Ok(rev)
    }
}

// ----------------- State Machine Contexts -----------------

/// Secret-bearing session state. Normal drop wipes the nonce,
/// the offer copy and, through their own `Drop`, the signing key and ephemeral secret.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct InitiatorWaitingForResponse {
    #[zeroize(skip)]
    alice_signing_key: SigningKey,
    #[zeroize(skip)]
    alice_x25519_secret: X25519Secret,
    alice_x25519_epk: [u8; 32],
    nonce_a: [u8; 16],
    offer_bytes: Vec<u8>,
}

impl InitiatorWaitingForResponse {
    #[cfg(feature = "test-support")]
    #[allow(dead_code)]
    pub(crate) fn campaign_opening(&self) -> ([u8; 32], [u8; 16]) {
        (self.alice_x25519_epk, self.nonce_a)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn opening_buffers_cleared(&self) -> bool {
        self.nonce_a == [0; 16] && self.alice_x25519_epk == [0; 32] && self.offer_bytes.is_empty()
    }
}
impl std::fmt::Debug for InitiatorWaitingForResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitiatorWaitingForResponse")
            .finish_non_exhaustive()
    }
}

/// Alice has verified QR2 and shown QR3; the user must now compare the SAS.
/// Fields are private so that a confirmed-encounter value can only come from the protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitiatorAwaitingConfirmation {
    local_identity_pk: [u8; 32],
    peer_ed25519_pk: [u8; 32],
    sas_code: u32,
    transcript: [u8; 32],
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ResponderAwaitingReveal {
    #[zeroize(skip)]
    bob_signing_key: SigningKey,
    #[zeroize(skip)]
    bob_x25519_secret: X25519Secret,
    bob_x25519_epk: [u8; 32],
    nonce_b: [u8; 16],
    peer_ed25519_pk: [u8; 32],
    offer_commit_a: [u8; 32],
    offer_bytes: Vec<u8>,
    response_bytes: Vec<u8>,
}

impl ResponderAwaitingReveal {
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn transcript_buffers_cleared(&self) -> bool {
        self.nonce_b == [0; 16]
            && self.response_bytes.is_empty()
            && self.offer_bytes.is_empty()
            && self.peer_ed25519_pk == [0; 32]
    }
}
impl std::fmt::Debug for ResponderAwaitingReveal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponderAwaitingReveal")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponderAwaitingConfirmation {
    local_identity_pk: [u8; 32],
    peer_ed25519_pk: [u8; 32],
    sas_code: u32,
    transcript: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitiatorConfirmed {
    local_identity_pk: [u8; 32],
    peer_ed25519_pk: [u8; 32],
    transcript: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResponderConfirmed {
    local_identity_pk: [u8; 32],
    peer_ed25519_pk: [u8; 32],
    transcript: [u8; 32],
}

mod sealed {
    pub trait Sealed {}
}

/// A confirmation issued by the protocol for a specific local identity.
///
/// ```compile_fail
/// use mesh_identity::protocol::ConfirmedEncounter;
/// struct Fake;
/// impl ConfirmedEncounter for Fake {
///     fn local_identity_pk(&self) -> [u8; 32] { [0; 32] }
///     fn peer_ed25519_pk(&self) -> [u8; 32] { [0; 32] }
///     fn transcript(&self) -> [u8; 32] { [0; 32] }
/// }
/// ```
pub trait ConfirmedEncounter: sealed::Sealed {
    fn local_identity_pk(&self) -> [u8; 32];
    fn peer_ed25519_pk(&self) -> [u8; 32];
    fn transcript(&self) -> [u8; 32];
}

macro_rules! awaiting_confirmation {
    ($awaiting:ident, $confirmed:ident) => {
        impl $awaiting {
            pub fn peer_ed25519_pk(&self) -> [u8; 32] {
                self.peer_ed25519_pk
            }
            pub fn transcript(&self) -> [u8; 32] {
                self.transcript
            }
            /// The six-digit code to display to the user.
            pub fn sas_code(&self) -> u32 {
                self.sas_code
            }
            /// The user reports the code shown on the other device. A mismatch aborts.
            pub fn confirm(self, code_seen_on_peer: u32) -> Result<$confirmed, EncounterError> {
                if code_seen_on_peer != self.sas_code {
                    return Err(EncounterError::SasMismatch);
                }
                Ok($confirmed {
                    local_identity_pk: self.local_identity_pk,
                    peer_ed25519_pk: self.peer_ed25519_pk,
                    transcript: self.transcript,
                })
            }
        }
        impl sealed::Sealed for $confirmed {}
        impl ConfirmedEncounter for $confirmed {
            fn local_identity_pk(&self) -> [u8; 32] {
                self.local_identity_pk
            }
            fn peer_ed25519_pk(&self) -> [u8; 32] {
                self.peer_ed25519_pk
            }
            fn transcript(&self) -> [u8; 32] {
                self.transcript
            }
        }
    };
}
awaiting_confirmation!(InitiatorAwaitingConfirmation, InitiatorConfirmed);
awaiting_confirmation!(ResponderAwaitingConfirmation, ResponderConfirmed);

// ----------------- Initiator (Alice) Implementation -----------------

pub struct Initiator;

impl Initiator {
    /// Step 1: Alice initiates the encounter, creates ephemeral key, nonce, and hash commitment.
    pub fn start<R: CryptoRng + RngCore>(
        alice_signing_key: SigningKey,
        rng: &mut R,
    ) -> (InitiatorWaitingForResponse, EncounterOfferV1) {
        let alice_x25519_secret = X25519Secret::random_from_rng(&mut *rng);
        let alice_x25519_epk = *X25519PublicKey::from(&alice_x25519_secret).as_bytes();

        let mut nonce_a = [0u8; 16];
        rng.fill_bytes(&mut nonce_a);

        // commit_a = SHA-256(cbor_det(["mesh.encounter.v1.commit", alice_x25519_epk, nonce_a]))
        let commit_items = vec![
            Value::Text("mesh.encounter.v1.commit".to_string()),
            Value::Bytes(alice_x25519_epk.to_vec()),
            Value::Bytes(nonce_a.to_vec()),
        ];
        let commit_payload = cbor_det_bytes(commit_items);
        let mut hasher = Sha256::new();
        hasher.update(&commit_payload);
        let commit_a: [u8; 32] = hasher.finalize().into();

        let offer = EncounterOfferV1 {
            proto: PROTO_V1.to_string(),
            role: "offer".to_string(),
            alice_ed25519_pk: alice_signing_key.verifying_key().to_bytes(),
            commit_a,
        };
        let offer_bytes = offer.to_bytes();

        let state = InitiatorWaitingForResponse {
            alice_signing_key,
            alice_x25519_secret,
            alice_x25519_epk,
            nonce_a,
            offer_bytes,
        };

        (state, offer)
    }
}

impl InitiatorWaitingForResponse {
    /// Step 3: Alice processes Bob's response (QR2), checks signatures, computes SAS, and reveals commitment (QR3).
    /// Consumes the state whether or not it succeeds, so no caller can obtain two reveals for one commitment.
    pub fn handle_response(
        self,
        resp_bytes: &[u8],
    ) -> Result<(InitiatorAwaitingConfirmation, EncounterRevealV1), EncounterError> {
        self.process_response(resp_bytes)
    }

    /// Like `handle_response`, but a frame that fails a check hands the untouched state back so the
    /// caller may try a different QR2. This is safe because a failure emits nothing (no QR3), so no
    /// guess is given away; a success consumes the state exactly as `handle_response` does.
    #[allow(clippy::result_large_err)]
    pub fn try_handle_response(
        self,
        resp_bytes: &[u8],
    ) -> Result<(InitiatorAwaitingConfirmation, EncounterRevealV1), (Self, EncounterError)> {
        match self.process_response(resp_bytes) {
            Ok(done) => Ok(done),
            Err(e) => Err((self, e)),
        }
    }

    fn process_response(
        &self,
        resp_bytes: &[u8],
    ) -> Result<(InitiatorAwaitingConfirmation, EncounterRevealV1), EncounterError> {
        let resp = EncounterResponseV1::from_bytes(resp_bytes)?;

        // Self-reflection guard: Alice must reject Bob if Bob's key equals Alice's key
        let own_ed25519_pk = self.alice_signing_key.verifying_key().to_bytes();
        if resp.bob_ed25519_pk == own_ed25519_pk {
            return Err(EncounterError::SelfReflectionRejected);
        }
        if resp.bob_x25519_epk == self.alice_x25519_epk {
            return Err(EncounterError::SelfReflectionRejected);
        }

        // Verify offer digest: offer_digest == SHA-256(cbor_det(["mesh.encounter.v1.offer", QR1_bytes]))
        let offer_items = vec![
            Value::Text("mesh.encounter.v1.offer".to_string()),
            Value::Bytes(self.offer_bytes.clone()),
        ];
        let expected_offer_digest: [u8; 32] = Sha256::digest(cbor_det_bytes(offer_items)).into();
        if resp.offer_digest != expected_offer_digest {
            return Err(EncounterError::SessionMismatch);
        }

        // Verify Bob's Ed25519 signature:
        // sig_b over cbor_det(["mesh.encounter.v1.resp", proto, offer_digest, alice_ed25519_pk, bob_ed25519_pk, bob_x25519_epk, nonce_b])
        let resp_sig_items = vec![
            Value::Text("mesh.encounter.v1.resp".to_string()),
            Value::Text(PROTO_V1.to_string()),
            Value::Bytes(resp.offer_digest.to_vec()),
            Value::Bytes(own_ed25519_pk.to_vec()),
            Value::Bytes(resp.bob_ed25519_pk.to_vec()),
            Value::Bytes(resp.bob_x25519_epk.to_vec()),
            Value::Bytes(resp.nonce_b.to_vec()),
        ];
        let resp_sig_payload = cbor_det_bytes(resp_sig_items);

        let bob_vk = parse_peer_identity(&resp.bob_ed25519_pk)?;
        let signature_b = Signature::from_bytes(&resp.sig_b);
        bob_vk
            .verify_strict(&resp_sig_payload, &signature_b)
            .map_err(|_| EncounterError::InvalidSignature)?;

        // Diffie-Hellman Key Agreement: X25519(alice_x25519_secret, bob_x25519_epk)
        let bob_epk = X25519PublicKey::from(resp.bob_x25519_epk);
        let shared_secret = self.alice_x25519_secret.diffie_hellman(&bob_epk);
        if !shared_secret.was_contributory() {
            return Err(EncounterError::InvalidDiffieHellman);
        }

        // Transcript: SHA-256(cbor_det(["mesh.encounter.v1.transcript", QR1_bytes, QR2_bytes, alice_x25519_epk, nonce_a]))
        let transcript_items = vec![
            Value::Text("mesh.encounter.v1.transcript".to_string()),
            Value::Bytes(self.offer_bytes.clone()),
            Value::Bytes(resp_bytes.to_vec()),
            Value::Bytes(self.alice_x25519_epk.to_vec()),
            Value::Bytes(self.nonce_a.to_vec()),
        ];
        let transcript_payload = cbor_det_bytes(transcript_items);
        let transcript: [u8; 32] = Sha256::digest(transcript_payload).into();

        // Sign transcript: sig_a = Ed25519_Sign(alice_sk, cbor_det(["mesh.encounter.v1.reveal", transcript]))
        let reveal_sig_items = vec![
            Value::Text("mesh.encounter.v1.reveal".to_string()),
            Value::Bytes(transcript.to_vec()),
        ];
        let reveal_sig_payload = cbor_det_bytes(reveal_sig_items);
        let sig_a = self.alice_signing_key.sign(&reveal_sig_payload);

        let reveal = EncounterRevealV1 {
            proto: PROTO_V1.to_string(),
            role: "reveal".to_string(),
            alice_x25519_epk: self.alice_x25519_epk,
            nonce_a: self.nonce_a,
            sig_a: sig_a.to_bytes(),
        };

        // SAS Derivation: HKDF-SHA256(ikm = shared_secret, salt = transcript, info = "mesh.encounter.v1.sas", length = 4)
        let sas_code = derive_sas_code(shared_secret.as_bytes(), &transcript);

        let confirm_state = InitiatorAwaitingConfirmation {
            local_identity_pk: own_ed25519_pk,
            peer_ed25519_pk: resp.bob_ed25519_pk,
            sas_code,
            transcript,
        };

        Ok((confirm_state, reveal))
    }
}

// ----------------- Responder (Bob) Implementation -----------------

pub struct Responder;

impl Responder {
    /// Step 2: Bob processes Alice's offer (QR1), generates ephemeral key and fresh nonce, signs offer digest, and returns response (QR2).
    pub fn handle_offer<R: CryptoRng + RngCore>(
        bob_signing_key: SigningKey,
        offer_bytes: &[u8],
        rng: &mut R,
    ) -> Result<(ResponderAwaitingReveal, EncounterResponseV1), EncounterError> {
        let offer = EncounterOfferV1::from_bytes(offer_bytes)?;

        // Self-reflection guard: Bob must reject Alice if Alice's key equals Bob's key
        let bob_ed25519_pk = bob_signing_key.verifying_key().to_bytes();
        if offer.alice_ed25519_pk == bob_ed25519_pk {
            return Err(EncounterError::SelfReflectionRejected);
        }

        parse_peer_identity(&offer.alice_ed25519_pk)?;

        let bob_x25519_secret = X25519Secret::random_from_rng(&mut *rng);
        let bob_x25519_epk = *X25519PublicKey::from(&bob_x25519_secret).as_bytes();

        let mut nonce_b = [0u8; 16];
        rng.fill_bytes(&mut nonce_b);

        // offer_digest = SHA-256(cbor_det(["mesh.encounter.v1.offer", QR1_bytes]))
        let offer_items = vec![
            Value::Text("mesh.encounter.v1.offer".to_string()),
            Value::Bytes(offer_bytes.to_vec()),
        ];
        let offer_digest: [u8; 32] = Sha256::digest(cbor_det_bytes(offer_items)).into();

        // sig_b = Ed25519_Sign(bob_sk, cbor_det(["mesh.encounter.v1.resp", proto, offer_digest, alice_ed25519_pk, bob_ed25519_pk, bob_x25519_epk, nonce_b]))
        let resp_sig_items = vec![
            Value::Text("mesh.encounter.v1.resp".to_string()),
            Value::Text(PROTO_V1.to_string()),
            Value::Bytes(offer_digest.to_vec()),
            Value::Bytes(offer.alice_ed25519_pk.to_vec()),
            Value::Bytes(bob_ed25519_pk.to_vec()),
            Value::Bytes(bob_x25519_epk.to_vec()),
            Value::Bytes(nonce_b.to_vec()),
        ];
        let resp_sig_payload = cbor_det_bytes(resp_sig_items);
        let sig_b = bob_signing_key.sign(&resp_sig_payload);

        let response = EncounterResponseV1 {
            proto: PROTO_V1.to_string(),
            role: "response".to_string(),
            bob_ed25519_pk,
            bob_x25519_epk,
            nonce_b,
            offer_digest,
            sig_b: sig_b.to_bytes(),
        };

        let response_bytes = response.to_bytes();

        let state = ResponderAwaitingReveal {
            bob_signing_key,
            bob_x25519_secret,
            bob_x25519_epk,
            nonce_b,
            peer_ed25519_pk: offer.alice_ed25519_pk,
            offer_commit_a: offer.commit_a,
            offer_bytes: offer_bytes.to_vec(),
            response_bytes,
        };

        Ok((state, response))
    }
}

impl ResponderAwaitingReveal {
    /// Step 4: Bob processes Alice's reveal (QR3), verifies commitment and signature, computes shared secret, and derives SAS.
    pub fn handle_reveal(
        self,
        reveal_bytes: &[u8],
    ) -> Result<ResponderAwaitingConfirmation, EncounterError> {
        self.process_reveal(reveal_bytes)
    }

    /// Like `handle_reveal`, but a failed check hands the untouched state back (nothing was emitted).
    #[allow(clippy::result_large_err)]
    pub fn try_handle_reveal(
        self,
        reveal_bytes: &[u8],
    ) -> Result<ResponderAwaitingConfirmation, (Self, EncounterError)> {
        match self.process_reveal(reveal_bytes) {
            Ok(done) => Ok(done),
            Err(e) => Err((self, e)),
        }
    }

    fn process_reveal(
        &self,
        reveal_bytes: &[u8],
    ) -> Result<ResponderAwaitingConfirmation, EncounterError> {
        let rev = EncounterRevealV1::from_bytes(reveal_bytes)?;

        // Self-reflection check
        if rev.alice_x25519_epk == self.bob_x25519_epk {
            return Err(EncounterError::SelfReflectionRejected);
        }

        // Verify commitment: commit_a == SHA-256(cbor_det(["mesh.encounter.v1.commit", alice_x25519_epk, nonce_a]))
        let commit_items = vec![
            Value::Text("mesh.encounter.v1.commit".to_string()),
            Value::Bytes(rev.alice_x25519_epk.to_vec()),
            Value::Bytes(rev.nonce_a.to_vec()),
        ];
        let expected_commit_a: [u8; 32] = Sha256::digest(cbor_det_bytes(commit_items)).into();
        if expected_commit_a != self.offer_commit_a {
            return Err(EncounterError::InvalidCommitment);
        }

        // Transcript: SHA-256(cbor_det(["mesh.encounter.v1.transcript", QR1_bytes, QR2_bytes, alice_x25519_epk, nonce_a]))
        let transcript_items = vec![
            Value::Text("mesh.encounter.v1.transcript".to_string()),
            Value::Bytes(self.offer_bytes.clone()),
            Value::Bytes(self.response_bytes.clone()),
            Value::Bytes(rev.alice_x25519_epk.to_vec()),
            Value::Bytes(rev.nonce_a.to_vec()),
        ];
        let transcript: [u8; 32] = Sha256::digest(cbor_det_bytes(transcript_items)).into();

        // Verify Alice's signature: sig_a over cbor_det(["mesh.encounter.v1.reveal", transcript])
        let reveal_sig_items = vec![
            Value::Text("mesh.encounter.v1.reveal".to_string()),
            Value::Bytes(transcript.to_vec()),
        ];
        let reveal_sig_payload = cbor_det_bytes(reveal_sig_items);

        let alice_vk = parse_peer_identity(&self.peer_ed25519_pk)?;
        let signature_a = Signature::from_bytes(&rev.sig_a);
        alice_vk
            .verify_strict(&reveal_sig_payload, &signature_a)
            .map_err(|_| EncounterError::InvalidSignature)?;

        // Diffie-Hellman Key Agreement: X25519(bob_x25519_secret, alice_x25519_epk)
        let alice_epk = X25519PublicKey::from(rev.alice_x25519_epk);
        let shared_secret = self.bob_x25519_secret.diffie_hellman(&alice_epk);
        if !shared_secret.was_contributory() {
            return Err(EncounterError::InvalidDiffieHellman);
        }

        // SAS Derivation: HKDF-SHA256
        let sas_code = derive_sas_code(shared_secret.as_bytes(), &transcript);

        Ok(ResponderAwaitingConfirmation {
            local_identity_pk: self.bob_signing_key.verifying_key().to_bytes(),
            peer_ed25519_pk: self.peer_ed25519_pk,
            sas_code,
            transcript,
        })
    }
}

/// Computes the 6-digit SAS code according to Section 3.2:
/// `sas_key = HKDF-SHA256(ikm = shared_secret, salt = transcript, info = "mesh.encounter.v1.sas", length = 4)`
/// `sas_code = big_endian_u32(sas_key) mod 1_000_000`
pub fn derive_sas_code(shared_secret: &[u8; 32], transcript: &[u8; 32]) -> u32 {
    #[cfg(feature = "test-support")]
    {
        let m = campaign::sas_modulus();
        if m != PRODUCTION_SAS_MODULUS {
            // Reduced SAS space for statistical power in the grinding campaign. Visibly domain-separated.
            let hk = Hkdf::<Sha256>::new(Some(transcript), shared_secret);
            let mut okm = [0u8; 4];
            hk.expand(b"mesh.encounter.v1.sas.TESTONLY-REDUCED", &mut okm)
                .expect("4 bytes is valid HKDF length");
            return u32::from_be_bytes(okm) % m;
        }
    }
    let hk = Hkdf::<Sha256>::new(Some(transcript), shared_secret);
    let mut okm = [0u8; 4];
    hk.expand(b"mesh.encounter.v1.sas", &mut okm)
        .expect("4 bytes is valid HKDF length");
    let val = u32::from_be_bytes(okm);
    val % PRODUCTION_SAS_MODULUS
}

pub const PRODUCTION_SAS_MODULUS: u32 = 1_000_000;

/// Test-only controls. Compiled only with `--features test-support`.
#[cfg(feature = "test-support")]
pub mod campaign {
    use super::PRODUCTION_SAS_MODULUS;
    use std::sync::atomic::{AtomicU32, Ordering};
    static MODULUS: AtomicU32 = AtomicU32::new(PRODUCTION_SAS_MODULUS);
    pub fn sas_modulus() -> u32 {
        MODULUS.load(Ordering::SeqCst)
    }
    /// Set a reduced SAS space (process-wide). Pass `PRODUCTION_SAS_MODULUS` to restore production behaviour.
    pub fn set_sas_modulus(m: u32) {
        MODULUS.store(m, Ordering::SeqCst);
    }
}
