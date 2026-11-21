//! Import a selected certificate key without attributing any Encounter evidence.

use crate::contact::ContactRecordV1;
use crate::session::installation::{Identity, Installation};
use ed25519_dalek::SigningKey;
use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::packet::SignatureType;
use pgp::types::{Fingerprint, KeyDetails, Tag};
use rand::{CryptoRng, RngCore};
use std::fmt;
use std::time::{Duration, SystemTime};

/// Refuse oversized certificates before parsing: certificates arrive from untrusted peers.
pub const MAX_CERTIFICATE_BYTES: usize = 256 * 1024;

pub(super) fn parse_certificate(bytes: &[u8]) -> Result<SignedPublicKey, ImportError> {
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(ImportError::Certificate(
            "certificate exceeds the size limit".into(),
        ));
    }
    if bytes.starts_with(b"-----BEGIN") || bytes.iter().take(40).any(|&b| b == b'-') {
        if let Ok((cert, _)) = SignedPublicKey::from_armor_single_buf(bytes) {
            return Ok(cert);
        }
    }
    SignedPublicKey::from_bytes(bytes).map_err(|error| ImportError::Certificate(error.into()))
}

pub(super) fn parse_secret_key(bytes: &[u8]) -> Result<SignedSecretKey, ImportError> {
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(ImportError::Certificate(
            "certificate exceeds the size limit".into(),
        ));
    }
    if bytes.starts_with(b"-----BEGIN") || bytes.iter().take(40).any(|&b| b == b'-') {
        if let Ok((key, _)) = SignedSecretKey::from_armor_single_buf(bytes) {
            return Ok(key);
        }
    }
    SignedSecretKey::from_bytes(bytes).map_err(|error| ImportError::Certificate(error.into()))
}

pub(super) fn parse_public_peer(bytes: &[u8]) -> Result<SignedPublicKey, ImportError> {
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(ImportError::Certificate(
            "certificate exceeds the size limit".into(),
        ));
    }
    if parse_secret_key(bytes).is_ok()
        || bytes
            .windows(15)
            .any(|w| w == b"PRIVATE KEY" || w == b"SECRET KEY")
    {
        return Err(ImportError::SecretMaterial);
    }
    parse_certificate(bytes)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Provenance {
    pub primary: Fingerprint,
    pub signing_key: Fingerprint,
    pub user_id: Vec<u8>,
}

/// Import a certificate for the exact key and User ID selected by the caller.
/// The returned provenance records a valid certificate binding, separate from
/// the contact's verification status. Verified revocations in the supplied
/// certificate are remembered even if the selected binding cannot be imported.
pub fn import_peer<'a>(
    installation: &'a mut Installation,
    certificate: &[u8],
    expected: Identity,
    user_id: &[u8],
    time: SystemTime,
    rng: &mut (impl CryptoRng + RngCore),
) -> Result<(&'a ContactRecordV1, Provenance), ImportError> {
    let cert = parse_public_peer(certificate)?;
    super::revocations::remember_certificate_revocations(installation, &cert)?;
    let cert = installation.openpgp_revocations.merge(cert)?;
    validate_binding(&cert, user_id, time)?;

    let primary_matches = matches_public(cert.primary_key.public_params(), &expected);
    let selected_key_fp = if primary_matches {
        if is_key_revoked(&cert, time) || is_primary_key_expired(&cert, time) {
            return Err(ImportError::KeyMismatch);
        }
        cert.primary_key.fingerprint()
    } else {
        let matching_subkey = cert.public_subkeys.iter().find(|sub| {
            matches_public(sub.key.public_params(), &expected) && is_subkey_valid(&cert, sub, time)
        });
        match matching_subkey {
            Some(sub) => sub.key.fingerprint(),
            None => return Err(ImportError::KeyMismatch),
        }
    };

    let provenance = Provenance {
        primary: cert.primary_key.fingerprint(),
        signing_key: selected_key_fp,
        user_id: user_id.to_vec(),
    };
    let local = installation.selected();
    installation
        .openpgp_revocations
        .check_capacity(&provenance.primary)?;
    installation
        .import_peer_key(local, expected, rng)
        .map_err(ImportError::Contact)?;
    installation
        .openpgp_revocations
        .protect(provenance.primary.clone());
    let record = installation
        .contacts(local)
        .and_then(|contacts| contacts.get(&expected))
        .expect("successful import stores the exact contact key");
    Ok((record, provenance))
}

/// Unlock the selected signing key and import it as an owned Mesh identity.
/// Certificate metadata remains separate from Encounter verification. Verified
/// revocations are remembered even when binding validation or unlocking fails.
pub fn import_owned(
    installation: &mut Installation,
    certificate: &[u8],
    expected: Identity,
    user_id: &[u8],
    time: SystemTime,
    passphrase: &[u8],
) -> Result<Provenance, ImportError> {
    if certificate.len() > MAX_CERTIFICATE_BYTES {
        return Err(ImportError::Certificate(
            "certificate exceeds the size limit".into(),
        ));
    }
    let sec_key = match parse_secret_key(certificate) {
        Ok(k) => k,
        Err(_) => {
            if parse_certificate(certificate).is_ok() {
                return Err(ImportError::SecretMissing);
            } else {
                return Err(ImportError::Certificate(
                    "failed to parse secret key".into(),
                ));
            }
        }
    };

    let pub_key = sec_key.to_public_key();
    super::revocations::remember_certificate_revocations(installation, &pub_key)?;
    let pub_key = installation.openpgp_revocations.merge(pub_key)?;
    validate_binding(&pub_key, user_id, time)?;

    let pw = pgp::types::Password::from(passphrase);
    let (signing, provenance) = if matches_public(sec_key.primary_key.public_params(), &expected) {
        if is_key_revoked(&pub_key, time) || is_primary_key_expired(&pub_key, time) {
            return Err(ImportError::KeyMismatch);
        }
        let signing = sec_key
            .primary_key
            .unlock(&pw, |_pub, plain| extract_ed25519_seed(plain))
            .map_err(|_| ImportError::UnlockFailed)?
            .map_err(|_| ImportError::InvalidSecret)?;
        let prov = Provenance {
            primary: pub_key.primary_key.fingerprint(),
            signing_key: pub_key.primary_key.fingerprint(),
            user_id: user_id.to_vec(),
        };
        (signing, prov)
    } else {
        let mut found = None;
        for sub in &sec_key.secret_subkeys {
            if matches_public(sub.key.public_params(), &expected) {
                let pub_sub = pub_key
                    .public_subkeys
                    .iter()
                    .find(|ps| matches_public(ps.key.public_params(), &expected));
                if let Some(pub_sub) = pub_sub {
                    if !is_subkey_valid(&pub_key, pub_sub, time) {
                        return Err(ImportError::KeyMismatch);
                    }
                } else {
                    return Err(ImportError::KeyMismatch);
                }

                let signing = sub
                    .key
                    .unlock(&pw, |_pub, plain| extract_ed25519_seed(plain))
                    .map_err(|_| ImportError::UnlockFailed)?
                    .map_err(|_| ImportError::InvalidSecret)?;
                let prov = Provenance {
                    primary: pub_key.primary_key.fingerprint(),
                    signing_key: sub.key.fingerprint(),
                    user_id: user_id.to_vec(),
                };
                found = Some((signing, prov));
                break;
            }
        }
        found.ok_or(ImportError::KeyMismatch)?
    };

    installation
        .openpgp_revocations
        .check_capacity(&provenance.primary)?;
    installation
        .import_identity(signing, expected)
        .map_err(ImportError::Contact)?;
    installation
        .openpgp_revocations
        .protect(provenance.primary.clone());
    Ok(provenance)
}

pub fn validate_binding(
    cert: &SignedPublicKey,
    user_id: &[u8],
    time: SystemTime,
) -> Result<(), ImportError> {
    if is_key_revoked(cert, time) {
        return Err(ImportError::InvalidBinding);
    }
    if is_primary_key_expired(cert, time) {
        return Err(ImportError::InvalidBinding);
    }
    let user_valid = cert
        .details
        .users
        .iter()
        .any(|user| is_user_id_valid(cert, user, user_id, time));

    if !user_valid {
        return Err(ImportError::InvalidBinding);
    }

    Ok(())
}

fn matches_public(pub_params: &pgp::types::PublicParams, expected: &[u8; 32]) -> bool {
    match pub_params {
        pgp::types::PublicParams::EdDSALegacy(pgp::types::EddsaLegacyPublicParams::Ed25519 {
            key,
        }) => key.as_bytes() == expected,
        pgp::types::PublicParams::Ed25519(pgp::types::Ed25519PublicParams { key }) => {
            key.as_bytes() == expected
        }
        _ => false,
    }
}

fn extract_ed25519_seed(
    plain: &pgp::types::PlainSecretParams,
) -> Result<SigningKey, pgp::errors::Error> {
    let mut seed = [0u8; 32];
    match plain {
        pgp::types::PlainSecretParams::Ed25519(sec) => {
            seed.copy_from_slice(sec.as_bytes());
        }
        pgp::types::PlainSecretParams::EdDSALegacy(sec) => match sec {
            pgp::crypto::eddsa_legacy::SecretKey::Ed25519(sec) => {
                seed.copy_from_slice(sec.as_bytes());
            }
            pgp::crypto::eddsa_legacy::SecretKey::Unsupported { opaque, .. } => {
                let val = opaque.as_ref();
                if val.len() <= 32 {
                    seed[32 - val.len()..].copy_from_slice(val);
                } else if val.len() == 33 && val[0] == 0 {
                    seed.copy_from_slice(&val[1..]);
                } else {
                    return Err("invalid secret key length".to_string().into());
                }
            }
        },
        _ => return Err("unsupported secret key algorithm".to_string().into()),
    }
    Ok(SigningKey::from_bytes(&seed))
}

fn is_key_revoked(cert: &SignedPublicKey, time: SystemTime) -> bool {
    cert.details.revocation_signatures.iter().any(|sig| {
        if sig.typ() != Some(SignatureType::KeyRevocation) {
            return false;
        }
        if sig.verify_key(&cert.primary_key).is_err() {
            return false;
        }
        if let Some(created) = sig.created() {
            let sig_time =
                SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(created.as_secs()));
            sig_time <= time
        } else {
            true
        }
    })
}

fn is_primary_key_expired(cert: &SignedPublicKey, time: SystemTime) -> bool {
    let key_created = SystemTime::UNIX_EPOCH
        + Duration::from_secs(u64::from(cert.primary_key.created_at().as_secs()));
    if key_created > time {
        return false;
    }
    for sig in &cert.details.direct_signatures {
        if let Some(exp) = sig.key_expiration_time() {
            let exp_dur: Duration = exp.into();
            if key_created + exp_dur <= time {
                return true;
            }
        }
    }
    for user in &cert.details.users {
        for sig in &user.signatures {
            if let Some(exp) = sig.key_expiration_time() {
                let exp_dur: Duration = exp.into();
                if key_created + exp_dur <= time {
                    return true;
                }
            }
        }
    }
    false
}

fn is_user_id_valid(
    cert: &SignedPublicKey,
    user: &pgp::types::SignedUser,
    target_uid: &[u8],
    time: SystemTime,
) -> bool {
    if user.id.id() != target_uid {
        return false;
    }

    let mut has_valid_cert = false;
    let mut latest_cert_time = None;

    for sig in &user.signatures {
        if let Some(typ) = sig.typ() {
            if matches!(
                typ,
                SignatureType::CertGeneric
                    | SignatureType::CertPersona
                    | SignatureType::CertCasual
                    | SignatureType::CertPositive
            ) && sig
                .verify_certification(&cert.primary_key, Tag::UserId, &user.id)
                .is_ok()
            {
                if let Some(created) = sig.created() {
                    let sig_time =
                        SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(created.as_secs()));
                    if sig_time <= time {
                        if let Some(exp) = sig.signature_expiration_time() {
                            let exp_dur: Duration = exp.into();
                            if sig_time + exp_dur <= time {
                                continue;
                            }
                        }
                        has_valid_cert = true;
                        latest_cert_time = Some(
                            latest_cert_time.map_or(sig_time, |t: SystemTime| t.max(sig_time)),
                        );
                    }
                }
            }
        }
    }

    if !has_valid_cert {
        return false;
    }

    for sig in &user.signatures {
        if sig.typ() == Some(SignatureType::CertRevocation)
            && sig
                .verify_certification(&cert.primary_key, Tag::UserId, &user.id)
                .is_ok()
        {
            if let Some(created) = sig.created() {
                let sig_time =
                    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(created.as_secs()));
                if sig_time <= time {
                    if let Some(cert_time) = latest_cert_time {
                        if sig_time >= cert_time {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            } else {
                return false;
            }
        }
    }

    true
}

fn is_subkey_valid(
    cert: &SignedPublicKey,
    subkey: &pgp::composed::SignedPublicSubKey,
    time: SystemTime,
) -> bool {
    let mut has_binding = false;
    let mut is_signing = false;
    let mut latest_binding_time = None;

    for sig in &subkey.signatures {
        if sig.typ() == Some(SignatureType::SubkeyBinding)
            && sig
                .verify_subkey_binding(&cert.primary_key, &subkey.key)
                .is_ok()
        {
            if let Some(created) = sig.created() {
                let sig_time =
                    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(created.as_secs()));
                if sig_time <= time {
                    if let Some(exp) = sig.signature_expiration_time() {
                        let exp_dur: Duration = exp.into();
                        if sig_time + exp_dur <= time {
                            continue;
                        }
                    }
                    has_binding = true;
                    if sig.key_flags().sign() {
                        is_signing = true;
                    }
                    latest_binding_time =
                        Some(latest_binding_time.map_or(sig_time, |t: SystemTime| t.max(sig_time)));
                }
            }
        }
    }

    if !has_binding || !is_signing {
        return false;
    }

    let key_created =
        SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(subkey.key.created_at().as_secs()));
    for sig in &subkey.signatures {
        if let Some(exp) = sig.key_expiration_time() {
            let exp_dur: Duration = exp.into();
            if key_created + exp_dur <= time {
                return false;
            }
        }
    }

    for sig in &subkey.signatures {
        if sig.typ() == Some(SignatureType::SubkeyRevocation)
            && sig
                .verify_subkey_binding(&cert.primary_key, &subkey.key)
                .is_ok()
        {
            if let Some(created) = sig.created() {
                let sig_time =
                    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(created.as_secs()));
                if sig_time <= time {
                    if let Some(bind_time) = latest_binding_time {
                        if sig_time >= bind_time {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            } else {
                return false;
            }
        }
    }

    true
}

#[derive(Debug)]
pub enum ImportError {
    Certificate(Box<dyn std::error::Error + Send + Sync>),
    SecretMaterial,
    SecretMissing,
    UnlockFailed,
    InvalidSecret,
    InvalidBinding,
    RevocationCapacity,
    KeyMismatch,
    Contact(crate::session::installation::Error),
}

impl fmt::Display for ImportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Certificate(err) => write!(f, "certificate error: {err}"),
            Self::SecretMaterial => write!(f, "secret key material present in public import"),
            Self::SecretMissing => write!(f, "secret key material missing in owned import"),
            Self::UnlockFailed => write!(f, "failed to unlock secret key with passphrase"),
            Self::InvalidSecret => write!(f, "invalid secret key format"),
            Self::InvalidBinding => {
                write!(f, "certificate binding is invalid, revoked, or expired")
            }
            Self::RevocationCapacity => write!(f, "revocation storage capacity exceeded"),
            Self::KeyMismatch => write!(f, "key does not match expected identity"),
            Self::Contact(err) => write!(f, "contact store error: {err:?}"),
        }
    }
}

impl std::error::Error for ImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Certificate(err) => Some(&**err),
            Self::Contact(err) => Some(err),
            _ => None,
        }
    }
}
