use super::{ImportError, parse_public_peer};
use crate::session::installation::Installation;
use pgp::composed::SignedPublicKey;
use pgp::packet::{Signature, SignatureType};
use pgp::types::{Fingerprint, KeyDetails, Tag};
use std::collections::{HashMap, VecDeque};

/// Slots for certificates that are not contacts. Contacts never compete for these.
pub(crate) const MAX_UNKNOWN_CERTIFICATES: usize = 256;
pub(crate) const MAX_PROTECTED_CERTIFICATES: usize = 256;
pub(crate) const MAX_SIGNATURES_PER_CERTIFICATE: usize = 16;

type Remembered = Option<Vec<Signature>>;

fn signatures_match(a: &Signature, b: &Signature) -> bool {
    if let (Some(sig_a), Some(sig_b)) = (a.signature(), b.signature()) {
        sig_a == sig_b
    } else {
        false
    }
}

/// Valid public revocation signatures observed by this installation.
///
/// Accepted certificate fingerprints have their own bounded storage. Updates
/// for other fingerprints use a separate FIFO. A certificate with more
/// distinct revocations than we keep is remembered as unusable (`None`).
#[derive(Clone, Debug, Default)]
pub struct PeerRevocations {
    protected: HashMap<Fingerprint, Remembered>,
    unknown: HashMap<Fingerprint, Remembered>,
    unknown_order: VecDeque<Fingerprint>,
}

impl PeerRevocations {
    pub fn is_empty(&self) -> bool {
        self.protected.is_empty() && self.unknown.is_empty()
    }

    pub(super) fn merge(&self, mut cert: SignedPublicKey) -> Result<SignedPublicKey, ImportError> {
        let fingerprint = cert.primary_key.fingerprint();
        let known = match self
            .protected
            .get(&fingerprint)
            .or_else(|| self.unknown.get(&fingerprint))
        {
            Some(Some(known)) => known,
            Some(None) => return Err(ImportError::RevocationCapacity),
            None => return Ok(cert),
        };

        for sig in known {
            match sig.typ() {
                Some(SignatureType::KeyRevocation) => {
                    if !cert
                        .details
                        .revocation_signatures
                        .iter()
                        .any(|prior| signatures_match(prior, sig))
                    {
                        cert.details.revocation_signatures.push(sig.clone());
                    }
                }
                Some(SignatureType::CertRevocation) => {
                    for user in &mut cert.details.users {
                        if sig
                            .verify_certification(&cert.primary_key, Tag::UserId, &user.id)
                            .is_ok()
                            && !user
                                .signatures
                                .iter()
                                .any(|prior| signatures_match(prior, sig))
                        {
                            user.signatures.push(sig.clone());
                        }
                    }
                }
                Some(SignatureType::SubkeyRevocation) => {
                    for subkey in &mut cert.public_subkeys {
                        if sig
                            .verify_subkey_binding(&cert.primary_key, &subkey.key)
                            .is_ok()
                            && !subkey
                                .signatures
                                .iter()
                                .any(|prior| signatures_match(prior, sig))
                        {
                            subkey.signatures.push(sig.clone());
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(cert)
    }

    pub(super) fn check_capacity(&self, fingerprint: &Fingerprint) -> Result<(), ImportError> {
        if !self.protected.contains_key(fingerprint)
            && self.protected.len() >= MAX_PROTECTED_CERTIFICATES
        {
            return Err(ImportError::RevocationCapacity);
        }
        Ok(())
    }

    pub(super) fn protect(&mut self, fingerprint: Fingerprint) {
        if self.protected.contains_key(&fingerprint) {
            return;
        }
        let previous = self.unknown.remove(&fingerprint);
        if previous.is_some() {
            self.unknown_order.retain(|known| known != &fingerprint);
        }
        self.protected
            .insert(fingerprint, previous.unwrap_or_else(|| Some(Vec::new())));
    }

    fn slot(&mut self, fingerprint: Fingerprint) -> &mut Remembered {
        if self.protected.contains_key(&fingerprint) {
            return self
                .protected
                .get_mut(&fingerprint)
                .expect("guaranteed by contains_key");
        }
        if !self.unknown.contains_key(&fingerprint) {
            if self.unknown.len() >= MAX_UNKNOWN_CERTIFICATES {
                if let Some(oldest) = self.unknown_order.pop_front() {
                    self.unknown.remove(&oldest);
                }
            }
            self.unknown_order.push_back(fingerprint.clone());
        }
        self.unknown
            .entry(fingerprint)
            .or_insert_with(|| Some(Vec::new()))
    }
}

/// Record verified primary-key, User ID, and subkey revocations from an updated public
/// certificate. Returns the number of newly remembered signatures. An update
/// omitting a revocation leaves the earlier observation intact.
pub fn remember_peer_revocations(
    installation: &mut Installation,
    certificate: &[u8],
) -> Result<usize, ImportError> {
    let cert = parse_public_peer(certificate)?;
    remember_certificate_revocations(installation, &cert)
}

/// Also used by ordinary imports, including secret certificates. Only verified
/// public signatures are retained; secret key material never enters this cache.
pub(super) fn remember_certificate_revocations(
    installation: &mut Installation,
    cert: &SignedPublicKey,
) -> Result<usize, ImportError> {
    let mut revoked = Vec::new();

    // 1. Primary key revocations
    for sig in &cert.details.revocation_signatures {
        if sig.typ() == Some(SignatureType::KeyRevocation)
            && sig.verify_key(&cert.primary_key).is_ok()
        {
            revoked.push(sig.clone());
        }
    }

    // 2. User ID revocations
    for user in &cert.details.users {
        for sig in &user.signatures {
            if sig.typ() == Some(SignatureType::CertRevocation)
                && sig
                    .verify_certification(&cert.primary_key, Tag::UserId, &user.id)
                    .is_ok()
            {
                revoked.push(sig.clone());
            }
        }
    }

    // 3. Subkey revocations
    for subkey in &cert.public_subkeys {
        for sig in &subkey.signatures {
            if sig.typ() == Some(SignatureType::SubkeyRevocation)
                && sig
                    .verify_subkey_binding(&cert.primary_key, &subkey.key)
                    .is_ok()
            {
                revoked.push(sig.clone());
            }
        }
    }

    if revoked.is_empty() {
        return Ok(0);
    }

    let fingerprint = cert.primary_key.fingerprint();
    if installation
        .openpgp_preview
        .as_ref()
        .is_some_and(|preview| preview.peer.as_ref() == Some(&fingerprint))
    {
        installation.openpgp_preview = None;
    }

    let entry = installation.openpgp_revocations.slot(fingerprint);
    let known = entry.as_mut().ok_or(ImportError::RevocationCapacity)?;
    let before = known.len();
    for signature in revoked {
        if !known
            .iter()
            .any(|prior| signatures_match(prior, &signature))
        {
            if known.len() >= MAX_SIGNATURES_PER_CERTIFICATE {
                *entry = None;
                return Err(ImportError::RevocationCapacity);
            }
            known.push(signature);
        }
    }
    Ok(known.len() - before)
}
