//! Library-backed issuance and OpenPGP adapter for `mesh-identity`.

use crate::session::installation::{Identity, Installation};
use ed25519_dalek::SigningKey;
use pgp::composed::SignedPublicKey;
use pgp::packet::{KeyFlags, SignatureConfig, SignatureType, Subpacket, SubpacketData, UserId};
use pgp::ser::Serialize;
use pgp::types::{Fingerprint, KeyDetails, Password, Tag, Timestamp};
use std::sync::{Arc, Weak};
use std::time::{Duration, SystemTime};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExportProfile {
    V4,
    V6,
}

pub(super) fn parse_public_peer(bytes: &[u8]) -> Result<SignedPublicKey, ImportError> {
    import::parse_public_peer(bytes)
}

fn check_peer_current(cert: &SignedPublicKey, user_id: &[u8]) -> Result<(), ImportError> {
    import::validate_binding(cert, user_id, SystemTime::now())
}

fn certification_peer<'a>(
    peer: Option<(&'a [u8], &'a [u8])>,
    remembered: Option<&PeerRevocations>,
) -> Result<Option<(SignedPublicKey, &'a [u8])>, ImportError> {
    peer.map(|(certificate, user_id)| {
        let mut cert = parse_public_peer(certificate)?;
        if let Some(revocations) = remembered {
            cert = revocations.merge(cert)?;
        }
        check_peer_current(&cert, user_id)?;
        Ok((cert, user_id))
    })
    .transpose()
}

pub struct Artifacts {
    pub certificate: Vec<u8>,
    pub detached: Vec<u8>,
    pub peer_signatures: Vec<(&'static str, Vec<u8>)>,
}

/// An export awaiting confirmation. It owns the exact inputs and carries no
/// signing key. Starting another preview or switching identities cancels it.
#[must_use = "confirm this preview to issue artifacts, or drop it to cancel"]
pub struct ExportPreview {
    handle: Weak<()>,
    identity: Identity,
    profile: ExportProfile,
    user_id: Vec<u8>,
    created: u32,
    document: Vec<u8>,
    peer: Option<PeerCertification>,
}

struct PeerCertification {
    fingerprint: Fingerprint,
    certificate: Vec<u8>,
    user_id: Vec<u8>,
}

#[derive(Clone, Debug)]
pub(crate) struct PendingExport {
    pub(crate) handle: Arc<()>,
    pub(crate) peer: Option<Fingerprint>,
}

impl ExportPreview {
    pub const WARNING: &'static str = "Anyone who has seen this Mesh public key can recognize it in the OpenPGP certificate. Recipients can keep or share a copy.";

    pub fn new(
        installation: &mut Installation,
        profile: ExportProfile,
        user_id: Vec<u8>,
        created: u32,
        document: Vec<u8>,
        peer: Option<(Vec<u8>, Vec<u8>)>,
    ) -> Result<Self, ImportError> {
        let peer = peer
            .map(|(certificate, user_id)| -> Result<_, ImportError> {
                let raw_peer = parse_public_peer(&certificate)?;
                let cert = installation.openpgp_revocations.merge(raw_peer)?;
                check_peer_current(&cert, &user_id)?;
                import::validate_binding(
                    &cert,
                    &user_id,
                    SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(created)),
                )?;
                Ok(PeerCertification {
                    fingerprint: cert.primary_key.fingerprint(),
                    certificate,
                    user_id,
                })
            })
            .transpose()?;

        let handle = Arc::new(());
        let preview = Self {
            handle: Arc::downgrade(&handle),
            identity: installation.selected(),
            profile,
            user_id,
            created,
            document,
            peer,
        };
        installation.openpgp_preview = Some(PendingExport {
            handle,
            peer: preview.peer.as_ref().map(|peer| peer.fingerprint.clone()),
        });
        Ok(preview)
    }

    pub fn identity(&self) -> Identity {
        self.identity
    }

    pub fn profile(&self) -> ExportProfile {
        self.profile
    }

    pub fn user_id(&self) -> &[u8] {
        &self.user_id
    }

    pub fn document(&self) -> &[u8] {
        &self.document
    }

    pub fn certification_target(&self) -> Option<(&Fingerprint, &[u8])> {
        self.peer
            .as_ref()
            .map(|peer| (&peer.fingerprint, peer.user_id.as_slice()))
    }

    /// Issue only the previewed export. Confirmation consumes the preview
    /// even if issuance fails. A preview cannot survive a restart.
    pub fn confirm(
        self,
        installation: &mut Installation,
    ) -> Result<Artifacts, Box<dyn std::error::Error + Send + Sync>> {
        let current = installation.openpgp_preview.as_ref();
        if !current.is_some_and(|pending| self.handle.ptr_eq(&Arc::downgrade(&pending.handle))) {
            return Err("OpenPGP export preview is no longer current".into());
        }
        if installation.selected() != self.identity {
            return Err("selected identity does not match the requested export key".into());
        }
        installation.openpgp_preview = None;
        let peer = self
            .peer
            .as_ref()
            .map(|peer| (peer.certificate.as_slice(), peer.user_id.as_slice()));
        let peer = certification_peer(peer, Some(&installation.openpgp_revocations))
            .map_err(|error| format!("{error:?}"))?;
        issue_profile(
            installation.selected_signing_key(),
            self.profile,
            &self.user_id,
            self.created,
            &self.document,
            peer,
        )
    }
}

/// Low-level issuance for a caller that has already authorized the operation.
/// Use `ExportPreview` for confirmation that can outlive an application callback.
pub fn issue_for(
    installation: &Installation,
    expected: Identity,
    user_id: &[u8],
    created: u32,
    document: &[u8],
    peer: Option<(&[u8], &[u8])>,
) -> Result<Artifacts, Box<dyn std::error::Error + Send + Sync>> {
    issue_for_profile(
        installation,
        expected,
        ExportProfile::V4,
        user_id,
        created,
        document,
        peer,
    )
}

pub fn issue_for_profile(
    installation: &Installation,
    expected: Identity,
    profile: ExportProfile,
    user_id: &[u8],
    created: u32,
    document: &[u8],
    peer: Option<(&[u8], &[u8])>,
) -> Result<Artifacts, Box<dyn std::error::Error + Send + Sync>> {
    if installation.selected() != expected {
        return Err("selected identity does not match the requested export key".into());
    }
    let peer = certification_peer(peer, Some(&installation.openpgp_revocations))
        .map_err(|error| format!("{error:?}"))?;
    issue_profile(
        installation.selected_signing_key(),
        profile,
        user_id,
        created,
        document,
        peer,
    )
}

pub fn issue(
    key: &SigningKey,
    user_id: &[u8],
    created: u32,
    document: &[u8],
    peer: Option<(&[u8], &[u8])>,
) -> Result<Artifacts, Box<dyn std::error::Error + Send + Sync>> {
    let peer = certification_peer(peer, None).map_err(|error| format!("{error:?}"))?;
    issue_profile(key, ExportProfile::V4, user_id, created, document, peer)
}

fn issue_profile(
    key: &SigningKey,
    profile: ExportProfile,
    user_id: &[u8],
    created: u32,
    document: &[u8],
    peer: Option<(SignedPublicKey, &[u8])>,
) -> Result<Artifacts, Box<dyn std::error::Error + Send + Sync>> {
    let mut rng = rand::rngs::OsRng;
    let seed: [u8; 32] = key.to_bytes();

    let mut keyflags = KeyFlags::default();
    keyflags.set_certify(true);
    keyflags.set_sign(true);

    let (primary_sec, primary_pub, direct_sig, self_sig) = match profile {
        ExportProfile::V4 => {
            let ed25519_sec = pgp::crypto::ed25519::SecretKey::try_from_bytes(
                seed,
                pgp::crypto::ed25519::Mode::EdDSALegacy,
            )?;
            let plain_sec = pgp::types::PlainSecretParams::EdDSALegacy(
                pgp::crypto::eddsa_legacy::SecretKey::Ed25519(ed25519_sec),
            );
            let public_params = pgp::types::PublicParams::try_from(&plain_sec)?;
            let pub_inner = pgp::packet::PubKeyInner::new(
                pgp::types::KeyVersion::V4,
                pgp::crypto::public_key::PublicKeyAlgorithm::EdDSALegacy,
                Timestamp::from_secs(created),
                None,
                public_params,
            )?;
            let primary_pub = pgp::packet::PublicKey::from_inner(pub_inner)?;
            let primary_sec = pgp::packet::SecretKey::new(
                primary_pub.clone(),
                pgp::types::SecretParams::Plain(plain_sec),
            )?;

            let mut config = SignatureConfig::v4(
                SignatureType::CertPositive,
                pgp::crypto::public_key::PublicKeyAlgorithm::EdDSALegacy,
                pgp::crypto::hash::HashAlgorithm::Sha256,
            );
            config.hashed_subpackets = vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                    created,
                )))?,
                Subpacket::regular(SubpacketData::IssuerFingerprint(primary_sec.fingerprint()))?,
                Subpacket::regular(SubpacketData::KeyFlags(keyflags))?,
                Subpacket::regular(SubpacketData::IsPrimary(true))?,
            ];
            config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
                primary_sec.legacy_key_id(),
            ))?];

            let uid_str = std::str::from_utf8(user_id)
                .map_err(|e| format!("user ID is not valid utf-8: {e}"))?;
            let user_id_packet = UserId::from_str(Default::default(), uid_str)?;
            let self_sig = config.sign_certification(
                &primary_sec,
                &primary_pub,
                &Password::empty(),
                Tag::UserId,
                &user_id_packet,
            )?;
            (primary_sec, primary_pub, None, self_sig)
        }
        ExportProfile::V6 => {
            let ed25519_sec = pgp::crypto::ed25519::SecretKey::try_from_bytes(
                seed,
                pgp::crypto::ed25519::Mode::Ed25519,
            )?;
            let plain_sec = pgp::types::PlainSecretParams::Ed25519(ed25519_sec);
            let public_params = pgp::types::PublicParams::try_from(&plain_sec)?;
            let pub_inner = pgp::packet::PubKeyInner::new(
                pgp::types::KeyVersion::V6,
                pgp::crypto::public_key::PublicKeyAlgorithm::Ed25519,
                Timestamp::from_secs(created),
                None,
                public_params,
            )?;
            let primary_pub = pgp::packet::PublicKey::from_inner(pub_inner)?;
            let primary_sec = pgp::packet::SecretKey::new(
                primary_pub.clone(),
                pgp::types::SecretParams::Plain(plain_sec),
            )?;

            let mut dks_config = SignatureConfig::v6(
                &mut rng,
                SignatureType::Key,
                pgp::crypto::public_key::PublicKeyAlgorithm::Ed25519,
                pgp::crypto::hash::HashAlgorithm::Sha256,
            )?;
            dks_config.hashed_subpackets = vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                    created,
                )))?,
                Subpacket::regular(SubpacketData::IssuerFingerprint(primary_sec.fingerprint()))?,
                Subpacket::regular(SubpacketData::KeyFlags(keyflags))?,
            ];
            let direct_sig = dks_config.sign_key(&primary_sec, &Password::empty(), &primary_pub)?;

            let mut cert_config = SignatureConfig::v6(
                &mut rng,
                SignatureType::CertPositive,
                pgp::crypto::public_key::PublicKeyAlgorithm::Ed25519,
                pgp::crypto::hash::HashAlgorithm::Sha256,
            )?;
            cert_config.hashed_subpackets = vec![
                Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
                    created,
                )))?,
                Subpacket::regular(SubpacketData::IssuerFingerprint(primary_sec.fingerprint()))?,
                Subpacket::regular(SubpacketData::IsPrimary(true))?,
            ];

            let uid_str = std::str::from_utf8(user_id)
                .map_err(|e| format!("user ID is not valid utf-8: {e}"))?;
            let user_id_packet = UserId::from_str(Default::default(), uid_str)?;
            let self_sig = cert_config.sign_certification(
                &primary_sec,
                &primary_pub,
                &Password::empty(),
                Tag::UserId,
                &user_id_packet,
            )?;
            (primary_sec, primary_pub, Some(direct_sig), self_sig)
        }
    };

    let uid_str =
        std::str::from_utf8(user_id).map_err(|e| format!("user ID is not valid utf-8: {e}"))?;
    let user_id_packet = UserId::from_str(Default::default(), uid_str)?;
    let signed_user = pgp::types::SignedUser::new(user_id_packet, vec![self_sig]);
    let direct_signatures = direct_sig.into_iter().collect();
    let details =
        pgp::composed::SignedKeyDetails::new(vec![], direct_signatures, vec![signed_user], vec![]);
    let public_cert = pgp::composed::SignedPublicKey::new(primary_pub, details, vec![]);

    let certificate = public_cert.to_bytes()?;

    // Detached signature
    let mut sig_config = match profile {
        ExportProfile::V4 => SignatureConfig::v4(
            SignatureType::Binary,
            pgp::crypto::public_key::PublicKeyAlgorithm::EdDSALegacy,
            pgp::crypto::hash::HashAlgorithm::Sha256,
        ),
        ExportProfile::V6 => SignatureConfig::v6(
            &mut rng,
            SignatureType::Binary,
            pgp::crypto::public_key::PublicKeyAlgorithm::Ed25519,
            pgp::crypto::hash::HashAlgorithm::Sha256,
        )?,
    };
    sig_config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            created,
        )))?,
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary_sec.fingerprint()))?,
    ];
    if matches!(profile, ExportProfile::V4) {
        sig_config.unhashed_subpackets = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
            primary_sec.legacy_key_id(),
        ))?];
    }
    let detached_sig = sig_config.sign(&primary_sec, &Password::empty(), document)?;
    let detached = pgp::composed::DetachedSignature::new(detached_sig).to_bytes()?;

    // Peer signatures
    let mut peer_signatures = Vec::new();
    if let Some((peer_cert, target_uid)) = peer {
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(u64::from(created));
        import::validate_binding(&peer_cert, target_uid, time)
            .map_err(|error| format!("peer certificate validation failed: {error}"))?;
        let peer_user = peer_cert
            .details
            .users
            .iter()
            .find(|u| u.id.id() == target_uid)
            .ok_or("peer User ID has no valid binding")?;

        let mut make_cert_sig =
            |typ: SignatureType,
             creation: u32,
             exportable: bool|
             -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
                let mut config = match profile {
                    ExportProfile::V4 => SignatureConfig::v4(
                        typ,
                        pgp::crypto::public_key::PublicKeyAlgorithm::EdDSALegacy,
                        pgp::crypto::hash::HashAlgorithm::Sha256,
                    ),
                    ExportProfile::V6 => SignatureConfig::v6(
                        &mut rng,
                        typ,
                        pgp::crypto::public_key::PublicKeyAlgorithm::Ed25519,
                        pgp::crypto::hash::HashAlgorithm::Sha256,
                    )?,
                };
                let mut hashed = vec![
                    Subpacket::regular(SubpacketData::SignatureCreationTime(
                        Timestamp::from_secs(creation),
                    ))?,
                    Subpacket::regular(SubpacketData::IssuerFingerprint(
                        primary_sec.fingerprint(),
                    ))?,
                ];
                if !exportable {
                    hashed.push(Subpacket::regular(SubpacketData::ExportableCertification(
                        false,
                    ))?);
                }
                config.hashed_subpackets = hashed;
                if matches!(profile, ExportProfile::V4) {
                    config.unhashed_subpackets = vec![Subpacket::regular(
                        SubpacketData::IssuerKeyId(primary_sec.legacy_key_id()),
                    )?];
                }
                let sig = config.sign_certification_third_party(
                    &primary_sec,
                    &Password::empty(),
                    &peer_cert.primary_key,
                    Tag::UserId,
                    &peer_user.id,
                )?;
                Ok(pgp::composed::DetachedSignature::new(sig).to_bytes()?)
            };

        peer_signatures = vec![
            (
                "peer-certification.sig",
                make_cert_sig(SignatureType::CertPositive, created, true)?,
            ),
            (
                "peer-local-certification.sig",
                make_cert_sig(SignatureType::CertPositive, created, false)?,
            ),
            (
                "peer-certification-revocation-same-second.sig",
                make_cert_sig(SignatureType::CertRevocation, created, true)?,
            ),
            (
                "peer-certification-revocation.sig",
                make_cert_sig(SignatureType::CertRevocation, created + 1, true)?,
            ),
        ];
    }

    Ok(Artifacts {
        certificate,
        detached,
        peer_signatures,
    })
}

mod import;
pub use import::{ImportError, MAX_CERTIFICATE_BYTES, Provenance, import_owned, import_peer};
mod revocations;
pub use revocations::PeerRevocations;
pub use revocations::remember_peer_revocations;
