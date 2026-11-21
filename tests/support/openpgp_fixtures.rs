use ed25519_dalek::SigningKey;
use mesh_identity::openpgp::issue;
use pgp::composed::{Deserializable, SignedPublicKey, SignedPublicSubKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{
    KeyFlags, PubKeyInner, PublicSubkey, SecretKey, SecretSubkey, Signature, SignatureConfig,
    SignatureType, Subpacket, SubpacketData,
};
use pgp::ser::Serialize;
use pgp::types::{
    KeyDetails, KeyVersion, Password, PlainSecretParams, PublicParams, SecretParams, Tag, Timestamp,
};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct RotationFixture {
    pub before: Vec<u8>,
    pub unbound: Vec<u8>,
    pub after: Vec<u8>,
    pub now: SystemTime,
}

pub fn make_primary_secret(
    key: &SigningKey,
    created_secs: u32,
) -> (SecretKey, pgp::packet::PublicKey) {
    let seed = key.to_bytes();
    let ed25519_sec = pgp::crypto::ed25519::SecretKey::try_from_bytes(
        seed,
        pgp::crypto::ed25519::Mode::EdDSALegacy,
    )
    .unwrap();
    let plain_sec =
        PlainSecretParams::EdDSALegacy(pgp::crypto::eddsa_legacy::SecretKey::Ed25519(ed25519_sec));
    let public_params = PublicParams::try_from(&plain_sec).unwrap();
    let pub_inner = PubKeyInner::new(
        KeyVersion::V4,
        PublicKeyAlgorithm::EdDSALegacy,
        Timestamp::from_secs(created_secs),
        None,
        public_params,
    )
    .unwrap();
    let primary_pub = pgp::packet::PublicKey::from_inner(pub_inner).unwrap();
    let primary_sec = SecretKey::new(primary_pub.clone(), SecretParams::Plain(plain_sec)).unwrap();
    (primary_sec, primary_pub)
}

pub fn make_key_revocation(
    key: &SigningKey,
    cert: &SignedPublicKey,
    revoked_secs: u32,
) -> Signature {
    let (primary_sec, _) = make_primary_secret(key, cert.primary_key.created_at().as_secs());
    let mut config = SignatureConfig::v4(
        SignatureType::KeyRevocation,
        PublicKeyAlgorithm::EdDSALegacy,
        HashAlgorithm::Sha256,
    );
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            revoked_secs,
        )))
        .unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary_sec.fingerprint())).unwrap(),
    ];
    config.unhashed_subpackets =
        vec![Subpacket::regular(SubpacketData::IssuerKeyId(primary_sec.legacy_key_id())).unwrap()];
    config
        .sign_key(&primary_sec, &Password::empty(), &cert.primary_key)
        .unwrap()
}

pub fn make_uid_revocation(
    key: &SigningKey,
    cert: &SignedPublicKey,
    uid: &[u8],
    revoked_secs: u32,
) -> Signature {
    let (primary_sec, _) = make_primary_secret(key, cert.primary_key.created_at().as_secs());
    let user_id = cert
        .details
        .users
        .iter()
        .find(|u| u.id.id() == uid)
        .expect("user id must exist on certificate");
    let mut config = SignatureConfig::v4(
        SignatureType::CertRevocation,
        PublicKeyAlgorithm::EdDSALegacy,
        HashAlgorithm::Sha256,
    );
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            revoked_secs,
        )))
        .unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary_sec.fingerprint())).unwrap(),
    ];
    config.unhashed_subpackets =
        vec![Subpacket::regular(SubpacketData::IssuerKeyId(primary_sec.legacy_key_id())).unwrap()];
    config
        .sign_certification_third_party(
            &primary_sec,
            &Password::empty(),
            &cert.primary_key,
            Tag::UserId,
            &user_id.id,
        )
        .unwrap()
}

pub fn make_subkey_revocation(
    key: &SigningKey,
    cert: &SignedPublicKey,
    subkey: &PublicSubkey,
    revoked_secs: u32,
) -> Signature {
    let (primary_sec, primary_pub) =
        make_primary_secret(key, cert.primary_key.created_at().as_secs());
    let mut config = SignatureConfig::v4(
        SignatureType::SubkeyRevocation,
        PublicKeyAlgorithm::EdDSALegacy,
        HashAlgorithm::Sha256,
    );
    config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            revoked_secs,
        )))
        .unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary_sec.fingerprint())).unwrap(),
    ];
    config.unhashed_subpackets =
        vec![Subpacket::regular(SubpacketData::IssuerKeyId(primary_sec.legacy_key_id())).unwrap()];
    config
        .sign_subkey_binding(&primary_sec, &primary_pub, &Password::empty(), subkey)
        .unwrap()
}

pub fn rotation_fixture(seed: [u8; 32], replacement_seed: [u8; 32], uid: &[u8]) -> RotationFixture {
    let original_key = SigningKey::from_bytes(&seed);
    let issued = 1_750_000_000;
    let created = UNIX_EPOCH + Duration::from_secs(u64::from(issued));
    let rotated = issued + 10;
    let now = created + Duration::from_secs(11);
    let before = issue(&original_key, uid, issued, b"fixture", None)
        .unwrap()
        .certificate;
    let cert = SignedPublicKey::from_bytes(&before[..]).unwrap();

    let (primary_sec, primary_pub) = make_primary_secret(&original_key, issued);

    let sub_ed25519 = pgp::crypto::ed25519::SecretKey::try_from_bytes(
        replacement_seed,
        pgp::crypto::ed25519::Mode::EdDSALegacy,
    )
    .unwrap();
    let sub_plain =
        PlainSecretParams::EdDSALegacy(pgp::crypto::eddsa_legacy::SecretKey::Ed25519(sub_ed25519));
    let sub_pub_params = PublicParams::try_from(&sub_plain).unwrap();
    let sub_pub_inner = PubKeyInner::new(
        KeyVersion::V4,
        PublicKeyAlgorithm::EdDSALegacy,
        Timestamp::from_secs(rotated),
        None,
        sub_pub_params,
    )
    .unwrap();
    let sub_pub = PublicSubkey::from_inner(sub_pub_inner).unwrap();
    let sub_sec = SecretSubkey::new(sub_pub.clone(), SecretParams::Plain(sub_plain)).unwrap();

    let mut backsig_config = SignatureConfig::v4(
        SignatureType::KeyBinding,
        PublicKeyAlgorithm::EdDSALegacy,
        HashAlgorithm::Sha256,
    );
    backsig_config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            rotated,
        )))
        .unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(sub_sec.fingerprint())).unwrap(),
    ];
    let backsig = backsig_config
        .sign_primary_key_binding(&sub_sec, &sub_pub, &Password::empty(), &primary_pub)
        .unwrap();

    let mut keyflags = KeyFlags::default();
    keyflags.set_sign(true);
    let mut bind_config = SignatureConfig::v4(
        SignatureType::SubkeyBinding,
        PublicKeyAlgorithm::EdDSALegacy,
        HashAlgorithm::Sha256,
    );
    bind_config.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            rotated,
        )))
        .unwrap(),
        Subpacket::regular(SubpacketData::KeyFlags(keyflags)).unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(primary_sec.fingerprint())).unwrap(),
        Subpacket::regular(SubpacketData::EmbeddedSignature(Box::new(backsig))).unwrap(),
    ];
    bind_config.unhashed_subpackets =
        vec![Subpacket::regular(SubpacketData::IssuerKeyId(primary_sec.legacy_key_id())).unwrap()];
    let binding_sig = bind_config
        .sign_subkey_binding(&primary_sec, &primary_pub, &Password::empty(), &sub_pub)
        .unwrap();

    let mut unbound_cert = cert.clone();
    unbound_cert.public_subkeys.push(SignedPublicSubKey {
        key: sub_pub.clone(),
        signatures: vec![],
    });
    let unbound = unbound_cert.to_bytes().unwrap();

    let mut after_cert = cert;
    after_cert.public_subkeys.push(SignedPublicSubKey {
        key: sub_pub,
        signatures: vec![binding_sig],
    });
    let after = after_cert.to_bytes().unwrap();

    RotationFixture {
        before,
        unbound,
        after,
        now,
    }
}
