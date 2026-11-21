#![cfg(feature = "openpgp")]

#[path = "support/openpgp_fixtures.rs"]
mod openpgp_fixtures;

use ed25519_dalek::SigningKey;
use mesh_identity::contact::VerificationStatus;
use mesh_identity::openpgp::{
    ExportPreview, ExportProfile, ImportError, MAX_CERTIFICATE_BYTES, import_owned, import_peer,
    issue, issue_for, issue_for_profile, remember_peer_revocations,
};
use mesh_identity::session::installation::Installation;
use openpgp_fixtures::{
    RotationFixture, make_key_revocation, make_primary_secret, make_subkey_revocation,
    make_uid_revocation, rotation_fixture,
};
use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey, SignedSecretKey};
use pgp::ser::Serialize;
use pgp::types::KeyDetails;
use rand::{SeedableRng, rngs::StdRng};
use std::time::{Duration, UNIX_EPOCH};

#[test]
fn imports_only_the_selected_valid_binding_and_preserves_contact_identity() {
    let key = SigningKey::from_bytes(&[12; 32]);
    let expected = key.verifying_key().to_bytes();
    let uid = b"Certificate fixture";
    let created = 1_750_000_000;
    let now = UNIX_EPOCH + Duration::from_secs(u64::from(created) + 1);
    let cert = issue(&key, uid, created, b"fixture", None)
        .unwrap()
        .certificate;
    let mut local = Installation::new(SigningKey::from_bytes(&[13; 32]));
    let selected = local.selected();
    let mut rng = StdRng::seed_from_u64(1);

    assert!(matches!(
        import_peer(&mut local, &cert, [0; 32], uid, now, &mut rng),
        Err(ImportError::KeyMismatch)
    ));
    assert!(matches!(
        import_peer(&mut local, &cert, expected, b"Other UID", now, &mut rng),
        Err(ImportError::InvalidBinding)
    ));
    assert!(import_peer(&mut local, b"invalid", expected, uid, now, &mut rng).is_err());
    assert_eq!(local.contacts(selected).unwrap().count(), 0);

    let (record, source) = import_peer(&mut local, &cert, expected, uid, now, &mut rng).unwrap();
    assert_eq!(record.peer_ed25519_pk, expected);
    assert_eq!(
        record.verification_status,
        VerificationStatus::ImportedUnverified
    );
    assert_eq!(record.encounter_count, 0);
    let contact_id = record.local_contact_id;
    assert_eq!(source.primary, source.signing_key);
    assert_eq!(source.user_id, uid);
    let (record, repeated) = import_peer(&mut local, &cert, expected, uid, now, &mut rng).unwrap();
    assert_eq!(record.local_contact_id, contact_id);
    assert_eq!(repeated, source);
    assert_eq!(local.contacts(selected).unwrap().count(), 1);
}

#[test]
fn v4_and_v6_imports_share_one_contact_and_keep_certificate_provenance() {
    let key = SigningKey::from_bytes(&[71; 32]);
    let mut peer = Installation::new(key.clone());
    let expected = peer.selected();
    let created = 1_750_000_000;
    let time = UNIX_EPOCH + Duration::from_secs(u64::from(created));
    let now = time + Duration::from_secs(2);
    let v4_uid = b"Legacy fixture";
    let v6_uid = b"Native fixture";
    let v4 = issue(&key, v4_uid, created, b"fixture", None)
        .unwrap()
        .certificate;
    let v6 = issue_for_profile(
        &peer,
        expected,
        ExportProfile::V6,
        v6_uid,
        created,
        b"fixture",
        None,
    )
    .unwrap()
    .certificate;

    let mut cert = SignedPublicKey::from_bytes(&v4[..]).unwrap();
    let rev = make_key_revocation(&key, &cert, created + 1);
    cert.details.revocation_signatures.push(rev);
    let revoked_v4 = cert.to_bytes().unwrap();

    let profiles = [
        (v4.as_slice(), v4_uid.as_slice()),
        (v6.as_slice(), v6_uid.as_slice()),
    ];
    let mut rng = StdRng::seed_from_u64(71);
    for [first, second] in [profiles, [profiles[1], profiles[0]]] {
        let mut local = Installation::new(SigningKey::from_bytes(&[72; 32]));
        let selected = local.selected();
        let (record, first_source) =
            import_peer(&mut local, first.0, expected, first.1, now, &mut rng).unwrap();
        assert_eq!(
            record.verification_status,
            VerificationStatus::ImportedUnverified
        );
        let contact_id = record.local_contact_id;
        let (record, second_source) =
            import_peer(&mut local, second.0, expected, second.1, now, &mut rng).unwrap();
        assert_eq!(record.local_contact_id, contact_id);
        assert_ne!(first_source.primary, second_source.primary);
        assert_ne!(first_source.signing_key, second_source.signing_key);
        assert_eq!(first_source.user_id, first.1);
        assert_eq!(second_source.user_id, second.1);

        let (initiator, offer) = local.start(1, &mut rng).unwrap();
        let responder = peer.open_scanner(1).unwrap();
        let response = peer.scan_offer(&responder, &offer, 1, &mut rng).unwrap();
        let reveal = local.scan_response(&initiator, &response, 1).unwrap();
        peer.scan_reveal(&responder, &reveal, 1).unwrap();
        let local_code = local.comparison(&initiator, 1).unwrap().unwrap();
        let peer_code = peer.comparison(&responder, 1).unwrap().unwrap();
        let verified = local
            .confirm_and_save(&initiator, local_code, peer_code.code, 1, 1, &mut rng)
            .unwrap()
            .clone();
        peer.confirm_and_save(&responder, peer_code, local_code.code, 1, 1, &mut rng)
            .unwrap();
        assert_eq!(verified.local_contact_id, contact_id);
        assert_eq!(verified.encounter_count, 1);

        assert!(matches!(
            import_peer(&mut local, &revoked_v4, expected, v4_uid, now, &mut rng),
            Err(ImportError::InvalidBinding)
        ));
        let (record, _) = import_peer(&mut local, &v6, expected, v6_uid, now, &mut rng).unwrap();
        assert_eq!(record, &verified);
        assert_eq!(local.contacts(selected).unwrap().count(), 1);
    }
}

#[test]
fn protected_secret_import_unlocks_only_the_selected_owned_identity() {
    let created_secs = 1_750_000_000;
    let created = UNIX_EPOCH + Duration::from_secs(u64::from(created_secs));
    let now = created + Duration::from_secs(1);
    let mut seed = [17; 32];
    seed[0] = 0;
    let key = SigningKey::from_bytes(&seed);
    let expected = key.verifying_key().to_bytes();
    let uid = b"Protected certificate fixture";

    let (mut primary_sec, primary_pub) = make_primary_secret(&key, created_secs);
    let mut config = pgp::packet::SignatureConfig::v4(
        pgp::packet::SignatureType::CertPositive,
        pgp::crypto::public_key::PublicKeyAlgorithm::EdDSALegacy,
        pgp::crypto::hash::HashAlgorithm::Sha256,
    );
    let mut keyflags = pgp::packet::KeyFlags::default();
    keyflags.set_certify(true);
    keyflags.set_sign(true);
    config.hashed_subpackets = vec![
        pgp::packet::Subpacket::regular(pgp::packet::SubpacketData::SignatureCreationTime(
            pgp::types::Timestamp::from_secs(created_secs),
        ))
        .unwrap(),
        pgp::packet::Subpacket::regular(pgp::packet::SubpacketData::IssuerFingerprint(
            primary_sec.fingerprint(),
        ))
        .unwrap(),
        pgp::packet::Subpacket::regular(pgp::packet::SubpacketData::KeyFlags(keyflags)).unwrap(),
        pgp::packet::Subpacket::regular(pgp::packet::SubpacketData::IsPrimary(true)).unwrap(),
    ];
    config.unhashed_subpackets = vec![
        pgp::packet::Subpacket::regular(pgp::packet::SubpacketData::IssuerKeyId(
            primary_sec.legacy_key_id(),
        ))
        .unwrap(),
    ];

    let user_id_packet =
        pgp::packet::UserId::from_str(Default::default(), std::str::from_utf8(uid).unwrap())
            .unwrap();
    let sig = config
        .sign_certification(
            &primary_sec,
            &primary_pub,
            &pgp::types::Password::empty(),
            pgp::types::Tag::UserId,
            &user_id_packet,
        )
        .unwrap();
    let signed_user = pgp::types::SignedUser::new(user_id_packet, vec![sig]);
    let details = pgp::composed::SignedKeyDetails::new(vec![], vec![], vec![signed_user], vec![]);

    primary_sec
        .set_password(
            rand::rngs::OsRng,
            &pgp::types::Password::from("fixture passphrase"),
        )
        .unwrap();

    let secret_cert = SignedSecretKey::new(primary_sec, details.clone(), vec![], vec![]);
    let secret_bytes = secret_cert.to_bytes().unwrap();
    let public_cert = SignedPublicKey::new(primary_pub, details, vec![]);
    let public_bytes = public_cert.to_bytes().unwrap();

    let mut local = Installation::new(SigningKey::from_bytes(&[18; 32]));
    let original = local.selected();
    let mut rng = StdRng::seed_from_u64(2);
    assert!(matches!(
        import_peer(&mut local, &secret_bytes, expected, uid, now, &mut rng),
        Err(ImportError::SecretMaterial)
    ));
    assert!(matches!(
        import_owned(
            &mut local,
            &public_bytes,
            expected,
            uid,
            now,
            b"fixture passphrase"
        ),
        Err(ImportError::SecretMissing)
    ));
    assert!(matches!(
        import_owned(
            &mut local,
            &secret_bytes,
            [0; 32],
            uid,
            now,
            b"fixture passphrase"
        ),
        Err(ImportError::KeyMismatch)
    ));
    assert!(matches!(
        import_owned(&mut local, &secret_bytes, expected, uid, now, b"wrong"),
        Err(ImportError::UnlockFailed)
    ));
    assert!(local.contacts(expected).is_none());

    let provenance = import_owned(
        &mut local,
        &secret_bytes,
        expected,
        uid,
        now,
        b"fixture passphrase",
    )
    .unwrap();
    assert_eq!(provenance.primary, public_cert.primary_key.fingerprint());
    assert_eq!(
        provenance.signing_key,
        public_cert.primary_key.fingerprint()
    );
    assert_eq!(local.selected(), original);
    assert!(matches!(
        import_owned(
            &mut local,
            &secret_bytes,
            expected,
            uid,
            now,
            b"fixture passphrase"
        ),
        Err(ImportError::Contact(
            mesh_identity::session::installation::Error::DuplicateIdentity
        ))
    ));
    local.select(expected, 0).unwrap();
    assert_eq!(local.selected(), expected);
    assert_eq!(local.contacts(expected).unwrap().count(), 0);
}

#[test]
fn replacement_signing_subkey_import_preserves_distinct_contact_provenance() {
    let seed = [71; 32];
    let replacement_seed = [72; 32];
    let original = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
    let replacement = SigningKey::from_bytes(&replacement_seed)
        .verifying_key()
        .to_bytes();
    let uid = b"Rotation fixture";
    let RotationFixture {
        before,
        unbound,
        after,
        now,
    } = rotation_fixture(seed, replacement_seed, uid);

    let mut local = Installation::new(SigningKey::from_bytes(&[73; 32]));
    let selected = local.selected();
    let mut rng = StdRng::seed_from_u64(74);
    let (contact, original_source) =
        import_peer(&mut local, &before, original, uid, now, &mut rng).unwrap();
    let original_id = contact.local_contact_id;
    for certificate in [&before, &unbound] {
        assert!(matches!(
            import_peer(&mut local, certificate, replacement, uid, now, &mut rng),
            Err(ImportError::KeyMismatch)
        ));
    }
    assert_eq!(local.contacts(selected).unwrap().count(), 1);

    let (contact, replacement_source) =
        import_peer(&mut local, &after, replacement, uid, now, &mut rng).unwrap();
    assert_ne!(contact.local_contact_id, original_id);
    assert_eq!(
        contact.verification_status,
        VerificationStatus::ImportedUnverified
    );
    assert_eq!(replacement_source.primary, original_source.primary);
    assert_ne!(replacement_source.signing_key, original_source.signing_key);

    let (contact, repeated) =
        import_peer(&mut local, &after, original, uid, now, &mut rng).unwrap();
    assert_eq!(contact.local_contact_id, original_id);
    assert_eq!(repeated, original_source);
    assert_eq!(local.contacts(selected).unwrap().count(), 2);
}

#[test]
fn oversized_certificates_are_refused_before_parsing() {
    let mut local = Installation::new(SigningKey::from_bytes(&[51; 32]));
    let key = SigningKey::from_bytes(&[52; 32]).verifying_key().to_bytes();
    let mut rng = StdRng::seed_from_u64(1);
    let oversized = vec![0u8; MAX_CERTIFICATE_BYTES + 1];
    let now = UNIX_EPOCH + Duration::from_secs(1_750_000_000);
    assert!(matches!(
        import_peer(&mut local, &oversized, key, b"UID", now, &mut rng),
        Err(ImportError::Certificate(_))
    ));
    assert!(matches!(
        import_owned(&mut local, &oversized, key, b"UID", now, b""),
        Err(ImportError::Certificate(_))
    ));
    assert!(matches!(
        remember_peer_revocations(&mut local, &oversized),
        Err(ImportError::Certificate(_))
    ));
}

#[test]
fn issuance_uses_the_installation_key_and_refuses_a_changed_selection() {
    let mut installation = Installation::new(SigningKey::from_bytes(&[61; 32]));
    let shown = installation.selected();
    let other = installation
        .add_identity(SigningKey::from_bytes(&[62; 32]))
        .unwrap();
    let ok = issue_for(&installation, shown, b"UID", 1_750_000_000, b"doc", None).unwrap();
    assert!(!ok.certificate.is_empty());
    installation.select(other, 0).unwrap();
    assert!(issue_for(&installation, shown, b"UID", 1_750_000_000, b"doc", None).is_err());
}

#[test]
fn deferred_openpgp_confirmation_expires_on_selection_change_or_restart() {
    let key = SigningKey::from_bytes(&[63; 32]);
    let mut installation = Installation::new(key.clone());
    let selected = installation.selected();
    let other_key = SigningKey::from_bytes(&[64; 32]);
    let other = installation.add_identity(other_key.clone()).unwrap();
    let prepare = |installation: &mut Installation| {
        ExportPreview::new(
            installation,
            ExportProfile::V4,
            b"UID".to_vec(),
            1_750_000_000,
            b"document".to_vec(),
            None,
        )
        .unwrap()
    };

    let before_removal = prepare(&mut installation);
    installation.select(other, 0).unwrap();
    installation.remove_identity(selected).unwrap();
    installation.import_identity(key.clone(), selected).unwrap();
    installation.select(selected, 0).unwrap();
    assert!(before_removal.confirm(&mut installation).is_err());

    let before_restart = prepare(&mut installation);
    let checkpoint = installation.into_snapshot(0);
    let mut restored = Installation::restore(checkpoint, [key.clone(), other_key]).unwrap();
    assert!(before_restart.confirm(&mut restored).is_err());

    let wrong_installation = prepare(&mut restored);
    let mut same_key = Installation::new(key);
    assert_eq!(same_key.selected(), selected);
    let its_own_preview = prepare(&mut same_key);
    assert!(wrong_installation.confirm(&mut same_key).is_err());
    assert!(its_own_preview.confirm(&mut same_key).is_ok());
}

#[test]
fn openpgp_confirmation_issues_only_the_latest_previewed_inputs() {
    let mut installation = Installation::new(SigningKey::from_bytes(&[65; 32]));
    let created = 1_750_000_000;
    let superseded = ExportPreview::new(
        &mut installation,
        ExportProfile::V4,
        b"Old UID".to_vec(),
        created,
        b"Old document".to_vec(),
        None,
    )
    .unwrap();
    let peer_uid = b"Peer UID";
    let peer_certificate = issue(
        &SigningKey::from_bytes(&[66; 32]),
        peer_uid,
        created,
        b"peer fixture",
        None,
    )
    .unwrap()
    .certificate;
    let peer = SignedPublicKey::from_bytes(&peer_certificate[..]).unwrap();
    let current = ExportPreview::new(
        &mut installation,
        ExportProfile::V6,
        b"New UID".to_vec(),
        created,
        b"New document".to_vec(),
        Some((peer_certificate, peer_uid.to_vec())),
    )
    .unwrap();
    assert_eq!(current.identity(), installation.selected());
    assert_eq!(current.profile(), ExportProfile::V6);
    assert_eq!(current.user_id(), b"New UID");
    assert_eq!(current.document(), b"New document");
    assert_eq!(
        current.certification_target(),
        Some((&peer.primary_key.fingerprint(), peer_uid.as_slice()))
    );
    assert!(superseded.confirm(&mut installation).is_err());

    let artifacts = current.confirm(&mut installation).unwrap();
    let cert = SignedPublicKey::from_bytes(&artifacts.certificate[..]).unwrap();
    assert_eq!(cert.primary_key.version(), pgp::types::KeyVersion::V6);
    assert_eq!(cert.details.users.first().unwrap().id.id(), b"New UID");

    let detached = DetachedSignature::from_bytes(&artifacts.detached[..]).unwrap();
    detached.verify(&cert.primary_key, b"New document").unwrap();
    assert!(detached.verify(&cert.primary_key, b"Old document").is_err());

    let (_, cert_bytes) = artifacts
        .peer_signatures
        .iter()
        .find(|(name, _)| *name == "peer-certification.sig")
        .unwrap();
    let detached_sig = DetachedSignature::from_bytes(&cert_bytes[..]).unwrap();
    detached_sig
        .signature
        .verify_third_party_certification(
            &peer.primary_key,
            &cert.primary_key,
            pgp::types::Tag::UserId,
            &peer.details.users.first().unwrap().id,
        )
        .unwrap();
}

#[test]
fn export_preview_rejects_unbound_or_revoked_peer_user_id() {
    let mut installation = Installation::new(SigningKey::from_bytes(&[81; 32]));
    let created = 1_750_000_000;
    let peer_uid = b"Legitimate Peer UID";
    let peer_certificate = issue(
        &SigningKey::from_bytes(&[82; 32]),
        peer_uid,
        created,
        b"peer fixture",
        None,
    )
    .unwrap()
    .certificate;

    let spoofed = ExportPreview::new(
        &mut installation,
        ExportProfile::V6,
        b"Local UID".to_vec(),
        created,
        b"doc".to_vec(),
        Some((peer_certificate.clone(), b"Forged Peer UID".to_vec())),
    );
    assert!(matches!(spoofed, Err(ImportError::InvalidBinding)));

    let valid = ExportPreview::new(
        &mut installation,
        ExportProfile::V6,
        b"Local UID".to_vec(),
        created,
        b"doc".to_vec(),
        Some((peer_certificate, peer_uid.to_vec())),
    );
    assert!(valid.is_ok());
}

#[test]
fn export_preview_confirm_rejects_identity_mismatch() {
    let key_a = SigningKey::from_bytes(&[83; 32]);
    let mut installation = Installation::new(key_a);
    let id_a = installation.selected();
    let key_b = SigningKey::from_bytes(&[84; 32]);
    let id_b = installation.add_identity(key_b).unwrap();

    let preview = ExportPreview::new(
        &mut installation,
        ExportProfile::V6,
        b"Local UID".to_vec(),
        1_750_000_000,
        b"doc".to_vec(),
        None,
    )
    .unwrap();
    assert_eq!(preview.identity(), id_a);

    installation.select(id_b, 0).unwrap();
    let err = preview.confirm(&mut installation);
    assert!(err.is_err());
}

#[test]
fn peer_certificates_are_judged_now_and_size_capped_on_every_issue_path() {
    let mut installation = Installation::new(SigningKey::from_bytes(&[91; 32]));
    let created = 1_750_000_000;
    let uid = b"Peer";
    let current = issue(&SigningKey::from_bytes(&[92; 32]), uid, created, b"d", None)
        .unwrap()
        .certificate;
    let future = issue(
        &SigningKey::from_bytes(&[93; 32]),
        uid,
        4_000_000_000,
        b"d",
        None,
    )
    .unwrap()
    .certificate;
    assert!(
        ExportPreview::new(
            &mut installation,
            ExportProfile::V4,
            b"Me".to_vec(),
            4_000_000_000,
            b"d".to_vec(),
            Some((future.clone(), uid.to_vec())),
        )
        .is_err()
    );
    assert!(
        issue(
            &SigningKey::from_bytes(&[94; 32]),
            b"Me",
            4_000_000_000,
            b"d",
            Some((&future, uid)),
        )
        .is_err()
    );
    assert!(
        issue(
            &SigningKey::from_bytes(&[94; 32]),
            b"Me",
            created,
            b"d",
            Some((&current, uid))
        )
        .is_ok()
    );
    let huge = vec![0u8; 300 * 1024];
    assert!(
        issue(
            &SigningKey::from_bytes(&[94; 32]),
            b"Me",
            created,
            b"d",
            Some((&huge, uid))
        )
        .is_err()
    );
    assert!(matches!(
        ExportPreview::new(
            &mut installation,
            ExportProfile::V4,
            b"Me".to_vec(),
            created,
            b"d".to_vec(),
            Some((huge, uid.to_vec())),
        ),
        Err(ImportError::Certificate(_))
    ));
}

#[test]
fn remembered_revocations_stop_deferred_and_replayed_certification() {
    let created = 1_750_000_000;
    let issuer = SigningKey::from_bytes(&[95; 32]);
    let peer_key = SigningKey::from_bytes(&[96; 32]);
    let expected = peer_key.verifying_key().to_bytes();
    let uid = b"Peer UID";
    let peer_v4 = issue(&peer_key, uid, created, b"fixture", None)
        .unwrap()
        .certificate;
    let other_uid = b"Second UID";
    let other_binding = issue(&peer_key, other_uid, created, b"fixture", None)
        .unwrap()
        .certificate;
    let peer_installation = Installation::new(peer_key.clone());
    let peer_v6 = issue_for_profile(
        &peer_installation,
        expected,
        ExportProfile::V6,
        uid,
        created,
        b"fixture",
        None,
    )
    .unwrap()
    .certificate;

    let cert = SignedPublicKey::from_bytes(&peer_v4[..]).unwrap();
    let uid_rev = make_uid_revocation(&peer_key, &cert, uid, created + 1);
    let mut uid_cert = cert.clone();
    for u in &mut uid_cert.details.users {
        if u.id.id() == uid {
            u.signatures.push(uid_rev.clone());
        }
    }
    let uid_update = uid_cert.to_bytes().unwrap();

    let untrusted_rev = make_uid_revocation(&issuer, &cert, uid, created + 1);
    let mut untrusted_cert = cert.clone();
    for u in &mut untrusted_cert.details.users {
        if u.id.id() == uid {
            u.signatures.push(untrusted_rev.clone());
        }
    }
    let untrusted_update = untrusted_cert.to_bytes().unwrap();

    let cert_rev = make_key_revocation(&peer_key, &cert, created + 1);
    let mut key_cert = cert.clone();
    key_cert.details.revocation_signatures.push(cert_rev);
    let cert_update = key_cert.to_bytes().unwrap();

    for (update, whole_certificate) in [(uid_update, false), (cert_update, true)] {
        let mut local = Installation::new(issuer.clone());
        let selected = local.selected();
        let preview = ExportPreview::new(
            &mut local,
            ExportProfile::V4,
            b"Local".to_vec(),
            created,
            b"document".to_vec(),
            Some((peer_v4.clone(), uid.to_vec())),
        )
        .unwrap();
        assert_eq!(
            remember_peer_revocations(&mut local, &untrusted_update).unwrap(),
            0
        );
        assert_eq!(remember_peer_revocations(&mut local, &update).unwrap(), 1);
        assert_eq!(remember_peer_revocations(&mut local, &update).unwrap(), 0);
        assert_eq!(remember_peer_revocations(&mut local, &peer_v4).unwrap(), 0);
        assert!(preview.confirm(&mut local).is_err());

        let checkpoint = local.into_snapshot(0);
        let mut local = Installation::restore(checkpoint, [issuer.clone()]).unwrap();
        assert_eq!(local.selected(), selected);
        assert_eq!(
            remember_peer_revocations(&mut local, &untrusted_update).unwrap(),
            0
        );
        assert_eq!(remember_peer_revocations(&mut local, &update).unwrap(), 0);

        assert!(
            issue_for(
                &local,
                selected,
                b"Local",
                created,
                b"d",
                Some((&peer_v4, uid))
            )
            .is_err()
        );
        assert_eq!(
            issue_for(
                &local,
                selected,
                b"Local",
                created,
                b"d",
                Some((&other_binding, other_uid))
            )
            .is_err(),
            whole_certificate
        );
        assert!(
            issue_for(
                &local,
                selected,
                b"Local",
                created,
                b"d",
                Some((&peer_v6, uid))
            )
            .is_ok()
        );

        let now = UNIX_EPOCH + Duration::from_secs(u64::from(created) + 2);
        assert!(matches!(
            import_peer(
                &mut local,
                &peer_v4,
                expected,
                uid,
                now,
                &mut StdRng::seed_from_u64(95),
            ),
            Err(ImportError::InvalidBinding)
        ));
    }
}

#[test]
fn remembered_revocations_track_subkey_revocations() {
    let seed = [101; 32];
    let subkey_seed = [102; 32];
    let uid = b"Subkey Peer";
    let fixture = rotation_fixture(seed, subkey_seed, uid);
    let cert = SignedPublicKey::from_bytes(&fixture.after[..]).unwrap();
    let subkey = cert.public_subkeys.first().unwrap();
    let expected = SigningKey::from_bytes(&subkey_seed)
        .verifying_key()
        .to_bytes();

    let original_key = SigningKey::from_bytes(&seed);
    let revocation = make_subkey_revocation(
        &original_key,
        &cert,
        &subkey.key,
        fixture.now.duration_since(UNIX_EPOCH).unwrap().as_secs() as u32,
    );

    let mut revoked_cert = cert.clone();
    revoked_cert.public_subkeys[0].signatures.push(revocation);
    let revoked_cert_bytes = revoked_cert.to_bytes().unwrap();

    let mut local = Installation::new(SigningKey::from_bytes(&[103; 32]));
    assert_eq!(
        remember_peer_revocations(&mut local, &revoked_cert_bytes).unwrap(),
        1
    );

    assert!(matches!(
        import_peer(
            &mut local,
            &fixture.after,
            expected,
            uid,
            fixture.now + Duration::from_secs(1),
            &mut StdRng::seed_from_u64(104),
        ),
        Err(ImportError::KeyMismatch)
    ));
}

#[test]
fn flooding_revoked_certificates_never_blocks_imports_or_evicts_contacts() {
    let created = 1_750_000_000;
    let created_at = UNIX_EPOCH + Duration::from_secs(u64::from(created));
    let uid = b"Peer";
    let revoked_update = |key: &SigningKey| {
        let raw = issue(key, uid, created, b"d", None).unwrap().certificate;
        let mut cert = SignedPublicKey::from_bytes(&raw[..]).unwrap();
        let rev = make_key_revocation(key, &cert, created + 1);
        cert.details.revocation_signatures.push(rev);
        cert.to_bytes().unwrap()
    };
    let mut local = Installation::new(SigningKey::from_bytes(&[97; 32]));
    let mut rng = StdRng::seed_from_u64(1);

    let contact_key = SigningKey::from_bytes(&[98; 32]);
    let contact_cert = issue(&contact_key, uid, created, b"d", None)
        .unwrap()
        .certificate;
    import_peer(
        &mut local,
        &contact_cert,
        contact_key.verifying_key().to_bytes(),
        uid,
        created_at,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        remember_peer_revocations(&mut local, &revoked_update(&contact_key)).unwrap(),
        1
    );

    let promoted = SigningKey::from_bytes(&[101; 32]);
    let promoted_cert = issue(&promoted, uid, created, b"d", None)
        .unwrap()
        .certificate;
    let mut cert = SignedPublicKey::from_bytes(&promoted_cert[..]).unwrap();
    let rev = make_uid_revocation(&promoted, &cert, uid, created + 1);
    for u in &mut cert.details.users {
        if u.id.id() == uid {
            u.signatures.push(rev.clone());
        }
    }
    let update = cert.to_bytes().unwrap();
    assert_eq!(remember_peer_revocations(&mut local, &update).unwrap(), 1);
    let alternate = issue(&promoted, b"Alternate", created, b"d", None)
        .unwrap()
        .certificate;
    import_peer(
        &mut local,
        &alternate,
        promoted.verifying_key().to_bytes(),
        b"Alternate",
        created_at + Duration::from_secs(2),
        &mut rng,
    )
    .unwrap();

    let pending = SigningKey::from_bytes(&[102; 32]);
    let pending_cert = issue(&pending, uid, created, b"d", None)
        .unwrap()
        .certificate;
    let preview = ExportPreview::new(
        &mut local,
        ExportProfile::V4,
        b"Local".to_vec(),
        created,
        b"d".to_vec(),
        Some((pending_cert.clone(), uid.to_vec())),
    )
    .unwrap();
    assert_eq!(
        remember_peer_revocations(&mut local, &revoked_update(&pending)).unwrap(),
        1
    );

    // Strangers mint many revoked certificates (400 > 256 unknown FIFO capacity)
    for seed in 0..400u32 {
        let mut bytes = [0u8; 32];
        bytes[..4].copy_from_slice(&seed.to_be_bytes());
        bytes[31] = 1;
        let update = revoked_update(&SigningKey::from_bytes(&bytes));
        assert_eq!(remember_peer_revocations(&mut local, &update).unwrap(), 1);
    }

    assert!(preview.confirm(&mut local).is_err());
    assert!(
        ExportPreview::new(
            &mut local,
            ExportProfile::V4,
            b"Local".to_vec(),
            created,
            b"d".to_vec(),
            Some((pending_cert, uid.to_vec())),
        )
        .is_ok()
    );
    assert!(matches!(
        import_peer(
            &mut local,
            &promoted_cert,
            promoted.verifying_key().to_bytes(),
            uid,
            created_at + Duration::from_secs(5),
            &mut rng,
        ),
        Err(ImportError::InvalidBinding)
    ));

    let fresh = SigningKey::from_bytes(&[99; 32]);
    let fresh_cert = issue(&fresh, uid, created, b"d", None).unwrap().certificate;
    assert!(
        import_peer(
            &mut local,
            &fresh_cert,
            fresh.verifying_key().to_bytes(),
            uid,
            created_at,
            &mut rng,
        )
        .is_ok()
    );
    assert!(
        import_peer(
            &mut local,
            &contact_cert,
            contact_key.verifying_key().to_bytes(),
            uid,
            created_at + Duration::from_secs(5),
            &mut rng,
        )
        .is_err()
    );
}

#[test]
fn accepted_certificate_capacity_counts_fingerprints_and_leaves_contacts_intact() {
    let created = 1_750_000_000;
    let now = UNIX_EPOCH + Duration::from_secs(u64::from(created + 256));
    let key = SigningKey::from_bytes(&[109; 32]);
    let mut local = Installation::new(SigningKey::from_bytes(&[110; 32]));
    let local_key = local.selected();
    let mut rng = StdRng::seed_from_u64(44);
    let expected = key.verifying_key().to_bytes();
    let uid = b"Peer";
    for offset in 0..=256 {
        let certificate = issue(&key, uid, created + offset, b"d", None)
            .unwrap()
            .certificate;
        let result = import_peer(&mut local, &certificate, expected, uid, now, &mut rng);
        if offset == 256 {
            assert!(matches!(result, Err(ImportError::RevocationCapacity)));
        } else {
            assert!(result.is_ok());
        }
    }
    assert_eq!(local.contacts(local_key).unwrap().count(), 1);
    let first = issue(&key, uid, created, b"d", None).unwrap().certificate;
    assert!(import_peer(&mut local, &first, expected, uid, now, &mut rng).is_ok());
}

#[test]
fn unknown_certificate_preserves_revocations_and_overflow_when_promoted_to_contact() {
    let created = 1_700_000_000;
    let created_at = UNIX_EPOCH + Duration::from_secs(u64::from(created));
    let uid = b"Peer";
    let key = SigningKey::from_bytes(&[88; 32]);
    let raw_cert = issue(&key, uid, created, b"d", None).unwrap().certificate;
    let cert = SignedPublicKey::from_bytes(&raw_cert[..]).unwrap();

    let mut local = Installation::new(SigningKey::from_bytes(&[87; 32]));
    let mut rng = StdRng::seed_from_u64(42);

    let sig1 = make_uid_revocation(&key, &cert, uid, created + 1);
    let mut update1_cert = cert.clone();
    for u in &mut update1_cert.details.users {
        if u.id.id() == uid {
            u.signatures.push(sig1.clone());
        }
    }
    let update1 = update1_cert.to_bytes().unwrap();
    assert_eq!(remember_peer_revocations(&mut local, &update1).unwrap(), 1);

    assert!(matches!(
        import_peer(
            &mut local,
            &raw_cert,
            key.verifying_key().to_bytes(),
            uid,
            created_at + Duration::from_secs(2),
            &mut rng,
        ),
        Err(ImportError::InvalidBinding)
    ));

    let oflow_key = SigningKey::from_bytes(&[89; 32]);
    let oflow_raw = issue(&oflow_key, uid, created, b"d", None)
        .unwrap()
        .certificate;
    let oflow_cert = SignedPublicKey::from_bytes(&oflow_raw[..]).unwrap();

    let remember = |local: &mut Installation, sig| {
        let mut c = oflow_cert.clone();
        for u in &mut c.details.users {
            if u.id.id() == uid {
                u.signatures.push(sig);
                break;
            }
        }
        remember_peer_revocations(local, &c.to_bytes().unwrap())
    };

    for offset in 1..=16 {
        let sig = make_uid_revocation(&oflow_key, &oflow_cert, uid, created + offset);
        assert_eq!(remember(&mut local, sig).unwrap(), 1);
    }

    let sig17 = make_key_revocation(&oflow_key, &oflow_cert, created + 17);
    let mut c17 = oflow_cert.clone();
    c17.details.revocation_signatures.push(sig17);
    assert!(matches!(
        remember_peer_revocations(&mut local, &c17.to_bytes().unwrap()),
        Err(ImportError::RevocationCapacity)
    ));

    assert!(matches!(
        import_peer(
            &mut local,
            &oflow_raw,
            oflow_key.verifying_key().to_bytes(),
            uid,
            created_at + Duration::from_secs(20),
            &mut rng,
        ),
        Err(ImportError::RevocationCapacity)
    ));
}

#[test]
fn ordinary_import_remembers_unselected_uid_revocations_even_when_import_fails() {
    let key = SigningKey::from_bytes(&[120; 32]);
    let expected = key.verifying_key().to_bytes();
    let created = 1_750_000_000;
    let created_at = UNIX_EPOCH + Duration::from_secs(u64::from(created));
    let now = created_at + Duration::from_secs(2);
    let good = issue(&key, b"Good", created, b"fixture", None)
        .unwrap()
        .certificate;
    let revoked = issue(&key, b"Revoked", created, b"fixture", None)
        .unwrap()
        .certificate;

    let mut cert = SignedPublicKey::from_bytes(&good[..]).unwrap();
    let other_cert = SignedPublicKey::from_bytes(&revoked[..]).unwrap();
    cert.details.users.extend(other_cert.details.users);
    let original = cert.to_bytes().unwrap();

    let rev_sig = make_uid_revocation(&key, &cert, b"Revoked", created + 1);
    let mut updated_cert = cert.clone();
    for u in &mut updated_cert.details.users {
        if u.id.id() == b"Revoked" {
            u.signatures.push(rev_sig.clone());
        }
    }
    let updated = updated_cert.to_bytes().unwrap();

    for succeeds in [true, false] {
        let mut local = Installation::new(SigningKey::from_bytes(&[121; 32]));
        let mut rng = StdRng::seed_from_u64(909);
        let selected: &[u8] = if succeeds { b"Good" } else { b"Missing" };
        assert_eq!(
            import_peer(&mut local, &updated, expected, selected, now, &mut rng).is_ok(),
            succeeds
        );
        let mut local =
            Installation::restore(local.into_snapshot(0), [SigningKey::from_bytes(&[121; 32])])
                .unwrap();
        assert!(matches!(
            import_peer(&mut local, &original, expected, b"Revoked", now, &mut rng),
            Err(ImportError::InvalidBinding)
        ));
        assert!(import_peer(&mut local, &original, expected, b"Good", now, &mut rng).is_ok());
    }

    let (primary_sec, _) = make_primary_secret(&key, created);
    let secret_cert =
        SignedSecretKey::new(primary_sec.clone(), cert.details.clone(), vec![], vec![]);
    let secret_original = secret_cert.to_bytes().unwrap();
    let secret_updated_cert =
        SignedSecretKey::new(primary_sec, updated_cert.details.clone(), vec![], vec![]);
    let secret_updated = secret_updated_cert.to_bytes().unwrap();

    for succeeds in [true, false] {
        let mut local = Installation::new(SigningKey::from_bytes(&[121; 32]));
        let selected: &[u8] = if succeeds { b"Good" } else { b"Missing" };
        let imported = import_owned(&mut local, &secret_updated, expected, selected, now, b"");
        assert_eq!(imported.is_ok(), succeeds, "{imported:?}");
        assert!(matches!(
            import_owned(&mut local, &secret_original, expected, b"Revoked", now, b""),
            Err(ImportError::InvalidBinding)
        ));
    }
}

#[test]
fn openpgp_contact_import_preserves_snapshot_save_and_restore() {
    let local_key = SigningKey::from_bytes(&[130; 32]);
    let mut local = Installation::new(local_key.clone());
    let peer_key = SigningKey::from_bytes(&[131; 32]);
    let peer_expected = peer_key.verifying_key().to_bytes();
    let uid = b"Saved Peer";
    let created = 1_750_000_000;
    let now = UNIX_EPOCH + Duration::from_secs(u64::from(created) + 1);
    let cert = issue(&peer_key, uid, created, b"fixture", None)
        .unwrap()
        .certificate;
    let mut rng = StdRng::seed_from_u64(42);

    // Import unrevoked OpenPGP contact
    let (record, provenance) =
        import_peer(&mut local, &cert, peer_expected, uid, now, &mut rng).unwrap();
    assert_eq!(record.peer_ed25519_pk, peer_expected);
    assert_eq!(provenance.primary, provenance.signing_key);

    // Snapshot save MUST succeed (Codex finding 1 regression test)
    let saved = local.save_bytes(u64::from(created) + 10).unwrap();
    assert!(!saved.is_empty());

    // Restore from saved bytes MUST succeed and keep the contact
    let restored = Installation::restore_bytes(&saved, [local_key]).unwrap();
    assert_eq!(restored.total_contacts(), 1);
}
