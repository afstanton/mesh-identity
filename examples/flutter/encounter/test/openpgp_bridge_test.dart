import 'dart:convert';
import 'dart:typed_data';

import 'package:encounter/features/identity/identity_view.dart';
import 'package:encounter/features/identity/openpgp_bridge_screen.dart';
import 'package:encounter/services/handoff_outbox.dart';
import 'package:encounter/services/hex_utils.dart';
import 'package:encounter/services/identity_controller.dart';
import 'package:encounter/services/keyring_service.dart';
import 'package:encounter/services/openpgp_codec.dart';
import 'package:encounter/services/snapshot_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mesh_identity/mesh_identity.dart';

class _FakeClock {
  DateTime current;

  _FakeClock([DateTime? initial])
    : current = initial ?? DateTime.utc(2026, 6, 1, 12, 0, 0);

  DateTime call() => current;
}

class _ControllableStorage implements SnapshotStorageService {
  final InMemorySnapshotStorageService inner = InMemorySnapshotStorageService();
  bool failNextSave = false;

  @override
  Future<bool> hasSnapshot() => inner.hasSnapshot();

  @override
  Future<Uint8List?> loadSnapshot() => inner.loadSnapshot();

  @override
  Future<void> saveSnapshot(Uint8List bytes) async {
    if (failNextSave) {
      failNextSave = false;
      throw StateError('Simulated snapshot write failure');
    }
    await inner.saveSnapshot(bytes);
  }

  @override
  Future<String?> archiveSnapshot() => inner.archiveSnapshot();

  @override
  Future<void> deleteSnapshot() => inner.deleteSnapshot();
}

Uint8List _hexToBytes(String hex) {
  final clean = hex.replaceAll(RegExp(r'\s+'), '');
  final out = Uint8List(clean.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(clean.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

void main() {
  test('openpgp_codec handles ASCII armor, base64, and enforces 256 KiB bound', () {
    final armor =
        '-----BEGIN PGP PUBLIC KEY BLOCK-----\nABC\n-----END PGP PUBLIC KEY BLOCK-----';
    expect(utf8.decode(decodeOpenPgpInput(armor)), armor);

    final raw = Uint8List.fromList([1, 2, 3, 4, 5, 6]);
    final b64 = encodeOpenPgpBase64(raw);
    expect(decodeOpenPgpInput('  $b64  '), equals(raw));

    expect(() => decodeOpenPgpInput('   '), throwsFormatException);
    expect(
      () => decodeOpenPgpInput(
        'A' * (MeshInstallation.maxOpenPgpCertificateBytes * 2),
      ),
      throwsFormatException,
    );
    expect(formatOpenPgpFingerprint('abcd1234ef56'), 'ABCD 1234 EF56');

    final armoredV4 = encodeOpenPgpArmor(
      raw,
      blockType: 'PGP PUBLIC KEY BLOCK',
      includeCrc24: true,
    );
    expect(armoredV4, contains('-----BEGIN PGP PUBLIC KEY BLOCK-----'));
    expect(armoredV4, contains('\n='));
    expect(utf8.decode(decodeOpenPgpInput(armoredV4)), armoredV4);

    final armoredV6 = encodeOpenPgpArmor(
      raw,
      blockType: 'PGP SIGNATURE',
      includeCrc24: false,
    );
    expect(armoredV6, contains('-----BEGIN PGP SIGNATURE-----'));
    expect(utf8.decode(decodeOpenPgpInput(armoredV6)), armoredV6);
  });

  test('IdentityController OpenPGP export preview, cross-certification, persona-switch expiration, peer import, and revocation persist', () async {
    final clock = _FakeClock();
    final aliceKeyring = InMemoryKeyringService();
    final aliceStorage = InMemorySnapshotStorageService();
    final aliceHandoffOutbox = InMemoryHandoffOutboxService();
    final alice = IdentityController(
      keyring: aliceKeyring,
      storage: aliceStorage,
      handoffOutbox: aliceHandoffOutbox,
      clock: clock.call,
    );
    final bob = IdentityController(
      keyring: InMemoryKeyringService(),
      storage: InMemorySnapshotStorageService(),
      handoffOutbox: InMemoryHandoffOutboxService(),
      clock: clock.call,
    );
    await alice.initialize();
    await bob.initialize();

    // 1. Bob exports a v6 certificate
    final bobPreview = await bob.createOpenPgpPreview(
      profile: OpenPgpProfile.v6,
      userId: 'Bob <bob@mesh.org>',
      document: Uint8List.fromList(utf8.encode('bob-doc')),
    );
    expect(bobPreview.warning, OpenPgpExportPreview.privacyWarning);
    final bobArtifacts = await bob.confirmOpenPgpPreview(bobPreview);
    final bobCert = alice.inspectOpenPgpCertificate(bobArtifacts.certificate);
    expect(bobCert.version, 6);
    expect(bobCert.userIds, contains('Bob <bob@mesh.org>'));

    // 2. Alice exports v4 certificate with cross-certification for Bob
    final alicePreview = await alice.createOpenPgpPreview(
      profile: OpenPgpProfile.v4,
      userId: 'Alice <alice@mesh.org>',
      document: Uint8List.fromList(utf8.encode('alice-doc')),
      peerCertificate: bobArtifacts.certificate,
      peerUserId: 'Bob <bob@mesh.org>',
    );
    expect(alicePreview.peerCertificationFingerprint, isNotNull);
    final aliceArtifacts = await alice.confirmOpenPgpPreview(alicePreview);
    expect(aliceArtifacts.certificate, isNotEmpty);
    expect(aliceArtifacts.detachedSignature, isNotEmpty);
    expect(aliceArtifacts.peerSignatures, hasLength(4));

    // 3. Persona switch invalidates active preview
    final stalePreview = await alice.createOpenPgpPreview(
      profile: OpenPgpProfile.v4,
      userId: 'Alice <alice@mesh.org>',
      document: Uint8List.fromList(utf8.encode('doc2')),
    );
    final persona2 = await alice.addPersona();
    await alice.selectPersona(persona2);
    await expectLater(
      alice.confirmOpenPgpPreview(stalePreview),
      throwsA(isA<OpenPgpPreviewExpiredException>()),
    );
    stalePreview.dispose();

    // 4. Alice imports Bob's OpenPGP certificate as an unverified contact & restarts
    final prov = await alice.importOpenPgpPeer(
      certificate: bobArtifacts.certificate,
      expectedPublicKey: bob.selectedIdentity!,
      userId: 'Bob <bob@mesh.org>',
    );
    expect(prov.userId, 'Bob <bob@mesh.org>');
    expect(alice.contactsCount, 1);
    expect(
      alice.contacts.first.verificationStatus,
      VerificationStatus.importedUnverified,
    );

    // 5. Active encounter blocks OpenPGP mutations
    await alice.startEncounterAsInitiator();
    await expectLater(
      alice.rememberOpenPgpRevocations(Uint8List.fromList([1, 2, 3])),
      throwsA(isA<CeremonyActiveException>()),
    );
    await alice.cancelActiveEncounter();

    alice.dispose();
    bob.dispose();

    // Cold restart preserves imported OpenPGP contact
    final restarted = IdentityController(
      keyring: aliceKeyring,
      storage: aliceStorage,
      handoffOutbox: aliceHandoffOutbox,
      clock: clock.call,
    );
    addTearDown(restarted.dispose);
    await restarted.initialize();
    expect(restarted.contactsCountForPersona(persona2), 1);
  });

  test('IdentityController.importOpenPgpOwned persists seed to keyring, survives restart, and rolls back on storage failure', () async {
    const fixtureSecretHex =
        'c58504684ee18016092b06010401da470f010107400392792031b6ea1dde02c5e383b84744dbd661b21b70d1778c484cce6bf28f06fe0903082824f04c07c8a0a8e0349f374e1f83e73a43aae98133234ecf76eaff13f47b1104aa4e35d18d2fdf5c1a4c35f3b0234a776b433e43972765fdab760f7e54ea3c53727021ec4a947b2a0e26519803cd1d50726f7465637465642063657274696669636174652066697874757265c27b0413160800230502684ee18016210417031e12de755edaf4c9981476322c1e4b10409d021b03021901000a091076322c1e4b10409dea7100ff43b20203e8ad0432035b6ce1c73bc623f0bca101d101e3b62ca44f72b5fe6e1300ff69a029e2a08f00208fdefdc65b69729f7d063dfdda836641a8386f7bc9882102';
    const fixtureExpectedPkHex =
        '0392792031b6ea1dde02c5e383b84744dbd661b21b70d1778c484cce6bf28f06';
    final secretBytes = _hexToBytes(fixtureSecretHex);
    final expectedPk = _hexToBytes(fixtureExpectedPkHex);

    // Fixed timestamp inside the fixture's certificate validity window
    final clock = _FakeClock(
      DateTime.fromMillisecondsSinceEpoch(1750000001000, isUtc: true),
    );
    final keyring = InMemoryKeyringService();
    final storage = _ControllableStorage();
    final handoffOutbox = InMemoryHandoffOutboxService();
    final ctrl = IdentityController(
      keyring: keyring,
      storage: storage,
      handoffOutbox: handoffOutbox,
      clock: clock.call,
    );
    await ctrl.initialize();

    // Rollback on storage failure removes seed and preserves persona count
    storage.failNextSave = true;
    await expectLater(
      ctrl.importOpenPgpOwned(
        secretKeyCertificate: secretBytes,
        expectedPublicKey: expectedPk,
        userId: 'Protected certificate fixture',
        passphrase: 'fixture passphrase',
      ),
      throwsStateError,
    );
    expect(ctrl.identities.length, 1);
    expect(await keyring.getSeed(expectedPk), isNull);

    // Successful owned import saves seed and survives cold restart
    final prov = await ctrl.importOpenPgpOwned(
      secretKeyCertificate: secretBytes,
      expectedPublicKey: expectedPk,
      userId: 'Protected certificate fixture',
      passphrase: 'fixture passphrase',
    );
    expect(prov.userId, 'Protected certificate fixture');
    expect(ctrl.identities.length, 2);
    expect(await keyring.getSeed(expectedPk), isNotNull);

    ctrl.dispose();

    final restarted = IdentityController(
      keyring: keyring,
      storage: storage,
      handoffOutbox: handoffOutbox,
      clock: clock.call,
    );
    addTearDown(restarted.dispose);
    await restarted.initialize();
    expect(restarted.identities.length, 2);
  });

  testWidgets(
    'IdentityView -> OpenPgpBridgeScreen inspects, previews with statutory warning, confirms export, and imports peer',
    (tester) async {
      final clock = _FakeClock();
      final alice = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
        clock: clock.call,
      );
      final bob = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
        clock: clock.call,
      );
      await alice.initialize();
      await bob.initialize();
      addTearDown(alice.dispose);
      addTearDown(bob.dispose);

      // Bob generates a cert to inspect & import in UI
      final bobPreview = await bob.createOpenPgpPreview(
        profile: OpenPgpProfile.v4,
        userId: 'Bob <bob@mesh.org>',
        document: Uint8List.fromList(utf8.encode('hello')),
      );
      final bobArtifacts = await bob.confirmOpenPgpPreview(bobPreview);
      final bobCertB64 = encodeOpenPgpBase64(bobArtifacts.certificate);
      final bobKeyHex = bytesToHex(bob.selectedIdentity!);

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(body: IdentityView(controller: alice)),
        ),
      );
      await tester.pumpAndSettle();

      await tester.scrollUntilVisible(
        find.byKey(const Key('open_openpgp_bridge_button')),
        200,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.ensureVisible(
        find.byKey(const Key('open_openpgp_bridge_button')),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('open_openpgp_bridge_button')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('openpgp_scroll_view')), findsOneWidget);

      // 1. Inspect Bob's cert -> shows unauthenticated warning
      await tester.enterText(
        find.byKey(const Key('openpgp_inspect_field')),
        bobCertB64,
      );
      await tester.tap(find.byKey(const Key('openpgp_inspect_button')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('openpgp_inspect_result')), findsOneWidget);
      expect(find.textContaining('Unauthenticated'), findsOneWidget);

      // 2. Preview export -> shows statutory privacy warning -> confirm emits artifacts
      await tester.scrollUntilVisible(
        find.byKey(const Key('openpgp_export_uid_field')),
        200,
        scrollable: find
            .descendant(
              of: find.byKey(const Key('openpgp_scroll_view')),
              matching: find.byType(Scrollable),
            )
            .first,
      );
      await tester.ensureVisible(
        find.byKey(const Key('openpgp_export_uid_field')),
      );
      await tester.pumpAndSettle();
      await tester.enterText(
        find.byKey(const Key('openpgp_export_uid_field')),
        'Alice <alice@mesh.org>',
      );
      await tester.scrollUntilVisible(
        find.byKey(const Key('openpgp_preview_button')),
        200,
        scrollable: find
            .descendant(
              of: find.byKey(const Key('openpgp_scroll_view')),
              matching: find.byType(Scrollable),
            )
            .first,
      );
      await tester.ensureVisible(
        find.byKey(const Key('openpgp_preview_button')),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('openpgp_preview_button')));
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('openpgp_preview_card')), findsOneWidget);
      expect(find.text(OpenPgpExportPreview.privacyWarning), findsOneWidget);

      // Editing an export input invalidates the active preview
      await tester.ensureVisible(
        find.byKey(const Key('openpgp_export_doc_field')),
      );
      await tester.pumpAndSettle();
      await tester.enterText(
        find.byKey(const Key('openpgp_export_doc_field')),
        'Edited statement',
      );
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('openpgp_preview_card')), findsNothing);

      // Re-create preview with updated document and confirm
      await tester.ensureVisible(
        find.byKey(const Key('openpgp_preview_button')),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('openpgp_preview_button')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('openpgp_preview_card')), findsOneWidget);

      await tester.scrollUntilVisible(
        find.byKey(const Key('openpgp_confirm_export_button')),
        150,
        scrollable: find
            .descendant(
              of: find.byKey(const Key('openpgp_scroll_view')),
              matching: find.byType(Scrollable),
            )
            .first,
      );
      await tester.ensureVisible(
        find.byKey(const Key('openpgp_confirm_export_button')),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('openpgp_confirm_export_button')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('openpgp_artifacts_card')), findsOneWidget);

      // 3. Import Bob's peer cert
      await tester.scrollUntilVisible(
        find.byKey(const Key('openpgp_peer_cert_field')),
        250,
        scrollable: find
            .descendant(
              of: find.byKey(const Key('openpgp_scroll_view')),
              matching: find.byType(Scrollable),
            )
            .first,
      );
      await tester.ensureVisible(
        find.byKey(const Key('openpgp_peer_cert_field')),
      );
      await tester.pumpAndSettle();
      await tester.enterText(
        find.byKey(const Key('openpgp_peer_cert_field')),
        bobCertB64,
      );
      await tester.enterText(
        find.byKey(const Key('openpgp_peer_key_field')),
        bobKeyHex,
      );
      await tester.enterText(
        find.byKey(const Key('openpgp_peer_uid_field')),
        'Bob <bob@mesh.org>',
      );
      await tester.scrollUntilVisible(
        find.byKey(const Key('openpgp_import_peer_button')),
        150,
        scrollable: find
            .descendant(
              of: find.byKey(const Key('openpgp_scroll_view')),
              matching: find.byType(Scrollable),
            )
            .first,
      );
      await tester.ensureVisible(
        find.byKey(const Key('openpgp_import_peer_button')),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('openpgp_import_peer_button')));
      await tester.pumpAndSettle();

      expect(
        find.byKey(const Key('openpgp_peer_provenance_card')),
        findsOneWidget,
      );
      expect(alice.contactsCount, 1);

      // 4. Invalid revocation payload surfaces error banner
      await tester.scrollUntilVisible(
        find.byKey(const Key('openpgp_remember_revocations_button')),
        250,
        scrollable: find
            .descendant(
              of: find.byKey(const Key('openpgp_scroll_view')),
              matching: find.byType(Scrollable),
            )
            .first,
      );
      await tester.ensureVisible(
        find.byKey(const Key('openpgp_remember_revocations_button')),
      );
      await tester.pumpAndSettle();
      await tester.enterText(
        find.byKey(const Key('openpgp_revocation_field')),
        'not-valid-revocation-!@#',
      );
      await tester.pumpAndSettle();
      await tester.ensureVisible(
        find.byKey(const Key('openpgp_remember_revocations_button')),
      );
      await tester.pumpAndSettle();
      await tester.tap(
        find.byKey(const Key('openpgp_remember_revocations_button')),
      );
      await tester.pumpAndSettle();
      await tester.scrollUntilVisible(
        find.byKey(const Key('openpgp_error_banner')),
        -300,
        scrollable: find
            .descendant(
              of: find.byKey(const Key('openpgp_scroll_view')),
              matching: find.byType(Scrollable),
            )
            .first,
      );
      expect(find.byKey(const Key('openpgp_error_banner')), findsOneWidget);
    },
  );

  testWidgets(
    'OpenPgpBridgeScreen owned secret key import clears secret fields and displays provenance',
    (tester) async {
      const fixtureSecretHex =
          'c58504684ee18016092b06010401da470f010107400392792031b6ea1dde02c5e383b84744dbd661b21b70d1778c484cce6bf28f06fe0903082824f04c07c8a0a8e0349f374e1f83e73a43aae98133234ecf76eaff13f47b1104aa4e35d18d2fdf5c1a4c35f3b0234a776b433e43972765fdab760f7e54ea3c53727021ec4a947b2a0e26519803cd1d50726f7465637465642063657274696669636174652066697874757265c27b0413160800230502684ee18016210417031e12de755edaf4c9981476322c1e4b10409d021b03021901000a091076322c1e4b10409dea7100ff43b20203e8ad0432035b6ce1c73bc623f0bca101d101e3b62ca44f72b5fe6e1300ff69a029e2a08f00208fdefdc65b69729f7d063dfdda836641a8386f7bc9882102';
      const fixtureExpectedPkHex =
          '0392792031b6ea1dde02c5e383b84744dbd661b21b70d1778c484cce6bf28f06';
      final clock = _FakeClock(
        DateTime.fromMillisecondsSinceEpoch(1750000001000, isUtc: true),
      );
      final ctrl = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
        clock: clock.call,
      );
      await ctrl.initialize();
      addTearDown(ctrl.dispose);

      await tester.pumpWidget(
        MaterialApp(home: OpenPgpBridgeScreen(controller: ctrl)),
      );
      await tester.pumpAndSettle();

      await tester.scrollUntilVisible(
        find.byKey(const Key('openpgp_import_owned_button')),
        300,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.ensureVisible(
        find.byKey(const Key('openpgp_owned_cert_field')),
      );
      await tester.enterText(
        find.byKey(const Key('openpgp_owned_cert_field')),
        encodeOpenPgpBase64(_hexToBytes(fixtureSecretHex)),
      );
      await tester.enterText(
        find.byKey(const Key('openpgp_owned_key_field')),
        fixtureExpectedPkHex,
      );
      await tester.enterText(
        find.byKey(const Key('openpgp_owned_uid_field')),
        'Protected certificate fixture',
      );
      await tester.enterText(
        find.byKey(const Key('openpgp_owned_passphrase_field')),
        'fixture passphrase',
      );
      await tester.ensureVisible(
        find.byKey(const Key('openpgp_import_owned_button')),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('openpgp_import_owned_button')));
      await tester.pumpAndSettle();

      await tester.scrollUntilVisible(
        find.byKey(const Key('openpgp_owned_provenance_card')),
        300,
        scrollable: find
            .descendant(
              of: find.byKey(const Key('openpgp_scroll_view')),
              matching: find.byType(Scrollable),
            )
            .first,
      );
      expect(
        find.byKey(const Key('openpgp_owned_provenance_card')),
        findsOneWidget,
      );
      expect(ctrl.identities.length, 2);

      // Secret fields are cleared after import
      final certField = tester.widget<TextField>(
        find.byKey(const Key('openpgp_owned_cert_field')),
      );
      final passField = tester.widget<TextField>(
        find.byKey(const Key('openpgp_owned_passphrase_field')),
      );
      expect(certField.controller!.text, isEmpty);
      expect(passField.controller!.text, isEmpty);
    },
  );
}
