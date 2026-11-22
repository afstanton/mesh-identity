import 'package:encounter/features/contacts/contacts_view.dart';
import 'package:encounter/services/encounter_session.dart';
import 'package:encounter/services/identity_controller.dart';
import 'package:encounter/services/keyring_service.dart';
import 'package:encounter/services/snapshot_storage.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mesh_identity/mesh_identity.dart';

class _FakeClock {
  DateTime current;

  _FakeClock([DateTime? initial])
    : current =
          initial ?? DateTime.fromMillisecondsSinceEpoch(1_700_000_000_000);

  DateTime call() => current;
}

Widget _wrap(IdentityController controller) {
  return MaterialApp(
    home: Scaffold(
      body: ListenableBuilder(
        listenable: controller,
        builder: (context, _) => ContactsView(controller: controller),
      ),
    ),
  );
}

Uint8List _validPeerPublicKey(int seedByte) {
  final seed = Uint8List.fromList(List<int>.filled(32, seedByte));
  final temp = MeshInstallation(seed: seed);
  try {
    return Uint8List.fromList(temp.selectedIdentity);
  } finally {
    temp.dispose();
  }
}

void main() {
  testWidgets('imports unverified peer key, validates hex, and filters', (
    tester,
  ) async {
    final keyring = InMemoryKeyringService();
    final storage = InMemorySnapshotStorageService();
    final clock = _FakeClock();
    final controller = IdentityController(
      keyring: keyring,
      storage: storage,
      clock: clock.call,
    );
    addTearDown(controller.dispose);
    await controller.initialize();

    await tester.pumpWidget(_wrap(controller));
    expect(find.text('No contacts yet'), findsOneWidget);

    // Open Import Peer Key dialog and test invalid hex
    await tester.tap(find.byKey(const Key('import_peer_key_button')));
    await tester.pumpAndSettle();

    await tester.enterText(
      find.byKey(const Key('import_peer_key_field')),
      'not-hex',
    );
    await tester.tap(find.byKey(const Key('confirm_import_peer_key_button')));
    await tester.pumpAndSettle();
    expect(
      find.text('Enter a 64-character hexadecimal Ed25519 public key.'),
      findsOneWidget,
    );

    // Enter valid 64-char hex key
    final peerA = _validPeerPublicKey(0x11);
    final peerAHex = formatHexKey(peerA);
    await tester.enterText(
      find.byKey(const Key('import_peer_key_field')),
      peerAHex,
    );
    await tester.tap(find.byKey(const Key('confirm_import_peer_key_button')));
    await tester.pumpAndSettle();

    expect(controller.contactsCount, 1);
    expect(find.text('Imported (Unverified)'), findsOneWidget);

    // Filter to Verified -> empty match
    await tester.tap(find.byKey(const Key('filter_verified')));
    await tester.pumpAndSettle();
    expect(find.text('No matching contacts'), findsOneWidget);

    // Filter to Unverified -> visible
    await tester.tap(find.byKey(const Key('filter_unverified')));
    await tester.pumpAndSettle();
    expect(find.byKey(Key('contact_tile_$peerAHex')), findsOneWidget);
  });

  testWidgets('alias editing, conflict warning, block/unblock, and restart', (
    tester,
  ) async {
    final keyring = InMemoryKeyringService();
    final storage = InMemorySnapshotStorageService();
    final clock = _FakeClock();
    final controller = IdentityController(
      keyring: keyring,
      storage: storage,
      clock: clock.call,
    );
    await controller.initialize();

    final peerA = _validPeerPublicKey(0x21);
    final peerB = _validPeerPublicKey(0x22);
    await controller.importPeerKey(peerA);
    await controller.importPeerKey(peerB);
    await controller.setContactAlias(peerA, 'Alice');

    await tester.pumpWidget(_wrap(controller));
    await tester.pumpAndSettle();

    // Open Peer B detail and test alias conflict with 'alice' (case-insensitive)
    final peerBHex = formatHexKey(peerB);
    await tester.tap(find.byKey(Key('contact_tile_$peerBHex')));
    await tester.pumpAndSettle();

    await tester.enterText(find.byKey(const Key('alias_input_field')), 'alice');
    await tester.tap(find.byKey(const Key('save_alias_button')));
    await tester.pumpAndSettle();
    expect(find.text(EncounterUiText.aliasConflictWarning), findsOneWidget);

    // Set unique alias 'Bob'
    await tester.enterText(find.byKey(const Key('alias_input_field')), 'Bob');
    await tester.tap(find.byKey(const Key('save_alias_button')));
    await tester.pumpAndSettle();
    expect(find.text('Alias updated.'), findsOneWidget);

    // Block Bob with confirmation
    await tester.ensureVisible(find.byKey(const Key('block_contact_button')));
    await tester.tap(find.byKey(const Key('block_contact_button')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('confirm_block_contact_button')));
    await tester.pumpAndSettle();
    expect(find.text('Contact blocked.'), findsOneWidget);

    // Unblock Bob
    await tester.ensureVisible(find.byKey(const Key('unblock_contact_button')));
    await tester.tap(find.byKey(const Key('unblock_contact_button')));
    await tester.pumpAndSettle();
    expect(find.text('Contact unblocked.'), findsOneWidget);

    // Close dialog
    await tester.tap(find.text('Close'));
    await tester.pumpAndSettle();

    // Verify search by alias
    await tester.enterText(
      find.byKey(const Key('contacts_search_field')),
      'bob',
    );
    await tester.pumpAndSettle();
    expect(find.text('Bob'), findsOneWidget);
    expect(find.text('Alice'), findsNothing);

    // Verify persistence across cold restart
    controller.dispose();
    final restarted = IdentityController(
      keyring: keyring,
      storage: storage,
      clock: clock.call,
    );
    addTearDown(restarted.dispose);
    await restarted.initialize();
    expect(restarted.getContact(peerB)?.alias, 'Bob');
    expect(restarted.getContact(peerB)?.status, ContactStatus.active);
  });

  test('active-ceremony guards block contact mutations', () async {
    final controller = IdentityController(
      keyring: InMemoryKeyringService(),
      storage: InMemorySnapshotStorageService(),
      clock: _FakeClock().call,
    );
    addTearDown(controller.dispose);
    await controller.initialize();

    final peer = _validPeerPublicKey(0x33);
    await controller.importPeerKey(peer);
    await controller.startEncounterAsInitiator();
    expect(controller.hasActiveEncounter, isTrue);

    await expectLater(
      controller.importPeerKey(_validPeerPublicKey(0x34)),
      throwsA(isA<CeremonyActiveException>()),
    );
    await expectLater(
      controller.setContactAlias(peer, 'BlockedEdit'),
      throwsA(isA<CeremonyActiveException>()),
    );
    await expectLater(
      controller.blockContact(peer),
      throwsA(isA<CeremonyActiveException>()),
    );
    await expectLater(
      controller.unblockContact(peer),
      throwsA(isA<CeremonyActiveException>()),
    );
  });

  test('resolvePausedUntil uses RateLimitedException.untilMs', () {
    final now = DateTime.fromMillisecondsSinceEpoch(1_700_000_000_000);
    final withUntil = RateLimitedException(
      'paused',
      untilMs: 1_700_000_045_000,
    );
    expect(
      EncounterSessionState.resolvePausedUntil(withUntil, now),
      DateTime.fromMillisecondsSinceEpoch(1_700_000_045_000),
    );

    const withoutUntil = RateLimitedException('paused');
    expect(
      EncounterSessionState.resolvePausedUntil(withoutUntil, now),
      now.add(EncounterUiText.rateLimitPause),
    );
  });
}
