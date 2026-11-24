import 'dart:io';

import 'package:encounter/features/identity/device_handoff_screen.dart';
import 'package:encounter/features/identity/identity_view.dart';
import 'package:encounter/services/encounter_session.dart';
import 'package:encounter/services/handoff_codec.dart';
import 'package:encounter/services/handoff_outbox.dart';
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
      throw StateError('Simulated disk write failure');
    }
    await inner.saveSnapshot(bytes);
  }

  @override
  Future<String?> archiveSnapshot() => inner.archiveSnapshot();

  @override
  Future<void> deleteSnapshot() => inner.deleteSnapshot();
}

void main() {
  test('handoff_codec validates nonces, seeds, and rejects malformed/oversized bundles', () {
    final nonceHex = List<String>.filled(32, 'ab').join();
    final parsed = parseDeviceNonceHex('  0x$nonceHex  ');
    expect(parsed.length, 32);
    expect(parsed.every((b) => b == 0xab), isTrue);

    final grouped = formatGroupedHex(parsed);
    expect(grouped.split(' ').length, 8);
    expect(parseDeviceNonceHex(grouped), equals(parsed));

    final parsedSeed = parseHexSeed('0x$nonceHex');
    expect(parsedSeed, equals(parsed));

    expect(() => parseDeviceNonceHex('abcd'), throwsFormatException);
    expect(() => parseHexSeed('z' * 64), throwsFormatException);

    expect(() => decodeHandoffBundle('   '), throwsFormatException);
    expect(
      () => decodeHandoffBundle('mesh:handoff:!!!not-base64!!!'),
      throwsFormatException,
    );
    expect(
      () => decodeHandoffBundle(
        'mesh:handoff:${'A' * (maxHandoffBase64Chars + 1)}',
      ),
      throwsFormatException,
    );
  });

  test(
    'ensureDeviceNonce persists across cold restart and is idempotent',
    () async {
      final keyring = InMemoryKeyringService();
      final storage = InMemorySnapshotStorageService();
      final outbox = InMemoryHandoffOutboxService();
      final clock = _FakeClock();
      final controller = IdentityController(
        keyring: keyring,
        storage: storage,
        handoffOutbox: outbox,
        clock: clock.call,
      );
      await controller.initialize();

      expect(controller.deviceNonce, isNull);
      final nonce1 = await controller.ensureDeviceNonce();
      expect(nonce1.length, 32);
      expect(listEquals(controller.deviceNonce, nonce1), isTrue);

      final nonce2 = await controller.ensureDeviceNonce();
      expect(listEquals(nonce2, nonce1), isTrue);

      controller.dispose();
      final restarted = IdentityController(
        keyring: keyring,
        storage: storage,
        handoffOutbox: outbox,
        clock: clock.call,
      );
      addTearDown(restarted.dispose);
      await restarted.initialize();
      expect(listEquals(restarted.deviceNonce, nonce1), isTrue);
    },
  );

  test('two normally initialized devices transfer voting role via seed provisioning, '
      'persist pending outbox across restart, and reject self/wrong-recipient handoffs', () async {
    final clock = _FakeClock();

    // Normally initialize Device A and Device B independently
    final keyringA = InMemoryKeyringService();
    final storageA = _ControllableStorage();
    final outboxA = InMemoryHandoffOutboxService();
    final deviceA = IdentityController(
      keyring: keyringA,
      storage: storageA,
      handoffOutbox: outboxA,
      clock: clock.call,
    );
    await deviceA.initialize();

    final keyringB = InMemoryKeyringService();
    final storageB = InMemorySnapshotStorageService();
    final outboxB = InMemoryHandoffOutboxService();
    final deviceB = IdentityController(
      keyring: keyringB,
      storage: storageB,
      handoffOutbox: outboxB,
      clock: clock.call,
    );
    await deviceB.initialize();

    // Provision Device A's persona onto Device B using export/import
    final personaA = deviceA.selectedIdentity!;
    final exportedSeed = await deviceA.exportPersonaSeed(personaA);
    try {
      await deviceB.importPersonaSeed(exportedSeed);
    } finally {
      exportedSeed.fillRange(0, exportedSeed.length, 0);
    }
    await deviceB.selectPersona(personaA);
    // Imported persona starts in Gated state until handoff is accepted!
    expect(deviceB.selectedVotingState, VotingState.gated);

    final nonceA = await deviceA.ensureDeviceNonce();
    final nonceB = await deviceB.ensureDeviceNonce();

    // Self-handoff is rejected BEFORE mutating state
    await expectLater(
      deviceA.beginHandoff(nonceA),
      throwsA(isA<InvalidArgumentsException>()),
    );
    expect(deviceA.selectedVotingState, VotingState.voting);
    expect(deviceA.pendingOutboundHandoff, isNull);

    // Persistence failure during beginHandoff rolls back Device A and cleans outbox
    storageA.failNextSave = true;
    await expectLater(deviceA.beginHandoff(nonceB), throwsStateError);
    expect(deviceA.selectedVotingState, VotingState.voting);
    expect(deviceA.pendingOutboundHandoff, isNull);
    expect((await outboxA.loadAllPendingBundles()).bundles, isEmpty);

    // Successful beginHandoff persists bundle to outbox and stops Device A
    final bundle = await deviceA.beginHandoff(nonceB);
    expect(deviceA.selectedVotingState, VotingState.stopped);
    expect(deviceA.pendingOutboundHandoff, isNotNull);

    // Survives cold restart with pending outbound bundle still recoverable
    deviceA.dispose();
    final restartedA = IdentityController(
      keyring: keyringA,
      storage: storageA,
      handoffOutbox: outboxA,
      clock: clock.call,
    );
    addTearDown(restartedA.dispose);
    await restartedA.initialize();
    expect(restartedA.selectedVotingState, VotingState.stopped);
    expect(
      restartedA.pendingOutboundHandoff?.rawBytes,
      equals(bundle.rawBytes),
    );

    // Wrong recipient rejection on a third normally initialized device
    final deviceC = IdentityController(
      keyring: InMemoryKeyringService(),
      storage: InMemorySnapshotStorageService(),
      handoffOutbox: InMemoryHandoffOutboxService(),
      clock: clock.call,
    );
    addTearDown(deviceC.dispose);
    await deviceC.initialize();
    final seedC = await restartedA.exportPersonaSeed(personaA);
    try {
      await deviceC.importPersonaSeed(seedC);
    } finally {
      seedC.fillRange(0, seedC.length, 0);
    }
    await deviceC.selectPersona(personaA);
    await deviceC.ensureDeviceNonce();
    await expectLater(
      deviceC.acceptHandoff(bundle),
      throwsA(isA<WrongHandoffRecipientException>()),
    );

    // Device B accepts handoff -> becomes Voting at Counter 1 and survives restart
    final encoded = encodeHandoffBundle(bundle);
    final decoded = decodeHandoffBundle(encoded);
    final newState = await deviceB.acceptHandoff(decoded);
    expect(newState, VotingState.voting);
    expect(deviceB.selectedVotingState, VotingState.voting);
    expect(deviceB.selectedVotingRecord?.counter, bundle.counter);

    // User clears pending outbound handoff on Device A after delivery
    await restartedA.clearPendingOutboundHandoff();
    expect(restartedA.pendingOutboundHandoff, isNull);
    expect((await outboxA.loadAllPendingBundles()).bundles, isEmpty);

    deviceB.dispose();
    final restartedB = IdentityController(
      keyring: keyringB,
      storage: storageB,
      handoffOutbox: outboxB,
      clock: clock.call,
    );
    addTearDown(restartedB.dispose);
    await restartedB.initialize();
    expect(restartedB.selectedVotingState, VotingState.voting);
    expect(restartedB.selectedVotingRecord?.counter, bundle.counter);
  });

  test('active-ceremony guards block handoff and seed mutations', () async {
    final controller = IdentityController(
      keyring: InMemoryKeyringService(),
      storage: InMemorySnapshotStorageService(),
      handoffOutbox: InMemoryHandoffOutboxService(),
      clock: _FakeClock().call,
    );
    addTearDown(controller.dispose);
    await controller.initialize();
    final persona = controller.selectedIdentity!;
    await controller.startEncounterAsInitiator();

    await expectLater(
      controller.ensureDeviceNonce(),
      throwsA(isA<CeremonyActiveException>()),
    );
    await expectLater(
      controller.beginHandoff(Uint8List(32)),
      throwsA(isA<CeremonyActiveException>()),
    );
    await expectLater(
      controller.importPersonaSeed(Uint8List(32)),
      throwsA(isA<CeremonyActiveException>()),
    );
    await expectLater(
      controller.exportPersonaSeed(persona),
      throwsA(isA<CeremonyActiveException>()),
    );
  });

  testWidgets(
    'IdentityView -> DeviceHandoffScreen persists bundle across navigation and validates missing persona',
    (tester) async {
      final clock = _FakeClock();
      final deviceA = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
        clock: clock.call,
      );
      final deviceB = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
        clock: clock.call,
      );
      addTearDown(deviceA.dispose);
      addTearDown(deviceB.dispose);
      await deviceA.initialize();
      await deviceB.initialize();

      final personaA = deviceA.selectedIdentity!;
      final nonceB = await deviceB.ensureDeviceNonce();

      // Open DeviceHandoffScreen from IdentityView on Device A
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: ListenableBuilder(
              listenable: deviceA,
              builder: (context, _) => IdentityView(controller: deviceA),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('Role: Voting (Counter 0)'), findsOneWidget);
      await tester.ensureVisible(
        find.byKey(const Key('open_device_handoff_button')),
      );
      await tester.tap(find.byKey(const Key('open_device_handoff_button')));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('generate_device_nonce_button')));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('device_nonce_text')), findsOneWidget);

      await tester.ensureVisible(
        find.byKey(const Key('handoff_recipient_nonce_field')),
      );
      await tester.enterText(
        find.byKey(const Key('handoff_recipient_nonce_field')),
        formatHexKey(nonceB),
      );
      await tester.pumpAndSettle();

      await tester.ensureVisible(find.byKey(const Key('begin_handoff_button')));
      await tester.tap(find.byKey(const Key('begin_handoff_button')));
      await tester.pumpAndSettle();

      // Confirmation dialog shows full grouped recipient nonce
      expect(find.textContaining(formatGroupedHex(nonceB)), findsOneWidget);
      await tester.tap(find.byKey(const Key('confirm_begin_handoff_button')));
      await tester.pumpAndSettle();

      expect(
        find.byKey(const Key('outbound_handoff_bundle_card')),
        findsOneWidget,
      );
      expect(deviceA.selectedVotingState, VotingState.stopped);
      expect(deviceA.selectedVotingRecord?.counter, BigInt.one);

      final bundleText = tester.widget<SelectableText>(
        find.descendant(
          of: find.byKey(const Key('outbound_handoff_bundle_card')),
          matching: find.byType(SelectableText),
        ),
      );
      final encodedBundle = bundleText.data!;

      // Navigate back out of DeviceHandoffScreen and re-open: bundle must still be there!
      await tester.pageBack();
      await tester.pumpAndSettle();
      await tester.ensureVisible(
        find.byKey(const Key('open_device_handoff_button')),
      );
      await tester.tap(find.byKey(const Key('open_device_handoff_button')));
      await tester.pumpAndSettle();
      expect(
        find.byKey(const Key('outbound_handoff_bundle_card')),
        findsOneWidget,
      );

      // Device B does NOT yet hold personaA -> Inspect warns & disables Accept
      await tester.pumpWidget(
        MaterialApp(
          key: const ValueKey('deviceB_missing_persona_app'),
          home: DeviceHandoffScreen(controller: deviceB),
        ),
      );
      await tester.pumpAndSettle();

      await tester.scrollUntilVisible(
        find.byKey(const Key('handoff_bundle_input_field')),
        300,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.enterText(
        find.byKey(const Key('handoff_bundle_input_field')),
        encodedBundle,
      );
      await tester.pumpAndSettle();
      await tester.ensureVisible(
        find.byKey(const Key('inspect_handoff_bundle_button')),
      );
      await tester.tap(find.byKey(const Key('inspect_handoff_bundle_button')));
      await tester.pumpAndSettle();

      expect(
        find.byKey(const Key('handoff_missing_persona_warning')),
        findsOneWidget,
      );
      final acceptDisabledBtn = tester.widget<FilledButton>(
        find.byKey(const Key('accept_handoff_button')),
      );
      expect(acceptDisabledBtn.onPressed, isNull);

      // Provision personaA on Device B, select it, and accept the bundle
      final seedA = await deviceA.exportPersonaSeed(personaA);
      try {
        await deviceB.importPersonaSeed(seedA);
      } finally {
        seedA.fillRange(0, seedA.length, 0);
      }
      await deviceB.selectPersona(personaA);
      await tester.pumpAndSettle();

      expect(
        find.byKey(const Key('handoff_missing_persona_warning')),
        findsNothing,
      );
      expect(find.textContaining('(Matches this device)'), findsOneWidget);

      await tester.scrollUntilVisible(
        find.byKey(const Key('accept_handoff_button')),
        200,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.tap(find.byKey(const Key('accept_handoff_button')));
      await tester.pumpAndSettle();

      expect(deviceB.selectedVotingState, VotingState.voting);
      expect(deviceB.selectedVotingRecord?.counter, BigInt.one);
      await tester.scrollUntilVisible(
        find.text('Voting (Counter 1)'),
        -300,
        scrollable: find.byType(Scrollable).first,
      );
      expect(find.text('Voting (Counter 1)'), findsOneWidget);
    },
  );

  test('FileHandoffOutboxService isolates oversized/corrupt files and supports full lifecycle', () async {
    final tempDir = await Directory.systemTemp.createTemp(
      'handoff_outbox_test',
    );
    addTearDown(() async {
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    });

    final outbox = FileHandoffOutboxService(
      directoryProvider: () async => tempDir,
    );
    final persona1 = Uint8List.fromList(List<int>.filled(32, 0x11));
    final persona2 = Uint8List.fromList(List<int>.filled(32, 0x22));
    final payload1 = Uint8List.fromList([1, 2, 3, 4]);

    await outbox.savePendingBundle(persona1, payload1);

    // Write an empty (0-byte) file for persona2 directly on disk
    final badHex = formatHexKey(persona2);
    final badFile = File(
      '${tempDir.path}/handoff_outbox/pending_handoff_$badHex.bin',
    );
    await badFile.writeAsBytes(const []);

    final loaded = await outbox.loadAllPendingBundles();
    expect(loaded.bundles.keys, equals([formatHexKey(persona1)]));
    expect(loaded.bundles[formatHexKey(persona1)], equals(payload1));
    expect(loaded.unreadablePersonas, equals({badHex}));

    await outbox.deletePendingBundle(persona1);
    final afterDelete = await outbox.loadAllPendingBundles();
    expect(afterDelete.bundles, isEmpty);

    await outbox.clearAll();
    final afterClear = await outbox.loadAllPendingBundles();
    expect(afterClear.unreadablePersonas, isEmpty);
  });

  testWidgets(
    'unreadable outbox entry surfaces recovery banner on DeviceHandoffScreen',
    (tester) async {
      final clock = _FakeClock();
      final keyring = InMemoryKeyringService();
      final storage = InMemorySnapshotStorageService();
      final outbox = InMemoryHandoffOutboxService();

      final controller = IdentityController(
        keyring: keyring,
        storage: storage,
        handoffOutbox: outbox,
        clock: clock.call,
      );
      await controller.initialize();
      final persona = controller.selectedIdentity!;
      final peerNonce = Uint8List.fromList(List<int>.filled(32, 0x77));
      await controller.beginHandoff(peerNonce);
      controller.dispose();

      // Restart with simulated unreadable outbox for this Stopped persona
      final brokenOutbox = InMemoryHandoffOutboxService(
        simulatedUnreadablePersonas: {formatHexKey(persona)},
      );
      final restarted = IdentityController(
        keyring: keyring,
        storage: storage,
        handoffOutbox: brokenOutbox,
        clock: clock.call,
      );
      addTearDown(restarted.dispose);
      await restarted.initialize();

      expect(restarted.pendingOutboundHandoff, isNull);
      expect(restarted.pendingOutboundHandoffError, isNotNull);

      await tester.pumpWidget(
        MaterialApp(home: DeviceHandoffScreen(controller: restarted)),
      );
      await tester.pumpAndSettle();

      expect(
        find.byKey(const Key('handoff_outbox_error_banner')),
        findsOneWidget,
      );
    },
  );

  testWidgets(
    'IdentityView Import Seed dialog imports persona in Gated state',
    (tester) async {
      final clock = _FakeClock();
      final controller = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
        clock: clock.call,
      );
      addTearDown(controller.dispose);
      await controller.initialize();

      final seed = MeshInstallation.generateSeed();
      addTearDown(() => seed.fillRange(0, seed.length, 0));

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: ListenableBuilder(
              listenable: controller,
              builder: (context, _) => IdentityView(controller: controller),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('import_persona_seed_button')));
      await tester.pumpAndSettle();

      await tester.enterText(
        find.byKey(const Key('import_persona_seed_field')),
        formatHexKey(seed),
      );
      await tester.tap(
        find.byKey(const Key('confirm_import_persona_seed_button')),
      );
      await tester.pumpAndSettle();

      expect(controller.identities.length, 2);
      final importedKey = controller.identities.firstWhere(
        (k) => !listEquals(k, controller.selectedIdentity),
      );
      expect(
        controller.votingRecordForPersona(importedKey)?.state,
        VotingState.gated,
      );
      expect(find.text('Role: Gated (Counter 0)'), findsNWidgets(2));
    },
  );
}
