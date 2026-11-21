import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:encounter/services/identity_controller.dart';
import 'package:encounter/services/keyring_service.dart';
import 'package:encounter/services/snapshot_storage.dart';

void main() {
  late InMemoryKeyringService keyring;
  late InMemorySnapshotStorageService storage;
  late IdentityController controller;

  setUp(() {
    keyring = InMemoryKeyringService();
    storage = InMemorySnapshotStorageService();
    controller = IdentityController(keyring: keyring, storage: storage);
  });

  tearDown(() {
    controller.dispose();
  });

  group('IdentityController (Slice 1)', () {
    test('initializes fresh node on first launch', () async {
      expect(controller.status, equals(IdentityStatus.uninitialized));
      expect(controller.isReady, isFalse);

      await controller.initialize();

      expect(controller.status, equals(IdentityStatus.ready));
      expect(controller.isReady, isTrue);
      expect(controller.selectedIdentity, isNotNull);
      expect(controller.selectedIdentity!.length, equals(32));
      expect(controller.identities.length, equals(1));
      expect(controller.identities.first, equals(controller.selectedIdentity));

      // Keyring holds initial seed and storage holds initial snapshot
      final seeds = await keyring.getAllSeeds();
      expect(seeds.length, equals(1));
      expect(await storage.hasSnapshot(), isTrue);
    });

    test('cold-start restores state across controller restarts', () async {
      await controller.initialize();
      final initialKey = Uint8List.fromList(controller.selectedIdentity!);
      controller.dispose();

      // Launch a new controller on the same storage & keyring
      final restartedController = IdentityController(
        keyring: keyring,
        storage: storage,
      );

      await restartedController.initialize();
      expect(restartedController.isReady, isTrue);
      expect(restartedController.selectedIdentity, equals(initialKey));
      expect(restartedController.identities.length, equals(1));

      restartedController.dispose();
    });

    test('multi-persona addition, selection, and removal with seed synchronization', () async {
      await controller.initialize();
      final primaryKey = controller.selectedIdentity!;

      // Add a second persona
      final secondKey = await controller.addPersona();
      expect(secondKey.length, equals(32));
      expect(secondKey, isNot(equals(primaryKey)));
      expect(controller.identities.length, equals(2));

      // Keyring holds both seeds
      final seeds = await keyring.getAllSeeds();
      expect(seeds.length, equals(2));

      // Switch to second persona
      await controller.selectPersona(secondKey);
      expect(controller.selectedIdentity, equals(secondKey));

      // Simulate restart and verify selection is preserved
      controller.dispose();
      final restarted = IdentityController(keyring: keyring, storage: storage);
      await restarted.initialize();

      expect(restarted.selectedIdentity, equals(secondKey));
      expect(restarted.identities.length, equals(2));

      // Remove the second persona
      await restarted.selectPersona(primaryKey);
      await restarted.removePersona(secondKey);

      expect(restarted.identities.length, equals(1));
      expect(await keyring.getSeed(secondKey), isNull);
      expect((await keyring.getAllSeeds()).length, equals(1));

      restarted.dispose();
    });

    test(
      'corrupted snapshot transitions to corrupted state and allows reset',
      () async {
        // Plant corrupt snapshot bytes
        await storage.saveSnapshot(
          Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]),
        );
        await keyring.saveSeed(Uint8List(32), Uint8List(32));

        await controller.initialize();

        expect(controller.status, equals(IdentityStatus.corrupted));
        expect(controller.isReady, isFalse);
        expect(controller.errorMessage, isNotNull);
        expect(
          controller.errorMessage,
          contains('Snapshot restoration failed'),
        );

        // Calling installation when corrupted throws StateError
        expect(() => controller.installation, throwsStateError);

        // Reset corrupted state recovers into clean ready node
        await controller.resetCorruptedState();
        expect(controller.status, equals(IdentityStatus.ready));
        expect(controller.isReady, isTrue);
        expect(controller.selectedIdentity, isNotNull);
      },
    );
  });
}
