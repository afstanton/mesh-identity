import 'dart:typed_data';

import 'package:encounter/services/identity_controller.dart';
import 'package:encounter/services/keyring_service.dart';
import 'package:encounter/services/snapshot_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_identity/mesh_identity.dart';

class FaultyKeyringService implements SecureKeyringService {
  final InMemoryKeyringService inner;
  bool failOnSave = false;
  bool failOnRemove = false;
  Duration? delayOnSave;

  FaultyKeyringService(this.inner);

  @override
  Future<void> saveSeed(Uint8List identityKey, Uint8List seed) async {
    if (delayOnSave != null) {
      await Future<void>.delayed(delayOnSave!);
    }
    if (failOnSave) {
      throw StateError('Simulated keyring save failure');
    }
    await inner.saveSeed(identityKey, seed);
  }

  @override
  Future<Uint8List?> getSeed(Uint8List identityKey) =>
      inner.getSeed(identityKey);

  @override
  Future<List<Uint8List>> getAllIdentityKeys() => inner.getAllIdentityKeys();

  @override
  Future<List<Uint8List>> getAllSeeds() => inner.getAllSeeds();

  @override
  Future<void> removeSeed(Uint8List identityKey) async {
    if (failOnRemove) {
      throw StateError('Simulated keyring remove failure');
    }
    await inner.removeSeed(identityKey);
  }

  @override
  Future<void> clear() => inner.clear();
}

class FaultySnapshotStorageService implements SnapshotStorageService {
  final InMemorySnapshotStorageService inner;
  bool failNextSave = false;
  Duration Function()? nextSaveDelay;

  FaultySnapshotStorageService(this.inner);

  @override
  Future<Uint8List?> loadSnapshot() => inner.loadSnapshot();

  @override
  Future<void> saveSnapshot(Uint8List snapshotBytes) async {
    final delay = nextSaveDelay?.call();
    if (delay != null) {
      await Future<void>.delayed(delay);
    }
    if (failNextSave) {
      failNextSave = false;
      throw StateError('Simulated disk write failure');
    }
    await inner.saveSnapshot(snapshotBytes);
  }

  @override
  Future<bool> hasSnapshot() => inner.hasSnapshot();

  @override
  Future<String?> archiveSnapshot() => inner.archiveSnapshot();

  @override
  Future<void> deleteSnapshot() => inner.deleteSnapshot();
}

void main() {
  late InMemoryKeyringService rawKeyring;
  late InMemorySnapshotStorageService rawStorage;
  late FaultyKeyringService keyring;
  late FaultySnapshotStorageService storage;
  late IdentityController controller;

  setUp(() {
    rawKeyring = InMemoryKeyringService();
    rawStorage = InMemorySnapshotStorageService();
    keyring = FaultyKeyringService(rawKeyring);
    storage = FaultySnapshotStorageService(rawStorage);
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

      final seeds = await rawKeyring.getAllSeeds();
      expect(seeds.length, equals(1));
      expect(await rawStorage.hasSnapshot(), isTrue);
    });

    test('cold-start restores state across controller restarts', () async {
      await controller.initialize();
      final initialKey = Uint8List.fromList(controller.selectedIdentity!);
      controller.dispose();

      final restartedController = IdentityController(
        keyring: rawKeyring,
        storage: rawStorage,
      );
      addTearDown(restartedController.dispose);

      await restartedController.initialize();
      expect(restartedController.isReady, isTrue);
      expect(restartedController.selectedIdentity, equals(initialKey));
      expect(restartedController.identities.length, equals(1));
    });

    test('multi-persona addition, selection, and removal with seed synchronization', () async {
      await controller.initialize();
      final primaryKey = controller.selectedIdentity!;

      final secondKey = await controller.addPersona();
      expect(secondKey.length, equals(32));
      expect(secondKey, isNot(equals(primaryKey)));
      expect(controller.identities.length, equals(2));
      expect((await rawKeyring.getAllSeeds()).length, equals(2));

      await controller.selectPersona(secondKey);
      expect(controller.selectedIdentity, equals(secondKey));

      controller.dispose();
      final restarted = IdentityController(
        keyring: rawKeyring,
        storage: rawStorage,
      );
      addTearDown(restarted.dispose);
      await restarted.initialize();

      expect(restarted.selectedIdentity, equals(secondKey));
      expect(restarted.identities.length, equals(2));

      await restarted.selectPersona(primaryKey);
      await restarted.removePersona(secondKey);

      expect(restarted.identities.length, equals(1));
      expect(await rawKeyring.getSeed(secondKey), isNull);
      expect((await rawKeyring.getAllSeeds()).length, equals(1));
    });

    test('snapshot present with empty keyring transitions to corrupted without overwriting', () async {
      final originalSnapshot = Uint8List.fromList([0x01, 0x02, 0x03, 0x04]);
      await rawStorage.saveSnapshot(originalSnapshot);

      await controller.initialize();

      expect(controller.status, equals(IdentityStatus.corrupted));
      expect(controller.isReady, isFalse);
      expect(controller.errorMessage, contains('no signing keys were found'));
      expect(await rawStorage.loadSnapshot(), equals(originalSnapshot));
    });

    test('missing snapshot with non-empty keyring transitions to corrupted without wiping seeds', () async {
      final existingKey = Uint8List(32)..[0] = 7;
      final existingSeed = MeshInstallation.generateSeed();
      await rawKeyring.saveSeed(existingKey, existingSeed);

      await controller.initialize();

      expect(controller.status, equals(IdentityStatus.corrupted));
      expect(controller.isReady, isFalse);
      expect(
        controller.errorMessage,
        contains('installation snapshot is missing'),
      );
      expect(await rawStorage.hasSnapshot(), isFalse);
      expect(await rawKeyring.getSeed(existingKey), equals(existingSeed));
    });

    test('addPersona snapshot failure rolls back state and orphaned key is pruned on restart', () async {
      await controller.initialize();
      final key1 = controller.selectedIdentity!;

      // Simulate snapshot write failure AND crashed seed cleanup (e.g. SIGKILL mid-tx)
      storage.failNextSave = true;
      keyring.failOnRemove = true;

      await expectLater(controller.addPersona, throwsStateError);

      // In-memory state rolled back to [key1]
      expect(controller.isReady, isTrue);
      expect(controller.identities, equals([key1]));
      // Keyring still contains orphaned second seed due to failOnRemove
      expect((await rawKeyring.getAllIdentityKeys()).length, equals(2));

      controller.dispose();

      // Restart restores durable [key1] cleanly and prunes orphan seed
      final restarted = IdentityController(
        keyring: rawKeyring,
        storage: rawStorage,
      );
      addTearDown(restarted.dispose);
      await restarted.initialize();

      expect(restarted.isReady, isTrue);
      expect(restarted.identities, equals([key1]));
      expect(await rawKeyring.getAllIdentityKeys(), equals([key1]));
    });

    test('removePersona snapshot failure preserves seed and rolls back installation', () async {
      await controller.initialize();
      final key1 = controller.selectedIdentity!;
      final key2 = await controller.addPersona();

      storage.failNextSave = true;
      await expectLater(() => controller.removePersona(key2), throwsStateError);

      // Seed for key2 must STILL be in keyring and memory state rolled back
      expect(await rawKeyring.getSeed(key2), isNotNull);
      expect(controller.identities.length, equals(2));
      expect(controller.selectedIdentity, equals(key1));

      controller.dispose();
      final restarted = IdentityController(
        keyring: rawKeyring,
        storage: rawStorage,
      );
      addTearDown(restarted.dispose);
      await restarted.initialize();

      expect(restarted.isReady, isTrue);
      expect(restarted.identities.length, equals(2));
    });

    test('removePersona keyring deletion failure after durable snapshot prunes orphan on restart', () async {
      await controller.initialize();
      final key1 = controller.selectedIdentity!;
      final key2 = await controller.addPersona();

      // Snapshot succeeds, keyring deletion fails
      keyring.failOnRemove = true;
      await controller.removePersona(key2);

      // Live controller has committed [key1]
      expect(controller.identities, equals([key1]));
      // Seed2 temporarily orphaned in keyring
      expect(await rawKeyring.getSeed(key2), isNotNull);

      controller.dispose();
      final restarted = IdentityController(
        keyring: rawKeyring,
        storage: rawStorage,
      );
      addTearDown(restarted.dispose);
      await restarted.initialize();

      expect(restarted.isReady, isTrue);
      expect(restarted.identities, equals([key1]));
      // Orphan pruned cleanly during envelope startup
      expect(await rawKeyring.getSeed(key2), isNull);
    });

    test(
      'selectPersona snapshot failure rolls back selectedIdentity',
      () async {
        await controller.initialize();
        final key1 = controller.selectedIdentity!;
        final key2 = await controller.addPersona();

        storage.failNextSave = true;
        await expectLater(
          () => controller.selectPersona(key2),
          throwsStateError,
        );

        expect(controller.selectedIdentity, equals(key1));

        controller.dispose();
        final restarted = IdentityController(
          keyring: rawKeyring,
          storage: rawStorage,
        );
        addTearDown(restarted.dispose);
        await restarted.initialize();

        expect(restarted.selectedIdentity, equals(key1));
      },
    );

    test(
      'concurrent mutations serialize FIFO despite skewed storage delays',
      () async {
        await controller.initialize();
        final key2 = await controller.addPersona();

        // First queued save is slow, second is fast, third is medium:
        // without FIFO serialization, the slow first save would overwrite later commits.
        final delays = [
          const Duration(milliseconds: 40),
          const Duration(milliseconds: 5),
          const Duration(milliseconds: 20),
        ];
        var callIndex = 0;
        storage.nextSaveDelay = () => delays[callIndex++ % delays.length];

        final add3 = controller.addPersona();
        final select2 = controller.selectPersona(key2);
        final add4 = controller.addPersona();

        final key3 = await add3;
        await select2;
        final key4 = await add4;

        expect(controller.identities.length, equals(4));
        expect(controller.selectedIdentity, equals(key2));
        expect(controller.identities, containsAll([key2, key3, key4]));

        controller.dispose();
        final restarted = IdentityController(
          keyring: rawKeyring,
          storage: rawStorage,
        );
        addTearDown(restarted.dispose);
        await restarted.initialize();

        expect(restarted.identities.length, equals(4));
        expect(restarted.selectedIdentity, equals(key2));
      },
    );

    test('corrupted state blocks mutators, guards reset confirmation, and archives corrupt blob', () async {
      final corruptBytes = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8]);
      await rawStorage.saveSnapshot(corruptBytes);
      await rawKeyring.saveSeed(Uint8List(32), Uint8List(32));

      await controller.initialize();

      expect(controller.status, equals(IdentityStatus.corrupted));
      expect(controller.isReady, isFalse);
      expect(controller.errorMessage, contains('Snapshot restoration failed'));

      // Mutator calls throw StateError when corrupted
      await expectLater(controller.addPersona, throwsStateError);
      expect(() => controller.getContact(Uint8List(32)), throwsStateError);

      // Unconfirmed reset throws ArgumentError and preserves corrupt snapshot
      await expectLater(
        () => controller.resetCorruptedState(confirmDestructiveReset: false),
        throwsArgumentError,
      );
      expect(await rawStorage.loadSnapshot(), equals(corruptBytes));
      expect(rawStorage.archivedSnapshots, isEmpty);

      // Confirmed reset archives corrupt snapshot and creates fresh node
      final archiveId = await controller.resetCorruptedState(
        confirmDestructiveReset: true,
      );
      expect(archiveId, isNotNull);
      expect(rawStorage.archivedSnapshots, equals([corruptBytes]));
      expect(controller.status, equals(IdentityStatus.ready));
      expect(controller.isReady, isTrue);
      expect(controller.selectedIdentity, isNotNull);
    });

    test(
      'legacy raw MeshInstallation snapshot without envelope restores cleanly',
      () async {
        final seed = MeshInstallation.generateSeed();
        final legacyInst = MeshInstallation(seed: seed);
        final legacyKey = legacyInst.selectedIdentity;
        final rawBytes = legacyInst.save();
        legacyInst.dispose();

        await rawKeyring.saveSeed(legacyKey, seed);
        seed.fillRange(0, 32, 0);
        await rawStorage.saveSnapshot(rawBytes);

        await controller.initialize();

        expect(controller.status, equals(IdentityStatus.ready));
        expect(controller.selectedIdentity, equals(legacyKey));
        expect(controller.identities, equals([legacyKey]));
      },
    );
  });
}
