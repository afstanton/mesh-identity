import 'dart:io';

import 'package:encounter/features/groups/groups_view.dart';
import 'package:encounter/features/identity/identity_view.dart';
import 'package:encounter/services/group_controller.dart';
import 'package:encounter/services/group_outbox.dart';
import 'package:encounter/services/identity_controller.dart';
import 'package:encounter/services/keyring_service.dart';
import 'package:encounter/services/local_labels_service.dart';
import 'package:encounter/services/snapshot_storage.dart';
import 'package:flutter/services.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

class _EmptyReadFailingWriteStorage implements FlutterSecureStorage {
  final Map<String, String> readablePrimaryEntries;

  _EmptyReadFailingWriteStorage({this.readablePrimaryEntries = const {}});

  @override
  Future<Map<String, String>> readAll({
    AppleOptions? iOptions,
    AndroidOptions? aOptions,
    LinuxOptions? lOptions,
    WebOptions? webOptions,
    AppleOptions? mOptions,
    WindowsOptions? wOptions,
  }) async => Map<String, String>.from(readablePrimaryEntries);

  @override
  Future<String?> read({
    required String key,
    AppleOptions? iOptions,
    AndroidOptions? aOptions,
    LinuxOptions? lOptions,
    WebOptions? webOptions,
    AppleOptions? mOptions,
    WindowsOptions? wOptions,
  }) async => readablePrimaryEntries[key];

  @override
  Future<void> write({
    required String key,
    required String? value,
    AppleOptions? iOptions,
    AndroidOptions? aOptions,
    LinuxOptions? lOptions,
    WebOptions? webOptions,
    AppleOptions? mOptions,
    WindowsOptions? wOptions,
  }) async {
    throw PlatformException(
      code: 'Unexpected security result code',
      message: 'A required entitlement isn\'t present.',
      details: -34018,
    );
  }

  @override
  Future<void> delete({
    required String key,
    AppleOptions? iOptions,
    AndroidOptions? aOptions,
    LinuxOptions? lOptions,
    WebOptions? webOptions,
    AppleOptions? mOptions,
    WindowsOptions? wOptions,
  }) async {}

  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class _FailingLabelsService implements LocalLabelsService {
  bool failLoad;
  bool failSave = false;
  Map<String, String> personas = {};
  Map<String, String> groups = {};

  _FailingLabelsService({this.failLoad = false});

  @override
  Future<({Map<String, String> personas, Map<String, String> groups})>
  loadAll() async {
    if (failLoad) {
      throw const FormatException('Corrupted labels JSON');
    }
    return (
      personas: Map<String, String>.from(personas),
      groups: Map<String, String>.from(groups),
    );
  }

  @override
  Future<void> saveAll({
    required Map<String, String> personas,
    required Map<String, String> groups,
  }) async {
    if (failSave) {
      throw StateError('Disk full');
    }
    this.personas = Map<String, String>.from(personas);
    this.groups = Map<String, String>.from(groups);
  }
}

void main() {
  test('setPersonaLabel and setGroupName enforce 64-char limit, roll back on save error, and prune on removePersona', () async {
    final labels = _FailingLabelsService();
    final controller = IdentityController(
      keyring: InMemoryKeyringService(),
      storage: InMemorySnapshotStorageService(),
      localLabels: labels,
    );
    addTearDown(controller.dispose);
    await controller.initialize();

    final first = controller.selectedIdentity!;
    final second = await controller.addPersona();

    await controller.setPersonaLabel(second, 'Work');
    expect(controller.personaLabel(second), 'Work');

    // 65-character label is rejected.
    await expectLater(
      () => controller.setPersonaLabel(second, 'a' * 65),
      throwsArgumentError,
    );

    // Save error rolls back in-memory state.
    labels.failSave = true;
    await expectLater(
      () => controller.setPersonaLabel(second, 'Updated'),
      throwsStateError,
    );
    expect(controller.personaLabel(second), 'Work');

    await expectLater(
      () => controller.setGroupName(BigInt.from(42), 'Field Team'),
      throwsStateError,
    );
    expect(controller.groupName(BigInt.from(42)), isNull);

    labels.failSave = false;
    await controller.removePersona(second);
    expect(controller.personaLabel(second), isNull);
    expect(labels.personas.containsKey(first.toString()), isFalse);
  });

  test('unreadable labels file does not block startup and refuses destructive overwrite', () async {
    final labels = _FailingLabelsService(failLoad: true);
    final controller = IdentityController(
      keyring: InMemoryKeyringService(),
      storage: InMemorySnapshotStorageService(),
      localLabels: labels,
    );
    addTearDown(controller.dispose);
    await controller.initialize();

    expect(controller.status, IdentityStatus.ready);
    await expectLater(
      () => controller.setPersonaLabel(controller.selectedIdentity!, 'Home'),
      throwsStateError,
    );
  });

  testWidgets(
    'GroupsView reports group name save failure separately after group creation succeeds',
    (tester) async {
      final labels = _FailingLabelsService();
      final identity = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        localLabels: labels,
      );
      await identity.initialize();
      final groups = GroupController(
        identityController: identity,
        outbox: InMemoryGroupOutboxService(),
      );
      await groups.initialize();
      addTearDown(() {
        groups.dispose();
        identity.dispose();
      });

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: GroupsView(
              identityController: identity,
              groupController: groups,
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      labels.failSave = true;
      await tester.tap(find.byKey(const Key('create_group_button')));
      await tester.pumpAndSettle();
      await tester.enterText(
        find.byKey(const Key('group_name_field')),
        'Team Alpha',
      );
      await tester.tap(find.byKey(const Key('confirm_create_group_button')));
      await tester.pumpAndSettle();

      expect(groups.groups, hasLength(1));
      expect(find.text('Group created.'), findsOneWidget);
      expect(
        find.textContaining('Group created, but saving the local name failed'),
        findsOneWidget,
      );
    },
  );

  testWidgets(
    'GroupsView saves optional group name under groupId and displays it on the group card',
    (tester) async {
      final labels = _FailingLabelsService();
      final identity = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        localLabels: labels,
      );
      await identity.initialize();
      final groups = GroupController(
        identityController: identity,
        outbox: InMemoryGroupOutboxService(),
      );
      await groups.initialize();
      addTearDown(() {
        groups.dispose();
        identity.dispose();
      });

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: GroupsView(
              identityController: identity,
              groupController: groups,
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('create_group_button')));
      await tester.pumpAndSettle();
      await tester.enterText(
        find.byKey(const Key('group_name_field')),
        'Family',
      );
      await tester.tap(find.byKey(const Key('confirm_create_group_button')));
      await tester.pumpAndSettle();

      expect(groups.groups, hasLength(1));
      expect(find.text('Family'), findsOneWidget);
      expect(identity.groupName(groups.groups.first.groupId), 'Family');
    },
  );

  test('macOS debug keyring fallback survives restart when readAll returns empty and write throws -34018', () async {
    if (!Platform.isMacOS) return;
    final tempDir = await Directory.systemTemp.createTemp('keyring_restart_');
    addTearDown(() async {
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    });

    final key = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
    final seed = Uint8List.fromList(List<int>.generate(32, (i) => i + 33));

    final firstRun = FlutterSecureKeyringService(
      storage: _EmptyReadFailingWriteStorage(),
      legacyMacOsStorage: _EmptyReadFailingWriteStorage(),
      debugFallbackDirectory: () async => tempDir,
    );
    await firstRun.saveSeed(key, seed);

    final secondRun = FlutterSecureKeyringService(
      storage: _EmptyReadFailingWriteStorage(),
      legacyMacOsStorage: _EmptyReadFailingWriteStorage(),
      debugFallbackDirectory: () async => tempDir,
    );
    final keys = await secondRun.getAllIdentityKeys();
    expect(keys, hasLength(1));
    expect(keys.first, equals(key));
    final loadedSeed = await secondRun.getSeed(key);
    expect(loadedSeed, equals(seed));
  });

  test('macOS debug fallback merges readable Keychain seeds with fallback file seeds', () async {
    if (!Platform.isMacOS) return;
    final tempDir = await Directory.systemTemp.createTemp('keyring_merge_');
    addTearDown(() async {
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    });

    final keyA = Uint8List.fromList(List<int>.generate(32, (i) => i + 1));
    final seedA = Uint8List.fromList(List<int>.generate(32, (i) => i + 33));
    final keyB = Uint8List.fromList(List<int>.generate(32, (i) => i + 65));
    final seedB = Uint8List.fromList(List<int>.generate(32, (i) => i + 97));

    String toHex(Uint8List bytes) =>
        bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    final primaryEntries = {'persona_seed_${toHex(keyA)}': toHex(seedA)};
    final service = FlutterSecureKeyringService(
      storage: _EmptyReadFailingWriteStorage(
        readablePrimaryEntries: primaryEntries,
      ),
      legacyMacOsStorage: _EmptyReadFailingWriteStorage(),
      debugFallbackDirectory: () async => tempDir,
    );

    // Saving keyB triggers -34018 and activates debug fallback mode.
    await service.saveSeed(keyB, seedB);

    final allKeys = await service.getAllIdentityKeys();
    expect(allKeys, hasLength(2));
    expect(await service.getSeed(keyA), equals(seedA));
    expect(await service.getSeed(keyB), equals(seedB));
    final allSeeds = await service.getAllSeeds();
    expect(allSeeds, hasLength(2));
  });

  testWidgets('IdentityView surfaces rename save failure in error banner', (
    tester,
  ) async {
    final labels = _FailingLabelsService();
    final controller = IdentityController(
      keyring: InMemoryKeyringService(),
      storage: InMemorySnapshotStorageService(),
      localLabels: labels,
    );
    await controller.initialize();
    addTearDown(controller.dispose);

    final key = controller.selectedIdentity!;
    final hex = key.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(body: IdentityView(controller: controller)),
      ),
    );
    await tester.pumpAndSettle();

    labels.failSave = true;
    await tester.tap(find.byKey(Key('rename_persona_button_$hex')));
    await tester.pumpAndSettle();
    await tester.enterText(
      find.byKey(const Key('rename_persona_field')),
      'Personal',
    );
    await tester.tap(find.byKey(const Key('confirm_rename_persona_button')));
    await tester.pumpAndSettle();

    expect(find.textContaining('Failed to save persona name:'), findsOneWidget);
    expect(controller.personaLabel(key), isNull);
  });
}
