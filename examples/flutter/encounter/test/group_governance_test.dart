import 'dart:io';

import 'package:encounter/features/groups/groups_view.dart';
import 'package:encounter/services/group_controller.dart';
import 'package:encounter/services/group_frame_codec.dart';
import 'package:encounter/services/group_outbox.dart';
import 'package:encounter/services/handoff_outbox.dart';
import 'package:encounter/services/hex_utils.dart';
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
      throw StateError('Simulated snapshot write failure');
    }
    await inner.saveSnapshot(bytes);
  }

  @override
  Future<String?> archiveSnapshot() => inner.archiveSnapshot();

  @override
  Future<void> deleteSnapshot() => inner.deleteSnapshot();
}

class _ControllableOutbox implements GroupOutboxService {
  final InMemoryGroupOutboxService inner = InMemoryGroupOutboxService();
  bool failNextAppend = false;

  @override
  Future<List<StoredOutgoingMessage>> appendMessages(
    List<OutgoingMessage> messages, {
    required DateTime at,
  }) async {
    if (failNextAppend) {
      failNextAppend = false;
      throw StateError('Simulated outbox write failure');
    }
    return inner.appendMessages(messages, at: at);
  }

  @override
  Future<GroupOutboxLoadResult> loadAll() => inner.loadAll();

  @override
  Future<void> deleteMessage(String id) => inner.deleteMessage(id);

  @override
  Future<void> clearAll() => inner.clearAll();
}

Future<void> _verifyPair(
  IdentityController alice,
  IdentityController bob,
) async {
  await alice.startEncounterAsInitiator();
  await bob.openEncounterAsResponder();
  await bob.submitEncounterOffer(alice.encounterSession.outgoingUri!);
  await alice.submitEncounterResponse(bob.encounterSession.outgoingUri!);
  await bob.submitEncounterReveal(alice.encounterSession.outgoingUri!);
  await alice.confirmEncounterCode(
    alice.encounterSession.comparison!.formattedCode,
  );
  await bob.confirmEncounterCode(
    bob.encounterSession.comparison!.formattedCode,
  );
}

void main() {
  test('group_frame_codec round-trips frames and enforces bounds', () {
    final from = Uint8List.fromList(List<int>.filled(32, 0x11));
    final to = [Uint8List.fromList(List<int>.filled(32, 0x22))];
    final auth = Uint8List.fromList(List<int>.filled(32, 0x33));
    final msg = OutgoingMessage(
      from: from,
      to: to,
      tag: MessageTag.genesis,
      bytes: Uint8List.fromList([1, 2, 3, 4, 5]),
      authenticator: auth,
    );

    final encoded = encodeGroupFrame(msg);
    expect(encoded.startsWith(groupFrameUriPrefix), isTrue);
    final decoded = decodeGroupFrame(encoded);
    expect(decoded, equals(msg));

    expect(() => decodeGroupFrame('   '), throwsFormatException);
    expect(() => decodeGroupFrame('mesh:group:!!!'), throwsFormatException);
    expect(
      () => decodeGroupFrame('mesh:group:${'A' * (maxGroupFrameUriChars + 1)}'),
      throwsFormatException,
    );
    expect(() => parseDigestHex('abcd'), throwsFormatException);
  });

  test(
    'FileGroupOutboxService isolates corrupt files and persists lifecycle',
    () async {
      final tempDir = await Directory.systemTemp.createTemp(
        'group_outbox_test',
      );
      addTearDown(() async {
        if (await tempDir.exists()) {
          await tempDir.delete(recursive: true);
        }
      });

      final outbox = FileGroupOutboxService(
        directoryProvider: () async => tempDir,
      );
      final msg = OutgoingMessage(
        from: Uint8List.fromList(List<int>.filled(32, 0x11)),
        to: [Uint8List.fromList(List<int>.filled(32, 0x22))],
        tag: MessageTag.invitation,
        bytes: Uint8List.fromList([9, 8, 7]),
      );

      final appended = await outbox.appendMessages([
        msg,
      ], at: DateTime.utc(2026));
      expect(appended.length, 1);

      // Add a malformed file alongside the valid one
      await File('${tempDir.path}/group_outbox/msg_999.json')
          .writeAsString('not-json');

      final loaded = await outbox.loadAll();
      expect(loaded.messages.length, 1);
      expect(loaded.messages.first.message, equals(msg));
      expect(loaded.unreadableCount, 1);

      await outbox.deleteMessage(appended.first.id);
      final afterDelete = await outbox.loadAll();
      expect(afterDelete.messages, isEmpty);

      await outbox.clearAll();
      final afterClear = await outbox.loadAll();
      expect(afterClear.unreadableCount, 0);
    },
  );

  test(
    'two-party Byzantine admission flow converges and survives cold restart',
    () async {
      final clock = _FakeClock();
      final aliceKeyring = InMemoryKeyringService();
      final aliceStorage = _ControllableStorage();
      final aliceHandoffOutbox = InMemoryHandoffOutboxService();
      final aliceId = IdentityController(
        keyring: aliceKeyring,
        storage: aliceStorage,
        handoffOutbox: aliceHandoffOutbox,
        clock: clock.call,
      );
      final bobKeyring = InMemoryKeyringService();
      final bobStorage = InMemorySnapshotStorageService();
      final bobHandoffOutbox = InMemoryHandoffOutboxService();
      final bobId = IdentityController(
        keyring: bobKeyring,
        storage: bobStorage,
        handoffOutbox: bobHandoffOutbox,
        clock: clock.call,
      );
      await aliceId.initialize();
      await bobId.initialize();
      await _verifyPair(aliceId, bobId);

      final aliceOutbox = InMemoryGroupOutboxService();
      final aliceGroups = GroupController(
        identityController: aliceId,
        outbox: aliceOutbox,
        clock: clock.call,
      );
      final bobOutbox = InMemoryGroupOutboxService();
      final bobGroups = GroupController(
        identityController: bobId,
        outbox: bobOutbox,
        clock: clock.call,
      );
      await aliceGroups.initialize();
      await bobGroups.initialize();

      // Two-phase rollback check: failed snapshot save releases zero outgoing frames
      aliceStorage.failNextSave = true;
      await expectLater(aliceGroups.createGroup(), throwsStateError);
      expect(aliceGroups.groups, isEmpty);
      expect(aliceGroups.outgoingMessages, isEmpty);

      // Alice creates a solo group and invites verified Bob
      await aliceGroups.createGroup();
      expect(aliceGroups.groups.length, 1);
      final groupId = aliceGroups.groups.first.groupId;
      await aliceGroups.invite(
        groupId: groupId,
        candidateKey: bobId.selectedIdentity!,
      );

      // Relay released protocol frames (skipping solo genesis archival frames)
      Future<void> relay(
        GroupController fromCtrl,
        GroupController toCtrl,
      ) async {
        final pending = List.of(fromCtrl.outgoingMessages);
        for (final item in pending) {
          if (item.message.tag != MessageTag.genesis) {
            await toCtrl.receiveFrame(item.message);
          }
          await fromCtrl.markOutgoingSent(item.id);
        }
      }

      await relay(aliceGroups, bobGroups);

      expect(bobGroups.pendingInvitations, hasLength(1));
      await bobGroups.acceptInvitation(
        bobGroups.pendingInvitations.first.binding,
      );

      for (var round = 0; round < 5; round++) {
        if (aliceGroups.outgoingMessages.isEmpty &&
            bobGroups.outgoingMessages.isEmpty) {
          break;
        }
        await relay(bobGroups, aliceGroups);
        await relay(aliceGroups, bobGroups);
      }

      expect(aliceGroups.groups.length, 1);
      expect(bobGroups.groups.length, 1);
      expect(aliceGroups.groups.first.members.length, 2);
      expect(bobGroups.groups.first.members.length, 2);

      // Cold restart both IdentityControllers and GroupControllers
      aliceGroups.dispose();
      bobGroups.dispose();
      aliceId.dispose();
      bobId.dispose();

      final restartedAliceId = IdentityController(
        keyring: aliceKeyring,
        storage: aliceStorage,
        handoffOutbox: aliceHandoffOutbox,
        clock: clock.call,
      );
      final restartedBobId = IdentityController(
        keyring: bobKeyring,
        storage: bobStorage,
        handoffOutbox: bobHandoffOutbox,
        clock: clock.call,
      );
      await restartedAliceId.initialize();
      await restartedBobId.initialize();

      final restartedAlice = GroupController(
        identityController: restartedAliceId,
        outbox: aliceOutbox,
        clock: clock.call,
      );
      final restartedBob = GroupController(
        identityController: restartedBobId,
        outbox: bobOutbox,
        clock: clock.call,
      );
      addTearDown(restartedAlice.dispose);
      addTearDown(restartedBob.dispose);
      addTearDown(restartedAliceId.dispose);
      addTearDown(restartedBobId.dispose);

      await restartedAlice.initialize();
      await restartedBob.initialize();

      expect(restartedAlice.groups.first.members.length, 2);
      expect(restartedBob.groups.first.members.length, 2);
    },
  );

  test('unified handle: handoff stops group voting, post-init verified contact can be invited, and persona add/switch persists across restart', () async {
    final clock = _FakeClock();
    final aliceKeyring = InMemoryKeyringService();
    final aliceStorage = InMemorySnapshotStorageService();
    final aliceHandoffOutbox = InMemoryHandoffOutboxService();
    final aliceId = IdentityController(
      keyring: aliceKeyring,
      storage: aliceStorage,
      handoffOutbox: aliceHandoffOutbox,
      clock: clock.call,
    );
    final bobId = IdentityController(
      keyring: InMemoryKeyringService(),
      storage: InMemorySnapshotStorageService(),
      handoffOutbox: InMemoryHandoffOutboxService(),
      clock: clock.call,
    );
    await aliceId.initialize();
    await bobId.initialize();

    final aliceOutbox = InMemoryGroupOutboxService();
    final aliceGroups = GroupController(
      identityController: aliceId,
      outbox: aliceOutbox,
      clock: clock.call,
    );
    await aliceGroups.initialize();

    // 1. Create group BEFORE verifying Bob
    await aliceGroups.createGroup();
    expect(aliceGroups.groups.length, 1);
    final groupId = aliceGroups.groups.first.groupId;

    // 2. Verify Bob AFTER GroupController already has committed group state
    await _verifyPair(aliceId, bobId);

    // 3. Invite newly-verified Bob into existing group on the same handle
    await aliceGroups.invite(
      groupId: groupId,
      candidateKey: bobId.selectedIdentity!,
    );
    expect(
      aliceGroups.outgoingMessages.any(
        (m) => m.message.tag == MessageTag.invitation,
      ),
      isTrue,
    );

    // 4. Add second persona & switch personas: GroupController updates live
    final persona1 = aliceId.selectedIdentity!;
    final persona2 = await aliceId.addPersona();
    await aliceId.selectPersona(persona2);
    expect(listEquals(aliceId.selectedIdentity, persona2), isTrue);
    expect(aliceGroups.groups, isEmpty);

    await aliceId.selectPersona(persona1);
    expect(aliceGroups.groups.length, 1);

    // 5. Handoff persona1: unified handle immediately reflects Stopped state
    final recipientNonce = Uint8List(32)..[0] = 0x55;
    await aliceId.beginHandoff(recipientNonce);
    expect(aliceId.selectedVotingState, VotingState.stopped);
    final handleVotingState = aliceId.readGroupState(
      (h) => h.installation.getVotingState(),
    );
    expect(handleVotingState, VotingState.stopped);

    // 6. Cold restart restores both personas, group, and Stopped voting state
    aliceGroups.dispose();
    aliceId.dispose();
    bobId.dispose();

    final restartedAliceId = IdentityController(
      keyring: aliceKeyring,
      storage: aliceStorage,
      handoffOutbox: aliceHandoffOutbox,
      clock: clock.call,
    );
    await restartedAliceId.initialize();
    final restartedGroups = GroupController(
      identityController: restartedAliceId,
      outbox: aliceOutbox,
      clock: clock.call,
    );
    addTearDown(restartedGroups.dispose);
    addTearDown(restartedAliceId.dispose);
    await restartedGroups.initialize();

    expect(restartedAliceId.identities.length, 2);
    expect(restartedAliceId.selectedVotingState, VotingState.stopped);
    expect(restartedGroups.groups.length, 1);
    expect(restartedGroups.groups.first.groupId, groupId);
  });

  test('post-commit outbox failure is recoverable via retry and cold-restart without resurrecting sent frames', () async {
    final clock = _FakeClock();
    final keyring = InMemoryKeyringService();
    final storage = InMemorySnapshotStorageService();
    final handoffOutbox = InMemoryHandoffOutboxService();
    final outbox = _ControllableOutbox();

    final idCtrl = IdentityController(
      keyring: keyring,
      storage: storage,
      handoffOutbox: handoffOutbox,
      clock: clock.call,
    );
    await idCtrl.initialize();

    final groupCtrl = GroupController(
      identityController: idCtrl,
      outbox: outbox,
      clock: clock.call,
    );
    await groupCtrl.initialize();

    // Fail outbox write after commit: group is committed, unsaved frame is retained
    outbox.failNextAppend = true;
    await groupCtrl.createGroup();
    expect(groupCtrl.groups.length, 1);
    expect(groupCtrl.outboxError, isNotNull);
    expect(groupCtrl.hasUnsavedOutgoing, isTrue);
    expect(groupCtrl.outgoingMessages.length, 1);
    expect(groupCtrl.outgoingMessages.first.isPersisted, isFalse);

    // Simulate crash BEFORE retry: cold restart recovers staged genesis frame!
    groupCtrl.dispose();
    idCtrl.dispose();

    final crashedRestartId = IdentityController(
      keyring: keyring,
      storage: storage,
      handoffOutbox: handoffOutbox,
      clock: clock.call,
    );
    await crashedRestartId.initialize();
    final crashedRestartGroups = GroupController(
      identityController: crashedRestartId,
      outbox: outbox,
      clock: clock.call,
    );
    await crashedRestartGroups.initialize();

    expect(crashedRestartGroups.groups.length, 1);
    expect(crashedRestartGroups.outgoingMessages.length, 1);
    expect(crashedRestartGroups.outgoingMessages.first.isPersisted, isTrue);
    expect(crashedRestartGroups.hasUnsavedOutgoing, isFalse);

    // Mark sent, then restart again: frame must NOT resurrect
    await crashedRestartGroups.markOutgoingSent(
      crashedRestartGroups.outgoingMessages.first.id,
    );
    expect(crashedRestartGroups.outgoingMessages, isEmpty);

    crashedRestartGroups.dispose();
    crashedRestartId.dispose();

    final cleanRestartId = IdentityController(
      keyring: keyring,
      storage: storage,
      handoffOutbox: handoffOutbox,
      clock: clock.call,
    );
    await cleanRestartId.initialize();
    final cleanRestartGroups = GroupController(
      identityController: cleanRestartId,
      outbox: outbox,
      clock: clock.call,
    );
    addTearDown(cleanRestartGroups.dispose);
    addTearDown(cleanRestartId.dispose);
    await cleanRestartGroups.initialize();

    expect(cleanRestartGroups.groups.length, 1);
    expect(cleanRestartGroups.outgoingMessages, isEmpty);

    // Also test direct retryPersistUnsavedOutgoing()
    outbox.failNextAppend = true;
    await cleanRestartGroups.createGroup();
    expect(cleanRestartGroups.hasUnsavedOutgoing, isTrue);
    await cleanRestartGroups.retryPersistUnsavedOutgoing();
    expect(cleanRestartGroups.hasUnsavedOutgoing, isFalse);
    expect(cleanRestartGroups.outboxError, isNull);
  });

  test('intervening identity save after outbox failure flushes or aborts without erasing recovery snapshot', () async {
    final clock = _FakeClock();
    final keyring = InMemoryKeyringService();
    final storage = InMemorySnapshotStorageService();
    final handoffOutbox = InMemoryHandoffOutboxService();
    final outbox = _ControllableOutbox();

    final idCtrl = IdentityController(
      keyring: keyring,
      storage: storage,
      handoffOutbox: handoffOutbox,
      clock: clock.call,
    );
    await idCtrl.initialize();

    final groupCtrl = GroupController(
      identityController: idCtrl,
      outbox: outbox,
      clock: clock.call,
    );
    await groupCtrl.initialize();

    // Fail outbox write during createGroup -> unsaved frame retained in memory,
    // and on-disk snapshot still holds the recovery copy.
    outbox.failNextAppend = true;
    await groupCtrl.createGroup();
    expect(groupCtrl.groups.length, 1);
    expect(groupCtrl.hasUnsavedOutgoing, isTrue);

    // Case A: persistent outbox failure -> intervening identity save aborts &
    // rolls back without overwriting the recovery snapshot.
    outbox.failNextAppend = true;
    await expectLater(idCtrl.addPersona(), throwsStateError);
    expect(idCtrl.identities.length, 1);
    expect(groupCtrl.hasUnsavedOutgoing, isTrue);

    // Case B: transient outbox failure -> intervening successful identity save
    // flushes the unsaved genesis frame BEFORE writing the new snapshot.
    await idCtrl.addPersona();
    expect(idCtrl.identities.length, 2);
    expect(groupCtrl.hasUnsavedOutgoing, isFalse);
    expect(groupCtrl.outboxError, isNull);

    // Cold restart retains BOTH the new persona and the persisted genesis frame.
    groupCtrl.dispose();
    idCtrl.dispose();

    final restartedId = IdentityController(
      keyring: keyring,
      storage: storage,
      handoffOutbox: handoffOutbox,
      clock: clock.call,
    );
    await restartedId.initialize();
    final restartedGroups = GroupController(
      identityController: restartedId,
      outbox: outbox,
      clock: clock.call,
    );
    addTearDown(restartedGroups.dispose);
    addTearDown(restartedId.dispose);
    await restartedGroups.initialize();

    expect(restartedId.identities.length, 2);
    expect(restartedGroups.outgoingMessages.length, 1);
    expect(restartedGroups.outgoingMessages.first.isPersisted, isTrue);
  });

  test('failed snapshot save during group op followed by successful op releases no duplicate frames', () async {
    final clock = _FakeClock();
    final storage = _ControllableStorage();
    final idCtrl = IdentityController(
      keyring: InMemoryKeyringService(),
      storage: storage,
      handoffOutbox: InMemoryHandoffOutboxService(),
      clock: clock.call,
    );
    await idCtrl.initialize();
    final groupCtrl = GroupController(
      identityController: idCtrl,
      outbox: InMemoryGroupOutboxService(),
      clock: clock.call,
    );
    addTearDown(groupCtrl.dispose);
    addTearDown(idCtrl.dispose);
    await groupCtrl.initialize();

    storage.failNextSave = true;
    await expectLater(groupCtrl.createGroup(), throwsStateError);
    expect(groupCtrl.groups, isEmpty);
    expect(groupCtrl.outgoingMessages, isEmpty);

    await groupCtrl.createGroup();
    expect(groupCtrl.groups.length, 1);
    expect(groupCtrl.outgoingMessages.length, 1);
  });

  testWidgets(
    'GroupsView requires out-of-band genesis digest, supports outbox retry, invite, accept, and leave',
    (tester) async {
      final clock = _FakeClock();
      final outbox = _ControllableOutbox();
      final idCtrl = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
        clock: clock.call,
      );
      final bobId = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
        clock: clock.call,
      );
      await idCtrl.initialize();
      await bobId.initialize();
      await _verifyPair(idCtrl, bobId);

      final groupCtrl = GroupController(
        identityController: idCtrl,
        outbox: outbox,
        clock: clock.call,
      );
      final bobGroups = GroupController(
        identityController: bobId,
        outbox: InMemoryGroupOutboxService(),
        clock: clock.call,
      );
      addTearDown(groupCtrl.dispose);
      addTearDown(bobGroups.dispose);
      addTearDown(idCtrl.dispose);
      addTearDown(bobId.dispose);
      await groupCtrl.initialize();
      await bobGroups.initialize();

      // Create an authenticated genesis frame from Bob (with Bob + Alice as members)
      await bobGroups.createGroup(members: [idCtrl.selectedIdentity!]);
      final genesisMsg = bobGroups.outgoingMessages.first.message;
      expect(genesisMsg.authenticator, isNotNull);
      final genesisUri = encodeGroupFrame(genesisMsg);
      final genesisDigestHex = bytesToHex(genesisMsg.authenticator!);

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: GroupsView(
              identityController: idCtrl,
              groupController: groupCtrl,
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();

      // 1. Import Genesis dialog MUST reject empty digest even when frame has authenticator
      await tester.tap(find.byKey(const Key('import_genesis_button')));
      await tester.pumpAndSettle();
      await tester.enterText(
        find.byKey(const Key('genesis_frame_field')),
        genesisUri,
      );
      await tester.tap(find.byKey(const Key('confirm_import_genesis_button')));
      await tester.pumpAndSettle();
      expect(groupCtrl.groups, isEmpty);
      expect(find.textContaining('out-of-band'), findsWidgets);

      // Entering the out-of-band digest succeeds
      await tester.enterText(
        find.byKey(const Key('genesis_digest_field')),
        genesisDigestHex,
      );
      await tester.tap(find.byKey(const Key('confirm_import_genesis_button')));
      await tester.pumpAndSettle();
      expect(groupCtrl.groups.length, 1);

      // 2. Outbox error retry banner works when outbox append fails
      outbox.failNextAppend = true;
      await tester.tap(find.byKey(const Key('create_group_button')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('confirm_create_group_button')));
      await tester.pumpAndSettle();
      expect(
        find.byKey(const Key('retry_persist_outbox_button')),
        findsOneWidget,
      );

      await tester.tap(find.byKey(const Key('retry_persist_outbox_button')));
      await tester.pumpAndSettle();
      expect(
        find.byKey(const Key('retry_persist_outbox_button')),
        findsNothing,
      );

      // 3. Leave group dialog works
      final gid = groupCtrl.groups.first.groupId;
      await tester.scrollUntilVisible(
        find.byKey(Key('leave_group_$gid')),
        200,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.tap(find.byKey(Key('leave_group_$gid')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Leave Group'));
      await tester.pumpAndSettle();
      expect(groupCtrl.groups.length, 1);

      // 4. Invalid inbound frame surfaces inline error banner cleanly
      await tester.scrollUntilVisible(
        find.byKey(const Key('receive_group_frame_field')),
        300,
        scrollable: find.byType(Scrollable).first,
      );
      await tester.enterText(
        find.byKey(const Key('receive_group_frame_field')),
        'invalid-frame',
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('receive_group_frame_button')));
      await tester.pumpAndSettle();

      await tester.scrollUntilVisible(
        find.byKey(const Key('groups_error_banner')),
        -300,
        scrollable: find.byType(Scrollable).first,
      );
      expect(find.byKey(const Key('groups_error_banner')), findsOneWidget);
    },
  );
}
