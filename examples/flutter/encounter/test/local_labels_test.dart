import 'package:encounter/features/groups/groups_view.dart';
import 'package:encounter/services/group_controller.dart';
import 'package:encounter/services/group_outbox.dart';
import 'package:encounter/services/identity_controller.dart';
import 'package:encounter/services/keyring_service.dart';
import 'package:encounter/services/local_labels_service.dart';
import 'package:encounter/services/snapshot_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

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
}
