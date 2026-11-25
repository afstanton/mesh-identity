import 'package:encounter/features/identity/identity_view.dart';
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
        builder: (context, _) => IdentityView(controller: controller),
      ),
    ),
  );
}

void main() {
  testWidgets(
    'add, switch, per-persona contact count, remove, and restart persistence',
    (tester) async {
      final keyring = InMemoryKeyringService();
      final storage = InMemorySnapshotStorageService();
      final clock = _FakeClock();
      final controller = IdentityController(
        keyring: keyring,
        storage: storage,
        clock: clock.call,
      );
      await controller.initialize();

      final firstPersona = controller.selectedIdentity!;
      final firstHex = formatHexKey(firstPersona);
      final peerSeed = Uint8List.fromList(List<int>.filled(32, 0x44));
      final peerInst = MeshInstallation(seed: peerSeed);
      final peerKey = Uint8List.fromList(peerInst.selectedIdentity);
      peerInst.dispose();
      await controller.importPeerKey(peerKey);

      await tester.pumpWidget(_wrap(controller));
      await tester.pumpAndSettle();

      // Active persona has Active chip and no Remove/Switch button
      expect(find.byKey(const Key('active_persona_chip')), findsOneWidget);
      expect(find.byKey(Key('remove_persona_$firstHex')), findsNothing);
      expect(find.byKey(Key('switch_persona_$firstHex')), findsNothing);
      expect(find.text('1 contact'), findsOneWidget);

      // Add second persona with an optional display name
      await tester.tap(find.byKey(const Key('add_persona_button')));
      await tester.pumpAndSettle();
      await tester.enterText(
        find.byKey(const Key('persona_name_field')),
        'Work',
      );
      await tester.tap(find.byKey(const Key('confirm_add_persona_button')));
      await tester.pumpAndSettle();

      expect(controller.identities.length, 2);
      expect(find.text('Work'), findsOneWidget);
      final secondPersona = controller.identities.firstWhere(
        (k) => !listEquals(k, firstPersona),
      );
      final secondHex = formatHexKey(secondPersona);
      expect(find.text('0 contacts'), findsOneWidget);

      // Switch to second persona
      ScaffoldMessenger.of(tester.element(find.byType(IdentityView)))
          .clearSnackBars();
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.byKey(Key('switch_persona_$secondHex')));
      await tester.tap(find.byKey(Key('switch_persona_$secondHex')));
      await tester.pumpAndSettle();

      expect(listEquals(controller.selectedIdentity, secondPersona), isTrue);
      expect(find.byKey(Key('remove_persona_$secondHex')), findsNothing);
      expect(find.byKey(Key('remove_persona_$firstHex')), findsOneWidget);

      // Switch back to first persona so we can remove the second
      await tester.ensureVisible(find.byKey(Key('switch_persona_$firstHex')));
      await tester.tap(find.byKey(Key('switch_persona_$firstHex')));
      await tester.pumpAndSettle();

      // Remove second persona with confirmation
      await tester.ensureVisible(find.byKey(Key('remove_persona_$secondHex')));
      await tester.tap(find.byKey(Key('remove_persona_$secondHex')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('confirm_remove_persona_button')));
      await tester.pumpAndSettle();

      expect(controller.identities.length, 1);

      // Verify persistence across cold restart
      controller.dispose();
      final restarted = IdentityController(
        keyring: keyring,
        storage: storage,
        clock: clock.call,
      );
      addTearDown(restarted.dispose);
      await restarted.initialize();
      expect(restarted.identities.length, 1);
      expect(listEquals(restarted.selectedIdentity, firstPersona), isTrue);
      expect(restarted.contactsCount, 1);
    },
  );

  testWidgets('disables persona actions while encounter ceremony is active', (
    tester,
  ) async {
    final controller = IdentityController(
      keyring: InMemoryKeyringService(),
      storage: InMemorySnapshotStorageService(),
      clock: _FakeClock().call,
    );
    addTearDown(controller.dispose);
    await controller.initialize();
    await controller.addPersona();
    await controller.startEncounterAsInitiator();

    await tester.pumpWidget(_wrap(controller));
    await tester.pumpAndSettle();

    expect(
      find.text(
        'Persona changes are disabled while an encounter ceremony is active.',
      ),
      findsOneWidget,
    );
    final addButton = tester.widget<FilledButton>(
      find.byKey(const Key('add_persona_button')),
    );
    expect(addButton.onPressed, isNull);
  });

  testWidgets(
    'Import Backup Key dialog shows live 64-char counter, plain error, and clears error on edit',
    (tester) async {
      final controller = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        clock: _FakeClock().call,
      );
      addTearDown(controller.dispose);
      await controller.initialize();

      await tester.pumpWidget(_wrap(controller));
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('import_persona_seed_button')));
      await tester.pumpAndSettle();

      expect(find.text('0 / 64 characters'), findsOneWidget);
      await tester.enterText(
        find.byKey(const Key('import_persona_seed_field')),
        'abcd',
      );
      await tester.pump();
      expect(find.text('4 / 64 characters'), findsOneWidget);

      await tester.tap(
        find.byKey(const Key('confirm_import_persona_seed_button')),
      );
      await tester.pumpAndSettle();
      expect(
        find.text('Enter a 64-character hexadecimal backup key.'),
        findsOneWidget,
      );
      expect(find.textContaining('Ed25519'), findsNothing);

      await tester.enterText(
        find.byKey(const Key('import_persona_seed_field')),
        'abcde',
      );
      await tester.pumpAndSettle();
      expect(find.text('5 / 64 characters'), findsOneWidget);
      expect(
        find.text('Enter a 64-character hexadecimal backup key.'),
        findsNothing,
      );
    },
  );
}
