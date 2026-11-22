import 'dart:typed_data';

import 'package:encounter/core/config.dart';
import 'package:encounter/main.dart';
import 'package:encounter/services/identity_controller.dart';
import 'package:encounter/services/keyring_service.dart';
import 'package:encounter/services/snapshot_storage.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  testWidgets('EncounterApp initializes and renders active persona status', (
    WidgetTester tester,
  ) async {
    final keyring = InMemoryKeyringService();
    final storage = InMemorySnapshotStorageService();
    final controller = IdentityController(keyring: keyring, storage: storage);
    addTearDown(controller.dispose);

    await controller.initialize();

    await tester.pumpWidget(EncounterApp(controller: controller));
    await tester.pumpAndSettle();

    expect(find.text(AppConfig.appName), findsOneWidget);
    expect(find.text('Active Persona'), findsOneWidget);
    expect(find.text('Personas: 1  •  Contacts: 0'), findsOneWidget);
  });

  testWidgets(
    'EncounterApp corrupted state requires confirmation dialog before reset',
    (WidgetTester tester) async {
      final keyring = InMemoryKeyringService();
      final storage = InMemorySnapshotStorageService();
      final corruptBytes = Uint8List.fromList([0x01, 0x02, 0x03, 0x04]);
      await storage.saveSnapshot(corruptBytes);

      final controller = IdentityController(keyring: keyring, storage: storage);
      addTearDown(controller.dispose);

      await controller.initialize();
      expect(controller.status, equals(IdentityStatus.corrupted));

      await tester.pumpWidget(EncounterApp(controller: controller));
      await tester.pumpAndSettle();

      expect(find.text('Identity Recovery Required'), findsOneWidget);
      expect(find.text('Reset Identity'), findsOneWidget);

      // Tap Reset Identity -> opens confirmation dialog
      await tester.tap(find.text('Reset Identity'));
      await tester.pumpAndSettle();
      expect(find.text('Reset Identity?'), findsOneWidget);

      // Dismissing dialog via Cancel leaves corrupted state intact
      await tester.tap(find.text('Cancel'));
      await tester.pumpAndSettle();
      expect(controller.status, equals(IdentityStatus.corrupted));
      expect(storage.archivedSnapshots, isEmpty);

      // Re-open dialog and confirm reset -> archives corrupt snapshot & recovers
      await tester.tap(find.text('Reset Identity'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Confirm Reset'));
      await tester.pumpAndSettle();

      expect(controller.status, equals(IdentityStatus.ready));
      expect(storage.archivedSnapshots, equals([corruptBytes]));
      expect(find.text('Active Persona'), findsOneWidget);
    },
  );
}
