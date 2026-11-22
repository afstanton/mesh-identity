import 'package:encounter/features/encounter/two_device_encounter_screen.dart';
import 'package:encounter/features/encounter/widgets/encounter_qr_view.dart';
import 'package:encounter/main.dart';
import 'package:encounter/services/encounter_session.dart';
import 'package:encounter/services/identity_controller.dart';
import 'package:encounter/services/keyring_service.dart';
import 'package:encounter/services/link_launcher.dart';
import 'package:encounter/services/snapshot_storage.dart';
import 'package:encounter/shell/theme_controller.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mesh_identity/mesh_identity.dart';

class _FakeClock {
  DateTime current;

  _FakeClock([DateTime? initial])
    : current =
          initial ?? DateTime.fromMillisecondsSinceEpoch(1_700_000_000_000);

  DateTime call() => current;

  void advance(Duration duration) {
    current = current.add(duration);
  }
}

class _ControllableStorage implements SnapshotStorageService {
  final InMemorySnapshotStorageService inner = InMemorySnapshotStorageService();
  bool failNextSave = false;

  @override
  Future<bool> hasSnapshot() => inner.hasSnapshot();

  @override
  Future<Uint8List?> loadSnapshot() => inner.loadSnapshot();

  @override
  Future<void> saveSnapshot(Uint8List snapshotBytes) async {
    if (failNextSave) {
      failNextSave = false;
      throw StateError('Simulated disk write failure');
    }
    await inner.saveSnapshot(snapshotBytes);
  }

  @override
  Future<String?> archiveSnapshot() => inner.archiveSnapshot();

  @override
  Future<void> deleteSnapshot() => inner.deleteSnapshot();
}

void _setViewport(WidgetTester tester, Size size) {
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1.0;
  addTearDown(() {
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();
  });
}

String _wrongSixDigits(EncounterComparison comparison) {
  final wrong = (comparison.code + 1) % 1000000;
  return wrong.toString().padLeft(6, '0');
}

void _installInMemoryClipboard(WidgetTester tester) {
  String? clipboardText;
  tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
    SystemChannels.platform,
    (MethodCall call) async {
      switch (call.method) {
        case 'Clipboard.setData':
          final args = call.arguments as Map<Object?, Object?>;
          clipboardText = args['text'] as String?;
          return null;
        case 'Clipboard.getData':
          if (clipboardText == null) return null;
          return <String, dynamic>{'text': clipboardText};
        case 'Clipboard.hasStrings':
          return <String, dynamic>{
            'value': clipboardText != null && clipboardText!.isNotEmpty,
          };
      }
      return null;
    },
  );
  addTearDown(() {
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      null,
    );
  });
}

void main() {
  group('TwoDeviceEncounterScreen & Hub Integration', () {
    testWidgets(
      'initiator full UI flow from Start Encounter through verification and back updates Contacts count',
      (WidgetTester tester) async {
        _setViewport(tester, const Size(1280, 800));
        _installInMemoryClipboard(tester);
        final clock = _FakeClock();

        final alice = IdentityController(
          keyring: InMemoryKeyringService(),
          storage: InMemorySnapshotStorageService(),
          clock: clock.call,
        );
        final bob = IdentityController(
          keyring: InMemoryKeyringService(),
          storage: InMemorySnapshotStorageService(),
          clock: clock.call,
        );
        addTearDown(alice.dispose);
        addTearDown(bob.dispose);

        await alice.initialize();
        await bob.initialize();

        await tester.pumpWidget(
          EncounterApp(controller: alice, linkLauncher: FakeLinkLauncher()),
        );
        await tester.pumpAndSettle();

        expect(find.text('Contacts: 0'), findsOneWidget);

        // Navigate into TwoDeviceEncounterScreen as Initiator.
        final startBtn = find.byKey(const Key('start_encounter_button'));
        await tester.ensureVisible(startBtn);
        await tester.tap(startBtn);
        await tester.pumpAndSettle();

        expect(find.byType(TwoDeviceEncounterScreen), findsOneWidget);
        expect(find.byType(EncounterQrView), findsOneWidget);
        expect(find.byKey(const Key('encounter_expiry_chip')), findsOneWidget);

        final qr1 = alice.encounterSession.outgoingUri!;

        // Simulate peer Bob generating QR 2 Response.
        await bob.openEncounterAsResponder();
        await bob.submitEncounterOffer(qr1);
        final qr2 = bob.encounterSession.outgoingUri!;

        // Use Clipboard + Paste button to import QR 2 on Alice.
        await Clipboard.setData(ClipboardData(text: qr2));
        final pasteBtn = find.byKey(const Key('encounter_paste_button'));
        await tester.ensureVisible(pasteBtn);
        await tester.tap(pasteBtn);
        await tester.pumpAndSettle();

        final submitBtn = find.byKey(const Key('encounter_submit_button'));
        await tester.ensureVisible(submitBtn);
        await tester.tap(submitBtn);
        await tester.pumpAndSettle();

        // Initiator now shows Reveal QR 3 and 6-digit SAS panel.
        expect(
          alice.encounterSession.phase,
          equals(EncounterPhase.initiatorShowingRevealAndCompare),
        );
        final qr3 = alice.encounterSession.outgoingUri!;
        await bob.submitEncounterReveal(qr3);
        final bobSas = bob.encounterSession.comparison!.formattedCode;

        expect(find.text(EncounterComparison.instruction), findsOneWidget);
        final confirmBtn = find.byKey(
          const Key('encounter_sas_confirm_button'),
        );
        expect(tester.widget<FilledButton>(confirmBtn).onPressed, isNull);

        await tester.enterText(
          find.byKey(const Key('encounter_sas_input')),
          bobSas,
        );
        await tester.pump();
        expect(tester.widget<FilledButton>(confirmBtn).onPressed, isNotNull);

        await tester.ensureVisible(confirmBtn);
        await tester.tap(confirmBtn);
        await tester.pumpAndSettle();

        expect(
          find.text(EncounterComparison.proximityDisclaimer),
          findsOneWidget,
        );
        expect(find.text(EncounterComparison.notIdentityProof), findsOneWidget);
        expect(
          find.text(EncounterUiText.localOnlyConfirmation),
          findsOneWidget,
        );

        final doneBtn = find.text('Done');
        await tester.ensureVisible(doneBtn);
        await tester.tap(doneBtn);
        await tester.pumpAndSettle();

        expect(find.byType(TwoDeviceEncounterScreen), findsNothing);
        expect(find.text('Contacts: 1'), findsOneWidget);
      },
    );

    testWidgets(
      'responder full UI flow from Join Encounter verifies contact on mobile viewport in dark theme',
      (WidgetTester tester) async {
        _setViewport(tester, const Size(390, 844));
        final clock = _FakeClock();

        final alice = IdentityController(
          keyring: InMemoryKeyringService(),
          storage: InMemorySnapshotStorageService(),
          clock: clock.call,
        );
        final bob = IdentityController(
          keyring: InMemoryKeyringService(),
          storage: InMemorySnapshotStorageService(),
          clock: clock.call,
        );
        final themeController = ThemeController(initialMode: ThemeMode.dark);
        addTearDown(alice.dispose);
        addTearDown(bob.dispose);
        addTearDown(themeController.dispose);

        await alice.initialize();
        await bob.initialize();

        await tester.pumpWidget(
          EncounterApp(
            controller: bob,
            themeController: themeController,
            linkLauncher: FakeLinkLauncher(),
          ),
        );
        await tester.pumpAndSettle();

        final joinBtn = find.byKey(const Key('join_encounter_button'));
        await tester.ensureVisible(joinBtn);
        await tester.tap(joinBtn);
        await tester.pumpAndSettle();

        expect(
          bob.encounterSession.phase,
          equals(EncounterPhase.responderAwaitingOffer),
        );

        await alice.startEncounterAsInitiator();
        final qr1 = alice.encounterSession.outgoingUri!;

        await tester.enterText(
          find.byKey(const Key('encounter_offer_field')),
          qr1,
        );
        await tester.pump();
        final submitOfferBtn = find.byKey(const Key('encounter_submit_button'));
        await tester.ensureVisible(submitOfferBtn);
        await tester.tap(submitOfferBtn);
        await tester.pumpAndSettle();

        expect(
          bob.encounterSession.phase,
          equals(EncounterPhase.responderShowingResponse),
        );
        expect(find.byType(EncounterQrView), findsOneWidget);

        final qr2 = bob.encounterSession.outgoingUri!;
        await alice.submitEncounterResponse(qr2);
        final qr3 = alice.encounterSession.outgoingUri!;

        await tester.enterText(
          find.byKey(const Key('encounter_reveal_field')),
          qr3,
        );
        await tester.pump();
        final submitRevealBtn = find.byKey(
          const Key('encounter_submit_button'),
        );
        await tester.ensureVisible(submitRevealBtn);
        await tester.tap(submitRevealBtn);
        await tester.pumpAndSettle();

        expect(
          bob.encounterSession.phase,
          equals(EncounterPhase.responderAwaitingConfirmation),
        );
        final aliceSas = alice.encounterSession.comparison!.formattedCode;

        await tester.enterText(
          find.byKey(const Key('encounter_sas_input')),
          aliceSas,
        );
        await tester.pump();
        final confirmBtn = find.byKey(
          const Key('encounter_sas_confirm_button'),
        );
        await tester.ensureVisible(confirmBtn);
        await tester.tap(confirmBtn);
        await tester.pumpAndSettle();

        expect(
          find.text(EncounterComparison.proximityDisclaimer),
          findsOneWidget,
        );

        final doneBtn = find.text('Done');
        await tester.ensureVisible(doneBtn);
        await tester.tap(doneBtn);
        await tester.pumpAndSettle();

        expect(find.text('Contacts: 1'), findsOneWidget);
      },
    );

    testWidgets(
      'cancel button and Navigator pop release active ceremony handle cleanly',
      (WidgetTester tester) async {
        _setViewport(tester, const Size(1280, 800));
        _installInMemoryClipboard(tester);
        final clock = _FakeClock();

        final controller = IdentityController(
          keyring: InMemoryKeyringService(),
          storage: InMemorySnapshotStorageService(),
          clock: clock.call,
        );
        addTearDown(controller.dispose);
        await controller.initialize();

        await tester.pumpWidget(
          EncounterApp(
            controller: controller,
            linkLauncher: FakeLinkLauncher(),
          ),
        );
        await tester.pumpAndSettle();

        // Cancel via AppBar button shows Ceremony Cancelled and clears active handle.
        await tester.tap(find.byKey(const Key('start_encounter_button')));
        await tester.pumpAndSettle();
        expect(controller.hasActiveEncounter, isTrue);

        await tester.tap(
          find.byKey(const Key('encounter_appbar_cancel_button')),
        );
        await tester.pumpAndSettle();
        expect(controller.hasActiveEncounter, isFalse);
        expect(find.text('Ceremony Cancelled'), findsOneWidget);

        // Start a fresh session then pop via AppBar back button triggers PopScope cleanup.
        await tester.tap(find.byKey(const Key('encounter_restart_button')));
        await tester.pumpAndSettle();
        expect(controller.hasActiveEncounter, isTrue);

        await tester.tap(find.byTooltip('Back'));
        await tester.pumpAndSettle();
        expect(find.byType(TwoDeviceEncounterScreen), findsNothing);
        expect(controller.hasActiveEncounter, isFalse);
      },
    );

    testWidgets(
      'backgrounding and resuming past 120s expires ceremony cleanly in UI',
      (WidgetTester tester) async {
        _setViewport(tester, const Size(1280, 800));
        _installInMemoryClipboard(tester);
        final clock = _FakeClock();

        final controller = IdentityController(
          keyring: InMemoryKeyringService(),
          storage: InMemorySnapshotStorageService(),
          clock: clock.call,
        );
        addTearDown(controller.dispose);
        await controller.initialize();

        await tester.pumpWidget(
          EncounterApp(
            controller: controller,
            linkLauncher: FakeLinkLauncher(),
          ),
        );
        await tester.pumpAndSettle();

        await tester.tap(find.byKey(const Key('start_encounter_button')));
        await tester.pumpAndSettle();
        expect(controller.hasActiveEncounter, isTrue);

        // Simulate OS backgrounding -> 125 seconds pass -> OS foreground resume.
        tester.binding.handleAppLifecycleStateChanged(
          AppLifecycleState.inactive,
        );
        tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
        tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
        clock.advance(const Duration(seconds: 125));
        tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
        tester.binding.handleAppLifecycleStateChanged(
          AppLifecycleState.inactive,
        );
        tester.binding.handleAppLifecycleStateChanged(
          AppLifecycleState.resumed,
        );
        await tester.pumpAndSettle();

        expect(find.text('Ceremony Expired'), findsOneWidget);
        expect(controller.hasActiveEncounter, isFalse);
      },
    );

    testWidgets(
      'rate-limited UI shows interferenceWarning countdown and disables Start/Join until cooldown elapses',
      (WidgetTester tester) async {
        _setViewport(tester, const Size(1280, 800));
        _installInMemoryClipboard(tester);
        final clock = _FakeClock();

        final alice = IdentityController(
          keyring: InMemoryKeyringService(),
          storage: InMemorySnapshotStorageService(),
          clock: clock.call,
        );
        final bob = IdentityController(
          keyring: InMemoryKeyringService(),
          storage: InMemorySnapshotStorageService(),
          clock: clock.call,
        );
        addTearDown(alice.dispose);
        addTearDown(bob.dispose);

        await alice.initialize();
        await bob.initialize();

        for (var i = 0; i < 3; i++) {
          await alice.startEncounterAsInitiator();
          await bob.openEncounterAsResponder();
          await bob.submitEncounterOffer(alice.encounterSession.outgoingUri!);
          await alice.submitEncounterResponse(
            bob.encounterSession.outgoingUri!,
          );
          await alice.confirmEncounterCode(
            _wrongSixDigits(alice.encounterSession.comparison!),
          );
          await bob.cancelActiveEncounter();
        }

        // Trigger the 4th attempt so controller enters rateLimited state.
        await alice.startEncounterAsInitiator();
        expect(
          alice.encounterSession.phase,
          equals(EncounterPhase.rateLimited),
        );

        await tester.pumpWidget(
          EncounterApp(controller: alice, linkLauncher: FakeLinkLauncher()),
        );
        await tester.pumpAndSettle();

        // Hub displays Interference warning + countdown and disables Start/Join.
        expect(find.text(EncounterUiText.interferenceWarning), findsOneWidget);
        expect(find.textContaining('01:00'), findsOneWidget);
        final startBtn = find.byKey(const Key('start_encounter_button'));
        final joinBtn = find.byKey(const Key('join_encounter_button'));
        expect(tester.widget<FilledButton>(startBtn).onPressed, isNull);
        expect(tester.widget<FilledButton>(joinBtn).onPressed, isNull);

        // Cooldown elapses -> checkEncounterExpiry re-enables buttons.
        clock.advance(const Duration(seconds: 61));
        await alice.checkEncounterExpiry();
        await tester.pumpAndSettle();

        expect(find.text(EncounterUiText.interferenceWarning), findsNothing);
        expect(tester.widget<FilledButton>(startBtn).onPressed, isNotNull);
        expect(tester.widget<FilledButton>(joinBtn).onPressed, isNotNull);
      },
    );

    testWidgets(
      'confirm persist failure shows localOnlyConfirmation notice and instructs starting a new encounter',
      (WidgetTester tester) async {
        _setViewport(tester, const Size(1280, 800));
        _installInMemoryClipboard(tester);
        final clock = _FakeClock();
        final aliceStorage = _ControllableStorage();

        final alice = IdentityController(
          keyring: InMemoryKeyringService(),
          storage: aliceStorage,
          clock: clock.call,
        );
        final bob = IdentityController(
          keyring: InMemoryKeyringService(),
          storage: InMemorySnapshotStorageService(),
          clock: clock.call,
        );
        addTearDown(alice.dispose);
        addTearDown(bob.dispose);

        await alice.initialize();
        await bob.initialize();

        await tester.pumpWidget(
          EncounterApp(controller: alice, linkLauncher: FakeLinkLauncher()),
        );
        await tester.pumpAndSettle();

        await tester.tap(find.byKey(const Key('start_encounter_button')));
        await tester.pumpAndSettle();

        await bob.openEncounterAsResponder();
        await bob.submitEncounterOffer(alice.encounterSession.outgoingUri!);

        await tester.enterText(
          find.byKey(const Key('encounter_response_field')),
          bob.encounterSession.outgoingUri!,
        );
        await tester.pump();
        final submitBtn = find.byKey(const Key('encounter_submit_button'));
        await tester.ensureVisible(submitBtn);
        await tester.tap(submitBtn);
        await tester.pumpAndSettle();

        await bob.submitEncounterReveal(alice.encounterSession.outgoingUri!);
        final bobSas = bob.encounterSession.comparison!.formattedCode;

        await tester.enterText(
          find.byKey(const Key('encounter_sas_input')),
          bobSas,
        );
        await tester.pump();

        aliceStorage.failNextSave = true;
        final confirmBtn = find.byKey(
          const Key('encounter_sas_confirm_button'),
        );
        await tester.ensureVisible(confirmBtn);
        await tester.tap(confirmBtn);
        await tester.pumpAndSettle();

        expect(find.text('Encounter Did Not Complete'), findsOneWidget);
        expect(
          find.textContaining('Start a new encounter'),
          findsAtLeastNWidgets(1),
        );
        expect(
          find.text(EncounterUiText.localOnlyConfirmation),
          findsOneWidget,
        );
        expect(alice.contactsCount, equals(0));
      },
    );
  });
}
