import 'package:encounter/features/encounter/practice_encounter_controller.dart';
import 'package:encounter/features/encounter/practice_encounter_screen.dart';
import 'package:encounter/features/encounter/widgets/encounter_qr_view.dart';
import 'package:encounter/main.dart';
import 'package:encounter/services/encounter_session.dart';
import 'package:encounter/services/identity_controller.dart';
import 'package:encounter/services/keyring_service.dart';
import 'package:encounter/services/link_launcher.dart';
import 'package:encounter/services/snapshot_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mesh_identity/mesh_identity.dart';

String _wrongSixDigits(EncounterComparison comparison) {
  final wrong = (comparison.code + 1) % 1000000;
  return wrong.toString().padLeft(6, '0');
}

void main() {
  group('PracticeEncounterController', () {
    test('executes isolated Offer -> Response -> Reveal -> dual SAS confirmation without affecting IdentityController', () async {
      final identityController = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
      );
      await identityController.initialize();
      addTearDown(identityController.dispose);

      final practice = PracticeEncounterController();
      addTearDown(practice.dispose);

      expect(practice.step, equals(PracticeStep.offerReady));
      expect(practice.offerUri, startsWith(QrTransport.uriPrefix));

      practice.deliverOfferToBob();
      expect(practice.step, equals(PracticeStep.responseReady));
      expect(practice.responseUri, startsWith(QrTransport.uriPrefix));

      practice.deliverResponseToAlice();
      expect(practice.step, equals(PracticeStep.revealReady));
      expect(practice.revealUri, startsWith(QrTransport.uriPrefix));
      expect(practice.aliceComparison, isNotNull);

      practice.deliverRevealToBob();
      expect(practice.step, equals(PracticeStep.comparing));
      expect(practice.bobComparison, isNotNull);
      expect(
        practice.aliceComparison!.code,
        equals(practice.bobComparison!.code),
      );

      // Partial digit input keeps outcome pending with inline error.
      practice.confirmAlice('123');
      expect(practice.aliceOutcome, equals(PracticePartyOutcome.pending));
      expect(practice.aliceError, isNotNull);

      // Full 6-digit manual entry confirms both sides independently.
      practice.confirmAlice(practice.bobComparison!.formattedCode);
      practice.confirmBob(practice.aliceComparison!.formattedCode);

      expect(practice.aliceOutcome, equals(PracticePartyOutcome.verified));
      expect(practice.bobOutcome, equals(PracticePartyOutcome.verified));
      expect(
        practice.aliceVerifiedContact!.peerPublicKey,
        equals(practice.bobPublicKey),
      );
      expect(
        practice.bobVerifiedContact!.peerPublicKey,
        equals(practice.alicePublicKey),
      );

      // Real persisted installation remains untouched.
      expect(identityController.contactsCount, equals(0));
      expect(identityController.identities, hasLength(1));
    });

    test('wrong SAS cancels Alice independently while Bob can still confirm, and restart creates fresh keys', () {
      final practice = PracticeEncounterController();
      addTearDown(practice.dispose);

      final firstAlicePk = practice.alicePublicKey;
      practice.deliverOfferToBob();
      practice.deliverResponseToAlice();
      practice.deliverRevealToBob();

      practice.confirmAlice(_wrongSixDigits(practice.bobComparison!));
      expect(practice.aliceOutcome, equals(PracticePartyOutcome.failed));
      expect(practice.aliceError, isNotNull);

      practice.confirmBob(practice.aliceComparison!.formattedCode);
      expect(practice.bobOutcome, equals(PracticePartyOutcome.verified));

      practice.restart();
      expect(practice.step, equals(PracticeStep.offerReady));
      expect(practice.aliceOutcome, equals(PracticePartyOutcome.pending));
      expect(practice.bobOutcome, equals(PracticePartyOutcome.pending));
      expect(practice.alicePublicKey, isNot(equals(firstAlicePk)));
    });
  });

  group('PracticeEncounterScreen', () {
    testWidgets(
      'drives full practice flow through EncounterQrView and manual 6-digit SAS confirmation',
      (WidgetTester tester) async {
        tester.view.physicalSize = const Size(1280, 900);
        tester.view.devicePixelRatio = 1.0;
        addTearDown(() {
          tester.view.resetPhysicalSize();
          tester.view.resetDevicePixelRatio();
        });

        final identityController = IdentityController(
          keyring: InMemoryKeyringService(),
          storage: InMemorySnapshotStorageService(),
        );
        await identityController.initialize();
        addTearDown(identityController.dispose);

        await tester.pumpWidget(
          EncounterApp(
            controller: identityController,
            linkLauncher: FakeLinkLauncher(),
          ),
        );
        await tester.pumpAndSettle();

        final practiceBtn = find.byKey(const Key('practice_mode_button'));
        await tester.ensureVisible(practiceBtn);
        await tester.tap(practiceBtn);
        await tester.pumpAndSettle();

        expect(find.byType(PracticeEncounterScreen), findsOneWidget);
        expect(
          find.textContaining('Practice Mode — Uses temporary in-memory keys.'),
          findsOneWidget,
        );
        expect(find.byType(EncounterQrView), findsOneWidget);

        // Step 1 -> Step 2
        final sendOffer = find.byKey(const Key('practice_send_offer'));
        await tester.ensureVisible(sendOffer);
        await tester.tap(sendOffer);
        await tester.pumpAndSettle();
        expect(find.byType(EncounterQrView), findsOneWidget);

        // Step 2 -> Step 3
        final sendResp = find.byKey(const Key('practice_send_response'));
        await tester.ensureVisible(sendResp);
        await tester.tap(sendResp);
        await tester.pumpAndSettle();
        expect(find.byType(EncounterQrView), findsOneWidget);

        // Step 3 -> Step 4
        final sendReveal = find.byKey(const Key('practice_send_reveal'));
        await tester.ensureVisible(sendReveal);
        await tester.tap(sendReveal);
        await tester.pumpAndSettle();

        // Mandatory SAS instruction visible for both panels.
        expect(find.text(EncounterComparison.instruction), findsNWidgets(2));

        // Confirm buttons disabled before 6 digits are typed.
        final aliceConfirm = find.byKey(const Key('practice_alice_confirm'));
        final bobConfirm = find.byKey(const Key('practice_bob_confirm'));
        expect(tester.widget<FilledButton>(aliceConfirm).onPressed, isNull);
        expect(tester.widget<FilledButton>(bobConfirm).onPressed, isNull);

        // Read displayed codes and confirm manually.
        final aliceSasText = tester
            .widget<SelectableText>(find.byKey(const Key('practice_alice_sas')))
            .data!
            .replaceAll(' ', '');
        final bobSasText = tester
            .widget<SelectableText>(find.byKey(const Key('practice_bob_sas')))
            .data!
            .replaceAll(' ', '');
        expect(aliceSasText.length, equals(6));
        expect(aliceSasText, equals(bobSasText));

        // Typing partial code keeps Confirm disabled.
        await tester.enterText(
          find.byKey(const Key('practice_alice_input')),
          bobSasText.substring(0, 5),
        );
        await tester.pump();
        expect(tester.widget<FilledButton>(aliceConfirm).onPressed, isNull);

        // Complete 6 digits enables Confirm.
        await tester.enterText(
          find.byKey(const Key('practice_alice_input')),
          bobSasText,
        );
        await tester.pump();
        expect(tester.widget<FilledButton>(aliceConfirm).onPressed, isNotNull);

        await tester.ensureVisible(aliceConfirm);
        await tester.tap(aliceConfirm);
        await tester.pumpAndSettle();

        await tester.enterText(
          find.byKey(const Key('practice_bob_input')),
          aliceSasText,
        );
        await tester.pump();
        await tester.ensureVisible(bobConfirm);
        await tester.tap(bobConfirm);
        await tester.pumpAndSettle();

        // Statutory disclaimers shown on both verified cards.
        expect(
          find.text(EncounterComparison.proximityDisclaimer),
          findsNWidgets(2),
        );
        expect(
          find.text(EncounterComparison.notIdentityProof),
          findsNWidgets(2),
        );
        expect(
          find.textContaining(EncounterUiText.localOnlyConfirmation),
          findsNWidgets(2),
        );

        // Persisted IdentityController remains untouched.
        expect(identityController.contactsCount, equals(0));
      },
    );

    testWidgets(
      'mobile viewport focuses active party per step, auto-switches to Bob after Alice confirms, and formats local timestamp',
      (WidgetTester tester) async {
        tester.view.physicalSize = const Size(390, 844);
        tester.view.devicePixelRatio = 1.0;
        addTearDown(() {
          tester.view.resetPhysicalSize();
          tester.view.resetDevicePixelRatio();
        });

        await tester.pumpWidget(
          const MaterialApp(home: PracticeEncounterScreen()),
        );
        await tester.pumpAndSettle();

        expect(find.byKey(const Key('practice_step_banner')), findsOneWidget);
        expect(find.text('Alice (Initiator)'), findsOneWidget);
        expect(find.text('Bob (Responder)'), findsNothing);

        final sendOffer = find.byKey(const Key('practice_send_offer'));
        await tester.ensureVisible(sendOffer);
        await tester.tap(sendOffer);
        await tester.pumpAndSettle();
        expect(find.text('Bob (Responder)'), findsOneWidget);
        expect(find.text('Alice (Initiator)'), findsNothing);

        final sendResponse = find.byKey(const Key('practice_send_response'));
        await tester.ensureVisible(sendResponse);
        await tester.tap(sendResponse);
        await tester.pumpAndSettle();
        expect(find.text('Alice (Initiator)'), findsOneWidget);

        final sendReveal = find.byKey(const Key('practice_send_reveal'));
        await tester.ensureVisible(sendReveal);
        await tester.tap(sendReveal);
        await tester.pumpAndSettle();

        expect(
          find.byKey(const Key('practice_party_selector')),
          findsOneWidget,
        );
        expect(find.text("Alice's 6-digit code:"), findsOneWidget);

        final aliceSasText = tester
            .widget<SelectableText>(find.byKey(const Key('practice_alice_sas')))
            .data!
            .replaceAll(' ', '');
        await tester.enterText(
          find.byKey(const Key('practice_alice_input')),
          aliceSasText,
        );
        await tester.pump();
        final aliceConfirm = find.byKey(const Key('practice_alice_confirm'));
        await tester.ensureVisible(aliceConfirm);
        await tester.tap(aliceConfirm);
        await tester.pumpAndSettle();

        // Auto-switches to Bob's SAS panel on narrow viewport.
        expect(find.text("Bob's 6-digit code:"), findsOneWidget);
        await tester.enterText(
          find.byKey(const Key('practice_bob_input')),
          aliceSasText,
        );
        await tester.pump();
        final bobConfirm = find.byKey(const Key('practice_bob_confirm'));
        await tester.ensureVisible(bobConfirm);
        await tester.tap(bobConfirm);
        await tester.pumpAndSettle();

        expect(find.text('Bob Verified Alice'), findsOneWidget);
        expect(find.textContaining('Verified: '), findsOneWidget);
        expect(find.textContaining('Verified (UTC):'), findsNothing);
      },
    );
  });
}
