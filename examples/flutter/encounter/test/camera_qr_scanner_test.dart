import 'package:encounter/features/encounter/camera_qr_scanner_screen.dart';
import 'package:encounter/features/encounter/two_device_encounter_screen.dart';
import 'package:encounter/features/encounter/widgets/encounter_payload_input.dart';
import 'package:encounter/services/encounter_session.dart';
import 'package:encounter/services/identity_controller.dart';
import 'package:encounter/services/keyring_service.dart';
import 'package:encounter/services/qr_scanner_service.dart';
import 'package:encounter/services/snapshot_storage.dart';
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

void main() {
  test('validateScannedEncounterUri enforces prefix, trim, and max length', () {
    expect(
      maxScannedEncounterUriChars,
      QrTransport.uriPrefix.length + QrTransport.maxB64Length,
    );
    expect(validateScannedEncounterUri(null), isNull);
    expect(validateScannedEncounterUri('   '), isNull);
    expect(validateScannedEncounterUri('https://example.com'), isNull);
    expect(validateScannedEncounterUri('mesh:handoff:abc'), isNull);

    final valid = '  mesh:encounter:v1:abc123  ';
    expect(validateScannedEncounterUri(valid), 'mesh:encounter:v1:abc123');

    final oversized =
        'mesh:encounter:${'a' * (maxScannedEncounterUriChars + 1)}';
    expect(validateScannedEncounterUri(oversized), isNull);
  });

  testWidgets(
    'EncounterPayloadInput handles scanned, denied, error, and unsupported',
    (tester) async {
      String? submitted;

      // 1. Supported camera scan auto-submits payload
      final scanner = FakeQrScannerService(
        queuedResults: const [
          QrScanResult.permissionDenied('Camera access denied in Settings.'),
          QrScanResult.error('No camera found.'),
          QrScanResult.cancelled(),
          QrScanResult.scanned('mesh:encounter:v1:scanned_payload'),
        ],
      );

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EncounterPayloadInput(
              title: 'Import Offer',
              hintText: 'mesh:encounter:...',
              submitLabel: 'Submit',
              qrScanner: scanner,
              textFieldKey: const Key('payload_field'),
              pasteButtonKey: const Key('paste_btn'),
              submitButtonKey: const Key('submit_btn'),
              onSubmit: (value) => submitted = value,
            ),
          ),
        ),
      );

      expect(find.byKey(const Key('encounter_scan_qr_button')), findsOneWidget);

      // Permission denied shows fallback notice without submitting
      await tester.tap(find.byKey(const Key('encounter_scan_qr_button')));
      await tester.pumpAndSettle();
      expect(
        find.byKey(const Key('encounter_scanner_fallback_notice')),
        findsOneWidget,
      );
      expect(find.text('Camera access denied in Settings.'), findsOneWidget);
      expect(submitted, isNull);

      // Error shows fallback notice without submitting
      await tester.tap(find.byKey(const Key('encounter_scan_qr_button')));
      await tester.pumpAndSettle();
      expect(find.text('No camera found.'), findsOneWidget);
      expect(submitted, isNull);

      // Cancelled leaves submitted null
      await tester.tap(find.byKey(const Key('encounter_scan_qr_button')));
      await tester.pumpAndSettle();
      expect(submitted, isNull);

      // Successful scan clears notice and submits
      await tester.tap(find.byKey(const Key('encounter_scan_qr_button')));
      await tester.pumpAndSettle();
      expect(submitted, 'mesh:encounter:v1:scanned_payload');
      expect(
        find.byKey(const Key('encounter_scanner_fallback_notice')),
        findsNothing,
      );

      // 2. Unsupported platform omits Scan QR button and shows manual hint
      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EncounterPayloadInput(
              title: 'Import Offer',
              hintText: 'mesh:encounter:...',
              submitLabel: 'Submit',
              qrScanner: FakeQrScannerService(isCameraSupported: false),
              onSubmit: (_) {},
            ),
          ),
        ),
      );
      expect(find.byKey(const Key('encounter_scan_qr_button')), findsNothing);
      expect(
        find.text('Paste or enter your peer\'s Encounter URI manually.'),
        findsOneWidget,
      );
    },
  );

  testWidgets(
    'TwoDeviceEncounterScreen completes full handshake via FakeQrScannerService',
    (tester) async {
      final clock = _FakeClock();
      final initiator = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        clock: clock.call,
      );
      final responder = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        clock: clock.call,
      );
      addTearDown(initiator.dispose);
      addTearDown(responder.dispose);
      await initiator.initialize();
      await responder.initialize();

      final fakeScanner = FakeQrScannerService(
        onScan: (context, title, instruction) async {
          // Initiator is scanning Responder's QR 2 Response.
          final offerUri = initiator.encounterSession.outgoingUri!;
          await responder.openEncounterAsResponder();
          await responder.submitEncounterOffer(offerUri);
          return QrScanResult.scanned(responder.encounterSession.outgoingUri!);
        },
      );

      await tester.pumpWidget(
        MaterialApp(
          home: TwoDeviceEncounterScreen(
            controller: initiator,
            initialRole: EncounterRole.initiator,
            qrScanner: fakeScanner,
          ),
        ),
      );
      await tester.pumpAndSettle();

      // Tap Scan QR Code to import QR 2 Response via camera abstraction
      await tester.ensureVisible(
        find.byKey(const Key('encounter_scan_qr_button')),
      );
      await tester.tap(find.byKey(const Key('encounter_scan_qr_button')));
      await tester.pumpAndSettle();

      // Initiator is now in Step 3 showing Reveal (QR 3) and 6-digit SAS code
      final sasCode = initiator.encounterSession.comparison!.formattedCode;
      final revealUri = initiator.encounterSession.outgoingUri!;
      await responder.submitEncounterReveal(revealUri);

      // Enter 6-digit SAS code manually (never auto-confirmed by scanner)
      await tester.ensureVisible(find.byKey(const Key('encounter_sas_input')));
      await tester.enterText(
        find.byKey(const Key('encounter_sas_input')),
        sasCode,
      );
      await tester.pump();
      await tester.ensureVisible(
        find.byKey(const Key('encounter_sas_confirm_button')),
      );
      await tester.tap(find.byKey(const Key('encounter_sas_confirm_button')));
      await tester.pumpAndSettle();

      expect(initiator.contactsCount, 1);
      expect(find.text('Contact Verified'), findsOneWidget);
    },
  );

  testWidgets(
    'EncounterPayloadInput cancels scan when session becomes inactive',
    (tester) async {
      final notifier = ChangeNotifier();
      addTearDown(notifier.dispose);
      var active = true;
      String? submitted;

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: EncounterPayloadInput(
              title: 'Import Offer',
              hintText: 'mesh:encounter:...',
              submitLabel: 'Submit',
              qrScanner: FakeQrScannerService(),
              sessionListenable: notifier,
              isSessionActive: () => active,
              onSubmit: (value) => submitted = value,
            ),
          ),
        ),
      );

      active = false;
      await tester.tap(find.byKey(const Key('encounter_scan_qr_button')));
      await tester.pumpAndSettle();

      expect(submitted, isNull);
      expect(
        find.byKey(const Key('encounter_scanner_fallback_notice')),
        findsNothing,
      );
    },
  );

  testWidgets(
    'CameraQrScannerScreen shows Camera Unavailable and hides instruction footer when no camera exists',
    (tester) async {
      const instruction =
          'Point your camera at your peer\'s Step 1 Offer QR code.';
      await tester.pumpWidget(
        MaterialApp(
          home: CameraQrScannerScreen(
            title: 'Scan Offer',
            instruction: instruction,
            availableCamerasLoader: () async => const [],
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('Camera Unavailable'), findsOneWidget);
      expect(
        find.byKey(const Key('camera_scanner_open_settings_button')),
        findsNothing,
      );
      expect(find.text(instruction), findsNothing);
      expect(
        find.byKey(const Key('camera_scanner_manual_fallback_button')),
        findsOneWidget,
      );
    },
  );

  testWidgets(
    'CameraQrScannerScreen shows Camera Access Required with Open Settings and hides instruction footer on permission denial',
    (tester) async {
      const instruction =
          'Point your camera at your peer\'s Step 1 Offer QR code.';
      var openedSettings = false;
      await tester.pumpWidget(
        MaterialApp(
          home: CameraQrScannerScreen(
            title: 'Scan Offer',
            instruction: instruction,
            availableCamerasLoader: () async {
              throw Exception('CameraAccessDenied: User denied camera access');
            },
            openAppSettings: () async {
              openedSettings = true;
            },
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('Camera Access Required'), findsOneWidget);
      expect(find.text('Camera Unavailable'), findsNothing);
      expect(find.text(instruction), findsNothing);

      final settingsBtn = find.byKey(
        const Key('camera_scanner_open_settings_button'),
      );
      expect(settingsBtn, findsOneWidget);
      await tester.tap(settingsBtn);
      await tester.pump();
      expect(openedSettings, isTrue);
    },
  );
}
