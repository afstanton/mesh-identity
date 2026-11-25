import 'dart:typed_data';

import 'package:encounter/features/encounter/two_device_encounter_screen.dart';
import 'package:encounter/services/ble_encounter_codec.dart';
import 'package:encounter/services/ble_encounter_transport.dart';
import 'package:encounter/services/encounter_session.dart';
import 'package:encounter/services/handoff_outbox.dart';
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
    : current = initial ?? DateTime.utc(2026, 6, 1, 12, 0, 0);

  DateTime call() => current;
}

void main() {
  test(
    'ble_encounter_codec chunks, reassembles out-of-order, and enforces bounds',
    () {
      expect(classifyBleProximity(-45), BleProximityBand.immediate);
      expect(classifyBleProximity(-65), BleProximityBand.near);
      expect(classifyBleProximity(-85), BleProximityBand.far);

      for (final mtu in [20, 64, 180]) {
        final payload = Uint8List.fromList(
          List<int>.generate(300, (i) => i & 0xFF),
        );
        final chunks = encodeBleChunks(payload, maxChunkPayloadBytes: mtu);
        final reassembler = BleChunkReassembler();

        // Feed in reverse order to verify out-of-order reassembly.
        Uint8List? result;
        for (final chunk in chunks.reversed) {
          result = reassembler.addChunk(chunk);
        }
        expect(result, equals(payload));
      }

      // Defensive bounds
      expect(() => encodeBleChunks(Uint8List(0)), throwsFormatException);
      expect(
        () => encodeBleChunks(Uint8List(maxBleEncounterPayloadBytes + 1)),
        throwsFormatException,
      );

      final reassembler = BleChunkReassembler();
      expect(
        () => reassembler.addChunk(Uint8List.fromList([0, 1, 0, 1])),
        throwsFormatException,
      );
      expect(
        () => reassembler.addChunk(Uint8List.fromList([0, 1, 3, 0, 1])),
        throwsFormatException,
      );
      expect(
        () => reassembler.addChunk(Uint8List.fromList([2, 2, 0, 1, 1])),
        throwsFormatException,
      );

      // Reassembler resets on malformed/mismatched chunks so subsequent valid
      // payloads still reassemble cleanly, including duplicate chunks.
      final validPayload = Uint8List.fromList(
        List<int>.generate(60, (i) => (i * 3) & 0xFF),
      );
      final validChunks = encodeBleChunks(
        validPayload,
        maxChunkPayloadBytes: 20,
      );
      reassembler.addChunk(validChunks.first);
      expect(
        () => reassembler.addChunk(Uint8List.fromList([0, 2, 0, 10, 1, 2])),
        throwsFormatException,
      );
      Uint8List? recovered;
      reassembler.addChunk(validChunks.first);
      for (final chunk in validChunks) {
        recovered = reassembler.addChunk(chunk);
      }
      expect(recovered, equals(validPayload));
    },
  );

  test('InMemoryBleEncounterTransport completes Offer -> Response -> Reveal and persists verified contact across restart', () async {
    final clock = _FakeClock();
    final aliceKeyring = InMemoryKeyringService();
    final aliceStorage = InMemorySnapshotStorageService();
    final aliceOutbox = InMemoryHandoffOutboxService();
    final alice = IdentityController(
      keyring: aliceKeyring,
      storage: aliceStorage,
      handoffOutbox: aliceOutbox,
      clock: clock.call,
    );
    final bob = IdentityController(
      keyring: InMemoryKeyringService(),
      storage: InMemorySnapshotStorageService(),
      handoffOutbox: InMemoryHandoffOutboxService(),
      clock: clock.call,
    );
    await alice.initialize();
    await bob.initialize();

    final channel = InMemoryBleChannel(rssi: -48);
    final aliceBle = channel.createInitiatorTransport();
    final bobBle = channel.createResponderTransport();
    addTearDown(aliceBle.dispose);
    addTearDown(bobBle.dispose);

    await alice.startEncounterAsInitiator();
    await bob.openEncounterAsResponder();

    final offerBytes = Uint8List.fromList(
      QrTransport.decodeUri(alice.encounterSession.outgoingUri!),
    );
    await aliceBle.startInitiatorPeripheral(
      offerBytes: offerBytes,
      onResponseReceived: (responseBytes) async {
        await alice.submitEncounterResponse(
          QrTransport.encodeUri(responseBytes),
        );
        return Uint8List.fromList(
          QrTransport.decodeUri(alice.encounterSession.outgoingUri!),
        );
      },
    );

    final peersFuture = bobBle.discoveredPeersStream.first;
    await bobBle.startResponderScan();
    final peers = await peersFuture;
    expect(peers, hasLength(1));
    expect(peers.first.proximity, BleProximityBand.immediate);

    await bobBle.connectAndExchangeAsResponder(
      peerId: peers.first.id,
      onOfferReceived: (offer) async {
        await bob.submitEncounterOffer(QrTransport.encodeUri(offer));
        return Uint8List.fromList(
          QrTransport.decodeUri(bob.encounterSession.outgoingUri!),
        );
      },
      onRevealReceived: (reveal) async {
        await bob.submitEncounterReveal(QrTransport.encodeUri(reveal));
      },
    );

    expect(
      alice.encounterSession.phase,
      EncounterPhase.initiatorShowingRevealAndCompare,
    );
    expect(
      bob.encounterSession.phase,
      EncounterPhase.responderAwaitingConfirmation,
    );
    final sas = alice.encounterSession.comparison!.formattedCode;
    expect(sas, bob.encounterSession.comparison!.formattedCode);

    // Manual SAS confirmation required on both devices
    await alice.confirmEncounterCode(sas);
    await bob.confirmEncounterCode(sas);
    expect(alice.contactsCount, 1);
    expect(bob.contactsCount, 1);

    alice.dispose();
    bob.dispose();

    final restartedAlice = IdentityController(
      keyring: aliceKeyring,
      storage: aliceStorage,
      handoffOutbox: aliceOutbox,
      clock: clock.call,
    );
    addTearDown(restartedAlice.dispose);
    await restartedAlice.initialize();
    expect(restartedAlice.contactsCount, 1);
  });

  testWidgets(
    'TwoDeviceEncounterScreen scans BLE peer with proximity indicator, exchanges payloads, and hands over to SAS screen',
    (tester) async {
      final clock = _FakeClock();
      final alice = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
        clock: clock.call,
      );
      final bob = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
        clock: clock.call,
      );
      await alice.initialize();
      await bob.initialize();
      addTearDown(alice.dispose);
      addTearDown(bob.dispose);

      final channel = InMemoryBleChannel(
        peerId: 'alice-ble',
        peerName: 'Alice Mesh Node',
        rssi: -48,
      );
      final aliceBle = channel.createInitiatorTransport();
      final bobBle = channel.createResponderTransport();
      addTearDown(aliceBle.dispose);
      addTearDown(bobBle.dispose);

      // Alice advertises her Offer in the background
      await alice.startEncounterAsInitiator();
      await aliceBle.startInitiatorPeripheral(
        offerBytes: Uint8List.fromList(
          QrTransport.decodeUri(alice.encounterSession.outgoingUri!),
        ),
        onResponseReceived: (responseBytes) async {
          await alice.submitEncounterResponse(
            QrTransport.encodeUri(responseBytes),
          );
          return Uint8List.fromList(
            QrTransport.decodeUri(alice.encounterSession.outgoingUri!),
          );
        },
      );

      await tester.pumpWidget(
        MaterialApp(
          home: TwoDeviceEncounterScreen(
            controller: bob,
            initialRole: EncounterRole.responder,
            qrScanner: FakeQrScannerService(isCameraSupported: false),
            bleTransport: bobBle,
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('ble_encounter_panel')), findsOneWidget);
      expect(find.byKey(const Key('ble_security_note')), findsOneWidget);
      await tester.tap(find.byKey(const Key('ble_toggle_button')));
      await tester.pumpAndSettle();

      // Discovered peer renders with Immediate proximity (-48 dBm)
      expect(find.byKey(const Key('ble_peer_alice-ble')), findsOneWidget);
      expect(find.textContaining('Immediate (-48 dBm)'), findsOneWidget);

      await tester.tap(find.byKey(const Key('ble_connect_alice-ble')));
      await tester.pumpAndSettle();

      // Seamlessly handed over to manual 6-digit SAS confirmation screen
      expect(find.byKey(const Key('encounter_sas_input')), findsOneWidget);
      expect(bob.contactsCount, 0);

      final sas = bob.encounterSession.comparison!.formattedCode;
      await tester.enterText(find.byKey(const Key('encounter_sas_input')), sas);
      await tester.pumpAndSettle();
      await tester.ensureVisible(
        find.byKey(const Key('encounter_sas_confirm_button')),
      );
      await tester.tap(find.byKey(const Key('encounter_sas_confirm_button')));
      await tester.pumpAndSettle();

      expect(bob.contactsCount, 1);
      expect(bobBle.status, BleTransportStatus.completed);
    },
  );

  testWidgets(
    'TwoDeviceEncounterScreen shows graceful BLE unavailable notice while preserving manual/QR fallback',
    (tester) async {
      final bob = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
      );
      await bob.initialize();
      addTearDown(bob.dispose);

      final channel = InMemoryBleChannel();
      final unsupportedBle = channel.createResponderTransport(
        forcedErrorStatus: BleTransportStatus.bluetoothOff,
        forcedErrorMessage:
            'Turn on Bluetooth to exchange Encounter payloads nearby.',
      );
      addTearDown(unsupportedBle.dispose);

      await tester.pumpWidget(
        MaterialApp(
          home: TwoDeviceEncounterScreen(
            controller: bob,
            initialRole: EncounterRole.responder,
            qrScanner: FakeQrScannerService(isCameraSupported: false),
            bleTransport: unsupportedBle,
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.byKey(const Key('ble_encounter_panel')), findsOneWidget);
      expect(find.text('Bluetooth is turned off'), findsOneWidget);
      expect(find.byKey(const Key('encounter_offer_field')), findsOneWidget);
    },
  );

  testWidgets(
    'TwoDeviceEncounterScreen dual-screen BLE handshake finishes sending Reveal before stopping and confirms SAS on both devices',
    (tester) async {
      tester.view.physicalSize = const Size(1400, 900);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);

      final clock = _FakeClock();
      final alice = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
        clock: clock.call,
      );
      final bob = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
        clock: clock.call,
      );
      await alice.initialize();
      await bob.initialize();
      addTearDown(alice.dispose);
      addTearDown(bob.dispose);

      final channel = InMemoryBleChannel(
        peerId: 'alice-ble',
        peerName: 'Alice Mesh Node',
        rssi: -46,
      );
      final aliceBle = channel.createInitiatorTransport();
      final bobBle = channel.createResponderTransport();
      addTearDown(aliceBle.dispose);
      addTearDown(bobBle.dispose);

      final aliceKey = GlobalKey();
      final bobKey = GlobalKey();

      await tester.pumpWidget(
        MaterialApp(
          home: Row(
            children: [
              Expanded(
                child: TwoDeviceEncounterScreen(
                  key: aliceKey,
                  controller: alice,
                  initialRole: EncounterRole.initiator,
                  qrScanner: FakeQrScannerService(isCameraSupported: false),
                  bleTransport: aliceBle,
                ),
              ),
              Expanded(
                child: TwoDeviceEncounterScreen(
                  key: bobKey,
                  controller: bob,
                  initialRole: EncounterRole.responder,
                  qrScanner: FakeQrScannerService(isCameraSupported: false),
                  bleTransport: bobBle,
                ),
              ),
            ],
          ),
        ),
      );
      await tester.pumpAndSettle();

      await tester.tap(
        find.descendant(
          of: find.byKey(aliceKey),
          matching: find.byKey(const Key('ble_toggle_button')),
        ),
      );
      await tester.pumpAndSettle();

      await tester.tap(
        find.descendant(
          of: find.byKey(bobKey),
          matching: find.byKey(const Key('ble_toggle_button')),
        ),
      );
      await tester.pumpAndSettle();

      await tester.tap(
        find.descendant(
          of: find.byKey(bobKey),
          matching: find.byKey(const Key('ble_connect_alice-ble')),
        ),
      );
      await tester.pumpAndSettle();

      expect(aliceBle.status, BleTransportStatus.completed);
      expect(bobBle.status, BleTransportStatus.completed);
      expect(
        alice.encounterSession.phase,
        EncounterPhase.initiatorShowingRevealAndCompare,
      );
      expect(
        bob.encounterSession.phase,
        EncounterPhase.responderAwaitingConfirmation,
      );

      final sas = alice.encounterSession.comparison!.formattedCode;
      expect(sas, bob.encounterSession.comparison!.formattedCode);

      await tester.enterText(
        find.descendant(
          of: find.byKey(aliceKey),
          matching: find.byKey(const Key('encounter_sas_input')),
        ),
        sas,
      );
      await tester.enterText(
        find.descendant(
          of: find.byKey(bobKey),
          matching: find.byKey(const Key('encounter_sas_input')),
        ),
        sas,
      );
      await tester.pumpAndSettle();

      final aliceConfirm = find.descendant(
        of: find.byKey(aliceKey),
        matching: find.byKey(const Key('encounter_sas_confirm_button')),
      );
      await tester.ensureVisible(aliceConfirm);
      await tester.tap(aliceConfirm);
      await tester.pumpAndSettle();

      final bobConfirm = find.descendant(
        of: find.byKey(bobKey),
        matching: find.byKey(const Key('encounter_sas_confirm_button')),
      );
      await tester.ensureVisible(bobConfirm);
      await tester.tap(bobConfirm);
      await tester.pumpAndSettle();

      expect(alice.contactsCount, 1);
      expect(bob.contactsCount, 1);
    },
  );

  testWidgets(
    'TwoDeviceEncounterScreen reports BLE error when Reveal is rejected by IdentityController',
    (tester) async {
      final clock = _FakeClock();
      final alice = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
        clock: clock.call,
      );
      final bob = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
        clock: clock.call,
      );
      await alice.initialize();
      await bob.initialize();
      addTearDown(alice.dispose);
      addTearDown(bob.dispose);

      final channel = InMemoryBleChannel(
        peerId: 'alice-ble',
        peerName: 'Alice Mesh Node',
        rssi: -50,
      );
      final aliceBle = channel.createInitiatorTransport();
      final bobBle = channel.createResponderTransport();
      addTearDown(aliceBle.dispose);
      addTearDown(bobBle.dispose);

      await alice.startEncounterAsInitiator();
      await aliceBle.startInitiatorPeripheral(
        offerBytes: Uint8List.fromList(
          QrTransport.decodeUri(alice.encounterSession.outgoingUri!),
        ),
        onResponseReceived: (responseBytes) async {
          // Return corrupted/mismatched bytes instead of a valid Reveal.
          return Uint8List.fromList([1, 2, 3, 4, 5, 6]);
        },
      );

      await tester.pumpWidget(
        MaterialApp(
          home: TwoDeviceEncounterScreen(
            controller: bob,
            initialRole: EncounterRole.responder,
            qrScanner: FakeQrScannerService(isCameraSupported: false),
            bleTransport: bobBle,
          ),
        ),
      );
      await tester.pumpAndSettle();

      await tester.tap(find.byKey(const Key('ble_toggle_button')));
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('ble_connect_alice-ble')));
      await tester.pumpAndSettle();

      expect(bobBle.status, BleTransportStatus.error);
      expect(
        bob.encounterSession.phase,
        isNot(EncounterPhase.responderAwaitingConfirmation),
      );
    },
  );

  testWidgets(
    'TwoDeviceEncounterScreen disables BLE toggle button when BLE is unsupported',
    (tester) async {
      final bob = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        handoffOutbox: InMemoryHandoffOutboxService(),
      );
      await bob.initialize();
      addTearDown(bob.dispose);

      final channel = InMemoryBleChannel();
      final unsupportedBle = channel.createResponderTransport(
        forcedErrorStatus: BleTransportStatus.unsupported,
        forcedErrorMessage:
            'Bluetooth Low Energy is not supported on this device.',
      );
      addTearDown(unsupportedBle.dispose);

      await tester.pumpWidget(
        MaterialApp(
          home: TwoDeviceEncounterScreen(
            controller: bob,
            initialRole: EncounterRole.responder,
            qrScanner: FakeQrScannerService(isCameraSupported: false),
            bleTransport: unsupportedBle,
          ),
        ),
      );
      await tester.pumpAndSettle();

      expect(find.text('BLE unavailable on this platform'), findsOneWidget);
      final toggle = tester.widget<FilledButton>(
        find.byKey(const Key('ble_toggle_button')),
      );
      expect(toggle.onPressed, isNull);
    },
  );
}
