import 'dart:convert';
import 'dart:typed_data';

import 'package:encounter/services/encounter_session.dart';
import 'package:encounter/services/identity_controller.dart';
import 'package:encounter/services/keyring_service.dart';
import 'package:encounter/services/snapshot_storage.dart';
import 'package:flutter_test/flutter_test.dart';
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

String _wrongSixDigits(EncounterComparison comparison) {
  final wrong = (comparison.code + 1) % 1000000;
  return wrong.toString().padLeft(6, '0');
}

void main() {
  group('IdentityController Encounter ceremonies', () {
    test('full two-device QrTransport roundtrip verifies and survives cold restart', () async {
      final clock = _FakeClock();
      final aliceKeyring = InMemoryKeyringService();
      final aliceStorage = InMemorySnapshotStorageService();
      final bobKeyring = InMemoryKeyringService();
      final bobStorage = InMemorySnapshotStorageService();

      final alice = IdentityController(
        keyring: aliceKeyring,
        storage: aliceStorage,
        clock: clock.call,
      );
      final bob = IdentityController(
        keyring: bobKeyring,
        storage: bobStorage,
        clock: clock.call,
      );

      await alice.initialize();
      await bob.initialize();
      final alicePk = alice.selectedIdentity!;
      final bobPk = bob.selectedIdentity!;

      // 1. Initiator starts and displays Offer (QR 1).
      await alice.startEncounterAsInitiator();
      expect(
        alice.encounterSession.phase,
        equals(EncounterPhase.initiatorShowingOffer),
      );
      expect(alice.hasActiveEncounter, isTrue);
      final qr1 = alice.encounterSession.outgoingUri!;
      expect(qr1, startsWith(QrTransport.uriPrefix));

      // 2. Responder opens scanner and imports Offer (QR 1) -> Response (QR 2).
      await bob.openEncounterAsResponder();
      expect(
        bob.encounterSession.phase,
        equals(EncounterPhase.responderAwaitingOffer),
      );
      await bob.submitEncounterOffer(qr1);
      expect(
        bob.encounterSession.phase,
        equals(EncounterPhase.responderShowingResponse),
      );
      final qr2 = bob.encounterSession.outgoingUri!;
      expect(qr2, startsWith(QrTransport.uriPrefix));

      // 3. Initiator imports Response (QR 2) -> Reveal (QR 3) + Initiator SAS.
      await alice.submitEncounterResponse(qr2);
      expect(
        alice.encounterSession.phase,
        equals(EncounterPhase.initiatorShowingRevealAndCompare),
      );
      final qr3 = alice.encounterSession.outgoingUri!;
      final aliceComp = alice.encounterSession.comparison!;

      // 4. Responder imports Reveal (QR 3) -> Responder SAS.
      await bob.submitEncounterReveal(qr3);
      expect(
        bob.encounterSession.phase,
        equals(EncounterPhase.responderAwaitingConfirmation),
      );
      final bobComp = bob.encounterSession.comparison!;
      expect(aliceComp.code, equals(bobComp.code));

      // 5. Both enter peer's 6 digits manually.
      await alice.confirmEncounterCode(bobComp.formattedCode);
      await bob.confirmEncounterCode(aliceComp.formattedCode);

      expect(alice.encounterSession.phase, equals(EncounterPhase.verified));
      expect(bob.encounterSession.phase, equals(EncounterPhase.verified));
      expect(alice.hasActiveEncounter, isFalse);
      expect(bob.hasActiveEncounter, isFalse);
      expect(alice.contactsCount, equals(1));
      expect(bob.contactsCount, equals(1));

      final aliceSavedBob = alice.getContact(bobPk);
      final bobSavedAlice = bob.getContact(alicePk);
      expect(aliceSavedBob, isNotNull);
      expect(bobSavedAlice, isNotNull);
      expect(aliceSavedBob!.isVerified, isTrue);
      expect(bobSavedAlice!.isVerified, isTrue);
      expect(aliceSavedBob.encounterCount, equals(1));
      expect(bobSavedAlice.encounterCount, equals(1));

      alice.dispose();
      bob.dispose();

      // Cold restart both devices with retained keyring & snapshot storage.
      final aliceRestarted = IdentityController(
        keyring: aliceKeyring,
        storage: aliceStorage,
        clock: clock.call,
      );
      final bobRestarted = IdentityController(
        keyring: bobKeyring,
        storage: bobStorage,
        clock: clock.call,
      );
      addTearDown(aliceRestarted.dispose);
      addTearDown(bobRestarted.dispose);

      await aliceRestarted.initialize();
      await bobRestarted.initialize();

      expect(aliceRestarted.contactsCount, equals(1));
      expect(bobRestarted.contactsCount, equals(1));
      expect(aliceRestarted.getContact(bobPk)?.isVerified, isTrue);
      expect(bobRestarted.getContact(alicePk)?.isVerified, isTrue);
    });

    test('SAS mismatch aborts ceremony with zero saved contacts and non-6-digit input stays inline', () async {
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

      await alice.startEncounterAsInitiator();
      await bob.openEncounterAsResponder();
      await bob.submitEncounterOffer(alice.encounterSession.outgoingUri!);
      await alice.submitEncounterResponse(bob.encounterSession.outgoingUri!);
      await bob.submitEncounterReveal(alice.encounterSession.outgoingUri!);

      // Short / malformed input keeps Alice live with inline validation error.
      await alice.confirmEncounterCode('123');
      expect(
        alice.encounterSession.phase,
        equals(EncounterPhase.initiatorShowingRevealAndCompare),
      );
      expect(alice.encounterSession.inlineError, isNotNull);
      expect(alice.hasActiveEncounter, isTrue);

      // Wrong 6-digit code aborts ceremony on Alice and leaves contacts == 0.
      final bobCode = bob.encounterSession.comparison!;
      await alice.confirmEncounterCode(_wrongSixDigits(bobCode));
      expect(alice.encounterSession.phase, equals(EncounterPhase.failed));
      expect(alice.hasActiveEncounter, isFalse);
      expect(alice.contactsCount, equals(0));

      // Bob can still confirm or cancel independently and start anew cleanly.
      await bob.cancelActiveEncounter();
      expect(bob.encounterSession.phase, equals(EncounterPhase.cancelled));

      await alice.startEncounterAsInitiator();
      expect(
        alice.encounterSession.phase,
        equals(EncounterPhase.initiatorShowingOffer),
      );
    });

    test('malformed and mismatched QR payloads are handled safely without leaving stale ceremonies', () async {
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

      final bogusUri = 'mesh:encounter:${base64.encode([1, 2, 3, 4, 5])}';

      // Responder rejects malformed URI inline, then corrupted protocol bytes terminate cleanly.
      await bob.openEncounterAsResponder();
      await bob.submitEncounterOffer('not-a-valid-uri');
      expect(
        bob.encounterSession.phase,
        equals(EncounterPhase.responderAwaitingOffer),
      );
      expect(bob.encounterSession.inlineError, isNotNull);

      await bob.submitEncounterOffer(bogusUri);
      expect(bob.encounterSession.phase, equals(EncounterPhase.failed));
      expect(bob.hasActiveEncounter, isFalse);

      // Responder can immediately open a fresh scanner after failed QR 1.
      await alice.startEncounterAsInitiator();
      await bob.openEncounterAsResponder();

      // Initiator rejects malformed and stray QR 2 inline, keeping ceremony live.
      await alice.submitEncounterResponse('not-a-uri');
      expect(
        alice.encounterSession.phase,
        equals(EncounterPhase.initiatorShowingOffer),
      );
      expect(alice.encounterSession.inlineError, isNotNull);

      await alice.submitEncounterResponse(bogusUri);
      expect(
        alice.encounterSession.phase,
        equals(EncounterPhase.initiatorShowingOffer),
      );
      expect(alice.encounterSession.inlineError, isNotNull);

      // Valid Offer & Response still succeed on the live session.
      await bob.submitEncounterOffer(alice.encounterSession.outgoingUri!);
      await alice.submitEncounterResponse(bob.encounterSession.outgoingUri!);
      expect(
        alice.encounterSession.phase,
        equals(EncounterPhase.initiatorShowingRevealAndCompare),
      );

      // Responder rejects malformed and stray QR 3 inline, then completes with real Reveal.
      await bob.submitEncounterReveal('garbage');
      expect(
        bob.encounterSession.phase,
        equals(EncounterPhase.responderShowingResponse),
      );
      expect(bob.encounterSession.inlineError, isNotNull);

      await bob.submitEncounterReveal(bogusUri);
      expect(
        bob.encounterSession.phase,
        equals(EncounterPhase.responderShowingResponse),
      );
      expect(bob.encounterSession.inlineError, isNotNull);

      await bob.submitEncounterReveal(alice.encounterSession.outgoingUri!);
      expect(
        bob.encounterSession.phase,
        equals(EncounterPhase.responderAwaitingConfirmation),
      );
    });

    test(
      'cancelActiveEncounter releases handle cleanly across active phases',
      () async {
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

        await alice.startEncounterAsInitiator();
        await alice.cancelActiveEncounter();
        expect(alice.encounterSession.phase, equals(EncounterPhase.cancelled));
        expect(alice.hasActiveEncounter, isFalse);

        await alice.startEncounterAsInitiator();
        await bob.openEncounterAsResponder();
        await bob.submitEncounterOffer(alice.encounterSession.outgoingUri!);
        await bob.cancelActiveEncounter();
        expect(bob.encounterSession.phase, equals(EncounterPhase.cancelled));
        expect(bob.hasActiveEncounter, isFalse);

        // Responder can immediately reopen after cancelling.
        await bob.openEncounterAsResponder();
        expect(
          bob.encounterSession.phase,
          equals(EncounterPhase.responderAwaitingOffer),
        );
      },
    );

    test(
      'ceremony expires after 120 seconds and permits starting a fresh session',
      () async {
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

        await alice.startEncounterAsInitiator();
        await bob.openEncounterAsResponder();
        await bob.submitEncounterOffer(alice.encounterSession.outgoingUri!);
        await alice.submitEncounterResponse(bob.encounterSession.outgoingUri!);

        clock.advance(const Duration(seconds: 119));
        await alice.checkEncounterExpiry();
        expect(
          alice.encounterSession.phase,
          equals(EncounterPhase.initiatorShowingRevealAndCompare),
        );

        clock.advance(const Duration(seconds: 2));
        await alice.checkEncounterExpiry();
        await bob.checkEncounterExpiry();
        expect(alice.encounterSession.phase, equals(EncounterPhase.expired));
        expect(bob.encounterSession.phase, equals(EncounterPhase.expired));
        expect(alice.hasActiveEncounter, isFalse);
        expect(bob.hasActiveEncounter, isFalse);

        // Fresh encounter starts cleanly after expiration.
        await alice.startEncounterAsInitiator();
        expect(
          alice.encounterSession.phase,
          equals(EncounterPhase.initiatorShowingOffer),
        );
      },
    );

    test('rate limiting triggers after 3 incomplete post-response attempts, survives cold restart, and clears after 60s', () async {
      final clock = _FakeClock();
      final aliceKeyring = InMemoryKeyringService();
      final aliceStorage = InMemorySnapshotStorageService();
      final alice = IdentityController(
        keyring: aliceKeyring,
        storage: aliceStorage,
        clock: clock.call,
      );
      final bob = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: InMemorySnapshotStorageService(),
        clock: clock.call,
      );
      addTearDown(bob.dispose);

      await alice.initialize();
      await bob.initialize();

      for (var attempt = 0; attempt < 3; attempt++) {
        await alice.startEncounterAsInitiator();
        await bob.openEncounterAsResponder();
        await bob.submitEncounterOffer(alice.encounterSession.outgoingUri!);
        await alice.submitEncounterResponse(bob.encounterSession.outgoingUri!);
        await alice.confirmEncounterCode(
          _wrongSixDigits(alice.encounterSession.comparison!),
        );
        expect(alice.encounterSession.phase, equals(EncounterPhase.failed));
        await bob.cancelActiveEncounter();
      }

      // 4th attempt hits native AttemptError::Paused (60s pause).
      await alice.startEncounterAsInitiator();
      expect(alice.encounterSession.phase, equals(EncounterPhase.rateLimited));
      expect(alice.encounterSession.interferenceWarning, isTrue);
      expect(
        alice.encounterSession.errorMessage,
        equals(EncounterUiText.interferenceWarning),
      );
      expect(alice.rateLimitedUntil, isNotNull);

      // Cold restart still enforces remaining pause window.
      alice.dispose();
      final aliceRestarted = IdentityController(
        keyring: aliceKeyring,
        storage: aliceStorage,
        clock: clock.call,
      );
      addTearDown(aliceRestarted.dispose);
      await aliceRestarted.initialize();
      await aliceRestarted.startEncounterAsInitiator();
      expect(
        aliceRestarted.encounterSession.phase,
        equals(EncounterPhase.rateLimited),
      );
      expect(aliceRestarted.encounterSession.interferenceWarning, isTrue);

      // Advancing clock past 60s clears the pause and allows a new session.
      clock.advance(const Duration(seconds: 61));
      await aliceRestarted.checkEncounterExpiry();
      expect(aliceRestarted.rateLimitedUntil, isNull);

      await aliceRestarted.startEncounterAsInitiator();
      expect(
        aliceRestarted.encounterSession.phase,
        equals(EncounterPhase.initiatorShowingOffer),
      );
    });

    test('confirmEncounterCode rolls back contact mutation if snapshot persistence fails', () async {
      final clock = _FakeClock();
      final aliceKeyring = InMemoryKeyringService();
      final aliceStorage = _ControllableStorage();
      final alice = IdentityController(
        keyring: aliceKeyring,
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
      final bobPk = bob.selectedIdentity!;

      await alice.startEncounterAsInitiator();
      await bob.openEncounterAsResponder();
      await bob.submitEncounterOffer(alice.encounterSession.outgoingUri!);
      await alice.submitEncounterResponse(bob.encounterSession.outgoingUri!);
      await bob.submitEncounterReveal(alice.encounterSession.outgoingUri!);

      final sas = alice.encounterSession.comparison!.formattedCode;
      aliceStorage.failNextSave = true;
      await alice.confirmEncounterCode(sas);

      expect(alice.encounterSession.phase, equals(EncounterPhase.failed));
      expect(alice.encounterSession.showLocalOnlyNotice, isTrue);
      expect(
        alice.encounterSession.errorMessage,
        contains('Start a new encounter'),
      );
      expect(
        alice.encounterSession.errorMessage,
        isNot(contains('Please try again')),
      );
      expect(alice.contactsCount, equals(0));
      expect(alice.getContact(bobPk), isNull);
      expect(alice.hasActiveEncounter, isFalse);

      // Storage recovers and node remains completely usable.
      await alice.startEncounterAsInitiator();
      expect(
        alice.encounterSession.phase,
        equals(EncounterPhase.initiatorShowingOffer),
      );
    });

    test('mutations during an active encounter reject with CeremonyActiveException and keep live ceremony working', () async {
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

      // Add a second persona and a peer contact before starting an encounter
      // so selectPersona, removePersona, and blockContact all target real keys.
      final secondPersona = await alice.addPersona();
      final dummySeed = MeshInstallation.generateSeed();
      final dummyInst = MeshInstallation(seed: dummySeed);
      dummySeed.fillRange(0, dummySeed.length, 0);
      final dummyPeer = dummyInst.selectedIdentity;
      dummyInst.dispose();
      await alice.runMutation((inst) => inst.importPeerKey(dummyPeer));

      await alice.startEncounterAsInitiator();
      expect(alice.hasActiveEncounter, isTrue);
      expect(
        alice.encounterSession.phase,
        equals(EncounterPhase.initiatorShowingOffer),
      );

      await expectLater(
        alice.selectPersona(secondPersona),
        throwsA(isA<CeremonyActiveException>()),
      );
      await expectLater(
        alice.addPersona(),
        throwsA(isA<CeremonyActiveException>()),
      );
      await expectLater(
        alice.removePersona(secondPersona),
        throwsA(isA<CeremonyActiveException>()),
      );
      await expectLater(
        alice.blockContact(dummyPeer),
        throwsA(isA<CeremonyActiveException>()),
      );
      await expectLater(
        alice.runMutation((inst) => inst.contactsCount()),
        throwsA(isA<CeremonyActiveException>()),
      );

      // Live encounter remains intact and completes normally.
      expect(alice.hasActiveEncounter, isTrue);
      expect(
        alice.encounterSession.phase,
        equals(EncounterPhase.initiatorShowingOffer),
      );

      await bob.openEncounterAsResponder();
      await bob.submitEncounterOffer(alice.encounterSession.outgoingUri!);
      await alice.submitEncounterResponse(bob.encounterSession.outgoingUri!);
      expect(
        alice.encounterSession.phase,
        equals(EncounterPhase.initiatorShowingRevealAndCompare),
      );
      await bob.submitEncounterReveal(alice.encounterSession.outgoingUri!);

      await alice.confirmEncounterCode(
        bob.encounterSession.comparison!.formattedCode,
      );
      await bob.confirmEncounterCode(
        alice.encounterSession.comparison!.formattedCode,
      );

      expect(alice.encounterSession.phase, equals(EncounterPhase.verified));
      expect(bob.encounterSession.phase, equals(EncounterPhase.verified));
      expect(alice.contactsCount, equals(2));
      expect(bob.contactsCount, equals(1));
    });

    test('snapshot write failure during submitEncounterOffer and submitEncounterResponse fails session cleanly without orphaned active state', () async {
      final clock = _FakeClock();
      final aliceStorage = _ControllableStorage();
      final bobStorage = _ControllableStorage();

      final alice = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: aliceStorage,
        clock: clock.call,
      );
      final bob = IdentityController(
        keyring: InMemoryKeyringService(),
        storage: bobStorage,
        clock: clock.call,
      );
      addTearDown(alice.dispose);
      addTearDown(bob.dispose);

      await alice.initialize();
      await bob.initialize();

      await alice.startEncounterAsInitiator();
      await bob.openEncounterAsResponder();

      bobStorage.failNextSave = true;
      await bob.submitEncounterOffer(alice.encounterSession.outgoingUri!);
      expect(bob.encounterSession.phase, equals(EncounterPhase.failed));
      expect(bob.hasActiveEncounter, isFalse);

      // Responder can immediately start a new ceremony after rollback.
      await bob.openEncounterAsResponder();
      await bob.submitEncounterOffer(alice.encounterSession.outgoingUri!);
      expect(
        bob.encounterSession.phase,
        equals(EncounterPhase.responderShowingResponse),
      );

      aliceStorage.failNextSave = true;
      await alice.submitEncounterResponse(bob.encounterSession.outgoingUri!);
      expect(alice.encounterSession.phase, equals(EncounterPhase.failed));
      expect(alice.hasActiveEncounter, isFalse);
    });
  });
}
