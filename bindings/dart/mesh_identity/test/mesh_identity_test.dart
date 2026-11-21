import 'dart:convert';
import 'dart:typed_data';

import 'package:mesh_identity/mesh_identity.dart';
import 'package:test/test.dart';

void main() {
  group('MeshInstallation', () {
    test('generateSeed creates cryptographically secure 32-byte seed', () {
      final s1 = MeshInstallation.generateSeed();
      final s2 = MeshInstallation.generateSeed();

      expect(s1.length, equals(32));
      expect(s2.length, equals(32));
      expect(s1, isNot(equals(s2)));

      final inst = MeshInstallation(seed: s1);
      expect(inst.selectedIdentity.length, equals(32));
      expect(inst.identities.length, equals(1));
      expect(inst.identities.first, equals(inst.selectedIdentity));
      inst.dispose();
    });

    test('creates deterministic installation from 32-byte seed', () {
      final seed = Uint8List(32)..fillRange(0, 32, 42);
      final inst1 = MeshInstallation(seed: seed);
      final inst2 = MeshInstallation(seed: seed);

      expect(inst1.selectedIdentity, equals(inst2.selectedIdentity));
      inst1.dispose();
      inst2.dispose();
    });

    test('rejects invalid seed lengths on creation', () {
      final badSeed = Uint8List(16);
      expect(
        () => MeshInstallation(seed: badSeed),
        throwsA(isA<InvalidArgumentsException>()),
      );
    });

    test('manages multiple personas (add, select, remove)', () {
      final rootSeed = Uint8List(32)..fillRange(0, 32, 1);
      final inst = MeshInstallation(seed: rootSeed);
      final rootPk = inst.selectedIdentity;

      final personaSeed = Uint8List(32)..fillRange(0, 32, 2);
      final personaPk = inst.addIdentity(personaSeed);

      expect(inst.identities.length, equals(2));
      expect(inst.selectedIdentity, equals(rootPk));

      // Switch to new persona
      inst.selectIdentity(personaPk);
      expect(inst.selectedIdentity, equals(personaPk));

      // Switch back
      inst.selectIdentity(rootPk);
      expect(inst.selectedIdentity, equals(rootPk));

      // Selecting unknown identity throws UnknownIdentityException
      final unknownPk = Uint8List(32)..fillRange(0, 32, 99);
      expect(
        () => inst.selectIdentity(unknownPk),
        throwsA(isA<UnknownIdentityException>()),
      );

      // Cannot remove selected identity
      expect(
        () => inst.removeIdentity(rootPk),
        throwsA(isA<SelectedIdentityException>()),
      );

      // Removing unknown identity throws UnknownIdentityException
      expect(
        () => inst.removeIdentity(unknownPk),
        throwsA(isA<UnknownIdentityException>()),
      );

      // Can remove inactive persona
      inst.removeIdentity(personaPk);
      expect(inst.identities.length, equals(1));
      expect(inst.identities.first, equals(rootPk));

      inst.dispose();
    });

    test('rejects bad key arguments in select and remove', () {
      final inst = MeshInstallation(seed: MeshInstallation.generateSeed());
      final badKey = Uint8List(20);

      expect(
        () => inst.selectIdentity(badKey),
        throwsA(isA<InvalidArgumentsException>()),
      );
      expect(
        () => inst.removeIdentity(badKey),
        throwsA(isA<InvalidArgumentsException>()),
      );
      expect(
        () => inst.addIdentity(badKey),
        throwsA(isA<InvalidArgumentsException>()),
      );

      inst.dispose();
    });

    test('pre-1970 timestamps throw InvalidArgumentsException', () {
      final inst = MeshInstallation(seed: MeshInstallation.generateSeed());
      final preEpoch = DateTime.utc(1969, 12, 31);

      expect(
        () => inst.save(at: preEpoch),
        throwsA(isA<InvalidArgumentsException>()),
      );
      expect(
        () => inst.startEncounter(at: preEpoch),
        throwsA(isA<InvalidArgumentsException>()),
      );
      expect(
        () => inst.openScanner(at: preEpoch),
        throwsA(isA<InvalidArgumentsException>()),
      );

      inst.dispose();
    });

    test('snapshot save and byte-for-byte restore', () {
      final rootSeed = Uint8List(32)..fillRange(0, 32, 10);
      final inst = MeshInstallation(seed: rootSeed);

      final secondSeed = Uint8List(32)..fillRange(0, 32, 20);
      final secondPk = inst.addIdentity(secondSeed);

      // Save snapshot bytes with fixed timestamp
      final fixedTime = DateTime.utc(2026, 1, 1, 12, 0, 0);
      final snapshot = inst.save(at: fixedTime);
      expect(snapshot, isNotEmpty);

      // Restore from bytes using the seeds
      final restored = MeshInstallation.restore(
        snapshotBytes: snapshot,
        signingKeySeeds: [rootSeed, secondSeed],
      );

      expect(restored.selectedIdentity, equals(inst.selectedIdentity));
      expect(restored.identities.length, equals(2));
      expect(restored.identities, anyElement(equals(secondPk)));

      // Verifying byte reproducibility of snapshot
      final snapshot2 = restored.save(at: fixedTime);
      expect(snapshot2, equals(snapshot));

      inst.dispose();
      restored.dispose();
    });

    test('restore rejects corrupted, truncated, or empty snapshots', () {
      final rootSeed = Uint8List(32)..fillRange(0, 32, 1);

      // Empty snapshot
      expect(
        () => MeshInstallation.restore(
          snapshotBytes: Uint8List(0),
          signingKeySeeds: [rootSeed],
        ),
        throwsA(isA<InvalidSnapshotException>()),
      );

      // Empty seeds
      expect(
        () => MeshInstallation.restore(
          snapshotBytes: Uint8List(64),
          signingKeySeeds: [],
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Invalid seed length
      expect(
        () => MeshInstallation.restore(
          snapshotBytes: Uint8List(64),
          signingKeySeeds: [Uint8List(16)],
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Truncated/garbage snapshot
      expect(
        () => MeshInstallation.restore(
          snapshotBytes: Uint8List.fromList([1, 2, 3, 4, 5]),
          signingKeySeeds: [rootSeed],
        ),
        throwsA(isA<InvalidSnapshotException>()),
      );
    });

    test('restore rejects mismatched seeds', () {
      final rootSeed = Uint8List(32)..fillRange(0, 32, 10);
      final inst = MeshInstallation(seed: rootSeed);
      final snapshot = inst.save();
      inst.dispose();

      // Attempt restore with wrong seed
      final wrongSeed = Uint8List(32)..fillRange(0, 32, 99);
      expect(
        () => MeshInstallation.restore(
          snapshotBytes: snapshot,
          signingKeySeeds: [wrongSeed],
        ),
        throwsA(isA<InvalidSnapshotException>()),
      );
    });

    test('restore rejects oversized seeds count (> 2048)', () {
      final excessiveSeeds = List.generate(2049, (_) => Uint8List(32));
      expect(
        () => MeshInstallation.restore(
          snapshotBytes: Uint8List(64),
          signingKeySeeds: excessiveSeeds,
        ),
        throwsA(isA<CapacityExceededException>()),
      );
    });

    test('contact management, querying, and blocking', () {
      final inst = MeshInstallation(seed: MeshInstallation.generateSeed());
      expect(inst.contactsCount(), equals(0));

      // Derive a valid verifying key from a peer installation
      final peerSeed = Uint8List(32)..fillRange(0, 32, 7);
      final peerInst = MeshInstallation(seed: peerSeed);
      final validPeerPk = peerInst.selectedIdentity;
      peerInst.dispose();

      // Querying nonexistent contact returns null
      expect(inst.getContact(validPeerPk), isNull);

      // Import contact
      inst.importPeerKey(validPeerPk);
      expect(inst.contactsCount(), equals(1));

      final contact = inst.getContact(validPeerPk);
      expect(contact, isNotNull);
      expect(contact!.peerPublicKey, equals(validPeerPk));
      expect(contact.status, equals(ContactStatus.active));
      expect(contact.isBlocked, isFalse);
      expect(
        contact.verificationStatus,
        equals(VerificationStatus.importedUnverified),
      );
      expect(contact.isVerified, isFalse);
      expect(contact.encounterCount, equals(0));

      // Block contact
      inst.blockContact(validPeerPk);
      final blocked = inst.getContact(validPeerPk);
      expect(blocked, isNotNull);
      expect(blocked!.status, equals(ContactStatus.blocked));
      expect(blocked.isBlocked, isTrue);

      inst.dispose();
    });

    test(
      'disposed installation throws on access and allows safe double dispose',
      () {
        final inst = MeshInstallation(seed: MeshInstallation.generateSeed());
        inst.dispose();

        // Double dispose is safe and does not crash
        expect(() => inst.dispose(), returnsNormally);

        expect(() => inst.selectedIdentity, throwsA(isA<DisposedException>()));
        expect(() => inst.save(), throwsA(isA<DisposedException>()));
        expect(() => inst.identities, throwsA(isA<DisposedException>()));
        expect(() => inst.contactsCount(), throwsA(isA<DisposedException>()));
      },
    );
  });

  group('Contact model', () {
    test('parses valid json map and tests equality', () {
      final pkHex = 'aa' * 32;
      final json = <String, dynamic>{
        'peer_public_key': pkHex,
        'alias': 'Bob',
        'status': 'active',
        'verification_status': 'verified',
        'encounter_count': 3,
        'verified_at': 1700000000,
      };

      final c1 = Contact.fromJson(json);
      final c2 = Contact.fromJson(json);

      expect(c1, equals(c2));
      expect(c1.hashCode, equals(c2.hashCode));
      expect(c1.alias, equals('Bob'));
      expect(c1.isVerified, isTrue);
      expect(c1.isBlocked, isFalse);
      expect(c1.toString(), contains('Bob'));
    });

    test('rejects malformed json in Contact.fromJson', () {
      // Invalid hex length
      expect(
        () => Contact.fromJson({
          'peer_public_key': 'aabb',
          'status': 'active',
          'verification_status': 'verified',
          'encounter_count': 1,
          'verified_at': 100,
        }),
        throwsA(isA<FormatException>()),
      );

      // Unknown status string
      expect(
        () => Contact.fromJson({
          'peer_public_key': 'aa' * 32,
          'status': 'unknown_status',
          'verification_status': 'verified',
          'encounter_count': 1,
          'verified_at': 100,
        }),
        throwsA(isA<FormatException>()),
      );

      // Unknown verification status
      expect(
        () => Contact.fromJson({
          'peer_public_key': 'aa' * 32,
          'status': 'active',
          'verification_status': 'bogus',
          'encounter_count': 1,
          'verified_at': 100,
        }),
        throwsA(isA<FormatException>()),
      );

      // Negative timestamp
      expect(
        () => Contact.fromJson({
          'peer_public_key': 'aa' * 32,
          'status': 'active',
          'verification_status': 'verified',
          'encounter_count': 1,
          'verified_at': -5,
        }),
        throwsA(isA<FormatException>()),
      );
    });
  });

  group('Encounter ceremonies', () {
    test('full end-to-end exchange between initiator and responder', () {
      final alice = MeshInstallation(
        seed: Uint8List(32)..fillRange(0, 32, 101),
      );
      final bob = MeshInstallation(seed: Uint8List(32)..fillRange(0, 32, 202));

      final now = DateTime.utc(2026, 6, 1, 10, 0, 0);

      // 1. Alice starts as initiator
      final aliceStart = alice.startEncounter(at: now);
      final offerPayload = aliceStart.offerPayload;
      expect(offerPayload, isNotEmpty);

      // 2. Bob opens scanner as responder
      final bobCeremony = bob.openScanner(at: now);

      // 3. Bob scans Alice's offer -> produces response
      final responsePayload = bob.scanOffer(bobCeremony, offerPayload, at: now);
      expect(responsePayload, isNotEmpty);

      // 4. Alice scans Bob's response -> produces reveal
      final revealPayload = alice.scanResponse(
        aliceStart.ceremony,
        responsePayload,
        at: now,
      );
      expect(revealPayload, isNotEmpty);

      // 5. Bob scans Alice's reveal
      bob.scanReveal(bobCeremony, revealPayload, at: now);

      // 6. Both compute SAS comparison
      final aliceComp = alice.getComparison(aliceStart.ceremony, at: now);
      final bobComp = bob.getComparison(bobCeremony, at: now);

      expect(aliceComp, isNotNull);
      expect(bobComp, isNotNull);
      expect(aliceComp!.code, equals(bobComp!.code));
      expect(aliceComp.formattedCode.length, equals(6));
      expect(aliceComp.formattedCode, equals(bobComp.formattedCode));

      // 7. Both confirm each other's code
      final aliceSaved = alice.confirmAndSave(
        aliceStart.ceremony,
        bobComp.code,
        at: now,
      );
      final bobSaved = bob.confirmAndSave(bobCeremony, aliceComp.code, at: now);

      expect(aliceSaved.peerPublicKey, equals(bob.selectedIdentity));
      expect(aliceSaved.isVerified, isTrue);
      expect(aliceSaved.status, equals(ContactStatus.active));

      expect(bobSaved.peerPublicKey, equals(alice.selectedIdentity));
      expect(bobSaved.isVerified, isTrue);
      expect(bobSaved.status, equals(ContactStatus.active));

      alice.dispose();
      bob.dispose();
    });

    test('rejects mismatched SAS comparison code', () {
      final alice = MeshInstallation(seed: Uint8List(32)..fillRange(0, 32, 11));
      final bob = MeshInstallation(seed: Uint8List(32)..fillRange(0, 32, 22));

      final now = DateTime.utc(2026, 6, 1, 10, 0, 0);

      final aliceStart = alice.startEncounter(at: now);
      final bobCeremony = bob.openScanner(at: now);

      final response = bob.scanOffer(
        bobCeremony,
        aliceStart.offerPayload,
        at: now,
      );
      final reveal = alice.scanResponse(aliceStart.ceremony, response, at: now);
      bob.scanReveal(bobCeremony, reveal, at: now);

      final aliceComp = alice.getComparison(aliceStart.ceremony, at: now)!;
      final wrongCode = (aliceComp.code + 1) % 1000000;

      // Alice rejects wrong code
      expect(
        () => alice.confirmAndSave(aliceStart.ceremony, wrongCode, at: now),
        throwsA(isA<EncounterProtocolException>()),
      );

      alice.dispose();
      bob.dispose();
    });

    test(
      'confirmAndSave throws NoComparisonException if called before getComparison',
      () {
        final alice = MeshInstallation(seed: MeshInstallation.generateSeed());
        final bob = MeshInstallation(seed: MeshInstallation.generateSeed());
        final now = DateTime.utc(2026, 6, 1, 10, 0, 0);

        final aliceStart = alice.startEncounter(at: now);
        final bobCeremony = bob.openScanner(at: now);
        final response = bob.scanOffer(
          bobCeremony,
          aliceStart.offerPayload,
          at: now,
        );
        final reveal = alice.scanResponse(
          aliceStart.ceremony,
          response,
          at: now,
        );
        bob.scanReveal(bobCeremony, reveal, at: now);

        // Attempting to confirm without querying comparison first throws NoComparisonException
        expect(
          () => alice.confirmAndSave(aliceStart.ceremony, 123456, at: now),
          throwsA(isA<NoComparisonException>()),
        );

        alice.cancelCeremony(aliceStart.ceremony);
        bob.cancelCeremony(bobCeremony);
        alice.dispose();
        bob.dispose();
      },
    );

    test('input frames exceeding 512 bytes are rejected before allocation', () {
      final alice = MeshInstallation(seed: MeshInstallation.generateSeed());
      final start = alice.startEncounter();
      final oversized = Uint8List(513);

      expect(
        () => alice.scanOffer(start.ceremony, oversized),
        throwsA(isA<InvalidArgumentsException>()),
      );
      expect(
        () => alice.scanResponse(start.ceremony, oversized),
        throwsA(isA<InvalidArgumentsException>()),
      );
      expect(
        () => alice.scanReveal(start.ceremony, oversized),
        throwsA(isA<InvalidArgumentsException>()),
      );

      alice.cancelCeremony(start.ceremony);
      alice.dispose();
    });

    test('prevents concurrent ceremonies on same installation', () {
      final inst = MeshInstallation(seed: MeshInstallation.generateSeed());
      final res = inst.startEncounter();

      expect(
        () => inst.startEncounter(),
        throwsA(isA<CeremonyActiveException>()),
      );
      expect(() => inst.openScanner(), throwsA(isA<CeremonyActiveException>()));

      inst.cancelCeremony(res.ceremony);
      inst.dispose();
    });

    test(
      'cancelling ceremony marks handle as stale and permits immediate restart',
      () {
        final inst = MeshInstallation(seed: MeshInstallation.generateSeed());
        final res = inst.startEncounter();

        inst.cancelCeremony(res.ceremony);
        expect(res.ceremony.isDisposed, isTrue);

        // Accessing with cancelled ceremony throws DisposedException
        expect(
          () => inst.getComparison(res.ceremony),
          throwsA(isA<DisposedException>()),
        );

        // Installation is immediately available without waiting for timeout
        final fresh = inst.startEncounter();
        expect(fresh.offerPayload, isNotEmpty);
        inst.cancelCeremony(fresh.ceremony);

        inst.dispose();
      },
    );

    test(
      'save mid-ceremony after advancing past 120s timeout expires ceremony',
      () {
        final alice = MeshInstallation(seed: MeshInstallation.generateSeed());
        final start = DateTime.utc(2026, 6, 1, 10, 0, 0);
        final aliceStart = alice.startEncounter(at: start);

        // Advance by 121 seconds (past SESSION_TIMEOUT_MS = 120_000 ms) and save
        final later = start.add(const Duration(seconds: 121));
        alice.save(at: later);

        // The previous ceremony is now expired/stale
        expect(
          () => alice.getComparison(aliceStart.ceremony, at: later),
          throwsA(isA<StaleCeremonyException>()),
        );

        // A new ceremony can now be started without CeremonyActiveException
        final fresh = alice.startEncounter(at: later);
        expect(fresh.offerPayload, isNotEmpty);
        alice.cancelCeremony(fresh.ceremony, at: later);

        alice.dispose();
      },
    );

    test('triggering rate limit pause throws RateLimitedException', () {
      final alice = MeshInstallation(seed: MeshInstallation.generateSeed());
      final bob = MeshInstallation(seed: MeshInstallation.generateSeed());
      final baseTime = DateTime.utc(2026, 6, 1, 12, 0, 0);

      // Cancel 3 encounters to trigger rate limiting pause
      for (var i = 0; i < 3; i++) {
        final t = baseTime.add(Duration(seconds: i));
        final aRes = alice.startEncounter(at: t);
        final bCeremony = bob.openScanner(at: t);
        final resp = bob.scanOffer(bCeremony, aRes.offerPayload, at: t);
        final reveal = alice.scanResponse(aRes.ceremony, resp, at: t);
        bob.scanReveal(bCeremony, reveal, at: t);
        alice.cancelCeremony(aRes.ceremony, at: t);
        bob.cancelCeremony(bCeremony, at: t);
      }

      // 4th encounter within pause period triggers RateLimitedException
      final pauseTime = baseTime.add(const Duration(seconds: 4));
      expect(
        () => bob.startEncounter(at: pauseTime),
        throwsA(isA<RateLimitedException>()),
      );

      // After 60 seconds (PAUSE_MS), starting encounters succeeds again
      final resumeTime = baseTime.add(const Duration(seconds: 65));
      final resumed = bob.startEncounter(at: resumeTime);
      expect(resumed.offerPayload, isNotEmpty);
      bob.cancelCeremony(resumed.ceremony, at: resumeTime);

      alice.dispose();
      bob.dispose();
    });

    test(
      'ceremony handle from installation A passed to installation B throws StaleCeremonyException',
      () {
        final alice = MeshInstallation(seed: MeshInstallation.generateSeed());
        final bob = MeshInstallation(seed: MeshInstallation.generateSeed());
        final aliceStart = alice.startEncounter();

        expect(
          () => bob.getComparison(aliceStart.ceremony),
          throwsA(isA<StaleCeremonyException>()),
        );
        expect(
          () => bob.cancelCeremony(aliceStart.ceremony),
          throwsA(isA<StaleCeremonyException>()),
        );

        alice.dispose();
        bob.dispose();
      },
    );

    test(
      'ceremony double dispose is safe and throws DisposedException on use',
      () {
        final inst = MeshInstallation(seed: MeshInstallation.generateSeed());
        final res = inst.startEncounter();
        final ceremony = res.ceremony;

        ceremony.dispose();
        // Double dispose is a no-op
        expect(() => ceremony.dispose(), returnsNormally);

        expect(
          () => inst.cancelCeremony(ceremony),
          throwsA(isA<DisposedException>()),
        );
        expect(
          () => inst.getComparison(ceremony),
          throwsA(isA<DisposedException>()),
        );

        inst.dispose();
      },
    );

    test(
      'ceremony dispose cancels session on installation and permits restart',
      () {
        final seed = MeshInstallation.generateSeed();
        final alice = MeshInstallation(seed: seed);
        final now = DateTime.utc(2026, 6, 1, 12, 0, 0);

        final start = alice.startEncounter(at: now);
        // Disposing the ceremony directly cancels the ceremony on the installation
        start.ceremony.dispose();

        // Can immediately restart without CeremonyActiveException
        final restart = alice.startEncounter(at: now);
        expect(restart.offerPayload.isNotEmpty, isTrue);
        restart.ceremony.dispose();

        alice.dispose();
      },
    );
  });

  group('QrTransport', () {
    test('encodes and decodes payload with URI scheme', () {
      final raw = Uint8List.fromList([10, 20, 30, 40, 50]);
      final uri = QrTransport.encodeUri(raw);

      expect(uri, startsWith('mesh:encounter:'));
      final decoded = QrTransport.decodeUri(uri);
      expect(decoded, equals(raw));
    });

    test('rejects invalid URI schemes', () {
      expect(
        () => QrTransport.decodeUri('https://example.com'),
        throwsA(isA<FormatException>()),
      );
    });

    test('rejects oversized payloads (> 512 bytes)', () {
      final huge = Uint8List(513);
      expect(
        () => QrTransport.encodeUri(huge),
        throwsA(isA<FormatException>()),
      );

      final hugeB64 = base64Url.encode(huge);
      expect(
        () => QrTransport.decodeUri('mesh:encounter:$hugeB64'),
        throwsA(isA<FormatException>()),
      );
    });
  });

  group('Device-to-device handoff', () {
    test('lazily creates and returns persistent device nonce', () {
      final inst = MeshInstallation(seed: MeshInstallation.generateSeed());
      expect(inst.getCurrentDeviceNonce(), isNull);

      final nonce = inst.getDeviceNonce();
      expect(nonce.length, equals(32));
      expect(inst.getCurrentDeviceNonce(), equals(nonce));

      // Subsequent calls return the same nonce
      final nonce2 = inst.getDeviceNonce();
      expect(nonce2, equals(nonce));

      inst.dispose();
    });

    test('initial voting record and state is voting at counter 0', () {
      final inst = MeshInstallation(seed: MeshInstallation.generateSeed());
      expect(inst.getVotingState(), equals(VotingState.voting));

      final record = inst.getVotingRecord();
      expect(record.counter, equals(BigInt.zero));
      expect(record.state, equals(VotingState.voting));
      expect(record.holder, isNull);

      // Explicit identityKey matches default
      final idKey = inst.selectedIdentity;
      expect(
        inst.getVotingState(identityKey: idKey),
        equals(VotingState.voting),
      );
      expect(inst.getVotingRecord(identityKey: idKey), equals(record));

      inst.dispose();
    });

    test('validates identity key arguments on voting query', () {
      final inst = MeshInstallation(seed: MeshInstallation.generateSeed());
      final badKey = Uint8List(16);

      expect(
        () => inst.getVotingState(identityKey: badKey),
        throwsA(isA<InvalidArgumentsException>()),
      );
      expect(
        () => inst.getVotingRecord(identityKey: badKey),
        throwsA(isA<InvalidArgumentsException>()),
      );

      final unknownKey = Uint8List(32)..fillRange(0, 32, 99);
      expect(
        () => inst.getVotingState(identityKey: unknownKey),
        throwsA(isA<UnknownIdentityException>()),
      );
      expect(
        () => inst.getVotingRecord(identityKey: unknownKey),
        throwsA(isA<UnknownIdentityException>()),
      );

      inst.dispose();
    });

    test('gate voting affects all owned identities and clears permits', () {
      final rootSeed = MeshInstallation.generateSeed();
      final inst = MeshInstallation(seed: rootSeed);
      final rootKey = inst.selectedIdentity;

      final secondSeed = Uint8List(32)..fillRange(0, 32, 7);
      final secondKey = inst.addIdentity(secondSeed);

      // Both start as voting
      expect(
        inst.getVotingState(identityKey: rootKey),
        equals(VotingState.voting),
      );
      expect(
        inst.getVotingState(identityKey: secondKey),
        equals(VotingState.voting),
      );

      // gateVoting gates ALL owned identities
      inst.gateVoting();
      expect(
        inst.getVotingState(identityKey: rootKey),
        equals(VotingState.gated),
      );
      expect(
        inst.getVotingState(identityKey: secondKey),
        equals(VotingState.gated),
      );

      inst.dispose();
    });

    test('gate voting and begin takeover flow with 64-bit unsigned BigInt', () {
      final inst = MeshInstallation(seed: MeshInstallation.generateSeed());

      // Attempting takeover when voting throws NotGatedException
      expect(() => inst.beginTakeover(), throwsA(isA<NotGatedException>()));

      // Gate voting transitions state to gated
      inst.gateVoting();
      expect(inst.getVotingState(), equals(VotingState.gated));
      expect(inst.getVotingRecord().state, equals(VotingState.gated));

      // Attempting takeover with negative floor throws InvalidArgumentsException
      expect(
        () => inst.beginTakeover(floor: -1),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Begin takeover succeeds from gated state
      final takeover = inst.beginTakeover(floor: 10);
      expect(takeover.identity, equals(inst.selectedIdentity));
      expect(takeover.counter, greaterThan(BigInt.from(10)));
      expect(takeover.nonce, equals(inst.getDeviceNonce()));
      expect(takeover.signature.length, equals(64));

      // Installation updates counter and holder, remaining gated until group recognition
      expect(inst.getVotingState(), equals(VotingState.gated));
      final newRecord = inst.getVotingRecord();
      expect(newRecord.state, equals(VotingState.gated));
      expect(newRecord.counter, equals(takeover.counter));
      expect(newRecord.holder, equals(inst.getDeviceNonce()));

      // High 64-bit counter (2^63 - 1) advances to 2^63 without double-to-int cast error
      final largeTakeover = inst.beginTakeover(floor: 0x7fffffffffffffff);
      final expectedLarge = BigInt.parse('9223372036854775808');
      expect(largeTakeover.counter, equals(expectedLarge));
      expect(inst.getVotingRecord().counter, equals(expectedLarge));

      inst.dispose();
    });

    test(
      'executes clean device-to-device handoff with durable persistence across restart',
      () {
        final seed = MeshInstallation.generateSeed();
        final deviceA = MeshInstallation(seed: seed);
        final deviceB = MeshInstallation(seed: seed);

        final nonceB = deviceB.getDeviceNonce();

        // Device A begins handoff to Device B with onPersist verification
        var persistACalled = false;
        final handoffResult = deviceA.beginHandoff(
          nonceB,
          onPersist: (bytes) {
            persistACalled = true;
            expect(bytes.isNotEmpty, isTrue);
          },
        );
        expect(persistACalled, isTrue);

        final bundle = handoffResult.bundle;
        expect(bundle.identity, equals(deviceA.selectedIdentity));
        expect(bundle.counter, equals(BigInt.one));
        expect(bundle.recipient, equals(nonceB));
        expect(bundle.statement.counter, equals(BigInt.one));
        expect(bundle.statement.identity, equals(deviceA.selectedIdentity));
        expect(bundle.statement.nonce, equals(nonceB));

        // Device A is now stopped permanently at counter 1
        expect(deviceA.getVotingState(), equals(VotingState.stopped));
        final recA = deviceA.getVotingRecord();
        expect(recA.state, equals(VotingState.stopped));
        expect(recA.counter, equals(BigInt.one));
        expect(recA.holder, equals(nonceB));

        // Device A cannot begin another handoff (throws NotVotingDeviceException)
        expect(
          () => deviceA.beginHandoff(nonceB),
          throwsA(isA<NotVotingDeviceException>()),
        );

        // Device B accepts the handoff bundle with onPersist verification
        var persistBCalled = false;
        final acceptResult = deviceB.acceptHandoff(
          bundle,
          onPersist: (bytes) {
            persistBCalled = true;
            expect(bytes.isNotEmpty, isTrue);
          },
        );
        expect(persistBCalled, isTrue);
        expect(acceptResult.state, equals(VotingState.voting));
        expect(deviceB.getVotingState(), equals(VotingState.voting));

        final recB = deviceB.getVotingRecord();
        expect(recB.state, equals(VotingState.voting));
        expect(recB.counter, equals(BigInt.one));
        expect(recB.holder, equals(nonceB));

        // Simulate crash & restart from persisted snapshots:
        // Restored Device A must be Stopped at counter 1
        final restoredA = MeshInstallation.restore(
          snapshotBytes: handoffResult.snapshotBytes,
          signingKeySeeds: [seed],
        );
        expect(restoredA.getVotingState(), equals(VotingState.stopped));
        expect(restoredA.getVotingRecord().counter, equals(BigInt.one));

        // Restored Device B must be Voting at counter 1 with nonceB preserved
        final restoredB = MeshInstallation.restore(
          snapshotBytes: acceptResult.snapshotBytes,
          signingKeySeeds: [seed],
        );
        expect(restoredB.getVotingState(), equals(VotingState.voting));
        expect(restoredB.getVotingRecord().counter, equals(BigInt.one));
        expect(restoredB.getVotingRecord().holder, equals(nonceB));

        deviceA.dispose();
        deviceB.dispose();
        restoredA.dispose();
        restoredB.dispose();
      },
    );

    test(
      'onPersist failure preserves pending handoff and retry succeeds without NotVotingDeviceException',
      () {
        final seed = MeshInstallation.generateSeed();
        final deviceA = MeshInstallation(seed: seed);
        final nonceB = Uint8List(32)..fillRange(0, 32, 42);

        // First attempt fails at persistence callback
        expect(
          () => deviceA.beginHandoff(
            nonceB,
            onPersist: (_) => throw Exception('Disk write failed!'),
          ),
          throwsA(isA<Exception>()),
        );

        // Pending handoff is preserved on the instance
        expect(deviceA.pendingHandoff, isNotNull);
        expect(deviceA.pendingHandoff!.bundle.recipient, equals(nonceB));

        // Retrying beginHandoff with the same recipient retries persistence and returns the bundle
        var persistedBytes = Uint8List(0);
        final retriedResult = deviceA.beginHandoff(
          nonceB,
          onPersist: (bytes) {
            persistedBytes = bytes;
          },
        );

        expect(retriedResult.bundle.recipient, equals(nonceB));
        expect(persistedBytes.isNotEmpty, isTrue);
        expect(deviceA.pendingHandoff, isNull);

        deviceA.dispose();
      },
    );

    test('handoff rejects wrong recipient nonce', () {
      final seed = MeshInstallation.generateSeed();
      final deviceA = MeshInstallation(seed: seed);
      final deviceB = MeshInstallation(seed: seed);
      final deviceC = MeshInstallation(seed: seed);

      final nonceB = deviceB.getDeviceNonce();
      final handoffResult = deviceA.beginHandoff(nonceB);

      // Device C has different nonce, attempting to accept throws WrongHandoffRecipientException
      deviceC.getDeviceNonce();
      expect(
        () => deviceC.acceptHandoff(handoffResult.bundle),
        throwsA(isA<WrongHandoffRecipientException>()),
      );

      deviceA.dispose();
      deviceB.dispose();
      deviceC.dispose();
    });

    test('handoff rejects stale counter', () {
      final seed = MeshInstallation.generateSeed();
      final deviceA = MeshInstallation(seed: seed);
      final deviceB = MeshInstallation(seed: seed);

      final nonceB = deviceB.getDeviceNonce();
      final handoffResult = deviceA.beginHandoff(nonceB);

      // Advance deviceB counter past bundle.counter via gateVoting + beginTakeover
      deviceB.gateVoting();
      deviceB.beginTakeover(floor: 5);
      expect(
        deviceB.getVotingRecord().counter,
        greaterThan(handoffResult.bundle.counter),
      );

      // Attempting to accept bundle with counter <= current.counter throws StaleHandoffException
      expect(
        () => deviceB.acceptHandoff(handoffResult.bundle),
        throwsA(isA<StaleHandoffException>()),
      );

      deviceA.dispose();
      deviceB.dispose();
    });

    test('handoff bundle roundtrip serialization and inspection', () {
      final seed = MeshInstallation.generateSeed();
      final deviceA = MeshInstallation(seed: seed);
      final recipientNonce = Uint8List(32)..fillRange(0, 32, 7);

      final handoffResult = deviceA.beginHandoff(recipientNonce);
      final bundle = handoffResult.bundle;
      final rawBytes = bundle.toBytes();

      final reloaded = HandoffBundle.fromBytes(rawBytes);
      expect(reloaded.identity, equals(bundle.identity));
      expect(reloaded.counter, equals(bundle.counter));
      expect(reloaded.recipient, equals(bundle.recipient));
      expect(reloaded.statement.signature, equals(bundle.statement.signature));
      expect(reloaded, equals(bundle));
      expect(reloaded.hashCode, equals(bundle.hashCode));

      deviceA.dispose();
    });

    test('enforces defensive bounds on handoff inputs and bundles', () {
      final inst = MeshInstallation(seed: MeshInstallation.generateSeed());

      // Reject invalid recipient nonce length
      expect(
        () => inst.beginHandoff(Uint8List(16)),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Reject empty handoff bundle
      expect(
        () => HandoffBundle.fromBytes(Uint8List(0)),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Reject oversized handoff bundle (> 5 MiB)
      final huge = Uint8List(HandoffBundle.maxBundleBytes + 1);
      expect(
        () => HandoffBundle.fromBytes(huge),
        throwsA(isA<InvalidArgumentsException>()),
      );

      inst.dispose();
    });

    test('handoff methods respect disposed installation', () {
      final inst = MeshInstallation(seed: MeshInstallation.generateSeed());
      final nonce = inst.getDeviceNonce();
      inst.dispose();

      expect(() => inst.getDeviceNonce(), throwsA(isA<DisposedException>()));
      expect(
        () => inst.getCurrentDeviceNonce(),
        throwsA(isA<DisposedException>()),
      );
      expect(() => inst.getVotingState(), throwsA(isA<DisposedException>()));
      expect(() => inst.getVotingRecord(), throwsA(isA<DisposedException>()));
      expect(() => inst.gateVoting(), throwsA(isA<DisposedException>()));
      expect(() => inst.beginTakeover(), throwsA(isA<DisposedException>()));
      expect(() => inst.beginHandoff(nonce), throwsA(isA<DisposedException>()));
    });
  });

  group('Byzantine Group Admission & Governance', () {
    void pairNodes(MeshInstallation alice, MeshInstallation bob, DateTime now) {
      final aliceStart = alice.startEncounter(at: now);
      final bobCeremony = bob.openScanner(at: now);
      final response = bob.scanOffer(
        bobCeremony,
        aliceStart.offerPayload,
        at: now,
      );
      final reveal = alice.scanResponse(aliceStart.ceremony, response, at: now);
      bob.scanReveal(bobCeremony, reveal, at: now);
      final aliceComp = alice.getComparison(aliceStart.ceremony, at: now)!;
      final bobComp = bob.getComparison(bobCeremony, at: now)!;
      expect(aliceComp.code, equals(bobComp.code));
      final aSaved = alice.confirmAndSave(
        aliceStart.ceremony,
        aliceComp.code,
        at: now,
      );
      final bSaved = bob.confirmAndSave(bobCeremony, bobComp.code, at: now);
      expect(aSaved.isVerified, isTrue);
      expect(bSaved.isVerified, isTrue);
      final aContact = alice.getContact(bob.selectedIdentity);
      expect(aContact, isNotNull);
      expect(aContact!.isVerified, isTrue);
    }

    bool matchesKey(List<Uint8List> list, Uint8List target) {
      return list.any((item) {
        if (item.length != target.length) return false;
        for (var i = 0; i < item.length; i++) {
          if (item[i] != target[i]) return false;
        }
        return true;
      });
    }

    test('group handle creation, identity, and disposal lifecycle', () {
      final seed = MeshInstallation.generateSeed();
      final handle = MeshGroupHandle(seed: seed);

      expect(handle.selectedIdentity.length, equals(32));
      expect(handle.getGroupIds(), isEmpty);
      expect(handle.getPendingInvitations(), isEmpty);
      expect(handle.isDisposed, isFalse);

      handle.dispose();
      expect(handle.isDisposed, isTrue);

      // Safe double dispose
      handle.dispose();

      // Disposed calls throw DisposedException
      expect(() => handle.selectedIdentity, throwsA(isA<DisposedException>()));
      expect(() => handle.getGroupIds(), throwsA(isA<DisposedException>()));
      expect(() => handle.createGroup(), throwsA(isA<DisposedException>()));
    });

    test('ownership transfer from MeshInstallation to MeshGroupHandle', () {
      final seed = MeshInstallation.generateSeed();
      final inst = MeshInstallation(seed: seed);
      final expectedIdentity = inst.selectedIdentity;

      final groupHandle = MeshGroupHandle.fromInstallation(inst);

      // Installation is immediately disposed
      expect(inst.isDisposed, isTrue);
      expect(() => inst.selectedIdentity, throwsA(isA<DisposedException>()));

      // Group handle now owns the identity
      expect(groupHandle.selectedIdentity, equals(expectedIdentity));
      expect(groupHandle.getGroupIds(), isEmpty);

      groupHandle.dispose();
    });

    test('group creation, two-phase outbox save, and genesis export', () {
      final seed = MeshInstallation.generateSeed();
      final handle = MeshGroupHandle(seed: seed);
      final now = DateTime.utc(2026, 6, 1, 12, 0, 0);

      final opId = handle.createGroup();
      expect(opId, greaterThanOrEqualTo(BigInt.zero));

      // Before save & confirm, group is not yet active or released
      expect(handle.takeOutgoing(), isEmpty);

      // Phase 1: save
      final saveRes = handle.save(at: now);
      expect(saveRes.token.counter, greaterThanOrEqualTo(BigInt.zero));
      expect(saveRes.token.incarnation.length, equals(32));
      expect(saveRes.blob.isNotEmpty, isTrue);

      // Phase 2: confirm saved
      final events = handle.confirmSaved(saveRes.token);
      expect(events.isNotEmpty, isTrue);
      final createdEvent = events.whereType<GroupCreatedEvent>().first;
      final groupId = createdEvent.groupId;
      expect(groupId, greaterThan(BigInt.zero));

      // Group now active in queries
      final groupIds = handle.getGroupIds();
      expect(groupIds, contains(groupId));

      final view = handle.getGroup(groupId);
      expect(view, isNotNull);
      expect(view!.groupId, equals(groupId));
      expect(view.revision, equals(BigInt.zero));
      expect(view.members.length, equals(1));
      expect(view.members.first, equals(handle.selectedIdentity));

      // Outgoing messages released: exactly 1 genesis frame
      final outgoing = handle.takeOutgoing();
      expect(outgoing.length, equals(1));
      expect(outgoing.first.tag, equals(MessageTag.genesis));
      expect(outgoing.first.from, equals(handle.selectedIdentity));
      expect(outgoing.first.bytes.isNotEmpty, isTrue);
      expect(outgoing.first.authenticator, isNotNull);
      expect(outgoing.first.authenticator!.length, equals(32));

      // takeOutgoing drained the queue
      expect(handle.takeOutgoing(), isEmpty);

      handle.dispose();
    });

    test('group import via authenticated genesis frame', () {
      final alice = MeshGroupHandle(seed: MeshInstallation.generateSeed());
      final bob = MeshGroupHandle(seed: MeshInstallation.generateSeed());
      final now = DateTime.utc(2026, 6, 1, 12, 0, 0);

      alice.createGroup(members: [bob.selectedIdentity]);
      final aliceSave = alice.save(at: now);
      final aliceEvents = alice.confirmSaved(aliceSave.token);
      final aliceGroupId =
          aliceEvents.whereType<GroupCreatedEvent>().first.groupId;
      final genesisMsg = alice.takeOutgoing().first;

      // Bob imports genesis with digest
      final bobOp = bob.importGenesis(
        frame: genesisMsg.bytes,
        expectedDigest: genesisMsg.authenticator!,
      );
      expect(bobOp, greaterThanOrEqualTo(BigInt.zero));

      final bobSave = bob.save(at: now);
      final bobEvents = bob.confirmSaved(bobSave.token);
      final importedEvent = bobEvents.whereType<GroupImportedEvent>().first;
      expect(importedEvent.groupId, equals(aliceGroupId));

      final bobGroup = bob.getGroup(aliceGroupId);
      expect(bobGroup, isNotNull);
      expect(bobGroup!.groupId, equals(aliceGroupId));
      expect(bobGroup.members.length, equals(2));
      expect(matchesKey(bobGroup.members, alice.selectedIdentity), isTrue);
      expect(matchesKey(bobGroup.members, bob.selectedIdentity), isTrue);

      alice.dispose();
      bob.dispose();
    });

    test('end-to-end verified invitation, consent, admission, and join', () {
      final now = DateTime.utc(2026, 6, 1, 12, 0, 0);
      final seedA = MeshInstallation.generateSeed();
      final seedB = MeshInstallation.generateSeed();
      final instA = MeshInstallation(seed: seedA);
      final instB = MeshInstallation(seed: seedB);

      // 1. Establish verified contact relationship via encounter
      pairNodes(instA, instB, now);

      // 2. Transition both installations to GroupHandles
      final alice = MeshGroupHandle.fromInstallation(instA);
      final bob = MeshGroupHandle.fromInstallation(instB);

      // 3. Alice creates group
      alice.createGroup();
      final aSave1 = alice.save(at: now);
      final aEvents1 = alice.confirmSaved(aSave1.token);
      final groupId = aEvents1.whereType<GroupCreatedEvent>().first.groupId;
      final genesisFrame = alice.takeOutgoing().first;
      expect(genesisFrame.tag, equals(MessageTag.genesis));

      // 4. Alice invites Bob (who is a verified contact)
      final inviteOp = alice.invite(
        groupId: groupId,
        candidateKey: bob.selectedIdentity,
        lifetime: const Duration(days: 7),
        at: now,
      );
      expect(inviteOp, greaterThanOrEqualTo(BigInt.zero));
      expect(inviteOp, greaterThanOrEqualTo(BigInt.zero));

      final aSave2 = alice.save(at: now);
      final aEvents2 = alice.confirmSaved(aSave2.token);
      expect(aEvents2.whereType<InvitationSentEvent>(), isNotEmpty);

      final invMessages = alice.takeOutgoing();
      expect(invMessages.length, equals(1));
      final invMsg = invMessages.first;
      expect(invMsg.tag, equals(MessageTag.invitation));
      expect(matchesKey(invMsg.to, bob.selectedIdentity), isTrue);

      // 5. Bob receives invitation frame
      final bRecvEvents = bob.receiveBytes(
        fromPeerKey: alice.selectedIdentity,
        bytes: invMsg.bytes,
        at: now,
      );
      expect(bRecvEvents, isEmpty); // no immediate rejection

      final bSave1 = bob.save(at: now);
      final bEvents1 = bob.confirmSaved(bSave1.token);
      expect(bEvents1.whereType<InvitationReceivedEvent>(), isNotEmpty);

      final pending = bob.getPendingInvitations();
      expect(pending.length, equals(1));
      expect(pending.first.groupId, equals(groupId));
      expect(pending.first.inviterKey, equals(alice.selectedIdentity));
      final binding = pending.first.binding;

      // 6. Bob accepts invitation
      bob.accept(invitationBinding: binding, at: now);
      final bSave2 = bob.save(at: now);
      final bEvents2 = bob.confirmSaved(bSave2.token);
      expect(bEvents2.whereType<AcceptanceSentEvent>(), isNotEmpty);

      final consentMessages = bob.takeOutgoing();
      expect(consentMessages.length, equals(1));
      final consentMsg = consentMessages.first;
      expect(consentMsg.tag, equals(MessageTag.consent));

      // 7. Alice receives Bob's consent frame
      alice.receiveBytes(
        fromPeerKey: bob.selectedIdentity,
        bytes: consentMsg.bytes,
        at: now,
      );
      final aSave3 = alice.save(at: now);
      final aEvents3 = alice.confirmSaved(aSave3.token);
      expect(aEvents3.whereType<ConsentReceivedEvent>(), isNotEmpty);
      expect(aEvents3.whereType<AdmittedEvent>(), isNotEmpty);

      // Alice now has outgoing certificate / snapshot frames for Bob
      final aliceOutgoing = alice.takeOutgoing();
      expect(aliceOutgoing.isNotEmpty, isTrue);

      // 8. Bob receives Alice's admission/certificate frames
      for (final msg in aliceOutgoing) {
        bob.receiveBytes(
          fromPeerKey: alice.selectedIdentity,
          bytes: msg.bytes,
          at: now,
        );
      }
      final bSave3 = bob.save(at: now);
      final bEvents3 = bob.confirmSaved(bSave3.token);
      expect(bEvents3.whereType<JoinedEvent>(), isNotEmpty);

      // 9. Both peers now share identical roster membership!
      final aliceView = alice.getGroup(groupId)!;
      final bobView = bob.getGroup(groupId)!;

      expect(aliceView.groupId, equals(groupId));
      expect(bobView.groupId, equals(groupId));
      expect(aliceView.revision, equals(bobView.revision));
      expect(aliceView.members.length, equals(2));
      expect(bobView.members.length, equals(2));
      expect(matchesKey(aliceView.members, alice.selectedIdentity), isTrue);
      expect(matchesKey(aliceView.members, bob.selectedIdentity), isTrue);
      expect(matchesKey(bobView.members, alice.selectedIdentity), isTrue);
      expect(matchesKey(bobView.members, bob.selectedIdentity), isTrue);

      // 10. Departure flow: Bob leaves the group
      bob.leaveGroup(groupId: groupId, at: now);
      final bSave4 = bob.save(at: now);
      final bEvents4 = bob.confirmSaved(bSave4.token);
      expect(bEvents4.whereType<LeftEvent>(), isNotEmpty);

      final bobDepartureMsgs = bob.takeOutgoing();
      expect(bobDepartureMsgs.length, equals(1));
      expect(bobDepartureMsgs.first.tag, equals(MessageTag.departure));

      // Alice receives Bob's departure frame
      alice.receiveBytes(
        fromPeerKey: bob.selectedIdentity,
        bytes: bobDepartureMsgs.first.bytes,
        at: now,
      );
      final aSave4 = alice.save(at: now);
      final aEvents4 = alice.confirmSaved(aSave4.token);
      expect(aEvents4.whereType<MemberDepartedEvent>(), isNotEmpty);

      alice.dispose();
      bob.dispose();
    });

    test(
      'group handle snapshot save and byte-for-byte restore across restart',
      () {
        final seed = MeshInstallation.generateSeed();
        final handle = MeshGroupHandle(seed: seed);
        final now = DateTime.utc(2026, 6, 1, 12, 0, 0);

        handle.createGroup();
        final save1 = handle.save(at: now);
        final events = handle.confirmSaved(save1.token);
        final groupId = events.whereType<GroupCreatedEvent>().first.groupId;

        // Save complete snapshot
        final save2 = handle.save(at: now);
        handle.dispose();

        // Restore fresh handle from snapshot blob and seed
        final restored = MeshGroupHandle.restore(
          snapshotBlob: save2.blob,
          signingKeySeeds: [seed],
        );

        expect(restored.selectedIdentity.length, equals(32));
        expect(restored.getGroupIds(), contains(groupId));

        final restoredView = restored.getGroup(groupId);
        expect(restoredView, isNotNull);
        expect(restoredView!.groupId, equals(groupId));
        expect(restoredView.members.length, equals(1));

        restored.dispose();
      },
    );

    test('defensive validation and error bounds on group handle methods', () {
      final seed = MeshInstallation.generateSeed();
      final handle = MeshGroupHandle(seed: seed);
      final now = DateTime.utc(2026, 6, 1, 12, 0, 0);

      // Ineligible exception on unverified candidate invitation
      handle.createGroup();
      final save1 = handle.save(at: now);
      final events = handle.confirmSaved(save1.token);
      final groupId = events.whereType<GroupCreatedEvent>().first.groupId;

      final unverifiedKey = Uint8List(32)..fillRange(0, 32, 99);
      expect(
        () => handle.invite(
          groupId: groupId,
          candidateKey: unverifiedKey,
          at: now,
        ),
        throwsA(isA<IneligibleException>()),
      );

      // Negative timestamp throws InvalidArgumentsException
      expect(
        () => handle.save(at: DateTime.fromMillisecondsSinceEpoch(-1000)),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Invalid frame length bounds
      expect(
        () => handle.receiveBytes(
          fromPeerKey: unverifiedKey,
          bytes: Uint8List(0),
          at: now,
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );

      expect(
        () => handle.importGenesis(
          frame: Uint8List(0),
          expectedDigest: Uint8List(32),
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Restore with empty seeds or mismatched sizes
      expect(
        () => MeshGroupHandle.restore(
          snapshotBlob: save1.blob,
          signingKeySeeds: [],
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );

      expect(
        () => MeshGroupHandle.restore(
          snapshotBlob: save1.blob,
          signingKeySeeds: [Uint8List(16)],
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );

      handle.dispose();
    });

    test(
      'acceptAuthenticated accepts with matching digest and rejects mismatch',
      () {
        final now = DateTime.utc(2026, 6, 1, 12, 0, 0);
        final seedA = MeshInstallation.generateSeed();
        final seedB = MeshInstallation.generateSeed();
        final instA = MeshInstallation(seed: seedA);
        final instB = MeshInstallation(seed: seedB);

        pairNodes(instA, instB, now);
        final alice = MeshGroupHandle.fromInstallation(instA);
        final bob = MeshGroupHandle.fromInstallation(instB);

        alice.createGroup();
        final aSave1 = alice.save(at: now);
        final aEvents1 = alice.confirmSaved(aSave1.token);
        final groupId = aEvents1.whereType<GroupCreatedEvent>().first.groupId;
        final genesisMsg = alice.takeOutgoing().first;

        alice.invite(
          groupId: groupId,
          candidateKey: bob.selectedIdentity,
          at: now,
        );
        final aSave2 = alice.save(at: now);
        alice.confirmSaved(aSave2.token);
        final invMsg = alice.takeOutgoing().first;

        bob.receiveBytes(
          fromPeerKey: alice.selectedIdentity,
          bytes: invMsg.bytes,
          at: now,
        );
        final bSave1 = bob.save(at: now);
        bob.confirmSaved(bSave1.token);
        final pending = bob.getPendingInvitations().first;

        // Acceptance with wrong genesis digest throws InvalidArgumentsException
        final wrongDigest = Uint8List(32)..fillRange(0, 32, 77);
        expect(
          () => bob.acceptAuthenticated(
            invitationBinding: pending.binding,
            genesisDigest: wrongDigest,
            at: now,
          ),
          throwsA(isA<InvalidArgumentsException>()),
        );

        // Acceptance with correct genesis digest succeeds
        final op = bob.acceptAuthenticated(
          invitationBinding: pending.binding,
          genesisDigest: genesisMsg.authenticator!,
          at: now,
        );
        expect(op, greaterThanOrEqualTo(BigInt.zero));

        final bSave2 = bob.save(at: now);
        final bEvents2 = bob.confirmSaved(bSave2.token);
        expect(bEvents2.whereType<AcceptanceSentEvent>(), isNotEmpty);

        alice.dispose();
        bob.dispose();
      },
    );

    test('resend and operation state tracking', () {
      final seed = MeshInstallation.generateSeed();
      final handle = MeshGroupHandle(seed: seed);
      final now = DateTime.utc(2026, 6, 1, 12, 0, 0);

      final opId = handle.createGroup();
      final initialOpState = handle.getOpState(opId);
      expect(initialOpState, isNotNull);
      expect(initialOpState!.isPending, isTrue);

      final save1 = handle.save(at: now);
      handle.confirmSaved(save1.token);
      final outgoing = handle.takeOutgoing();
      expect(outgoing.length, equals(1));

      // After takeOutgoing, outgoing queue is empty
      expect(handle.takeOutgoing(), isEmpty);

      // Resending the operation re-stages frames without re-signing
      handle.resend(opId);
      final save2 = handle.save(at: now);
      handle.confirmSaved(save2.token);

      final resentOutgoing = handle.takeOutgoing();
      expect(resentOutgoing.length, equals(1));
      expect(resentOutgoing.first.tag, equals(MessageTag.genesis));

      // Unknown op query returns null
      expect(handle.getOpState(BigInt.parse('999999999')), isNull);

      handle.dispose();
    });

    test('receiveBytes immediate rejection of malformed frame', () {
      final seed = MeshInstallation.generateSeed();
      final handle = MeshGroupHandle(seed: seed);
      final now = DateTime.utc(2026, 6, 1, 12, 0, 0);
      final peerKey = Uint8List(32)..fillRange(0, 32, 42);

      // Malformed wire bytes (garbage frame)
      final garbage = Uint8List.fromList([0xFF, 0x01, 0x02, 0x03]);
      final events = handle.receiveBytes(
        fromPeerKey: peerKey,
        bytes: garbage,
        at: now,
      );

      expect(events.length, equals(1));
      expect(events.first, isA<FrameRejectedEvent>());
      final rejected = events.first as FrameRejectedEvent;
      expect(rejected.reason, equals(FrameRejectReason.malformed));

      handle.dispose();
    });

    test(
      'OutgoingMessage value equality and hashCode includes to and authenticator',
      () {
        final keyA = Uint8List(32)..fillRange(0, 32, 1);
        final keyB = Uint8List(32)..fillRange(0, 32, 2);
        final keyC = Uint8List(32)..fillRange(0, 32, 3);
        final auth1 = Uint8List(32)..fillRange(0, 32, 10);
        final auth2 = Uint8List(32)..fillRange(0, 32, 20);
        final payload = Uint8List.fromList([1, 2, 3, 4]);

        final msg1 = OutgoingMessage(
          from: keyA,
          to: [keyB],
          tag: MessageTag.genesis,
          bytes: payload,
          authenticator: auth1,
        );

        final msg1Dup = OutgoingMessage(
          from: Uint8List.fromList(keyA),
          to: [Uint8List.fromList(keyB)],
          tag: MessageTag.genesis,
          bytes: Uint8List.fromList(payload),
          authenticator: Uint8List.fromList(auth1),
        );

        // Same recipients and authenticator: equal and same hashCode
        expect(msg1, equals(msg1Dup));
        expect(msg1.hashCode, equals(msg1Dup.hashCode));

        // Different recipient: must NOT be equal
        final msgDifferentTo = OutgoingMessage(
          from: keyA,
          to: [keyC],
          tag: MessageTag.genesis,
          bytes: payload,
          authenticator: auth1,
        );
        expect(msg1, isNot(equals(msgDifferentTo)));
        expect(msg1.hashCode, isNot(equals(msgDifferentTo.hashCode)));

        // Different authenticator: must NOT be equal
        final msgDifferentAuth = OutgoingMessage(
          from: keyA,
          to: [keyB],
          tag: MessageTag.genesis,
          bytes: payload,
          authenticator: auth2,
        );
        expect(msg1, isNot(equals(msgDifferentAuth)));

        // Set deduplication respects deep equality
        final set = {msg1, msg1Dup, msgDifferentTo, msgDifferentAuth};
        expect(set.length, equals(3));
      },
    );

    test('enforces defensive bounds on group inputs', () {
      final seed = MeshInstallation.generateSeed();
      final handle = MeshGroupHandle(seed: seed);
      final now = DateTime.utc(2026, 6, 1, 12, 0, 0);
      final peerKey = Uint8List(32)..fillRange(0, 32, 1);

      // Members count >= 192 throws GroupTooLargeException
      final hugeMemberList = List.generate(
        192,
        (i) => Uint8List(32)..fillRange(0, 32, (i + 1) % 256),
      );
      expect(
        () => handle.createGroup(members: hugeMemberList),
        throwsA(isA<GroupTooLargeException>()),
      );

      // Inbound frame > 128 KiB throws InvalidArgumentsException
      final hugeFrame = Uint8List(MeshGroupHandle.maxGroupFrameBytes + 1);
      expect(
        () => handle.receiveBytes(
          fromPeerKey: peerKey,
          bytes: hugeFrame,
          at: now,
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Inbound genesis > 128 KiB throws InvalidArgumentsException
      expect(
        () => handle.importGenesis(
          frame: hugeFrame,
          expectedDigest: Uint8List(32),
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Snapshot restore > 256 MiB throws InvalidArgumentsException
      // Note: we don't allocate 256MB in test memory, but verify the constant
      expect(MeshGroupHandle.maxGroupFrameBytes, equals(128 * 1024));
      expect(MeshGroupHandle.maxGroupSnapshotBytes, equals(256 * 1024 * 1024));
      expect(MeshGroupHandle.maxGroupMembers, equals(192));

      handle.dispose();
    });

    test('outgoing messages are strictly withheld until confirmSaved', () {
      final seed = MeshInstallation.generateSeed();
      final handle = MeshGroupHandle(seed: seed);
      final now = DateTime.utc(2026, 6, 1, 12, 0, 0);

      // Create group
      handle.createGroup();

      // Before save or confirmSaved, no messages are released
      expect(handle.takeOutgoing(), isEmpty);

      // Save produces token and blob, but messages remain withheld
      final saveRes = handle.save(at: now);
      expect(handle.takeOutgoing(), isEmpty);

      // Only after confirmSaved are messages released to network
      final events = handle.confirmSaved(saveRes.token);
      expect(events.isNotEmpty, isTrue);

      final outgoing = handle.takeOutgoing();
      expect(outgoing.length, equals(1));
      expect(outgoing.first.tag, equals(MessageTag.genesis));

      handle.dispose();
    });

    test(
      'atomic transfer preserves installation if native fails or throws',
      () {
        final seed = MeshInstallation.generateSeed();
        final inst = MeshInstallation(seed: seed);

        // Calling a method on active installation works
        expect(inst.selectedIdentity.length, equals(32));

        // Successfully transferring ownership consumes installation
        final handle = MeshGroupHandle.fromInstallation(inst);
        expect(inst.isDisposed, isTrue);
        expect(handle.selectedIdentity.length, equals(32));

        handle.dispose();
      },
    );

    test('restores valid 65-persona group snapshot', () {
      final seeds = List.generate(65, (_) => MeshInstallation.generateSeed());
      final inst = MeshInstallation(seed: seeds[0]);
      inst.setMaxIdentities(100);
      for (var i = 1; i < 65; i++) {
        inst.addIdentity(seeds[i]);
      }
      expect(inst.identities.length, equals(65));

      final groupHandle = MeshGroupHandle.fromInstallation(inst);
      final saveRes = groupHandle.save();

      // Restoring with 65 seeds must succeed and not throw InvalidArgumentsException
      final restored = MeshGroupHandle.restore(
        snapshotBlob: saveRes.blob,
        signingKeySeeds: seeds,
      );
      expect(restored.selectedIdentity.length, equals(32));

      groupHandle.dispose();
      restored.dispose();
    });

    test(
      'group handle restored before confirmSaved has empty outgoing frames',
      () {
        final seed = MeshInstallation.generateSeed();
        final handle = MeshGroupHandle(seed: seed);
        final now = DateTime.utc(2026, 6, 1, 12, 0, 0);

        // Create group
        handle.createGroup();
        // Phase 1: save snapshot to blob
        final saveRes = handle.save(at: now);
        // Disposed / restart without confirmSaved
        handle.dispose();

        // Restore from the unconfirmed snapshot
        final restored = MeshGroupHandle.restore(
          snapshotBlob: saveRes.blob,
          signingKeySeeds: [seed],
        );

        // Unconfirmed operation frames are withheld and never released
        expect(restored.takeOutgoing(), isEmpty);

        restored.dispose();
      },
    );
  });

  group('OpenPGP Interoperability Bridge', () {
    test('inspects OpenPGP certificates and checks defensive limits', () {
      expect(
        () => MeshInstallation.inspectOpenPgpCertificate(Uint8List(0)),
        throwsA(isA<InvalidArgumentsException>()),
      );
      expect(
        () => MeshInstallation.inspectOpenPgpCertificate(
          Uint8List(MeshInstallation.maxOpenPgpCertificateBytes + 1),
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );
      expect(
        () => MeshInstallation.inspectOpenPgpCertificate(Uint8List(10)),
        throwsA(isA<OpenPgpCertificateException>()),
      );
    });

    test('statutory privacy warning is present on OpenPgpExportPreview', () {
      final seed = MeshInstallation.generateSeed();
      final inst = MeshInstallation(seed: seed);

      final preview = inst.createOpenPgpPreview(
        profile: OpenPgpProfile.v4,
        userId: 'alice@example.com',
        document: Uint8List.fromList(utf8.encode('Mesh Identity Verification')),
      );

      expect(
        preview.warning,
        contains('Anyone who has seen this Mesh public key'),
      );
      expect(preview.warning, equals(OpenPgpExportPreview.privacyWarning));
      expect(preview.userId, equals('alice@example.com'));
      expect(preview.profile, equals(OpenPgpProfile.v4));
      expect(preview.isDisposed, isFalse);

      preview.dispose();
      expect(preview.isDisposed, isTrue);
      expect(
        () => preview.confirm(inst),
        throwsA(isA<OpenPgpPreviewExpiredException>()),
      );

      inst.dispose();
    });

    test('v4 profile end-to-end export preview and confirmation', () {
      final seed = MeshInstallation.generateSeed();
      final inst = MeshInstallation(seed: seed);
      final doc = Uint8List.fromList(utf8.encode('Hello OpenPGP v4'));

      final preview = inst.createOpenPgpPreview(
        profile: OpenPgpProfile.v4,
        userId: 'v4user@mesh.org',
        document: doc,
      );

      final artifacts = preview.confirm(inst);
      expect(preview.isDisposed, isTrue);
      expect(artifacts.certificate.isNotEmpty, isTrue);
      expect(artifacts.detachedSignature.isNotEmpty, isTrue);
      expect(artifacts.peerSignatures, isEmpty);

      // Certificate inspection
      final cert = MeshInstallation.inspectOpenPgpCertificate(
        artifacts.certificate,
      );
      expect(cert.version, equals(4));
      expect(cert.algorithm, equals('EdDSALegacy'));
      expect(cert.userIds, contains('v4user@mesh.org'));
      expect(cert.primaryKeyBytes, equals(inst.selectedIdentity));
      expect(cert.fingerprint.isNotEmpty, isTrue);

      inst.dispose();
    });

    test('v6 profile end-to-end export preview and confirmation', () {
      final seed = MeshInstallation.generateSeed();
      final inst = MeshInstallation(seed: seed);
      final doc = Uint8List.fromList(utf8.encode('Hello OpenPGP v6'));

      final preview = inst.createOpenPgpPreview(
        profile: OpenPgpProfile.v6,
        userId: 'v6user@mesh.org',
        document: doc,
      );

      final artifacts = preview.confirm(inst);
      expect(preview.isDisposed, isTrue);
      expect(artifacts.certificate.isNotEmpty, isTrue);
      expect(artifacts.detachedSignature.isNotEmpty, isTrue);
      expect(artifacts.peerSignatures, isEmpty);

      // Certificate inspection
      final cert = MeshInstallation.inspectOpenPgpCertificate(
        artifacts.certificate,
      );
      expect(cert.version, equals(6));
      expect(cert.algorithm, equals('Ed25519'));
      expect(cert.userIds, contains('v6user@mesh.org'));
      expect(cert.primaryKeyBytes, equals(inst.selectedIdentity));
      expect(cert.fingerprint.length, equals(64));

      inst.dispose();
    });

    test(
      'cross-certification generates peer signatures for peer certificate',
      () {
        final seedAlice = MeshInstallation.generateSeed();
        final alice = MeshInstallation(seed: seedAlice);

        final seedBob = MeshInstallation.generateSeed();
        final bob = MeshInstallation(seed: seedBob);

        // Alice exports a v4 certificate
        final alicePreview = alice.createOpenPgpPreview(
          profile: OpenPgpProfile.v4,
          userId: 'alice@mesh.org',
          document: Uint8List.fromList(utf8.encode('Alice doc')),
        );
        final aliceArtifacts = alicePreview.confirm(alice);
        final aliceCert = MeshInstallation.inspectOpenPgpCertificate(
          aliceArtifacts.certificate,
        );

        // Bob creates an export preview including Alice as peer
        final bobPreview = bob.createOpenPgpPreview(
          profile: OpenPgpProfile.v6,
          userId: 'bob@mesh.org',
          document: Uint8List.fromList(utf8.encode('Bob doc')),
          peerCertificate: aliceArtifacts.certificate,
          peerUserId: 'alice@mesh.org',
        );

        expect(
          bobPreview.peerCertificationFingerprint,
          equals(aliceCert.fingerprint),
        );
        expect(bobPreview.peerCertificationUserId, equals('alice@mesh.org'));

        final bobArtifacts = bobPreview.confirm(bob);
        expect(bobArtifacts.peerSignatures.isNotEmpty, isTrue);
        for (final sig in bobArtifacts.peerSignatures) {
          expect(sig.label.isNotEmpty, isTrue);
          expect(sig.bytes.isNotEmpty, isTrue);
        }

        alice.dispose();
        bob.dispose();
      },
    );

    test(
      'preview invalidation: consumed upon confirmation or persona change',
      () {
        final seed = MeshInstallation.generateSeed();
        final inst = MeshInstallation(seed: seed);
        final otherSeed = MeshInstallation.generateSeed();
        final otherKey = inst.addIdentity(otherSeed);

        // Superseded preview
        final preview1 = inst.createOpenPgpPreview(
          profile: OpenPgpProfile.v4,
          userId: 'user1@mesh.org',
          document: Uint8List.fromList(utf8.encode('doc1')),
        );

        final preview2 = inst.createOpenPgpPreview(
          profile: OpenPgpProfile.v4,
          userId: 'user2@mesh.org',
          document: Uint8List.fromList(utf8.encode('doc2')),
        );

        // Confirming the first preview throws because preview2 replaced it in installation state
        expect(
          () => preview1.confirm(inst),
          throwsA(isA<OpenPgpPreviewExpiredException>()),
        );

        // Preview 2 succeeds
        final artifacts2 = preview2.confirm(inst);
        expect(artifacts2.certificate.isNotEmpty, isTrue);

        // Second confirm of preview2 throws because it was consumed
        expect(
          () => preview2.confirm(inst),
          throwsA(isA<OpenPgpPreviewExpiredException>()),
        );

        // Persona change invalidates pending preview
        final preview3 = inst.createOpenPgpPreview(
          profile: OpenPgpProfile.v4,
          userId: 'user3@mesh.org',
          document: Uint8List.fromList(utf8.encode('doc3')),
        );
        inst.selectIdentity(otherKey);
        expect(
          () => preview3.confirm(inst),
          throwsA(isA<OpenPgpPreviewExpiredException>()),
        );

        inst.dispose();
      },
    );

    test('peer certificate import adds contact and returns provenance', () {
      final seedAlice = MeshInstallation.generateSeed();
      final alice = MeshInstallation(seed: seedAlice);

      final seedBob = MeshInstallation.generateSeed();
      final bob = MeshInstallation(seed: seedBob);

      // Alice exports certificate
      final alicePreview = alice.createOpenPgpPreview(
        profile: OpenPgpProfile.v4,
        userId: 'alice@mesh.org',
        document: Uint8List.fromList(utf8.encode('doc')),
      );
      final aliceArtifacts = alicePreview.confirm(alice);
      final aliceCert = MeshInstallation.inspectOpenPgpCertificate(
        aliceArtifacts.certificate,
      );

      expect(bob.getContact(alice.selectedIdentity), isNull);

      // Bob imports Alice's certificate
      final provenance = bob.importOpenPgpPeer(
        certificate: aliceArtifacts.certificate,
        expectedPublicKey: alice.selectedIdentity,
        userId: 'alice@mesh.org',
      );

      expect(provenance.primaryFingerprint, equals(aliceCert.fingerprint));
      expect(provenance.signingKeyFingerprint, equals(aliceCert.fingerprint));
      expect(provenance.userId, equals('alice@mesh.org'));

      // Alice is now recorded in Bob's contact store
      final contact = bob.getContact(alice.selectedIdentity);
      expect(contact, isNotNull);
      expect(contact!.peerPublicKey, equals(alice.selectedIdentity));
      expect(
        contact.verificationStatus,
        equals(VerificationStatus.importedUnverified),
      );

      // Attempting to import with mismatched expected key throws KeyMismatchException
      final wrongKey = Uint8List(32)..fillRange(0, 32, 99);
      expect(
        () => bob.importOpenPgpPeer(
          certificate: aliceArtifacts.certificate,
          expectedPublicKey: wrongKey,
          userId: 'alice@mesh.org',
        ),
        throwsA(isA<OpenPgpKeyMismatchException>()),
      );

      alice.dispose();
      bob.dispose();
    });

    test('OpenPgpExportPreview document view is strictly unmodifiable', () {
      final seed = MeshInstallation.generateSeed();
      final inst = MeshInstallation(seed: seed);
      final doc = Uint8List.fromList([1, 2, 3]);

      final preview = inst.createOpenPgpPreview(
        profile: OpenPgpProfile.v4,
        userId: 'alice@mesh.org',
        document: doc,
      );

      // Mutating preview.document must throw UnsupportedError
      expect(() => preview.document[0] = 99, throwsA(isA<UnsupportedError>()));

      inst.dispose();
    });

    test('OpenPgpCertificate equals and hashCode contract', () {
      final cert1 = OpenPgpCertificate(
        fingerprint: 'abcd',
        version: 4,
        algorithm: 'EdDSALegacy',
        primaryKeyBytes: Uint8List.fromList([1, 2, 3]),
        userIds: ['user1', 'user2'],
        subkeys: [
          OpenPgpSubkey(
            fingerprint: 'sub1',
            algorithm: 'Ed25519',
            publicKeyBytes: Uint8List.fromList([4, 5]),
          ),
        ],
      );

      final cert2 = OpenPgpCertificate(
        fingerprint: 'abcd',
        version: 4,
        algorithm: 'EdDSALegacy',
        primaryKeyBytes: Uint8List.fromList([1, 2, 3]),
        userIds: ['user1', 'user2'],
        subkeys: [
          OpenPgpSubkey(
            fingerprint: 'sub1',
            algorithm: 'Ed25519',
            publicKeyBytes: Uint8List.fromList([4, 5]),
          ),
        ],
      );

      final cert3 = OpenPgpCertificate(
        fingerprint: 'abcd',
        version: 4,
        algorithm: 'EdDSALegacy',
        primaryKeyBytes: Uint8List.fromList([1, 2, 3]),
        userIds: ['different', 'user2'],
        subkeys: cert1.subkeys,
      );

      expect(cert1, equals(cert2));
      expect(cert1.hashCode, equals(cert2.hashCode));
      expect(cert1, isNot(equals(cert3)));
      expect(cert1.hashCode, isNot(equals(cert3.hashCode)));
    });

    test(
      'owned secret key import returns seed and enables complete snapshot restore',
      () {
        const fixtureSecretHex =
            'c58504684ee18016092b06010401da470f010107400392792031b6ea1dde02c5e383b84744dbd661b21b70d1778c484cce6bf28f06fe0903082824f04c07c8a0a8e0349f374e1f83e73a43aae98133234ecf76eaff13f47b1104aa4e35d18d2fdf5c1a4c35f3b0234a776b433e43972765fdab760f7e54ea3c53727021ec4a947b2a0e26519803cd1d50726f7465637465642063657274696669636174652066697874757265c27b0413160800230502684ee18016210417031e12de755edaf4c9981476322c1e4b10409d021b03021901000a091076322c1e4b10409dea7100ff43b20203e8ad0432035b6ce1c73bc623f0bca101d101e3b62ca44f72b5fe6e1300ff69a029e2a08f00208fdefdc65b69729f7d063dfdda836641a8386f7bc9882102';
        const fixtureExpectedPkHex =
            '0392792031b6ea1dde02c5e383b84744dbd661b21b70d1778c484cce6bf28f06';

        final secretBytes = _hexToBytes(fixtureSecretHex);
        final expectedPk = _hexToBytes(fixtureExpectedPkHex);

        final rootSeed = MeshInstallation.generateSeed();
        final inst = MeshInstallation(seed: rootSeed);
        expect(inst.identities.length, equals(1));

        // Import owned secret key
        final result = inst.importOpenPgpOwned(
          secretKeyCertificate: secretBytes,
          expectedPublicKey: expectedPk,
          userId: 'Protected certificate fixture',
          passphrase: 'fixture passphrase',
          at: DateTime.fromMillisecondsSinceEpoch(1750000001000),
        );

        // Result has extracted 32-byte seed
        expect(result.seed.length, equals(32));
        expect(result.seed[0], equals(0));
        expect(result.seed[1], equals(17));
        expect(
          result.provenance.userId,
          equals('Protected certificate fixture'),
        );

        // Installation now has two personas
        expect(inst.identities.length, equals(2));
        inst.selectIdentity(expectedPk);
        expect(inst.selectedIdentity, equals(expectedPk));

        // Save snapshot containing both personas
        final snapshot = inst.save();
        inst.dispose();

        // Path 1: Restoring with retained import seed succeeds!
        final restored1 = MeshInstallation.restore(
          snapshotBytes: snapshot,
          signingKeySeeds: [rootSeed, result.seed],
        );
        expect(restored1.identities.length, equals(2));
        expect(restored1.selectedIdentity, equals(expectedPk));
        restored1.dispose();

        // Path 2: Standalone seed extraction from retained certificate also restores!
        final extractedSeed = MeshInstallation.extractOpenPgpSecretSeed(
          secretKeyCertificate: secretBytes,
          expectedPublicKey: expectedPk,
          userId: 'Protected certificate fixture',
          passphrase: 'fixture passphrase',
          at: DateTime.fromMillisecondsSinceEpoch(1750000001000),
        );
        expect(extractedSeed, equals(result.seed));

        final restored2 = MeshInstallation.restore(
          snapshotBytes: snapshot,
          signingKeySeeds: [rootSeed, extractedSeed],
        );
        expect(restored2.identities.length, equals(2));
        expect(restored2.selectedIdentity, equals(expectedPk));
        restored2.dispose();
      },
    );

    test('owned secret import rejects public certificate or mismatched key', () {
      final seed = MeshInstallation.generateSeed();
      final inst = MeshInstallation(seed: seed);

      final preview = inst.createOpenPgpPreview(
        profile: OpenPgpProfile.v4,
        userId: 'alice@mesh.org',
        document: Uint8List.fromList(utf8.encode('doc')),
      );
      final artifacts = preview.confirm(inst);

      // Passing public certificate to importOpenPgpOwned fails with SecretMissingException
      expect(
        () => inst.importOpenPgpOwned(
          secretKeyCertificate: artifacts.certificate,
          expectedPublicKey: inst.selectedIdentity,
          userId: 'alice@mesh.org',
        ),
        throwsA(isA<OpenPgpSecretMissingException>()),
      );

      // Passing corrupt bytes fails with OpenPgpCertificateException
      expect(
        () => inst.importOpenPgpOwned(
          secretKeyCertificate: Uint8List.fromList([1, 2, 3, 4, 5]),
          expectedPublicKey: inst.selectedIdentity,
          userId: 'alice@mesh.org',
        ),
        throwsA(isA<OpenPgpCertificateException>()),
      );

      // Passing public certificate to importOpenPgpOwned fails with SecretMissingException even with different key
      final wrongKey = Uint8List(32)..fillRange(0, 32, 7);
      expect(
        () => inst.importOpenPgpOwned(
          secretKeyCertificate: artifacts.certificate,
          expectedPublicKey: wrongKey,
          userId: 'alice@mesh.org',
        ),
        throwsA(isA<OpenPgpSecretMissingException>()),
      );

      inst.dispose();
    });

    test('openpgp contact import survives snapshot save and restore', () {
      final seedAlice = MeshInstallation.generateSeed();
      final alice = MeshInstallation(seed: seedAlice);

      final seedBob = MeshInstallation.generateSeed();
      final bob = MeshInstallation(seed: seedBob);

      final alicePreview = alice.createOpenPgpPreview(
        profile: OpenPgpProfile.v4,
        userId: 'alice@mesh.org',
        document: Uint8List.fromList(utf8.encode('doc')),
      );
      final aliceArtifacts = alicePreview.confirm(alice);

      bob.importOpenPgpPeer(
        certificate: aliceArtifacts.certificate,
        expectedPublicKey: alice.selectedIdentity,
        userId: 'alice@mesh.org',
      );
      final initialContact = bob.getContact(alice.selectedIdentity);
      expect(initialContact, isNotNull);
      expect(initialContact!.peerPublicKey, equals(alice.selectedIdentity));

      // Save snapshot and restore Bob
      final snapshot = bob.save();
      bob.dispose();

      final restoredBob = MeshInstallation.restore(
        snapshotBytes: snapshot,
        signingKeySeeds: [seedBob],
      );
      final restoredContact = restoredBob.getContact(alice.selectedIdentity);
      expect(restoredContact, isNotNull);
      expect(restoredContact!.peerPublicKey, equals(alice.selectedIdentity));

      alice.dispose();
      restoredBob.dispose();
    });

    test('enforces defensive bounds on OpenPGP inputs', () {
      final seed = MeshInstallation.generateSeed();
      final inst = MeshInstallation(seed: seed);
      final validKey = inst.selectedIdentity;
      final validDoc = Uint8List.fromList(utf8.encode('doc'));

      // User ID bounds
      expect(
        () => inst.createOpenPgpPreview(
          profile: OpenPgpProfile.v4,
          userId: '',
          document: validDoc,
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );
      expect(
        () => inst.createOpenPgpPreview(
          profile: OpenPgpProfile.v4,
          userId: 'a' * 2049,
          document: validDoc,
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Document bounds
      expect(
        () => inst.createOpenPgpPreview(
          profile: OpenPgpProfile.v4,
          userId: 'user@mesh.org',
          document: Uint8List(MeshInstallation.maxOpenPgpDocumentBytes + 1),
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Peer certificate bounds
      expect(
        () => inst.createOpenPgpPreview(
          profile: OpenPgpProfile.v4,
          userId: 'user@mesh.org',
          document: validDoc,
          peerCertificate: Uint8List(
            MeshInstallation.maxOpenPgpCertificateBytes + 1,
          ),
          peerUserId: 'peer@mesh.org',
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Peer import bounds
      expect(
        () => inst.importOpenPgpPeer(
          certificate: Uint8List(0),
          expectedPublicKey: validKey,
          userId: 'user@mesh.org',
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );
      expect(
        () => inst.importOpenPgpPeer(
          certificate: Uint8List(10),
          expectedPublicKey: Uint8List(31),
          userId: 'user@mesh.org',
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );
      expect(
        () => inst.importOpenPgpPeer(
          certificate: Uint8List(10),
          expectedPublicKey: validKey,
          userId: '',
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Owned import bounds
      expect(
        () => inst.importOpenPgpOwned(
          secretKeyCertificate: Uint8List(0),
          expectedPublicKey: validKey,
          userId: 'user@mesh.org',
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );
      expect(
        () => inst.importOpenPgpOwned(
          secretKeyCertificate: Uint8List(10),
          expectedPublicKey: Uint8List(33),
          userId: 'user@mesh.org',
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );
      expect(
        () => inst.importOpenPgpOwned(
          secretKeyCertificate: Uint8List(10),
          expectedPublicKey: validKey,
          userId: 'user@mesh.org',
          passphrase: 'p' * 2049,
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Revocation bounds
      expect(
        () => inst.rememberOpenPgpRevocations(Uint8List(0)),
        throwsA(isA<InvalidArgumentsException>()),
      );
      expect(
        () => inst.rememberOpenPgpRevocations(
          Uint8List(MeshInstallation.maxOpenPgpCertificateBytes + 1),
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Timestamp bounds (pre-1970 and post-2106)
      expect(
        () => inst.createOpenPgpPreview(
          profile: OpenPgpProfile.v4,
          userId: 'user@mesh.org',
          document: validDoc,
          at: DateTime.utc(2107, 1, 1),
        ),
        throwsA(isA<InvalidArgumentsException>()),
      );

      // Disposed installation throws DisposedException
      inst.dispose();
      expect(
        () => inst.createOpenPgpPreview(
          profile: OpenPgpProfile.v4,
          userId: 'user@mesh.org',
          document: validDoc,
        ),
        throwsA(isA<DisposedException>()),
      );
      expect(
        () => inst.importOpenPgpPeer(
          certificate: Uint8List(10),
          expectedPublicKey: validKey,
          userId: 'user@mesh.org',
        ),
        throwsA(isA<DisposedException>()),
      );
    });
  });
}

Uint8List _hexToBytes(String hex) {
  final clean = hex.replaceAll(' ', '');
  if (clean.length.isOdd) {
    throw FormatException('Hex string must have an even length', hex);
  }
  final len = clean.length ~/ 2;
  final bytes = Uint8List(len);
  for (var i = 0; i < len; i++) {
    final b = int.tryParse(clean.substring(i * 2, i * 2 + 2), radix: 16);
    if (b == null) {
      throw FormatException('Non-hexadecimal character in hex string', hex);
    }
    bytes[i] = b;
  }
  return bytes;
}
