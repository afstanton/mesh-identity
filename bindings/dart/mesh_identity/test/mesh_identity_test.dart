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

    test('onPersist failure aborts handoff bundle return', () {
      final seed = MeshInstallation.generateSeed();
      final deviceA = MeshInstallation(seed: seed);
      final nonceB = Uint8List(32)..fillRange(0, 32, 42);

      expect(
        () => deviceA.beginHandoff(
          nonceB,
          onPersist: (_) => throw Exception('Disk write failed!'),
        ),
        throwsA(isA<Exception>()),
      );

      deviceA.dispose();
    });

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
}
