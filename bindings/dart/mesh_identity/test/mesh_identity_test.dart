import 'dart:typed_data';

import 'package:mesh_identity/mesh_identity.dart';
import 'package:test/test.dart';

void main() {
  group('MeshInstallation', () {
    test('creates installation with random seed', () {
      final inst = MeshInstallation.create();
      expect(inst.selectedIdentity.length, equals(32));
      expect(inst.identities.length, equals(1));
      expect(inst.identities.first, equals(inst.selectedIdentity));
      inst.dispose();
    });

    test('creates deterministic installation from 32-byte seed', () {
      final seed = Uint8List(32)..fillRange(0, 32, 42);
      final inst1 = MeshInstallation.create(seed: seed);
      final inst2 = MeshInstallation.create(seed: seed);

      expect(inst1.selectedIdentity, equals(inst2.selectedIdentity));
      inst1.dispose();
      inst2.dispose();
    });

    test('rejects invalid seed lengths on creation', () {
      final badSeed = Uint8List(16);
      expect(
        () => MeshInstallation.create(seed: badSeed),
        throwsA(isA<InvalidArgumentsException>()),
      );
    });

    test('manages multiple personas (add, select, remove)', () {
      final rootSeed = Uint8List(32)..fillRange(0, 32, 1);
      final inst = MeshInstallation.create(seed: rootSeed);
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
      final inst = MeshInstallation.create();
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

    test('snapshot save and byte-for-byte restore', () {
      final rootSeed = Uint8List(32)..fillRange(0, 32, 10);
      final inst = MeshInstallation.create(seed: rootSeed);

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
      final inst = MeshInstallation.create(seed: rootSeed);
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

    test('contact management, querying, and blocking', () {
      final inst = MeshInstallation.create();
      expect(inst.contactsCount(), equals(0));

      // Derive a valid verifying key from a peer installation
      final peerSeed = Uint8List(32)..fillRange(0, 32, 7);
      final peerInst = MeshInstallation.create(seed: peerSeed);
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
        final inst = MeshInstallation.create();
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
}
