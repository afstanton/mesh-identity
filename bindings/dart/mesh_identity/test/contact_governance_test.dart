import 'dart:typed_data';

import 'package:mesh_identity/mesh_identity.dart';
import 'package:test/test.dart';

void _verifyPair(MeshInstallation alice, MeshInstallation bob, DateTime at) {
  final startRes = alice.startEncounter(at: at);
  final bobCeremony = bob.openScanner(at: at);
  final resp = bob.scanOffer(bobCeremony, startRes.offerPayload, at: at);
  final reveal = alice.scanResponse(startRes.ceremony, resp, at: at);
  bob.scanReveal(bobCeremony, reveal, at: at);
  final aliceComp = alice.getComparison(startRes.ceremony, at: at)!;
  final bobComp = bob.getComparison(bobCeremony, at: at)!;
  alice.confirmAndSave(startRes.ceremony, bobComp.code, at: at);
  bob.confirmAndSave(bobCeremony, aliceComp.code, at: at);
}

void main() {
  group('Contact Governance & Release 0.5.1 Additions', () {
    test(
      'listContacts returns deterministic sorted contacts scoped per persona',
      () {
        final aliceSeed1 = MeshInstallation.generateSeed();
        final aliceSeed2 = MeshInstallation.generateSeed();
        final bobSeed = MeshInstallation.generateSeed();
        final carolSeed = MeshInstallation.generateSeed();

        final alice = MeshInstallation(seed: aliceSeed1);
        final aliceSecondPk = alice.addIdentity(aliceSeed2);
        final bob = MeshInstallation(seed: bobSeed);
        final carol = MeshInstallation(seed: carolSeed);

        addTearDown(() {
          alice.dispose();
          bob.dispose();
          carol.dispose();
        });

        final alicePrimaryPk = alice.selectedIdentity;
        final bobPk = bob.selectedIdentity;
        final carolPk = carol.selectedIdentity;

        expect(alice.listContacts(), isEmpty);

        alice.importPeerKey(carolPk);
        alice.importPeerKey(bobPk);

        final listed = alice.listContacts();
        expect(listed, hasLength(2));
        expect(alice.listContacts(identityKey: aliceSecondPk), isEmpty);

        final hexList =
            listed
                .map(
                  (c) =>
                      c.peerPublicKey
                          .map((b) => b.toRadixString(16).padLeft(2, '0'))
                          .join(),
                )
                .toList();
        final sortedHex = List<String>.from(hexList)..sort();
        expect(hexList, equals(sortedHex));

        // Unknown identity throws UnknownIdentityException.
        expect(
          () => alice.listContacts(identityKey: Uint8List(32)),
          throwsA(isA<UnknownIdentityException>()),
        );
        expect(alice.listContacts(identityKey: alicePrimaryPk), hasLength(2));
      },
    );

    test(
      'setContactAlias trims, detects conflicts, validates bounds, and persists',
      () {
        final seed = MeshInstallation.generateSeed();
        final peerASeed = MeshInstallation.generateSeed();
        final peerBSeed = MeshInstallation.generateSeed();

        final alice = MeshInstallation(seed: seed);
        final peerA = MeshInstallation(seed: peerASeed);
        final peerB = MeshInstallation(seed: peerBSeed);
        final peerAPk = peerA.selectedIdentity;
        final peerBPk = peerB.selectedIdentity;
        peerA.dispose();
        peerB.dispose();

        alice.importPeerKey(peerAPk);
        alice.importPeerKey(peerBPk);

        alice.setContactAlias(peerAPk, '  Alice Friend  ');
        expect(alice.getContact(peerAPk)?.alias, equals('Alice Friend'));

        // Case-only update on the same peer succeeds.
        alice.setContactAlias(peerAPk, 'alice friend');
        expect(alice.getContact(peerAPk)?.alias, equals('alice friend'));

        // Conflicting alias on a different peer throws AliasConflictException.
        expect(
          () => alice.setContactAlias(peerBPk, 'ALICE FRIEND'),
          throwsA(isA<AliasConflictException>()),
        );

        // Empty and >64-byte aliases throw InvalidArgumentsException.
        expect(
          () => alice.setContactAlias(peerAPk, '   '),
          throwsA(isA<InvalidArgumentsException>()),
        );
        expect(
          () => alice.setContactAlias(
            peerAPk,
            'a' * (MeshInstallation.maxAliasBytes + 1),
          ),
          throwsA(isA<InvalidArgumentsException>()),
        );

        // Unknown contact throws ContactNotFoundException.
        expect(
          () => alice.setContactAlias(Uint8List(32), 'Unknown'),
          throwsA(isA<ContactNotFoundException>()),
        );

        final snapshot = alice.save();
        alice.dispose();

        final restored = MeshInstallation.restore(
          snapshotBytes: snapshot,
          signingKeySeeds: [seed],
        );
        addTearDown(restored.dispose);
        expect(restored.getContact(peerAPk)?.alias, equals('alice friend'));
      },
    );

    test(
      'unblockContact restores active status, preserves verification, and persists',
      () {
        final aliceSeed = MeshInstallation.generateSeed();
        final bobSeed = MeshInstallation.generateSeed();
        final alice = MeshInstallation(seed: aliceSeed);
        final bob = MeshInstallation(seed: bobSeed);
        addTearDown(bob.dispose);

        final bobPk = bob.selectedIdentity;
        final now = DateTime.fromMillisecondsSinceEpoch(1_700_000_000_000);
        _verifyPair(alice, bob, now);

        alice.blockContact(bobPk);
        expect(alice.getContact(bobPk)?.isBlocked, isTrue);

        alice.unblockContact(bobPk);
        final unblocked = alice.getContact(bobPk)!;
        expect(unblocked.isBlocked, isFalse);
        expect(unblocked.status, equals(ContactStatus.active));
        expect(
          unblocked.verificationStatus,
          equals(VerificationStatus.verified),
        );

        expect(
          () => alice.unblockContact(Uint8List(32)),
          throwsA(isA<ContactNotFoundException>()),
        );

        final snapshot = alice.save(at: now);
        alice.dispose();

        final restored = MeshInstallation.restore(
          snapshotBytes: snapshot,
          signingKeySeeds: [aliceSeed],
        );
        addTearDown(restored.dispose);
        final restoredContact = restored.getContact(bobPk)!;
        expect(restoredContact.isBlocked, isFalse);
        expect(restoredContact.isVerified, isTrue);
      },
    );

    test(
      'RateLimitedException exposes structured untilMs from native AttemptError::Paused',
      () {
        final alice = MeshInstallation(seed: MeshInstallation.generateSeed());
        final bob = MeshInstallation(seed: MeshInstallation.generateSeed());
        addTearDown(alice.dispose);
        addTearDown(bob.dispose);

        var clockMs = 1_700_000_000_000;
        for (var i = 0; i < 3; i++) {
          final t = DateTime.fromMillisecondsSinceEpoch(clockMs);
          final startRes = alice.startEncounter(at: t);
          final bobCeremony = bob.openScanner(at: t);
          final resp = bob.scanOffer(bobCeremony, startRes.offerPayload, at: t);
          alice.scanResponse(startRes.ceremony, resp, at: t);
          final aliceComp = alice.getComparison(startRes.ceremony, at: t)!;
          final wrongCode = (aliceComp.code + 1) % 1000000;

          expect(
            () => alice.confirmAndSave(startRes.ceremony, wrongCode, at: t),
            throwsA(isA<EncounterProtocolException>()),
          );
          bob.cancelCeremony(bobCeremony, at: t);
          clockMs += 1000;
        }

        final pauseTriggerTime = DateTime.fromMillisecondsSinceEpoch(clockMs);
        expect(
          () => alice.startEncounter(at: pauseTriggerTime),
          throwsA(
            isA<RateLimitedException>().having(
              (e) => e.untilMs,
              'untilMs',
              equals((clockMs - 1000) + 60000),
            ),
          ),
        );
      },
    );

    test('EncounterComparison exposes statutory UI text constants', () {
      expect(EncounterComparison.localOnlyConfirmation, isNotEmpty);
      expect(EncounterComparison.interferenceWarning, isNotEmpty);
      expect(EncounterComparison.aliasConflictWarning, isNotEmpty);
    });
  });
}
