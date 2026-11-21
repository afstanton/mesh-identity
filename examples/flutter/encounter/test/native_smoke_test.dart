import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_identity/mesh_identity.dart';

void main() {
  test(
    'native integration smoke test: installation, save, restore, and dispose',
    () {
      // 1. Generate secure 32-byte seed
      final seed = MeshInstallation.generateSeed();
      expect(seed.length, equals(32));

      // 2. Instantiate MeshInstallation
      final installation = MeshInstallation(seed: seed);
      final identity = installation.selectedIdentity;
      expect(identity.length, equals(32));

      // 3. Save snapshot
      final snapshot = installation.save();
      expect(snapshot, isNotEmpty);

      // 4. Restore from snapshot with retained seed
      final restored = MeshInstallation.restore(
        snapshotBytes: snapshot,
        signingKeySeeds: [seed],
      );
      expect(restored.selectedIdentity, equals(identity));

      // 5. Clean up native resources
      installation.dispose();
      restored.dispose();

      // 6. Zero out secret seed buffer
      seed.fillRange(0, 32, 0);
    },
  );

  test('single-device practice encounter ceremony smoke test', () {
    final aliceSeed = MeshInstallation.generateSeed();
    final bobSeed = MeshInstallation.generateSeed();

    final alice = MeshInstallation(seed: aliceSeed);
    final bob = MeshInstallation(seed: bobSeed);

    final at = DateTime.utc(2026, 6, 1, 12, 0, 0);

    // 1. Alice starts encounter (initiator)
    final aliceStart = alice.startEncounter(at: at);
    expect(aliceStart.offerPayload, isNotEmpty);

    // 2. Bob opens scanner and processes Alice's offer (responder)
    final bobCeremony = bob.openScanner(at: at);
    final bobResp = bob.scanOffer(bobCeremony, aliceStart.offerPayload, at: at);
    expect(bobResp, isNotEmpty);

    // 3. Alice scans Bob's response and produces reveal
    final aliceReveal = alice.scanResponse(
      aliceStart.ceremony,
      bobResp,
      at: at,
    );
    expect(aliceReveal, isNotEmpty);

    // 4. Bob scans Alice's reveal
    bob.scanReveal(bobCeremony, aliceReveal, at: at);

    // 5. Both derive and verify SAS comparison
    final aliceCmp = alice.getComparison(aliceStart.ceremony, at: at);
    final bobCmp = bob.getComparison(bobCeremony, at: at);

    expect(aliceCmp, isNotNull);
    expect(bobCmp, isNotNull);
    expect(aliceCmp!.code, equals(bobCmp!.code));
    expect(aliceCmp.formattedCode.length, equals(6));
    expect(aliceCmp.formattedCode, equals(bobCmp.formattedCode));

    // 6. Both confirm and save
    final aliceSaved = alice.confirmAndSave(
      aliceStart.ceremony,
      bobCmp.code,
      at: at,
    );
    final bobSaved = bob.confirmAndSave(bobCeremony, aliceCmp.code, at: at);

    // 7. Verify contact records
    expect(aliceSaved.peerPublicKey, equals(bob.selectedIdentity));
    expect(aliceSaved.isVerified, isTrue);
    expect(aliceSaved.status, equals(ContactStatus.active));

    expect(bobSaved.peerPublicKey, equals(alice.selectedIdentity));
    expect(bobSaved.isVerified, isTrue);
    expect(bobSaved.status, equals(ContactStatus.active));

    // 8. Lookup contacts directly
    final aliceLookup = alice.getContact(bob.selectedIdentity);
    expect(aliceLookup, isNotNull);
    expect(aliceLookup!.isVerified, isTrue);

    final bobLookup = bob.getContact(alice.selectedIdentity);
    expect(bobLookup, isNotNull);
    expect(bobLookup!.isVerified, isTrue);

    // 9. Clean up
    alice.dispose();
    bob.dispose();
    aliceSeed.fillRange(0, 32, 0);
    bobSeed.fillRange(0, 32, 0);
  });
}
