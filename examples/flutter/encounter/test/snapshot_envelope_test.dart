import 'dart:typed_data';

import 'package:encounter/services/snapshot_envelope.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mesh_identity/mesh_identity.dart';

void main() {
  Uint8List makeKey(int fillByte) {
    final key = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      key[i] = (fillByte + i) & 0xFF;
    }
    return key;
  }

  group('SnapshotEnvelope', () {
    test('round-trips single and multiple identity keys with payload', () {
      final key1 = makeKey(1);
      final key2 = makeKey(99);
      final payload = Uint8List.fromList([0xA1, 0x01, 0x02, 0x03, 0x04]);

      final singleEncoded = SnapshotEnvelope.encode(
        identityKeys: [key1],
        snapshotBytes: payload,
      );
      expect(SnapshotEnvelope.hasEnvelopeMagic(singleEncoded), isTrue);

      final singleDecoded = SnapshotEnvelope.decode(singleEncoded);
      expect(singleDecoded.identityKeys.length, equals(1));
      expect(singleDecoded.identityKeys[0], equals(key1));
      expect(singleDecoded.snapshotBytes, equals(payload));

      final multiEncoded = SnapshotEnvelope.encode(
        identityKeys: [key1, key2],
        snapshotBytes: payload,
      );
      final multiDecoded = SnapshotEnvelope.decode(multiEncoded);
      expect(multiDecoded.identityKeys.length, equals(2));
      expect(multiDecoded.identityKeys[0], equals(key1));
      expect(multiDecoded.identityKeys[1], equals(key2));
      expect(multiDecoded.snapshotBytes, equals(payload));
    });

    test('rejects invalid encode inputs', () {
      final payload = Uint8List.fromList([1, 2, 3]);
      final key1 = makeKey(1);

      expect(
        () => SnapshotEnvelope.encode(
          identityKeys: const [],
          snapshotBytes: payload,
        ),
        throwsFormatException,
      );

      final tooManyKeys = List.generate(
        SnapshotEnvelope.maxKeys + 1,
        (i) => Uint8List(32)
          ..[0] = i & 0xFF
          ..[1] = (i >> 8) & 0xFF,
      );
      expect(
        () => SnapshotEnvelope.encode(
          identityKeys: tooManyKeys,
          snapshotBytes: payload,
        ),
        throwsFormatException,
      );

      expect(
        () => SnapshotEnvelope.encode(
          identityKeys: [key1, Uint8List.fromList(key1)],
          snapshotBytes: payload,
        ),
        throwsFormatException,
      );

      expect(
        () => SnapshotEnvelope.encode(
          identityKeys: [Uint8List(31)],
          snapshotBytes: payload,
        ),
        throwsFormatException,
      );

      expect(
        () => SnapshotEnvelope.encode(
          identityKeys: [key1],
          snapshotBytes: Uint8List(0),
        ),
        throwsFormatException,
      );
    });

    test('rejects malformed, wrong version, truncated, or duplicate-key envelopes on decode', () {
      final key1 = makeKey(10);
      final key2 = makeKey(20);
      final valid = SnapshotEnvelope.encode(
        identityKeys: [key1, key2],
        snapshotBytes: Uint8List.fromList([0xA1, 0x05, 0x06]),
      );

      // Too short
      expect(
        () => SnapshotEnvelope.decode(Uint8List(3)),
        throwsFormatException,
      );

      // Invalid magic
      final badMagic = Uint8List.fromList(valid);
      badMagic[0] = 0xFF;
      expect(SnapshotEnvelope.hasEnvelopeMagic(badMagic), isFalse);
      expect(() => SnapshotEnvelope.decode(badMagic), throwsFormatException);

      // Wrong version
      final badVersion = Uint8List.fromList(valid);
      badVersion[4] = 99;
      expect(() => SnapshotEnvelope.decode(badVersion), throwsFormatException);

      // Zero keyCount
      final zeroKeys = Uint8List.fromList(valid);
      zeroKeys[5] = 0;
      zeroKeys[6] = 0;
      expect(() => SnapshotEnvelope.decode(zeroKeys), throwsFormatException);

      // KeyCount > maxKeys (2049 = 0x0801)
      final hugeKeys = Uint8List.fromList(valid);
      hugeKeys[5] = 0x08;
      hugeKeys[6] = 0x01;
      expect(() => SnapshotEnvelope.decode(hugeKeys), throwsFormatException);

      // Truncated before payload (exactly header + keys = 0 payload bytes)
      final truncated = Uint8List.fromList(valid.sublist(0, 7 + 64));
      expect(() => SnapshotEnvelope.decode(truncated), throwsFormatException);

      // Duplicate keys crafted on wire
      final dupKeys = Uint8List.fromList(valid);
      dupKeys.setRange(7 + 32, 7 + 64, dupKeys.sublist(7, 7 + 32));
      expect(() => SnapshotEnvelope.decode(dupKeys), throwsFormatException);
    });

    test(
      'hasEnvelopeMagic returns false on raw MeshInstallation snapshot bytes',
      () {
        final seed = MeshInstallation.generateSeed();
        final inst = MeshInstallation(seed: seed);
        try {
          final raw = inst.save();
          expect(SnapshotEnvelope.hasEnvelopeMagic(raw), isFalse);
        } finally {
          inst.dispose();
          seed.fillRange(0, 32, 0);
        }
      },
    );
  });
}
