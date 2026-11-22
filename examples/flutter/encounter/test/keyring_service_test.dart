import 'dart:typed_data';

import 'package:encounter/services/keyring_service.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  Uint8List makeBytes(int start) {
    final out = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      out[i] = (start + i) & 0xFF;
    }
    return out;
  }

  String toHex(Uint8List bytes) =>
      bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

  group('FlutterSecureKeyringService', () {
    setUp(() {
      TestWidgetsFlutterBinding.ensureInitialized();
      FlutterSecureStorage.setMockInitialValues({});
    });

    test(
      'save, get, getAllIdentityKeys, getAllSeeds, remove, and clear',
      () async {
        final keyring = FlutterSecureKeyringService();
        final key1 = makeBytes(1);
        final seed1 = makeBytes(100);
        final key2 = makeBytes(2);
        final seed2 = makeBytes(200);

        expect(await keyring.getSeed(key1), isNull);
        expect(await keyring.getAllIdentityKeys(), isEmpty);
        expect(await keyring.getAllSeeds(), isEmpty);

        await keyring.saveSeed(key1, seed1);
        await keyring.saveSeed(key2, seed2);

        expect(await keyring.getSeed(key1), equals(seed1));
        expect(await keyring.getSeed(key2), equals(seed2));

        final keys = await keyring.getAllIdentityKeys();
        expect(keys.length, equals(2));
        expect(keys.map(toHex).toSet(), equals({toHex(key1), toHex(key2)}));

        final seeds = await keyring.getAllSeeds();
        expect(seeds.length, equals(2));
        expect(seeds.map(toHex).toSet(), equals({toHex(seed1), toHex(seed2)}));

        await keyring.removeSeed(key1);
        expect(await keyring.getSeed(key1), isNull);
        expect(await keyring.getAllIdentityKeys(), equals([key2]));

        await keyring.clear();
        expect(await keyring.getSeed(key2), isNull);
        expect(await keyring.getAllIdentityKeys(), isEmpty);
        expect(await keyring.getAllSeeds(), isEmpty);
      },
    );

    test(
      'concurrent saveSeed calls serialize cleanly without losing entries',
      () async {
        final keyring = FlutterSecureKeyringService();
        final entries = List.generate(
          8,
          (i) => (makeBytes(i * 10), makeBytes(i * 10 + 50)),
        );

        await Future.wait(entries.map((e) => keyring.saveSeed(e.$1, e.$2)));

        final storedKeys = await keyring.getAllIdentityKeys();
        expect(storedKeys.length, equals(8));
        for (final (k, s) in entries) {
          expect(await keyring.getSeed(k), equals(s));
        }
      },
    );

    test('ignores unrelated and malformed keys cleanly', () async {
      final validKey = makeBytes(42);
      final validSeed = makeBytes(84);
      final mockValues = <String, String>{
        'unrelated_setting': 'some_value',
        'persona_index': 'unrelated_index_entry',
        'persona_seed_short': toHex(validSeed),
        'persona_seed_${'zz' * 32}': toHex(validSeed),
        'persona_seed_${toHex(makeBytes(9))}': 'not_valid_hex',
        'persona_seed_${toHex(validKey)}': toHex(validSeed),
      };
      FlutterSecureStorage.setMockInitialValues(mockValues);

      final keyring = FlutterSecureKeyringService();
      final keys = await keyring.getAllIdentityKeys();
      expect(keys, equals([validKey]));

      final seeds = await keyring.getAllSeeds();
      expect(seeds, equals([validSeed]));

      await keyring.clear();
      // Unrelated settings (including non-prefixed keys) are preserved; persona entries cleared.
      expect(await keyring.getAllIdentityKeys(), isEmpty);
      const rawStorage = FlutterSecureStorage();
      expect(
        await rawStorage.read(key: 'unrelated_setting'),
        equals('some_value'),
      );
      expect(
        await rawStorage.read(key: 'persona_index'),
        equals('unrelated_index_entry'),
      );
    });

    test('rejects non-32-byte keys or seeds', () async {
      final keyring = FlutterSecureKeyringService();
      await expectLater(
        () => keyring.saveSeed(Uint8List(31), makeBytes(1)),
        throwsArgumentError,
      );
      await expectLater(
        () => keyring.saveSeed(makeBytes(1), Uint8List(33)),
        throwsArgumentError,
      );
      await expectLater(
        () => keyring.getSeed(Uint8List(0)),
        throwsArgumentError,
      );
      await expectLater(
        () => keyring.removeSeed(Uint8List(16)),
        throwsArgumentError,
      );
    });
  });

  group('InMemoryKeyringService', () {
    test(
      'returns defensive copies, lists keys, and validates 32-byte lengths',
      () async {
        final keyring = InMemoryKeyringService();
        final key = makeBytes(5);
        final seed = makeBytes(55);

        await keyring.saveSeed(key, seed);
        // Mutating caller's seed after save must not mutate stored copy.
        seed.fillRange(0, 32, 0);

        final loaded = await keyring.getSeed(key);
        expect(loaded, isNotNull);
        expect(loaded, equals(makeBytes(55)));

        // Mutating returned copy must not mutate stored copy.
        loaded!.fillRange(0, 32, 0);
        expect(await keyring.getSeed(key), equals(makeBytes(55)));

        expect(await keyring.getAllIdentityKeys(), equals([key]));

        await expectLater(
          () => keyring.saveSeed(Uint8List(10), makeBytes(1)),
          throwsArgumentError,
        );
        await expectLater(
          () => keyring.saveSeed(makeBytes(1), Uint8List(10)),
          throwsArgumentError,
        );
      },
    );
  });
}
