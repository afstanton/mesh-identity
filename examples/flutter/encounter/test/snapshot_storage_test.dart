import 'dart:io';
import 'dart:typed_data';

import 'package:encounter/services/snapshot_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as p;

void main() {
  late Directory tempDir;
  late FileSnapshotStorageService storage;

  setUp(() async {
    tempDir = await Directory.systemTemp.createTemp('encounter_snapshot_test_');
    storage = FileSnapshotStorageService(
      directoryProvider: () async => tempDir,
    );
  });

  tearDown(() async {
    if (await tempDir.exists()) {
      await tempDir.delete(recursive: true);
    }
  });

  group('FileSnapshotStorageService (Slice 1)', () {
    test('atomic write, load, overwrite, and delete lifecycle', () async {
      expect(await storage.hasSnapshot(), isFalse);
      expect(await storage.loadSnapshot(), isNull);

      final payload1 = Uint8List.fromList([1, 2, 3, 4, 5, 6, 7, 8, 9]);
      await storage.saveSnapshot(payload1);

      expect(await storage.hasSnapshot(), isTrue);
      final loaded1 = await storage.loadSnapshot();
      expect(loaded1, equals(payload1));

      // Overwrite atomically
      final payload2 = Uint8List.fromList([9, 8, 7, 6, 5, 4, 3, 2, 1, 0]);
      await storage.saveSnapshot(payload2);

      final loaded2 = await storage.loadSnapshot();
      expect(loaded2, equals(payload2));

      // Delete snapshot
      await storage.deleteSnapshot();
      expect(await storage.hasSnapshot(), isFalse);
      expect(await storage.loadSnapshot(), isNull);
    });

    test(
      'generational replacement prunes older generations and stale tmp files',
      () async {
        // Plant a stale tmp file alongside commits
        final staleTmp = File(
          p.join(tempDir.path, 'encounter_installation.snapshot.stale.tmp'),
        );
        await staleTmp.writeAsBytes([0xDE, 0xAD]);

        for (var gen = 1; gen <= 4; gen++) {
          await storage.saveSnapshot(
            Uint8List.fromList([gen, gen + 1, gen + 2]),
          );
        }

        final files = tempDir
            .listSync()
            .whereType<File>()
            .map((f) => p.basename(f.path))
            .toList();

        expect(
          files,
          equals(['encounter_installation.snapshot.0000000000000004']),
        );
        expect(
          await storage.loadSnapshot(),
          equals(Uint8List.fromList([4, 5, 6])),
        );
      },
    );

    test('failed rename preserves previous generation and cleans up temporary file', () async {
      final original = Uint8List.fromList([10, 20, 30, 40]);
      await storage.saveSnapshot(original);

      final failingStorage = FileSnapshotStorageService(
        directoryProvider: () async => tempDir,
        renameOverride: (_, _) async {
          throw const FileSystemException('Simulated rename failure');
        },
      );

      await expectLater(
        () => failingStorage.saveSnapshot(Uint8List.fromList([99, 98, 97])),
        throwsA(isA<FileSystemException>()),
      );

      // Previous generation remains 100% intact and temp file was cleaned up
      final files = tempDir
          .listSync()
          .whereType<File>()
          .map((f) => p.basename(f.path))
          .toList();
      expect(
        files,
        equals(['encounter_installation.snapshot.0000000000000001']),
      );
      expect(await storage.loadSnapshot(), equals(original));
    });

    test(
      'concurrent saveSnapshot calls serialize cleanly and retain last write',
      () async {
        final payloads = List.generate(
          10,
          (i) => Uint8List.fromList([0x40 + i, i, i + 1, i + 2]),
        );

        await Future.wait(payloads.map(storage.saveSnapshot));

        expect(await storage.hasSnapshot(), isTrue);
        expect(await storage.loadSnapshot(), equals(payloads.last));

        final files = tempDir
            .listSync()
            .whereType<File>()
            .map((f) => p.basename(f.path))
            .toList();
        expect(files.length, equals(1));
        expect(
          files.single,
          equals('encounter_installation.snapshot.0000000000000010'),
        );
      },
    );

    test(
      'archiveSnapshot quarantines active snapshot and clears hasSnapshot',
      () async {
        final corruptPayload = Uint8List.fromList([0xBA, 0xAD, 0xF0, 0x0D]);
        await storage.saveSnapshot(corruptPayload);

        final archivedPath = await storage.archiveSnapshot();
        expect(archivedPath, isNotNull);
        expect(await storage.hasSnapshot(), isFalse);
        expect(await storage.loadSnapshot(), isNull);

        final archivedFile = File(archivedPath!);
        expect(await archivedFile.exists(), isTrue);
        expect(
          p.basename(archivedFile.path),
          startsWith('encounter_installation.corrupt-'),
        );
        expect(p.basename(archivedFile.path), endsWith('.bak'));
        expect(await archivedFile.readAsBytes(), equals(corruptPayload));

        // deleteSnapshot does NOT delete archived quarantine files
        await storage.deleteSnapshot();
        expect(await archivedFile.exists(), isTrue);
      },
    );

    test(
      'reads legacy unnumbered snapshot and upgrades to generation 1 on save',
      () async {
        final legacyFile = File(
          p.join(tempDir.path, 'encounter_installation.snapshot'),
        );
        final legacyBytes = Uint8List.fromList([7, 7, 7, 7]);
        await legacyFile.writeAsBytes(legacyBytes);

        expect(await storage.hasSnapshot(), isTrue);
        expect(await storage.loadSnapshot(), equals(legacyBytes));

        final upgradedBytes = Uint8List.fromList([8, 8, 8, 8]);
        await storage.saveSnapshot(upgradedBytes);

        expect(await legacyFile.exists(), isFalse);
        expect(await storage.loadSnapshot(), equals(upgradedBytes));
        final files = tempDir
            .listSync()
            .whereType<File>()
            .map((f) => p.basename(f.path))
            .toList();
        expect(
          files,
          equals(['encounter_installation.snapshot.0000000000000001']),
        );
      },
    );
  });
}
