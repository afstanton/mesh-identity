import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:encounter/services/snapshot_storage.dart';

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
  });
}
