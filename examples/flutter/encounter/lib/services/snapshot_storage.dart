import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

/// Contract for durable persistence of installation snapshot bytes.
abstract interface class SnapshotStorageService {
  /// Load the saved snapshot bytes, returning null if no snapshot exists.
  Future<Uint8List?> loadSnapshot();

  /// Atomically write snapshot bytes to durable storage.
  Future<void> saveSnapshot(Uint8List snapshotBytes);

  /// Check whether a saved snapshot exists.
  Future<bool> hasSnapshot();

  /// Move any active snapshot aside to a quarantine archive for diagnostics.
  ///
  /// Returns the archive path or identifier if a snapshot was archived, or `null`
  /// if no active snapshot existed.
  Future<String?> archiveSnapshot();

  /// Delete active snapshot state from storage (preserves any archived backups).
  Future<void> deleteSnapshot();
}

/// Signature for renaming a flushed temporary file to a target snapshot path.
typedef SnapshotRenameFn = Future<void> Function(
  File tempFile,
  String targetPath,
);

class _DirectoryScan {
  final Map<int, File> generations = {};
  File? legacyFile;
  final List<File> tempFiles = [];

  int get maxGeneration {
    if (generations.isEmpty) return 0;
    var highest = 0;
    for (final gen in generations.keys) {
      if (gen > highest) highest = gen;
    }
    return highest;
  }

  File? get latestSnapshot {
    if (generations.isNotEmpty) {
      return generations[maxGeneration];
    }
    return legacyFile;
  }
}

/// Production implementation using serialized, generational atomic file writes
/// (`.tmp` write + flush + rename to a fresh generation path) so the previous
/// durable snapshot is never deleted prior to replacement on any OS, including Windows.
class FileSnapshotStorageService implements SnapshotStorageService {
  final Future<Directory> Function() _getDirectory;
  final SnapshotRenameFn _rename;

  static const String _legacyFileName = 'encounter_installation.snapshot';
  static const String _legacyTempFileName =
      'encounter_installation.snapshot.tmp';
  static const String _generationPrefix = 'encounter_installation.snapshot.';
  static const String _corruptPrefix = 'encounter_installation.corrupt-';
  static final RegExp _generationRegex = RegExp(
    r'^encounter_installation\.snapshot\.(\d{16})$',
  );

  Future<void> _queue = Future<void>.value();
  int _writeCounter = 0;
  int _archiveCounter = 0;

  FileSnapshotStorageService({
    Future<Directory> Function()? directoryProvider,
    @visibleForTesting SnapshotRenameFn? renameOverride,
  }) : _getDirectory = directoryProvider ?? getApplicationSupportDirectory,
       _rename = renameOverride ?? _defaultRename;

  static Future<void> _defaultRename(File tempFile, String targetPath) async {
    await tempFile.rename(targetPath);
  }

  Future<T> _serialized<T>(Future<T> Function() action) {
    final completer = Completer<T>();
    _queue = _queue.then((_) async {
      try {
        final result = await action();
        completer.complete(result);
      } catch (e, st) {
        completer.completeError(e, st);
      }
    });
    return completer.future;
  }

  Future<_DirectoryScan> _scan(Directory dir) async {
    final scan = _DirectoryScan();
    if (!await dir.exists()) {
      return scan;
    }

    await for (final entity in dir.list(followLinks: false)) {
      if (entity is! File) continue;
      final name = p.basename(entity.path);
      if (name.startsWith(_corruptPrefix)) {
        continue;
      }
      if (name == _legacyTempFileName ||
          (name.startsWith(_generationPrefix) && name.endsWith('.tmp'))) {
        scan.tempFiles.add(entity);
        continue;
      }
      if (name == _legacyFileName) {
        scan.legacyFile = entity;
        continue;
      }
      final match = _generationRegex.firstMatch(name);
      if (match != null) {
        final gen = int.tryParse(match.group(1)!);
        if (gen != null && gen > 0) {
          scan.generations[gen] = entity;
        }
      }
    }
    return scan;
  }

  Future<void> _bestEffortDelete(File file) async {
    try {
      if (await file.exists()) {
        await file.delete();
      }
    } catch (_) {
      // Best-effort cleanup; ignore errors so committed snapshots are never masked.
    }
  }

  @override
  Future<Uint8List?> loadSnapshot() {
    return _serialized(() async {
      final dir = await _getDirectory();
      final scan = await _scan(dir);
      final latest = scan.latestSnapshot;
      if (latest == null) {
        return null;
      }
      return latest.readAsBytes();
    });
  }

  @override
  Future<void> saveSnapshot(Uint8List snapshotBytes) {
    return _serialized(() async {
      final dir = await _getDirectory();
      if (!await dir.exists()) {
        await dir.create(recursive: true);
      }
      final scan = await _scan(dir);
      final nextGen = scan.maxGeneration + 1;
      final genLabel = nextGen.toString().padLeft(16, '0');
      final counter = ++_writeCounter;

      final tempFile = File(
        p.join(dir.path, '$_generationPrefix$genLabel.$counter.tmp'),
      );
      final targetPath = p.join(dir.path, '$_generationPrefix$genLabel');

      try {
        await tempFile.writeAsBytes(snapshotBytes, flush: true);
        // Rename directly to a brand-new generation path without deleting prior generations first.
        await _rename(tempFile, targetPath);
      } catch (_) {
        await _bestEffortDelete(tempFile);
        rethrow;
      }

      // Best-effort cleanup of superseded generations, legacy file, and stale temps.
      for (final entry in scan.generations.entries) {
        if (entry.key < nextGen) {
          await _bestEffortDelete(entry.value);
        }
      }
      if (scan.legacyFile != null) {
        await _bestEffortDelete(scan.legacyFile!);
      }
      for (final staleTemp in scan.tempFiles) {
        await _bestEffortDelete(staleTemp);
      }
    });
  }

  @override
  Future<bool> hasSnapshot() {
    return _serialized(() async {
      final dir = await _getDirectory();
      final scan = await _scan(dir);
      return scan.latestSnapshot != null;
    });
  }

  @override
  Future<String?> archiveSnapshot() {
    return _serialized(() async {
      final dir = await _getDirectory();
      final scan = await _scan(dir);
      final latest = scan.latestSnapshot;

      if (latest == null) {
        for (final staleTemp in scan.tempFiles) {
          await _bestEffortDelete(staleTemp);
        }
        return null;
      }

      final timestamp = DateTime.now().toUtc().millisecondsSinceEpoch;
      final seq = ++_archiveCounter;
      final archivePath = p.join(
        dir.path,
        '$_corruptPrefix$timestamp-$seq.bak',
      );
      final archived = await latest.rename(archivePath);

      for (final entry in scan.generations.entries) {
        if (entry.value.path != latest.path) {
          await _bestEffortDelete(entry.value);
        }
      }
      if (scan.legacyFile != null && scan.legacyFile!.path != latest.path) {
        await _bestEffortDelete(scan.legacyFile!);
      }
      for (final staleTemp in scan.tempFiles) {
        await _bestEffortDelete(staleTemp);
      }

      return archived.path;
    });
  }

  @override
  Future<void> deleteSnapshot() {
    return _serialized(() async {
      final dir = await _getDirectory();
      final scan = await _scan(dir);
      for (final file in scan.generations.values) {
        await _bestEffortDelete(file);
      }
      if (scan.legacyFile != null) {
        await _bestEffortDelete(scan.legacyFile!);
      }
      for (final temp in scan.tempFiles) {
        await _bestEffortDelete(temp);
      }
    });
  }
}

/// In-memory implementation for unit and widget testing.
class InMemorySnapshotStorageService implements SnapshotStorageService {
  Uint8List? _snapshot;

  /// Snapshots quarantined via [archiveSnapshot].
  final List<Uint8List> archivedSnapshots = [];

  @override
  Future<Uint8List?> loadSnapshot() async {
    return _snapshot != null ? Uint8List.fromList(_snapshot!) : null;
  }

  @override
  Future<void> saveSnapshot(Uint8List snapshotBytes) async {
    _snapshot = Uint8List.fromList(snapshotBytes);
  }

  @override
  Future<bool> hasSnapshot() async {
    return _snapshot != null;
  }

  @override
  Future<String?> archiveSnapshot() async {
    final current = _snapshot;
    if (current == null) {
      return null;
    }
    archivedSnapshots.add(Uint8List.fromList(current));
    _snapshot = null;
    return 'memory://corrupt-${archivedSnapshots.length}';
  }

  @override
  Future<void> deleteSnapshot() async {
    _snapshot = null;
  }
}
