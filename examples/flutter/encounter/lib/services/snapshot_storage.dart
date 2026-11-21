import 'dart:io';
import 'dart:typed_data';

import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

/// Contract for durable persistence of installation snapshot bytes.
abstract interface class SnapshotStorageService {
  /// Load the saved snapshot bytes, returning null if no snapshot exists.
  Future<Uint8List?> loadSnapshot();

  /// Atomically write snapshot bytes to durable storage.
  Future<void> saveSnapshot(Uint8List snapshotBytes);

  /// Check whether a saved snapshot file exists.
  Future<bool> hasSnapshot();

  /// Delete the saved snapshot file.
  Future<void> deleteSnapshot();
}

/// Production implementation using atomic file writes (.tmp file + rename).
class FileSnapshotStorageService implements SnapshotStorageService {
  final Future<Directory> Function() _getDirectory;
  static const String _snapshotFileName = 'encounter_installation.snapshot';
  static const String _tempFileName = 'encounter_installation.snapshot.tmp';

  FileSnapshotStorageService({Future<Directory> Function()? directoryProvider})
    : _getDirectory = directoryProvider ?? getApplicationSupportDirectory;

  Future<File> _getFile(String name) async {
    final dir = await _getDirectory();
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }
    return File(p.join(dir.path, name));
  }

  @override
  Future<Uint8List?> loadSnapshot() async {
    final file = await _getFile(_snapshotFileName);
    if (!await file.exists()) {
      return null;
    }
    return file.readAsBytes();
  }

  @override
  Future<void> saveSnapshot(Uint8List snapshotBytes) async {
    final tempFile = await _getFile(_tempFileName);
    final targetFile = await _getFile(_snapshotFileName);

    // Write to temporary file with flush enabled
    await tempFile.writeAsBytes(snapshotBytes, flush: true);

    // Atomic rename over destination
    if (Platform.isWindows && await targetFile.exists()) {
      // Windows rename fails if target exists; delete target first
      await targetFile.delete();
    }
    await tempFile.rename(targetFile.path);
  }

  @override
  Future<bool> hasSnapshot() async {
    final file = await _getFile(_snapshotFileName);
    return file.exists();
  }

  @override
  Future<void> deleteSnapshot() async {
    final file = await _getFile(_snapshotFileName);
    if (await file.exists()) {
      await file.delete();
    }
    final temp = await _getFile(_tempFileName);
    if (await temp.exists()) {
      await temp.delete();
    }
  }
}

/// In-memory implementation for unit and widget testing.
class InMemorySnapshotStorageService implements SnapshotStorageService {
  Uint8List? _snapshot;

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
  Future<void> deleteSnapshot() async {
    _snapshot = null;
  }
}
