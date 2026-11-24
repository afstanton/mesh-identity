import 'dart:io';
import 'dart:typed_data';

import 'package:mesh_identity/mesh_identity.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

/// Result of loading persisted pending outbound handoff bundles.
///
/// Tracks per-persona read/size failures and directory-level errors separately
/// from valid bundles so one unreadable file never hides other pending handoffs.
class HandoffOutboxLoadResult {
  final Map<String, Uint8List> bundles;
  final Set<String> unreadablePersonas;
  final String? directoryError;

  const HandoffOutboxLoadResult({
    this.bundles = const {},
    this.unreadablePersonas = const {},
    this.directoryError,
  });
}

/// Durable storage for unacknowledged outbound [HandoffBundle] payloads.
///
/// Persists the signed outbound bundle alongside the sender's `Stopped`
/// snapshot so closing the screen or restarting the app never strands a
/// transferred voting role before the user delivers it to the recipient.
abstract interface class HandoffOutboxService {
  /// Atomically persist [bundleBytes] for [personaKey] (32 bytes).
  Future<void> savePendingBundle(Uint8List personaKey, Uint8List bundleBytes);

  /// Load all persisted pending bundles keyed by 64-character lowercase hex
  /// persona public key, isolating per-file read or size errors.
  Future<HandoffOutboxLoadResult> loadAllPendingBundles();

  /// Remove any pending bundle for [personaKey] (32 bytes).
  Future<void> deletePendingBundle(Uint8List personaKey);

  /// Remove all pending bundles (e.g., on destructive identity reset).
  Future<void> clearAll();
}

/// Atomic file-backed [HandoffOutboxService] storing one binary file per
/// persona under `<appSupportDir>/handoff_outbox/`.
class FileHandoffOutboxService implements HandoffOutboxService {
  static const String _dirName = 'handoff_outbox';
  static const String _filePrefix = 'pending_handoff_';
  static const String _fileSuffix = '.bin';

  final Future<Directory> Function() _directoryProvider;

  FileHandoffOutboxService({Future<Directory> Function()? directoryProvider})
    : _directoryProvider = directoryProvider ?? getApplicationSupportDirectory;

  Future<Directory> _resolveDir() async {
    final base = await _directoryProvider();
    return Directory(p.join(base.path, _dirName));
  }

  static String _keyToHex(Uint8List key) {
    if (key.length != 32) {
      throw ArgumentError.value(
        key.length,
        'personaKey.length',
        'Persona public key must be exactly 32 bytes',
      );
    }
    final sb = StringBuffer();
    for (final b in key) {
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }

  @override
  Future<void> savePendingBundle(
    Uint8List personaKey,
    Uint8List bundleBytes,
  ) async {
    final hex = _keyToHex(personaKey);
    if (bundleBytes.isEmpty ||
        bundleBytes.length > HandoffBundle.maxBundleBytes) {
      throw ArgumentError.value(
        bundleBytes.length,
        'bundleBytes.length',
        'Handoff bundle must be 1..${HandoffBundle.maxBundleBytes} bytes',
      );
    }

    final dir = await _resolveDir();
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }

    final targetPath = p.join(dir.path, '$_filePrefix$hex$_fileSuffix');
    final tmpPath = '$targetPath.tmp.${DateTime.now().microsecondsSinceEpoch}';
    final tmpFile = File(tmpPath);
    try {
      final raf = await tmpFile.open(mode: FileMode.writeOnly);
      try {
        await raf.writeFrom(bundleBytes);
        await raf.flush();
      } finally {
        await raf.close();
      }
      await tmpFile.rename(targetPath);
    } catch (_) {
      if (await tmpFile.exists()) {
        await tmpFile.delete();
      }
      rethrow;
    }
  }

  @override
  Future<HandoffOutboxLoadResult> loadAllPendingBundles() async {
    final Directory dir;
    try {
      dir = await _resolveDir();
      if (!await dir.exists()) {
        return const HandoffOutboxLoadResult();
      }
    } catch (e) {
      return HandoffOutboxLoadResult(
        directoryError: 'Unable to open handoff outbox directory: $e',
      );
    }

    final result = <String, Uint8List>{};
    final unreadable = <String>{};
    try {
      await for (final entity in dir.list(followLinks: false)) {
        if (entity is! File) continue;
        final name = p.basename(entity.path);
        if (!name.startsWith(_filePrefix) || !name.endsWith(_fileSuffix)) {
          continue;
        }
        final hex = name.substring(
          _filePrefix.length,
          name.length - _fileSuffix.length,
        );
        if (!RegExp(r'^[0-9a-f]{64}$').hasMatch(hex)) {
          continue;
        }

        try {
          final stat = await entity.stat();
          if (stat.size <= 0 || stat.size > HandoffBundle.maxBundleBytes) {
            unreadable.add(hex);
            continue;
          }
          final bytes = await entity.readAsBytes();
          if (bytes.isEmpty || bytes.length > HandoffBundle.maxBundleBytes) {
            unreadable.add(hex);
            continue;
          }
          result[hex] = Uint8List.fromList(bytes);
        } catch (_) {
          unreadable.add(hex);
        }
      }
    } catch (e) {
      return HandoffOutboxLoadResult(
        bundles: result,
        unreadablePersonas: unreadable,
        directoryError: 'Failed to scan handoff outbox directory: $e',
      );
    }
    return HandoffOutboxLoadResult(
      bundles: result,
      unreadablePersonas: unreadable,
    );
  }

  @override
  Future<void> deletePendingBundle(Uint8List personaKey) async {
    final hex = _keyToHex(personaKey);
    final dir = await _resolveDir();
    final file = File(p.join(dir.path, '$_filePrefix$hex$_fileSuffix'));
    if (await file.exists()) {
      await file.delete();
    }
  }

  @override
  Future<void> clearAll() async {
    final dir = await _resolveDir();
    if (await dir.exists()) {
      await dir.delete(recursive: true);
    }
  }
}

/// Deterministic in-memory [HandoffOutboxService] for unit and widget tests.
class InMemoryHandoffOutboxService implements HandoffOutboxService {
  final Map<String, Uint8List> _entries = {};
  final Set<String> simulatedUnreadablePersonas;
  final String? simulatedDirectoryError;

  InMemoryHandoffOutboxService({
    Set<String>? simulatedUnreadablePersonas,
    this.simulatedDirectoryError,
  }) : simulatedUnreadablePersonas = simulatedUnreadablePersonas ?? <String>{};

  static String _keyToHex(Uint8List key) {
    if (key.length != 32) {
      throw ArgumentError.value(
        key.length,
        'personaKey.length',
        'Persona public key must be exactly 32 bytes',
      );
    }
    final sb = StringBuffer();
    for (final b in key) {
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }

  @override
  Future<void> savePendingBundle(
    Uint8List personaKey,
    Uint8List bundleBytes,
  ) async {
    final hex = _keyToHex(personaKey);
    if (bundleBytes.isEmpty ||
        bundleBytes.length > HandoffBundle.maxBundleBytes) {
      throw ArgumentError.value(
        bundleBytes.length,
        'bundleBytes.length',
        'Handoff bundle must be 1..${HandoffBundle.maxBundleBytes} bytes',
      );
    }
    _entries[hex] = Uint8List.fromList(bundleBytes);
  }

  @override
  Future<HandoffOutboxLoadResult> loadAllPendingBundles() async {
    return HandoffOutboxLoadResult(
      bundles: {
        for (final entry in _entries.entries)
          if (!simulatedUnreadablePersonas.contains(entry.key))
            entry.key: Uint8List.fromList(entry.value),
      },
      unreadablePersonas: Set<String>.of(simulatedUnreadablePersonas),
      directoryError: simulatedDirectoryError,
    );
  }

  @override
  Future<void> deletePendingBundle(Uint8List personaKey) async {
    _entries.remove(_keyToHex(personaKey));
  }

  @override
  Future<void> clearAll() async {
    _entries.clear();
  }
}
