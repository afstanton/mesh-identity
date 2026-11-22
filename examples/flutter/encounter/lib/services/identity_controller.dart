import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:mesh_identity/mesh_identity.dart';

import 'keyring_service.dart';
import 'snapshot_envelope.dart';
import 'snapshot_storage.dart';

/// Lifecycle status of the node's local identity engine.
enum IdentityStatus {
  /// Engine has not attempted initialization.
  uninitialized,

  /// Initializing or restoring identity from durable storage.
  initializing,

  /// Identity engine is initialized, restored, and ready for operations.
  ready,

  /// Storage or snapshot is corrupted or mismatched; requires explicit user recovery.
  corrupted,
}

/// App-level controller managing the single-isolate [MeshInstallation] lifecycle,
/// persona seed storage, and serialized atomic snapshot writes.
class IdentityController extends ChangeNotifier {
  final SecureKeyringService _keyring;
  final SnapshotStorageService _storage;

  MeshInstallation? _installation;
  IdentityStatus _status = IdentityStatus.uninitialized;
  String? _errorMessage;

  Uint8List? _cachedSelectedIdentity;
  List<Uint8List> _cachedIdentities = const [];
  int _cachedContactsCount = 0;

  Future<void> _queue = Future<void>.value();
  bool _isDisposed = false;

  IdentityController({
    SecureKeyringService? keyring,
    SnapshotStorageService? storage,
  }) : _keyring = keyring ?? FlutterSecureKeyringService(),
       _storage = storage ?? FileSnapshotStorageService();

  IdentityStatus get status => _status;
  bool get isReady => _status == IdentityStatus.ready && _installation != null;
  bool get isDisposed => _isDisposed;
  String? get errorMessage => _errorMessage;

  /// Defensive copy of the 32-byte Ed25519 public key of the active local persona.
  Uint8List? get selectedIdentity => _cachedSelectedIdentity == null
      ? null
      : Uint8List.fromList(_cachedSelectedIdentity!);

  /// Unmodifiable list of defensive copies of all committed 32-byte public keys.
  List<Uint8List> get identities =>
      List.unmodifiable(_cachedIdentities.map(Uint8List.fromList));

  /// Number of contacts in the currently selected persona's address book.
  int get contactsCount => _cachedContactsCount;

  /// Look up a contact record by [peerPublicKey] on the selected persona.
  Contact? getContact(Uint8List peerPublicKey) {
    final inst = _requireInstallation();
    return inst.getContact(peerPublicKey);
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

  MeshInstallation _requireInstallation() {
    if (_isDisposed) {
      throw StateError('IdentityController has been disposed');
    }
    final inst = _installation;
    if (inst == null || _status != IdentityStatus.ready) {
      throw StateError('IdentityController is not ready (status: $_status)');
    }
    return inst;
  }

  void _syncCachedView() {
    final inst = _installation;
    if (_isDisposed ||
        inst == null ||
        _status != IdentityStatus.ready ||
        inst.isDisposed) {
      _clearCachedView();
      return;
    }
    _cachedSelectedIdentity = Uint8List.fromList(inst.selectedIdentity);
    _cachedIdentities = inst.identities.map(Uint8List.fromList).toList();
    _cachedContactsCount = inst.contactsCount();
  }

  void _clearCachedView() {
    _cachedSelectedIdentity = null;
    _cachedIdentities = const [];
    _cachedContactsCount = 0;
  }

  void _notifySafely() {
    if (!_isDisposed) {
      notifyListeners();
    }
  }

  static String _bytesToHex(Uint8List bytes) {
    final sb = StringBuffer();
    for (final b in bytes) {
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }

  static String _shortHex(Uint8List bytes) {
    final hex = _bytesToHex(bytes);
    return hex.length <= 12 ? hex : '${hex.substring(0, 12)}...';
  }

  /// Initialize the controller: restores from durable snapshot or generates a fresh
  /// node strictly when both snapshot storage and keyring are empty.
  Future<void> initialize() {
    return _serialized(() async {
      if (_isDisposed) return;
      await _initializeInternal();
    });
  }

  Future<void> _initializeInternal() async {
    _installation?.dispose();
    _installation = null;
    _status = IdentityStatus.initializing;
    _errorMessage = null;
    _clearCachedView();
    _notifySafely();

    try {
      final hasSnapshot = await _storage.hasSnapshot();
      if (_isDisposed) return;
      final keyringKeys = await _keyring.getAllIdentityKeys();
      if (_isDisposed) return;

      if (!hasSnapshot && keyringKeys.isEmpty) {
        // Case 1: True first launch (neither snapshot nor keys exist).
        await _initializeFreshNode();
        return;
      }

      if (hasSnapshot && keyringKeys.isEmpty) {
        // Case 2: Existing snapshot with empty keyring (never silently overwrite).
        _status = IdentityStatus.corrupted;
        _errorMessage =
            'Snapshot restoration failed: saved identity snapshot exists, '
            'but no signing keys were found in the device keyring.';
        _clearCachedView();
        _notifySafely();
        return;
      }

      if (!hasSnapshot && keyringKeys.isNotEmpty) {
        // Case 3: Keyring keys exist without a snapshot (never silently discard keys).
        _status = IdentityStatus.corrupted;
        _errorMessage =
            'Snapshot restoration failed: signing keys exist in the device keyring, '
            'but the installation snapshot is missing.';
        _clearCachedView();
        _notifySafely();
        return;
      }

      // Case 4: Both snapshot and keyring keys exist.
      final bytes = await _storage.loadSnapshot();
      if (_isDisposed) return;
      if (bytes == null) {
        _status = IdentityStatus.corrupted;
        _errorMessage =
            'Snapshot restoration failed: snapshot file missing or unreadable.';
        _clearCachedView();
        _notifySafely();
        return;
      }

      if (SnapshotEnvelope.hasEnvelopeMagic(bytes)) {
        final SnapshotEnvelope envelope;
        try {
          envelope = SnapshotEnvelope.decode(bytes);
        } on FormatException catch (e) {
          _status = IdentityStatus.corrupted;
          _errorMessage = 'Snapshot restoration failed: ${e.message}';
          _clearCachedView();
          _notifySafely();
          return;
        }

        final seeds = await _loadSeedsForKeys(envelope.identityKeys);
        MeshInstallation? restored;
        try {
          if (_isDisposed) return;
          restored = MeshInstallation.restore(
            snapshotBytes: envelope.snapshotBytes,
            signingKeySeeds: seeds,
          );
        } on Exception catch (e) {
          _status = IdentityStatus.corrupted;
          _errorMessage = 'Snapshot restoration failed: $e';
          _clearCachedView();
          _notifySafely();
          return;
        } finally {
          for (final seed in seeds) {
            seed.fillRange(0, seed.length, 0);
          }
        }

        if (_isDisposed) {
          restored.dispose();
          return;
        }
        _installation = restored;
        _status = IdentityStatus.ready;
        _syncCachedView();

        // Best-effort prune orphan keyring keys left behind by a crashed transaction.
        await _pruneOrphanKeys(
          keyringKeys: keyringKeys,
          committedKeys: envelope.identityKeys,
        );
        _notifySafely();
      } else {
        // Legacy raw CBOR snapshot without envelope framing.
        final allSeeds = await _keyring.getAllSeeds();
        MeshInstallation? restored;
        try {
          if (_isDisposed) return;
          restored = MeshInstallation.restore(
            snapshotBytes: bytes,
            signingKeySeeds: allSeeds,
          );
        } on Exception catch (e) {
          _status = IdentityStatus.corrupted;
          _errorMessage = 'Snapshot restoration failed: $e';
          _clearCachedView();
          _notifySafely();
          return;
        } finally {
          for (final seed in allSeeds) {
            seed.fillRange(0, seed.length, 0);
          }
        }

        if (_isDisposed) {
          restored.dispose();
          return;
        }
        _installation = restored;
        _status = IdentityStatus.ready;
        _syncCachedView();
        _notifySafely();
      }
    } catch (e) {
      if (_isDisposed) return;
      _status = IdentityStatus.corrupted;
      _errorMessage = 'Snapshot restoration failed: $e';
      _clearCachedView();
      _notifySafely();
    }
  }

  Future<void> _initializeFreshNode() async {
    final initialSeed = MeshInstallation.generateSeed();
    MeshInstallation? inst;
    Uint8List? primaryKey;

    try {
      inst = MeshInstallation(seed: initialSeed);
      primaryKey = inst.selectedIdentity;

      await _keyring.saveSeed(primaryKey, initialSeed);
      if (_isDisposed) {
        inst.dispose();
        return;
      }

      final encoded = SnapshotEnvelope.encode(
        identityKeys: [primaryKey],
        snapshotBytes: inst.save(),
      );
      await _storage.saveSnapshot(encoded);
      if (_isDisposed) {
        inst.dispose();
        return;
      }

      _installation = inst;
      inst = null;
      _status = IdentityStatus.ready;
      _syncCachedView();
      _notifySafely();
    } catch (e) {
      inst?.dispose();
      if (primaryKey != null) {
        try {
          await _keyring.removeSeed(primaryKey);
        } catch (_) {
          // Best-effort cleanup if initial snapshot write failed.
        }
      }
      if (_isDisposed) return;
      _status = IdentityStatus.corrupted;
      _errorMessage = 'Failed to initialize identity: $e';
      _clearCachedView();
      _notifySafely();
    } finally {
      initialSeed.fillRange(0, 32, 0);
    }
  }

  Future<List<Uint8List>> _loadSeedsForKeys(
    List<Uint8List> identityKeys,
  ) async {
    final seeds = <Uint8List>[];
    try {
      for (final key in identityKeys) {
        final seed = await _keyring.getSeed(key);
        if (seed == null || seed.length != 32) {
          seed?.fillRange(0, seed.length, 0);
          throw FormatException(
            'Missing signing seed in keyring for identity ${_shortHex(key)}',
          );
        }
        seeds.add(seed);
      }
      return seeds;
    } catch (_) {
      for (final s in seeds) {
        s.fillRange(0, s.length, 0);
      }
      rethrow;
    }
  }

  Future<void> _pruneOrphanKeys({
    required List<Uint8List> keyringKeys,
    required List<Uint8List> committedKeys,
  }) async {
    final committedHex = committedKeys.map(_bytesToHex).toSet();
    for (final key in keyringKeys) {
      if (!committedHex.contains(_bytesToHex(key))) {
        try {
          await _keyring.removeSeed(key);
        } catch (_) {
          // Best-effort orphan cleanup; ignore failures.
        }
      }
    }
  }

  /// Persist the latest framed snapshot atomically. Must be called inside [_serialized].
  Future<void> _persistSnapshotInternal() async {
    final inst = _requireInstallation();
    final encoded = SnapshotEnvelope.encode(
      identityKeys: inst.identities,
      snapshotBytes: inst.save(),
    );
    await _storage.saveSnapshot(encoded);
  }

  Future<void> _rollbackInstallation(
    Uint8List prevSnapshotBytes,
    List<Uint8List> prevKeys,
  ) async {
    if (_isDisposed) return;
    try {
      final seeds = await _loadSeedsForKeys(prevKeys);
      MeshInstallation? restored;
      try {
        if (_isDisposed) return;
        restored = MeshInstallation.restore(
          snapshotBytes: prevSnapshotBytes,
          signingKeySeeds: seeds,
        );
      } finally {
        for (final seed in seeds) {
          seed.fillRange(0, seed.length, 0);
        }
      }
      if (_isDisposed) {
        restored.dispose();
        return;
      }
      _installation?.dispose();
      _installation = restored;
      _syncCachedView();
    } catch (e) {
      if (_isDisposed) return;
      _installation?.dispose();
      _installation = null;
      _status = IdentityStatus.corrupted;
      _errorMessage = 'State rollback failed after persistence error: $e';
      _clearCachedView();
      _notifySafely();
    }
  }

  Future<T> _transactionalMutate<T>(
    T Function(MeshInstallation inst) mutate,
  ) async {
    final inst = _requireInstallation();
    final prevKeys = inst.identities;
    final prevSnapshotBytes = inst.save();

    final T result;
    try {
      result = mutate(inst);
      await _persistSnapshotInternal();
    } catch (_) {
      await _rollbackInstallation(prevSnapshotBytes, prevKeys);
      rethrow;
    }

    if (!_isDisposed) {
      _syncCachedView();
      _notifySafely();
    }
    return result;
  }

  /// Add a new persona with a freshly generated 32-byte Ed25519 signing seed.
  ///
  /// Uses a recoverable transaction: writes seed, persists framed snapshot, and
  /// rolls back on failure without exposing uncommitted keys.
  Future<Uint8List> addPersona() {
    return _serialized(() async {
      final inst = _requireInstallation();
      final newSeed = MeshInstallation.generateSeed();
      Uint8List? newKey;
      var seedSaved = false;

      try {
        newKey = inst.addIdentity(newSeed);
        await _keyring.saveSeed(newKey, newSeed);
        seedSaved = true;
        await _persistSnapshotInternal();
        if (!_isDisposed) {
          _syncCachedView();
          _notifySafely();
        }
        return Uint8List.fromList(newKey);
      } catch (_) {
        if (newKey != null) {
          if (!_isDisposed && !inst.isDisposed) {
            try {
              inst.removeIdentity(newKey);
            } catch (_) {
              // Ignore if rollback removal fails.
            }
          }
          if (seedSaved) {
            try {
              await _keyring.removeSeed(newKey);
            } catch (_) {
              // Best-effort cleanup; durable envelope excludes newKey so startup prunes it.
            }
          }
        }
        rethrow;
      } finally {
        newSeed.fillRange(0, 32, 0);
      }
    });
  }

  /// Select active persona by [identityKey].
  Future<void> selectPersona(Uint8List identityKey) {
    return _serialized(() async {
      await _transactionalMutate((inst) {
        inst.selectIdentity(identityKey);
      });
    });
  }

  /// Remove persona identified by [identityKey].
  ///
  /// Persists the updated snapshot FIRST before deleting the seed from keyring so
  /// a write failure or crash never leaves a snapshot referencing a missing seed.
  Future<void> removePersona(Uint8List identityKey) {
    return _serialized(() async {
      final inst = _requireInstallation();
      final prevKeys = inst.identities;
      final prevSnapshotBytes = inst.save();

      try {
        inst.removeIdentity(identityKey);
        await _persistSnapshotInternal();
      } catch (_) {
        await _rollbackInstallation(prevSnapshotBytes, prevKeys);
        rethrow;
      }

      if (!_isDisposed) {
        _syncCachedView();
        _notifySafely();
      }

      // Replacement snapshot is durable; best-effort remove seed from keyring.
      try {
        await _keyring.removeSeed(identityKey);
      } catch (_) {
        // Next startup will restore the new snapshot without identityKey and prune orphan.
      }
    });
  }

  /// Block an unverified or verified peer public key.
  Future<void> blockContact(Uint8List peerPublicKey) {
    return _serialized(() async {
      await _transactionalMutate((inst) {
        inst.blockContact(peerPublicKey);
      });
    });
  }

  /// Execute an arbitrary [MeshInstallation] mutation under the serialization lock
  /// with atomic snapshot persistence and rollback on failure.
  Future<T> runMutation<T>(T Function(MeshInstallation installation) action) {
    return _serialized(() async {
      return _transactionalMutate(action);
    });
  }

  /// Non-destructively archive any corrupted snapshot and reset identity state.
  ///
  /// Requires explicit [confirmDestructiveReset] `true` confirmation. Returns the
  /// archived backup path/identifier if a snapshot was quarantined.
  Future<String?> resetCorruptedState({required bool confirmDestructiveReset}) {
    return _serialized(() async {
      if (_isDisposed) {
        throw StateError('IdentityController has been disposed');
      }
      if (!confirmDestructiveReset) {
        throw ArgumentError.value(
          confirmDestructiveReset,
          'confirmDestructiveReset',
          'Explicit user confirmation is required to reset identity state.',
        );
      }

      _installation?.dispose();
      _installation = null;
      _clearCachedView();

      final archivedPath = await _storage.archiveSnapshot();
      await _keyring.clear();
      await _initializeInternal();
      return archivedPath;
    });
  }

  /// Manually trigger snapshot persistence (e.g. when app goes to background).
  Future<void> persist() {
    return _serialized(() async {
      if (_isDisposed || !isReady) return;
      await _persistSnapshotInternal();
    });
  }

  @override
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;
    _installation?.dispose();
    _installation = null;
    _clearCachedView();
    super.dispose();
  }
}
