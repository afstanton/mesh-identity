import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:mesh_identity/mesh_identity.dart';

import 'encounter_coordinator.dart';
import 'encounter_session.dart';
import 'handoff_outbox.dart';
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

  /// Storage or keyring was temporarily unavailable (e.g. locked keychain or stopped
  /// secret service). User should retry without erasing identity state.
  unavailable,

  /// Stored snapshot or snapshot/keyring pairing is corrupted or mismatched;
  /// requires explicit destructive reset to recover.
  corrupted,
}

/// Result of a two-phase group mutation committed durably on [IdentityController].
class GroupTwoPhaseCommitResult<T> {
  final T value;
  final List<GroupEvent> confirmedEvents;
  final List<OutgoingMessage> releasedMessages;

  const GroupTwoPhaseCommitResult({
    required this.value,
    required this.confirmedEvents,
    required this.releasedMessages,
  });
}

/// App-level controller managing the single-isolate authoritative [MeshGroupHandle]
/// (and its borrowed [MeshInstallation] view), persona seed storage, serialized
/// atomic snapshot writes, and delegated Encounter ceremony coordination.
class IdentityController extends ChangeNotifier {
  final SecureKeyringService _keyring;
  final SnapshotStorageService _storage;
  final HandoffOutboxService _handoffOutbox;
  final DateTime Function() _clock;
  late final EncounterCoordinator _encounter;

  MeshGroupHandle? _groupHandle;
  IdentityStatus _status = IdentityStatus.uninitialized;
  String? _errorMessage;

  MeshInstallation? get _installation {
    final handle = _groupHandle;
    if (handle == null || handle.isDisposed) return null;
    return handle.installation;
  }

  Uint8List? _cachedSelectedIdentity;
  List<Uint8List> _cachedIdentities = const [];
  int _cachedContactsCount = 0;
  List<Contact> _cachedContacts = const [];
  Map<String, int> _cachedPersonaContactCounts = const {};
  Uint8List? _cachedDeviceNonce;
  VotingRecord? _cachedSelectedVotingRecord;
  Map<String, VotingRecord> _cachedPersonaVotingRecords = const {};
  final Map<String, HandoffBundle> _pendingOutboundHandoffs = {};
  final Set<String> _unreadableOutboxPersonas = {};
  String? _outboxLoadError;

  Future<void> _queue = Future<void>.value();
  Future<void> Function()? _beforePersistHook;
  bool _isDisposed = false;
  bool _hasPendingChanges = false;
  int _lastNowMs = 0;

  /// Register an optional hook invoked before any identity-level snapshot write
  /// so [GroupController] can flush any unsaved post-commit outbox frames
  /// before overwriting the on-disk snapshot.
  void setBeforePersistHook(Future<void> Function()? hook) {
    _beforePersistHook = hook;
  }

  IdentityController({
    SecureKeyringService? keyring,
    SnapshotStorageService? storage,
    HandoffOutboxService? handoffOutbox,
    DateTime Function()? clock,
  }) : _keyring = keyring ?? FlutterSecureKeyringService(),
       _storage = storage ?? FileSnapshotStorageService(),
       _handoffOutbox =
           handoffOutbox ??
           (storage == null
               ? FileHandoffOutboxService()
               : InMemoryHandoffOutboxService()),
       _clock = clock ?? DateTime.now {
    _encounter = EncounterCoordinator(_IdentityEncounterHost(this));
  }

  IdentityStatus get status => _status;
  bool get isReady =>
      _status == IdentityStatus.ready &&
      _groupHandle != null &&
      !_groupHandle!.isDisposed;
  bool get isDisposed => _isDisposed;
  String? get errorMessage => _errorMessage;
  EncounterSessionState get encounterSession => _encounter.session;
  bool get hasActiveEncounter => _encounter.session.isActive;
  DateTime? get rateLimitedUntil => _encounter.rateLimitedUntil;
  DateTime get currentTime => _now();

  DateTime _now() {
    final raw = _clock().millisecondsSinceEpoch;
    final clamped = raw < _lastNowMs ? _lastNowMs : raw;
    _lastNowMs = clamped;
    return DateTime.fromMillisecondsSinceEpoch(clamped);
  }

  void _disposeInstallationAndCeremony() {
    // Dispose group handle (which invalidates its borrowed installation view)
    // before ceremony teardown so EncounterCeremony.dispose() never invokes
    // native cancel with wall-clock time during teardown or rollback.
    _groupHandle?.dispose();
    _groupHandle = null;
    _encounter.disposeCeremonyHandleOnly();
  }

  /// Defensive copy of the 32-byte Ed25519 public key of the active local persona.
  Uint8List? get selectedIdentity => _cachedSelectedIdentity == null
      ? null
      : Uint8List.fromList(_cachedSelectedIdentity!);

  /// Unmodifiable list of defensive copies of all committed 32-byte public keys.
  List<Uint8List> get identities =>
      List.unmodifiable(_cachedIdentities.map(Uint8List.fromList));

  /// Number of contacts in the currently selected persona's address book.
  int get contactsCount => _cachedContactsCount;

  /// Unmodifiable snapshot of contacts in the selected persona's address book.
  List<Contact> get contacts => List.unmodifiable(_cachedContacts);

  /// Cached contact count for a specific [identityKey] persona.
  int contactsCountForPersona(Uint8List identityKey) =>
      _cachedPersonaContactCounts[_bytesToHex(identityKey)] ?? 0;

  /// Defensive copy of this device's 32-byte persistent nonce, or `null` if
  /// not generated yet.
  Uint8List? get deviceNonce => _cachedDeviceNonce == null
      ? null
      : Uint8List.fromList(_cachedDeviceNonce!);

  /// Monotonic voting record for the currently selected persona.
  VotingRecord? get selectedVotingRecord => _cachedSelectedVotingRecord;

  /// Monotonic voting state for the currently selected persona.
  VotingState? get selectedVotingState => _cachedSelectedVotingRecord?.state;

  /// Cached monotonic voting record for a specific [identityKey] persona.
  VotingRecord? votingRecordForPersona(Uint8List identityKey) =>
      _cachedPersonaVotingRecords[_bytesToHex(identityKey)];

  /// Pending unacknowledged outbound [HandoffBundle] for the selected persona,
  /// persisted across screen closes and app restarts until cleared.
  HandoffBundle? get pendingOutboundHandoff {
    final selected = _cachedSelectedIdentity;
    if (selected == null) return null;
    return _pendingOutboundHandoffs[_bytesToHex(selected)];
  }

  /// Pending unacknowledged outbound [HandoffBundle] for [identityKey], if any.
  HandoffBundle? pendingOutboundHandoffFor(Uint8List identityKey) =>
      _pendingOutboundHandoffs[_bytesToHex(identityKey)];

  /// Recovery error message when the selected persona is `Stopped` but its
  /// persisted outbound handoff bundle could not be loaded.
  String? get pendingOutboundHandoffError {
    if (_outboxLoadError != null) {
      return 'This device may have a pending handoff, but the handoff outbox '
          'could not be read ($_outboxLoadError).';
    }
    final selected = _cachedSelectedIdentity;
    if (selected == null) return null;
    final state = _cachedSelectedVotingRecord?.state;
    if (state == VotingState.stopped &&
        _unreadableOutboxPersonas.contains(_bytesToHex(selected))) {
      return 'This device is Stopped for this persona, but its saved '
          'outbound handoff bundle could not be read. Check local storage '
          'or transfer the role back from another device.';
    }
    return null;
  }

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

  MeshGroupHandle _requireGroupHandle() {
    if (_isDisposed) {
      throw StateError('IdentityController has been disposed');
    }
    final handle = _groupHandle;
    if (handle == null ||
        _status != IdentityStatus.ready ||
        handle.isDisposed) {
      throw StateError('IdentityController is not ready (status: $_status)');
    }
    return handle;
  }

  MeshInstallation _requireInstallation() => _requireGroupHandle().installation;

  void _ensureNoActiveEncounter() {
    if (_encounter.hasActiveCeremony) {
      throw const CeremonyActiveException(
        'Cannot modify personas or contacts while an encounter ceremony is active.',
      );
    }
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
    _cachedContacts = inst.listContacts();
    _cachedPersonaContactCounts = {
      for (final id in _cachedIdentities)
        _bytesToHex(id): inst.contactsCount(identityKey: id),
    };
    final currentNonce = inst.getCurrentDeviceNonce();
    _cachedDeviceNonce = currentNonce == null
        ? null
        : Uint8List.fromList(currentNonce);
    _cachedSelectedVotingRecord = inst.getVotingRecord();
    _cachedPersonaVotingRecords = {
      for (final id in _cachedIdentities)
        _bytesToHex(id): inst.getVotingRecord(identityKey: id),
    };
  }

  void _clearCachedView() {
    _cachedSelectedIdentity = null;
    _cachedIdentities = const [];
    _cachedContactsCount = 0;
    _cachedContacts = const [];
    _cachedPersonaContactCounts = const {};
    _cachedDeviceNonce = null;
    _cachedSelectedVotingRecord = null;
    _cachedPersonaVotingRecords = const {};
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
    _disposeInstallationAndCeremony();
    _encounter.resetState();
    _hasPendingChanges = false;
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

      final SnapshotEnvelope envelope;
      final List<Uint8List> seeds;
      MeshGroupHandle? restored;
      try {
        envelope = SnapshotEnvelope.decode(bytes);
        seeds = await _loadSeedsForKeys(envelope.identityKeys);
        try {
          if (_isDisposed) return;
          try {
            restored = MeshGroupHandle.restore(
              snapshotBlob: envelope.snapshotBytes,
              signingKeySeeds: seeds,
            );
          } on InvalidSnapshotException {
            // Backward-compatible upgrade for pre-Slice-7 bare installation snapshots.
            final legacyInst = MeshInstallation.restore(
              snapshotBytes: envelope.snapshotBytes,
              signingKeySeeds: seeds,
            );
            restored = MeshGroupHandle.fromInstallation(legacyInst);
          } on MalformedGroupException {
            // Backward-compatible upgrade for pre-Slice-7 bare installation snapshots.
            final legacyInst = MeshInstallation.restore(
              snapshotBytes: envelope.snapshotBytes,
              signingKeySeeds: seeds,
            );
            restored = MeshGroupHandle.fromInstallation(legacyInst);
          }
        } finally {
          for (final seed in seeds) {
            seed.fillRange(0, seed.length, 0);
          }
        }
      } on FormatException catch (e) {
        if (_isDisposed) return;
        _status = IdentityStatus.corrupted;
        _errorMessage = 'Snapshot restoration failed: ${e.message}';
        _clearCachedView();
        _notifySafely();
        return;
      } on MeshIdentityException catch (e) {
        if (_isDisposed) return;
        _status = IdentityStatus.corrupted;
        _errorMessage = 'Snapshot restoration failed: $e';
        _clearCachedView();
        _notifySafely();
        return;
      }

      if (_isDisposed) {
        restored.dispose();
        return;
      }
      _groupHandle = restored;
      _status = IdentityStatus.ready;
      _hasPendingChanges = false;
      _syncCachedView();

      await _loadAndPrunePendingOutboundHandoffs(restored.installation);

      // Best-effort prune orphan keyring keys left behind by a crashed transaction.
      await _pruneOrphanKeys(
        keyringKeys: keyringKeys,
        committedKeys: envelope.identityKeys,
      );
      _notifySafely();
    } catch (e) {
      if (_isDisposed) return;
      _disposeInstallationAndCeremony();
      _encounter.resetState();
      _status = IdentityStatus.unavailable;
      _errorMessage = 'Unable to access local identity storage: $e';
      _clearCachedView();
      _notifySafely();
    }
  }

  Future<void> _initializeFreshNode() async {
    final initialSeed = MeshInstallation.generateSeed();
    MeshGroupHandle? handle;
    Uint8List? primaryKey;

    try {
      handle = MeshGroupHandle(seed: initialSeed);
      primaryKey = handle.selectedIdentity;

      await _keyring.saveSeed(primaryKey, initialSeed);
      if (_isDisposed) {
        handle.dispose();
        return;
      }

      final saved = handle.save(at: _now());
      final encoded = SnapshotEnvelope.encode(
        identityKeys: handle.installation.identities,
        snapshotBytes: saved.blob,
      );
      await _storage.saveSnapshot(encoded);
      handle.confirmSaved(saved.token);
      if (_isDisposed) {
        handle.dispose();
        return;
      }

      _groupHandle = handle;
      handle = null;
      _status = IdentityStatus.ready;
      _hasPendingChanges = false;
      _syncCachedView();
      _notifySafely();
    } catch (e) {
      handle?.dispose();
      if (primaryKey != null) {
        try {
          await _keyring.removeSeed(primaryKey);
        } catch (_) {
          // Best-effort cleanup if initial snapshot write failed.
        }
      }
      if (_isDisposed) return;
      _status = IdentityStatus.unavailable;
      _errorMessage = 'Unable to initialize local identity storage: $e';
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
  Future<void> _persistSnapshotInternal({
    DateTime? at,
    bool runBeforePersistHook = true,
  }) async {
    if (runBeforePersistHook && _beforePersistHook != null) {
      await _beforePersistHook!();
    }
    final handle = _requireGroupHandle();
    final saved = handle.save(at: at ?? _now());
    final encoded = SnapshotEnvelope.encode(
      identityKeys: handle.installation.identities,
      snapshotBytes: saved.blob,
    );
    await _storage.saveSnapshot(encoded);
    _hasPendingChanges = false;
  }

  Future<void> _rollbackInstallation(
    Uint8List prevSnapshotBytes,
    List<Uint8List> prevKeys,
  ) async {
    if (_isDisposed) return;
    final hadActiveEncounter = _encounter.hasActiveCeremony;
    try {
      final seeds = await _loadSeedsForKeys(prevKeys);
      MeshGroupHandle? restored;
      try {
        if (_isDisposed) return;
        restored = MeshGroupHandle.restore(
          snapshotBlob: prevSnapshotBytes,
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
      _disposeInstallationAndCeremony();
      _groupHandle = restored;
      _hasPendingChanges = false;
      _syncCachedView();
      if (hadActiveEncounter) {
        _encounter.onExternalRollback();
        _notifySafely();
      }
    } catch (e) {
      if (_isDisposed) return;
      _disposeInstallationAndCeremony();
      _encounter.resetState();
      _hasPendingChanges = false;
      _status = IdentityStatus.corrupted;
      _errorMessage = 'State rollback failed after persistence error: $e';
      _clearCachedView();
      _notifySafely();
    }
  }

  Future<T> _transactionalMutate<T>(
    FutureOr<T> Function(MeshInstallation inst) mutate,
  ) async {
    final handle = _requireGroupHandle();
    final inst = handle.installation;
    final now = _now();
    final prevKeys = inst.identities;
    final prevSnapshotBytes = handle.save(at: now).blob;

    final T result;
    try {
      result = await mutate(inst);
      if (_isDisposed) {
        throw StateError('IdentityController has been disposed');
      }
      await _persistSnapshotInternal(at: _now());
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
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is live.
  /// Otherwise uses a recoverable transaction: writes seed, persists framed
  /// snapshot, and rolls back on failure without exposing uncommitted keys.
  Future<Uint8List> addPersona() {
    return _serialized(() async {
      final inst = _requireInstallation();
      _ensureNoActiveEncounter();
      return _addSeededPersona(inst, MeshInstallation.generateSeed());
    });
  }

  /// Import an existing 32-byte Ed25519 signing [seed] as a persona on this
  /// installation, zeroizing the internal copy on completion.
  ///
  /// Useful for provisioning a shared persona onto a second device prior to
  /// transferring its monotonic voting role via device handoff.
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  Future<Uint8List> importPersonaSeed(Uint8List seed) {
    return _serialized(() async {
      final inst = _requireInstallation();
      _ensureNoActiveEncounter();
      if (seed.length != 32) {
        throw const InvalidArgumentsException(
          'Persona signing seed must be exactly 32 bytes.',
        );
      }
      return _addSeededPersona(
        inst,
        Uint8List.fromList(seed),
        gateAfterImport: true,
      );
    });
  }

  /// Return the 32-byte Ed25519 signing seed for [identityKey] from the
  /// secure keyring. Callers must zeroize the returned buffer immediately
  /// after use.
  Future<Uint8List> exportPersonaSeed(Uint8List identityKey) {
    return _serialized(() async {
      _requireInstallation();
      _ensureNoActiveEncounter();
      final seed = await _keyring.getSeed(identityKey);
      if (seed == null) {
        throw StateError('Signing seed not found in keyring for persona.');
      }
      return seed;
    });
  }

  Future<Uint8List> _addSeededPersona(
    MeshInstallation inst,
    Uint8List seedBuffer, {
    bool gateAfterImport = false,
  }) async {
    final prevKeys = gateAfterImport ? inst.identities : const <Uint8List>[];
    final prevSnapshotBytes = gateAfterImport
        ? _requireGroupHandle().save(at: _now()).blob
        : Uint8List(0);
    Uint8List? newKey;
    var seedSaved = false;
    try {
      newKey = inst.addIdentity(seedBuffer);
      if (gateAfterImport) {
        inst.gateVoting();
      }
      await _keyring.saveSeed(newKey, seedBuffer);
      seedSaved = true;
      await _persistSnapshotInternal(at: _now());
      if (!_isDisposed) {
        _syncCachedView();
        _notifySafely();
      }
      return Uint8List.fromList(newKey);
    } catch (_) {
      if (seedSaved && newKey != null) {
        try {
          await _keyring.removeSeed(newKey);
        } catch (_) {
          // Best-effort cleanup; durable envelope excludes newKey so startup prunes it.
        }
      }
      if (gateAfterImport) {
        await _rollbackInstallation(prevSnapshotBytes, prevKeys);
      } else if (newKey != null && !_isDisposed && !inst.isDisposed) {
        try {
          inst.removeIdentity(newKey);
        } catch (_) {
          // Ignore if rollback removal fails.
        }
      }
      rethrow;
    } finally {
      seedBuffer.fillRange(0, seedBuffer.length, 0);
    }
  }

  /// Select active persona by [identityKey].
  ///
  /// Rejects with [CeremonyActiveException] without altering state if an
  /// encounter ceremony is active.
  Future<void> selectPersona(Uint8List identityKey) {
    return _serialized(() async {
      _requireInstallation();
      _ensureNoActiveEncounter();
      await _transactionalMutate((inst) {
        inst.selectIdentity(identityKey, at: _now());
      });
    });
  }

  /// Remove persona identified by [identityKey].
  ///
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  /// Otherwise persists the updated snapshot FIRST before deleting the seed from
  /// keyring so a write failure or crash never leaves a missing seed reference.
  Future<void> removePersona(Uint8List identityKey) {
    return _serialized(() async {
      final handle = _requireGroupHandle();
      final inst = handle.installation;
      _ensureNoActiveEncounter();
      final prevKeys = inst.identities;
      final prevSnapshotBytes = handle.save(at: _now()).blob;

      try {
        inst.removeIdentity(identityKey);
        await _persistSnapshotInternal(at: _now());
      } catch (_) {
        await _rollbackInstallation(prevSnapshotBytes, prevKeys);
        rethrow;
      }

      if (!_isDisposed) {
        _syncCachedView();
        _notifySafely();
      }

      // Clean up any stale pending handoff bundle for the removed persona.
      _pendingOutboundHandoffs.remove(_bytesToHex(identityKey));
      try {
        await _handoffOutbox.deletePendingBundle(identityKey);
      } catch (_) {
        // Startup pruning will clean up any remaining stale outbox file.
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
  ///
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  Future<void> blockContact(Uint8List peerPublicKey) {
    return _serialized(() async {
      _requireInstallation();
      _ensureNoActiveEncounter();
      await _transactionalMutate((inst) {
        inst.blockContact(peerPublicKey);
      });
    });
  }

  /// Restore a previously blocked contact back to active status.
  ///
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  Future<void> unblockContact(Uint8List peerPublicKey) {
    return _serialized(() async {
      _requireInstallation();
      _ensureNoActiveEncounter();
      await _transactionalMutate((inst) {
        inst.unblockContact(peerPublicKey);
      });
    });
  }

  /// Set or update the local alias for [peerPublicKey] on the active persona.
  ///
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  Future<void> setContactAlias(Uint8List peerPublicKey, String alias) {
    return _serialized(() async {
      _requireInstallation();
      _ensureNoActiveEncounter();
      await _transactionalMutate((inst) {
        inst.setContactAlias(peerPublicKey, alias);
      });
    });
  }

  /// Import an unverified peer public key into the active persona's address book.
  ///
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  Future<Contact> importPeerKey(Uint8List peerPublicKey) {
    return _serialized(() async {
      _requireInstallation();
      _ensureNoActiveEncounter();
      return _transactionalMutate((inst) {
        inst.importPeerKey(peerPublicKey);
        return inst.getContact(peerPublicKey)!;
      });
    });
  }

  /// Return this device's persistent 32-byte nonce, generating and durably
  /// persisting a new one if none exists yet.
  ///
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  Future<Uint8List> ensureDeviceNonce() {
    return _serialized(() async {
      final inst = _requireInstallation();
      _ensureNoActiveEncounter();
      final existing = inst.getCurrentDeviceNonce();
      if (existing != null) {
        return Uint8List.fromList(existing);
      }
      return _transactionalMutate((activeInst) {
        return Uint8List.fromList(activeInst.getDeviceNonce());
      });
    });
  }

  Future<void> _loadAndPrunePendingOutboundHandoffs(
    MeshInstallation inst,
  ) async {
    _pendingOutboundHandoffs.clear();
    _unreadableOutboxPersonas.clear();
    _outboxLoadError = null;

    final HandoffOutboxLoadResult loaded;
    try {
      loaded = await _handoffOutbox.loadAllPendingBundles();
    } catch (e) {
      _outboxLoadError = e.toString();
      return;
    }

    _outboxLoadError = loaded.directoryError;
    _unreadableOutboxPersonas.addAll(loaded.unreadablePersonas);

    final liveByHex = <String, Uint8List>{
      for (final id in inst.identities) _bytesToHex(id): id,
    };

    for (final entry in loaded.bundles.entries) {
      final personaKey = liveByHex[entry.key];
      if (personaKey == null) {
        continue;
      }
      final votingState = inst.getVotingRecord(identityKey: personaKey).state;
      if (votingState != VotingState.stopped) {
        try {
          await _handoffOutbox.deletePendingBundle(personaKey);
        } catch (_) {
          // Best-effort cleanup.
        }
        continue;
      }
      try {
        _pendingOutboundHandoffs[entry.key] = HandoffBundle.fromBytes(
          entry.value,
        );
      } catch (_) {
        // Keep the unreadable file on disk and surface a recovery notice.
        _unreadableOutboxPersonas.add(entry.key);
      }
    }
  }

  /// Begin a device-to-device handoff transferring the selected persona's
  /// monotonic voting role to [recipientNonce].
  ///
  /// Rejects self-handoff before mutating state, persists the pending outbound
  /// [HandoffBundle] and post-handoff `Stopped` snapshot atomically BEFORE
  /// returning, and rolls back if persistence fails.
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  Future<HandoffBundle> beginHandoff(Uint8List recipientNonce) {
    return _serialized(() async {
      final inst = _requireInstallation();
      _ensureNoActiveEncounter();
      final localNonce = inst.getCurrentDeviceNonce();
      if (localNonce != null && listEquals(localNonce, recipientNonce)) {
        throw const InvalidArgumentsException(
          'Cannot hand off to this device\'s own nonce. '
          'Enter the receiving device\'s nonce.',
        );
      }

      final handle = _requireGroupHandle();
      final activePersona = Uint8List.fromList(inst.selectedIdentity);
      final activeHex = _bytesToHex(activePersona);
      final now = _now();
      final prevKeys = inst.identities;
      final prevSnapshotBytes = handle.save(at: now).blob;

      final HandoffResult result;
      var outboxSaved = false;
      try {
        result = inst.beginHandoff(recipientNonce, at: now);
        await _handoffOutbox.savePendingBundle(
          activePersona,
          result.bundle.rawBytes,
        );
        outboxSaved = true;
        await _persistSnapshotInternal(at: now);
      } catch (_) {
        if (outboxSaved) {
          try {
            await _handoffOutbox.deletePendingBundle(activePersona);
          } catch (_) {
            // Best-effort outbox cleanup on rollback.
          }
        }
        await _rollbackInstallation(prevSnapshotBytes, prevKeys);
        rethrow;
      }

      _pendingOutboundHandoffs[activeHex] = result.bundle;
      _unreadableOutboxPersonas.remove(activeHex);
      _outboxLoadError = null;
      if (!_isDisposed) {
        _syncCachedView();
        _notifySafely();
      }
      return result.bundle;
    });
  }

  /// Accept an authenticated [HandoffBundle] addressed to this device's nonce,
  /// durably persisting the updated voting state and merged locks.
  ///
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  Future<VotingState> acceptHandoff(HandoffBundle bundle) {
    return _serialized(() async {
      final inst = _requireInstallation();
      _ensureNoActiveEncounter();
      final handle = _requireGroupHandle();
      final targetPersona = Uint8List.fromList(bundle.identity);
      final targetHex = _bytesToHex(targetPersona);
      final now = _now();
      final prevKeys = inst.identities;
      final prevSnapshotBytes = handle.save(at: now).blob;

      final AcceptHandoffResult result;
      try {
        result = inst.acceptHandoff(bundle, at: now);
        await _persistSnapshotInternal(at: now);
      } catch (_) {
        await _rollbackInstallation(prevSnapshotBytes, prevKeys);
        rethrow;
      }

      if (result.state == VotingState.voting) {
        _pendingOutboundHandoffs.remove(targetHex);
        _unreadableOutboxPersonas.remove(targetHex);
        try {
          await _handoffOutbox.deletePendingBundle(targetPersona);
        } catch (_) {
          // Startup pruning will clean up any remaining stale outbox file.
        }
      }

      if (!_isDisposed) {
        _syncCachedView();
        _notifySafely();
      }
      return result.state;
    });
  }

  /// Clear the active persona's persisted pending outbound handoff bundle
  /// after the user confirms it has been delivered to the receiving device.
  Future<void> clearPendingOutboundHandoff() {
    return _serialized(() async {
      final inst = _requireInstallation();
      _ensureNoActiveEncounter();
      final activePersona = Uint8List.fromList(inst.selectedIdentity);
      final activeHex = _bytesToHex(activePersona);
      await _handoffOutbox.deletePendingBundle(activePersona);
      _pendingOutboundHandoffs.remove(activeHex);
      _unreadableOutboxPersonas.remove(activeHex);
      _outboxLoadError = null;
      if (!_isDisposed) {
        _notifySafely();
      }
    });
  }

  /// Execute a synchronous or asynchronous [MeshInstallation] mutation under
  /// the serialization lock with atomic snapshot persistence and rollback on failure.
  ///
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  Future<T> runMutation<T>(
    FutureOr<T> Function(MeshInstallation installation) action,
  ) {
    return _serialized(() async {
      _requireInstallation();
      _ensureNoActiveEncounter();
      return _transactionalMutate(action);
    });
  }

  /// Start a two-device Encounter ceremony as Initiator (generates QR 1 Offer).
  Future<void> startEncounterAsInitiator() => _encounter.startAsInitiator();

  /// Open a two-device Encounter ceremony as Responder (awaiting peer's QR 1 Offer).
  Future<void> openEncounterAsResponder() => _encounter.openAsResponder();

  /// Responder imports Initiator's QR 1 Offer URI and emits QR 2 Response URI.
  Future<void> submitEncounterOffer(String rawUri) =>
      _encounter.submitOffer(rawUri);

  /// Initiator imports Responder's QR 2 Response URI, emits QR 3 Reveal URI,
  /// and computes the 6-digit SAS comparison code.
  Future<void> submitEncounterResponse(String rawUri) =>
      _encounter.submitResponse(rawUri);

  /// Responder imports Initiator's QR 3 Reveal URI and computes the 6-digit SAS code.
  Future<void> submitEncounterReveal(String rawUri) =>
      _encounter.submitReveal(rawUri);

  /// Confirm the human-typed 6-digit SAS code and durably save the verified contact.
  Future<void> confirmEncounterCode(String sixDigitInput) =>
      _encounter.confirmCode(sixDigitInput);

  /// Explicitly cancel any live Encounter ceremony on the active installation.
  Future<void> cancelActiveEncounter() => _encounter.cancelActive();

  /// Check ceremony timeout (120s) and rate-limit pause expiry (60s).
  Future<void> checkEncounterExpiry() => _encounter.checkExpiry();

  /// Dismiss the current encounter screen state, cancelling any live session
  /// and returning to `idle` (or `rateLimited` if pause remains active).
  Future<void> dismissEncounterSession() => _encounter.dismissSession();

  /// Permanently erase local signing keys, archive any corrupted snapshot file
  /// strictly for diagnostics, and initialize a brand-new identity.
  ///
  /// Once the keyring is cleared, the archived snapshot cannot be restored and
  /// the previous identity, personas, and contacts are permanently lost. Requires
  /// [status] == [IdentityStatus.corrupted] and explicit [confirmDestructiveReset] `true`.
  Future<String?> resetCorruptedState({required bool confirmDestructiveReset}) {
    return _serialized(() async {
      if (_isDisposed) {
        throw StateError('IdentityController has been disposed');
      }
      if (_status != IdentityStatus.corrupted) {
        throw StateError(
          'resetCorruptedState can only be called when status is '
          'IdentityStatus.corrupted (current: $_status)',
        );
      }
      if (!confirmDestructiveReset) {
        throw ArgumentError.value(
          confirmDestructiveReset,
          'confirmDestructiveReset',
          'Explicit user confirmation is required to reset identity state.',
        );
      }

      _disposeInstallationAndCeremony();
      _encounter.resetState();
      _hasPendingChanges = false;
      _clearCachedView();

      final archivedPath = await _storage.archiveSnapshot();
      await _handoffOutbox.clearAll();
      _pendingOutboundHandoffs.clear();
      _unreadableOutboxPersonas.clear();
      _outboxLoadError = null;
      await _keyring.clear();
      await _initializeInternal();
      return archivedPath;
    });
  }

  /// Trigger snapshot persistence if uncommitted changes exist (or when [force] is `true`).
  Future<void> persist({bool force = false}) {
    return _serialized(() async {
      if (_isDisposed || !isReady || (!force && !_hasPendingChanges)) return;
      await _persistSnapshotInternal(at: _now());
    });
  }

  /// Synchronously read group state from the authoritative [MeshGroupHandle].
  T readGroupState<T>(T Function(MeshGroupHandle handle) reader) {
    final handle = _requireGroupHandle();
    return reader(handle);
  }

  /// Execute a two-phase group mutation on the authoritative [MeshGroupHandle],
  /// persisting the unified snapshot atomically BEFORE calling `confirmSaved`
  /// and draining released outgoing frames.
  ///
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  Future<GroupTwoPhaseCommitResult<T>> runGroupTwoPhase<T>(
    T Function(MeshGroupHandle handle) mutate, {
    required DateTime at,
  }) {
    return _serialized(() async {
      final handle = _requireGroupHandle();
      _ensureNoActiveEncounter();
      if (_beforePersistHook != null) {
        await _beforePersistHook!();
      }
      final prevKeys = handle.installation.identities;
      final prevBlob = handle.save(at: at).blob;

      final T result;
      final GroupSaveResult saved;
      try {
        result = mutate(handle);
        saved = handle.save(at: at);
        final encoded = SnapshotEnvelope.encode(
          identityKeys: handle.installation.identities,
          snapshotBytes: saved.blob,
        );
        await _storage.saveSnapshot(encoded);
        _hasPendingChanges = false;
      } catch (_) {
        await _rollbackInstallation(prevBlob, prevKeys);
        rethrow;
      }

      final confirmedEvents = handle.confirmSaved(saved.token);
      final released = handle.takeOutgoing();
      if (!_isDisposed) {
        _syncCachedView();
        _notifySafely();
      }
      return GroupTwoPhaseCommitResult<T>(
        value: result,
        confirmedEvents: confirmedEvents,
        releasedMessages: released,
      );
    });
  }

  /// Persist a clean post-outbox checkpoint of the authoritative [MeshGroupHandle]
  /// so already-persisted outgoing frames are not re-staged on future restarts.
  Future<void> checkpointGroupSnapshot({required DateTime at}) {
    return _serialized(() async {
      if (_isDisposed || !isReady) return;
      await _persistSnapshotInternal(at: at, runBeforePersistHook: false);
    });
  }

  /// Drain any re-staged outgoing frames from the restored [MeshGroupHandle]
  /// (e.g. after a crash or outbox write failure between `confirmSaved` and
  /// durable outbox persistence).
  Future<List<OutgoingMessage>> recoverStagedGroupOutgoing({
    required DateTime at,
  }) {
    return _serialized(() async {
      final handle = _requireGroupHandle();
      final saved = handle.save(at: at);
      handle.confirmSaved(saved.token);
      return handle.takeOutgoing();
    });
  }

  /// Parse and inspect an unauthenticated OpenPGP certificate.
  OpenPgpCertificate inspectOpenPgpCertificate(Uint8List bytes) =>
      OpenPgpCertificate.fromBytes(bytes);

  /// Create an [OpenPgpExportPreview] for the currently selected persona.
  ///
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  Future<OpenPgpExportPreview> createOpenPgpPreview({
    required OpenPgpProfile profile,
    required String userId,
    required Uint8List document,
    Uint8List? peerCertificate,
    String? peerUserId,
  }) {
    return _serialized(() async {
      final inst = _requireInstallation();
      _ensureNoActiveEncounter();
      return inst.createOpenPgpPreview(
        profile: profile,
        userId: userId,
        document: document,
        peerCertificate: peerCertificate,
        peerUserId: peerUserId,
        at: _now(),
      );
    });
  }

  /// Confirm an [OpenPgpExportPreview] on the currently selected persona and
  /// issue transferable OpenPGP artifacts.
  ///
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  Future<OpenPgpArtifacts> confirmOpenPgpPreview(OpenPgpExportPreview preview) {
    return _serialized(() async {
      final inst = _requireInstallation();
      _ensureNoActiveEncounter();
      return preview.confirm(inst);
    });
  }

  /// Import an unverified OpenPGP peer certificate bound to [expectedPublicKey]
  /// and [userId], persisting the updated contact list atomically.
  ///
  /// Any verified revocations recorded natively before a rejection are
  /// preserved durably rather than rolled back.
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  Future<OpenPgpProvenance> importOpenPgpPeer({
    required Uint8List certificate,
    required Uint8List expectedPublicKey,
    required String userId,
  }) {
    return _serialized(() async {
      final handle = _requireGroupHandle();
      final inst = handle.installation;
      _ensureNoActiveEncounter();

      final now = _now();
      final prevKeys = inst.identities;
      final prevSnapshotBytes = handle.save(at: now).blob;

      final OpenPgpProvenance provenance;
      try {
        provenance = inst.importOpenPgpPeer(
          certificate: certificate,
          expectedPublicKey: expectedPublicKey,
          userId: userId,
          at: now,
        );
      } on MeshIdentityException {
        // Native import records verified revocations before checking the
        // target key/User ID; persist those revocations even on rejection.
        try {
          await _persistSnapshotInternal(at: _now());
        } catch (_) {
          // Best-effort revocation persistence before rethrowing original error.
        }
        if (!_isDisposed) {
          _syncCachedView();
          _notifySafely();
        }
        rethrow;
      }

      try {
        await _persistSnapshotInternal(at: _now());
      } catch (_) {
        await _rollbackInstallation(prevSnapshotBytes, prevKeys);
        rethrow;
      }

      if (!_isDisposed) {
        _syncCachedView();
        _notifySafely();
      }
      return provenance;
    });
  }

  /// Import an owned OpenPGP secret key certificate for a new persona not
  /// already in this installation, storing the extracted 32-byte signing seed
  /// directly in [_keyring] and persisting the updated snapshot atomically.
  ///
  /// Any verified revocations recorded natively before a rejection are
  /// preserved durably; persistence failures remove any newly saved seed and
  /// roll back. The temporary seed buffer is always zeroized in `finally`.
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  Future<OpenPgpProvenance> importOpenPgpOwned({
    required Uint8List secretKeyCertificate,
    required Uint8List expectedPublicKey,
    required String userId,
    String? passphrase,
  }) {
    return _serialized(() async {
      final handle = _requireGroupHandle();
      final inst = handle.installation;
      _ensureNoActiveEncounter();

      final now = _now();
      final prevKeys = inst.identities;
      final prevSnapshotBytes = handle.save(at: now).blob;

      OpenPgpOwnedImportResult? result;
      var seedSaved = false;
      try {
        result = inst.importOpenPgpOwned(
          secretKeyCertificate: secretKeyCertificate,
          expectedPublicKey: expectedPublicKey,
          userId: userId,
          passphrase: passphrase,
          at: now,
        );
        await _keyring.saveSeed(expectedPublicKey, result.seed);
        seedSaved = true;
        await _persistSnapshotInternal(at: _now());
        if (!_isDisposed) {
          _syncCachedView();
          _notifySafely();
        }
        return result.provenance;
      } on MeshIdentityException {
        try {
          await _persistSnapshotInternal(at: _now());
        } catch (_) {
          // Best-effort revocation persistence before rethrowing original error.
        }
        if (!_isDisposed) {
          _syncCachedView();
          _notifySafely();
        }
        rethrow;
      } catch (_) {
        if (seedSaved) {
          try {
            await _keyring.removeSeed(expectedPublicKey);
          } catch (_) {
            // Best-effort cleanup; durable envelope excludes uncommitted key.
          }
        }
        await _rollbackInstallation(prevSnapshotBytes, prevKeys);
        rethrow;
      } finally {
        result?.seed.fillRange(0, result.seed.length, 0);
      }
    });
  }

  /// Store peer OpenPGP revocation certificates and persist atomically.
  ///
  /// Rejects with [CeremonyActiveException] if an encounter ceremony is active.
  Future<void> rememberOpenPgpRevocations(Uint8List revocationBytes) {
    return _serialized(() async {
      _requireInstallation();
      _ensureNoActiveEncounter();
      await _transactionalMutate(
        (inst) => inst.rememberOpenPgpRevocations(revocationBytes),
      );
    });
  }

  @override
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;
    _hasPendingChanges = false;
    _disposeInstallationAndCeremony();
    _encounter.resetState();
    _clearCachedView();
    super.dispose();
  }
}

class _IdentityEncounterHost implements EncounterHost {
  final IdentityController _controller;

  _IdentityEncounterHost(this._controller);

  @override
  Future<T> runSerialized<T>(Future<T> Function() action) =>
      _controller._serialized(action);

  @override
  DateTime now() => _controller._now();

  @override
  MeshInstallation? get installation => _controller._installation;

  @override
  MeshInstallation requireInstallation() => _controller._requireInstallation();

  @override
  bool get isReady => _controller.isReady;

  @override
  bool get isDisposed => _controller._isDisposed;

  @override
  Future<void> persistSnapshot(DateTime at) =>
      _controller._persistSnapshotInternal(at: at);

  @override
  Uint8List captureRollbackSnapshot(DateTime at) =>
      _controller._requireGroupHandle().save(at: at).blob;

  @override
  Future<void> rollbackInstallation(
    Uint8List prevSnapshotBytes,
    List<Uint8List> prevKeys,
  ) => _controller._rollbackInstallation(prevSnapshotBytes, prevKeys);

  @override
  void markPendingChanges() => _controller._hasPendingChanges = true;

  @override
  void clearPendingChanges() => _controller._hasPendingChanges = false;

  @override
  void syncCachedView() => _controller._syncCachedView();

  @override
  void notifyHost() => _controller._notifySafely();
}
