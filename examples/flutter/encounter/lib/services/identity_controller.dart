import 'package:flutter/foundation.dart';
import 'package:mesh_identity/mesh_identity.dart';

import 'keyring_service.dart';
import 'snapshot_storage.dart';

/// Lifecycle status of the node's local identity engine.
enum IdentityStatus {
  /// Engine has not attempted initialization.
  uninitialized,

  /// Initializing or restoring identity from durable storage.
  initializing,

  /// Identity engine is initialized, restored, and ready for operations.
  ready,

  /// Storage or snapshot is corrupted; requires explicit user recovery.
  corrupted,
}

/// App-level controller managing the single-isolate [MeshInstallation] lifecycle,
/// persona seed storage, and atomic snapshot writes.
class IdentityController extends ChangeNotifier {
  final SecureKeyringService _keyring;
  final SnapshotStorageService _storage;

  MeshInstallation? _installation;
  IdentityStatus _status = IdentityStatus.uninitialized;
  String? _errorMessage;

  IdentityController({
    SecureKeyringService? keyring,
    SnapshotStorageService? storage,
  }) : _keyring = keyring ?? FlutterSecureKeyringService(),
       _storage = storage ?? FileSnapshotStorageService();

  IdentityStatus get status => _status;
  bool get isReady => _status == IdentityStatus.ready && _installation != null;
  String? get errorMessage => _errorMessage;

  /// The live [MeshInstallation] instance. Throws if not in [IdentityStatus.ready] state.
  MeshInstallation get installation {
    final inst = _installation;
    if (inst == null || _status != IdentityStatus.ready) {
      throw StateError('IdentityController is not ready (status: $_status)');
    }
    return inst;
  }

  /// The 32-byte Ed25519 public key of the currently selected local persona.
  Uint8List? get selectedIdentity {
    if (!isReady) return null;
    return _installation!.selectedIdentity;
  }

  /// All 32-byte public keys registered on this installation.
  List<Uint8List> get identities {
    if (!isReady) return const [];
    return _installation!.identities;
  }

  /// Number of contacts in the currently selected persona's address book.
  int get contactsCount {
    if (!isReady) return 0;
    return _installation!.contactsCount();
  }

  /// Initialize the controller: restores from durable snapshot or generates a fresh node.
  Future<void> initialize() async {
    _status = IdentityStatus.initializing;
    _errorMessage = null;
    notifyListeners();

    try {
      final hasSnapshot = await _storage.hasSnapshot();
      final seeds = await _keyring.getAllSeeds();

      if (hasSnapshot && seeds.isNotEmpty) {
        // Restore from existing durable snapshot
        final snapshotBytes = await _storage.loadSnapshot();
        if (snapshotBytes == null) {
          throw const FormatException('Snapshot file missing or unreadable');
        }

        try {
          _installation = MeshInstallation.restore(
            snapshotBytes: snapshotBytes,
            signingKeySeeds: seeds,
          );
        } on Exception catch (e) {
          _status = IdentityStatus.corrupted;
          _errorMessage = 'Snapshot restoration failed: $e';
          notifyListeners();
          return;
        }
      } else {
        // First launch: generate initial persona seed and create node
        final initialSeed = MeshInstallation.generateSeed();
        try {
          final inst = MeshInstallation(seed: initialSeed);
          final primaryKey = inst.selectedIdentity;

          await _keyring.saveSeed(primaryKey, initialSeed);
          final initialSnapshot = inst.save();
          await _storage.saveSnapshot(initialSnapshot);

          _installation = inst;
        } finally {
          initialSeed.fillRange(0, 32, 0);
        }
      }

      _status = IdentityStatus.ready;
      notifyListeners();
    } catch (e) {
      _status = IdentityStatus.corrupted;
      _errorMessage = 'Failed to initialize identity: $e';
      notifyListeners();
    }
  }

  /// Persist the latest snapshot atomically.
  Future<void> _persistSnapshot() async {
    final inst = _installation;
    if (inst == null) return;
    final snapshotBytes = inst.save();
    await _storage.saveSnapshot(snapshotBytes);
  }

  /// Add a new persona with a freshly generated 32-byte Ed25519 signing seed.
  Future<Uint8List> addPersona() async {
    final inst = installation;
    final newSeed = MeshInstallation.generateSeed();

    try {
      final newKey = inst.addIdentity(newSeed);
      await _keyring.saveSeed(newKey, newSeed);
      await _persistSnapshot();
      notifyListeners();
      return newKey;
    } finally {
      newSeed.fillRange(0, 32, 0);
    }
  }

  /// Select active persona by [identityKey].
  Future<void> selectPersona(Uint8List identityKey) async {
    final inst = installation;
    inst.selectIdentity(identityKey);
    await _persistSnapshot();
    notifyListeners();
  }

  /// Remove persona identified by [identityKey] and clear its retained seed.
  Future<void> removePersona(Uint8List identityKey) async {
    final inst = installation;
    inst.removeIdentity(identityKey);
    await _keyring.removeSeed(identityKey);
    await _persistSnapshot();
    notifyListeners();
  }

  /// Block an unverified or verified peer public key.
  Future<void> blockContact(Uint8List peerPublicKey) async {
    final inst = installation;
    inst.blockContact(peerPublicKey);
    await _persistSnapshot();
    notifyListeners();
  }

  /// Explicitly reset a corrupted installation, clearing corrupt data so the user can restart.
  Future<void> resetCorruptedState() async {
    _installation?.dispose();
    _installation = null;
    await _storage.deleteSnapshot();
    await _keyring.clear();
    await initialize();
  }

  /// Manually trigger snapshot persistence (e.g. after backgrounding).
  Future<void> persist() async {
    await _persistSnapshot();
  }

  bool _isDisposed = false;
  bool get isDisposed => _isDisposed;

  @override
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;
    _installation?.dispose();
    _installation = null;
    super.dispose();
  }
}
