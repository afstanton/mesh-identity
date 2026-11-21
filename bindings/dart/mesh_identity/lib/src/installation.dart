import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'exceptions.dart';
import 'mesh_identity_bindings.dart';
import 'models.dart';

/// The root controller for a local node's identities and contact relationships.
class MeshInstallation implements ffi.Finalizable {
  /// Create a new installation.
  ///
  /// If [seed] is provided, it must be exactly 32 bytes (Ed25519 signing seed).
  /// If [seed] is null, a cryptographically secure random key is generated.
  factory MeshInstallation({Uint8List? seed}) => _create(seed);

  /// Named constructor to create a new installation.
  static MeshInstallation create({Uint8List? seed}) => _create(seed);

  static MeshInstallation _create(Uint8List? seed) {
    if (seed != null && seed.length != 32) {
      throw const InvalidArgumentsException('Seed must be exactly 32 bytes');
    }

    return using((Arena arena) {
      final outHandle = arena<ffi.Pointer<ffi.Void>>();
      ffi.Pointer<ffi.Uint8> seedPtr = ffi.nullptr;
      var seedLen = 0;

      if (seed != null) {
        seedLen = 32;
        seedPtr = arena<ffi.Uint8>(32);
        final list = seedPtr.asTypedList(32);
        list.setAll(0, seed);
      }

      final res = mesh_installation_create(seedPtr, seedLen, outHandle);

      // Securely zero out native memory for seed
      if (seedPtr != ffi.nullptr) {
        seedPtr.asTypedList(32).fillRange(0, 32, 0);
      }

      MeshIdentityBindings.checkResult(res, 'Failed to create installation');
      final handle = outHandle.value;
      if (handle == ffi.nullptr) {
        throw const GenericMeshIdentityException(
          'Failed to allocate installation handle',
        );
      }

      return MeshInstallation._(handle);
    });
  }

  /// Internal constructor for already allocated native handle.
  MeshInstallation._(ffi.Pointer<ffi.Void> handle) : _handle = handle {
    _finalizer.attach(this, handle, detach: this);
  }

  static final ffi.NativeFinalizer _finalizer = ffi.NativeFinalizer(
    ffi.Native.addressOf(mesh_installation_free),
  );

  ffi.Pointer<ffi.Void> _handle;

  /// Whether this installation has been explicitly closed.
  bool get isDisposed => _handle == ffi.nullptr;

  void _checkDisposed() {
    if (isDisposed) {
      throw const DisposedException(
        'MeshInstallation has already been disposed and cannot be used.',
      );
    }
  }

  /// Explicitly release native resources held by this installation.
  void dispose() {
    if (!isDisposed) {
      _finalizer.detach(this);
      mesh_installation_free(_handle);
      _handle = ffi.nullptr;
    }
  }

  /// The 32-byte Ed25519 public key of the currently selected identity.
  Uint8List get selectedIdentity {
    _checkDisposed();
    return using((Arena arena) {
      final outPk = arena<ffi.Uint8>(32);
      final res = mesh_installation_selected(_handle, outPk, 32);
      MeshIdentityBindings.checkResult(
        res,
        'Failed to get selected identity public key',
      );
      return Uint8List.fromList(outPk.asTypedList(32));
    });
  }

  /// The list of 32-byte public keys of all identities registered in this installation.
  List<Uint8List> get identities {
    _checkDisposed();
    final count = mesh_installation_identities_count(_handle);
    return using((Arena arena) {
      final outPk = arena<ffi.Uint8>(32);
      final list = <Uint8List>[];
      for (var i = 0; i < count; i++) {
        final res = mesh_installation_identities_get(_handle, i, outPk, 32);
        MeshIdentityBindings.checkResult(
          res,
          'Failed to retrieve identity at index $i',
        );
        list.add(Uint8List.fromList(outPk.asTypedList(32)));
      }
      return List<Uint8List>.unmodifiable(list);
    });
  }

  /// Switch the active identity to [identityKey].
  ///
  /// [at] specifies the checkpoint timestamp (defaults to current time).
  void selectIdentity(Uint8List identityKey, {DateTime? at}) {
    _checkDisposed();
    if (identityKey.length != 32) {
      throw const InvalidArgumentsException(
        'Identity key must be exactly 32 bytes',
      );
    }

    final timestampSec = (at ?? DateTime.now()).millisecondsSinceEpoch ~/ 1000;
    if (timestampSec < 0) {
      throw const InvalidArgumentsException('Timestamp must not be pre-1970');
    }

    using((Arena arena) {
      final keyPtr = arena<ffi.Uint8>(32);
      keyPtr.asTypedList(32).setAll(0, identityKey);
      final res = mesh_installation_select_identity(
        _handle,
        keyPtr,
        32,
        timestampSec,
      );
      MeshIdentityBindings.checkResult(
        res,
        'Failed to select identity: $identityKey',
      );
    });
  }

  /// Add a new identity persona from a 32-byte [seed].
  ///
  /// Returns the newly added identity's 32-byte public key.
  Uint8List addIdentity(Uint8List seed) {
    _checkDisposed();
    if (seed.length != 32) {
      throw const InvalidArgumentsException('Seed must be exactly 32 bytes');
    }

    return using((Arena arena) {
      final seedPtr = arena<ffi.Uint8>(32);
      seedPtr.asTypedList(32).setAll(0, seed);
      final outPk = arena<ffi.Uint8>(32);

      final res = mesh_installation_add_identity(
        _handle,
        seedPtr,
        32,
        outPk,
        32,
      );

      // Zero out native memory for seed
      seedPtr.asTypedList(32).fillRange(0, 32, 0);

      MeshIdentityBindings.checkResult(res, 'Failed to add identity');
      return Uint8List.fromList(outPk.asTypedList(32));
    });
  }

  /// Remove an inactive persona identity by its 32-byte [identityKey].
  void removeIdentity(Uint8List identityKey) {
    _checkDisposed();
    if (identityKey.length != 32) {
      throw const InvalidArgumentsException(
        'Identity key must be exactly 32 bytes',
      );
    }

    using((Arena arena) {
      final keyPtr = arena<ffi.Uint8>(32);
      keyPtr.asTypedList(32).setAll(0, identityKey);
      final res = mesh_installation_remove_identity(_handle, keyPtr, 32);
      MeshIdentityBindings.checkResult(
        res,
        'Failed to remove identity: $identityKey',
      );
    });
  }

  /// Serialize this installation to an authenticated snapshot blob.
  ///
  /// [at] specifies the snapshot timestamp (defaults to current time).
  Uint8List save({DateTime? at}) {
    _checkDisposed();
    final timestampSec = (at ?? DateTime.now()).millisecondsSinceEpoch ~/ 1000;
    if (timestampSec < 0) {
      throw const InvalidArgumentsException('Timestamp must not be pre-1970');
    }

    return using((Arena arena) {
      final outBuf = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();

      final res = mesh_installation_save(_handle, timestampSec, outBuf, outLen);
      MeshIdentityBindings.checkResult(
        res,
        'Failed to save installation snapshot',
      );

      final ptr = outBuf.value;
      final len = outLen.value;
      try {
        return Uint8List.fromList(ptr.asTypedList(len));
      } finally {
        mesh_buffer_free(ptr, len);
      }
    });
  }

  /// Restore an installation from snapshot bytes and known signing seeds.
  ///
  /// Every identity present in the snapshot must have its 32-byte private
  /// signing seed supplied in [signingKeySeeds].
  static MeshInstallation restore({
    required Uint8List snapshotBytes,
    required List<Uint8List> signingKeySeeds,
  }) {
    if (snapshotBytes.isEmpty) {
      throw const InvalidSnapshotException('Snapshot bytes cannot be empty');
    }
    if (signingKeySeeds.isEmpty) {
      throw const InvalidArgumentsException('Signing seeds cannot be empty');
    }
    for (var i = 0; i < signingKeySeeds.length; i++) {
      if (signingKeySeeds[i].length != 32) {
        throw InvalidArgumentsException(
          'Signing seed at index $i must be exactly 32 bytes',
        );
      }
    }

    return using((Arena arena) {
      final bytesPtr = arena<ffi.Uint8>(snapshotBytes.length);
      bytesPtr.asTypedList(snapshotBytes.length).setAll(0, snapshotBytes);

      final totalSeedBytes = signingKeySeeds.length * 32;
      final seedsPtr = arena<ffi.Uint8>(totalSeedBytes);
      final seedsList = seedsPtr.asTypedList(totalSeedBytes);
      for (var i = 0; i < signingKeySeeds.length; i++) {
        seedsList.setAll(i * 32, signingKeySeeds[i]);
      }

      final outHandle = arena<ffi.Pointer<ffi.Void>>();
      final res = mesh_installation_restore(
        bytesPtr,
        snapshotBytes.length,
        seedsPtr,
        signingKeySeeds.length,
        outHandle,
      );

      // Zero out native memory for seeds
      seedsList.fillRange(0, totalSeedBytes, 0);

      MeshIdentityBindings.checkResult(
        res,
        'Failed to restore installation from snapshot',
      );

      final handle = outHandle.value;
      if (handle == ffi.nullptr) {
        throw const InvalidSnapshotException(
          'Failed to restore installation: null handle returned',
        );
      }

      return MeshInstallation._(handle);
    });
  }

  /// Total number of contacts stored for [identityKey] (or selected identity if null).
  int contactsCount({Uint8List? identityKey}) {
    _checkDisposed();
    if (identityKey != null && identityKey.length != 32) {
      throw const InvalidArgumentsException(
        'Identity key must be exactly 32 bytes',
      );
    }

    return using((Arena arena) {
      ffi.Pointer<ffi.Uint8> idPtr = ffi.nullptr;
      var idLen = 0;
      if (identityKey != null) {
        idLen = 32;
        idPtr = arena<ffi.Uint8>(32);
        idPtr.asTypedList(32).setAll(0, identityKey);
      }
      return mesh_installation_contacts_count(_handle, idPtr, idLen);
    });
  }

  /// Look up a contact record by [peerPublicKey] in the store of [identityKey]
  /// (or selected identity if null).
  ///
  /// Returns null if the contact is not found.
  Contact? getContact(Uint8List peerPublicKey, {Uint8List? identityKey}) {
    _checkDisposed();
    if (peerPublicKey.length != 32) {
      throw const InvalidArgumentsException(
        'Peer public key must be exactly 32 bytes',
      );
    }
    if (identityKey != null && identityKey.length != 32) {
      throw const InvalidArgumentsException(
        'Identity key must be exactly 32 bytes',
      );
    }

    return using((Arena arena) {
      ffi.Pointer<ffi.Uint8> idPtr = ffi.nullptr;
      var idLen = 0;
      if (identityKey != null) {
        idLen = 32;
        idPtr = arena<ffi.Uint8>(32);
        idPtr.asTypedList(32).setAll(0, identityKey);
      }

      final peerPtr = arena<ffi.Uint8>(32);
      peerPtr.asTypedList(32).setAll(0, peerPublicKey);

      final outJson = arena<ffi.Pointer<ffi.Char>>();
      final res = mesh_installation_get_contact(
        _handle,
        idPtr,
        idLen,
        peerPtr,
        32,
        outJson,
      );

      if (res == MeshIdentityBindings.meshErrNotFound) {
        return null;
      }
      MeshIdentityBindings.checkResult(res, 'Failed to get contact');

      final jsonPtr = outJson.value;
      if (jsonPtr == ffi.nullptr) return null;

      try {
        final jsonStr = jsonPtr.cast<Utf8>().toDartString();
        final map = jsonDecode(jsonStr) as Map<String, dynamic>;
        return Contact.fromJson(map);
      } finally {
        mesh_string_free(jsonPtr);
      }
    });
  }

  /// Mark [peerPublicKey] as administratively blocked.
  void blockContact(Uint8List peerPublicKey, {Uint8List? identityKey}) {
    _checkDisposed();
    if (peerPublicKey.length != 32) {
      throw const InvalidArgumentsException(
        'Peer public key must be exactly 32 bytes',
      );
    }
    if (identityKey != null && identityKey.length != 32) {
      throw const InvalidArgumentsException(
        'Identity key must be exactly 32 bytes',
      );
    }

    using((Arena arena) {
      ffi.Pointer<ffi.Uint8> idPtr = ffi.nullptr;
      var idLen = 0;
      if (identityKey != null) {
        idLen = 32;
        idPtr = arena<ffi.Uint8>(32);
        idPtr.asTypedList(32).setAll(0, identityKey);
      }

      final peerPtr = arena<ffi.Uint8>(32);
      peerPtr.asTypedList(32).setAll(0, peerPublicKey);

      final res = mesh_installation_block_contact(
        _handle,
        idPtr,
        idLen,
        peerPtr,
        32,
      );
      MeshIdentityBindings.checkResult(res, 'Failed to block contact');
    });
  }

  /// Import an unverified peer public key into the relationship context of [localIdentityKey]
  /// (or selected identity if null).
  void importPeerKey(Uint8List peerPublicKey, {Uint8List? localIdentityKey}) {
    _checkDisposed();
    if (peerPublicKey.length != 32) {
      throw const InvalidArgumentsException(
        'Peer public key must be exactly 32 bytes',
      );
    }
    if (localIdentityKey != null && localIdentityKey.length != 32) {
      throw const InvalidArgumentsException(
        'Local identity key must be exactly 32 bytes',
      );
    }

    using((Arena arena) {
      ffi.Pointer<ffi.Uint8> localPtr = ffi.nullptr;
      var localLen = 0;
      if (localIdentityKey != null) {
        localLen = 32;
        localPtr = arena<ffi.Uint8>(32);
        localPtr.asTypedList(32).setAll(0, localIdentityKey);
      }

      final peerPtr = arena<ffi.Uint8>(32);
      peerPtr.asTypedList(32).setAll(0, peerPublicKey);

      final res = mesh_installation_import_peer_key(
        _handle,
        localPtr,
        localLen,
        peerPtr,
        32,
      );
      MeshIdentityBindings.checkResult(res, 'Failed to import peer key');
    });
  }
}
