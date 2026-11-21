import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:math';
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'exceptions.dart';
import 'mesh_identity_bindings.dart';
import 'models.dart';

part 'ceremony.dart';

/// The root controller for a local node's identities and contact relationships.
///
/// **Concurrency Note**: Instances wrap raw native pointers without internal locking.
/// An instance must not be accessed concurrently across multiple Dart isolates.
class MeshInstallation implements ffi.Finalizable {
  /// Maximum number of signing key seeds allowed during restoration.
  static const int maxRestoreSeeds = 2048;

  /// Generate a cryptographically secure 32-byte Ed25519 signing seed.
  ///
  /// Callers should retain this seed in secure storage (e.g. keychain / secure enclave)
  /// so it can be supplied to [MeshInstallation.restore] upon app restart.
  static Uint8List generateSeed() {
    final random = Random.secure();
    final bytes = Uint8List(32);
    for (var i = 0; i < 32; i++) {
      bytes[i] = random.nextInt(256);
    }
    return bytes;
  }

  /// Create a new installation with an initial root persona.
  ///
  /// [seed] must be exactly 32 bytes (Ed25519 signing seed). Use [generateSeed]
  /// to create a fresh secure random seed if needed. The caller is responsible for
  /// retaining this seed to restore the installation later via [restore].
  factory MeshInstallation({required Uint8List seed}) {
    if (seed.length != 32) {
      throw const InvalidArgumentsException('Seed must be exactly 32 bytes');
    }

    return using((Arena arena) {
      final outHandle = arena<ffi.Pointer<ffi.Void>>();
      final seedPtr = arena<ffi.Uint8>(32);
      final list = seedPtr.asTypedList(32);
      list.setAll(0, seed);

      final res = mesh_installation_create(seedPtr, 32, outHandle);

      // Securely zero out native memory for seed
      seedPtr.asTypedList(32).fillRange(0, 32, 0);

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
  bool _isPoisoned = false;
  HandoffResult? _pendingHandoff;
  AcceptHandoffResult? _pendingAccept;

  /// Returns the pending [HandoffResult] if a prior [beginHandoff] produced a bundle
  /// whose persistence failed or was not yet finalized.
  HandoffResult? get pendingHandoff => _pendingHandoff;

  /// Returns the pending [AcceptHandoffResult] if a prior [acceptHandoff] produced a result
  /// whose persistence failed or was not yet finalized.
  AcceptHandoffResult? get pendingAccept => _pendingAccept;

  /// Whether this installation has been explicitly closed.
  bool get isDisposed => _handle == ffi.nullptr;

  void _checkDisposed() {
    if (isDisposed) {
      throw const DisposedException(
        'MeshInstallation has already been disposed and cannot be used.',
      );
    }
    if (_isPoisoned) {
      throw const NativePanicException(
        'MeshInstallation is poisoned due to a prior native panic and cannot be used.',
      );
    }
  }

  void _checkResult(int code, [String? fallbackMessage]) {
    try {
      MeshIdentityBindings.checkResult(code, fallbackMessage);
    } on NativePanicException {
      _isPoisoned = true;
      rethrow;
    }
  }

  /// Native handle used when transferring ownership to [MeshGroupHandle].
  ffi.Pointer<ffi.Void> get handleForTransfer {
    _checkDisposed();
    return _handle;
  }

  /// Finalize transferring native handle ownership away from this installation.
  ///
  /// Call only after the recipient has successfully taken ownership of the handle.
  void finalizeTransfer() {
    _finalizer.detach(this);
    _handle = ffi.nullptr;
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
      _checkResult(res, 'Failed to get selected identity public key');
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
        _checkResult(res, 'Failed to retrieve identity at index $i');
        list.add(Uint8List.fromList(outPk.asTypedList(32)));
      }
      return List<Uint8List>.unmodifiable(list);
    });
  }

  /// Switch the active identity to [identityKey].
  ///
  /// [at] specifies the session timestamp in milliseconds (defaults to current time).
  void selectIdentity(Uint8List identityKey, {DateTime? at}) {
    _checkDisposed();
    if (identityKey.length != 32) {
      throw const InvalidArgumentsException(
        'Identity key must be exactly 32 bytes',
      );
    }

    final nowMs = (at ?? DateTime.now()).millisecondsSinceEpoch;
    if (nowMs < 0) {
      throw const InvalidArgumentsException('Timestamp must not be pre-1970');
    }

    using((Arena arena) {
      final keyPtr = arena<ffi.Uint8>(32);
      keyPtr.asTypedList(32).setAll(0, identityKey);
      final res = mesh_installation_select_identity(_handle, keyPtr, 32, nowMs);
      _checkResult(res, 'Failed to select identity: $identityKey');
    });
  }

  /// Configure the maximum number of identities allowed in this installation (up to 2048).
  void setMaxIdentities(int limit) {
    _checkDisposed();
    if (limit < 1 || limit > maxRestoreSeeds) {
      throw const InvalidArgumentsException(
        'maxIdentities must be between 1 and 2048',
      );
    }
    final res = mesh_installation_set_max_identities(_handle, limit);
    _checkResult(res, 'Failed to set max identities');
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

      _checkResult(res, 'Failed to add identity');
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
      _checkResult(res, 'Failed to remove identity: $identityKey');
    });
  }

  /// Serialize this installation to an authenticated snapshot blob.
  ///
  /// [at] specifies the session timestamp in milliseconds (defaults to current time).
  Uint8List save({DateTime? at}) {
    _checkDisposed();
    final nowMs = (at ?? DateTime.now()).millisecondsSinceEpoch;
    if (nowMs < 0) {
      throw const InvalidArgumentsException('Timestamp must not be pre-1970');
    }

    return using((Arena arena) {
      final outBuf = arena<ffi.Pointer<ffi.Uint8>>();
      final outLen = arena<ffi.Size>();

      final res = mesh_installation_save(_handle, nowMs, outBuf, outLen);
      _checkResult(res, 'Failed to save installation snapshot');

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
    if (snapshotBytes.length > 64 * 1024 * 1024) {
      throw const CapacityExceededException(
        'Snapshot bytes exceed 64 MiB ceiling',
      );
    }
    if (signingKeySeeds.isEmpty) {
      throw const InvalidArgumentsException('Signing seeds cannot be empty');
    }
    if (signingKeySeeds.length > maxRestoreSeeds) {
      throw const CapacityExceededException(
        'Signing seeds count exceeds maximum ceiling of 2048',
      );
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
      _checkResult(res, 'Failed to get contact');

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
      _checkResult(res, 'Failed to block contact');
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
      _checkResult(res, 'Failed to import peer key');
    });
  }

  /// Start an in-person Encounter ceremony as initiator.
  ///
  /// Returns an [EncounterStartResult] containing the active [EncounterCeremony]
  /// and the initial offer payload to transmit to the peer (e.g. via QR or BLE).
  EncounterStartResult startEncounter({DateTime? at}) {
    _checkDisposed();
    final nowMs = (at ?? DateTime.now()).millisecondsSinceEpoch;
    if (nowMs < 0) {
      throw const InvalidArgumentsException('Timestamp must not be pre-1970');
    }

    return using((Arena arena) {
      final outCeremony = arena<ffi.Pointer<ffi.Void>>();
      final outPayload = arena<ffi.Pointer<ffi.Uint8>>();
      final outPayloadLen = arena<ffi.Size>();

      final res = mesh_installation_start(
        _handle,
        nowMs,
        outCeremony,
        outPayload,
        outPayloadLen,
      );
      _checkResult(res, 'Failed to start encounter ceremony');

      final ptr = outPayload.value;
      final len = outPayloadLen.value;
      final payload = Uint8List.fromList(ptr.asTypedList(len));
      mesh_buffer_free(ptr, len);

      return EncounterStartResult(
        ceremony: EncounterCeremony._fromHandle(outCeremony.value, this),
        offerPayload: payload,
      );
    });
  }

  /// Open an in-person Encounter ceremony as responder (scanner).
  ///
  /// Returns an active [EncounterCeremony] awaiting an initiator's offer payload.
  EncounterCeremony openScanner({DateTime? at}) {
    _checkDisposed();
    final nowMs = (at ?? DateTime.now()).millisecondsSinceEpoch;
    if (nowMs < 0) {
      throw const InvalidArgumentsException('Timestamp must not be pre-1970');
    }

    return using((Arena arena) {
      final outCeremony = arena<ffi.Pointer<ffi.Void>>();
      final res = mesh_installation_open_scanner(_handle, nowMs, outCeremony);
      _checkResult(res, 'Failed to open encounter scanner');
      return EncounterCeremony._fromHandle(outCeremony.value, this);
    });
  }

  /// Responder scans the initiator's offer payload and produces a response payload.
  Uint8List scanOffer(
    EncounterCeremony ceremony,
    Uint8List offerBytes, {
    DateTime? at,
  }) {
    _checkDisposed();
    if (offerBytes.isEmpty) {
      throw const InvalidArgumentsException('Offer payload cannot be empty');
    }
    if (offerBytes.length > 512) {
      throw const InvalidArgumentsException(
        'Offer payload exceeds maximum frame size (512 bytes)',
      );
    }
    final nowMs = (at ?? DateTime.now()).millisecondsSinceEpoch;
    if (nowMs < 0) {
      throw const InvalidArgumentsException('Timestamp must not be pre-1970');
    }

    return using((Arena arena) {
      final bytesPtr = arena<ffi.Uint8>(offerBytes.length);
      bytesPtr.asTypedList(offerBytes.length).setAll(0, offerBytes);
      final outPayload = arena<ffi.Pointer<ffi.Uint8>>();
      final outPayloadLen = arena<ffi.Size>();

      final res = mesh_installation_scan_offer(
        _handle,
        ceremony.handle,
        bytesPtr,
        offerBytes.length,
        nowMs,
        outPayload,
        outPayloadLen,
      );
      _checkResult(res, 'Failed to scan encounter offer');

      final ptr = outPayload.value;
      final len = outPayloadLen.value;
      final payload = Uint8List.fromList(ptr.asTypedList(len));
      mesh_buffer_free(ptr, len);

      return payload;
    });
  }

  /// Initiator scans the responder's response payload and produces a reveal payload.
  Uint8List scanResponse(
    EncounterCeremony ceremony,
    Uint8List responseBytes, {
    DateTime? at,
  }) {
    _checkDisposed();
    if (responseBytes.isEmpty) {
      throw const InvalidArgumentsException('Response payload cannot be empty');
    }
    if (responseBytes.length > 512) {
      throw const InvalidArgumentsException(
        'Response payload exceeds maximum frame size (512 bytes)',
      );
    }
    final nowMs = (at ?? DateTime.now()).millisecondsSinceEpoch;
    if (nowMs < 0) {
      throw const InvalidArgumentsException('Timestamp must not be pre-1970');
    }

    return using((Arena arena) {
      final bytesPtr = arena<ffi.Uint8>(responseBytes.length);
      bytesPtr.asTypedList(responseBytes.length).setAll(0, responseBytes);
      final outPayload = arena<ffi.Pointer<ffi.Uint8>>();
      final outPayloadLen = arena<ffi.Size>();

      final res = mesh_installation_scan_response(
        _handle,
        ceremony.handle,
        bytesPtr,
        responseBytes.length,
        nowMs,
        outPayload,
        outPayloadLen,
      );
      _checkResult(res, 'Failed to scan encounter response');

      final ptr = outPayload.value;
      final len = outPayloadLen.value;
      final payload = Uint8List.fromList(ptr.asTypedList(len));
      mesh_buffer_free(ptr, len);

      return payload;
    });
  }

  /// Responder scans the initiator's reveal payload to complete cryptographic exchange.
  void scanReveal(
    EncounterCeremony ceremony,
    Uint8List revealBytes, {
    DateTime? at,
  }) {
    _checkDisposed();
    if (revealBytes.isEmpty) {
      throw const InvalidArgumentsException('Reveal payload cannot be empty');
    }
    if (revealBytes.length > 512) {
      throw const InvalidArgumentsException(
        'Reveal payload exceeds maximum frame size (512 bytes)',
      );
    }
    final nowMs = (at ?? DateTime.now()).millisecondsSinceEpoch;
    if (nowMs < 0) {
      throw const InvalidArgumentsException('Timestamp must not be pre-1970');
    }

    using((Arena arena) {
      final bytesPtr = arena<ffi.Uint8>(revealBytes.length);
      bytesPtr.asTypedList(revealBytes.length).setAll(0, revealBytes);

      final res = mesh_installation_scan_reveal(
        _handle,
        ceremony.handle,
        bytesPtr,
        revealBytes.length,
        nowMs,
      );
      _checkResult(res, 'Failed to scan encounter reveal');
    });
  }

  /// Query the Short Authentication String (SAS) comparison code for an active ceremony.
  ///
  /// Returns null if comparison is not yet ready.
  EncounterComparison? getComparison(
    EncounterCeremony ceremony, {
    DateTime? at,
  }) {
    _checkDisposed();
    final nowMs = (at ?? DateTime.now()).millisecondsSinceEpoch;
    if (nowMs < 0) {
      throw const InvalidArgumentsException('Timestamp must not be pre-1970');
    }

    return using((Arena arena) {
      final outCode = arena<ffi.Uint32>();
      final res = mesh_installation_comparison(
        _handle,
        ceremony.handle,
        nowMs,
        outCode,
      );
      if (res == MeshIdentityBindings.meshErrNoComparison ||
          res == MeshIdentityBindings.meshErrNotFound) {
        return null;
      }
      _checkResult(res, 'Failed to query encounter comparison');
      return EncounterComparison(outCode.value);
    });
  }

  /// Confirm matching peer SAS code and persist the cryptographically verified contact.
  ///
  /// [peerCode] must be entered by the human user from reading the 6-digit code
  /// displayed on the peer's physical device screen.
  ///
  /// Returns the newly verified [Contact] record.
  Contact confirmAndSave(
    EncounterCeremony ceremony,
    int peerCode, {
    DateTime? at,
  }) {
    _checkDisposed();
    if (peerCode < 0 || peerCode >= 1000000) {
      throw const InvalidArgumentsException('Peer SAS code must be 0..999999');
    }
    final atTime = at ?? DateTime.now();
    final nowMs = atTime.millisecondsSinceEpoch;
    final timestampSec = nowMs ~/ 1000;
    if (nowMs < 0) {
      throw const InvalidArgumentsException('Timestamp must not be pre-1970');
    }

    return using((Arena arena) {
      final outJson = arena<ffi.Pointer<ffi.Char>>();
      final res = mesh_installation_confirm_and_save(
        _handle,
        ceremony.handle,
        peerCode,
        nowMs,
        timestampSec,
        outJson,
      );
      _checkResult(res, 'Failed to confirm and save encounter');

      final jsonPtr = outJson.value;
      try {
        final jsonStr = jsonPtr.cast<Utf8>().toDartString();
        final map = jsonDecode(jsonStr) as Map<String, dynamic>;
        return Contact.fromJson(map);
      } finally {
        mesh_string_free(jsonPtr);
      }
    });
  }

  /// Cancel an active encounter ceremony.
  ///
  /// Cancels the ceremony on the installation and releases native resources held by [ceremony].
  void cancelCeremony(EncounterCeremony ceremony, {DateTime? at}) {
    _checkDisposed();
    final nowMs = (at ?? DateTime.now()).millisecondsSinceEpoch;
    if (nowMs < 0) {
      throw const InvalidArgumentsException('Timestamp must not be pre-1970');
    }

    try {
      final res = mesh_installation_cancel_ceremony(
        _handle,
        ceremony.handle,
        nowMs,
      );
      _checkResult(res, 'Failed to cancel ceremony');
    } finally {
      ceremony.dispose();
    }
  }

  /// Returns the persistent 32-byte device nonce for this installation,
  /// generating one lazily if not already created.
  ///
  /// IMPORTANT: The device nonce is held in volatile memory until saved.
  /// Call [save] after generating a new device nonce before transmitting it to
  /// peers or initiating a handoff.
  Uint8List getDeviceNonce() {
    _checkDisposed();
    return using((Arena arena) {
      final outNonce = arena<ffi.Uint8>(32);
      final res = mesh_installation_device_nonce(_handle, outNonce);
      _checkResult(res, 'Failed to get device nonce');
      return Uint8List.fromList(outNonce.asTypedList(32));
    });
  }

  /// Returns the current 32-byte device nonce if already generated,
  /// or `null` if none has been generated yet.
  Uint8List? getCurrentDeviceNonce() {
    _checkDisposed();
    return using((Arena arena) {
      final outNonce = arena<ffi.Uint8>(32);
      final outHasNonce = arena<ffi.Bool>();
      final res = mesh_installation_current_device_nonce(
        _handle,
        outNonce,
        outHasNonce,
      );
      _checkResult(res, 'Failed to get current device nonce');
      if (!outHasNonce.value) {
        return null;
      }
      return Uint8List.fromList(outNonce.asTypedList(32));
    });
  }

  /// Query the voting state for an identity on this installation.
  ///
  /// If [identityKey] is omitted, queries the currently selected persona.
  VotingState getVotingState({Uint8List? identityKey}) {
    _checkDisposed();
    if (identityKey != null && identityKey.length != 32) {
      throw const InvalidArgumentsException(
        'Identity key must be exactly 32 bytes',
      );
    }
    return using((Arena arena) {
      final ffi.Pointer<ffi.Uint8> keyPtr;
      final int keyLen;
      if (identityKey != null) {
        keyPtr = arena<ffi.Uint8>(32);
        keyPtr.asTypedList(32).setAll(0, identityKey);
        keyLen = 32;
      } else {
        keyPtr = ffi.nullptr;
        keyLen = 0;
      }
      final outState = arena<ffi.Int32>();
      final res = mesh_installation_voting_state(
        _handle,
        keyPtr,
        keyLen,
        outState,
      );
      _checkResult(res, 'Failed to get voting state');
      return _parseVotingState(outState.value);
    });
  }

  /// Query the full voting record (counter, state, holder) for an identity.
  ///
  /// If [identityKey] is omitted, queries the currently selected persona.
  VotingRecord getVotingRecord({Uint8List? identityKey}) {
    _checkDisposed();
    if (identityKey != null && identityKey.length != 32) {
      throw const InvalidArgumentsException(
        'Identity key must be exactly 32 bytes',
      );
    }
    return using((Arena arena) {
      final ffi.Pointer<ffi.Uint8> keyPtr;
      final int keyLen;
      if (identityKey != null) {
        keyPtr = arena<ffi.Uint8>(32);
        keyPtr.asTypedList(32).setAll(0, identityKey);
        keyLen = 32;
      } else {
        keyPtr = ffi.nullptr;
        keyLen = 0;
      }
      final outCounter = arena<ffi.Uint64>();
      final outState = arena<ffi.Int32>();
      final outHolder = arena<ffi.Uint8>(32);
      final outHasHolder = arena<ffi.Bool>();

      final res = mesh_installation_voting_record(
        _handle,
        keyPtr,
        keyLen,
        outCounter,
        outState,
        outHolder,
        outHasHolder,
      );
      _checkResult(res, 'Failed to get voting record');

      final holder =
          outHasHolder.value
              ? Uint8List.fromList(outHolder.asTypedList(32))
              : null;
      final rawCounter = outCounter.value;
      final counter = BigInt.from(rawCounter).toUnsigned(64);

      return VotingRecord(
        counter: counter,
        state: _parseVotingState(outState.value),
        holder: holder,
      );
    });
  }

  /// Explicitly transitions every owned identity on this installation into the
  /// [VotingState.gated] state and clears group permits.
  void gateVoting() {
    _checkDisposed();
    final res = mesh_installation_gate_voting(_handle);
    _checkResult(res, 'Failed to gate voting');
  }

  /// Begin a takeover claim for the selected identity while in the [VotingState.gated] state.
  ///
  /// Produces a signed [TakeoverStatement] with a sequence counter strictly greater than [floor]
  /// and greater than any previously observed counter.
  ///
  /// [floor] can be an [int] or [BigInt] representing an unsigned 64-bit integer (0..2^64-1).
  TakeoverStatement beginTakeover({Object floor = 0}) {
    _checkDisposed();
    final BigInt floorVal;
    if (floor is int) {
      floorVal = BigInt.from(floor);
    } else if (floor is BigInt) {
      floorVal = floor;
    } else {
      throw const InvalidArgumentsException(
        'Floor counter must be an int or BigInt',
      );
    }

    if (floorVal < BigInt.zero ||
        floorVal > BigInt.parse('18446744073709551615')) {
      throw const InvalidArgumentsException(
        'Floor counter must be an unsigned 64-bit integer (0..2^64 - 1)',
      );
    }

    return using((Arena arena) {
      final outJson = arena<ffi.Pointer<ffi.Char>>();
      final floorInt = floorVal.toSigned(64).toInt();
      final res = mesh_installation_begin_takeover(_handle, floorInt, outJson);
      _checkResult(res, 'Failed to begin takeover');

      final jsonPtr = outJson.value;
      try {
        final jsonStr = jsonPtr.cast<Utf8>().toDartString();
        final map = jsonDecode(jsonStr) as Map<String, dynamic>;
        return TakeoverStatement.fromJson(map);
      } finally {
        mesh_string_free(jsonPtr);
      }
    });
  }

  /// Begin a handoff transferring the selected identity's voting role to [recipientNonce].
  ///
  /// On success, this device permanently transitions to [VotingState.stopped] at this counter,
  /// and produces a [HandoffResult] containing the signed [HandoffBundle] and the updated
  /// [HandoffResult.snapshotBytes].
  ///
  /// If [onPersist] is supplied, it is invoked synchronously with the snapshot bytes BEFORE
  /// this method returns. If [onPersist] throws an exception, the handoff bundle is not returned.
  ///
  /// CRITICAL: To prevent double-voting across crashes, [snapshotBytes] must be written to
  /// durable storage before the bundle is transmitted or displayed.
  HandoffResult beginHandoff(
    Uint8List recipientNonce, {
    DateTime? at,
    void Function(Uint8List snapshotBytes)? onPersist,
  }) {
    _checkDisposed();
    if (recipientNonce.length != 32) {
      throw const InvalidArgumentsException(
        'Recipient nonce must be exactly 32 bytes',
      );
    }

    // If a previous handoff for the same recipient is pending (e.g. onPersist threw),
    // retry the persistence step with the preserved bundle rather than failing with NotVotingDeviceException.
    if (_pendingHandoff != null &&
        _bytesEqual(_pendingHandoff!.bundle.recipient, recipientNonce)) {
      if (onPersist != null) {
        onPersist(_pendingHandoff!.snapshotBytes);
      }
      final result = _pendingHandoff!;
      _pendingHandoff = null;
      return result;
    }

    final nowMs = (at ?? DateTime.now()).millisecondsSinceEpoch;
    if (nowMs < 0) {
      throw const InvalidArgumentsException('Timestamp must not be pre-1970');
    }

    return using((Arena arena) {
      final recipientPtr = arena<ffi.Uint8>(32);
      recipientPtr.asTypedList(32).setAll(0, recipientNonce);
      final outBundlePtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outBundleLen = arena<ffi.Size>();
      final outSnapshotPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outSnapshotLen = arena<ffi.Size>();

      final res = mesh_installation_begin_handoff(
        _handle,
        recipientPtr,
        32,
        nowMs,
        outBundlePtr,
        outBundleLen,
        outSnapshotPtr,
        outSnapshotLen,
      );
      _checkResult(res, 'Failed to begin handoff');

      final bundlePtr = outBundlePtr.value;
      final bundleLen = outBundleLen.value;
      final snapshotPtr = outSnapshotPtr.value;
      final snapshotLen = outSnapshotLen.value;

      try {
        final bundleBytes = Uint8List.fromList(
          bundlePtr.asTypedList(bundleLen),
        );
        final snapshotBytes = Uint8List.fromList(
          snapshotPtr.asTypedList(snapshotLen),
        );

        final result = HandoffResult(
          bundle: HandoffBundle.fromBytes(bundleBytes),
          snapshotBytes: snapshotBytes,
        );
        _pendingHandoff = result;

        if (onPersist != null) {
          onPersist(snapshotBytes);
        }

        _pendingHandoff = null;
        return result;
      } finally {
        mesh_buffer_free(bundlePtr, bundleLen);
        mesh_buffer_free(snapshotPtr, snapshotLen);
      }
    });
  }

  /// Accept an authenticated [HandoffBundle] addressed to this device's nonce.
  ///
  /// Transitions this installation to [VotingState.voting] (or [VotingState.gated] if conflict),
  /// and returns an [AcceptHandoffResult] containing the new state and the updated post-handoff
  /// snapshot bytes.
  ///
  /// If [onPersist] is supplied, it is invoked synchronously with the snapshot bytes BEFORE
  /// this method returns.
  AcceptHandoffResult acceptHandoff(
    HandoffBundle bundle, {
    DateTime? at,
    void Function(Uint8List snapshotBytes)? onPersist,
  }) {
    _checkDisposed();
    if (bundle.rawBytes.isEmpty ||
        bundle.rawBytes.length > HandoffBundle.maxBundleBytes) {
      throw const InvalidArgumentsException('Invalid handoff bundle size');
    }

    if (_pendingAccept != null) {
      if (onPersist != null) {
        onPersist(_pendingAccept!.snapshotBytes);
      }
      final result = _pendingAccept!;
      _pendingAccept = null;
      return result;
    }

    final nowMs = (at ?? DateTime.now()).millisecondsSinceEpoch;
    if (nowMs < 0) {
      throw const InvalidArgumentsException('Timestamp must not be pre-1970');
    }

    return using((Arena arena) {
      final bundlePtr = arena<ffi.Uint8>(bundle.rawBytes.length);
      bundlePtr.asTypedList(bundle.rawBytes.length).setAll(0, bundle.rawBytes);
      final outNewState = arena<ffi.Int32>();
      final outSnapshotPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outSnapshotLen = arena<ffi.Size>();

      final res = mesh_installation_accept_handoff(
        _handle,
        bundlePtr,
        bundle.rawBytes.length,
        nowMs,
        outNewState,
        outSnapshotPtr,
        outSnapshotLen,
      );
      _checkResult(res, 'Failed to accept handoff');

      final snapshotPtr = outSnapshotPtr.value;
      final snapshotLen = outSnapshotLen.value;
      try {
        final snapshotBytes = Uint8List.fromList(
          snapshotPtr.asTypedList(snapshotLen),
        );
        final result = AcceptHandoffResult(
          state: _parseVotingState(outNewState.value),
          snapshotBytes: snapshotBytes,
        );
        _pendingAccept = result;

        if (onPersist != null) {
          onPersist(snapshotBytes);
        }

        _pendingAccept = null;
        return result;
      } finally {
        mesh_buffer_free(snapshotPtr, snapshotLen);
      }
    });
  }
}

VotingState _parseVotingState(int code) {
  switch (code) {
    case 0:
      return VotingState.voting;
    case 1:
      return VotingState.stopped;
    case 2:
      return VotingState.gated;
    default:
      throw GenericMeshIdentityException('Unknown voting state code: $code');
  }
}

bool _bytesEqual(Uint8List? a, Uint8List? b) {
  if (identical(a, b)) return true;
  if (a == null || b == null) return false;
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
