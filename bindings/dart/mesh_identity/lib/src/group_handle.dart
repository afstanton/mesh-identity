import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'exceptions.dart';
import 'group_models.dart';
import 'installation.dart';
import 'mesh_identity_bindings.dart';

/// The root controller for Byzantine group admission, governance, and outbox messaging.
///
/// Encapsulates an [Installation] and extends it with multi-party group lifecycle:
/// - Group formation, genesis distribution, and verified invitations
/// - Two-phase commit outbox staging ([save], [confirmSaved], [takeOutgoing])
/// - Byzantine voting and certificate processing ([receiveBytes])
///
/// **Concurrency Note**: Instances wrap raw native pointers without internal locking.
/// An instance must not be accessed concurrently across multiple Dart isolates.
class MeshGroupHandle implements ffi.Finalizable {
  /// The maximum size of an inbound or genesis wire frame (128 KiB).
  static const int maxGroupFrameBytes = 128 * 1024;

  /// The maximum size of a serialized group snapshot blob (256 MiB).
  static const int maxGroupSnapshotBytes = 256 * 1024 * 1024;

  /// Maximum allowed initial members when creating a group (192 members total).
  static const int maxGroupMembers = 192;

  static const int _maxSeedsCeiling = 64;

  /// Create a fresh group handle initialized with a new root installation and persona.
  ///
  /// [seed] must be exactly 32 bytes.
  factory MeshGroupHandle({required Uint8List seed}) {
    if (seed.length != 32) {
      throw const InvalidArgumentsException('Seed must be exactly 32 bytes');
    }

    return using((Arena arena) {
      final outHandle = arena<ffi.Pointer<ffi.Void>>();
      final seedPtr = arena<ffi.Uint8>(32);
      seedPtr.asTypedList(32).setAll(0, seed);

      final res = mesh_group_handle_create(seedPtr, 32, outHandle);
      seedPtr.asTypedList(32).fillRange(0, 32, 0);

      MeshIdentityBindings.checkResult(res, 'Failed to create group handle');
      final handle = outHandle.value;
      if (handle == ffi.nullptr) {
        throw const GenericMeshIdentityException(
          'Failed to allocate group handle',
        );
      }
      return MeshGroupHandle._(handle);
    });
  }

  /// Create a group handle consuming an existing [installation].
  ///
  /// Ownership of the installation is transferred to this group handle.
  /// The [installation] instance is marked as disposed on success.
  factory MeshGroupHandle.fromInstallation(MeshInstallation installation) {
    final instHandle = installation.handleForTransfer;
    return using((Arena arena) {
      final outHandle = arena<ffi.Pointer<ffi.Void>>();
      final res = mesh_group_handle_from_installation(instHandle, outHandle);
      MeshIdentityBindings.checkResult(
        res,
        'Failed to create group handle from installation',
      );
      installation.finalizeTransfer();
      final handle = outHandle.value;
      if (handle == ffi.nullptr) {
        throw const GenericMeshIdentityException(
          'Failed to allocate group handle from installation',
        );
      }
      return MeshGroupHandle._(handle);
    });
  }

  /// Restore a group handle from an authenticated snapshot blob and signing seeds.
  ///
  /// [snapshotBlob] is the bytes produced by [save].
  /// [signingKeySeeds] must contain the 32-byte Ed25519 signing seeds for all
  /// personas held by this node.
  factory MeshGroupHandle.restore({
    required Uint8List snapshotBlob,
    required List<Uint8List> signingKeySeeds,
  }) {
    if (snapshotBlob.isEmpty || snapshotBlob.length > maxGroupSnapshotBytes) {
      throw const InvalidArgumentsException(
        'Snapshot blob must be non-empty and <= 256MB',
      );
    }
    if (signingKeySeeds.isEmpty ||
        signingKeySeeds.length > _maxSeedsCeiling ||
        signingKeySeeds.any((s) => s.length != 32)) {
      throw const InvalidArgumentsException(
        'Must provide 1..64 signing key seeds of exactly 32 bytes each',
      );
    }

    return using((Arena arena) {
      final blobPtr = arena<ffi.Uint8>(snapshotBlob.length);
      blobPtr.asTypedList(snapshotBlob.length).setAll(0, snapshotBlob);

      final totalSeedBytes = signingKeySeeds.length * 32;
      final seedsPtr = arena<ffi.Uint8>(totalSeedBytes);
      final seedsList = seedsPtr.asTypedList(totalSeedBytes);
      for (var i = 0; i < signingKeySeeds.length; i++) {
        seedsList.setRange(i * 32, (i + 1) * 32, signingKeySeeds[i]);
      }

      final outHandle = arena<ffi.Pointer<ffi.Void>>();
      final res = mesh_group_handle_restore(
        blobPtr,
        snapshotBlob.length,
        seedsPtr,
        signingKeySeeds.length,
        outHandle,
      );

      seedsList.fillRange(0, totalSeedBytes, 0);

      MeshIdentityBindings.checkResult(
        res,
        'Failed to restore group handle snapshot',
      );
      final handle = outHandle.value;
      if (handle == ffi.nullptr) {
        throw const GenericMeshIdentityException(
          'Failed to allocate restored group handle',
        );
      }
      return MeshGroupHandle._(handle);
    });
  }

  MeshGroupHandle._(ffi.Pointer<ffi.Void> handle) : _handle = handle {
    _finalizer.attach(this, handle, detach: this);
  }

  static final ffi.NativeFinalizer _finalizer = ffi.NativeFinalizer(
    ffi.Native.addressOf(mesh_group_handle_free),
  );

  ffi.Pointer<ffi.Void> _handle;
  bool _isPoisoned = false;

  /// Whether this group handle has been explicitly disposed.
  bool get isDisposed => _handle == ffi.nullptr;

  void _checkDisposed() {
    if (isDisposed) {
      throw const DisposedException(
        'MeshGroupHandle has already been disposed and cannot be used.',
      );
    }
    if (_isPoisoned) {
      throw const NativePanicException(
        'MeshGroupHandle is poisoned due to a prior native panic and cannot be used.',
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

  int _validateNow(DateTime? at) {
    final now = (at ?? DateTime.now()).millisecondsSinceEpoch;
    if (now < 0) {
      throw const InvalidArgumentsException('Timestamp cannot be negative');
    }
    return now;
  }

  /// Explicitly release native resources held by this group handle.
  void dispose() {
    if (!isDisposed) {
      _finalizer.detach(this);
      mesh_group_handle_free(_handle);
      _handle = ffi.nullptr;
    }
  }

  /// Retrieve the 32-byte Ed25519 public key of the active persona.
  Uint8List get selectedIdentity {
    _checkDisposed();
    return using((Arena arena) {
      final outPk = arena<ffi.Uint8>(32);
      final res = mesh_group_handle_selected_identity(_handle, outPk);
      _checkResult(res, 'Failed to get selected identity');
      return Uint8List.fromList(outPk.asTypedList(32));
    });
  }

  /// Create a new Byzantine group with the selected identity and optional initial members.
  ///
  /// Returns the assigned operation ID as [BigInt].
  BigInt createGroup({List<Uint8List> members = const []}) {
    _checkDisposed();
    if (members.length >= maxGroupMembers) {
      throw const GroupTooLargeException(
        'Initial group members count cannot exceed 191 (192 total with creator)',
      );
    }
    for (final m in members) {
      if (m.length != 32) {
        throw const InvalidArgumentsException(
          'Each member key must be exactly 32 bytes',
        );
      }
    }

    return using((Arena arena) {
      final outOpId = arena<ffi.Uint64>();
      ffi.Pointer<ffi.Uint8> membersPtr = ffi.nullptr;
      if (members.isNotEmpty) {
        membersPtr = arena<ffi.Uint8>(members.length * 32);
        final list = membersPtr.asTypedList(members.length * 32);
        for (var i = 0; i < members.length; i++) {
          list.setRange(i * 32, (i + 1) * 32, members[i]);
        }
      }

      final res = mesh_group_handle_create_group(
        _handle,
        membersPtr,
        members.length,
        outOpId,
      );
      _checkResult(res, 'Failed to create group');
      return BigInt.from(outOpId.value).toUnsigned(64);
    });
  }

  /// Import a group from an authenticated genesis frame.
  ///
  /// [expectedDigest] must be the 32-byte SHA-256 digest of the genesis frame.
  /// Returns the assigned operation ID as [BigInt].
  BigInt importGenesis({
    required Uint8List frame,
    required Uint8List expectedDigest,
  }) {
    _checkDisposed();
    if (frame.isEmpty || frame.length > maxGroupFrameBytes) {
      throw const InvalidArgumentsException(
        'Genesis frame must be non-empty and <= 128 KiB',
      );
    }
    if (expectedDigest.length != 32) {
      throw const InvalidArgumentsException(
        'Expected digest must be exactly 32 bytes',
      );
    }

    return using((Arena arena) {
      final framePtr = arena<ffi.Uint8>(frame.length);
      framePtr.asTypedList(frame.length).setAll(0, frame);
      final digestPtr = arena<ffi.Uint8>(32);
      digestPtr.asTypedList(32).setAll(0, expectedDigest);
      final outOpId = arena<ffi.Uint64>();

      final res = mesh_group_handle_import_genesis(
        _handle,
        framePtr,
        frame.length,
        digestPtr,
        outOpId,
      );
      _checkResult(res, 'Failed to import genesis frame');
      return BigInt.from(outOpId.value).toUnsigned(64);
    });
  }

  /// Invite a candidate contact to an active group.
  ///
  /// [candidateKey] must be a verified contact of the selected identity.
  /// Returns the assigned operation ID as [BigInt].
  BigInt invite({
    required BigInt groupId,
    required Uint8List candidateKey,
    Duration lifetime = const Duration(days: 1),
    DateTime? at,
  }) {
    _checkDisposed();
    if (candidateKey.length != 32) {
      throw const InvalidArgumentsException(
        'Candidate key must be exactly 32 bytes',
      );
    }
    if (groupId < BigInt.zero ||
        groupId > BigInt.parse('18446744073709551615')) {
      throw const InvalidArgumentsException('Group ID out of 64-bit range');
    }
    final now = _validateNow(at);
    final lifetimeMs = lifetime.inMilliseconds;
    if (lifetimeMs <= 0) {
      throw const InvalidArgumentsException('Lifetime must be positive');
    }

    return using((Arena arena) {
      final candidatePtr = arena<ffi.Uint8>(32);
      candidatePtr.asTypedList(32).setAll(0, candidateKey);
      final outOpId = arena<ffi.Uint64>();

      final res = mesh_group_handle_invite(
        _handle,
        groupId.toSigned(64).toInt(),
        candidatePtr,
        lifetimeMs,
        now,
        outOpId,
      );
      _checkResult(res, 'Failed to invite candidate to group');
      return BigInt.from(outOpId.value).toUnsigned(64);
    });
  }

  /// Accept an invitation to join a group.
  ///
  /// [invitationBinding] must be the 32-byte binding returned in [PendingInvitation.binding].
  /// Returns the assigned operation ID as [BigInt].
  BigInt accept({required Uint8List invitationBinding, DateTime? at}) {
    _checkDisposed();
    if (invitationBinding.length != 32) {
      throw const InvalidArgumentsException(
        'Invitation binding must be exactly 32 bytes',
      );
    }
    final now = _validateNow(at);

    return using((Arena arena) {
      final bindingPtr = arena<ffi.Uint8>(32);
      bindingPtr.asTypedList(32).setAll(0, invitationBinding);
      final outOpId = arena<ffi.Uint64>();

      final res = mesh_group_handle_accept(_handle, bindingPtr, now, outOpId);
      _checkResult(res, 'Failed to accept invitation');
      return BigInt.from(outOpId.value).toUnsigned(64);
    });
  }

  /// Accept an invitation with explicit out-of-band genesis authentication.
  ///
  /// Returns the assigned operation ID as [BigInt].
  BigInt acceptAuthenticated({
    required Uint8List invitationBinding,
    required Uint8List genesisDigest,
    DateTime? at,
  }) {
    _checkDisposed();
    if (invitationBinding.length != 32 || genesisDigest.length != 32) {
      throw const InvalidArgumentsException(
        'Invitation binding and genesis digest must each be exactly 32 bytes',
      );
    }
    final now = _validateNow(at);

    return using((Arena arena) {
      final bindingPtr = arena<ffi.Uint8>(32);
      bindingPtr.asTypedList(32).setAll(0, invitationBinding);
      final digestPtr = arena<ffi.Uint8>(32);
      digestPtr.asTypedList(32).setAll(0, genesisDigest);
      final outOpId = arena<ffi.Uint64>();

      final res = mesh_group_handle_accept_authenticated(
        _handle,
        bindingPtr,
        digestPtr,
        now,
        outOpId,
      );
      _checkResult(res, 'Failed to accept invitation with authentication');
      return BigInt.from(outOpId.value).toUnsigned(64);
    });
  }

  /// Leave an active group.
  ///
  /// Initiates Byzantine departure consensus. Returns operation ID as [BigInt].
  BigInt leaveGroup({required BigInt groupId, DateTime? at}) {
    _checkDisposed();
    if (groupId < BigInt.zero ||
        groupId > BigInt.parse('18446744073709551615')) {
      throw const InvalidArgumentsException('Group ID out of 64-bit range');
    }
    final now = _validateNow(at);

    return using((Arena arena) {
      final outOpId = arena<ffi.Uint64>();
      final res = mesh_group_handle_leave(
        _handle,
        groupId.toSigned(64).toInt(),
        now,
        outOpId,
      );
      _checkResult(res, 'Failed to leave group');
      return BigInt.from(outOpId.value).toUnsigned(64);
    });
  }

  /// Process incoming wire bytes from a peer.
  ///
  /// Returns immediate events (such as [FrameRejectedEvent] on malformed or invalid frame).
  /// Normal valid frames are staged internally and confirmed upon [save] and [confirmSaved].
  List<GroupEvent> receiveBytes({
    required Uint8List fromPeerKey,
    required Uint8List bytes,
    DateTime? at,
  }) {
    _checkDisposed();
    if (fromPeerKey.length != 32) {
      throw const InvalidArgumentsException(
        'fromPeerKey must be exactly 32 bytes',
      );
    }
    if (bytes.isEmpty || bytes.length > maxGroupFrameBytes) {
      throw const InvalidArgumentsException(
        'Frame bytes must be non-empty and <= 128 KiB',
      );
    }
    final now = _validateNow(at);

    return using((Arena arena) {
      final fromPtr = arena<ffi.Uint8>(32);
      fromPtr.asTypedList(32).setAll(0, fromPeerKey);
      final bytesPtr = arena<ffi.Uint8>(bytes.length);
      bytesPtr.asTypedList(bytes.length).setAll(0, bytes);
      final outEventsJson = arena<ffi.Pointer<ffi.Char>>();

      final res = mesh_group_handle_receive_bytes(
        _handle,
        fromPtr,
        bytesPtr,
        bytes.length,
        now,
        outEventsJson,
      );
      _checkResult(res, 'Failed to process incoming bytes');

      final jsonPtr = outEventsJson.value;
      if (jsonPtr == ffi.nullptr) return const [];
      try {
        final jsonStr = jsonPtr.cast<Utf8>().toDartString();
        final list = jsonDecode(jsonStr) as List<dynamic>;
        return list
            .map((e) => GroupEvent.fromJson(e as Map<String, dynamic>))
            .toList();
      } finally {
        mesh_string_free(jsonPtr);
      }
    });
  }

  /// Query all active group IDs held by the selected persona.
  List<BigInt> getGroupIds() {
    _checkDisposed();
    return using((Arena arena) {
      final outJson = arena<ffi.Pointer<ffi.Char>>();
      final res = mesh_group_handle_group_ids(_handle, outJson);
      _checkResult(res, 'Failed to query group IDs');

      final jsonPtr = outJson.value;
      if (jsonPtr == ffi.nullptr) return const [];
      try {
        final jsonStr = jsonPtr.cast<Utf8>().toDartString();
        final list = jsonDecode(jsonStr) as List<dynamic>;
        return list.map((s) => BigInt.parse(s as String)).toList();
      } finally {
        mesh_string_free(jsonPtr);
      }
    });
  }

  /// Query the current membership and revision of an active group.
  ///
  /// Returns `null` if the group is not found.
  GroupView? getGroup(BigInt groupId) {
    _checkDisposed();
    if (groupId < BigInt.zero ||
        groupId > BigInt.parse('18446744073709551615')) {
      throw const InvalidArgumentsException('Group ID out of 64-bit range');
    }

    return using((Arena arena) {
      final outJson = arena<ffi.Pointer<ffi.Char>>();
      final res = mesh_group_handle_get_group(
        _handle,
        groupId.toSigned(64).toInt(),
        outJson,
      );
      if (res == MeshIdentityBindings.meshErrNotFound) {
        return null;
      }
      _checkResult(res, 'Failed to get group');

      final jsonPtr = outJson.value;
      if (jsonPtr == ffi.nullptr) return null;
      try {
        final jsonStr = jsonPtr.cast<Utf8>().toDartString();
        final map = jsonDecode(jsonStr) as Map<String, dynamic>;
        return GroupView.fromJson(map);
      } finally {
        mesh_string_free(jsonPtr);
      }
    });
  }

  /// Query pending invitations waiting for acceptance by the selected identity.
  List<PendingInvitation> getPendingInvitations() {
    _checkDisposed();
    return using((Arena arena) {
      final outJson = arena<ffi.Pointer<ffi.Char>>();
      final res = mesh_group_handle_pending_invitations(_handle, outJson);
      _checkResult(res, 'Failed to query pending invitations');

      final jsonPtr = outJson.value;
      if (jsonPtr == ffi.nullptr) return const [];
      try {
        final jsonStr = jsonPtr.cast<Utf8>().toDartString();
        final list = jsonDecode(jsonStr) as List<dynamic>;
        return list
            .map((m) => PendingInvitation.fromJson(m as Map<String, dynamic>))
            .toList();
      } finally {
        mesh_string_free(jsonPtr);
      }
    });
  }

  /// Save the complete group handle state to an authenticated CBOR blob.
  ///
  /// Part 1 of the two-phase outbox commit:
  /// The caller must persist [GroupSaveResult.snapshotBlob] to durable storage,
  /// then call [confirmSaved] with [GroupSaveResult.token].
  GroupSaveResult save({DateTime? at}) {
    _checkDisposed();
    final now = _validateNow(at);

    return using((Arena arena) {
      final outTokenCounter = arena<ffi.Uint64>();
      final outTokenIncarnation = arena<ffi.Uint8>(32);
      final outBlobPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outBlobLen = arena<ffi.Size>();

      final res = mesh_group_handle_save(
        _handle,
        now,
        outTokenCounter,
        outTokenIncarnation,
        outBlobPtr,
        outBlobLen,
      );
      _checkResult(res, 'Failed to save group handle state');

      final blobPtr = outBlobPtr.value;
      final blobLen = outBlobLen.value;
      if (blobPtr == ffi.nullptr || blobLen == 0) {
        throw const GenericMeshIdentityException(
          'Empty save snapshot returned',
        );
      }

      try {
        final blobBytes = Uint8List.fromList(blobPtr.asTypedList(blobLen));
        final incarnation = Uint8List.fromList(
          outTokenIncarnation.asTypedList(32),
        );
        final token = SaveToken(
          counter: BigInt.from(outTokenCounter.value).toUnsigned(64),
          incarnation: incarnation,
        );
        return GroupSaveResult(token: token, blob: blobBytes);
      } finally {
        mesh_buffer_free(blobPtr, blobLen);
      }
    });
  }

  /// Confirm that a saved snapshot blob is durable.
  ///
  /// Part 2 of the two-phase outbox commit:
  /// Releases staged outgoing messages covered by [token] and returns newly
  /// confirmed [GroupEvent]s.
  List<GroupEvent> confirmSaved(SaveToken token) {
    _checkDisposed();
    if (token.incarnation.length != 32) {
      throw const InvalidArgumentsException(
        'Save token incarnation must be exactly 32 bytes',
      );
    }

    return using((Arena arena) {
      final incarnationPtr = arena<ffi.Uint8>(32);
      incarnationPtr.asTypedList(32).setAll(0, token.incarnation);
      final outEventsJson = arena<ffi.Pointer<ffi.Char>>();

      final res = mesh_group_handle_confirm_saved(
        _handle,
        token.counter.toSigned(64).toInt(),
        incarnationPtr,
        outEventsJson,
      );
      _checkResult(res, 'Failed to confirm saved token');

      final jsonPtr = outEventsJson.value;
      if (jsonPtr == ffi.nullptr) return const [];
      try {
        final jsonStr = jsonPtr.cast<Utf8>().toDartString();
        final list = jsonDecode(jsonStr) as List<dynamic>;
        return list
            .map((e) => GroupEvent.fromJson(e as Map<String, dynamic>))
            .toList();
      } finally {
        mesh_string_free(jsonPtr);
      }
    });
  }

  /// Retrieve and remove all released outgoing messages ready to transmit.
  ///
  /// Only messages released by [confirmSaved] will appear here.
  List<OutgoingMessage> takeOutgoing() {
    _checkDisposed();
    return using((Arena arena) {
      final outJson = arena<ffi.Pointer<ffi.Char>>();
      final res = mesh_group_handle_take_outgoing(_handle, outJson);
      _checkResult(res, 'Failed to take outgoing messages');

      final jsonPtr = outJson.value;
      if (jsonPtr == ffi.nullptr) return const [];
      try {
        final jsonStr = jsonPtr.cast<Utf8>().toDartString();
        final list = jsonDecode(jsonStr) as List<dynamic>;
        return list
            .map((m) => OutgoingMessage.fromJson(m as Map<String, dynamic>))
            .toList();
      } finally {
        mesh_string_free(jsonPtr);
      }
    });
  }

  /// Re-stage the frames of an operation without re-signing.
  void resend(BigInt opId) {
    _checkDisposed();
    if (opId < BigInt.zero || opId > BigInt.parse('18446744073709551615')) {
      throw const InvalidArgumentsException('OpId out of 64-bit range');
    }
    final res = mesh_group_handle_resend(_handle, opId.toSigned(64).toInt());
    _checkResult(res, 'Failed to resend operation');
  }

  /// Query the execution state of an operation by ID.
  ///
  /// Returns `null` if the operation is unknown.
  GroupOpState? getOpState(BigInt opId) {
    _checkDisposed();
    if (opId < BigInt.zero || opId > BigInt.parse('18446744073709551615')) {
      throw const InvalidArgumentsException('OpId out of 64-bit range');
    }

    return using((Arena arena) {
      final outJson = arena<ffi.Pointer<ffi.Char>>();
      final res = mesh_group_handle_op_state(
        _handle,
        opId.toSigned(64).toInt(),
        outJson,
      );
      if (res == MeshIdentityBindings.meshErrNotFound) {
        return null;
      }
      _checkResult(res, 'Failed to get operation state');

      final jsonPtr = outJson.value;
      if (jsonPtr == ffi.nullptr) return null;
      try {
        final jsonStr = jsonPtr.cast<Utf8>().toDartString();
        final map = jsonDecode(jsonStr) as Map<String, dynamic>;
        return GroupOpState.fromJson(map);
      } finally {
        mesh_string_free(jsonPtr);
      }
    });
  }
}
