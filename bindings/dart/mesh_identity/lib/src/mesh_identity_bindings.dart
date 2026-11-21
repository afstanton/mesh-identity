// ignore_for_file: non_constant_identifier_names

import 'dart:ffi' as ffi;
import 'package:ffi/ffi.dart';
import 'exceptions.dart';

@ffi.Native<ffi.Int32 Function(ffi.Pointer<ffi.Char>, ffi.Size)>()
external int mesh_last_error(ffi.Pointer<ffi.Char> outBuf, int maxLen);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Pointer<ffi.Pointer<ffi.Void>>,
  )
>()
external int mesh_installation_create(
  ffi.Pointer<ffi.Uint8> seedPtr,
  int seedLen,
  ffi.Pointer<ffi.Pointer<ffi.Void>> outHandle,
);

@ffi.Native<ffi.Void Function(ffi.Pointer<ffi.Void>)>()
external void mesh_installation_free(ffi.Pointer<ffi.Void> handle);

@ffi.Native<
  ffi.Int32 Function(ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Uint8>, ffi.Size)
>()
external int mesh_installation_selected(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Uint8> outPk,
  int outPkLen,
);

@ffi.Native<ffi.Size Function(ffi.Pointer<ffi.Void>)>()
external int mesh_installation_identities_count(ffi.Pointer<ffi.Void> handle);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Size,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
  )
>()
external int mesh_installation_identities_get(
  ffi.Pointer<ffi.Void> handle,
  int index,
  ffi.Pointer<ffi.Uint8> outPk,
  int outPkLen,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Uint64,
  )
>()
external int mesh_installation_select_identity(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Uint8> keyPtr,
  int keyLen,
  int timestamp,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
  )
>()
external int mesh_installation_add_identity(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Uint8> seedPtr,
  int seedLen,
  ffi.Pointer<ffi.Uint8> outPk,
  int outPkLen,
);

@ffi.Native<
  ffi.Int32 Function(ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Uint8>, ffi.Size)
>()
external int mesh_installation_remove_identity(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Uint8> keyPtr,
  int keyLen,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Uint64,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
  )
>()
external int mesh_installation_save(
  ffi.Pointer<ffi.Void> handle,
  int timestamp,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> outBuf,
  ffi.Pointer<ffi.Size> outLen,
);

@ffi.Native<ffi.Void Function(ffi.Pointer<ffi.Uint8>, ffi.Size)>()
external void mesh_buffer_free(ffi.Pointer<ffi.Uint8> buf, int len);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Pointer<ffi.Pointer<ffi.Void>>,
  )
>()
external int mesh_installation_restore(
  ffi.Pointer<ffi.Uint8> bytesPtr,
  int bytesLen,
  ffi.Pointer<ffi.Uint8> seedsPtr,
  int seedsCount,
  ffi.Pointer<ffi.Pointer<ffi.Void>> outHandle,
);

@ffi.Native<
  ffi.Size Function(ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Uint8>, ffi.Size)
>()
external int mesh_installation_contacts_count(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Uint8> identityPk,
  int identityPkLen,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Pointer<ffi.Pointer<ffi.Char>>,
  )
>()
external int mesh_installation_get_contact(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Uint8> identityPk,
  int identityPkLen,
  ffi.Pointer<ffi.Uint8> peerPk,
  int peerPkLen,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

@ffi.Native<ffi.Void Function(ffi.Pointer<ffi.Char>)>()
external void mesh_string_free(ffi.Pointer<ffi.Char> ptr);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
  )
>()
external int mesh_installation_block_contact(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Uint8> identityPk,
  int identityPkLen,
  ffi.Pointer<ffi.Uint8> peerPk,
  int peerPkLen,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
  )
>()
external int mesh_installation_import_peer_key(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Uint8> localPk,
  int localPkLen,
  ffi.Pointer<ffi.Uint8> peerPk,
  int peerPkLen,
);

@ffi.Native<ffi.Void Function(ffi.Pointer<ffi.Void>)>()
external void mesh_ceremony_free(ffi.Pointer<ffi.Void> handle);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Uint64,
    ffi.Pointer<ffi.Pointer<ffi.Void>>,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
  )
>()
external int mesh_installation_start(
  ffi.Pointer<ffi.Void> handle,
  int now,
  ffi.Pointer<ffi.Pointer<ffi.Void>> outCeremony,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> outPayload,
  ffi.Pointer<ffi.Size> outPayloadLen,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Uint64,
    ffi.Pointer<ffi.Pointer<ffi.Void>>,
  )
>()
external int mesh_installation_open_scanner(
  ffi.Pointer<ffi.Void> handle,
  int now,
  ffi.Pointer<ffi.Pointer<ffi.Void>> outCeremony,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Uint64,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
  )
>()
external int mesh_installation_scan_offer(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Void> ceremony,
  ffi.Pointer<ffi.Uint8> bytes,
  int bytesLen,
  int now,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> outPayload,
  ffi.Pointer<ffi.Size> outPayloadLen,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Uint64,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
  )
>()
external int mesh_installation_scan_response(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Void> ceremony,
  ffi.Pointer<ffi.Uint8> bytes,
  int bytesLen,
  int now,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> outPayload,
  ffi.Pointer<ffi.Size> outPayloadLen,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Uint64,
  )
>()
external int mesh_installation_scan_reveal(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Void> ceremony,
  ffi.Pointer<ffi.Uint8> bytes,
  int bytesLen,
  int now,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Void>,
    ffi.Uint64,
    ffi.Pointer<ffi.Uint32>,
  )
>()
external int mesh_installation_comparison(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Void> ceremony,
  int now,
  ffi.Pointer<ffi.Uint32> outCode,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Void>,
    ffi.Uint32,
    ffi.Uint64,
    ffi.Uint64,
    ffi.Pointer<ffi.Pointer<ffi.Char>>,
  )
>()
external int mesh_installation_confirm_and_save(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Void> ceremony,
  int peerCode,
  int now,
  int timestamp,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

@ffi.Native<
  ffi.Int32 Function(ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Void>, ffi.Uint64)
>()
external int mesh_installation_cancel_ceremony(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Void> ceremony,
  int now,
);

@ffi.Native<ffi.Int32 Function(ffi.Pointer<ffi.Void>, ffi.Pointer<ffi.Uint8>)>()
external int mesh_installation_device_nonce(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Uint8> outNonce,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Bool>,
  )
>()
external int mesh_installation_current_device_nonce(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Uint8> outNonce,
  ffi.Pointer<ffi.Bool> outHasNonce,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Pointer<ffi.Int32>,
  )
>()
external int mesh_installation_voting_state(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Uint8> keyPtr,
  int keyLen,
  ffi.Pointer<ffi.Int32> outState,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Pointer<ffi.Uint64>,
    ffi.Pointer<ffi.Int32>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Pointer<ffi.Bool>,
  )
>()
external int mesh_installation_voting_record(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Uint8> keyPtr,
  int keyLen,
  ffi.Pointer<ffi.Uint64> outCounter,
  ffi.Pointer<ffi.Int32> outState,
  ffi.Pointer<ffi.Uint8> outHolder,
  ffi.Pointer<ffi.Bool> outHasHolder,
);

@ffi.Native<ffi.Int32 Function(ffi.Pointer<ffi.Void>)>()
external int mesh_installation_gate_voting(ffi.Pointer<ffi.Void> handle);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Uint64,
    ffi.Pointer<ffi.Pointer<ffi.Char>>,
  )
>()
external int mesh_installation_begin_takeover(
  ffi.Pointer<ffi.Void> handle,
  int floor,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Uint64,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
  )
>()
external int mesh_installation_begin_handoff(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Uint8> recipientPtr,
  int recipientLen,
  int now,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> outBundlePtr,
  ffi.Pointer<ffi.Size> outBundleLen,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> outSnapshotPtr,
  ffi.Pointer<ffi.Size> outSnapshotLen,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Void>,
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Uint64,
    ffi.Pointer<ffi.Int32>,
    ffi.Pointer<ffi.Pointer<ffi.Uint8>>,
    ffi.Pointer<ffi.Size>,
  )
>()
external int mesh_installation_accept_handoff(
  ffi.Pointer<ffi.Void> handle,
  ffi.Pointer<ffi.Uint8> bundlePtr,
  int bundleLen,
  int now,
  ffi.Pointer<ffi.Int32> outNewState,
  ffi.Pointer<ffi.Pointer<ffi.Uint8>> outSnapshotPtr,
  ffi.Pointer<ffi.Size> outSnapshotLen,
);

@ffi.Native<
  ffi.Int32 Function(
    ffi.Pointer<ffi.Uint8>,
    ffi.Size,
    ffi.Pointer<ffi.Pointer<ffi.Char>>,
  )
>()
external int mesh_handoff_bundle_inspect(
  ffi.Pointer<ffi.Uint8> bundlePtr,
  int bundleLen,
  ffi.Pointer<ffi.Pointer<ffi.Char>> outJson,
);

/// Utility for querying last native errors and checking call results.
abstract final class MeshIdentityBindings {
  static const int meshOk = 0;
  static const int meshErrPanic = -1;
  static const int meshErrInvalidArg = -2;
  static const int meshErrUnknownIdentity = -3;
  static const int meshErrSelectedIdentity = -4;
  static const int meshErrCapacityExceeded = -5;
  static const int meshErrInvalidSnapshot = -6;
  static const int meshErrNotFound = -7;
  static const int meshErrInternal = -8;
  static const int meshErrCeremonyActive = -9;
  static const int meshErrStaleCeremony = -10;
  static const int meshErrProtocol = -11;
  static const int meshErrRateLimited = -12;
  static const int meshErrIndexOutOfBounds = -13;
  static const int meshErrNoComparison = -14;
  static const int meshErrNotVotingDevice = -15;
  static const int meshErrInvalidHandoff = -16;
  static const int meshErrStaleHandoff = -17;
  static const int meshErrWrongHandoffRecipient = -18;
  static const int meshErrCounterExhausted = -19;
  static const int meshErrNotGated = -20;
  static const int meshErrHandoffWriteFailed = -21;

  /// Retrieve the last recorded error string from native TLS.
  static String? getLastError() {
    return using((Arena arena) {
      final buf = arena<ffi.Char>(1024);
      final res = mesh_last_error(buf, 1024);
      if (res != 0) return null;
      final str = buf.cast<Utf8>().toDartString();
      return str.isEmpty ? null : str;
    });
  }

  /// Verify that [code] is [meshOk]; otherwise, throws a typed exception.
  static void checkResult(int code, [String? fallbackMessage]) {
    if (code == meshOk) return;
    final errText =
        getLastError() ?? fallbackMessage ?? 'Native error code: $code';
    switch (code) {
      case meshErrPanic:
        throw NativePanicException(errText);
      case meshErrInvalidArg:
        throw InvalidArgumentsException(errText);
      case meshErrUnknownIdentity:
        throw UnknownIdentityException(errText);
      case meshErrSelectedIdentity:
        throw SelectedIdentityException(errText);
      case meshErrCapacityExceeded:
        throw CapacityExceededException(errText);
      case meshErrInvalidSnapshot:
        throw InvalidSnapshotException(errText);
      case meshErrNotFound:
        throw ContactNotFoundException(errText);
      case meshErrCeremonyActive:
        throw CeremonyActiveException(errText);
      case meshErrStaleCeremony:
        throw StaleCeremonyException(errText);
      case meshErrProtocol:
        throw EncounterProtocolException(errText);
      case meshErrRateLimited:
        throw RateLimitedException(errText);
      case meshErrIndexOutOfBounds:
        throw IndexOutOfBoundsException(errText);
      case meshErrNoComparison:
        throw NoComparisonException(errText);
      case meshErrNotVotingDevice:
        throw NotVotingDeviceException(errText);
      case meshErrInvalidHandoff:
        throw InvalidHandoffException(errText);
      case meshErrStaleHandoff:
        throw StaleHandoffException(errText);
      case meshErrWrongHandoffRecipient:
        throw WrongHandoffRecipientException(errText);
      case meshErrCounterExhausted:
        throw CounterExhaustedException(errText);
      case meshErrNotGated:
        throw NotGatedException(errText);
      case meshErrHandoffWriteFailed:
        throw HandoffWriteFailedException(errText);
      default:
        throw GenericMeshIdentityException(errText);
    }
  }
}
