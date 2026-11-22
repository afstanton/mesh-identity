import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:typed_data';

import 'package:ffi/ffi.dart';

import 'exceptions.dart';
import 'mesh_identity_bindings.dart';

/// The verification status of a contact record.
enum VerificationStatus {
  /// Confirmed through offline cryptographic Encounter ceremony.
  verified,

  /// Imported from external certificate or backup without verification ceremony.
  importedUnverified,
}

/// The active or blocked administrative state of a contact.
enum ContactStatus {
  /// Normal active contact.
  active,

  /// Contact is blocked from future encounters or operations.
  blocked,
}

/// An immutable representation of a peer contact.
class Contact {
  /// Creates a [Contact] record.
  const Contact({
    required this.peerPublicKey,
    this.alias,
    required this.status,
    required this.verificationStatus,
    required this.encounterCount,
    required this.verifiedAt,
  });

  /// Factory to parse from JSON map.
  factory Contact.fromJson(Map<String, dynamic> json) {
    final hexPk = json['peer_public_key'];
    if (hexPk is! String || hexPk.length != 64) {
      throw FormatException(
        'peer_public_key must be a 64-character hex string',
        hexPk,
      );
    }

    final pkBytes = Uint8List(32);
    for (var i = 0; i < 64; i += 2) {
      final byte = int.tryParse(hexPk.substring(i, i + 2), radix: 16);
      if (byte == null) {
        throw FormatException(
          'Invalid hex character in peer_public_key',
          hexPk,
        );
      }
      pkBytes[i ~/ 2] = byte;
    }

    final statusStr = json['status'];
    final ContactStatus status;
    switch (statusStr) {
      case 'active':
        status = ContactStatus.active;
      case 'blocked':
        status = ContactStatus.blocked;
      default:
        throw FormatException('Unknown contact status: $statusStr');
    }

    final verStr = json['verification_status'];
    final VerificationStatus verificationStatus;
    switch (verStr) {
      case 'verified':
        verificationStatus = VerificationStatus.verified;
      case 'imported_unverified':
        verificationStatus = VerificationStatus.importedUnverified;
      default:
        throw FormatException('Unknown verification status: $verStr');
    }

    final encounterCount = json['encounter_count'];
    if (encounterCount is! int || encounterCount < 0) {
      throw const FormatException(
        'encounter_count must be a non-negative integer',
      );
    }

    final verifiedAtSec = json['verified_at'];
    if (verifiedAtSec is! int || verifiedAtSec < 0) {
      throw const FormatException(
        'verified_at must be a non-negative Unix timestamp',
      );
    }

    return Contact(
      peerPublicKey: pkBytes,
      alias: json['alias'] as String?,
      status: status,
      verificationStatus: verificationStatus,
      encounterCount: encounterCount,
      verifiedAt: DateTime.fromMillisecondsSinceEpoch(
        verifiedAtSec * 1000,
        isUtc: true,
      ),
    );
  }

  /// The 32-byte Ed25519 public key of the peer.
  final Uint8List peerPublicKey;

  /// Private local user-assigned alias, if any.
  final String? alias;

  /// Administrative state (active or blocked).
  final ContactStatus status;

  /// Cryptographic verification status.
  final VerificationStatus verificationStatus;

  /// Total number of successful encounter ceremonies with this peer.
  final int encounterCount;

  /// When this contact was first verified or recorded.
  final DateTime verifiedAt;

  /// Whether this contact is currently blocked.
  bool get isBlocked => status == ContactStatus.blocked;

  /// Whether this contact is cryptographically verified.
  bool get isVerified => verificationStatus == VerificationStatus.verified;

  static bool _bytesEqual(Uint8List a, Uint8List b) {
    if (identical(a, b)) return true;
    if (a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  static int _bytesHashCode(Uint8List bytes) {
    var hash = 0;
    for (final b in bytes) {
      hash = (hash * 31 + b) & 0x3fffffff;
    }
    return hash;
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Contact &&
          _bytesEqual(peerPublicKey, other.peerPublicKey) &&
          alias == other.alias &&
          status == other.status &&
          verificationStatus == other.verificationStatus &&
          encounterCount == other.encounterCount &&
          verifiedAt == other.verifiedAt;

  @override
  int get hashCode => Object.hash(
    _bytesHashCode(peerPublicKey),
    alias,
    status,
    verificationStatus,
    encounterCount,
    verifiedAt,
  );

  @override
  String toString() {
    final pkPrefix =
        peerPublicKey.length >= 4 ? peerPublicKey.sublist(0, 4) : peerPublicKey;
    return 'Contact(pk: $pkPrefix..., alias: $alias, status: $status, ver: $verificationStatus)';
  }
}

/// The Short Authentication String (SAS) comparison result for mutual human confirmation.
class EncounterComparison {
  /// Creates an [EncounterComparison] with the derived numeric code.
  const EncounterComparison(this.code);

  /// The 6-digit numeric comparison code (0..999999).
  final int code;

  /// The zero-padded 6-digit string representation.
  String get formattedCode => code.toString().padLeft(6, '0');

  /// Required user-visible instruction to mitigate human glance-and-confirm complacency.
  static const String instruction =
      'Compare the 6-digit code with your peer. Check every digit carefully. Do not confirm if any digit differs.';

  /// Proximity disclaimer warning that QR codes could theoretically be forwarded.
  static const String proximityDisclaimer =
      'Verified matching keys. This does not prove physical proximity if the QR codes were forwarded.';

  /// Disclaimer that an encounter confirms a key, not a legal human identity.
  static const String notIdentityProof =
      'This confirms a key, not who a person is. One person can have several keys.';

  /// Notice shown after confirming a contact locally.
  static const String localOnlyConfirmation =
      'Saved on this device only. The other device may not have saved you, and cancelling there cannot undo this.';

  /// Warning shown after repeated incomplete encounter attempts.
  static const String interferenceWarning =
      'Several attempts did not finish. This can mean something is interfering with the exchange. Wait before trying again.';

  /// Warning shown when a peer alias conflicts with an existing contact's key.
  static const String aliasConflictWarning =
      'Different cryptographic identity from previously saved contact with this name.';

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is EncounterComparison && other.code == code;

  @override
  int get hashCode => code.hashCode;

  @override
  String toString() => 'EncounterComparison($formattedCode)';
}

/// Optical QR code transport URI encoding and decoding utilities.
abstract final class QrTransport {
  /// The standard URI scheme prefix for encounter payloads.
  static const String uriPrefix = 'mesh:encounter:';

  /// Maximum raw frame bytes permitted in an encounter transport message (matching core MAX_FRAME_BYTES).
  static const int maxFrameBytes = 512;

  /// Maximum base64 string length for [maxFrameBytes].
  static const int maxB64Length = ((maxFrameBytes + 2) ~/ 3) * 4;

  /// Encodes a binary encounter payload into a `mesh:encounter:<base64>` URI.
  static String encodeUri(Uint8List payload) {
    if (payload.length > maxFrameBytes) {
      throw FormatException(
        'Payload length ${payload.length} exceeds maxFrameBytes $maxFrameBytes',
      );
    }
    return '$uriPrefix${base64.encode(payload)}';
  }

  /// Decodes a `mesh:encounter:<base64>` URI into a raw payload buffer.
  static Uint8List decodeUri(String uri) {
    if (!uri.startsWith(uriPrefix)) {
      throw FormatException(
        'Invalid QR URI scheme, expected prefix $uriPrefix',
        uri,
      );
    }
    final b64 = uri.substring(uriPrefix.length);
    if (b64.length > maxB64Length) {
      throw FormatException(
        'QR URI payload length ${b64.length} exceeds maximum base64 length $maxB64Length',
        uri,
      );
    }
    final bytes = base64.decode(b64);
    if (bytes.length > maxFrameBytes) {
      throw FormatException(
        'Decoded payload length ${bytes.length} exceeds maxFrameBytes $maxFrameBytes',
      );
    }
    return Uint8List.fromList(bytes);
  }
}

/// The voting role state of an identity on this device.
enum VotingState {
  /// This device holds the voting role and may sign for the identity.
  voting,

  /// This device handed the role off and must never sign again at this counter.
  stopped,

  /// This device may not sign until a handoff or recognition raises its counter.
  gated,
}

/// Information about an identity's monotonic voting role on this device.
class VotingRecord {
  /// Creates a [VotingRecord].
  const VotingRecord({required this.counter, required this.state, this.holder});

  /// The monotonic sequence counter of this identity's voting role (0..2^64 - 1).
  final BigInt counter;

  /// The current voting capability state on this device.
  final VotingState state;

  /// The 32-byte device nonce the counter was granted to (or null if not yet handed off).
  final Uint8List? holder;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is VotingRecord &&
          other.counter == counter &&
          other.state == state &&
          _bytesEqual(other.holder, holder);

  @override
  int get hashCode =>
      Object.hash(counter, state, holder == null ? 0 : Object.hashAll(holder!));

  @override
  String toString() =>
      'VotingRecord(counter: $counter, state: $state, holder: ${holder == null ? "none" : _toHex(holder!)})';
}

/// A signed claim requesting groups to recognize a monotonic counter for a device nonce.
class TakeoverStatement {
  /// Creates a [TakeoverStatement].
  const TakeoverStatement({
    required this.identity,
    required this.counter,
    required this.nonce,
    required this.signature,
  });

  /// Factory to parse from JSON map.
  factory TakeoverStatement.fromJson(Map<String, dynamic> json) {
    return TakeoverStatement(
      identity: _hexToBytes(json['identity'] as String, 'identity', 32),
      counter: BigInt.parse(json['counter'].toString()),
      nonce: _hexToBytes(json['nonce'] as String, 'nonce', 32),
      signature: _hexToBytes(json['signature'] as String, 'signature', 64),
    );
  }

  /// The 32-byte public key of the identity.
  final Uint8List identity;

  /// The monotonic counter claimed (0..2^64 - 1).
  final BigInt counter;

  /// The 32-byte device nonce granted this counter.
  final Uint8List nonce;

  /// The 64-byte Ed25519 signature over (identity, counter, nonce).
  final Uint8List signature;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is TakeoverStatement &&
          other.counter == counter &&
          _bytesEqual(other.identity, identity) &&
          _bytesEqual(other.nonce, nonce) &&
          _bytesEqual(other.signature, signature);

  @override
  int get hashCode => Object.hash(
    counter,
    Object.hashAll(identity),
    Object.hashAll(nonce),
    Object.hashAll(signature),
  );

  @override
  String toString() =>
      'TakeoverStatement(identity: ${_toHex(identity)}, counter: $counter, nonce: ${_toHex(nonce)})';
}

/// An unauthenticated handoff bundle transferring voting role between devices.
///
/// NOTE: Instances parsed via [fromBytes] decode the CBOR structure without
/// cryptographically verifying signatures. Signatures are verified when accepted
/// by [MeshInstallation.acceptHandoff] or by group admission governance.
class HandoffBundle {
  /// Maximum raw bytes permitted in a handoff bundle (5 MiB).
  static const int maxBundleBytes = 5 * 1024 * 1024;

  const HandoffBundle._({
    required this.rawBytes,
    required this.identity,
    required this.counter,
    required this.recipient,
    required this.statement,
  });

  /// Parse and inspect an unauthenticated handoff bundle from binary CBOR bytes.
  ///
  /// NOTE: This validates CBOR structure and size limits, but does NOT authenticate
  /// signatures. Signatures are verified upon calling [MeshInstallation.acceptHandoff].
  factory HandoffBundle.fromBytes(Uint8List bytes) {
    if (bytes.isEmpty) {
      throw const InvalidArgumentsException('Handoff bundle cannot be empty');
    }
    if (bytes.length > maxBundleBytes) {
      throw const InvalidArgumentsException(
        'Handoff bundle exceeds 5 MiB ceiling',
      );
    }

    return using((Arena arena) {
      final bytesPtr = arena<ffi.Uint8>(bytes.length);
      bytesPtr.asTypedList(bytes.length).setAll(0, bytes);
      final outJson = arena<ffi.Pointer<ffi.Char>>();

      final res = mesh_handoff_bundle_inspect(bytesPtr, bytes.length, outJson);
      MeshIdentityBindings.checkResult(res, 'Failed to inspect handoff bundle');

      final jsonPtr = outJson.value;
      try {
        final jsonStr = jsonPtr.cast<Utf8>().toDartString();
        final map = jsonDecode(jsonStr) as Map<String, dynamic>;
        final statementMap = map['statement'] as Map<String, dynamic>;
        return HandoffBundle._(
          rawBytes: Uint8List.fromList(bytes),
          identity: _hexToBytes(map['identity'] as String, 'identity', 32),
          counter: BigInt.parse(map['counter'].toString()),
          recipient: _hexToBytes(map['recipient'] as String, 'recipient', 32),
          statement: TakeoverStatement.fromJson(statementMap),
        );
      } finally {
        mesh_string_free(jsonPtr);
      }
    });
  }

  /// Raw CBOR bytes of the bundle.
  final Uint8List rawBytes;

  /// The 32-byte public key of the identity being handed off.
  final Uint8List identity;

  /// The monotonic counter granted.
  final BigInt counter;

  /// The 32-byte device nonce of the recipient device.
  final Uint8List recipient;

  /// The public takeover grant statement contained within this bundle.
  final TakeoverStatement statement;

  /// Return the serialized bytes of the bundle.
  Uint8List toBytes() => rawBytes;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is HandoffBundle && _bytesEqual(other.rawBytes, rawBytes);

  @override
  int get hashCode => Object.hashAll(rawBytes);

  @override
  String toString() =>
      'HandoffBundle(identity: ${_toHex(identity)}, counter: $counter, recipient: ${_toHex(recipient)})';
}

/// The result of initiating a device-to-device handoff.
class HandoffResult {
  /// Creates a [HandoffResult].
  const HandoffResult({required this.bundle, required this.snapshotBytes});

  /// The signed handoff bundle to transfer to the recipient device.
  ///
  /// CRITICAL: The caller MUST persist [snapshotBytes] to durable storage BEFORE
  /// transmitting or displaying [bundle] to prevent equivocation / double-voting on crash.
  final HandoffBundle bundle;

  /// The updated installation snapshot bytes recording this device as Stopped.
  final Uint8List snapshotBytes;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is HandoffResult &&
          other.bundle == bundle &&
          _bytesEqual(other.snapshotBytes, snapshotBytes);

  @override
  int get hashCode => Object.hash(bundle, Object.hashAll(snapshotBytes));

  @override
  String toString() =>
      'HandoffResult(bundle: $bundle, snapshotBytes: ${snapshotBytes.length} bytes)';
}

/// The result of accepting a device-to-device handoff bundle.
class AcceptHandoffResult {
  /// Creates an [AcceptHandoffResult].
  const AcceptHandoffResult({required this.state, required this.snapshotBytes});

  /// The new voting capability state assumed by this device.
  final VotingState state;

  /// The updated installation snapshot bytes recording the assumed voting role and merged locks.
  final Uint8List snapshotBytes;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is AcceptHandoffResult &&
          other.state == state &&
          _bytesEqual(other.snapshotBytes, snapshotBytes);

  @override
  int get hashCode => Object.hash(state, Object.hashAll(snapshotBytes));

  @override
  String toString() =>
      'AcceptHandoffResult(state: $state, snapshotBytes: ${snapshotBytes.length} bytes)';
}

Uint8List _hexToBytes(String hex, String fieldName, int expectedByteLen) {
  if (hex.length != expectedByteLen * 2) {
    throw FormatException(
      '$fieldName must be a ${expectedByteLen * 2}-character hex string',
      hex,
    );
  }
  final bytes = Uint8List(expectedByteLen);
  for (var i = 0; i < hex.length; i += 2) {
    final b = int.tryParse(hex.substring(i, i + 2), radix: 16);
    if (b == null) {
      throw FormatException('Invalid hex character in $fieldName', hex);
    }
    bytes[i ~/ 2] = b;
  }
  return bytes;
}

String _toHex(Uint8List bytes) =>
    bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join();

bool _bytesEqual(Uint8List? a, Uint8List? b) {
  if (identical(a, b)) return true;
  if (a == null || b == null) return false;
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}
