import 'dart:convert';
import 'dart:typed_data';

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
