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
