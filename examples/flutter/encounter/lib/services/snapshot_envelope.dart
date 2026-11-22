import 'dart:typed_data';

/// Plain, unauthenticated framing envelope binding committed persona public keys
/// to a local snapshot payload.
///
/// The header carries no MAC or cryptographic hash; integrity of local snapshot
/// storage relies on platform file protections and `MeshInstallation.restore`
/// domain validation.
///
/// Format:
/// - Bytes `0..4`: ASCII magic `"ENCS"` (`[0x45, 0x4E, 0x43, 0x53]`), disjoint
///   from CBOR map headers (`0xA0..=0xBF`).
/// - Byte `4`: format version (`0x01`).
/// - Bytes `5..7`: `keyCount` as big-endian `uint16` (`1 <= keyCount <= 2048`).
/// - Next `keyCount * 32` bytes: unique 32-byte Ed25519 public keys.
/// - Remaining bytes: non-empty raw `MeshInstallation` snapshot (`<= 64 MiB`).
class SnapshotEnvelope {
  /// Magic header `"ENCS"`.
  static const List<int> magic = [0x45, 0x4E, 0x43, 0x53];

  /// Envelope format version.
  static const int formatVersion = 1;

  /// Maximum permitted identity keys per envelope.
  static const int maxKeys = 2048;

  /// Maximum permitted raw snapshot payload size (64 MiB).
  static const int maxSnapshotBytes = 64 * 1024 * 1024;

  static const int _headerLength = 7;
  static const int _keyLength = 32;

  /// The ordered list of 32-byte Ed25519 identity public keys committed in the snapshot.
  final List<Uint8List> identityKeys;

  /// The raw serialized `MeshInstallation` snapshot bytes.
  final Uint8List snapshotBytes;

  SnapshotEnvelope({
    required List<Uint8List> identityKeys,
    required Uint8List snapshotBytes,
  }) : identityKeys = List.unmodifiable(identityKeys.map(Uint8List.fromList)),
       snapshotBytes = Uint8List.fromList(snapshotBytes);

  /// Returns `true` iff [bytes] begins with the `"ENCS"` envelope magic bytes.
  static bool hasEnvelopeMagic(Uint8List bytes) {
    if (bytes.length < magic.length) return false;
    for (var i = 0; i < magic.length; i++) {
      if (bytes[i] != magic[i]) return false;
    }
    return true;
  }

  static String _bytesToHex(Uint8List bytes) {
    final sb = StringBuffer();
    for (final b in bytes) {
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }

  /// Encodes [identityKeys] and [snapshotBytes] into a versioned framing envelope.
  static Uint8List encode({
    required List<Uint8List> identityKeys,
    required Uint8List snapshotBytes,
  }) {
    if (identityKeys.isEmpty || identityKeys.length > maxKeys) {
      throw FormatException(
        'Envelope keyCount must be in 1..=$maxKeys, got ${identityKeys.length}',
      );
    }
    if (snapshotBytes.isEmpty || snapshotBytes.length > maxSnapshotBytes) {
      throw FormatException(
        'Snapshot payload length must be in 1..=$maxSnapshotBytes, got ${snapshotBytes.length}',
      );
    }

    final seenKeys = <String>{};
    for (var i = 0; i < identityKeys.length; i++) {
      final key = identityKeys[i];
      if (key.length != _keyLength) {
        throw FormatException(
          'Identity key at index $i must be $_keyLength bytes, got ${key.length}',
        );
      }
      final hex = _bytesToHex(key);
      if (!seenKeys.add(hex)) {
        throw FormatException('Duplicate identity key at index $i');
      }
    }

    final totalLength =
        _headerLength + identityKeys.length * _keyLength + snapshotBytes.length;
    final out = Uint8List(totalLength);

    // Magic bytes
    out.setRange(0, 4, magic);
    // Format version
    out[4] = formatVersion;
    // Key count (big-endian uint16)
    out[5] = (identityKeys.length >> 8) & 0xFF;
    out[6] = identityKeys.length & 0xFF;

    var offset = _headerLength;
    for (final key in identityKeys) {
      out.setRange(offset, offset + _keyLength, key);
      offset += _keyLength;
    }

    out.setRange(offset, totalLength, snapshotBytes);
    return out;
  }

  /// Decodes a framed [SnapshotEnvelope] from [bytes], throwing [FormatException] on any violation.
  static SnapshotEnvelope decode(Uint8List bytes) {
    if (bytes.length < _headerLength) {
      throw FormatException(
        'Envelope too short: expected at least $_headerLength bytes, got ${bytes.length}',
      );
    }
    if (!hasEnvelopeMagic(bytes)) {
      throw const FormatException('Invalid envelope magic bytes');
    }
    final version = bytes[4];
    if (version != formatVersion) {
      throw FormatException('Unsupported envelope version: $version');
    }

    final keyCount = (bytes[5] << 8) | bytes[6];
    if (keyCount < 1 || keyCount > maxKeys) {
      throw FormatException(
        'Envelope keyCount out of range 1..=$maxKeys: $keyCount',
      );
    }

    final payloadOffset = _headerLength + keyCount * _keyLength;
    if (bytes.length <= payloadOffset) {
      throw FormatException(
        'Envelope truncated: length ${bytes.length} does not leave non-empty payload after $payloadOffset header bytes',
      );
    }

    final payloadLength = bytes.length - payloadOffset;
    if (payloadLength > maxSnapshotBytes) {
      throw FormatException(
        'Envelope snapshot payload exceeds $maxSnapshotBytes bytes: $payloadLength',
      );
    }

    final keys = <Uint8List>[];
    final seenKeys = <String>{};
    for (var i = 0; i < keyCount; i++) {
      final start = _headerLength + i * _keyLength;
      final key = Uint8List.fromList(bytes.sublist(start, start + _keyLength));
      final hex = _bytesToHex(key);
      if (!seenKeys.add(hex)) {
        throw FormatException('Duplicate identity key at index $i in envelope');
      }
      keys.add(key);
    }

    final payload = Uint8List.fromList(bytes.sublist(payloadOffset));
    return SnapshotEnvelope(identityKeys: keys, snapshotBytes: payload);
  }
}
