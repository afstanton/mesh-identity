import 'dart:convert';
import 'dart:typed_data';

import 'package:mesh_identity/mesh_identity.dart';

/// Decode an OpenPGP certificate, revocation, or signature input from either
/// ASCII armor (`-----BEGIN PGP ...`) or base64/base64url text.
///
/// Enforces [maxBytes] (default [MeshInstallation.maxOpenPgpCertificateBytes],
/// 256 KiB) BEFORE allocating decoded byte buffers.
Uint8List decodeOpenPgpInput(
  String input, {
  int maxBytes = MeshInstallation.maxOpenPgpCertificateBytes,
  String label = 'OpenPGP payload',
}) {
  final trimmed = input.trim();
  if (trimmed.isEmpty) {
    throw FormatException('Enter $label.');
  }

  if (trimmed.startsWith('-----BEGIN PGP')) {
    if (trimmed.length > maxBytes) {
      throw FormatException('$label exceeds ${maxBytes ~/ 1024} KiB limit.');
    }
    final bytes = utf8.encode(trimmed);
    if (bytes.length > maxBytes) {
      throw FormatException('$label exceeds ${maxBytes ~/ 1024} KiB limit.');
    }
    return Uint8List.fromList(bytes);
  }

  final normalized = trimmed.replaceAll(RegExp(r'\s+'), '');
  final maxBase64Chars = ((maxBytes + 2) ~/ 3) * 4;
  if (normalized.length > maxBase64Chars) {
    throw FormatException('$label exceeds ${maxBytes ~/ 1024} KiB limit.');
  }

  final Uint8List bytes;
  try {
    final padded = normalized.length % 4 == 0
        ? normalized
        : normalized.padRight(
            normalized.length + (4 - normalized.length % 4),
            '=',
          );
    bytes = (padded.contains('-') || padded.contains('_'))
        ? base64Url.decode(padded)
        : base64Decode(padded);
  } on FormatException {
    throw FormatException(
      '$label must be ASCII-armored PGP text or valid base64.',
    );
  }

  if (bytes.isEmpty || bytes.length > maxBytes) {
    throw FormatException(
      '$label must be non-empty and <= ${maxBytes ~/ 1024} KiB.',
    );
  }
  return bytes;
}

/// Encode raw OpenPGP binary bytes as standard base64 for copy/paste.
String encodeOpenPgpBase64(Uint8List bytes) => base64Encode(bytes);

/// Encode raw OpenPGP binary bytes as an ASCII-armored block (`-----BEGIN ...`).
///
/// Includes the 24-bit OpenPGP CRC (`=XXXX`) for v4 compatibility when
/// [includeCrc24] is `true`; omit for v6 per RFC 9580.
String encodeOpenPgpArmor(
  Uint8List bytes, {
  required String blockType,
  bool includeCrc24 = true,
}) {
  final b64 = base64Encode(bytes);
  final sb = StringBuffer('-----BEGIN $blockType-----\n\n');
  for (var i = 0; i < b64.length; i += 64) {
    final end = i + 64 < b64.length ? i + 64 : b64.length;
    sb.writeln(b64.substring(i, end));
  }
  if (includeCrc24) {
    final crc = _crc24OpenPgp(bytes);
    final crcBytes = Uint8List.fromList([
      (crc >> 16) & 0xFF,
      (crc >> 8) & 0xFF,
      crc & 0xFF,
    ]);
    sb.writeln('=${base64Encode(crcBytes)}');
  }
  sb.write('-----END $blockType-----');
  return sb.toString();
}

int _crc24OpenPgp(Uint8List data) {
  var crc = 0xB704CE;
  for (final byte in data) {
    crc ^= (byte & 0xFF) << 16;
    for (var i = 0; i < 8; i++) {
      crc <<= 1;
      if ((crc & 0x1000000) != 0) {
        crc ^= 0x1864CFB;
      }
    }
  }
  return crc & 0xFFFFFF;
}

/// Format a hex OpenPGP fingerprint into uppercase 4-character groups.
String formatOpenPgpFingerprint(String hex) {
  final clean = hex.replaceAll(RegExp(r'\s+'), '').toUpperCase();
  final sb = StringBuffer();
  for (var i = 0; i < clean.length; i++) {
    if (i > 0 && i % 4 == 0) {
      sb.write(' ');
    }
    sb.write(clean[i]);
  }
  return sb.toString();
}
