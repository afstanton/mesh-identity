import 'dart:convert';
import 'dart:typed_data';

import 'package:mesh_identity/mesh_identity.dart';

import 'hex_utils.dart';

/// URI prefix used when encoding a signed [HandoffBundle] for transfer.
const String handoffUriPrefix = 'mesh:handoff:';

/// Maximum base64 character count corresponding to [HandoffBundle.maxBundleBytes].
const int maxHandoffBase64Chars = ((HandoffBundle.maxBundleBytes + 2) ~/ 3) * 4;

/// Encode a signed [HandoffBundle] as a `mesh:handoff:<base64url>` payload.
String encodeHandoffBundle(HandoffBundle bundle) {
  return '$handoffUriPrefix${base64UrlEncode(bundle.rawBytes)}';
}

/// Decode and structurally inspect an unauthenticated [HandoffBundle] from
/// a `mesh:handoff:<base64url>` string or raw base64/base64url text.
///
/// Enforces [maxHandoffBase64Chars] before allocating decoded bytes.
/// Note: [HandoffBundle.fromBytes] validates CBOR structure only; signatures
/// are verified when [MeshInstallation.acceptHandoff] is called.
HandoffBundle decodeHandoffBundle(String input) {
  var normalized = input.trim();
  if (normalized.startsWith(handoffUriPrefix)) {
    normalized = normalized.substring(handoffUriPrefix.length);
  }
  normalized = normalized.replaceAll(RegExp(r'\s+'), '');
  if (normalized.isEmpty) {
    throw const FormatException('Handoff bundle cannot be empty.');
  }
  if (normalized.length > maxHandoffBase64Chars) {
    throw const FormatException('Handoff bundle exceeds maximum size limit.');
  }

  Uint8List bytes;
  try {
    final padded = base64Url.normalize(normalized);
    bytes = base64Url.decode(padded);
  } on FormatException {
    try {
      final padded = base64.normalize(normalized);
      bytes = base64.decode(padded);
    } on FormatException {
      throw const FormatException(
        'Invalid handoff bundle encoding. '
        'Paste the complete mesh:handoff: payload.',
      );
    }
  }

  return HandoffBundle.fromBytes(bytes);
}

/// Format a 32-byte key or nonce into 8-character space-separated hex groups
/// for reliable full-value visual verification.
String formatGroupedHex(Uint8List bytes) {
  final sb = StringBuffer();
  for (var i = 0; i < bytes.length; i++) {
    if (i > 0 && i % 4 == 0) {
      sb.write(' ');
    }
    sb.write(bytes[i].toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

Uint8List _parse32ByteHex(String input, String invalidMessage) =>
    parse32ByteHex(input, invalidMessage: invalidMessage);

/// Parse a 32-byte device nonce from a 64-character hexadecimal string.
Uint8List parseDeviceNonceHex(String input) => _parse32ByteHex(
  input,
  'Enter a 64-character hexadecimal recipient device nonce.',
);

/// Parse a 32-byte Ed25519 persona seed from a 64-character hexadecimal string.
Uint8List parseHexSeed(String input) => _parse32ByteHex(
  input,
  'Enter a 64-character hexadecimal Ed25519 persona seed.',
);
