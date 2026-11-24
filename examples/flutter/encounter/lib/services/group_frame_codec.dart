import 'dart:convert';
import 'dart:typed_data';

import 'package:mesh_identity/mesh_identity.dart';

import 'hex_utils.dart';

/// URI prefix used when encoding a released [OutgoingMessage] for transfer.
const String groupFrameUriPrefix = 'mesh:group:';

/// Defensive ceiling on encoded `mesh:group:` URI length (128 KiB raw frame
/// base64url-encoded plus JSON envelope metadata).
const int maxGroupFrameUriChars = 256 * 1024;

String _bytesToHex(Uint8List bytes) => bytesToHex(bytes);

Uint8List _parse32ByteHex(String hex, String label) =>
    parse32ByteHex(hex, label: label);

/// Parse a 32-byte SHA-256 genesis digest or authenticator from hex.
Uint8List parseDigestHex(String input) =>
    _parse32ByteHex(input, 'Genesis digest');

/// Encode an [OutgoingMessage] as a copy-pasteable `mesh:group:<base64url>`
/// wire payload.
String encodeGroupFrame(OutgoingMessage message) {
  final map = <String, dynamic>{
    'from': _bytesToHex(message.from),
    'to': message.to.map(_bytesToHex).toList(growable: false),
    'tag': message.tag.value,
    'bytes': base64UrlEncode(message.bytes),
    if (message.authenticator != null)
      'authenticator': _bytesToHex(message.authenticator!),
  };
  final jsonBytes = utf8.encode(jsonEncode(map));
  return '$groupFrameUriPrefix${base64UrlEncode(jsonBytes)}';
}

/// Decode and validate an [OutgoingMessage] from a `mesh:group:<base64url>`
/// payload, enforcing [maxGroupFrameUriChars] and
/// [MeshGroupHandle.maxGroupFrameBytes] before allocating.
OutgoingMessage decodeGroupFrame(String input) {
  var normalized = input.trim();
  if (normalized.startsWith(groupFrameUriPrefix)) {
    normalized = normalized.substring(groupFrameUriPrefix.length);
  }
  normalized = normalized.replaceAll(RegExp(r'\s+'), '');
  if (normalized.isEmpty) {
    throw const FormatException('Group frame payload cannot be empty.');
  }
  if (normalized.length > maxGroupFrameUriChars) {
    throw const FormatException('Group frame payload exceeds maximum size.');
  }

  final String jsonStr;
  try {
    final padded = base64Url.normalize(normalized);
    jsonStr = utf8.decode(base64Url.decode(padded));
  } on FormatException {
    throw const FormatException(
      'Invalid group frame encoding. Paste the complete mesh:group: payload.',
    );
  }

  final dynamic decoded;
  try {
    decoded = jsonDecode(jsonStr);
  } on FormatException {
    throw const FormatException('Malformed JSON inside group frame payload.');
  }
  if (decoded is! Map<String, dynamic>) {
    throw const FormatException('Group frame payload must be a JSON object.');
  }

  final fromHex = decoded['from'];
  if (fromHex is! String) {
    throw const FormatException('Group frame missing sender public key.');
  }
  final from = _parse32ByteHex(fromHex, 'Sender public key');

  final rawTo = decoded['to'];
  if (rawTo is! List<dynamic>) {
    throw const FormatException('Group frame missing recipient list.');
  }
  if (rawTo.length > MeshGroupHandle.maxGroupMembers) {
    throw const FormatException('Group frame recipient list exceeds limit.');
  }
  final to = <Uint8List>[];
  for (final item in rawTo) {
    if (item is! String) {
      throw const FormatException('Recipient key must be a hex string.');
    }
    to.add(_parse32ByteHex(item, 'Recipient public key'));
  }

  final tagInt = decoded['tag'];
  if (tagInt is! int) {
    throw const FormatException('Group frame missing message tag.');
  }
  final MessageTag tag;
  try {
    tag = MessageTag.fromValue(tagInt);
  } on ArgumentError {
    throw const FormatException('Unknown group message tag.');
  }

  final bytesB64 = decoded['bytes'];
  if (bytesB64 is! String || bytesB64.isEmpty) {
    throw const FormatException('Group frame missing wire bytes.');
  }
  if (bytesB64.length > ((MeshGroupHandle.maxGroupFrameBytes + 2) ~/ 3) * 4) {
    throw const FormatException('Group frame wire bytes exceed 128 KiB limit.');
  }
  final Uint8List wireBytes;
  try {
    wireBytes = base64Url.decode(base64Url.normalize(bytesB64));
  } on FormatException {
    throw const FormatException('Invalid base64 wire bytes in group frame.');
  }
  if (wireBytes.isEmpty ||
      wireBytes.length > MeshGroupHandle.maxGroupFrameBytes) {
    throw const FormatException('Group frame wire bytes exceed 128 KiB limit.');
  }

  Uint8List? authenticator;
  final authHex = decoded['authenticator'];
  if (authHex != null) {
    if (authHex is! String) {
      throw const FormatException('Authenticator must be a hex string.');
    }
    authenticator = _parse32ByteHex(authHex, 'Authenticator');
  }

  return OutgoingMessage(
    from: from,
    to: to,
    tag: tag,
    bytes: wireBytes,
    authenticator: authenticator,
  );
}
