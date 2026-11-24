import 'dart:typed_data';

/// Format a byte buffer as lowercase hexadecimal.
String bytesToHex(Uint8List bytes) {
  final sb = StringBuffer();
  for (final b in bytes) {
    sb.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

/// Parse a 32-byte value from a 64-character hexadecimal string.
///
/// Ignores surrounding/embedded whitespace and an optional `0x` prefix. Throws
/// a [FormatException] if the input is not 64 valid hexadecimal characters.
Uint8List parse32ByteHex(
  String input, {
  String label = 'Value',
  String? invalidMessage,
}) {
  var normalized = input.replaceAll(RegExp(r'\s+'), '');
  if (normalized.startsWith('0x') || normalized.startsWith('0X')) {
    normalized = normalized.substring(2);
  }
  const expectedHexLength = 64;
  if (normalized.length != expectedHexLength ||
      !RegExp(r'^[0-9a-fA-F]{64}$').hasMatch(normalized)) {
    throw FormatException(
      invalidMessage ?? '$label must be a 64-character hexadecimal string.',
    );
  }
  final bytes = Uint8List(32);
  for (var i = 0; i < 32; i++) {
    bytes[i] = int.parse(normalized.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return bytes;
}
