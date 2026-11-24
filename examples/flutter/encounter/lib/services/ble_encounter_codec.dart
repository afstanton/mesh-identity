import 'dart:typed_data';

/// GATT Service UUID for Encounter offline BLE payload exchange.
const String bleEncounterServiceUuid = '7b9a4c10-6e2d-4a8e-9f1b-0d3c5e7a9001';

/// GATT Characteristic UUID carrying the Initiator's Offer payload.
const String bleOfferCharUuid = '7b9a4c10-6e2d-4a8e-9f1b-0d3c5e7a9002';

/// GATT Characteristic UUID carrying the Responder's Response payload.
const String bleResponseCharUuid = '7b9a4c10-6e2d-4a8e-9f1b-0d3c5e7a9003';

/// GATT Characteristic UUID carrying the Initiator's Reveal payload.
const String bleRevealCharUuid = '7b9a4c10-6e2d-4a8e-9f1b-0d3c5e7a9004';

/// Maximum Encounter payload size in bytes (matching `mesh_identity` ceiling).
const int maxBleEncounterPayloadBytes = 512;

/// Number of header bytes prefixed to every BLE GATT chunk:
/// `[seqIndex, totalChunks, totalLenHi, totalLenLo]`.
const int bleChunkHeaderBytes = 4;

/// Maximum number of chunks permitted for a single Encounter payload.
const int maxBleChunks = 32;

/// Coarse proximity band derived from BLE RSSI.
enum BleProximityBand { immediate, near, far }

/// Classify an RSSI reading (in dBm) into a [BleProximityBand].
BleProximityBand classifyBleProximity(int rssi) {
  if (rssi >= -55) return BleProximityBand.immediate;
  if (rssi >= -72) return BleProximityBand.near;
  return BleProximityBand.far;
}

/// Split an Encounter [payload] (1..512 bytes) into chunked GATT frames
/// prefixed with `[seqIndex, totalChunks, totalLenHi, totalLenLo]`.
List<Uint8List> encodeBleChunks(
  Uint8List payload, {
  int maxChunkPayloadBytes = 180,
}) {
  if (payload.isEmpty || payload.length > maxBleEncounterPayloadBytes) {
    throw FormatException(
      'BLE Encounter payload must be 1..$maxBleEncounterPayloadBytes bytes.',
    );
  }
  if (maxChunkPayloadBytes < 16) {
    throw ArgumentError.value(
      maxChunkPayloadBytes,
      'maxChunkPayloadBytes',
      'Chunk payload size must be at least 16 bytes.',
    );
  }

  final totalLen = payload.length;
  final totalChunks =
      (totalLen + maxChunkPayloadBytes - 1) ~/ maxChunkPayloadBytes;
  if (totalChunks > maxBleChunks) {
    throw FormatException('Payload requires more than $maxBleChunks chunks.');
  }

  final frames = <Uint8List>[];
  for (var seq = 0; seq < totalChunks; seq++) {
    final start = seq * maxChunkPayloadBytes;
    final end = start + maxChunkPayloadBytes < totalLen
        ? start + maxChunkPayloadBytes
        : totalLen;
    final sliceLen = end - start;
    final frame = Uint8List(bleChunkHeaderBytes + sliceLen);
    frame[0] = seq;
    frame[1] = totalChunks;
    frame[2] = (totalLen >> 8) & 0xFF;
    frame[3] = totalLen & 0xFF;
    frame.setRange(
      bleChunkHeaderBytes,
      bleChunkHeaderBytes + sliceLen,
      payload,
      start,
    );
    frames.add(frame);
  }
  return frames;
}

/// Stateful reassembler for chunked BLE Encounter GATT frames.
class BleChunkReassembler {
  int? _expectedTotalChunks;
  int? _expectedTotalLength;
  final Map<int, Uint8List> _chunks = {};

  /// Add a received GATT [frame]. Returns the complete reassembled payload once
  /// all chunks have arrived, or `null` if more chunks are needed.
  ///
  /// Throws a [FormatException] on malformed headers, out-of-range lengths,
  /// or inconsistent chunk metadata.
  Uint8List? addChunk(Uint8List frame) {
    if (frame.length <= bleChunkHeaderBytes ||
        frame.length > bleChunkHeaderBytes + maxBleEncounterPayloadBytes) {
      reset();
      throw const FormatException('Invalid BLE chunk frame length.');
    }

    final seq = frame[0];
    final totalChunks = frame[1];
    final totalLen = (frame[2] << 8) | frame[3];

    if (totalLen < 1 || totalLen > maxBleEncounterPayloadBytes) {
      reset();
      throw const FormatException('Invalid BLE payload total length.');
    }
    if (totalChunks < 1 || totalChunks > maxBleChunks) {
      reset();
      throw const FormatException('Invalid BLE total chunk count.');
    }
    if (seq >= totalChunks) {
      reset();
      throw const FormatException('BLE chunk sequence index out of bounds.');
    }

    if (_expectedTotalChunks == null) {
      _expectedTotalChunks = totalChunks;
      _expectedTotalLength = totalLen;
    } else if (_expectedTotalChunks != totalChunks ||
        _expectedTotalLength != totalLen) {
      reset();
      throw const FormatException('Inconsistent BLE chunk metadata.');
    }

    final data = Uint8List.sublistView(frame, bleChunkHeaderBytes);
    _chunks[seq] = Uint8List.fromList(data);

    if (_chunks.length < totalChunks) {
      return null;
    }

    var assembledLen = 0;
    for (var i = 0; i < totalChunks; i++) {
      final part = _chunks[i];
      if (part == null) return null;
      assembledLen += part.length;
    }
    if (assembledLen != totalLen) {
      reset();
      throw const FormatException('Reassembled BLE payload length mismatch.');
    }

    final result = Uint8List(totalLen);
    var offset = 0;
    for (var i = 0; i < totalChunks; i++) {
      final part = _chunks[i]!;
      result.setRange(offset, offset + part.length, part);
      offset += part.length;
    }
    reset();
    return result;
  }

  /// Clear any partially received chunks.
  void reset() {
    _expectedTotalChunks = null;
    _expectedTotalLength = null;
    _chunks.clear();
  }
}
