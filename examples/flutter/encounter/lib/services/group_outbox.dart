import 'dart:convert';
import 'dart:io';

import 'package:mesh_identity/mesh_identity.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';

import 'group_frame_codec.dart';

/// A released [OutgoingMessage] tracked by the durable group outbox.
class StoredOutgoingMessage {
  final String id;
  final OutgoingMessage message;
  final DateTime createdAt;
  final bool isPersisted;

  const StoredOutgoingMessage({
    required this.id,
    required this.message,
    required this.createdAt,
    this.isPersisted = true,
  });
}

/// Result of loading persisted group outbox messages with per-file isolation.
class GroupOutboxLoadResult {
  final List<StoredOutgoingMessage> messages;
  final int unreadableCount;
  final String? directoryError;

  const GroupOutboxLoadResult({
    this.messages = const [],
    this.unreadableCount = 0,
    this.directoryError,
  });
}

/// Durable storage for released group protocol [OutgoingMessage]s after
/// two-phase `save` + `confirmSaved` succeeds.
abstract interface class GroupOutboxService {
  Future<List<StoredOutgoingMessage>> appendMessages(
    List<OutgoingMessage> messages, {
    required DateTime at,
  });

  Future<GroupOutboxLoadResult> loadAll();

  Future<void> deleteMessage(String id);

  Future<void> clearAll();
}

/// Atomic file-backed [GroupOutboxService] storing one JSON record per released
/// message under `<appSupportDir>/group_outbox/`.
class FileGroupOutboxService implements GroupOutboxService {
  static const String _dirName = 'group_outbox';
  static const String _filePrefix = 'msg_';
  static const String _fileSuffix = '.json';
  static const int _maxFileBytes = maxGroupFrameUriChars + 512;

  final Future<Directory> Function() _directoryProvider;
  int _seq = 0;

  FileGroupOutboxService({Future<Directory> Function()? directoryProvider})
    : _directoryProvider = directoryProvider ?? getApplicationSupportDirectory;

  Future<Directory> _resolveDir() async {
    final base = await _directoryProvider();
    return Directory(p.join(base.path, _dirName));
  }

  String _nextId(DateTime at) {
    _seq += 1;
    final micros = at.microsecondsSinceEpoch;
    final seqStr = _seq.toString().padLeft(6, '0');
    return '${micros}_$seqStr';
  }

  @override
  Future<List<StoredOutgoingMessage>> appendMessages(
    List<OutgoingMessage> messages, {
    required DateTime at,
  }) async {
    if (messages.isEmpty) return const [];
    final dir = await _resolveDir();
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }

    final stored = <StoredOutgoingMessage>[];
    for (final msg in messages) {
      final id = _nextId(at);
      final encoded = jsonEncode(<String, dynamic>{
        'id': id,
        'created_at_ms': at.millisecondsSinceEpoch,
        'frame': encodeGroupFrame(msg),
      });
      final bytes = utf8.encode(encoded);
      final targetPath = p.join(dir.path, '$_filePrefix$id$_fileSuffix');
      final tmpPath =
          '$targetPath.tmp.${DateTime.now().microsecondsSinceEpoch}';
      final tmpFile = File(tmpPath);
      try {
        final raf = await tmpFile.open(mode: FileMode.writeOnly);
        try {
          await raf.writeFrom(bytes);
          await raf.flush();
        } finally {
          await raf.close();
        }
        await tmpFile.rename(targetPath);
      } catch (_) {
        if (await tmpFile.exists()) {
          await tmpFile.delete();
        }
        rethrow;
      }
      stored.add(StoredOutgoingMessage(id: id, message: msg, createdAt: at));
    }
    return stored;
  }

  @override
  Future<GroupOutboxLoadResult> loadAll() async {
    final Directory dir;
    try {
      dir = await _resolveDir();
      if (!await dir.exists()) {
        return const GroupOutboxLoadResult();
      }
    } catch (e) {
      return GroupOutboxLoadResult(
        directoryError: 'Unable to open group outbox directory: $e',
      );
    }

    final messages = <StoredOutgoingMessage>[];
    var unreadable = 0;

    try {
      await for (final entity in dir.list(followLinks: false)) {
        if (entity is! File) continue;
        final name = p.basename(entity.path);
        if (!name.startsWith(_filePrefix) || !name.endsWith(_fileSuffix)) {
          continue;
        }
        try {
          final stat = await entity.stat();
          if (stat.size <= 0 || stat.size > _maxFileBytes) {
            unreadable += 1;
            continue;
          }
          final content = await entity.readAsString();
          final map = jsonDecode(content);
          if (map is! Map<String, dynamic>) {
            unreadable += 1;
            continue;
          }
          final id = map['id'];
          final createdAtMs = map['created_at_ms'];
          final frameStr = map['frame'];
          if (id is! String || createdAtMs is! int || frameStr is! String) {
            unreadable += 1;
            continue;
          }
          final msg = decodeGroupFrame(frameStr);
          messages.add(
            StoredOutgoingMessage(
              id: id,
              message: msg,
              createdAt: DateTime.fromMillisecondsSinceEpoch(createdAtMs),
            ),
          );
        } catch (_) {
          unreadable += 1;
        }
      }
    } catch (e) {
      return GroupOutboxLoadResult(
        messages: messages,
        unreadableCount: unreadable,
        directoryError: 'Failed to scan group outbox directory: $e',
      );
    }

    messages.sort((a, b) => a.id.compareTo(b.id));
    return GroupOutboxLoadResult(
      messages: messages,
      unreadableCount: unreadable,
    );
  }

  @override
  Future<void> deleteMessage(String id) async {
    if (!RegExp(r'^[0-9_]+$').hasMatch(id)) return;
    final dir = await _resolveDir();
    final file = File(p.join(dir.path, '$_filePrefix$id$_fileSuffix'));
    if (await file.exists()) {
      await file.delete();
    }
  }

  @override
  Future<void> clearAll() async {
    final dir = await _resolveDir();
    if (await dir.exists()) {
      await dir.delete(recursive: true);
    }
  }
}

/// Deterministic in-memory [GroupOutboxService] for unit and widget tests.
class InMemoryGroupOutboxService implements GroupOutboxService {
  final List<StoredOutgoingMessage> _messages = [];
  int _seq = 0;

  @override
  Future<List<StoredOutgoingMessage>> appendMessages(
    List<OutgoingMessage> messages, {
    required DateTime at,
  }) async {
    final added = <StoredOutgoingMessage>[];
    for (final msg in messages) {
      _seq += 1;
      final item = StoredOutgoingMessage(
        id: '${at.microsecondsSinceEpoch}_${_seq.toString().padLeft(6, '0')}',
        message: msg,
        createdAt: at,
      );
      _messages.add(item);
      added.add(item);
    }
    return added;
  }

  @override
  Future<GroupOutboxLoadResult> loadAll() async {
    return GroupOutboxLoadResult(messages: List.of(_messages));
  }

  @override
  Future<void> deleteMessage(String id) async {
    _messages.removeWhere((m) => m.id == id);
  }

  @override
  Future<void> clearAll() async {
    _messages.clear();
  }
}
