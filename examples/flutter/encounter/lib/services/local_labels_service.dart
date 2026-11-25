import 'dart:convert';
import 'dart:io';

import 'package:path_provider/path_provider.dart';

/// Persistent local display labels for personas and groups (never transmitted
/// over the network or stored inside cryptographic snapshots).
abstract interface class LocalLabelsService {
  Future<({Map<String, String> personas, Map<String, String> groups})>
  loadAll();

  Future<void> saveAll({
    required Map<String, String> personas,
    required Map<String, String> groups,
  });
}

/// File-backed [LocalLabelsService] storing `local_labels.json` in
/// Application Support.
class FileLocalLabelsService implements LocalLabelsService {
  static const String _fileName = 'local_labels.json';

  Future<File> _file() async {
    final dir = await getApplicationSupportDirectory();
    if (!await dir.exists()) {
      await dir.create(recursive: true);
    }
    return File('${dir.path}${Platform.pathSeparator}$_fileName');
  }

  @override
  Future<({Map<String, String> personas, Map<String, String> groups})>
  loadAll() async {
    try {
      final file = await _file();
      if (!await file.exists()) {
        return (personas: <String, String>{}, groups: <String, String>{});
      }
      final raw = await file.readAsString();
      if (raw.trim().isEmpty) {
        return (personas: <String, String>{}, groups: <String, String>{});
      }
      final decoded = jsonDecode(raw);
      if (decoded is! Map) {
        return (personas: <String, String>{}, groups: <String, String>{});
      }
      Map<String, String> readMap(String key) {
        final section = decoded[key];
        if (section is! Map) return <String, String>{};
        return section.map((k, v) => MapEntry(k.toString(), v.toString()));
      }

      return (personas: readMap('personas'), groups: readMap('groups'));
    } catch (_) {
      return (personas: <String, String>{}, groups: <String, String>{});
    }
  }

  @override
  Future<void> saveAll({
    required Map<String, String> personas,
    required Map<String, String> groups,
  }) async {
    final file = await _file();
    final encoded = jsonEncode({'personas': personas, 'groups': groups});
    await file.writeAsString(encoded, flush: true);
  }
}

/// In-memory [LocalLabelsService] for deterministic unit and widget tests.
class InMemoryLocalLabelsService implements LocalLabelsService {
  Map<String, String> _personas = {};
  Map<String, String> _groups = {};

  @override
  Future<({Map<String, String> personas, Map<String, String> groups})>
  loadAll() async {
    return (
      personas: Map<String, String>.from(_personas),
      groups: Map<String, String>.from(_groups),
    );
  }

  @override
  Future<void> saveAll({
    required Map<String, String> personas,
    required Map<String, String> groups,
  }) async {
    _personas = Map<String, String>.from(personas);
    _groups = Map<String, String>.from(groups);
  }
}
