import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Secure storage contract for retaining 32-byte Ed25519 persona signing seeds.
abstract interface class SecureKeyringService {
  /// Save a 32-byte seed for the given identity public key.
  Future<void> saveSeed(Uint8List identityKey, Uint8List seed);

  /// Retrieve the 32-byte seed for a specific identity public key.
  Future<Uint8List?> getSeed(Uint8List identityKey);

  /// Retrieve all retained persona seeds currently in the keyring.
  Future<List<Uint8List>> getAllSeeds();

  /// Remove a persona's seed from the keyring.
  Future<void> removeSeed(Uint8List identityKey);

  /// Clear all seeds from the keyring.
  Future<void> clear();
}

/// Production implementation backed by platform-native secure storage
/// (iOS/macOS Keychain, Android Keystore, Linux SecretService, Windows CredentialStore).
class FlutterSecureKeyringService implements SecureKeyringService {
  final FlutterSecureStorage _storage;
  static const String _prefix = 'persona_seed_';
  static const String _indexKey = 'persona_index';

  FlutterSecureKeyringService({FlutterSecureStorage? storage})
    : _storage =
          storage ??
          const FlutterSecureStorage(
            aOptions: AndroidOptions(),
            mOptions: MacOsOptions(
              accessibility: KeychainAccessibility.first_unlock,
            ),
            iOptions: IOSOptions(
              accessibility: KeychainAccessibility.first_unlock,
            ),
          );

  static String _bytesToHex(Uint8List bytes) {
    final sb = StringBuffer();
    for (final b in bytes) {
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }

  static Uint8List _hexToBytes(String hex) {
    final result = Uint8List(hex.length ~/ 2);
    for (var i = 0; i < result.length; i++) {
      result[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    }
    return result;
  }

  Future<Set<String>> _loadIndex() async {
    final raw = await _storage.read(key: _indexKey);
    if (raw == null || raw.isEmpty) return <String>{};
    return raw.split(',').where((s) => s.isNotEmpty).toSet();
  }

  Future<void> _saveIndex(Set<String> index) async {
    await _storage.write(key: _indexKey, value: index.join(','));
  }

  @override
  Future<void> saveSeed(Uint8List identityKey, Uint8List seed) async {
    final hexKey = _bytesToHex(identityKey);
    final hexSeed = _bytesToHex(seed);

    await _storage.write(key: '$_prefix$hexKey', value: hexSeed);
    final index = await _loadIndex();
    index.add(hexKey);
    await _saveIndex(index);
  }

  @override
  Future<Uint8List?> getSeed(Uint8List identityKey) async {
    final hexKey = _bytesToHex(identityKey);
    final hexSeed = await _storage.read(key: '$_prefix$hexKey');
    if (hexSeed == null || hexSeed.length != 64) return null;
    return _hexToBytes(hexSeed);
  }

  @override
  Future<List<Uint8List>> getAllSeeds() async {
    final index = await _loadIndex();
    final seeds = <Uint8List>[];

    for (final hexKey in index) {
      final hexSeed = await _storage.read(key: '$_prefix$hexKey');
      if (hexSeed != null && hexSeed.length == 64) {
        seeds.add(_hexToBytes(hexSeed));
      }
    }
    return seeds;
  }

  @override
  Future<void> removeSeed(Uint8List identityKey) async {
    final hexKey = _bytesToHex(identityKey);
    await _storage.delete(key: '$_prefix$hexKey');
    final index = await _loadIndex();
    index.remove(hexKey);
    await _saveIndex(index);
  }

  @override
  Future<void> clear() async {
    final index = await _loadIndex();
    for (final hexKey in index) {
      await _storage.delete(key: '$_prefix$hexKey');
    }
    await _storage.delete(key: _indexKey);
  }
}

/// In-memory keyring service for headless tests and transient practice mode.
class InMemoryKeyringService implements SecureKeyringService {
  final Map<String, Uint8List> _seeds = {};

  static String _bytesToHex(Uint8List bytes) {
    final sb = StringBuffer();
    for (final b in bytes) {
      sb.write(b.toRadixString(16).padLeft(2, '0'));
    }
    return sb.toString();
  }

  @override
  Future<void> saveSeed(Uint8List identityKey, Uint8List seed) async {
    // Store a defensive copy of the seed
    _seeds[_bytesToHex(identityKey)] = Uint8List.fromList(seed);
  }

  @override
  Future<Uint8List?> getSeed(Uint8List identityKey) async {
    final found = _seeds[_bytesToHex(identityKey)];
    return found != null ? Uint8List.fromList(found) : null;
  }

  @override
  Future<List<Uint8List>> getAllSeeds() async {
    return _seeds.values.map(Uint8List.fromList).toList();
  }

  @override
  Future<void> removeSeed(Uint8List identityKey) async {
    _seeds.remove(_bytesToHex(identityKey));
  }

  @override
  Future<void> clear() async {
    _seeds.clear();
  }
}
