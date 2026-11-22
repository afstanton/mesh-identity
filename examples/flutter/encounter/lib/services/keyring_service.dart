import 'dart:async';
import 'dart:typed_data';

import 'package:flutter_secure_storage/flutter_secure_storage.dart';

/// Secure storage contract for retaining 32-byte Ed25519 persona signing seeds.
abstract interface class SecureKeyringService {
  /// Save a 32-byte seed for the given 32-byte identity public key.
  Future<void> saveSeed(Uint8List identityKey, Uint8List seed);

  /// Retrieve the 32-byte seed for a specific 32-byte identity public key.
  Future<Uint8List?> getSeed(Uint8List identityKey);

  /// Retrieve all 32-byte identity public keys whose valid seeds are stored in the keyring.
  Future<List<Uint8List>> getAllIdentityKeys();

  /// Retrieve all retained persona seeds currently in the keyring.
  Future<List<Uint8List>> getAllSeeds();

  /// Remove a persona's seed from the keyring.
  Future<void> removeSeed(Uint8List identityKey);

  /// Clear all seeds from the keyring.
  Future<void> clear();
}

String _bytesToHex(Uint8List bytes) {
  final sb = StringBuffer();
  for (final b in bytes) {
    sb.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

final RegExp _hex64Regex = RegExp(r'^[0-9a-fA-F]{64}$');

Uint8List? _tryHexToBytes32(String? hex) {
  if (hex == null || !_hex64Regex.hasMatch(hex)) {
    return null;
  }
  final result = Uint8List(32);
  for (var i = 0; i < 32; i++) {
    final parsed = int.tryParse(hex.substring(i * 2, i * 2 + 2), radix: 16);
    if (parsed == null) return null;
    result[i] = parsed;
  }
  return result;
}

/// Production implementation backed by platform-native secure storage
/// (iOS/macOS Keychain, Android Keystore, Linux SecretService, Windows CredentialStore).
class FlutterSecureKeyringService implements SecureKeyringService {
  final FlutterSecureStorage _storage;
  static const String _prefix = 'persona_seed_';
  static const String _legacyIndexKey = 'persona_index';

  Future<void> _queue = Future<void>.value();

  FlutterSecureKeyringService({FlutterSecureStorage? storage})
    : _storage =
          storage ??
          const FlutterSecureStorage(
            aOptions: AndroidOptions(),
            // Uses the OS login keychain rather than the Data Protection Keychain so
            // sandboxed macOS builds work both in ad-hoc/unsigned open-source builds
            // and Mac App Store builds without requiring keychain-access-groups /
            // provisioning profiles that cause -34018 errSecMissingEntitlement.
            mOptions: MacOsOptions(
              accessibility: KeychainAccessibility.first_unlock_this_device,
              usesDataProtectionKeychain: false,
            ),
            // Bind signing keys to this device so backups cannot restore keys without
            // explicit handoff/voting-lock migration.
            iOptions: IOSOptions(
              accessibility: KeychainAccessibility.first_unlock_this_device,
            ),
          );

  Future<T> _serialized<T>(Future<T> Function() action) {
    final completer = Completer<T>();
    _queue = _queue.then((_) async {
      try {
        final result = await action();
        completer.complete(result);
      } catch (e, st) {
        completer.completeError(e, st);
      }
    });
    return completer.future;
  }

  static void _validateKey(Uint8List identityKey) {
    if (identityKey.length != 32) {
      throw ArgumentError.value(
        identityKey.length,
        'identityKey.length',
        'Identity key must be exactly 32 bytes',
      );
    }
  }

  static void _validateSeed(Uint8List seed) {
    if (seed.length != 32) {
      throw ArgumentError.value(
        seed.length,
        'seed.length',
        'Signing seed must be exactly 32 bytes',
      );
    }
  }

  @override
  Future<void> saveSeed(Uint8List identityKey, Uint8List seed) async {
    _validateKey(identityKey);
    _validateSeed(seed);
    final hexKey = _bytesToHex(identityKey);
    final hexSeed = _bytesToHex(seed);
    return _serialized(() async {
      await _storage.write(key: '$_prefix$hexKey', value: hexSeed);
    });
  }

  @override
  Future<Uint8List?> getSeed(Uint8List identityKey) async {
    _validateKey(identityKey);
    final hexKey = _bytesToHex(identityKey);
    return _serialized(() async {
      final hexSeed = await _storage.read(key: '$_prefix$hexKey');
      return _tryHexToBytes32(hexSeed);
    });
  }

  @override
  Future<List<Uint8List>> getAllIdentityKeys() {
    return _serialized(() async {
      final all = await _storage.readAll();
      final keys = <Uint8List>[];
      for (final entry in all.entries) {
        if (!entry.key.startsWith(_prefix)) continue;
        final keyHex = entry.key.substring(_prefix.length);
        final decodedKey = _tryHexToBytes32(keyHex);
        final decodedSeed = _tryHexToBytes32(entry.value);
        if (decodedKey != null && decodedSeed != null) {
          decodedSeed.fillRange(0, 32, 0);
          keys.add(decodedKey);
        } else {
          decodedSeed?.fillRange(0, 32, 0);
        }
      }
      return keys;
    });
  }

  @override
  Future<List<Uint8List>> getAllSeeds() {
    return _serialized(() async {
      final all = await _storage.readAll();
      final seeds = <Uint8List>[];
      for (final entry in all.entries) {
        if (!entry.key.startsWith(_prefix)) continue;
        final keyHex = entry.key.substring(_prefix.length);
        final decodedKey = _tryHexToBytes32(keyHex);
        final decodedSeed = _tryHexToBytes32(entry.value);
        if (decodedKey != null && decodedSeed != null) {
          seeds.add(decodedSeed);
        } else {
          decodedSeed?.fillRange(0, 32, 0);
        }
      }
      return seeds;
    });
  }

  @override
  Future<void> removeSeed(Uint8List identityKey) async {
    _validateKey(identityKey);
    final hexKey = _bytesToHex(identityKey);
    return _serialized(() async {
      await _storage.delete(key: '$_prefix$hexKey');
    });
  }

  @override
  Future<void> clear() {
    return _serialized(() async {
      final all = await _storage.readAll();
      final keysToDelete = all.keys
          .where((key) => key.startsWith(_prefix) || key == _legacyIndexKey)
          .toList();
      for (final key in keysToDelete) {
        await _storage.delete(key: key);
      }
    });
  }
}

/// In-memory keyring service for headless tests and transient practice mode.
class InMemoryKeyringService implements SecureKeyringService {
  final Map<String, Uint8List> _seeds = {};

  @override
  Future<void> saveSeed(Uint8List identityKey, Uint8List seed) async {
    if (identityKey.length != 32) {
      throw ArgumentError.value(
        identityKey.length,
        'identityKey.length',
        'Identity key must be exactly 32 bytes',
      );
    }
    if (seed.length != 32) {
      throw ArgumentError.value(
        seed.length,
        'seed.length',
        'Signing seed must be exactly 32 bytes',
      );
    }
    // Store a defensive copy of the seed
    _seeds[_bytesToHex(identityKey)] = Uint8List.fromList(seed);
  }

  @override
  Future<Uint8List?> getSeed(Uint8List identityKey) async {
    if (identityKey.length != 32) {
      throw ArgumentError.value(
        identityKey.length,
        'identityKey.length',
        'Identity key must be exactly 32 bytes',
      );
    }
    final found = _seeds[_bytesToHex(identityKey)];
    return found != null ? Uint8List.fromList(found) : null;
  }

  @override
  Future<List<Uint8List>> getAllIdentityKeys() async {
    final keys = <Uint8List>[];
    for (final hexKey in _seeds.keys) {
      final decoded = _tryHexToBytes32(hexKey);
      if (decoded != null) {
        keys.add(decoded);
      }
    }
    return keys;
  }

  @override
  Future<List<Uint8List>> getAllSeeds() async {
    return _seeds.values.map(Uint8List.fromList).toList();
  }

  @override
  Future<void> removeSeed(Uint8List identityKey) async {
    if (identityKey.length != 32) {
      throw ArgumentError.value(
        identityKey.length,
        'identityKey.length',
        'Identity key must be exactly 32 bytes',
      );
    }
    final removed = _seeds.remove(_bytesToHex(identityKey));
    removed?.fillRange(0, removed.length, 0);
  }

  @override
  Future<void> clear() async {
    for (final seed in _seeds.values) {
      seed.fillRange(0, seed.length, 0);
    }
    _seeds.clear();
  }
}
