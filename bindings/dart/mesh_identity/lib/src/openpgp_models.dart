part of 'installation.dart';

/// Supported OpenPGP certificate profile format.
enum OpenPgpProfile {
  /// OpenPGP v4 profile (RFC 4880, EdDSALegacy).
  v4(0),

  /// OpenPGP v6 profile (RFC 9580, Ed25519).
  v6(1);

  const OpenPgpProfile(this.value);

  /// Integer value matching native FFI representation.
  final int value;

  static OpenPgpProfile fromValue(int val) {
    for (final p in values) {
      if (p.value == val) return p;
    }
    throw ArgumentError.value(val, 'val', 'Unknown OpenPgpProfile value');
  }
}

/// An inspected subkey contained within an OpenPGP certificate.
class OpenPgpSubkey {
  const OpenPgpSubkey({
    required this.fingerprint,
    required this.algorithm,
    required this.publicKeyBytes,
  });

  /// The hex-encoded fingerprint of the subkey.
  final String fingerprint;

  /// The public key algorithm identifier (e.g. "Ed25519", "EdDSALegacy").
  final String algorithm;

  /// The raw public key bytes.
  final Uint8List publicKeyBytes;

  factory OpenPgpSubkey.fromJson(Map<String, dynamic> json) {
    return OpenPgpSubkey(
      fingerprint: json['fingerprint'] as String,
      algorithm: json['algorithm'] as String,
      publicKeyBytes: _hexToBytes(json['key_bytes'] as String),
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is OpenPgpSubkey &&
          other.fingerprint == fingerprint &&
          other.algorithm == algorithm &&
          _bytesEqual(other.publicKeyBytes, publicKeyBytes);

  @override
  int get hashCode =>
      Object.hash(fingerprint, algorithm, Object.hashAll(publicKeyBytes));

  @override
  String toString() =>
      'OpenPgpSubkey(fp: $fingerprint, algo: $algorithm, bytes: ${publicKeyBytes.length})';
}

/// Inspected details of an OpenPGP public key or certificate.
///
/// **Security Warning**: The returned certificate details ([userIds], [fingerprint], [subkeys])
/// are unauthenticated and have NOT been verified against or bound to any Mesh identity.
/// Treat these fields as untrusted/attacker-controlled until imported and verified.
class OpenPgpCertificate {
  const OpenPgpCertificate({
    required this.fingerprint,
    required this.version,
    required this.algorithm,
    required this.primaryKeyBytes,
    required this.userIds,
    required this.subkeys,
  });

  /// The hex-encoded fingerprint of the primary key.
  final String fingerprint;

  /// Key version (typically 4 or 6).
  final int version;

  /// Public key algorithm (e.g. "EdDSALegacy", "Ed25519", "RSA").
  final String algorithm;

  /// The raw primary public key bytes.
  final Uint8List primaryKeyBytes;

  /// List of user ID strings bound to this certificate.
  ///
  /// **Warning**: These strings are unauthenticated attacker-controlled inputs
  /// until bound to an identity via [MeshInstallation.importOpenPgpPeer].
  final List<String> userIds;

  /// List of subkeys contained in this certificate.
  final List<OpenPgpSubkey> subkeys;

  /// Parse and inspect an OpenPGP public key or certificate from raw bytes or ASCII armor.
  ///
  /// **Security Warning**: The returned certificate details are unauthenticated and
  /// have NOT been verified against any Mesh identity.
  static OpenPgpCertificate fromBytes(Uint8List bytes) {
    if (bytes.isEmpty ||
        bytes.length > MeshInstallation.maxOpenPgpCertificateBytes) {
      throw const InvalidArgumentsException(
        'Certificate bytes must be non-empty and <= 256 KiB',
      );
    }
    return using((Arena arena) {
      final certPtr = arena<ffi.Uint8>(bytes.length);
      certPtr.asTypedList(bytes.length).setAll(0, bytes);
      final outJson = arena<ffi.Pointer<ffi.Char>>();
      final res = mesh_openpgp_inspect_certificate(
        certPtr,
        bytes.length,
        outJson,
      );
      MeshIdentityBindings.checkResult(
        res,
        'Failed to inspect OpenPGP certificate',
      );
      final jsonPtr = outJson.value;
      try {
        final jsonStr = jsonPtr.cast<Utf8>().toDartString();
        final map = jsonDecode(jsonStr) as Map<String, dynamic>;
        return OpenPgpCertificate.fromJson(map);
      } finally {
        mesh_string_free(jsonPtr);
      }
    });
  }

  factory OpenPgpCertificate.fromJson(Map<String, dynamic> json) {
    final subkeysList =
        (json['subkeys'] as List<dynamic>?)
            ?.map((e) => OpenPgpSubkey.fromJson(e as Map<String, dynamic>))
            .toList() ??
        const [];
    final uids =
        (json['user_ids'] as List<dynamic>?)
            ?.map((e) => e as String)
            .toList() ??
        const [];
    return OpenPgpCertificate(
      fingerprint: json['fingerprint'] as String,
      version: json['version'] as int,
      algorithm: json['algorithm'] as String,
      primaryKeyBytes: _hexToBytes(json['primary_key_bytes'] as String),
      userIds: uids,
      subkeys: subkeysList,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is OpenPgpCertificate &&
          other.fingerprint == fingerprint &&
          other.version == version &&
          other.algorithm == algorithm &&
          _bytesEqual(other.primaryKeyBytes, primaryKeyBytes) &&
          _listsEqual(other.userIds, userIds) &&
          _listsEqual(other.subkeys, subkeys);

  @override
  int get hashCode => Object.hash(
    fingerprint,
    version,
    algorithm,
    Object.hashAll(primaryKeyBytes),
    Object.hashAll(userIds),
    Object.hashAll(subkeys),
  );

  @override
  String toString() =>
      'OpenPgpCertificate(fp: $fingerprint, v$version, uids: $userIds, subkeys: ${subkeys.length})';
}

/// Provenance metadata confirming a successful certificate import.
class OpenPgpProvenance {
  const OpenPgpProvenance({
    required this.primaryFingerprint,
    required this.signingKeyFingerprint,
    required this.userId,
  });

  /// Hex-encoded fingerprint of the certificate's primary key.
  final String primaryFingerprint;

  /// Hex-encoded fingerprint of the specific key matching the Mesh identity.
  final String signingKeyFingerprint;

  /// The user ID bound to this certification.
  final String userId;

  factory OpenPgpProvenance.fromJson(Map<String, dynamic> json) {
    return OpenPgpProvenance(
      primaryFingerprint: json['primary_fingerprint'] as String,
      signingKeyFingerprint: json['signing_key_fingerprint'] as String,
      userId: json['user_id'] as String,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is OpenPgpProvenance &&
          other.primaryFingerprint == primaryFingerprint &&
          other.signingKeyFingerprint == signingKeyFingerprint &&
          other.userId == userId;

  @override
  int get hashCode =>
      Object.hash(primaryFingerprint, signingKeyFingerprint, userId);

  @override
  String toString() =>
      'OpenPgpProvenance(primary: $primaryFingerprint, signing: $signingKeyFingerprint, uid: "$userId")';
}

/// The result of importing an owned OpenPGP secret key certificate into an installation.
class OpenPgpOwnedImportResult {
  const OpenPgpOwnedImportResult({
    required this.provenance,
    required this.seed,
  });

  /// The cryptographic provenance tracking the bound OpenPGP certificate.
  final OpenPgpProvenance provenance;

  /// The 32-byte Ed25519 signing seed extracted from the unlocked OpenPGP secret key.
  ///
  /// Callers should retain this seed in secure storage (alongside other persona seeds)
  /// so that the installation can be restored from snapshots via [MeshInstallation.restore].
  final Uint8List seed;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is OpenPgpOwnedImportResult &&
          other.provenance == provenance &&
          _bytesEqual(other.seed, seed);

  @override
  int get hashCode => Object.hash(provenance, Object.hashAll(seed));

  @override
  String toString() =>
      'OpenPgpOwnedImportResult(provenance: $provenance, seed: 32 bytes)';
}

/// A detached third-party signature cross-signing a peer's OpenPGP key.
class PeerSignature {
  const PeerSignature({required this.label, required this.bytes});

  /// The descriptive name of the certification signature (e.g. "peer-certification.sig").
  final String label;

  /// The raw signature packet bytes.
  final Uint8List bytes;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is PeerSignature &&
          other.label == label &&
          _bytesEqual(other.bytes, bytes);

  @override
  int get hashCode => Object.hash(label, Object.hashAll(bytes));

  @override
  String toString() => 'PeerSignature($label: ${bytes.length} bytes)';
}

/// Complete artifact bundle emitted by confirming an OpenPGP export preview.
class OpenPgpArtifacts {
  const OpenPgpArtifacts({
    required this.certificate,
    required this.detachedSignature,
    required this.peerSignatures,
  });

  /// The primary OpenPGP transferable public key / certificate bytes.
  final Uint8List certificate;

  /// Detached OpenPGP signature bytes over the document provided in preview.
  final Uint8List detachedSignature;

  /// List of detached cross-certification signatures issued for a peer, if any.
  final List<PeerSignature> peerSignatures;
}

/// An export preview awaiting user confirmation.
///
/// CRITICAL: Enforces privacy disclosure of [privacyWarning] before confirming.
/// Confirmation consumes the preview handle even if issuance fails.
class OpenPgpExportPreview implements ffi.Finalizable {
  /// The statutory user-facing privacy disclosure that must be presented to the user.
  static const String privacyWarning =
      'Anyone who has seen this Mesh public key can recognize it in the OpenPGP certificate. Recipients can keep or share a copy.';

  /// Internal constructor for [MeshInstallation.createOpenPgpPreview].
  ///
  /// Constructor is library-private to prevent external construction with arbitrary raw pointers.
  OpenPgpExportPreview._({
    required ffi.Pointer<ffi.Void> handle,
    required this.userId,
    required this.createdSeconds,
    required this.profile,
    required Uint8List document,
    this.peerCertificationFingerprint,
    this.peerCertificationUserId,
    required this.warning,
  }) : _handle = handle,
       document = Uint8List.fromList(document).asUnmodifiableView() {
    _finalizer.attach(this, handle, detach: this);
  }

  static final ffi.NativeFinalizer _finalizer = ffi.NativeFinalizer(
    ffi.Native.addressOf(mesh_openpgp_preview_free),
  );

  ffi.Pointer<ffi.Void> _handle;

  /// The user ID bound to this certificate.
  final String userId;

  /// Creation timestamp in seconds since UNIX epoch.
  final int createdSeconds;

  /// The certificate profile (v4 or v6).
  final OpenPgpProfile profile;

  /// The unmodifiable document to be signed with a detached signature.
  final Uint8List document;

  /// Fingerprint of the peer certificate target for cross-certification, if any.
  final String? peerCertificationFingerprint;

  /// User ID of the peer certificate target for cross-certification, if any.
  final String? peerCertificationUserId;

  /// The statutory privacy warning text returned from the core crate.
  final String warning;

  /// Whether this preview has been confirmed or disposed.
  bool get isDisposed => _handle == ffi.nullptr;

  void _checkDisposed() {
    if (isDisposed) {
      throw const OpenPgpPreviewExpiredException(
        'OpenPgpExportPreview has already been confirmed or disposed.',
      );
    }
  }

  /// Confirm this export preview, consuming the preview session and issuing [OpenPgpArtifacts].
  ///
  /// [installation] must be the active installation and must have the same persona selected
  /// as when the preview was created.
  OpenPgpArtifacts confirm(MeshInstallation installation) {
    _checkDisposed();
    if (installation.isDisposed) {
      throw const DisposedException(
        'MeshInstallation is disposed and cannot confirm OpenPGP export.',
      );
    }

    // Resolve and validate installation handle BEFORE detaching the preview
    // finalizer so a disposed/poisoned installation never leaks the preview.
    final instPtr = installation.nativeHandle;

    return using((Arena arena) {
      final outCertPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outCertLen = arena<ffi.Size>();
      final outDetachedPtr = arena<ffi.Pointer<ffi.Uint8>>();
      final outDetachedLen = arena<ffi.Size>();
      final outPeerSigsJson = arena<ffi.Pointer<ffi.Char>>();

      // Taking ownership: detach finalizer so double-free is avoided
      _finalizer.detach(this);
      final previewPtr = _handle;
      _handle = ffi.nullptr;

      final res = mesh_openpgp_preview_confirm(
        previewPtr,
        instPtr,
        outCertPtr,
        outCertLen,
        outDetachedPtr,
        outDetachedLen,
        outPeerSigsJson,
      );
      MeshIdentityBindings.checkResult(res, 'Failed to confirm OpenPGP export');

      final certPtr = outCertPtr.value;
      final certLen = outCertLen.value;
      final detachedPtr = outDetachedPtr.value;
      final detachedLen = outDetachedLen.value;
      final peerSigsPtr = outPeerSigsJson.value;

      try {
        final certBytes = Uint8List.fromList(certPtr.asTypedList(certLen));
        final detachedBytes = Uint8List.fromList(
          detachedPtr.asTypedList(detachedLen),
        );

        final peerSignatures = <PeerSignature>[];
        if (peerSigsPtr != ffi.nullptr) {
          final jsonStr = peerSigsPtr.cast<Utf8>().toDartString();
          final list = jsonDecode(jsonStr) as List<dynamic>;
          for (final item in list) {
            final map = item as Map<String, dynamic>;
            peerSignatures.add(
              PeerSignature(
                label: map['label'] as String,
                bytes: _hexToBytes(map['signature_hex'] as String),
              ),
            );
          }
        }

        return OpenPgpArtifacts(
          certificate: certBytes,
          detachedSignature: detachedBytes,
          peerSignatures: peerSignatures,
        );
      } finally {
        mesh_buffer_free(certPtr, certLen);
        mesh_buffer_free(detachedPtr, detachedLen);
        if (peerSigsPtr != ffi.nullptr) {
          mesh_string_free(peerSigsPtr);
        }
      }
    });
  }

  /// Explicitly release native resources held by this preview.
  void dispose() {
    if (!isDisposed) {
      _finalizer.detach(this);
      mesh_openpgp_preview_free(_handle);
      _handle = ffi.nullptr;
    }
  }
}

bool _listsEqual<T>(List<T> a, List<T> b) {
  if (identical(a, b)) return true;
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

Uint8List _hexToBytes(String hex) {
  final clean = hex.replaceAll(' ', '');
  if (clean.length.isOdd) {
    throw FormatException('Hex string must have an even length', hex);
  }
  final len = clean.length ~/ 2;
  final bytes = Uint8List(len);
  for (var i = 0; i < len; i++) {
    final b = int.tryParse(clean.substring(i * 2, i * 2 + 2), radix: 16);
    if (b == null) {
      throw FormatException('Non-hexadecimal character in hex string', hex);
    }
    bytes[i] = b;
  }
  return bytes;
}
