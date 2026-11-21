part of 'installation.dart';

/// An active in-person Encounter ceremony session.
///
/// Holds an opaque native handle to an active ceremony state machine.
/// Automatically cleans up resources via [ffi.NativeFinalizer] when garbage collected,
/// or can be explicitly disposed with [dispose].
///
/// To explicitly cancel an active ceremony on an installation, call
/// [MeshInstallation.cancelCeremony] instead, which cancels the session on the
/// installation immediately and releases ceremony resources.
class EncounterCeremony implements ffi.Finalizable {
  /// Internal constructor.
  EncounterCeremony._(this._handle) {
    _finalizer.attach(this, _handle, detach: this);
  }

  /// Library-private factory to create a ceremony from a native handle.
  static EncounterCeremony _fromHandle(ffi.Pointer<ffi.Void> handle) =>
      EncounterCeremony._(handle);

  static final ffi.NativeFinalizer _finalizer = ffi.NativeFinalizer(
    ffi.Native.addressOf(mesh_ceremony_free),
  );

  ffi.Pointer<ffi.Void> _handle;

  /// Whether this ceremony has been explicitly disposed or finalized.
  bool get isDisposed => _handle == ffi.nullptr;

  /// Underlying native pointer for package-internal FFI calls.
  ffi.Pointer<ffi.Void> get handle {
    if (isDisposed) {
      throw const DisposedException(
        'EncounterCeremony has already been disposed or completed.',
      );
    }
    return _handle;
  }

  /// Explicitly release native resources held by this ceremony.
  ///
  /// Safe to call multiple times (idempotent).
  /// Note: To abort an active ceremony on an installation, prefer calling
  /// [MeshInstallation.cancelCeremony] so the installation state machine
  /// is cancelled immediately without awaiting timeout.
  void dispose() {
    if (!isDisposed) {
      _finalizer.detach(this);
      mesh_ceremony_free(_handle);
      _handle = ffi.nullptr;
    }
  }
}

/// The result of starting an encounter ceremony as initiator.
class EncounterStartResult {
  /// Creates an [EncounterStartResult].
  const EncounterStartResult({
    required this.ceremony,
    required this.offerPayload,
  });

  /// The active ceremony handle.
  final EncounterCeremony ceremony;

  /// The initial offer payload bytes to transmit out-of-band to the peer.
  final Uint8List offerPayload;
}
