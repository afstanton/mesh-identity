/// Base class for all mesh_identity exceptions.
sealed class MeshIdentityException implements Exception {
  /// Creates a new [MeshIdentityException] with the given [message].
  const MeshIdentityException(this.message);

  /// Human-readable description of the error.
  final String message;

  @override
  String toString() => '$runtimeType: $message';
}

/// Generic error when an internal or unexpected native condition occurs.
final class GenericMeshIdentityException extends MeshIdentityException {
  const GenericMeshIdentityException(super.message);
}

/// Thrown when an invalid or malformed snapshot is supplied.
final class InvalidSnapshotException extends MeshIdentityException {
  const InvalidSnapshotException(super.message);
}

/// Thrown when attempting an operation on an unknown identity.
final class UnknownIdentityException extends MeshIdentityException {
  const UnknownIdentityException(super.message);
}

/// Thrown when attempting to operate on or remove the active identity.
final class SelectedIdentityException extends MeshIdentityException {
  const SelectedIdentityException(super.message);
}

/// Thrown when identity limit, contact limit, or roster lock capacity is exceeded.
final class CapacityExceededException extends MeshIdentityException {
  const CapacityExceededException(super.message);
}

/// Thrown when a contact record is not found in the specified store.
final class ContactNotFoundException extends MeshIdentityException {
  const ContactNotFoundException(super.message);
}

/// Thrown when invalid arguments (e.g. wrong key length or null pointer) are passed.
final class InvalidArgumentsException extends MeshIdentityException {
  const InvalidArgumentsException(super.message);
}

/// Thrown when an index is out of bounds.
final class IndexOutOfBoundsException extends MeshIdentityException {
  const IndexOutOfBoundsException(super.message);
}

/// Thrown when attempting to operate on an object that has already been disposed.
final class DisposedException extends MeshIdentityException {
  const DisposedException(super.message);
}

/// Thrown when a native Rust panic was caught at the FFI boundary.
final class NativePanicException extends MeshIdentityException {
  const NativePanicException(super.message);
}

/// Thrown when attempting to start a ceremony while one is already active on this installation.
final class CeremonyActiveException extends MeshIdentityException {
  const CeremonyActiveException(super.message);
}

/// Thrown when using a ceremony handle that has lapsed, expired, or been cancelled.
final class StaleCeremonyException extends MeshIdentityException {
  const StaleCeremonyException(super.message);
}

/// Thrown when an encounter protocol error occurs (e.g. SAS code mismatch or unexpected payload).
final class EncounterProtocolException extends MeshIdentityException {
  const EncounterProtocolException(super.message);
}

/// Thrown when encounter attempts are temporarily paused by the rate-limiting attempt policy.
final class RateLimitedException extends MeshIdentityException {
  const RateLimitedException(super.message);
}

/// Thrown when attempting to confirm an encounter ceremony before a comparison code is available.
final class NoComparisonException extends MeshIdentityException {
  const NoComparisonException(super.message);
}
