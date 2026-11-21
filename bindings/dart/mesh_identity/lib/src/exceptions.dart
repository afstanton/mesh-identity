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

/// Thrown when this device does not hold the voting role for an identity (stopped or gated).
final class NotVotingDeviceException extends MeshIdentityException {
  const NotVotingDeviceException(super.message);
}

/// Thrown when a handoff bundle fails authentication or structural checks.
final class InvalidHandoffException extends MeshIdentityException {
  const InvalidHandoffException(super.message);
}

/// Thrown when a handoff bundle's counter is not strictly higher than this device's counter.
final class StaleHandoffException extends MeshIdentityException {
  const StaleHandoffException(super.message);
}

/// Thrown when a handoff bundle names a recipient device nonce different from this device's nonce.
final class WrongHandoffRecipientException extends MeshIdentityException {
  const WrongHandoffRecipientException(super.message);
}

/// Thrown when an identity's monotonic counter has reached maximum value (2^64 - 1).
final class CounterExhaustedException extends MeshIdentityException {
  const CounterExhaustedException(super.message);
}

/// Thrown when attempting a takeover from a device that is not in the Gated state.
final class NotGatedException extends MeshIdentityException {
  const NotGatedException(super.message);
}

/// Thrown when persisting a handoff record or snapshot fails during handoff.
final class HandoffWriteFailedException extends MeshIdentityException {
  const HandoffWriteFailedException(super.message);
}

/// Thrown when an operation is ineligible (e.g. not a member, not a verified contact, or gated).
final class IneligibleException extends MeshIdentityException {
  const IneligibleException(super.message);
}

/// Thrown when a duplicate group ID is detected.
final class DuplicateGroupException extends MeshIdentityException {
  const DuplicateGroupException(super.message);
}

/// Thrown when an unsupported group policy or version is encountered.
final class UnsupportedGroupException extends MeshIdentityException {
  const UnsupportedGroupException(super.message);
}

/// Thrown when a group formation fails or is refused.
final class GroupFormationException extends MeshIdentityException {
  const GroupFormationException(super.message);
}

/// Thrown when a group blob, frame, or item exceeds maximum size limits.
final class GroupTooLargeException extends MeshIdentityException {
  const GroupTooLargeException(super.message);
}

/// Thrown when a group frame or blob is malformed.
final class MalformedGroupException extends MeshIdentityException {
  const MalformedGroupException(super.message);
}
