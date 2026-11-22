import 'dart:typed_data';

import 'package:mesh_identity/mesh_identity.dart';

/// Role assumed by this device in an in-person Encounter ceremony.
enum EncounterRole {
  /// Initiator: generates QR 1 Offer, scans QR 2 Response, emits QR 3 Reveal,
  /// and confirms peer's 6-digit SAS code.
  initiator,

  /// Responder: scans QR 1 Offer, emits QR 2 Response, scans QR 3 Reveal,
  /// and confirms peer's 6-digit SAS code.
  responder,
}

/// Lifecycle phase of an active or completed Encounter ceremony session.
enum EncounterPhase {
  /// No active ceremony.
  idle,

  /// Initiator is showing QR 1 Offer and waiting for peer's QR 2 Response URI.
  initiatorShowingOffer,

  /// Responder opened a scanner and is waiting for peer's QR 1 Offer URI.
  responderAwaitingOffer,

  /// Responder is showing QR 2 Response and waiting for peer's QR 3 Reveal URI.
  responderShowingResponse,

  /// Initiator is showing QR 3 Reveal and awaits human 6-digit SAS entry.
  initiatorShowingRevealAndCompare,

  /// Responder received QR 3 Reveal and awaits human 6-digit SAS entry.
  responderAwaitingConfirmation,

  /// SAS matched and verified contact was durably saved to local storage.
  verified,

  /// Ceremony was explicitly cancelled by the user or on navigation exit.
  cancelled,

  /// Ceremony exceeded the 120-second session timeout.
  expired,

  /// Ceremony failed (SAS mismatch, rejected payload, or storage failure).
  failed,

  /// Attempt policy temporarily paused new ceremonies after repeated failures.
  rateLimited,
}

/// Statutory user-visible notices and protocol timeouts from `mesh_identity`.
abstract final class EncounterUiText {
  /// Required instruction displayed alongside the 6-digit SAS code.
  static const String instruction = EncounterComparison.instruction;

  /// Required proximity disclaimer shown on any verified result.
  static const String proximityDisclaimer =
      EncounterComparison.proximityDisclaimer;

  /// Required disclaimer clarifying key verification vs human/legal identity.
  static const String notIdentityProof = EncounterComparison.notIdentityProof;

  /// Required notice clarifying that confirmation is local to each device.
  static const String localOnlyConfirmation =
      'Saved on this device only. The other device may not have saved you, '
      'and cancelling there cannot undo this.';

  /// Required warning displayed after repeated incomplete attempts.
  static const String interferenceWarning =
      'Several attempts did not finish. This can mean something is '
      'interfering with the exchange. Wait before trying again.';

  /// Session lifetime enforced by `mesh_identity::session::SESSION_TIMEOUT_MS`.
  static const Duration sessionTimeout = Duration(milliseconds: 120000);

  /// Pause duration enforced by `mesh_identity::session::PAUSE_MS`.
  static const Duration rateLimitPause = Duration(milliseconds: 60000);
}

/// Immutable UI projection of the active or most recent Encounter ceremony.
class EncounterSessionState {
  static final RegExp _pausedUntilRegex = RegExp(r'until\s+(\d+)\s*ms');

  final EncounterPhase phase;
  final EncounterRole? role;
  final String? outgoingUri;
  final EncounterComparison? comparison;
  final Contact? verifiedContact;
  final DateTime? startedAt;
  final DateTime? expiresAt;
  final DateTime? rateLimitedUntil;
  final String? errorMessage;
  final String? inlineError;
  final bool interferenceWarning;
  final bool showLocalOnlyNotice;
  final bool responseExchanged;
  final bool isBusy;

  const EncounterSessionState({
    required this.phase,
    this.role,
    this.outgoingUri,
    this.comparison,
    this.verifiedContact,
    this.startedAt,
    this.expiresAt,
    this.rateLimitedUntil,
    this.errorMessage,
    this.inlineError,
    this.interferenceWarning = false,
    this.showLocalOnlyNotice = false,
    this.responseExchanged = false,
    this.isBusy = false,
  });

  /// Initial idle state with no active ceremony.
  const EncounterSessionState.idle() : this(phase: EncounterPhase.idle);

  /// Whether a native ceremony session is currently live and awaiting input.
  bool get isActive => switch (phase) {
    EncounterPhase.initiatorShowingOffer ||
    EncounterPhase.responderAwaitingOffer ||
    EncounterPhase.responderShowingResponse ||
    EncounterPhase.initiatorShowingRevealAndCompare ||
    EncounterPhase.responderAwaitingConfirmation => true,
    _ => false,
  };

  /// Whether the ceremony has reached a finished terminal outcome.
  bool get isTerminal => switch (phase) {
    EncounterPhase.verified ||
    EncounterPhase.cancelled ||
    EncounterPhase.expired ||
    EncounterPhase.failed => true,
    _ => false,
  };

  /// Time remaining until session expiry at [now], clamped at [Duration.zero].
  Duration? remainingTime(DateTime now) {
    final target = expiresAt;
    if (target == null) return null;
    if (!now.isBefore(target)) return Duration.zero;
    return target.difference(now);
  }

  /// Time remaining in the active rate-limit pause at [now], clamped at zero.
  Duration? rateLimitRemaining(DateTime now) {
    final target = rateLimitedUntil;
    if (target == null) return null;
    if (!now.isBefore(target)) return Duration.zero;
    return target.difference(now);
  }

  /// Parse `until <ms> ms` from `RateLimitedException.message` until `mesh_identity`
  /// 0.5.1 exposes a structured `untilMs` field, falling back to
  /// [EncounterUiText.rateLimitPause] from [now].
  static DateTime parsePausedUntil(String message, DateTime now) {
    final match = _pausedUntilRegex.firstMatch(message);
    if (match != null) {
      final parsed = int.tryParse(match.group(1)!);
      if (parsed != null && parsed > now.millisecondsSinceEpoch) {
        return DateTime.fromMillisecondsSinceEpoch(parsed);
      }
    }
    return now.add(EncounterUiText.rateLimitPause);
  }

  EncounterSessionState copyWith({
    EncounterPhase? phase,
    EncounterRole? role,
    bool clearRole = false,
    String? outgoingUri,
    bool clearOutgoingUri = false,
    EncounterComparison? comparison,
    bool clearComparison = false,
    Contact? verifiedContact,
    bool clearVerifiedContact = false,
    DateTime? startedAt,
    bool clearStartedAt = false,
    DateTime? expiresAt,
    bool clearExpiresAt = false,
    DateTime? rateLimitedUntil,
    bool clearRateLimitedUntil = false,
    String? errorMessage,
    bool clearErrorMessage = false,
    String? inlineError,
    bool clearInlineError = false,
    bool? interferenceWarning,
    bool? showLocalOnlyNotice,
    bool? responseExchanged,
    bool? isBusy,
  }) {
    return EncounterSessionState(
      phase: phase ?? this.phase,
      role: clearRole ? null : (role ?? this.role),
      outgoingUri: clearOutgoingUri ? null : (outgoingUri ?? this.outgoingUri),
      comparison: clearComparison ? null : (comparison ?? this.comparison),
      verifiedContact: clearVerifiedContact
          ? null
          : (verifiedContact ?? this.verifiedContact),
      startedAt: clearStartedAt ? null : (startedAt ?? this.startedAt),
      expiresAt: clearExpiresAt ? null : (expiresAt ?? this.expiresAt),
      rateLimitedUntil: clearRateLimitedUntil
          ? null
          : (rateLimitedUntil ?? this.rateLimitedUntil),
      errorMessage: clearErrorMessage
          ? null
          : (errorMessage ?? this.errorMessage),
      inlineError: clearInlineError ? null : (inlineError ?? this.inlineError),
      interferenceWarning: interferenceWarning ?? this.interferenceWarning,
      showLocalOnlyNotice: showLocalOnlyNotice ?? this.showLocalOnlyNotice,
      responseExchanged: responseExchanged ?? this.responseExchanged,
      isBusy: isBusy ?? this.isBusy,
    );
  }
}

/// Format raw bytes as lowercase hexadecimal.
String formatHexKey(Uint8List bytes) {
  final sb = StringBuffer();
  for (final b in bytes) {
    sb.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return sb.toString();
}

/// Format a 32-byte key as a short `<first12>...<last8>` fingerprint.
String shortHexKey(Uint8List bytes) {
  final hex = formatHexKey(bytes);
  if (hex.length <= 20) return hex;
  return '${hex.substring(0, 12)}...${hex.substring(hex.length - 8)}';
}

/// Group the 6-digit SAS code into two 3-digit blocks for readable human comparison.
String formatSasDigits(EncounterComparison comparison) {
  final padded = comparison.formattedCode;
  return '${padded.substring(0, 3)} ${padded.substring(3)}';
}

/// Format a non-negative duration as `MM:SS`, rounding partial seconds up so `00:01`
/// remains visible until the deadline is actually reached.
String formatCountdown(Duration duration) {
  if (duration <= Duration.zero) {
    return '00:00';
  }
  final totalSeconds = (duration.inMilliseconds + 999) ~/ 1000;
  final minutes = totalSeconds ~/ 60;
  final seconds = totalSeconds % 60;
  return '${minutes.toString().padLeft(2, '0')}:'
      '${seconds.toString().padLeft(2, '0')}';
}
