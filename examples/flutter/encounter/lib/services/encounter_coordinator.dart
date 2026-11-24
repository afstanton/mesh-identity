import 'dart:typed_data';

import 'package:mesh_identity/mesh_identity.dart';

import 'encounter_session.dart';

/// Host contract providing serialized execution, installation lifecycle,
/// persistence, and change notifications to [EncounterCoordinator].
abstract interface class EncounterHost {
  Future<T> runSerialized<T>(Future<T> Function() action);
  DateTime now();
  MeshInstallation? get installation;
  MeshInstallation requireInstallation();
  bool get isReady;
  bool get isDisposed;
  Future<void> persistSnapshot(DateTime at);
  Uint8List captureRollbackSnapshot(DateTime at);
  Future<void> rollbackInstallation(
    Uint8List prevSnapshotBytes,
    List<Uint8List> prevKeys,
  );
  void markPendingChanges();
  void clearPendingChanges();
  void syncCachedView();
  void notifyHost();
}

/// Coordinates in-person Encounter ceremonies (`EncounterCeremony`), QR payload
/// exchange, SAS confirmation, timeout checks, and rate-limit cooldowns using
/// [EncounterHost]'s serialized execution queue and snapshot storage.
class EncounterCoordinator {
  final EncounterHost _host;

  EncounterCeremony? _activeCeremony;
  EncounterSessionState _session = const EncounterSessionState.idle();
  DateTime? _rateLimitedUntil;

  EncounterCoordinator(this._host);

  EncounterSessionState get session => _session;
  bool get hasActiveCeremony => _activeCeremony != null || _session.isActive;
  DateTime? get rateLimitedUntil => _rateLimitedUntil;

  /// Disposes the tracked ceremony handle without invoking native cancel on
  /// a still-live installation (callers must dispose the installation first
  /// during teardown or rollback).
  void disposeCeremonyHandleOnly() {
    final ceremony = _activeCeremony;
    _activeCeremony = null;
    ceremony?.dispose();
  }

  /// Clears encounter UI state and rate-limit deadline after controller reset or dispose.
  void resetState() {
    _session = const EncounterSessionState.idle();
    _rateLimitedUntil = null;
  }

  /// Transitions an active session to `failed` when an external rollback
  /// replaces the underlying native installation and discards the ceremony.
  void onExternalRollback() {
    if (_session.isActive) {
      _failEncounter(
        'Encounter ceremony was interrupted by a local storage rollback. '
        'Start a new encounter.',
      );
    }
  }

  void _failEncounter(
    String message, {
    EncounterRole? role,
    bool showLocalOnlyNotice = false,
  }) {
    _session = _session.copyWith(
      phase: EncounterPhase.failed,
      role: role,
      clearOutgoingUri: true,
      clearComparison: true,
      clearInlineError: true,
      errorMessage: message,
      showLocalOnlyNotice: showLocalOnlyNotice,
    );
  }

  bool _refreshRateLimitLocked(DateTime now) {
    final until = _rateLimitedUntil;
    if (until == null) return false;
    if (!now.isBefore(until)) {
      _rateLimitedUntil = null;
      if (_session.phase == EncounterPhase.rateLimited) {
        _session = const EncounterSessionState.idle();
      }
      return false;
    }
    _session = EncounterSessionState(
      phase: EncounterPhase.rateLimited,
      rateLimitedUntil: until,
      interferenceWarning: true,
      errorMessage: EncounterUiText.interferenceWarning,
    );
    return true;
  }

  void _recordRateLimited(RateLimitedException e, DateTime now) {
    final until = EncounterSessionState.resolvePausedUntil(e, now);
    _rateLimitedUntil = until;
    disposeCeremonyHandleOnly();
    _session = EncounterSessionState(
      phase: EncounterPhase.rateLimited,
      rateLimitedUntil: until,
      interferenceWarning: true,
      errorMessage: EncounterUiText.interferenceWarning,
    );
  }

  Future<void> _bestEffortPersistPolicyLocked(DateTime now) async {
    try {
      await _host.persistSnapshot(now);
    } catch (_) {
      _host.markPendingChanges();
    }
  }

  Future<void> _cancelActiveLocked(DateTime now) async {
    final ceremony = _activeCeremony;
    _activeCeremony = null;
    final hadResponseExchanged = _session.responseExchanged;
    if (ceremony != null) {
      final inst = _host.installation;
      if (inst != null && !inst.isDisposed && _host.isReady) {
        try {
          inst.cancelCeremony(ceremony, at: now);
        } catch (_) {
          ceremony.dispose();
        }
        if (hadResponseExchanged) {
          await _bestEffortPersistPolicyLocked(now);
        }
      } else {
        ceremony.dispose();
      }
    }
  }

  Future<bool> _expireIfLapsedLocked(DateTime now) async {
    final expiresAt = _session.expiresAt;
    if (!_session.isActive || expiresAt == null || now.isBefore(expiresAt)) {
      return false;
    }
    final inst = _host.installation;
    if (inst != null && !inst.isDisposed && _host.isReady) {
      try {
        // persistSnapshot(now) invokes native Installation::expire(now),
        // clearing self.ceremony and recording any incomplete response state.
        await _host.persistSnapshot(now);
        _host.clearPendingChanges();
      } catch (_) {
        _host.markPendingChanges();
      }
    }
    _transitionToExpiredLocked();
    return true;
  }

  void _transitionToExpiredLocked() {
    disposeCeremonyHandleOnly();
    _session = _session.copyWith(
      phase: EncounterPhase.expired,
      clearOutgoingUri: true,
      clearComparison: true,
      clearInlineError: true,
      showLocalOnlyNotice: false,
      errorMessage: 'This 2-minute encounter session timed out. Start a new encounter to try again.',
    );
  }

  /// Start a two-device Encounter ceremony as Initiator (generates QR 1 Offer).
  Future<void> startAsInitiator() {
    return _host.runSerialized(() async {
      if (_host.isDisposed || !_host.isReady) return;
      final now = _host.now();
      if (_refreshRateLimitLocked(now)) {
        _host.notifyHost();
        return;
      }
      if (_activeCeremony != null) {
        await _cancelActiveLocked(now);
        if (_host.isDisposed || !_host.isReady) return;
      }

      final inst = _host.requireInstallation();
      try {
        final res = inst.startEncounter(at: now);
        final offerUri = QrTransport.encodeUri(res.offerPayload);
        _activeCeremony = res.ceremony;
        _session = EncounterSessionState(
          phase: EncounterPhase.initiatorShowingOffer,
          role: EncounterRole.initiator,
          outgoingUri: offerUri,
          startedAt: now,
          expiresAt: now.add(EncounterUiText.sessionTimeout),
          responseExchanged: false,
        );
      } on RateLimitedException catch (e) {
        _recordRateLimited(e, now);
      } on MeshIdentityException catch (e) {
        _session = EncounterSessionState(
          phase: EncounterPhase.failed,
          role: EncounterRole.initiator,
          errorMessage: e.message,
        );
      }
      _host.notifyHost();
    });
  }

  /// Open a two-device Encounter ceremony as Responder (awaiting peer's QR 1 Offer).
  Future<void> openAsResponder() {
    return _host.runSerialized(() async {
      if (_host.isDisposed || !_host.isReady) return;
      final now = _host.now();
      if (_refreshRateLimitLocked(now)) {
        _host.notifyHost();
        return;
      }
      if (_activeCeremony != null) {
        await _cancelActiveLocked(now);
        if (_host.isDisposed || !_host.isReady) return;
      }

      final inst = _host.requireInstallation();
      try {
        final ceremony = inst.openScanner(at: now);
        _activeCeremony = ceremony;
        _session = EncounterSessionState(
          phase: EncounterPhase.responderAwaitingOffer,
          role: EncounterRole.responder,
          startedAt: now,
          expiresAt: now.add(EncounterUiText.sessionTimeout),
          responseExchanged: false,
        );
      } on RateLimitedException catch (e) {
        _recordRateLimited(e, now);
      } on MeshIdentityException catch (e) {
        _session = EncounterSessionState(
          phase: EncounterPhase.failed,
          role: EncounterRole.responder,
          errorMessage: e.message,
        );
      }
      _host.notifyHost();
    });
  }

  /// Responder imports Initiator's QR 1 Offer URI and emits QR 2 Response URI.
  ///
  /// If durable snapshot persistence fails after [MeshInstallation.scanOffer],
  /// rollback restores `prevSnapshotBytes` to preserve strict in-memory/on-disk
  /// consistency.
  Future<void> submitOffer(String rawUri) {
    return _host.runSerialized(() async {
      final ceremony = _activeCeremony;
      if (_host.isDisposed ||
          !_host.isReady ||
          ceremony == null ||
          _session.phase != EncounterPhase.responderAwaitingOffer) {
        return;
      }

      final now = _host.now();
      if (await _expireIfLapsedLocked(now)) {
        _host.notifyHost();
        return;
      }

      final Uint8List offerBytes;
      try {
        offerBytes = QrTransport.decodeUri(rawUri.trim());
      } on FormatException {
        _session = _session.copyWith(
          inlineError: 'Invalid encounter payload. Expected a valid mesh:encounter: URI.',
        );
        _host.notifyHost();
        return;
      }

      final inst = _host.requireInstallation();
      final prevKeys = inst.identities;
      final prevSnapshotBytes = _host.captureRollbackSnapshot(now);

      final Uint8List responseBytes;
      try {
        responseBytes = inst.scanOffer(ceremony, offerBytes, at: now);
      } on RateLimitedException catch (e) {
        _recordRateLimited(e, now);
        _host.notifyHost();
        return;
      } on StaleCeremonyException {
        _transitionToExpiredLocked();
        _host.notifyHost();
        return;
      } on EncounterProtocolException {
        // ResponderMachine moves to Aborted on a rejected first offer and
        // Installation::scan_offer clears self.ceremony.
        disposeCeremonyHandleOnly();
        _failEncounter(
          'Offer payload was rejected by the encounter protocol. '
          'Start a new session and try again.',
        );
        _host.notifyHost();
        return;
      } on MeshIdentityException catch (e) {
        await _cancelActiveLocked(now);
        _failEncounter(e.message);
        _host.notifyHost();
        return;
      }

      final responseUri = QrTransport.encodeUri(responseBytes);
      try {
        await _host.persistSnapshot(now);
      } catch (e) {
        await _host.rollbackInstallation(prevSnapshotBytes, prevKeys);
        _failEncounter('Failed to persist encounter state: $e');
        _host.notifyHost();
        return;
      }

      _session = _session.copyWith(
        phase: EncounterPhase.responderShowingResponse,
        outgoingUri: responseUri,
        responseExchanged: true,
        clearInlineError: true,
      );
      _host.notifyHost();
    });
  }

  /// Initiator imports Responder's QR 2 Response URI, emits QR 3 Reveal URI,
  /// and computes the 6-digit SAS comparison code.
  ///
  /// If durable snapshot persistence fails after [MeshInstallation.scanResponse],
  /// rollback restores `prevSnapshotBytes` to preserve strict in-memory/on-disk
  /// consistency.
  Future<void> submitResponse(String rawUri) {
    return _host.runSerialized(() async {
      final ceremony = _activeCeremony;
      if (_host.isDisposed ||
          !_host.isReady ||
          ceremony == null ||
          _session.phase != EncounterPhase.initiatorShowingOffer) {
        return;
      }

      final now = _host.now();
      if (await _expireIfLapsedLocked(now)) {
        _host.notifyHost();
        return;
      }

      final Uint8List responseBytes;
      try {
        responseBytes = QrTransport.decodeUri(rawUri.trim());
      } on FormatException {
        _session = _session.copyWith(
          inlineError: 'Invalid encounter payload. Expected a valid mesh:encounter: URI.',
        );
        _host.notifyHost();
        return;
      }

      final inst = _host.requireInstallation();
      final prevKeys = inst.identities;
      final prevSnapshotBytes = _host.captureRollbackSnapshot(now);

      final Uint8List revealBytes;
      final EncounterComparison? comparison;
      try {
        revealBytes = inst.scanResponse(ceremony, responseBytes, at: now);
        comparison = inst.getComparison(ceremony, at: now);
      } on RateLimitedException catch (e) {
        _recordRateLimited(e, now);
        _host.notifyHost();
        return;
      } on StaleCeremonyException {
        await _bestEffortPersistPolicyLocked(now);
        _transitionToExpiredLocked();
        _host.notifyHost();
        return;
      } on EncounterProtocolException {
        // InitiatorMachine ignores invalid QR 2 while OfferShown and keeps the
        // live ceremony open unless a conflicting QR 2 arrives after reveal.
        _session = _session.copyWith(
          inlineError:
              'Response payload did not match this encounter. Verify you '
              'copied the peer\'s Response URI and try again.',
        );
        _host.notifyHost();
        return;
      } on MeshIdentityException catch (e) {
        await _cancelActiveLocked(now);
        _failEncounter(e.message);
        _host.notifyHost();
        return;
      }

      if (comparison == null) {
        await _cancelActiveLocked(now);
        _failEncounter('Comparison code is unavailable for this encounter.');
        _host.notifyHost();
        return;
      }

      final revealUri = QrTransport.encodeUri(revealBytes);
      try {
        await _host.persistSnapshot(now);
      } catch (e) {
        await _host.rollbackInstallation(prevSnapshotBytes, prevKeys);
        _failEncounter('Failed to persist encounter state: $e');
        _host.notifyHost();
        return;
      }

      _session = _session.copyWith(
        phase: EncounterPhase.initiatorShowingRevealAndCompare,
        outgoingUri: revealUri,
        comparison: comparison,
        responseExchanged: true,
        clearInlineError: true,
      );
      _host.notifyHost();
    });
  }

  /// Responder imports Initiator's QR 3 Reveal URI and computes the 6-digit SAS code.
  Future<void> submitReveal(String rawUri) {
    return _host.runSerialized(() async {
      final ceremony = _activeCeremony;
      if (_host.isDisposed ||
          !_host.isReady ||
          ceremony == null ||
          _session.phase != EncounterPhase.responderShowingResponse) {
        return;
      }

      final now = _host.now();
      if (await _expireIfLapsedLocked(now)) {
        _host.notifyHost();
        return;
      }

      final Uint8List revealBytes;
      try {
        revealBytes = QrTransport.decodeUri(rawUri.trim());
      } on FormatException {
        _session = _session.copyWith(
          inlineError: 'Invalid encounter payload. Expected a valid mesh:encounter: URI.',
        );
        _host.notifyHost();
        return;
      }

      final inst = _host.requireInstallation();
      final EncounterComparison? comparison;
      try {
        inst.scanReveal(ceremony, revealBytes, at: now);
        comparison = inst.getComparison(ceremony, at: now);
      } on StaleCeremonyException {
        await _bestEffortPersistPolicyLocked(now);
        _transitionToExpiredLocked();
        _host.notifyHost();
        return;
      } on EncounterProtocolException {
        // ResponderMachine ignores invalid QR 3 while ResponseShown and keeps the
        // live session open.
        _session = _session.copyWith(
          inlineError:
              'Reveal payload did not match this encounter. Verify you copied '
              'the peer\'s Reveal URI and try again.',
        );
        _host.notifyHost();
        return;
      } on MeshIdentityException catch (e) {
        await _cancelActiveLocked(now);
        _failEncounter(e.message);
        _host.notifyHost();
        return;
      }

      if (comparison == null) {
        await _cancelActiveLocked(now);
        _failEncounter('Comparison code is unavailable for this encounter.');
        _host.notifyHost();
        return;
      }

      _session = _session.copyWith(
        phase: EncounterPhase.responderAwaitingConfirmation,
        comparison: comparison,
        clearOutgoingUri: true,
        clearInlineError: true,
      );
      _host.notifyHost();
    });
  }

  /// Confirm the human-typed 6-digit SAS code and durably save the verified contact.
  ///
  /// When snapshot persistence fails after [MeshInstallation.confirmAndSave],
  /// `prevSnapshotBytes` already carries `pending_response: true`, so restoring it
  /// preserves atomic state and ensures recovery accounts for the incomplete attempt
  /// while instructing the user to start a new encounter.
  Future<void> confirmCode(String sixDigitInput) {
    return _host.runSerialized(() async {
      final ceremony = _activeCeremony;
      final phase = _session.phase;
      if (_host.isDisposed ||
          !_host.isReady ||
          ceremony == null ||
          (phase != EncounterPhase.initiatorShowingRevealAndCompare &&
              phase != EncounterPhase.responderAwaitingConfirmation)) {
        return;
      }

      final now = _host.now();
      if (await _expireIfLapsedLocked(now)) {
        _host.notifyHost();
        return;
      }

      final trimmed = sixDigitInput.trim();
      if (!RegExp(r'^\d{6}$').hasMatch(trimmed)) {
        _session = _session.copyWith(
          inlineError: 'Enter all 6 digits shown on your peer\'s device.',
        );
        _host.notifyHost();
        return;
      }

      final peerCode = int.parse(trimmed);
      final inst = _host.requireInstallation();
      final prevKeys = inst.identities;
      final prevSnapshotBytes = _host.captureRollbackSnapshot(now);

      final Contact contact;
      try {
        contact = inst.confirmAndSave(ceremony, peerCode, at: now);
      } on StaleCeremonyException {
        await _bestEffortPersistPolicyLocked(now);
        _transitionToExpiredLocked();
        _host.notifyHost();
        return;
      } on EncounterProtocolException {
        disposeCeremonyHandleOnly();
        await _bestEffortPersistPolicyLocked(now);
        _failEncounter(
          'The 6-digit codes did not match. This encounter was cancelled for security.',
        );
        _host.notifyHost();
        return;
      } on MeshIdentityException catch (e) {
        disposeCeremonyHandleOnly();
        await _bestEffortPersistPolicyLocked(now);
        _failEncounter(e.message);
        _host.notifyHost();
        return;
      }

      try {
        await _host.persistSnapshot(now);
      } catch (_) {
        await _host.rollbackInstallation(prevSnapshotBytes, prevKeys);
        _failEncounter(
          'Failed to save the verified contact to local storage. '
          'Start a new encounter to verify this peer again.',
          showLocalOnlyNotice: true,
        );
        _host.notifyHost();
        return;
      }

      disposeCeremonyHandleOnly();
      _rateLimitedUntil = null;
      _host.syncCachedView();
      _session = _session.copyWith(
        phase: EncounterPhase.verified,
        verifiedContact: contact,
        clearOutgoingUri: true,
        clearInlineError: true,
        clearErrorMessage: true,
        showLocalOnlyNotice: false,
      );
      _host.notifyHost();
    });
  }

  /// Explicitly cancel any live Encounter ceremony on the active installation.
  Future<void> cancelActive() {
    return _host.runSerialized(() async {
      if (_host.isDisposed || !_host.isReady) return;
      final now = _host.now();
      final wasActive = _session.isActive;
      await _cancelActiveLocked(now);
      if (wasActive) {
        _session = _session.copyWith(
          phase: EncounterPhase.cancelled,
          clearOutgoingUri: true,
          clearComparison: true,
          clearInlineError: true,
          clearErrorMessage: true,
          showLocalOnlyNotice: false,
        );
        _host.notifyHost();
      }
    });
  }

  /// Check ceremony timeout (120s) and rate-limit pause expiry (60s).
  Future<void> checkExpiry() {
    return _host.runSerialized(() async {
      if (_host.isDisposed || !_host.isReady) return;
      final now = _host.now();
      var changed = false;
      if (_rateLimitedUntil != null && !now.isBefore(_rateLimitedUntil!)) {
        _rateLimitedUntil = null;
        if (_session.phase == EncounterPhase.rateLimited) {
          _session = const EncounterSessionState.idle();
        }
        changed = true;
      }
      if (await _expireIfLapsedLocked(now)) {
        changed = true;
      }
      if (changed) {
        _host.notifyHost();
      }
    });
  }

  /// Dismiss the current encounter screen state, cancelling any live session
  /// and returning to `idle` (or `rateLimited` if pause remains active).
  Future<void> dismissSession() {
    return _host.runSerialized(() async {
      if (_host.isDisposed) return;
      final now = _host.now();
      if (_session.isActive) {
        await _cancelActiveLocked(now);
      }
      if (!_refreshRateLimitLocked(now)) {
        _session = const EncounterSessionState.idle();
      }
      _host.notifyHost();
    });
  }
}
