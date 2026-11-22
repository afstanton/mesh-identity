import 'package:flutter/foundation.dart';
import 'package:mesh_identity/mesh_identity.dart';

/// Current transport exchange stage of a single-device Practice Mode session.
enum PracticeStep {
  /// Step 1: Alice generated QR 1 Offer; waiting to deliver to Bob.
  offerReady,

  /// Step 2: Bob scanned QR 1 and emitted QR 2 Response; waiting to deliver to Alice.
  responseReady,

  /// Step 3: Alice scanned QR 2 and emitted QR 3 Reveal; waiting to deliver to Bob.
  revealReady,

  /// Step 4: Both parties have derived 6-digit SAS codes and await independent manual confirmation.
  comparing,
}

/// Independent confirmation outcome for a simulated Practice Mode participant.
enum PracticePartyOutcome { pending, verified, failed }

/// Single-device, completely isolated Alice & Bob Practice Mode controller.
///
/// Uses ephemeral in-memory [MeshInstallation] handles whose 32-byte signing
/// seeds are zeroized immediately after initialization. Never touches
/// [IdentityController], the device keyring, or durable snapshot storage.
class PracticeEncounterController extends ChangeNotifier {
  final DateTime Function() _clock;
  int _lastNowMs = 0;

  MeshInstallation? _alice;
  MeshInstallation? _bob;
  EncounterCeremony? _aliceCeremony;
  EncounterCeremony? _bobCeremony;

  late Uint8List _alicePublicKey;
  late Uint8List _bobPublicKey;

  PracticeStep _step = PracticeStep.offerReady;
  String? _offerUri;
  String? _responseUri;
  String? _revealUri;
  EncounterComparison? _aliceComparison;
  EncounterComparison? _bobComparison;

  PracticePartyOutcome _aliceOutcome = PracticePartyOutcome.pending;
  PracticePartyOutcome _bobOutcome = PracticePartyOutcome.pending;
  Contact? _aliceVerifiedContact;
  Contact? _bobVerifiedContact;
  String? _aliceError;
  String? _bobError;
  bool _isDisposed = false;

  PracticeEncounterController({DateTime Function()? clock})
    : _clock = clock ?? DateTime.now {
    _startFreshPair();
  }

  PracticeStep get step => _step;
  Uint8List get alicePublicKey => Uint8List.fromList(_alicePublicKey);
  Uint8List get bobPublicKey => Uint8List.fromList(_bobPublicKey);
  String? get offerUri => _offerUri;
  String? get responseUri => _responseUri;
  String? get revealUri => _revealUri;
  EncounterComparison? get aliceComparison => _aliceComparison;
  EncounterComparison? get bobComparison => _bobComparison;
  PracticePartyOutcome get aliceOutcome => _aliceOutcome;
  PracticePartyOutcome get bobOutcome => _bobOutcome;
  Contact? get aliceVerifiedContact => _aliceVerifiedContact;
  Contact? get bobVerifiedContact => _bobVerifiedContact;
  String? get aliceError => _aliceError;
  String? get bobError => _bobError;
  bool get isDisposed => _isDisposed;

  DateTime _now() {
    final raw = _clock().millisecondsSinceEpoch;
    final clamped = raw < _lastNowMs ? _lastNowMs : raw;
    _lastNowMs = clamped;
    return DateTime.fromMillisecondsSinceEpoch(clamped);
  }

  static MeshInstallation _createEphemeralInstallation() {
    final seed = MeshInstallation.generateSeed();
    try {
      return MeshInstallation(seed: seed);
    } finally {
      seed.fillRange(0, seed.length, 0);
    }
  }

  void _disposeNativeHandles() {
    // Dispose installations before ceremonies so ceremony finalizers do not
    // invoke native cancel against wall-clock time during cleanup or restart.
    _alice?.dispose();
    _alice = null;
    _bob?.dispose();
    _bob = null;
    _aliceCeremony?.dispose();
    _aliceCeremony = null;
    _bobCeremony?.dispose();
    _bobCeremony = null;
  }

  void _startFreshPair() {
    _disposeNativeHandles();

    final alice = _createEphemeralInstallation();
    final bob = _createEphemeralInstallation();
    try {
      final now = _now();
      final startRes = alice.startEncounter(at: now);
      _alice = alice;
      _bob = bob;
      _aliceCeremony = startRes.ceremony;
      _bobCeremony = null;
      _alicePublicKey = alice.selectedIdentity;
      _bobPublicKey = bob.selectedIdentity;

      _step = PracticeStep.offerReady;
      _offerUri = QrTransport.encodeUri(startRes.offerPayload);
      _responseUri = null;
      _revealUri = null;
      _aliceComparison = null;
      _bobComparison = null;
      _aliceOutcome = PracticePartyOutcome.pending;
      _bobOutcome = PracticePartyOutcome.pending;
      _aliceVerifiedContact = null;
      _bobVerifiedContact = null;
      _aliceError = null;
      _bobError = null;
    } catch (_) {
      alice.dispose();
      bob.dispose();
      rethrow;
    }
  }

  void _notifySafely() {
    if (!_isDisposed) {
      notifyListeners();
    }
  }

  static String _formatStepError(String step, Object error) {
    if (error is MeshIdentityException) {
      return 'Failed to process $step: ${error.message}';
    }
    if (error is FormatException) {
      return 'Failed to process $step: ${error.message}';
    }
    return 'Failed to process $step. Restart Practice Mode and try again.';
  }

  /// Step 1 -> Step 2: Deliver Alice's QR 1 Offer URI to Bob's scanner.
  void deliverOfferToBob() {
    if (_isDisposed || _step != PracticeStep.offerReady) return;
    final bob = _bob;
    final uri = _offerUri;
    if (bob == null || uri == null) return;

    final now = _now();
    EncounterCeremony? bobCeremony;
    try {
      final offerBytes = QrTransport.decodeUri(uri);
      bobCeremony = bob.openScanner(at: now);
      final respBytes = bob.scanOffer(bobCeremony, offerBytes, at: now);
      _bobCeremony = bobCeremony;
      bobCeremony = null;
      _responseUri = QrTransport.encodeUri(respBytes);
      _step = PracticeStep.responseReady;
      _aliceError = null;
      _bobError = null;
      _notifySafely();
    } catch (e) {
      bobCeremony?.dispose();
      _bobError = _formatStepError('offer', e);
      _notifySafely();
    }
  }

  /// Step 2 -> Step 3: Deliver Bob's QR 2 Response URI back to Alice.
  void deliverResponseToAlice() {
    if (_isDisposed || _step != PracticeStep.responseReady) return;
    final alice = _alice;
    final aliceCeremony = _aliceCeremony;
    final uri = _responseUri;
    if (alice == null || aliceCeremony == null || uri == null) return;

    final now = _now();
    try {
      final responseBytes = QrTransport.decodeUri(uri);
      final revealBytes = alice.scanResponse(
        aliceCeremony,
        responseBytes,
        at: now,
      );
      _aliceComparison = alice.getComparison(aliceCeremony, at: now);
      _revealUri = QrTransport.encodeUri(revealBytes);
      _step = PracticeStep.revealReady;
      _aliceError = null;
      _notifySafely();
    } catch (e) {
      _aliceError = _formatStepError('response', e);
      _notifySafely();
    }
  }

  /// Step 3 -> Step 4: Deliver Alice's QR 3 Reveal URI to Bob to unlock both SAS codes.
  void deliverRevealToBob() {
    if (_isDisposed || _step != PracticeStep.revealReady) return;
    final bob = _bob;
    final bobCeremony = _bobCeremony;
    final uri = _revealUri;
    if (bob == null || bobCeremony == null || uri == null) return;

    final now = _now();
    try {
      final revealBytes = QrTransport.decodeUri(uri);
      bob.scanReveal(bobCeremony, revealBytes, at: now);
      _bobComparison = bob.getComparison(bobCeremony, at: now);
      _step = PracticeStep.comparing;
      _bobError = null;
      _notifySafely();
    } catch (e) {
      _bobError = _formatStepError('reveal', e);
      _notifySafely();
    }
  }

  /// Alice manually enters the 6-digit code shown on Bob's panel and confirms.
  void confirmAlice(String sixDigitInput) {
    if (_isDisposed ||
        _step != PracticeStep.comparing ||
        _aliceOutcome != PracticePartyOutcome.pending) {
      return;
    }
    final alice = _alice;
    final ceremony = _aliceCeremony;
    if (alice == null || ceremony == null) return;

    final trimmed = sixDigitInput.trim();
    if (!RegExp(r'^\d{6}$').hasMatch(trimmed)) {
      _aliceError = 'Enter all 6 digits shown on Bob\'s side.';
      _notifySafely();
      return;
    }

    final peerCode = int.parse(trimmed);
    final now = _now();
    try {
      final contact = alice.confirmAndSave(ceremony, peerCode, at: now);
      _aliceCeremony = null;
      ceremony.dispose();
      _aliceVerifiedContact = contact;
      _aliceOutcome = PracticePartyOutcome.verified;
      _aliceError = null;
    } on EncounterProtocolException {
      _aliceCeremony = null;
      ceremony.dispose();
      _aliceOutcome = PracticePartyOutcome.failed;
      _aliceError = 'The 6-digit codes did not match. Alice cancelled her side for security.';
    } on MeshIdentityException catch (e) {
      _aliceCeremony = null;
      ceremony.dispose();
      _aliceOutcome = PracticePartyOutcome.failed;
      _aliceError = e.message;
    }
    _notifySafely();
  }

  /// Bob manually enters the 6-digit code shown on Alice's panel and confirms.
  void confirmBob(String sixDigitInput) {
    if (_isDisposed ||
        _step != PracticeStep.comparing ||
        _bobOutcome != PracticePartyOutcome.pending) {
      return;
    }
    final bob = _bob;
    final ceremony = _bobCeremony;
    if (bob == null || ceremony == null) return;

    final trimmed = sixDigitInput.trim();
    if (!RegExp(r'^\d{6}$').hasMatch(trimmed)) {
      _bobError = 'Enter all 6 digits shown on Alice\'s side.';
      _notifySafely();
      return;
    }

    final peerCode = int.parse(trimmed);
    final now = _now();
    try {
      final contact = bob.confirmAndSave(ceremony, peerCode, at: now);
      _bobCeremony = null;
      ceremony.dispose();
      _bobVerifiedContact = contact;
      _bobOutcome = PracticePartyOutcome.verified;
      _bobError = null;
    } on EncounterProtocolException {
      _bobCeremony = null;
      ceremony.dispose();
      _bobOutcome = PracticePartyOutcome.failed;
      _bobError = 'The 6-digit codes did not match. Bob cancelled his side for security.';
    } on MeshIdentityException catch (e) {
      _bobCeremony = null;
      ceremony.dispose();
      _bobOutcome = PracticePartyOutcome.failed;
      _bobError = e.message;
    }
    _notifySafely();
  }

  /// Reset Practice Mode with a brand-new ephemeral Alice & Bob keypair.
  void restart() {
    if (_isDisposed) return;
    _startFreshPair();
    _notifySafely();
  }

  @override
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;
    _disposeNativeHandles();
    super.dispose();
  }
}
