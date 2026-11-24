import 'package:material_ui/material_ui.dart';
import 'package:mesh_identity/mesh_identity.dart';

/// Maximum accepted length for a scanned `mesh:encounter:` URI payload,
/// derived from [QrTransport.uriPrefix] and [QrTransport.maxB64Length].
const int maxScannedEncounterUriChars =
    QrTransport.uriPrefix.length + QrTransport.maxB64Length;

/// Validate and normalize a raw QR payload before passing it into an active
/// Encounter ceremony.
///
/// Returns the trimmed URI when non-empty, within [maxScannedEncounterUriChars],
/// and prefixed with [QrTransport.uriPrefix]; otherwise returns `null`.
String? validateScannedEncounterUri(String? raw) {
  if (raw == null) return null;
  final trimmed = raw.trim();
  if (trimmed.isEmpty || trimmed.length > maxScannedEncounterUriChars) {
    return null;
  }
  if (!trimmed.startsWith(QrTransport.uriPrefix)) {
    return null;
  }
  return trimmed;
}

/// Outcome of a QR scanner session.
enum QrScanStatus {
  /// A valid `mesh:encounter:` payload was scanned.
  scanned,

  /// The user closed the scanner or chose manual entry instead.
  cancelled,

  /// Camera permission was denied or blocked by OS settings.
  permissionDenied,

  /// Hardware camera scanning is unavailable on the current platform.
  unsupported,

  /// Camera initialization or capture failed unexpectedly.
  error,
}

/// Result returned by [QrScannerService.scanQr].
class QrScanResult {
  final QrScanStatus status;
  final String? payload;
  final String? message;

  const QrScanResult._({required this.status, this.payload, this.message});

  const QrScanResult.scanned(String payload)
    : this._(status: QrScanStatus.scanned, payload: payload);

  const QrScanResult.cancelled() : this._(status: QrScanStatus.cancelled);

  const QrScanResult.permissionDenied([String? message])
    : this._(status: QrScanStatus.permissionDenied, message: message);

  const QrScanResult.unsupported([String? message])
    : this._(status: QrScanStatus.unsupported, message: message);

  const QrScanResult.error(String message)
    : this._(status: QrScanStatus.error, message: message);
}

/// Abstraction over hardware QR code scanning so Encounter UI works uniformly
/// across iOS, Android, macOS, Windows, Linux, and deterministic widget tests.
abstract interface class QrScannerService {
  /// Whether hardware camera scanning is supported on the current target.
  bool get isCameraSupported;

  /// Present a QR scanner UI and resolve with the validated Encounter URI or
  /// a graceful cancellation/fallback status.
  ///
  /// When [sessionListenable] and [isSessionActive] are provided, the scanner
  /// automatically closes if the underlying ceremony becomes inactive (e.g.,
  /// after the 2-minute timeout).
  Future<QrScanResult> scanQr(
    BuildContext context, {
    required String title,
    required String instruction,
    Listenable? sessionListenable,
    bool Function()? isSessionActive,
  });
}

/// Deterministic in-memory [QrScannerService] for widget and integration tests.
class FakeQrScannerService implements QrScannerService {
  @override
  final bool isCameraSupported;

  final Future<QrScanResult> Function(
    BuildContext context,
    String title,
    String instruction,
  )?
  onScan;

  final List<QrScanResult> _queuedResults;

  FakeQrScannerService({
    this.isCameraSupported = true,
    this.onScan,
    List<QrScanResult> queuedResults = const [],
  }) : _queuedResults = List<QrScanResult>.of(queuedResults);

  @override
  Future<QrScanResult> scanQr(
    BuildContext context, {
    required String title,
    required String instruction,
    Listenable? sessionListenable,
    bool Function()? isSessionActive,
  }) async {
    if (!isCameraSupported) {
      return const QrScanResult.unsupported(
        'Camera scanning is not available on this platform.',
      );
    }
    if (isSessionActive != null && !isSessionActive()) {
      return const QrScanResult.cancelled();
    }
    if (onScan != null) {
      return onScan!(context, title, instruction);
    }
    if (_queuedResults.isNotEmpty) {
      return _queuedResults.removeAt(0);
    }
    return const QrScanResult.cancelled();
  }
}
