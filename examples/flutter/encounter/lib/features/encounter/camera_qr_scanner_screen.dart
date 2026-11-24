import 'package:flutter/foundation.dart';
import 'package:flutter_zxing/flutter_zxing.dart';
import 'package:material_ui/material_ui.dart';

import '../../services/qr_scanner_service.dart';

/// Cross-platform [QrScannerService] backed by `flutter_zxing` and
/// `camera_desktop` (iOS, Android, macOS, Windows, Linux).
class ZxingQrScannerService implements QrScannerService {
  const ZxingQrScannerService();

  @override
  bool get isCameraSupported {
    if (kIsWeb) return false;
    return switch (defaultTargetPlatform) {
      TargetPlatform.android ||
      TargetPlatform.iOS ||
      TargetPlatform.macOS ||
      TargetPlatform.windows ||
      TargetPlatform.linux => true,
      TargetPlatform.fuchsia => false,
    };
  }

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

    final result = await Navigator.of(context).push<QrScanResult>(
      MaterialPageRoute<QrScanResult>(
        fullscreenDialog: true,
        builder: (_) => CameraQrScannerScreen(
          title: title,
          instruction: instruction,
          sessionListenable: sessionListenable,
          isSessionActive: isSessionActive,
        ),
      ),
    );
    return result ?? const QrScanResult.cancelled();
  }
}

/// Full-screen camera QR scanner for `mesh:encounter:` ceremony payloads.
///
/// Uses `flutter_zxing` (plus `camera_desktop` on Windows/Linux) and guards
/// against non-Encounter QR codes, oversized payloads, session expiry, and
/// camera permission or hardware initialization errors with a manual fallback.
class CameraQrScannerScreen extends StatefulWidget {
  final String title;
  final String instruction;
  final Listenable? sessionListenable;
  final bool Function()? isSessionActive;

  const CameraQrScannerScreen({
    super.key,
    required this.title,
    required this.instruction,
    this.sessionListenable,
    this.isSessionActive,
  });

  @override
  State<CameraQrScannerScreen> createState() => _CameraQrScannerScreenState();
}

class _CameraQrScannerScreenState extends State<CameraQrScannerScreen> {
  static const String _invalidQrHint =
      'Not an Encounter QR code. '
      'Point the camera at your peer\'s Encounter QR.';

  static const Set<String> _permissionErrorSubstrings = {
    'cameraaccessdenied',
    'cameraaccessdeniedwithoutprompt',
    'cameraaccessrestricted',
    'permission',
    'accessdenied',
    'notauthorized',
  };

  bool _hasCompleted = false;
  bool _permissionDenied = false;
  String? _cameraError;
  String? _scanHint;

  @override
  void initState() {
    super.initState();
    widget.sessionListenable?.addListener(_onSessionChanged);
  }

  @override
  void didUpdateWidget(covariant CameraQrScannerScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.sessionListenable != oldWidget.sessionListenable) {
      oldWidget.sessionListenable?.removeListener(_onSessionChanged);
      widget.sessionListenable?.addListener(_onSessionChanged);
    }
  }

  @override
  void dispose() {
    widget.sessionListenable?.removeListener(_onSessionChanged);
    super.dispose();
  }

  void _onSessionChanged() {
    if (!mounted || _hasCompleted) return;
    if (widget.isSessionActive != null && !widget.isSessionActive!()) {
      _complete(const QrScanResult.cancelled());
    }
  }

  ResolutionPreset get _resolution =>
      !kIsWeb && defaultTargetPlatform == TargetPlatform.linux
      ? ResolutionPreset.low
      : ResolutionPreset.high;

  void _complete(QrScanResult result) {
    if (_hasCompleted || !mounted) return;
    _hasCompleted = true;
    Navigator.of(context).pop(result);
  }

  bool _isPermissionException(Exception error) {
    final lower = error.toString().toLowerCase();
    return _permissionErrorSubstrings.any(lower.contains);
  }

  void _handleControllerCreated(
    CameraController? controller,
    Exception? error,
  ) {
    if (error == null || !mounted) return;
    final isPermission = _isPermissionException(error);
    setState(() {
      _permissionDenied = isPermission;
      _cameraError = isPermission
          ? 'Camera permission was denied. Check system settings to allow '
                'camera access, or paste the Encounter URI manually.'
          : 'Unable to start camera ($error). Check system settings or '
                'paste the Encounter URI manually instead.';
    });
  }

  void _handleScan(Code result) {
    if (_hasCompleted || !mounted) return;
    final validated = validateScannedEncounterUri(result.text);
    if (validated == null) {
      if (_scanHint != _invalidQrHint) {
        setState(() {
          _scanHint = _invalidQrHint;
        });
      }
      return;
    }
    _complete(QrScanResult.scanned(validated));
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final errorText = _cameraError;

    return PopScope(
      canPop: false,
      onPopInvokedWithResult: (didPop, _) {
        if (!didPop) {
          _complete(
            errorText != null
                ? (_permissionDenied
                      ? QrScanResult.permissionDenied(errorText)
                      : QrScanResult.error(errorText))
                : const QrScanResult.cancelled(),
          );
        }
      },
      child: Scaffold(
        appBar: AppBar(
          title: Text(widget.title),
          leading: IconButton(
            key: const Key('camera_scanner_close_button'),
            tooltip: 'Cancel scan',
            icon: const Icon(Icons.close),
            onPressed: () => _complete(
              errorText != null
                  ? (_permissionDenied
                        ? QrScanResult.permissionDenied(errorText)
                        : QrScanResult.error(errorText))
                  : const QrScanResult.cancelled(),
            ),
          ),
        ),
        body: Column(
          children: [
            Expanded(
              child: errorText != null
                  ? Center(
                      child: Padding(
                        padding: const EdgeInsets.all(24),
                        child: ConstrainedBox(
                          constraints: const BoxConstraints(maxWidth: 420),
                          child: Card.outlined(
                            child: Padding(
                              padding: const EdgeInsets.all(20),
                              child: Column(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Icon(
                                    _permissionDenied
                                        ? Icons.no_photography_outlined
                                        : Icons.videocam_off_outlined,
                                    size: 40,
                                    color: theme.colorScheme.error,
                                  ),
                                  const SizedBox(height: 12),
                                  Text(
                                    _permissionDenied
                                        ? 'Camera Access Required'
                                        : 'Camera Unavailable',
                                    style: theme.textTheme.titleMedium,
                                  ),
                                  const SizedBox(height: 8),
                                  Text(
                                    errorText,
                                    textAlign: TextAlign.center,
                                    style: theme.textTheme.bodyMedium?.copyWith(
                                      color: theme.colorScheme.onSurfaceVariant,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ),
                        ),
                      ),
                    )
                  : Stack(
                      fit: StackFit.expand,
                      children: [
                        ReaderWidget(
                          codeFormat: Format.qrCode,
                          resolution: _resolution,
                          showGallery: false,
                          tryRotate: true,
                          onControllerCreated: _handleControllerCreated,
                          onScan: _handleScan,
                        ),
                        if (_scanHint != null)
                          Positioned(
                            left: 16,
                            right: 16,
                            top: 16,
                            child: Material(
                              color: theme.colorScheme.errorContainer,
                              borderRadius: BorderRadius.circular(10),
                              child: Padding(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 14,
                                  vertical: 10,
                                ),
                                child: Text(
                                  _scanHint!,
                                  textAlign: TextAlign.center,
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: theme.colorScheme.onErrorContainer,
                                  ),
                                ),
                              ),
                            ),
                          ),
                      ],
                    ),
            ),
            SafeArea(
              top: false,
              child: Container(
                width: double.infinity,
                padding: const EdgeInsets.all(16),
                color: theme.colorScheme.surfaceContainerLow,
                child: Column(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      widget.instruction,
                      textAlign: TextAlign.center,
                      style: theme.textTheme.bodyMedium,
                    ),
                    const SizedBox(height: 12),
                    OutlinedButton.icon(
                      key: const Key('camera_scanner_manual_fallback_button'),
                      onPressed: () => _complete(
                        errorText != null
                            ? (_permissionDenied
                                  ? QrScanResult.permissionDenied(errorText)
                                  : QrScanResult.error(errorText))
                            : const QrScanResult.cancelled(),
                      ),
                      icon: const Icon(Icons.keyboard_outlined, size: 18),
                      label: const Text('Enter Manually Instead'),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
