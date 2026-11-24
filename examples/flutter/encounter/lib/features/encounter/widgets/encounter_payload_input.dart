import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import '../../../core/theme.dart';
import '../../../services/qr_scanner_service.dart';

/// Camera QR, text, and clipboard import panel for incoming peer
/// `mesh:encounter:` URIs.
class EncounterPayloadInput extends StatefulWidget {
  final String title;
  final String hintText;
  final String submitLabel;
  final String? inlineError;
  final bool enabled;
  final ValueChanged<String> onSubmit;
  final QrScannerService? qrScanner;
  final String? scanTitle;
  final String? scanInstruction;
  final Listenable? sessionListenable;
  final bool Function()? isSessionActive;
  final Key? textFieldKey;
  final Key? pasteButtonKey;
  final Key? submitButtonKey;

  const EncounterPayloadInput({
    super.key,
    required this.title,
    required this.hintText,
    required this.submitLabel,
    required this.onSubmit,
    this.inlineError,
    this.enabled = true,
    this.qrScanner,
    this.scanTitle,
    this.scanInstruction,
    this.sessionListenable,
    this.isSessionActive,
    this.textFieldKey,
    this.pasteButtonKey,
    this.submitButtonKey,
  });

  @override
  State<EncounterPayloadInput> createState() => _EncounterPayloadInputState();
}

class _EncounterPayloadInputState extends State<EncounterPayloadInput> {
  final TextEditingController _textController = TextEditingController();
  bool _isScanning = false;
  String? _scannerNotice;

  @override
  void dispose() {
    _textController.dispose();
    super.dispose();
  }

  Future<void> _pasteFromClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (!mounted) return;
    final text = data?.text?.trim();
    if (text == null || text.isEmpty) {
      ScaffoldMessenger.of(context)
          .showSnackBar(const SnackBar(content: Text('Clipboard is empty')));
      return;
    }
    setState(() {
      _scannerNotice = null;
      _textController.text = text;
      _textController.selection = TextSelection.collapsed(offset: text.length);
    });
  }

  Future<void> _scanQrCode() async {
    final scanner = widget.qrScanner;
    if (scanner == null || !widget.enabled || _isScanning) return;

    setState(() {
      _isScanning = true;
      _scannerNotice = null;
    });
    try {
      final result = await scanner.scanQr(
        context,
        title: widget.scanTitle ?? 'Scan Encounter QR',
        instruction:
            widget.scanInstruction ??
            'Point your camera at your peer\'s Encounter QR code.',
        sessionListenable: widget.sessionListenable,
        isSessionActive: widget.isSessionActive,
      );
      if (!mounted) return;
      switch (result.status) {
        case QrScanStatus.scanned:
          final payload = result.payload;
          if (payload != null && payload.isNotEmpty) {
            setState(() {
              _scannerNotice = null;
              _textController.text = payload;
              _textController.selection = TextSelection.collapsed(
                offset: payload.length,
              );
            });
            widget.onSubmit(payload);
          }
        case QrScanStatus.permissionDenied:
          setState(() {
            _scannerNotice =
                result.message ??
                'Camera permission denied. '
                    'Paste or enter the Encounter URI manually below.';
          });
        case QrScanStatus.unsupported:
          setState(() {
            _scannerNotice =
                result.message ??
                'Camera scanning is unavailable here. '
                    'Paste or enter the Encounter URI manually.';
          });
        case QrScanStatus.error:
          setState(() {
            _scannerNotice =
                result.message ??
                'Camera unavailable. '
                    'Paste or enter the Encounter URI manually below.';
          });
        case QrScanStatus.cancelled:
          break;
      }
    } finally {
      if (mounted) {
        setState(() => _isScanning = false);
      }
    }
  }

  void _submit() {
    final value = _textController.text.trim();
    if (value.isEmpty || !widget.enabled) return;
    widget.onSubmit(value);
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final showScanButton = widget.qrScanner?.isCameraSupported ?? false;
    final controlsEnabled = widget.enabled && !_isScanning;
    final canSubmit = controlsEnabled && _textController.text.trim().isNotEmpty;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(widget.title, style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 12),
            if (_scannerNotice != null) ...[
              Container(
                key: const Key('encounter_scanner_fallback_notice'),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: colorScheme.secondaryContainer,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    Icon(
                      Icons.info_outline,
                      size: 18,
                      color: colorScheme.onSecondaryContainer,
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        _scannerNotice!,
                        style: Theme.of(context).textTheme.bodySmall
                            ?.copyWith(color: colorScheme.onSecondaryContainer),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 12),
            ],
            TextField(
              key: widget.textFieldKey,
              controller: _textController,
              enabled: controlsEnabled,
              minLines: 2,
              maxLines: 4,
              autocorrect: false,
              enableSuggestions: false,
              style: AppTheme.monospaceStyle(context).copyWith(fontSize: 13),
              decoration: InputDecoration(
                border: const OutlineInputBorder(),
                hintText: widget.hintText,
                errorText: widget.inlineError,
                errorMaxLines: 3,
              ),
              onChanged: (_) => setState(() {}),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 12,
              runSpacing: 8,
              alignment: WrapAlignment.spaceBetween,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    if (showScanButton)
                      FilledButton.tonalIcon(
                        key: const Key('encounter_scan_qr_button'),
                        onPressed: controlsEnabled ? _scanQrCode : null,
                        icon: const Icon(Icons.qr_code_scanner, size: 18),
                        label: const Text('Scan QR Code'),
                      ),
                    OutlinedButton.icon(
                      key: widget.pasteButtonKey,
                      onPressed: controlsEnabled ? _pasteFromClipboard : null,
                      icon: const Icon(Icons.content_paste_outlined, size: 18),
                      label: const Text('Paste'),
                    ),
                  ],
                ),
                FilledButton.icon(
                  key: widget.submitButtonKey,
                  onPressed: canSubmit ? _submit : null,
                  icon: const Icon(Icons.arrow_forward, size: 18),
                  label: Text(widget.submitLabel),
                ),
              ],
            ),
            const SizedBox(height: 10),
            Text(
              showScanButton
                  ? 'Scan your peer\'s QR code with the camera or paste the URI manually.'
                  : 'Paste or enter your peer\'s Encounter URI manually.',
              style: Theme.of(context).textTheme.bodySmall
                  ?.copyWith(color: colorScheme.onSurfaceVariant),
            ),
          ],
        ),
      ),
    );
  }
}
