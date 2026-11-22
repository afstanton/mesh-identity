import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';
import 'package:qr/qr.dart';

import '../../../core/theme.dart';

/// Pure-Flutter optical QR code matrix renderer using an explicit high-contrast
/// white canvas and ISO 4-module quiet zone regardless of dark/light app theme.
class EncounterQrView extends StatelessWidget {
  final String data;
  final double size;
  final String? semanticsLabel;

  const EncounterQrView({
    super.key,
    required this.data,
    this.size = 220,
    this.semanticsLabel,
  });

  @override
  Widget build(BuildContext context) {
    final qrCode = QrCode(
      payload: QrPayload.fromString(data),
      errorCorrectLevel: QrErrorCorrectLevel.medium,
    );
    final qrImage = QrImage(qrCode);

    return Semantics(
      label: semanticsLabel ?? 'Encounter QR code',
      image: true,
      child: Container(
        width: size,
        height: size,
        decoration: BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: Colors.black12),
        ),
        child: ClipRRect(
          borderRadius: BorderRadius.circular(11),
          child: CustomPaint(
            size: Size.square(size),
            painter: _QrMatrixPainter(data: data, qrImage: qrImage),
          ),
        ),
      ),
    );
  }
}

class _QrMatrixPainter extends CustomPainter {
  static const int _quietModules = 4;

  final String data;
  final QrImage qrImage;

  const _QrMatrixPainter({required this.data, required this.qrImage});

  @override
  void paint(Canvas canvas, Size size) {
    final bgPaint = Paint()..color = Colors.white;
    canvas.drawRect(Offset.zero & size, bgPaint);

    final moduleCount = qrImage.moduleCount;
    final totalModules = moduleCount + (_quietModules * 2);
    final cellSize = size.shortestSide / totalModules;
    final darkPaint = Paint()
      ..color = Colors.black
      ..isAntiAlias = false;

    for (var row = 0; row < moduleCount; row++) {
      for (var col = 0; col < moduleCount; col++) {
        if (qrImage.isDark(row, col)) {
          canvas.drawRect(
            Rect.fromLTWH(
              (col + _quietModules) * cellSize,
              (row + _quietModules) * cellSize,
              cellSize,
              cellSize,
            ),
            darkPaint,
          );
        }
      }
    }
  }

  @override
  bool shouldRepaint(covariant _QrMatrixPainter oldDelegate) =>
      oldDelegate.data != data;
}

/// Card presenting an outgoing Encounter QR code alongside its copyable URI text.
class EncounterPayloadCard extends StatelessWidget {
  final String title;
  final String subtitle;
  final String payloadUri;
  final String copyButtonLabel;
  final Key? copyButtonKey;

  const EncounterPayloadCard({
    super.key,
    required this.title,
    required this.subtitle,
    required this.payloadUri,
    this.copyButtonLabel = 'Copy Payload URI',
    this.copyButtonKey,
  });

  Future<void> _copyPayload(BuildContext context) async {
    await Clipboard.setData(ClipboardData(text: payloadUri));
    if (!context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Encounter payload copied to clipboard')),
    );
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(title, style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 6),
            Text(
              subtitle,
              style: Theme.of(context).textTheme.bodyMedium
                  ?.copyWith(color: colorScheme.onSurfaceVariant),
            ),
            const SizedBox(height: 16),
            Center(
              child: EncounterQrView(data: payloadUri, semanticsLabel: title),
            ),
            const SizedBox(height: 16),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: colorScheme.surfaceContainerHighest,
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: colorScheme.outlineVariant),
              ),
              constraints: const BoxConstraints(maxHeight: 96),
              child: SingleChildScrollView(
                child: SelectableText(
                  payloadUri,
                  style: AppTheme.monospaceStyle(context)
                      .copyWith(fontSize: 12),
                ),
              ),
            ),
            const SizedBox(height: 12),
            Align(
              alignment: Alignment.centerLeft,
              child: OutlinedButton.icon(
                key: copyButtonKey,
                onPressed: () => _copyPayload(context),
                icon: const Icon(Icons.copy_outlined, size: 18),
                label: Text(copyButtonLabel),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
