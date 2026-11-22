import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mesh_identity/mesh_identity.dart';

import '../../../core/theme.dart';
import '../../../services/encounter_session.dart';

/// Displays this device's 6-digit Short Authentication String (SAS) code and
/// requires manual 6-digit entry from the peer's screen before confirmation.
class SasConfirmationPanel extends StatefulWidget {
  final String title;
  final EncounterComparison comparison;
  final String? inlineError;
  final bool enabled;
  final ValueChanged<String> onConfirm;
  final VoidCallback? onCancel;
  final String confirmLabel;
  final Key? codeKey;
  final Key? inputKey;
  final Key? confirmButtonKey;
  final Key? cancelButtonKey;

  const SasConfirmationPanel({
    super.key,
    required this.title,
    required this.comparison,
    required this.onConfirm,
    this.inlineError,
    this.enabled = true,
    this.onCancel,
    this.confirmLabel = 'Confirm & Save Contact',
    this.codeKey,
    this.inputKey,
    this.confirmButtonKey,
    this.cancelButtonKey,
  });

  @override
  State<SasConfirmationPanel> createState() => _SasConfirmationPanelState();
}

class _SasConfirmationPanelState extends State<SasConfirmationPanel> {
  final TextEditingController _controller = TextEditingController();

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _confirm() {
    if (!widget.enabled || _controller.text.length != 6) return;
    widget.onConfirm(_controller.text);
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final formatted = formatSasDigits(widget.comparison);
    final digitCount = _controller.text.length;
    final canConfirm = widget.enabled && digitCount == 6;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(widget.title, style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 12),
            Text(
              'This device\'s 6-digit code:',
              style: Theme.of(context).textTheme.labelMedium
                  ?.copyWith(color: colorScheme.onSurfaceVariant),
            ),
            const SizedBox(height: 8),
            Container(
              padding: const EdgeInsets.symmetric(vertical: 16, horizontal: 20),
              decoration: BoxDecoration(
                color: colorScheme.primaryContainer,
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: colorScheme.primary.withValues(alpha: 0.35),
                ),
              ),
              alignment: Alignment.center,
              child: SelectableText(
                formatted,
                key: widget.codeKey,
                style: AppTheme.monospaceStyle(context).copyWith(
                  fontSize: 32,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 3,
                  color: colorScheme.onPrimaryContainer,
                ),
              ),
            ),
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: colorScheme.secondaryContainer,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Icon(
                    Icons.verified_outlined,
                    size: 20,
                    color: colorScheme.onSecondaryContainer,
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      EncounterUiText.instruction,
                      style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                        color: colorScheme.onSecondaryContainer,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            TextField(
              key: widget.inputKey,
              controller: _controller,
              enabled: widget.enabled,
              keyboardType: TextInputType.number,
              maxLength: 6,
              inputFormatters: [
                FilteringTextInputFormatter.digitsOnly,
                LengthLimitingTextInputFormatter(6),
              ],
              style: AppTheme.monospaceStyle(context)
                  .copyWith(fontSize: 20, letterSpacing: 4),
              decoration: InputDecoration(
                border: const OutlineInputBorder(),
                labelText: 'Enter peer\'s 6-digit code',
                hintText: '000000',
                counterText: '$digitCount / 6 digits',
                errorText: widget.inlineError,
                errorMaxLines: 3,
              ),
              onChanged: (_) => setState(() {}),
              onSubmitted: (_) => _confirm(),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 12,
              runSpacing: 8,
              alignment: WrapAlignment.spaceBetween,
              children: [
                if (widget.onCancel != null)
                  OutlinedButton(
                    key: widget.cancelButtonKey,
                    onPressed: widget.enabled ? widget.onCancel : null,
                    child: const Text('Codes Don\'t Match / Cancel'),
                  ),
                FilledButton.icon(
                  key: widget.confirmButtonKey,
                  onPressed: canConfirm ? _confirm : null,
                  icon: const Icon(Icons.check_circle_outline, size: 18),
                  label: Text(widget.confirmLabel),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
