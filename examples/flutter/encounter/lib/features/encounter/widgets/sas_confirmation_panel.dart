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
  final String codeLabel;

  const SasConfirmationPanel({
    super.key,
    required this.title,
    required this.comparison,
    required this.onConfirm,
    this.inlineError,
    this.enabled = true,
    this.onCancel,
    this.confirmLabel = 'Confirm & Save Contact',
    this.codeLabel = 'This device\'s match code (SAS):',
    this.codeKey,
    this.inputKey,
    this.confirmButtonKey,
    this.cancelButtonKey,
  });

  @override
  State<SasConfirmationPanel> createState() => _SasConfirmationPanelState();
}

class _GroupedSixDigitFormatter extends TextInputFormatter {
  @override
  TextEditingValue formatEditUpdate(
    TextEditingValue oldValue,
    TextEditingValue newValue,
  ) {
    final digitsOnly = newValue.text.replaceAll(RegExp(r'\D'), '');
    final clamped = digitsOnly.length > 6
        ? digitsOnly.substring(0, 6)
        : digitsOnly;
    final formatted = clamped.length <= 3
        ? clamped
        : '${clamped.substring(0, 3)} ${clamped.substring(3)}';
    return TextEditingValue(
      text: formatted,
      selection: TextSelection.collapsed(offset: formatted.length),
    );
  }
}

class _SasConfirmationPanelState extends State<SasConfirmationPanel> {
  final TextEditingController _controller = TextEditingController();

  String get _rawDigits => _controller.text.replaceAll(RegExp(r'\D'), '');

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _confirm() {
    final digits = _rawDigits;
    if (!widget.enabled || digits.length != 6) return;
    widget.onConfirm(digits);
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final formatted = formatSasDigits(widget.comparison);
    final digitCount = _rawDigits.length;
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
              widget.codeLabel,
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
              textInputAction: TextInputAction.done,
              inputFormatters: [_GroupedSixDigitFormatter()],
              style: AppTheme.monospaceStyle(context)
                  .copyWith(fontSize: 20, letterSpacing: 4),
              decoration: InputDecoration(
                border: const OutlineInputBorder(),
                labelText: 'Enter peer\'s 6-digit match code',
                hintText: '000 000',
                counterText: '$digitCount / 6 digits',
                errorText: widget.inlineError,
                errorMaxLines: 3,
              ),
              onTapOutside: (_) =>
                  FocusManager.instance.primaryFocus?.unfocus(),
              onChanged: (_) {
                setState(() {});
                if (_rawDigits.length == 6) {
                  FocusManager.instance.primaryFocus?.unfocus();
                }
              },
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
