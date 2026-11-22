import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import '../../../core/theme.dart';

/// Text and clipboard import panel for incoming peer `mesh:encounter:` URIs.
class EncounterPayloadInput extends StatefulWidget {
  final String title;
  final String hintText;
  final String submitLabel;
  final String? inlineError;
  final bool enabled;
  final ValueChanged<String> onSubmit;
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
    this.textFieldKey,
    this.pasteButtonKey,
    this.submitButtonKey,
  });

  @override
  State<EncounterPayloadInput> createState() => _EncounterPayloadInputState();
}

class _EncounterPayloadInputState extends State<EncounterPayloadInput> {
  final TextEditingController _textController = TextEditingController();

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
      _textController.text = text;
      _textController.selection = TextSelection.collapsed(offset: text.length);
    });
  }

  void _submit() {
    final value = _textController.text.trim();
    if (value.isEmpty || !widget.enabled) return;
    widget.onSubmit(value);
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final canSubmit = widget.enabled && _textController.text.trim().isNotEmpty;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(widget.title, style: Theme.of(context).textTheme.titleMedium),
            const SizedBox(height: 12),
            TextField(
              key: widget.textFieldKey,
              controller: _textController,
              enabled: widget.enabled,
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
                OutlinedButton.icon(
                  key: widget.pasteButtonKey,
                  onPressed: widget.enabled ? _pasteFromClipboard : null,
                  icon: const Icon(Icons.content_paste_outlined, size: 18),
                  label: const Text('Paste'),
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
              'Manual payload URI import (camera QR scanning arrives in Slice 5).',
              style: Theme.of(context).textTheme.bodySmall
                  ?.copyWith(color: colorScheme.onSurfaceVariant),
            ),
          ],
        ),
      ),
    );
  }
}
