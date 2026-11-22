import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mesh_identity/mesh_identity.dart';

import '../../core/theme.dart';
import '../../services/encounter_session.dart';
import '../../services/identity_controller.dart';

/// Slice 4: Multi-persona identity management (create, switch active persona,
/// inspect per-persona contact counts, copy public key, and remove inactive
/// personas).
class IdentityView extends StatefulWidget {
  final IdentityController controller;

  const IdentityView({super.key, required this.controller});

  @override
  State<IdentityView> createState() => _IdentityViewState();
}

class _IdentityViewState extends State<IdentityView> {
  bool _isBusy = false;
  String? _errorMessage;

  Future<void> _addPersona() async {
    setState(() {
      _isBusy = true;
      _errorMessage = null;
    });
    try {
      final created = await widget.controller.addPersona();
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Added persona ${shortHexKey(created)}')),
      );
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to add persona: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _selectPersona(Uint8List identityKey) async {
    setState(() {
      _isBusy = true;
      _errorMessage = null;
    });
    try {
      await widget.controller.selectPersona(identityKey);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'Switched active persona to ${shortHexKey(identityKey)}',
          ),
        ),
      );
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to switch persona: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _removePersona(Uint8List identityKey) async {
    final contactCount = widget.controller.contactsCountForPersona(identityKey);
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Remove persona?'),
        content: Text(
          'Removing ${shortHexKey(identityKey)} permanently deletes its '
          'local signing seed from this device and removes its $contactCount '
          'persona-scoped ${contactCount == 1 ? 'contact' : 'contacts'}.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            key: const Key('confirm_remove_persona_button'),
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    setState(() {
      _isBusy = true;
      _errorMessage = null;
    });
    try {
      await widget.controller.removePersona(identityKey);
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Removed persona ${shortHexKey(identityKey)}')),
      );
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to remove persona: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _copyPublicKey(Uint8List identityKey) async {
    await Clipboard.setData(ClipboardData(text: formatHexKey(identityKey)));
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('Copied public key ${shortHexKey(identityKey)}')),
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final selected = widget.controller.selectedIdentity;
    final identities = widget.controller.identities;
    final encounterActive = widget.controller.hasActiveEncounter;
    final actionsDisabled = _isBusy || encounterActive;

    return Align(
      alignment: Alignment.topCenter,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 820),
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('Identity', style: theme.textTheme.headlineSmall),
                      const SizedBox(height: 4),
                      Text(
                        '${identities.length} '
                        '${identities.length == 1 ? 'persona' : 'personas'} '
                        'on this installation',
                        style: theme.textTheme.bodyMedium?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 12),
                FilledButton.icon(
                  key: const Key('add_persona_button'),
                  onPressed: actionsDisabled ? null : _addPersona,
                  icon: const Icon(Icons.person_add_outlined),
                  label: const Text('Add Persona'),
                ),
              ],
            ),
            if (encounterActive) ...[
              const SizedBox(height: 12),
              Card(
                color: theme.colorScheme.secondaryContainer,
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Row(
                    children: [
                      Icon(
                        Icons.info_outline,
                        color: theme.colorScheme.onSecondaryContainer,
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: Text(
                          'Persona changes are disabled while an encounter '
                          'ceremony is active.',
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSecondaryContainer,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
            if (_errorMessage != null) ...[
              const SizedBox(height: 12),
              Card(
                color: theme.colorScheme.errorContainer,
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Text(
                    _errorMessage!,
                    style: theme.textTheme.bodySmall?.copyWith(
                      color: theme.colorScheme.onErrorContainer,
                    ),
                  ),
                ),
              ),
            ],
            const SizedBox(height: 16),
            ...identities.map((identity) {
              final hex = formatHexKey(identity);
              final isSelected =
                  selected != null && listEquals(identity, selected);
              final contactCount = widget.controller.contactsCountForPersona(
                identity,
              );
              return Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Card.outlined(
                  key: Key('persona_card_$hex'),
                  child: Padding(
                    padding: const EdgeInsets.all(16),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Expanded(
                              child: Text(
                                shortHexKey(identity),
                                style: theme.textTheme.titleMedium?.merge(
                                  AppTheme.monospaceStyle(context),
                                ),
                              ),
                            ),
                            if (isSelected)
                              Chip(
                                key: const Key('active_persona_chip'),
                                label: const Text('Active'),
                                avatar: const Icon(Icons.check, size: 16),
                                visualDensity: VisualDensity.compact,
                              ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        Row(
                          children: [
                            Expanded(
                              child: SelectableText(
                                hex,
                                style: AppTheme.monospaceStyle(context)
                                    .copyWith(
                                      fontSize: 12,
                                      color: theme.colorScheme.onSurfaceVariant,
                                    ),
                              ),
                            ),
                            IconButton(
                              key: Key('copy_persona_key_$hex'),
                              tooltip: 'Copy public key',
                              onPressed: () => _copyPublicKey(identity),
                              icon: const Icon(Icons.copy_outlined, size: 18),
                            ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        Text(
                          '$contactCount '
                          '${contactCount == 1 ? 'contact' : 'contacts'}',
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onSurfaceVariant,
                          ),
                        ),
                        if (!isSelected) ...[
                          const SizedBox(height: 12),
                          Wrap(
                            spacing: 8,
                            runSpacing: 8,
                            children: [
                              FilledButton.tonalIcon(
                                key: Key('switch_persona_$hex'),
                                onPressed: actionsDisabled
                                    ? null
                                    : () => _selectPersona(identity),
                                icon: const Icon(Icons.swap_horiz),
                                label: const Text('Switch'),
                              ),
                              TextButton.icon(
                                key: Key('remove_persona_$hex'),
                                onPressed: actionsDisabled
                                    ? null
                                    : () => _removePersona(identity),
                                icon: Icon(
                                  Icons.delete_outline,
                                  color: theme.colorScheme.error,
                                ),
                                label: Text(
                                  'Remove',
                                  style: TextStyle(
                                    color: theme.colorScheme.error,
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ],
                      ],
                    ),
                  ),
                ),
              );
            }),
            const SizedBox(height: 8),
            Card.outlined(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Upcoming Capabilities',
                      style: theme.textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Slice 6: Multi-device encrypted handoff export/import.\n'
                      'Slice 8: OpenPGP public-key certificate export.',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
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
