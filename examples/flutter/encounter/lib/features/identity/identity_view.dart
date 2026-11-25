import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mesh_identity/mesh_identity.dart';

import '../../core/theme.dart';
import '../../services/encounter_session.dart';
import '../../services/handoff_codec.dart';
import '../../services/identity_controller.dart';
import 'device_handoff_screen.dart';
import 'openpgp_bridge_screen.dart';

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
  Timer? _clipboardClearTimer;

  @override
  void dispose() {
    _clipboardClearTimer?.cancel();
    super.dispose();
  }

  Future<void> _addPersona() async {
    var label = '';
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Create Persona'),
        content: TextField(
          key: const Key('persona_name_field'),
          maxLength: IdentityController.maxLocalLabelLength,
          onChanged: (value) => label = value,
          decoration: const InputDecoration(
            labelText: 'Display name (optional)',
            hintText: 'e.g. Work, Personal',
            border: OutlineInputBorder(),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            key: const Key('confirm_add_persona_button'),
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Create'),
          ),
        ],
      ),
    );
    final trimmed = label.trim();
    if (confirmed != true || !mounted) return;

    setState(() {
      _isBusy = true;
      _errorMessage = null;
    });
    try {
      final created = await widget.controller.addPersona();
      String? labelError;
      if (trimmed.isNotEmpty) {
        try {
          await widget.controller.setPersonaLabel(created, trimmed);
        } catch (e) {
          labelError = 'Persona created, but saving the local name failed: $e';
        }
      }
      if (!mounted) return;
      final display = (trimmed.isNotEmpty && labelError == null)
          ? trimmed
          : shortHexKey(created);
      if (labelError != null) {
        setState(() => _errorMessage = labelError);
      }
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('Added persona $display')));
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

  Future<void> _editPersonaLabel(Uint8List identityKey) async {
    var label = widget.controller.personaLabel(identityKey) ?? '';
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Rename Persona'),
        content: TextFormField(
          key: const Key('rename_persona_field'),
          initialValue: label,
          maxLength: IdentityController.maxLocalLabelLength,
          onChanged: (value) => label = value,
          decoration: const InputDecoration(
            labelText: 'Display name (local only)',
            hintText: 'e.g. Work, Personal',
            border: OutlineInputBorder(),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            key: const Key('confirm_rename_persona_button'),
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Save'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    await widget.controller.setPersonaLabel(identityKey, label.trim());
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

  static String _votingStateLabel(VotingState state) {
    return switch (state) {
      VotingState.voting => 'Voting',
      VotingState.stopped => 'Stopped',
      VotingState.gated => 'Gated',
    };
  }

  void _openDeviceHandoff() {
    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => DeviceHandoffScreen(controller: widget.controller),
      ),
    );
  }

  void _openOpenPgpBridge() {
    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => OpenPgpBridgeScreen(controller: widget.controller),
      ),
    );
  }

  Future<void> _importPersonaSeed() async {
    final imported = await showDialog<Uint8List>(
      context: context,
      builder: (_) => _ImportPersonaSeedDialog(controller: widget.controller),
    );
    if (!mounted || imported == null) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('Imported persona ${shortHexKey(imported)}')),
    );
  }

  Future<void> _exportPersonaSeed(Uint8List identityKey) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Copy Persona Signing Seed?'),
        content: Text(
          'WARNING: This copies the private 32-byte signing seed for '
          '${shortHexKey(identityKey)} to your clipboard as plain text. Anyone '
          'or any app with clipboard access (including OS clipboard history '
          'or synced clipboards) gains full, permanent control of this persona, '
          'not just its voting role. Encounter will attempt to clear the '
          'clipboard after 30 seconds.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            key: const Key('confirm_export_persona_seed_button'),
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Copy Seed'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    Uint8List? seed;
    try {
      seed = await widget.controller.exportPersonaSeed(identityKey);
      final hexSeed = formatHexKey(seed);
      await Clipboard.setData(ClipboardData(text: hexSeed));
      _clipboardClearTimer?.cancel();
      _clipboardClearTimer = Timer(const Duration(seconds: 30), () async {
        try {
          final current = await Clipboard.getData(Clipboard.kTextPlain);
          if (current?.text == hexSeed) {
            await Clipboard.setData(const ClipboardData(text: ''));
          }
        } catch (_) {
          // Best-effort clipboard clear.
        }
      });
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'Copied private seed for ${shortHexKey(identityKey)}. '
            'Clipboard will auto-clear in 30 seconds.',
          ),
        ),
      );
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to export seed: $e');
    } finally {
      if (seed != null) {
        seed.fillRange(0, seed.length, 0);
      }
    }
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
            Wrap(
              spacing: 12,
              runSpacing: 12,
              alignment: WrapAlignment.spaceBetween,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                Text(
                  '${identities.length} '
                  '${identities.length == 1 ? 'persona' : 'personas'} '
                  'on this installation',
                  style: theme.textTheme.bodyMedium?.copyWith(
                    color: theme.colorScheme.onSurfaceVariant,
                  ),
                ),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    OutlinedButton.icon(
                      key: const Key('import_persona_seed_button'),
                      onPressed: actionsDisabled ? null : _importPersonaSeed,
                      icon: const Icon(Icons.key_outlined),
                      label: const Text('Import Seed'),
                    ),
                    FilledButton.icon(
                      key: const Key('add_persona_button'),
                      onPressed: actionsDisabled ? null : _addPersona,
                      icon: const Icon(Icons.person_add_outlined),
                      label: const Text('Add Persona'),
                    ),
                  ],
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
              final votingRecord = widget.controller.votingRecordForPersona(
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
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  if (widget.controller.personaLabel(
                                        identity,
                                      ) !=
                                      null) ...[
                                    Text(
                                      widget.controller.personaLabel(identity)!,
                                      style: theme.textTheme.titleMedium,
                                    ),
                                    const SizedBox(height: 2),
                                  ],
                                  Text(
                                    shortHexKey(identity),
                                    style:
                                        (widget.controller.personaLabel(
                                                      identity,
                                                    ) !=
                                                    null
                                                ? theme.textTheme.bodyMedium
                                                : theme.textTheme.titleMedium)
                                            ?.merge(
                                              AppTheme.monospaceStyle(context),
                                            ),
                                  ),
                                ],
                              ),
                            ),
                            IconButton(
                              key: Key('rename_persona_button_$hex'),
                              tooltip: 'Rename persona',
                              onPressed: actionsDisabled
                                  ? null
                                  : () => _editPersonaLabel(identity),
                              icon: const Icon(Icons.edit_outlined, size: 18),
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
                        Wrap(
                          spacing: 12,
                          runSpacing: 4,
                          crossAxisAlignment: WrapCrossAlignment.center,
                          children: [
                            Text(
                              '$contactCount '
                              '${contactCount == 1 ? 'contact' : 'contacts'}',
                              style: theme.textTheme.bodySmall?.copyWith(
                                color: theme.colorScheme.onSurfaceVariant,
                              ),
                            ),
                            if (votingRecord != null)
                              Tooltip(
                                message: 'Active signing role for this device',
                                child: Text(
                                  'Role: ${_votingStateLabel(votingRecord.state)} '
                                  '(Counter ${votingRecord.counter})',
                                  style: theme.textTheme.bodySmall?.copyWith(
                                    color: theme.colorScheme.onSurfaceVariant,
                                  ),
                                ),
                              ),
                          ],
                        ),
                        const SizedBox(height: 12),
                        Wrap(
                          spacing: 8,
                          runSpacing: 8,
                          children: [
                            if (!isSelected)
                              FilledButton.tonalIcon(
                                key: Key('switch_persona_$hex'),
                                onPressed: actionsDisabled
                                    ? null
                                    : () => _selectPersona(identity),
                                icon: const Icon(Icons.swap_horiz),
                                label: const Text('Switch'),
                              ),
                            OutlinedButton.icon(
                              key: Key('export_persona_seed_$hex'),
                              onPressed: actionsDisabled
                                  ? null
                                  : () => _exportPersonaSeed(identity),
                              icon: const Icon(
                                Icons.vpn_key_outlined,
                                size: 18,
                              ),
                              label: const Text('Export Seed'),
                            ),
                            if (!isSelected)
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
                      'Device Handoff & Voting Role',
                      style: theme.textTheme.titleMedium,
                    ),
                    const SizedBox(height: 6),
                    Tooltip(
                      message: 'Unique per-device transfer token',
                      child: Text(
                        widget.controller.deviceNonce == null
                            ? 'Device nonce: not generated yet.'
                            : 'Device nonce: ${shortHexKey(widget.controller.deviceNonce!)}',
                        style: AppTheme.monospaceStyle(context).copyWith(
                          fontSize: 12,
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ),
                    const SizedBox(height: 12),
                    FilledButton.tonalIcon(
                      key: const Key('open_device_handoff_button'),
                      onPressed: actionsDisabled ? null : _openDeviceHandoff,
                      icon: const Icon(Icons.devices_outlined),
                      label: const Text('Open Device Handoff'),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 12),
            Card.outlined(
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'OpenPGP Interoperability',
                      style: theme.textTheme.titleMedium,
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Inspect certificates, preview & export v4/v6 OpenPGP '
                      'public keys with cross-certification, and import peer '
                      'or owned OpenPGP keys.',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                    const SizedBox(height: 12),
                    FilledButton.tonalIcon(
                      key: const Key('open_openpgp_bridge_button'),
                      onPressed: actionsDisabled ? null : _openOpenPgpBridge,
                      icon: const Icon(Icons.vpn_key_outlined),
                      label: const Text('Open OpenPGP Bridge'),
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

class _ImportPersonaSeedDialog extends StatefulWidget {
  final IdentityController controller;

  const _ImportPersonaSeedDialog({required this.controller});

  @override
  State<_ImportPersonaSeedDialog> createState() =>
      _ImportPersonaSeedDialogState();
}

class _ImportPersonaSeedDialogState extends State<_ImportPersonaSeedDialog> {
  final TextEditingController _seedController = TextEditingController();
  bool _isBusy = false;
  String? _errorMessage;

  @override
  void dispose() {
    _seedController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    setState(() {
      _isBusy = true;
      _errorMessage = null;
    });
    Uint8List? seedBytes;
    try {
      seedBytes = parseHexSeed(_seedController.text);
      final key = await widget.controller.importPersonaSeed(seedBytes);
      if (!mounted) return;
      Navigator.of(context).pop(key);
    } on FormatException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to import seed: $e');
    } finally {
      if (seedBytes != null) {
        seedBytes.fillRange(0, seedBytes.length, 0);
      }
      if (mounted) {
        setState(() => _isBusy = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return AlertDialog(
      title: const Text('Import Persona Signing Seed'),
      content: SizedBox(
        width: 440,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Import a 64-character hex Ed25519 signing seed from another '
              'device to provision a shared persona. Imported personas start '
              'in Gated state until a device handoff transfers the voting role.',
              style: theme.textTheme.bodySmall,
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('import_persona_seed_field'),
              controller: _seedController,
              enabled: !_isBusy,
              maxLines: 1,
              obscureText: true,
              style: AppTheme.monospaceStyle(context),
              decoration: InputDecoration(
                labelText: 'Persona Seed (64 hex chars)',
                border: const OutlineInputBorder(),
                errorText: _errorMessage,
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _isBusy ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          key: const Key('confirm_import_persona_seed_button'),
          onPressed: _isBusy ? null : _submit,
          child: const Text('Import'),
        ),
      ],
    );
  }
}
