import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mesh_identity/mesh_identity.dart';

import '../../core/theme.dart';
import '../../services/encounter_session.dart';
import '../../services/identity_controller.dart';

/// Filter categories for the persona's contact address book.
enum ContactFilter { all, verified, unverified, blocked }

/// Slice 4: Contact governance, search, alias management, block/unblock, and
/// unverified hex peer key import for the active persona.
class ContactsView extends StatefulWidget {
  final IdentityController controller;
  final VoidCallback? onStartEncounter;

  const ContactsView({
    super.key,
    required this.controller,
    this.onStartEncounter,
  });

  @override
  State<ContactsView> createState() => _ContactsViewState();
}

class _ContactsViewState extends State<ContactsView> {
  final TextEditingController _searchController = TextEditingController();
  ContactFilter _filter = ContactFilter.all;

  @override
  void dispose() {
    _searchController.dispose();
    super.dispose();
  }

  List<Contact> _filteredContacts(List<Contact> contacts) {
    final query = _searchController.text.trim().toLowerCase();
    return contacts.where((contact) {
      switch (_filter) {
        case ContactFilter.all:
          break;
        case ContactFilter.verified:
          if (contact.verificationStatus != VerificationStatus.verified ||
              contact.status == ContactStatus.blocked) {
            return false;
          }
        case ContactFilter.unverified:
          if (contact.verificationStatus !=
                  VerificationStatus.importedUnverified ||
              contact.status == ContactStatus.blocked) {
            return false;
          }
        case ContactFilter.blocked:
          if (contact.status != ContactStatus.blocked) {
            return false;
          }
      }
      if (query.isEmpty) return true;
      final aliasMatch = contact.alias?.toLowerCase().contains(query) ?? false;
      final hexMatch = formatHexKey(contact.peerPublicKey)
          .toLowerCase()
          .contains(query);
      return aliasMatch || hexMatch;
    }).toList();
  }

  Future<void> _openImportDialog() async {
    final imported = await showDialog<Contact>(
      context: context,
      builder: (_) => _ImportPeerKeyDialog(controller: widget.controller),
    );
    if (!mounted || imported == null) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(
          'Imported unverified peer ${shortHexKey(imported.peerPublicKey)}',
        ),
      ),
    );
  }

  Future<void> _openContactDetail(Contact contact) async {
    await showDialog<void>(
      context: context,
      builder: (_) => _ContactDetailDialog(
        controller: widget.controller,
        initialContact: contact,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final contacts = widget.controller.contacts;
    final filtered = _filteredContacts(contacts);
    final encounterActive = widget.controller.hasActiveEncounter;

    return Align(
      alignment: Alignment.topCenter,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 820),
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            Row(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                Expanded(
                  child: Text(
                    '${contacts.length} '
                    '${contacts.length == 1 ? 'contact' : 'contacts'} '
                    'for the active persona',
                    style: theme.textTheme.bodyMedium?.copyWith(
                      color: theme.colorScheme.onSurfaceVariant,
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                FilledButton.icon(
                  key: const Key('import_peer_key_button'),
                  onPressed: encounterActive ? null : _openImportDialog,
                  icon: const Icon(Icons.key_outlined),
                  label: const Text('Import Peer Key'),
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
                          'Contact modifications are disabled while an '
                          'encounter ceremony is active.',
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
            if (contacts.isNotEmpty) ...[
              const SizedBox(height: 16),
              TextField(
                key: const Key('contacts_search_field'),
                controller: _searchController,
                onChanged: (_) => setState(() {}),
                decoration: InputDecoration(
                  labelText: 'Search contacts',
                  hintText: 'Filter by alias or public key hex',
                  prefixIcon: const Icon(Icons.search),
                  suffixIcon: _searchController.text.isEmpty
                      ? null
                      : IconButton(
                          tooltip: 'Clear search',
                          onPressed: () {
                            _searchController.clear();
                            setState(() {});
                          },
                          icon: const Icon(Icons.close),
                        ),
                  border: const OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 12),
              SingleChildScrollView(
                scrollDirection: Axis.horizontal,
                child: Row(
                  children: [
                    FilterChip(
                      key: const Key('filter_all'),
                      label: const Text('All'),
                      selected: _filter == ContactFilter.all,
                      onSelected: (_) =>
                          setState(() => _filter = ContactFilter.all),
                    ),
                    const SizedBox(width: 8),
                    FilterChip(
                      key: const Key('filter_verified'),
                      label: const Text('Verified'),
                      selected: _filter == ContactFilter.verified,
                      onSelected: (_) =>
                          setState(() => _filter = ContactFilter.verified),
                    ),
                    const SizedBox(width: 8),
                    FilterChip(
                      key: const Key('filter_unverified'),
                      label: const Text('Unverified'),
                      selected: _filter == ContactFilter.unverified,
                      onSelected: (_) =>
                          setState(() => _filter = ContactFilter.unverified),
                    ),
                    const SizedBox(width: 8),
                    FilterChip(
                      key: const Key('filter_blocked'),
                      label: const Text('Blocked'),
                      selected: _filter == ContactFilter.blocked,
                      onSelected: (_) =>
                          setState(() => _filter = ContactFilter.blocked),
                    ),
                  ],
                ),
              ),
            ],
            const SizedBox(height: 16),
            if (contacts.isEmpty)
              _EmptyContactsCard(
                icon: Icons.people_outline,
                title: 'No contacts yet',
                message:
                    'Meet someone in person to verify them, or import a '
                    'public key to add your first contact.',
                actionLabel: widget.onStartEncounter == null
                    ? null
                    : 'Start an Encounter',
                onAction: widget.onStartEncounter,
              )
            else if (filtered.isEmpty)
              _EmptyContactsCard(
                icon: Icons.filter_list_off,
                title: 'No matching contacts',
                message:
                    'Try clearing the search query or switching to a different '
                    'filter.',
              )
            else
              ...filtered.map(
                (contact) => Padding(
                  padding: const EdgeInsets.only(bottom: 10),
                  child: _ContactListCard(
                    contact: contact,
                    onTap: () => _openContactDetail(contact),
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

class _EmptyContactsCard extends StatelessWidget {
  final IconData icon;
  final String title;
  final String message;
  final String? actionLabel;
  final VoidCallback? onAction;

  const _EmptyContactsCard({
    required this.icon,
    required this.title,
    required this.message,
    this.actionLabel,
    this.onAction,
  });

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Card.outlined(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          children: [
            Icon(icon, size: 40, color: theme.colorScheme.onSurfaceVariant),
            const SizedBox(height: 12),
            Text(title, style: theme.textTheme.titleMedium),
            const SizedBox(height: 6),
            Text(
              message,
              textAlign: TextAlign.center,
              style: theme.textTheme.bodyMedium?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            if (actionLabel != null && onAction != null) ...[
              const SizedBox(height: 16),
              FilledButton.icon(
                key: const Key('empty_contacts_start_encounter_button'),
                onPressed: onAction,
                icon: const Icon(Icons.qr_code_2, size: 18),
                label: Text(actionLabel!),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _ContactListCard extends StatelessWidget {
  final Contact contact;
  final VoidCallback onTap;

  const _ContactListCard({required this.contact, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final shortHex = shortHexKey(contact.peerPublicKey);
    final hasAlias = contact.alias != null && contact.alias!.isNotEmpty;
    final isBlocked = contact.status == ContactStatus.blocked;
    final isVerified =
        contact.verificationStatus == VerificationStatus.verified;

    return Card.outlined(
      child: ListTile(
        key: Key('contact_tile_${formatHexKey(contact.peerPublicKey)}'),
        onTap: onTap,
        leading: CircleAvatar(
          backgroundColor: isBlocked
              ? theme.colorScheme.errorContainer
              : isVerified
              ? theme.colorScheme.primaryContainer
              : theme.colorScheme.surfaceContainerHighest,
          child: Icon(
            isBlocked
                ? Icons.block
                : isVerified
                ? Icons.verified_user_outlined
                : Icons.person_outline,
            color: isBlocked
                ? theme.colorScheme.onErrorContainer
                : isVerified
                ? theme.colorScheme.onPrimaryContainer
                : theme.colorScheme.onSurfaceVariant,
          ),
        ),
        title: Text(
          hasAlias ? contact.alias! : shortHex,
          style: hasAlias
              ? theme.textTheme.titleMedium
              : AppTheme.monospaceStyle(context),
        ),
        subtitle: Padding(
          padding: const EdgeInsets.only(top: 4),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              if (hasAlias)
                Text(shortHex, style: AppTheme.monospaceStyle(context)),
              const SizedBox(height: 4),
              Wrap(
                spacing: 6,
                runSpacing: 4,
                children: [
                  _StatusBadge(
                    label: isVerified ? 'Verified' : 'Imported (Unverified)',
                    color: isVerified
                        ? theme.colorScheme.primaryContainer
                        : theme.colorScheme.surfaceContainerHighest,
                    textColor: isVerified
                        ? theme.colorScheme.onPrimaryContainer
                        : theme.colorScheme.onSurfaceVariant,
                  ),
                  if (isBlocked)
                    _StatusBadge(
                      label: 'Blocked',
                      color: theme.colorScheme.errorContainer,
                      textColor: theme.colorScheme.onErrorContainer,
                    ),
                  _StatusBadge(
                    label:
                        '${contact.encounterCount} '
                        '${contact.encounterCount == 1 ? 'encounter' : 'encounters'}',
                    color: theme.colorScheme.secondaryContainer,
                    textColor: theme.colorScheme.onSecondaryContainer,
                  ),
                ],
              ),
            ],
          ),
        ),
        trailing: const Icon(Icons.chevron_right),
      ),
    );
  }
}

class _StatusBadge extends StatelessWidget {
  final String label;
  final Color color;
  final Color textColor;

  const _StatusBadge({
    required this.label,
    required this.color,
    required this.textColor,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        color: color,
        borderRadius: BorderRadius.circular(6),
      ),
      child: Text(
        label,
        style: Theme.of(context).textTheme.labelSmall
            ?.copyWith(color: textColor),
      ),
    );
  }
}

class _ContactDetailDialog extends StatefulWidget {
  final IdentityController controller;
  final Contact initialContact;

  const _ContactDetailDialog({
    required this.controller,
    required this.initialContact,
  });

  @override
  State<_ContactDetailDialog> createState() => _ContactDetailDialogState();
}

class _ContactDetailDialogState extends State<_ContactDetailDialog> {
  late Contact _contact;
  late final TextEditingController _aliasController;
  bool _isBusy = false;
  String? _errorMessage;
  String? _successMessage;

  @override
  void initState() {
    super.initState();
    _contact = widget.initialContact;
    _aliasController = TextEditingController(text: _contact.alias ?? '');
  }

  @override
  void dispose() {
    _aliasController.dispose();
    super.dispose();
  }

  void _refreshContact() {
    final latest = widget.controller.getContact(_contact.peerPublicKey);
    if (latest != null) {
      _contact = latest;
    }
  }

  Future<void> _saveAlias() async {
    final trimmed = _aliasController.text.trim();
    if (trimmed.isEmpty) {
      setState(() {
        _errorMessage = 'Alias cannot be empty.';
        _successMessage = null;
      });
      return;
    }
    setState(() {
      _isBusy = true;
      _errorMessage = null;
      _successMessage = null;
    });
    try {
      await widget.controller.setContactAlias(_contact.peerPublicKey, trimmed);
      if (!mounted) return;
      setState(() {
        _refreshContact();
        _aliasController.text = _contact.alias ?? trimmed;
        _successMessage = 'Alias updated.';
      });
    } on AliasConflictException {
      if (!mounted) return;
      setState(() {
        _errorMessage = EncounterUiText.aliasConflictWarning;
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() {
        _errorMessage = e.message;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _errorMessage = 'Failed to update alias: $e';
      });
    } finally {
      if (mounted) {
        setState(() => _isBusy = false);
      }
    }
  }

  Future<void> _blockContact() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Block contact?'),
        content: Text(
          'Blocking ${shortHexKey(_contact.peerPublicKey)} prevents future '
          'encounters with this peer until you unblock them.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            key: const Key('confirm_block_contact_button'),
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Block'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    setState(() {
      _isBusy = true;
      _errorMessage = null;
      _successMessage = null;
    });
    try {
      await widget.controller.blockContact(_contact.peerPublicKey);
      if (!mounted) return;
      setState(() {
        _refreshContact();
        _successMessage = 'Contact blocked.';
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to block contact: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _unblockContact() async {
    setState(() {
      _isBusy = true;
      _errorMessage = null;
      _successMessage = null;
    });
    try {
      await widget.controller.unblockContact(_contact.peerPublicKey);
      if (!mounted) return;
      setState(() {
        _refreshContact();
        _successMessage = 'Contact unblocked.';
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to unblock contact: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _copyHexKey() async {
    final hex = formatHexKey(_contact.peerPublicKey);
    await Clipboard.setData(ClipboardData(text: hex));
    if (!mounted) return;
    setState(() {
      _successMessage = 'Public key copied to clipboard.';
      _errorMessage = null;
    });
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final fullHex = formatHexKey(_contact.peerPublicKey);
    final isBlocked = _contact.status == ContactStatus.blocked;
    final isVerified =
        _contact.verificationStatus == VerificationStatus.verified;
    final encounterActive = widget.controller.hasActiveEncounter;

    return AlertDialog(
      title: Text(
        _contact.alias?.isNotEmpty == true
            ? _contact.alias!
            : shortHexKey(_contact.peerPublicKey),
      ),
      content: SizedBox(
        width: 460,
        child: SingleChildScrollView(
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text('Peer Public Key', style: theme.textTheme.labelMedium),
              const SizedBox(height: 6),
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: theme.colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Row(
                  children: [
                    Expanded(
                      child: SelectableText(
                        fullHex,
                        style: AppTheme.monospaceStyle(context),
                      ),
                    ),
                    IconButton(
                      key: const Key('copy_contact_key_button'),
                      tooltip: 'Copy public key',
                      onPressed: _copyHexKey,
                      icon: const Icon(Icons.copy_outlined, size: 18),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 14),
              _DetailRow(
                label: 'Verification',
                value: isVerified
                    ? 'Verified (In-Person Encounter)'
                    : 'Imported (Unverified)',
              ),
              _DetailRow(
                label: 'Status',
                value: isBlocked ? 'Blocked' : 'Active',
              ),
              _DetailRow(
                label: 'Encounters',
                value: '${_contact.encounterCount}',
              ),
              _DetailRow(
                label: 'Recorded (UTC)',
                value: _contact.verifiedAt.toUtc().toIso8601String(),
              ),
              const SizedBox(height: 16),
              TextField(
                key: const Key('alias_input_field'),
                controller: _aliasController,
                enabled: !_isBusy && !encounterActive,
                maxLength: MeshInstallation.maxAliasBytes,
                decoration: const InputDecoration(
                  labelText: 'Local Alias',
                  hintText: 'Enter a unique local name (up to 64 bytes)',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 8),
              Align(
                alignment: Alignment.centerRight,
                child: FilledButton.tonal(
                  key: const Key('save_alias_button'),
                  onPressed: _isBusy || encounterActive ? null : _saveAlias,
                  child: const Text('Save Alias'),
                ),
              ),
              if (_errorMessage != null) ...[
                const SizedBox(height: 12),
                Text(
                  _errorMessage!,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.error,
                  ),
                ),
              ],
              if (_successMessage != null) ...[
                const SizedBox(height: 12),
                Text(
                  _successMessage!,
                  style: theme.textTheme.bodySmall?.copyWith(
                    color: theme.colorScheme.primary,
                  ),
                ),
              ],
            ],
          ),
        ),
      ),
      actions: [
        if (isBlocked)
          FilledButton.tonalIcon(
            key: const Key('unblock_contact_button'),
            onPressed: _isBusy || encounterActive ? null : _unblockContact,
            icon: const Icon(Icons.lock_open_outlined),
            label: const Text('Unblock'),
          )
        else
          TextButton.icon(
            key: const Key('block_contact_button'),
            onPressed: _isBusy || encounterActive ? null : _blockContact,
            icon: Icon(Icons.block, color: theme.colorScheme.error),
            label: Text(
              'Block',
              style: TextStyle(color: theme.colorScheme.error),
            ),
          ),
        TextButton(
          onPressed: _isBusy ? null : () => Navigator.of(context).pop(),
          child: const Text('Close'),
        ),
      ],
    );
  }
}

class _DetailRow extends StatelessWidget {
  final String label;
  final String value;

  const _DetailRow({required this.label, required this.value});

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 120,
            child: Text(
              label,
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ),
          Expanded(child: Text(value, style: theme.textTheme.bodySmall)),
        ],
      ),
    );
  }
}

class _ImportPeerKeyDialog extends StatefulWidget {
  final IdentityController controller;

  const _ImportPeerKeyDialog({required this.controller});

  @override
  State<_ImportPeerKeyDialog> createState() => _ImportPeerKeyDialogState();
}

class _ImportPeerKeyDialogState extends State<_ImportPeerKeyDialog> {
  final TextEditingController _hexController = TextEditingController();
  bool _isBusy = false;
  String? _errorMessage;

  @override
  void dispose() {
    _hexController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    setState(() {
      _isBusy = true;
      _errorMessage = null;
    });
    try {
      final keyBytes = parseHexPublicKey(_hexController.text);
      final contact = await widget.controller.importPeerKey(keyBytes);
      if (!mounted) return;
      Navigator.of(context).pop(contact);
    } on FormatException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to import peer key: $e');
    } finally {
      if (mounted) {
        setState(() => _isBusy = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    return AlertDialog(
      title: const Text('Import Unverified Peer Key'),
      content: SizedBox(
        width: 440,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Imported keys are marked Unverified until confirmed in an '
              'in-person Encounter ceremony.',
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('import_peer_key_field'),
              controller: _hexController,
              enabled: !_isBusy,
              maxLines: 2,
              style: AppTheme.monospaceStyle(context),
              decoration: const InputDecoration(
                labelText: 'Peer Public Key (64 hex chars)',
                hintText: '0123abcd...',
                border: OutlineInputBorder(),
              ),
            ),
            if (_errorMessage != null) ...[
              const SizedBox(height: 10),
              Text(
                _errorMessage!,
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.error,
                ),
              ),
            ],
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _isBusy ? null : () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          key: const Key('confirm_import_peer_key_button'),
          onPressed: _isBusy ? null : _submit,
          child: const Text('Import'),
        ),
      ],
    );
  }
}
