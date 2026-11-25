import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mesh_identity/mesh_identity.dart';

import '../../core/theme.dart';
import '../../services/encounter_session.dart';
import '../../services/group_controller.dart';
import '../../services/group_frame_codec.dart';
import '../../services/group_outbox.dart';
import '../../services/identity_controller.dart';

/// Slice 7: Byzantine group admission, genesis import, verified contact
/// invitations, two-phase commit outbox, and inbound frame exchange.
class GroupsView extends StatefulWidget {
  final IdentityController identityController;
  final GroupController groupController;

  const GroupsView({
    super.key,
    required this.identityController,
    required this.groupController,
  });

  @override
  State<GroupsView> createState() => _GroupsViewState();
}

class _GroupsViewState extends State<GroupsView> {
  final TextEditingController _inboundFrameController = TextEditingController();
  Uint8List? _selectedSenderKey;
  bool _isBusy = false;
  String? _errorMessage;
  String? _statusMessage;

  @override
  void initState() {
    super.initState();
    _ensureInitialized();
  }

  @override
  void didUpdateWidget(covariant GroupsView oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.groupController != widget.groupController ||
        oldWidget.identityController != widget.identityController) {
      _ensureInitialized();
    }
  }

  void _ensureInitialized() {
    if (!widget.identityController.isReady) return;
    if (widget.groupController.status == GroupControllerStatus.uninitialized) {
      unawaited(widget.groupController.initialize());
    }
  }

  @override
  void dispose() {
    _inboundFrameController.dispose();
    super.dispose();
  }

  List<Contact> get _verifiedActiveContacts => widget
      .identityController
      .contacts
      .where(
        (c) =>
            c.status == ContactStatus.active &&
            c.verificationStatus == VerificationStatus.verified,
      )
      .toList(growable: false);

  String _contactLabel(Uint8List key) {
    final contact = widget.identityController.getContact(key);
    if (contact?.alias != null && contact!.alias!.isNotEmpty) {
      return '${contact.alias} (${shortHexKey(key)})';
    }
    if (widget.identityController.selectedIdentity != null &&
        listEquals(widget.identityController.selectedIdentity, key)) {
      return 'You (${shortHexKey(key)})';
    }
    return shortHexKey(key);
  }

  static String _shortGroupId(BigInt groupId) {
    final s = groupId.toString();
    return s.length <= 8 ? s : s.substring(0, 8);
  }

  String _groupTitle(BigInt groupId) {
    final name = widget.identityController.groupName(groupId);
    if (name != null && name.isNotEmpty) return name;
    return 'Group #${_shortGroupId(groupId)}';
  }

  Future<void> _createGroup() async {
    final verifiedContacts = _verifiedActiveContacts;
    final selectedKeys = <String, Uint8List>{};
    var groupNameInput = '';

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => StatefulBuilder(
        builder: (dialogContext, setDialogState) => AlertDialog(
          title: const Text('Create Group'),
          content: SizedBox(
            width: 440,
            child: SingleChildScrollView(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'Create a new group with your active identity. You can '
                    'include verified contacts now or invite them later.',
                    style: Theme.of(dialogContext).textTheme.bodySmall,
                  ),
                  const SizedBox(height: 12),
                  TextField(
                    key: const Key('group_name_field'),
                    maxLength: IdentityController.maxLocalLabelLength,
                    onChanged: (value) => groupNameInput = value,
                    decoration: const InputDecoration(
                      labelText: 'Group name (optional)',
                      hintText: 'e.g. Family, Field Team',
                      border: OutlineInputBorder(),
                    ),
                  ),
                  const SizedBox(height: 12),
                  if (verifiedContacts.isEmpty)
                    Text(
                      'No verified contacts yet. You can create a solo group '
                      'now and invite verified contacts later.',
                      style: Theme.of(dialogContext).textTheme.bodySmall
                          ?.copyWith(
                            color: Theme.of(dialogContext)
                                .colorScheme
                                .onSurfaceVariant,
                          ),
                    )
                  else
                    ...verifiedContacts.map((contact) {
                      final hex = formatHexKey(contact.peerPublicKey);
                      final checked = selectedKeys.containsKey(hex);
                      return CheckboxListTile(
                        dense: true,
                        value: checked,
                        title: Text(
                          contact.alias?.isNotEmpty == true
                              ? contact.alias!
                              : shortHexKey(contact.peerPublicKey),
                        ),
                        subtitle: Text(shortHexKey(contact.peerPublicKey)),
                        onChanged: (val) {
                          setDialogState(() {
                            if (val == true) {
                              selectedKeys[hex] = contact.peerPublicKey;
                            } else {
                              selectedKeys.remove(hex);
                            }
                          });
                        },
                      );
                    }),
                ],
              ),
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(dialogContext).pop(false),
              child: const Text('Cancel'),
            ),
            FilledButton(
              key: const Key('confirm_create_group_button'),
              onPressed: () => Navigator.of(dialogContext).pop(true),
              child: const Text('Create Group'),
            ),
          ],
        ),
      ),
    );
    final groupName = groupNameInput.trim();
    if (confirmed != true || !mounted) return;

    setState(() {
      _isBusy = true;
      _errorMessage = null;
      _statusMessage = null;
    });
    try {
      final existingGroupIds = widget.groupController.groups
          .map((g) => g.groupId)
          .toSet();
      await widget.groupController.createGroup(
        members: selectedKeys.values.toList(growable: false),
      );
      String? labelWarning;
      if (groupName.isNotEmpty) {
        final createdGroups = widget.groupController.groups
            .where((g) => !existingGroupIds.contains(g.groupId))
            .toList(growable: false);
        if (createdGroups.isNotEmpty) {
          try {
            await widget.identityController.setGroupName(
              createdGroups.first.groupId,
              groupName,
            );
          } catch (e) {
            labelWarning =
                'Group created, but saving the local name failed: $e';
          }
        }
      }
      if (!mounted) return;
      setState(() {
        _statusMessage = 'Group created.';
        if (labelWarning != null) {
          _errorMessage = labelWarning;
        }
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to create group: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _openImportGenesisDialog() async {
    final result = await showDialog<bool>(
      context: context,
      builder: (_) => _ImportGenesisDialog(controller: widget.groupController),
    );
    if (!mounted || result != true) return;
    setState(() {
      _statusMessage = 'Authenticated genesis imported.';
      _errorMessage = null;
    });
  }

  Future<void> _inviteContact(GroupView group) async {
    final candidates = _verifiedActiveContacts
        .where((c) => !group.isMember(c.peerPublicKey))
        .toList(growable: false);
    if (candidates.isEmpty) {
      setState(() {
        _errorMessage =
            'No eligible verified contacts outside this group. Verify a peer '
            'in Encounter first.';
      });
      return;
    }

    final chosen = await showDialog<Contact>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Text('Invite to Group ${group.groupId}'),
        content: SizedBox(
          width: 420,
          child: ListView.builder(
            shrinkWrap: true,
            itemCount: candidates.length,
            itemBuilder: (_, index) {
              final contact = candidates[index];
              return ListTile(
                title: Text(
                  contact.alias?.isNotEmpty == true
                      ? contact.alias!
                      : shortHexKey(contact.peerPublicKey),
                ),
                subtitle: Text(shortHexKey(contact.peerPublicKey)),
                onTap: () => Navigator.of(dialogContext).pop(contact),
              );
            },
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(),
            child: const Text('Cancel'),
          ),
        ],
      ),
    );
    if (chosen == null || !mounted) return;

    setState(() {
      _isBusy = true;
      _errorMessage = null;
      _statusMessage = null;
    });
    try {
      await widget.groupController.invite(
        groupId: group.groupId,
        candidateKey: chosen.peerPublicKey,
      );
      if (!mounted) return;
      setState(() {
        _statusMessage =
            'Invitation staged & released for '
            '${shortHexKey(chosen.peerPublicKey)}.';
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to invite contact: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _leaveGroup(GroupView group) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: Text('Leave Group ${group.groupId}?'),
        content: const Text(
          'Leaving initiates Byzantine departure consensus and stages a '
          'departure frame for peers.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            key: const Key('confirm_leave_group_button'),
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Leave Group'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    setState(() {
      _isBusy = true;
      _errorMessage = null;
      _statusMessage = null;
    });
    try {
      await widget.groupController.leaveGroup(group.groupId);
      if (!mounted) return;
      setState(() {
        _statusMessage = 'Departure initiated for group ${group.groupId}.';
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to leave group: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _acceptInvitation(PendingInvitation invitation) async {
    setState(() {
      _isBusy = true;
      _errorMessage = null;
      _statusMessage = null;
    });
    try {
      await widget.groupController.acceptInvitation(invitation.binding);
      if (!mounted) return;
      setState(() {
        _statusMessage = 'Accepted invitation to group ${invitation.groupId}.';
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to accept invitation: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _acceptAuthenticated(PendingInvitation invitation) async {
    final digest = await showDialog<Uint8List>(
      context: context,
      builder: (_) => const _GenesisDigestDialog(),
    );
    if (digest == null || !mounted) return;

    setState(() {
      _isBusy = true;
      _errorMessage = null;
      _statusMessage = null;
    });
    try {
      await widget.groupController.acceptInvitationAuthenticated(
        invitationBinding: invitation.binding,
        genesisDigest: digest,
      );
      if (!mounted) return;
      setState(() {
        _statusMessage =
            'Accepted authenticated invitation to group ${invitation.groupId}.';
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to accept invitation: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _receiveInboundFrame() async {
    setState(() {
      _errorMessage = null;
      _statusMessage = null;
    });

    final OutgoingMessage frame;
    try {
      frame = decodeGroupFrame(_inboundFrameController.text);
    } on FormatException catch (e) {
      setState(() => _errorMessage = e.message);
      return;
    }

    setState(() => _isBusy = true);
    try {
      final events = await widget.groupController.receiveFrame(
        frame,
        fromPeerKey: _selectedSenderKey,
      );
      if (!mounted) return;
      _inboundFrameController.clear();
      setState(() {
        _statusMessage = events.isEmpty
            ? 'Frame received and committed.'
            : 'Frame processed: ${events.map(_eventSummary).join(', ')}';
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to receive frame: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _copyFrame(StoredOutgoingMessage item) async {
    await Clipboard.setData(
      ClipboardData(text: encodeGroupFrame(item.message)),
    );
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text('Copied ${item.message.tag.name} frame')),
    );
  }

  Future<void> _retryPersistOutbox() async {
    setState(() {
      _isBusy = true;
      _errorMessage = null;
    });
    try {
      await widget.groupController.retryPersistUnsavedOutgoing();
      if (!mounted) return;
      setState(() => _statusMessage = 'Pending outgoing frames saved.');
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to save outbox frames: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _confirmClearOutboxAndRetry() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Clear Group Outbox?'),
        content: const Text(
          'This removes unreadable or stuck outbox files and retries loading '
          'group state. Committed group memberships are preserved, and recent '
          'operations can be re-sent.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Clear Outbox & Retry'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;
    await widget.groupController.clearOutboxAndRetry();
  }

  Future<void> _resendOperation(BigInt opId) async {
    setState(() {
      _isBusy = true;
      _errorMessage = null;
    });
    try {
      await widget.groupController.resendOperation(opId);
      if (!mounted) return;
      setState(() => _statusMessage = 'Re-staged frames for operation $opId.');
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to re-send operation: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _pasteInbound() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (!mounted) return;
    final text = data?.text?.trim();
    if (text == null || text.isEmpty) return;
    setState(() {
      _inboundFrameController.text = text;
    });
  }

  static String _eventSummary(GroupEvent event) {
    return switch (event) {
      GroupCreatedEvent(:final groupId) => 'Group $groupId created',
      GroupImportedEvent(:final groupId) => 'Group $groupId imported',
      GroupFormedEvent(:final groupId) => 'Group $groupId formed',
      InvitationSentEvent(:final opId) => 'Invitation sent (op $opId)',
      InvitationReceivedEvent(:final groupId) =>
        'Invitation received for group $groupId',
      AcceptanceSentEvent(:final opId) => 'Acceptance sent (op $opId)',
      ConsentReceivedEvent(:final opId) => 'Consent received (op $opId)',
      AdmittedEvent(:final opId) => 'Admitted (op $opId)',
      JoinedEvent(:final groupId) => 'Joined group $groupId',
      MemberAdmittedEvent(:final groupId, :final memberKey) =>
        'Member ${shortHexKey(memberKey)} admitted to group $groupId',
      LeftEvent(:final groupId) => 'Left group $groupId',
      MemberDepartedEvent(:final groupId, :final memberKey) =>
        'Member ${shortHexKey(memberKey)} departed group $groupId',
      FrameRejectedEvent(:final reason) => 'Frame rejected (${reason.name})',
    };
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: Listenable.merge([
        widget.identityController,
        widget.groupController,
      ]),
      builder: (context, _) {
        final theme = Theme.of(context);
        final groupCtrl = widget.groupController;
        final encounterActive = widget.identityController.hasActiveEncounter;
        final actionsDisabled =
            _isBusy || encounterActive || !groupCtrl.isReady;

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
                      '${groupCtrl.groups.length} active '
                      '${groupCtrl.groups.length == 1 ? 'group' : 'groups'}',
                      style: theme.textTheme.bodyMedium?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        Tooltip(
                          message:
                              'Import an existing group shared by a member',
                          child: OutlinedButton.icon(
                            key: const Key('import_genesis_button'),
                            onPressed: actionsDisabled
                                ? null
                                : _openImportGenesisDialog,
                            icon: const Icon(Icons.download_outlined),
                            label: const Text('Import Group'),
                          ),
                        ),
                        FilledButton.icon(
                          key: const Key('create_group_button'),
                          onPressed: actionsDisabled ? null : _createGroup,
                          icon: const Icon(Icons.group_add_outlined),
                          label: const Text('Create Group'),
                        ),
                      ],
                    ),
                  ],
                ),
                if (groupCtrl.status == GroupControllerStatus.initializing) ...[
                  const SizedBox(height: 16),
                  const LinearProgressIndicator(),
                ],
                if (encounterActive) ...[
                  const SizedBox(height: 12),
                  Card(
                    key: const Key('groups_encounter_active_banner'),
                    color: theme.colorScheme.secondaryContainer,
                    child: Padding(
                      padding: const EdgeInsets.all(12),
                      child: Text(
                        'Group actions are paused while an in-person '
                        'Encounter ceremony is active.',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSecondaryContainer,
                        ),
                      ),
                    ),
                  ),
                ],
                if (groupCtrl.errorMessage != null ||
                    groupCtrl.outboxError != null ||
                    groupCtrl.hasUnsavedOutgoing ||
                    _errorMessage != null) ...[
                  const SizedBox(height: 12),
                  Card(
                    key: const Key('groups_error_banner'),
                    color: theme.colorScheme.errorContainer,
                    child: Padding(
                      padding: const EdgeInsets.all(12),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            _errorMessage ??
                                groupCtrl.errorMessage ??
                                groupCtrl.outboxError ??
                                'Some outgoing frames are not yet saved to the outbox.',
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: theme.colorScheme.onErrorContainer,
                            ),
                          ),
                          if (groupCtrl.hasUnsavedOutgoing ||
                              groupCtrl.status ==
                                  GroupControllerStatus.error) ...[
                            const SizedBox(height: 8),
                            Wrap(
                              spacing: 8,
                              runSpacing: 8,
                              children: [
                                if (groupCtrl.hasUnsavedOutgoing)
                                  FilledButton.tonal(
                                    key: const Key(
                                      'retry_persist_outbox_button',
                                    ),
                                    onPressed: _isBusy
                                        ? null
                                        : _retryPersistOutbox,
                                    child: const Text('Retry Save'),
                                  ),
                                if (groupCtrl.status ==
                                    GroupControllerStatus.error) ...[
                                  FilledButton.tonal(
                                    key: const Key('groups_retry_button'),
                                    onPressed: _isBusy
                                        ? null
                                        : groupCtrl.retryInitialize,
                                    child: const Text('Retry'),
                                  ),
                                  OutlinedButton(
                                    key: const Key(
                                      'groups_reset_outbox_button',
                                    ),
                                    onPressed: _isBusy
                                        ? null
                                        : _confirmClearOutboxAndRetry,
                                    child: const Text('Clear Outbox & Retry'),
                                  ),
                                ],
                              ],
                            ),
                          ],
                        ],
                      ),
                    ),
                  ),
                ],
                if (_statusMessage != null) ...[
                  const SizedBox(height: 12),
                  Card(
                    key: const Key('groups_status_banner'),
                    color: theme.colorScheme.primaryContainer,
                    child: Padding(
                      padding: const EdgeInsets.all(12),
                      child: Text(
                        _statusMessage!,
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onPrimaryContainer,
                        ),
                      ),
                    ),
                  ),
                ],
                const SizedBox(height: 16),
                _buildActiveGroupsSection(context, groupCtrl, actionsDisabled),
                const SizedBox(height: 16),
                _buildInvitationsSection(context, groupCtrl, actionsDisabled),
                const SizedBox(height: 16),
                if (groupCtrl.groups.isEmpty &&
                    groupCtrl.outgoingMessages.isEmpty)
                  Card.outlined(
                    child: ExpansionTile(
                      key: const Key('groups_advanced_tile'),
                      title: const Text('Advanced Tools'),
                      subtitle: const Text(
                        'Outbox frames and manual peer frame import',
                      ),
                      childrenPadding: const EdgeInsets.fromLTRB(12, 0, 12, 12),
                      children: [
                        _buildOutboxSection(
                          context,
                          groupCtrl,
                          actionsDisabled,
                        ),
                        const SizedBox(height: 12),
                        _buildReceiveFrameCard(context, actionsDisabled),
                      ],
                    ),
                  )
                else ...[
                  _buildOutboxSection(context, groupCtrl, actionsDisabled),
                  const SizedBox(height: 16),
                  _buildReceiveFrameCard(context, actionsDisabled),
                ],
                if (groupCtrl.recentEvents.isNotEmpty ||
                    groupCtrl.recentOpIds.isNotEmpty) ...[
                  const SizedBox(height: 16),
                  _buildEventsCard(context, groupCtrl, actionsDisabled),
                ],
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildActiveGroupsSection(
    BuildContext context,
    GroupController groupCtrl,
    bool actionsDisabled,
  ) {
    final theme = Theme.of(context);
    if (groupCtrl.groups.isEmpty) {
      return Card.outlined(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Text(
            'No active groups yet. Create a group or import one shared by a '
            'member.',
            style: theme.textTheme.bodyMedium?.copyWith(
              color: theme.colorScheme.onSurfaceVariant,
            ),
          ),
        ),
      );
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: groupCtrl.groups
          .map(
            (group) => Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Card.outlined(
                key: Key('group_card_${group.groupId}'),
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Wrap(
                        spacing: 8,
                        runSpacing: 8,
                        crossAxisAlignment: WrapCrossAlignment.center,
                        children: [
                          Text(
                            _groupTitle(group.groupId),
                            style: theme.textTheme.titleMedium,
                          ),
                          Tooltip(
                            message:
                                'Group version (revision ${group.revision})',
                            child: Chip(
                              label: Text('v${group.revision}'),
                              visualDensity: VisualDensity.compact,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 4),
                      Text(
                        'Policy: ${group.policy} • '
                        '${group.members.length} '
                        '${group.members.length == 1 ? 'member' : 'members'}',
                        style: theme.textTheme.bodySmall?.copyWith(
                          color: theme.colorScheme.onSurfaceVariant,
                        ),
                      ),
                      const SizedBox(height: 8),
                      ...group.members.map(
                        (member) => Text(
                          '• ${_contactLabel(member)}',
                          style: AppTheme.monospaceStyle(context)
                              .copyWith(fontSize: 12),
                        ),
                      ),
                      const SizedBox(height: 12),
                      Wrap(
                        spacing: 8,
                        runSpacing: 8,
                        children: [
                          FilledButton.tonalIcon(
                            key: Key('invite_contact_${group.groupId}'),
                            onPressed: actionsDisabled
                                ? null
                                : () => _inviteContact(group),
                            icon: const Icon(Icons.person_add_alt_1_outlined),
                            label: const Text('Invite Contact'),
                          ),
                          TextButton.icon(
                            key: Key('leave_group_${group.groupId}'),
                            onPressed: actionsDisabled
                                ? null
                                : () => _leaveGroup(group),
                            icon: Icon(
                              Icons.logout,
                              color: theme.colorScheme.error,
                            ),
                            label: Text(
                              'Leave',
                              style: TextStyle(color: theme.colorScheme.error),
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
            ),
          )
          .toList(growable: false),
    );
  }

  Widget _buildInvitationsSection(
    BuildContext context,
    GroupController groupCtrl,
    bool actionsDisabled,
  ) {
    final invitations = groupCtrl.pendingInvitations;
    if (invitations.isEmpty) return const SizedBox.shrink();

    final theme = Theme.of(context);
    return Card.outlined(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Pending Invitations', style: theme.textTheme.titleMedium),
            const SizedBox(height: 10),
            ...invitations.map(
              (inv) => Padding(
                key: Key('pending_invitation_${formatHexKey(inv.binding)}'),
                padding: const EdgeInsets.only(bottom: 10),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Group ${inv.groupId} from ${_contactLabel(inv.inviterKey)}',
                      style: theme.textTheme.bodyMedium,
                    ),
                    const SizedBox(height: 6),
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      children: [
                        FilledButton.tonal(
                          onPressed: actionsDisabled
                              ? null
                              : () => _acceptInvitation(inv),
                          child: const Text('Accept'),
                        ),
                        OutlinedButton(
                          onPressed: actionsDisabled
                              ? null
                              : () => _acceptAuthenticated(inv),
                          child: const Text('Accept Authenticated'),
                        ),
                      ],
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

  Widget _buildOutboxSection(
    BuildContext context,
    GroupController groupCtrl,
    bool actionsDisabled,
  ) {
    final theme = Theme.of(context);
    final messages = groupCtrl.outgoingMessages;

    return Card.outlined(
      key: const Key('group_outbox_card'),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Pending Updates (${messages.length})',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 2),
            Text(
              'Pending outgoing group updates waiting to be shared',
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            if (messages.isEmpty) ...[
              const SizedBox(height: 10),
              Text(
                'No pending outgoing frames.',
                style: theme.textTheme.bodySmall,
              ),
            ] else ...[
              const SizedBox(height: 10),
              ...messages.map((item) {
                final auth = item.message.authenticator;
                return Padding(
                  padding: const EdgeInsets.only(bottom: 10),
                  child: Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: theme.colorScheme.surfaceContainerHighest,
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          '${item.message.tag.name} • '
                          '${item.message.to.isEmpty ? 'broadcast' : '${item.message.to.length} recipient(s)'} • '
                          '${item.message.bytes.length} B',
                          style: theme.textTheme.titleSmall,
                        ),
                        if (auth != null) ...[
                          const SizedBox(height: 4),
                          SelectableText(
                            'Digest: ${formatHexKey(auth)}',
                            style: AppTheme.monospaceStyle(context)
                                .copyWith(fontSize: 11),
                          ),
                        ],
                        const SizedBox(height: 8),
                        Wrap(
                          spacing: 8,
                          runSpacing: 8,
                          children: [
                            FilledButton.tonalIcon(
                              key: Key('copy_group_frame_${item.id}'),
                              onPressed: () => _copyFrame(item),
                              icon: const Icon(Icons.copy_outlined, size: 16),
                              label: const Text('Copy Frame'),
                            ),
                            TextButton.icon(
                              key: Key('mark_group_frame_sent_${item.id}'),
                              onPressed: actionsDisabled
                                  ? null
                                  : () => groupCtrl.markOutgoingSent(item.id),
                              icon: const Icon(Icons.check_outlined, size: 16),
                              label: const Text('Mark Sent'),
                            ),
                          ],
                        ),
                      ],
                    ),
                  ),
                );
              }),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildReceiveFrameCard(BuildContext context, bool actionsDisabled) {
    final theme = Theme.of(context);
    final hasText = _inboundFrameController.text.trim().isNotEmpty;
    final contacts = _verifiedActiveContacts;
    final selectedKey =
        _selectedSenderKey != null &&
            contacts.any((c) => listEquals(c.peerPublicKey, _selectedSenderKey))
        ? contacts
              .firstWhere(
                (c) => listEquals(c.peerPublicKey, _selectedSenderKey),
              )
              .peerPublicKey
        : null;

    return Card.outlined(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text('Receive Group Update', style: theme.textTheme.titleMedium),
            const SizedBox(height: 4),
            Text(
              'Paste an update shared by another group member. Optionally '
              'choose who sent it.',
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 10),
            if (contacts.isNotEmpty) ...[
              DropdownButtonFormField<Uint8List?>(
                key: const Key('receive_frame_sender_dropdown'),
                initialValue: selectedKey,
                isExpanded: true,
                decoration: const InputDecoration(
                  labelText:
                      'Sender Contact (optional — defaults to frame header)',
                  border: OutlineInputBorder(),
                ),
                items: [
                  const DropdownMenuItem<Uint8List?>(
                    value: null,
                    child: Text('Use frame header sender'),
                  ),
                  ...contacts.map(
                    (c) => DropdownMenuItem<Uint8List?>(
                      value: c.peerPublicKey,
                      child: Text(
                        c.alias?.isNotEmpty == true
                            ? '${c.alias} (${shortHexKey(c.peerPublicKey)})'
                            : shortHexKey(c.peerPublicKey),
                      ),
                    ),
                  ),
                ],
                onChanged: actionsDisabled
                    ? null
                    : (value) => setState(() => _selectedSenderKey = value),
              ),
              const SizedBox(height: 10),
            ],
            TextField(
              key: const Key('receive_group_frame_field'),
              controller: _inboundFrameController,
              enabled: !actionsDisabled,
              minLines: 2,
              maxLines: 4,
              style: AppTheme.monospaceStyle(context).copyWith(fontSize: 12),
              onChanged: (_) => setState(() {}),
              decoration: const InputDecoration(
                labelText: 'Peer Frame (mesh:group:...)',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 10),
            Wrap(
              spacing: 10,
              runSpacing: 8,
              alignment: WrapAlignment.spaceBetween,
              children: [
                OutlinedButton.icon(
                  onPressed: actionsDisabled ? null : _pasteInbound,
                  icon: const Icon(Icons.content_paste_outlined, size: 18),
                  label: const Text('Paste'),
                ),
                FilledButton.icon(
                  key: const Key('receive_group_frame_button'),
                  onPressed: actionsDisabled || !hasText
                      ? null
                      : _receiveInboundFrame,
                  icon: const Icon(Icons.call_received, size: 18),
                  label: const Text('Process Frame'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildEventsCard(
    BuildContext context,
    GroupController groupCtrl,
    bool actionsDisabled,
  ) {
    final theme = Theme.of(context);
    final events = groupCtrl.recentEvents;
    final opIds = groupCtrl.recentOpIds;
    return Card.outlined(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Recent Group Activity', style: theme.textTheme.titleMedium),
            if (opIds.isNotEmpty) ...[
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 6,
                children: opIds
                    .take(5)
                    .map(
                      (opId) => ActionChip(
                        key: Key('resend_op_$opId'),
                        avatar: const Icon(Icons.replay, size: 16),
                        label: Text('Re-send Op $opId'),
                        onPressed: actionsDisabled
                            ? null
                            : () => _resendOperation(opId),
                      ),
                    )
                    .toList(growable: false),
              ),
            ],
            if (events.isNotEmpty) ...[
              const SizedBox(height: 8),
              ...events
                  .take(10)
                  .map(
                    (event) => Padding(
                      padding: const EdgeInsets.only(bottom: 4),
                      child: Text(
                        '• ${_eventSummary(event)}',
                        style: theme.textTheme.bodySmall,
                      ),
                    ),
                  ),
            ],
          ],
        ),
      ),
    );
  }
}

class _ImportGenesisDialog extends StatefulWidget {
  final GroupController controller;

  const _ImportGenesisDialog({required this.controller});

  @override
  State<_ImportGenesisDialog> createState() => _ImportGenesisDialogState();
}

class _ImportGenesisDialogState extends State<_ImportGenesisDialog> {
  final TextEditingController _frameController = TextEditingController();
  final TextEditingController _digestController = TextEditingController();
  bool _isBusy = false;
  String? _error;

  @override
  void dispose() {
    _frameController.dispose();
    _digestController.dispose();
    super.dispose();
  }

  Future<void> _submit() async {
    setState(() {
      _isBusy = true;
      _error = null;
    });
    try {
      final msg = decodeGroupFrame(_frameController.text);
      if (msg.tag != MessageTag.genesis) {
        throw const FormatException('Pasted frame is not a genesis frame.');
      }
      if (_digestController.text.trim().isEmpty) {
        throw const FormatException(
          'Enter the 64-character hex genesis digest obtained out-of-band.',
        );
      }
      final digest = parseDigestHex(_digestController.text);
      await widget.controller.importGenesis(
        frame: msg.bytes,
        expectedDigest: digest,
      );
      if (!mounted) return;
      Navigator.of(context).pop(true);
    } on FormatException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _error = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = 'Failed to import genesis: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Import Existing Group'),
      content: SizedBox(
        width: 440,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              key: const Key('genesis_frame_field'),
              controller: _frameController,
              enabled: !_isBusy,
              maxLines: 2,
              style: AppTheme.monospaceStyle(context).copyWith(fontSize: 12),
              decoration: const InputDecoration(
                labelText: 'Group invite frame (mesh:group:...)',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('genesis_digest_field'),
              controller: _digestController,
              enabled: !_isBusy,
              style: AppTheme.monospaceStyle(context).copyWith(fontSize: 12),
              decoration: InputDecoration(
                labelText: 'Verification code (64-char digest)',
                helperText:
                    'Get this code from the group creator in person or over a '
                    'trusted call.',
                helperMaxLines: 2,
                border: const OutlineInputBorder(),
                errorText: _error,
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: _isBusy ? null : () => Navigator.of(context).pop(false),
          child: const Text('Cancel'),
        ),
        FilledButton(
          key: const Key('confirm_import_genesis_button'),
          onPressed: _isBusy ? null : _submit,
          child: const Text('Import'),
        ),
      ],
    );
  }
}

class _GenesisDigestDialog extends StatefulWidget {
  const _GenesisDigestDialog();

  @override
  State<_GenesisDigestDialog> createState() => _GenesisDigestDialogState();
}

class _GenesisDigestDialogState extends State<_GenesisDigestDialog> {
  final TextEditingController _controller = TextEditingController();
  String? _error;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Genesis Digest'),
      content: TextField(
        controller: _controller,
        style: AppTheme.monospaceStyle(context).copyWith(fontSize: 12),
        decoration: InputDecoration(
          labelText: '64-character hex genesis digest',
          border: const OutlineInputBorder(),
          errorText: _error,
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('Cancel'),
        ),
        FilledButton(
          onPressed: () {
            try {
              Navigator.of(context).pop(parseDigestHex(_controller.text));
            } on FormatException catch (e) {
              setState(() => _error = e.message);
            }
          },
          child: const Text('Accept'),
        ),
      ],
    );
  }
}
