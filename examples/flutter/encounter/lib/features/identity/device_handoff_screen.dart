import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';
import 'package:mesh_identity/mesh_identity.dart';

import '../../core/theme.dart';
import '../../services/encounter_session.dart';
import '../../services/handoff_codec.dart';
import '../../services/identity_controller.dart';

/// Slice 6: Device-to-device handoff workflow and monotonic voting role status
/// for the active persona.
class DeviceHandoffScreen extends StatefulWidget {
  final IdentityController controller;

  const DeviceHandoffScreen({super.key, required this.controller});

  @override
  State<DeviceHandoffScreen> createState() => _DeviceHandoffScreenState();
}

class _DeviceHandoffScreenState extends State<DeviceHandoffScreen> {
  final TextEditingController _recipientNonceController =
      TextEditingController();
  final TextEditingController _inboundBundleController =
      TextEditingController();

  bool _isBusy = false;
  String? _statusMessage;
  String? _errorMessage;
  HandoffBundle? _inspectedInboundBundle;

  @override
  void dispose() {
    _recipientNonceController.dispose();
    _inboundBundleController.dispose();
    super.dispose();
  }

  Future<void> _copyText(String text, String label) async {
    await Clipboard.setData(ClipboardData(text: text));
    if (!mounted) return;
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text('$label copied to clipboard')));
  }

  Future<void> _pasteInto(TextEditingController target) async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    if (!mounted) return;
    final text = data?.text?.trim();
    if (text == null || text.isEmpty) {
      ScaffoldMessenger.of(context)
          .showSnackBar(const SnackBar(content: Text('Clipboard is empty')));
      return;
    }
    setState(() {
      target.text = text;
      target.selection = TextSelection.collapsed(offset: text.length);
      if (target == _inboundBundleController) {
        _inspectedInboundBundle = null;
      }
    });
  }

  Future<void> _generateDeviceNonce() async {
    setState(() {
      _isBusy = true;
      _errorMessage = null;
      _statusMessage = null;
    });
    try {
      await widget.controller.ensureDeviceNonce();
      if (!mounted) return;
      setState(() {
        _statusMessage = 'Device nonce generated and saved.';
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to generate device nonce: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _beginHandoff() async {
    setState(() {
      _errorMessage = null;
      _statusMessage = null;
    });

    final Uint8List recipientNonce;
    try {
      recipientNonce = parseDeviceNonceHex(_recipientNonceController.text);
    } on FormatException catch (e) {
      setState(() => _errorMessage = e.message);
      return;
    }

    final localNonce = widget.controller.deviceNonce;
    if (localNonce != null && listEquals(localNonce, recipientNonce)) {
      setState(() {
        _errorMessage =
            'Cannot hand off to this device\'s own nonce. '
            'Enter the receiving device\'s nonce.';
      });
      return;
    }

    final selected = widget.controller.selectedIdentity;
    final personaLabel = selected == null
        ? 'this persona'
        : shortHexKey(selected);
    final groupedNonce = formatGroupedHex(recipientNonce);

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Transfer Voting Role?'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Verify the full 64-character recipient device nonce:',
                style: Theme.of(dialogContext).textTheme.bodyMedium,
              ),
              const SizedBox(height: 8),
              SelectableText(
                groupedNonce,
                style: AppTheme.monospaceStyle(dialogContext)
                    .copyWith(fontSize: 12),
              ),
              const SizedBox(height: 12),
              Text(
                'The receiving device must already hold persona $personaLabel '
                'to accept this bundle. Initiating handoff permanently marks '
                'this device Stopped at the current counter. This cannot be '
                'undone by this device.',
                style: Theme.of(dialogContext).textTheme.bodySmall,
              ),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            key: const Key('confirm_begin_handoff_button'),
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Confirm Handoff'),
          ),
        ],
      ),
    );
    if (confirmed != true || !mounted) return;

    setState(() => _isBusy = true);
    try {
      await widget.controller.beginHandoff(recipientNonce);
      if (!mounted) return;
      setState(() {
        _recipientNonceController.clear();
        _statusMessage =
            'Handoff bundle saved and local state persisted as Stopped.';
      });
    } on NotVotingDeviceException {
      if (!mounted) return;
      setState(() {
        _errorMessage =
            'This device does not currently hold the voting role for the '
            'active persona.';
      });
    } on HandoffWriteFailedException catch (e) {
      if (!mounted) return;
      setState(
        () => _errorMessage = 'Handoff persistence failed: ${e.message}',
      );
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to begin handoff: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  Future<void> _clearPendingOutboundHandoff() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Clear Pending Handoff Bundle?'),
        content: const Text(
          'Only clear this bundle after the receiving device has accepted it. '
          'This device remains Stopped and cannot regenerate the bundle.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Keep Saved'),
          ),
          FilledButton(
            key: const Key('confirm_clear_pending_handoff_button'),
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Mark Delivered & Clear'),
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
      await widget.controller.clearPendingOutboundHandoff();
      if (!mounted) return;
      setState(() {
        _statusMessage = 'Pending outbound handoff bundle cleared.';
      });
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to clear pending bundle: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  void _inspectInboundBundle() {
    setState(() {
      _errorMessage = null;
      _statusMessage = null;
    });
    try {
      final bundle = decodeHandoffBundle(_inboundBundleController.text);
      setState(() {
        _inspectedInboundBundle = bundle;
      });
    } on FormatException catch (e) {
      setState(() {
        _inspectedInboundBundle = null;
        _errorMessage = e.message;
      });
    } on MeshIdentityException catch (e) {
      setState(() {
        _inspectedInboundBundle = null;
        _errorMessage = 'Invalid handoff bundle: ${e.message}';
      });
    }
  }

  Future<void> _acceptInboundBundle() async {
    setState(() {
      _errorMessage = null;
      _statusMessage = null;
    });

    final HandoffBundle bundle;
    try {
      bundle =
          _inspectedInboundBundle ??
          decodeHandoffBundle(_inboundBundleController.text);
    } on FormatException catch (e) {
      setState(() => _errorMessage = e.message);
      return;
    } on MeshIdentityException catch (e) {
      setState(() => _errorMessage = 'Invalid handoff bundle: ${e.message}');
      return;
    }

    final hasPersona = widget.controller.identities.any(
      (k) => listEquals(k, bundle.identity),
    );
    if (!hasPersona) {
      setState(() {
        _inspectedInboundBundle = bundle;
        _errorMessage =
            'This device does not hold persona '
            '${shortHexKey(bundle.identity)}. Import its signing seed in '
            'Identity before accepting this handoff.';
      });
      return;
    }

    setState(() => _isBusy = true);
    try {
      final newState = await widget.controller.acceptHandoff(bundle);
      if (!mounted) return;
      setState(() {
        _inspectedInboundBundle = null;
        _inboundBundleController.clear();
        _statusMessage =
            'Handoff accepted. Device voting state is now '
            '${_votingStateLabel(newState)}.';
      });
    } on WrongHandoffRecipientException {
      if (!mounted) return;
      setState(() {
        _errorMessage =
            'This handoff bundle is addressed to a different device nonce.';
      });
    } on StaleHandoffException {
      if (!mounted) return;
      setState(() {
        _errorMessage =
            'This handoff bundle is stale (counter is not higher than this '
            'device\'s current counter).';
      });
    } on InvalidHandoffException catch (e) {
      if (!mounted) return;
      setState(() {
        _errorMessage = 'Handoff authentication failed: ${e.message}';
      });
    } on HandoffWriteFailedException catch (e) {
      if (!mounted) return;
      setState(
        () => _errorMessage = 'Handoff persistence failed: ${e.message}',
      );
    } on MeshIdentityException catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = e.message);
    } catch (e) {
      if (!mounted) return;
      setState(() => _errorMessage = 'Failed to accept handoff: $e');
    } finally {
      if (mounted) setState(() => _isBusy = false);
    }
  }

  static String _votingStateLabel(VotingState state) {
    return switch (state) {
      VotingState.voting => 'Voting',
      VotingState.stopped => 'Stopped',
      VotingState.gated => 'Gated',
    };
  }

  static String _votingStateDescription(VotingState state) {
    return switch (state) {
      VotingState.voting =>
        'This device holds the monotonic voting role and may sign or hand off.',
      VotingState.stopped =>
        'This device handed off the voting role and must not sign at this '
            'counter. Only a higher-counter handoff can return the role.',
      VotingState.gated =>
        'This device cannot vote until a higher-counter handoff or '
            'recognition unlocks it.',
    };
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('Device Handoff & Voting Role')),
      body: SafeArea(
        child: ListenableBuilder(
          listenable: widget.controller,
          builder: (context, _) {
            final theme = Theme.of(context);
            final selected = widget.controller.selectedIdentity;
            final votingRecord = widget.controller.selectedVotingRecord;
            final deviceNonce = widget.controller.deviceNonce;
            final pendingBundle = widget.controller.pendingOutboundHandoff;
            final outboxError = widget.controller.pendingOutboundHandoffError;
            final encounterActive = widget.controller.hasActiveEncounter;
            final actionsDisabled = _isBusy || encounterActive;
            final canBeginHandoff =
                !actionsDisabled &&
                votingRecord?.state == VotingState.voting &&
                _recipientNonceController.text.trim().isNotEmpty;

            return Align(
              alignment: Alignment.topCenter,
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 820),
                child: ListView(
                  padding: const EdgeInsets.all(20),
                  children: [
                    if (encounterActive) ...[
                      Card(
                        color: theme.colorScheme.secondaryContainer,
                        child: Padding(
                          padding: const EdgeInsets.all(12),
                          child: Text(
                            'Handoff actions are disabled while an encounter '
                            'ceremony is active.',
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: theme.colorScheme.onSecondaryContainer,
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(height: 12),
                    ],
                    if (_errorMessage != null) ...[
                      Card(
                        key: const Key('handoff_error_banner'),
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
                      const SizedBox(height: 12),
                    ],
                    if (_statusMessage != null) ...[
                      Card(
                        key: const Key('handoff_status_banner'),
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
                      const SizedBox(height: 12),
                    ],
                    _buildDeviceStatusCard(
                      context,
                      selected: selected,
                      votingRecord: votingRecord,
                      deviceNonce: deviceNonce,
                      actionsDisabled: actionsDisabled,
                    ),
                    const SizedBox(height: 16),
                    if (outboxError != null) ...[
                      Card(
                        key: const Key('handoff_outbox_error_banner'),
                        color: theme.colorScheme.errorContainer,
                        child: Padding(
                          padding: const EdgeInsets.all(12),
                          child: Text(
                            outboxError,
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: theme.colorScheme.onErrorContainer,
                            ),
                          ),
                        ),
                      ),
                      const SizedBox(height: 12),
                    ],
                    _buildOutboundCard(
                      context,
                      votingRecord: votingRecord,
                      pendingBundle: pendingBundle,
                      actionsDisabled: actionsDisabled,
                      canBeginHandoff: canBeginHandoff,
                    ),
                    const SizedBox(height: 16),
                    _buildInboundCard(
                      context,
                      deviceNonce: deviceNonce,
                      actionsDisabled: actionsDisabled,
                    ),
                  ],
                ),
              ),
            );
          },
        ),
      ),
    );
  }

  Widget _buildDeviceStatusCard(
    BuildContext context, {
    required Uint8List? selected,
    required VotingRecord? votingRecord,
    required Uint8List? deviceNonce,
    required bool actionsDisabled,
  }) {
    final theme = Theme.of(context);
    final state = votingRecord?.state;

    return Card.outlined(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Expanded(
                  child: Text(
                    'Active Persona & Device Nonce',
                    style: theme.textTheme.titleMedium,
                  ),
                ),
                if (state != null)
                  Chip(
                    key: const Key('handoff_voting_state_chip'),
                    label: Text(
                      '${_votingStateLabel(state)} '
                      '(Counter ${votingRecord!.counter})',
                    ),
                    visualDensity: VisualDensity.compact,
                  ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              selected == null
                  ? 'No persona selected'
                  : 'Persona: ${shortHexKey(selected)}',
              style: AppTheme.monospaceStyle(context),
            ),
            if (state != null) ...[
              const SizedBox(height: 6),
              Text(
                _votingStateDescription(state),
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
            ],
            const Divider(height: 24),
            Text('This Device Nonce', style: theme.textTheme.labelMedium),
            const SizedBox(height: 6),
            if (deviceNonce == null) ...[
              Text(
                'Not generated yet. Generate a persistent device nonce so '
                'another device can address a handoff bundle here.',
                style: theme.textTheme.bodySmall?.copyWith(
                  color: theme.colorScheme.onSurfaceVariant,
                ),
              ),
              const SizedBox(height: 10),
              FilledButton.tonalIcon(
                key: const Key('generate_device_nonce_button'),
                onPressed: actionsDisabled ? null : _generateDeviceNonce,
                icon: const Icon(Icons.fingerprint),
                label: const Text('Generate Device Nonce'),
              ),
            ] else
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
                        formatHexKey(deviceNonce),
                        key: const Key('device_nonce_text'),
                        style: AppTheme.monospaceStyle(context)
                            .copyWith(fontSize: 12),
                      ),
                    ),
                    IconButton(
                      key: const Key('copy_device_nonce_button'),
                      tooltip: 'Copy device nonce',
                      onPressed: () =>
                          _copyText(formatHexKey(deviceNonce), 'Device nonce'),
                      icon: const Icon(Icons.copy_outlined, size: 18),
                    ),
                  ],
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildOutboundCard(
    BuildContext context, {
    required VotingRecord? votingRecord,
    required HandoffBundle? pendingBundle,
    required bool actionsDisabled,
    required bool canBeginHandoff,
  }) {
    final theme = Theme.of(context);
    final outbound = pendingBundle == null
        ? null
        : encodeHandoffBundle(pendingBundle);

    return Card.outlined(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Send Voting Role (Outbound Handoff)',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 6),
            Text(
              'Enter the receiving device\'s 64-character hex device nonce. '
              'The receiving device must already hold this persona. Initiating '
              'a handoff permanently marks this device Stopped at the current '
              'counter.',
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('handoff_recipient_nonce_field'),
              controller: _recipientNonceController,
              enabled:
                  !actionsDisabled && votingRecord?.state == VotingState.voting,
              style: AppTheme.monospaceStyle(context).copyWith(fontSize: 13),
              onChanged: (_) => setState(() {}),
              decoration: const InputDecoration(
                labelText: 'Recipient Device Nonce (64 hex chars)',
                hintText: '0123abcd...',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 10,
              runSpacing: 8,
              alignment: WrapAlignment.spaceBetween,
              children: [
                OutlinedButton.icon(
                  onPressed:
                      actionsDisabled ||
                          votingRecord?.state != VotingState.voting
                      ? null
                      : () => _pasteInto(_recipientNonceController),
                  icon: const Icon(Icons.content_paste_outlined, size: 18),
                  label: const Text('Paste Nonce'),
                ),
                FilledButton.icon(
                  key: const Key('begin_handoff_button'),
                  onPressed: canBeginHandoff ? _beginHandoff : null,
                  icon: const Icon(Icons.send_outlined, size: 18),
                  label: const Text('Begin Handoff'),
                ),
              ],
            ),
            if (outbound != null) ...[
              const Divider(height: 24),
              Container(
                key: const Key('outbound_handoff_bundle_card'),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: theme.colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text(
                      'Pending Outbound Handoff Bundle',
                      style: theme.textTheme.titleSmall,
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'Saved on this device until you confirm delivery. Copy '
                      'and transfer this payload to the receiving device.',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                    const SizedBox(height: 8),
                    SelectableText(
                      outbound,
                      maxLines: 4,
                      style: AppTheme.monospaceStyle(context)
                          .copyWith(fontSize: 12),
                    ),
                    const SizedBox(height: 10),
                    Wrap(
                      spacing: 8,
                      runSpacing: 8,
                      alignment: WrapAlignment.end,
                      children: [
                        TextButton.icon(
                          key: const Key('clear_pending_handoff_button'),
                          onPressed: actionsDisabled
                              ? null
                              : _clearPendingOutboundHandoff,
                          icon: const Icon(Icons.check_outlined, size: 18),
                          label: const Text('Mark Delivered & Clear'),
                        ),
                        FilledButton.tonalIcon(
                          key: const Key('copy_handoff_bundle_button'),
                          onPressed: () =>
                              _copyText(outbound, 'Handoff bundle'),
                          icon: const Icon(Icons.copy_outlined, size: 18),
                          label: const Text('Copy Handoff Bundle'),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildInboundCard(
    BuildContext context, {
    required Uint8List? deviceNonce,
    required bool actionsDisabled,
  }) {
    final theme = Theme.of(context);
    final preview = _inspectedInboundBundle;
    final hasText = _inboundBundleController.text.trim().isNotEmpty;
    final recipientMatches =
        preview != null &&
        deviceNonce != null &&
        listEquals(preview.recipient, deviceNonce);
    final hasPersona =
        preview == null ||
        widget.controller.identities.any(
          (k) => listEquals(k, preview.identity),
        );

    return Card.outlined(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(
              'Receive Voting Role (Inbound Handoff)',
              style: theme.textTheme.titleMedium,
            ),
            const SizedBox(height: 6),
            Text(
              'Paste a `mesh:handoff:` bundle from your previous device, '
              'inspect its metadata, and accept it to assume the voting role.',
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              key: const Key('handoff_bundle_input_field'),
              controller: _inboundBundleController,
              enabled: !actionsDisabled,
              minLines: 2,
              maxLines: 4,
              style: AppTheme.monospaceStyle(context).copyWith(fontSize: 12),
              onChanged: (_) => setState(() {
                _inspectedInboundBundle = null;
              }),
              decoration: const InputDecoration(
                labelText: 'Handoff Bundle (mesh:handoff:...)',
                hintText: 'mesh:handoff:...',
                border: OutlineInputBorder(),
              ),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 10,
              runSpacing: 8,
              alignment: WrapAlignment.spaceBetween,
              children: [
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    OutlinedButton.icon(
                      onPressed: actionsDisabled
                          ? null
                          : () => _pasteInto(_inboundBundleController),
                      icon: const Icon(Icons.content_paste_outlined, size: 18),
                      label: const Text('Paste Bundle'),
                    ),
                    OutlinedButton.icon(
                      key: const Key('inspect_handoff_bundle_button'),
                      onPressed: actionsDisabled || !hasText
                          ? null
                          : _inspectInboundBundle,
                      icon: const Icon(Icons.search, size: 18),
                      label: const Text('Inspect Bundle'),
                    ),
                  ],
                ),
                FilledButton.icon(
                  key: const Key('accept_handoff_button'),
                  onPressed: actionsDisabled || !hasText || !hasPersona
                      ? null
                      : _acceptInboundBundle,
                  icon: const Icon(Icons.check_circle_outline, size: 18),
                  label: const Text('Accept Handoff'),
                ),
              ],
            ),
            if (preview != null) ...[
              const SizedBox(height: 14),
              Container(
                key: const Key('handoff_preview_card'),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: theme.colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(8),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Unauthenticated Bundle Preview',
                      style: theme.textTheme.titleSmall,
                    ),
                    const SizedBox(height: 4),
                    Text(
                      'Signatures are verified when you tap Accept Handoff.',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: theme.colorScheme.onSurfaceVariant,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Identity: ${shortHexKey(preview.identity)}',
                      style: AppTheme.monospaceStyle(context),
                    ),
                    Text(
                      'Granted Counter: ${preview.counter}',
                      style: theme.textTheme.bodySmall,
                    ),
                    Text(
                      'Recipient Nonce: ${shortHexKey(preview.recipient)}'
                      '${deviceNonce == null ? '' : (recipientMatches ? ' (Matches this device)' : ' (Does NOT match this device)')}',
                      style: theme.textTheme.bodySmall?.copyWith(
                        color: deviceNonce != null && !recipientMatches
                            ? theme.colorScheme.error
                            : null,
                      ),
                    ),
                    if (!hasPersona) ...[
                      const SizedBox(height: 8),
                      Container(
                        key: const Key('handoff_missing_persona_warning'),
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(
                          color: theme.colorScheme.errorContainer,
                          borderRadius: BorderRadius.circular(6),
                        ),
                        child: Text(
                          'This device does not hold persona '
                          '${shortHexKey(preview.identity)}. Import its '
                          'signing seed in Identity before accepting.',
                          style: theme.textTheme.bodySmall?.copyWith(
                            color: theme.colorScheme.onErrorContainer,
                          ),
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}
