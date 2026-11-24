import 'dart:async';

import 'package:material_ui/material_ui.dart';

import '../../services/encounter_session.dart';
import '../../services/identity_controller.dart';
import '../../services/qr_scanner_service.dart';
import 'camera_qr_scanner_screen.dart';
import 'widgets/encounter_payload_input.dart';
import 'widgets/encounter_qr_view.dart';
import 'widgets/sas_confirmation_panel.dart';
import 'widgets/statutory_notices.dart';

/// Guided two-device Encounter ceremony workflow using optical QR display,
/// manual/clipboard URI exchange, and 6-digit SAS verification.
class TwoDeviceEncounterScreen extends StatefulWidget {
  final IdentityController controller;
  final EncounterRole initialRole;
  final QrScannerService qrScanner;

  const TwoDeviceEncounterScreen({
    super.key,
    required this.controller,
    required this.initialRole,
    this.qrScanner = const ZxingQrScannerService(),
  });

  @override
  State<TwoDeviceEncounterScreen> createState() =>
      _TwoDeviceEncounterScreenState();
}

class _TwoDeviceEncounterScreenState extends State<TwoDeviceEncounterScreen> {
  Timer? _ticker;
  late EncounterRole _currentRole;

  @override
  void initState() {
    super.initState();
    _currentRole = widget.initialRole;
    _ticker = Timer.periodic(const Duration(seconds: 1), _onTick);
    if (!widget.controller.hasActiveEncounter) {
      _startCeremony(_currentRole);
    }
  }

  void _onTick(Timer _) {
    if (!mounted || widget.controller.isDisposed) return;
    final session = widget.controller.encounterSession;
    if (session.isActive || session.phase == EncounterPhase.rateLimited) {
      unawaited(widget.controller.checkEncounterExpiry());
      setState(() {});
    }
  }

  void _startCeremony(EncounterRole role) {
    _currentRole = role;
    switch (role) {
      case EncounterRole.initiator:
        unawaited(widget.controller.startEncounterAsInitiator());
      case EncounterRole.responder:
        unawaited(widget.controller.openEncounterAsResponder());
    }
  }

  Future<void> _closeScreen() async {
    await widget.controller.dismissEncounterSession();
    if (mounted) {
      Navigator.of(context).pop();
    }
  }

  @override
  void dispose() {
    _ticker?.cancel();
    if (!widget.controller.isDisposed && widget.controller.hasActiveEncounter) {
      unawaited(widget.controller.cancelActiveEncounter());
    }
    super.dispose();
  }

  String _screenTitle(EncounterRole? activeRole) {
    final role = activeRole ?? _currentRole;
    return switch (role) {
      EncounterRole.initiator => 'Start Encounter',
      EncounterRole.responder => 'Join Encounter',
    };
  }

  Widget _buildCountdownChip(
    BuildContext context,
    EncounterSessionState session,
    DateTime now,
  ) {
    final remaining = session.remainingTime(now);
    if (remaining == null) return const SizedBox.shrink();
    final colorScheme = Theme.of(context).colorScheme;
    final urgent = remaining.inSeconds < 30;
    return Padding(
      padding: const EdgeInsets.only(right: 4),
      child: Chip(
        key: const Key('encounter_expiry_chip'),
        avatar: Icon(
          Icons.timer_outlined,
          size: 16,
          color: urgent ? colorScheme.error : colorScheme.onSurfaceVariant,
        ),
        label: Text(
          formatCountdown(remaining),
          style: TextStyle(
            fontFamily: 'monospace',
            fontWeight: FontWeight.w600,
            color: urgent ? colorScheme.error : null,
          ),
        ),
        visualDensity: VisualDensity.compact,
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: widget.controller,
      builder: (context, _) {
        final session = widget.controller.encounterSession;
        final now = widget.controller.currentTime;
        final role = session.role ?? _currentRole;

        return PopScope(
          canPop: !session.isActive,
          onPopInvokedWithResult: (didPop, result) async {
            if (didPop) return;
            await widget.controller.cancelActiveEncounter();
            if (context.mounted) {
              Navigator.of(context).pop(result);
            }
          },
          child: Scaffold(
            appBar: AppBar(
              title: Text(_screenTitle(session.role)),
              actions: [
                if (session.isActive) ...[
                  _buildCountdownChip(context, session, now),
                  TextButton(
                    key: const Key('encounter_appbar_cancel_button'),
                    onPressed: () {
                      unawaited(widget.controller.cancelActiveEncounter());
                    },
                    child: const Text('Cancel'),
                  ),
                ] else
                  TextButton(
                    key: const Key('encounter_appbar_close_button'),
                    onPressed: _closeScreen,
                    child: const Text('Close'),
                  ),
              ],
            ),
            body: SafeArea(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(20),
                child: Center(
                  child: ConstrainedBox(
                    constraints: const BoxConstraints(maxWidth: 820),
                    child: _buildPhaseBody(context, session, role, now),
                  ),
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildPhaseBody(
    BuildContext context,
    EncounterSessionState session,
    EncounterRole role,
    DateTime now,
  ) {
    switch (session.phase) {
      case EncounterPhase.idle:
        return _TerminalOutcomeCard(
          icon: Icons.qr_code_2_outlined,
          title: 'Ready to Start Encounter',
          message:
              'Begin a fresh two-device key exchange ceremony when both '
              'devices are ready.',
          primaryLabel: 'Start New Encounter',
          primaryKey: const Key('encounter_restart_button'),
          onPrimary: () => _startCeremony(role),
          onClose: _closeScreen,
        );

      case EncounterPhase.initiatorShowingOffer:
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const _StepHeader(
              stepNumber: 1,
              totalSteps: 3,
              title: 'Share Offer (QR 1) & Import Response (QR 2)',
              subtitle:
                  'Have your peer open "Join Encounter" and scan or paste this Offer URI, '
                  'then paste back their Response URI below.',
            ),
            const SizedBox(height: 16),
            EncounterPayloadCard(
              title: 'Step 1: Your Offer Payload (QR 1)',
              subtitle: 'Share this QR code or payload URI with your peer.',
              payloadUri: session.outgoingUri!,
              copyButtonLabel: 'Copy Offer URI',
              copyButtonKey: const Key('encounter_copy_payload_button'),
            ),
            const SizedBox(height: 16),
            EncounterPayloadInput(
              key: const ValueKey('initiator_response_input'),
              title: 'Step 2: Paste Peer\'s Response Payload (QR 2)',
              hintText: 'mesh:encounter:...',
              submitLabel: 'Verify Response & Continue',
              inlineError: session.inlineError,
              enabled: !session.isBusy,
              qrScanner: widget.qrScanner,
              scanTitle: 'Scan Response QR (QR 2)',
              scanInstruction:
                  'Point your camera at your peer\'s Step 2 Response QR code.',
              sessionListenable: widget.controller,
              isSessionActive: () => widget.controller.hasActiveEncounter,
              textFieldKey: const Key('encounter_response_field'),
              pasteButtonKey: const Key('encounter_paste_button'),
              submitButtonKey: const Key('encounter_submit_button'),
              onSubmit: (uri) {
                unawaited(widget.controller.submitEncounterResponse(uri));
              },
            ),
          ],
        );

      case EncounterPhase.responderAwaitingOffer:
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const _StepHeader(
              stepNumber: 1,
              totalSteps: 3,
              title: 'Import Peer\'s Offer (QR 1)',
              subtitle: 'Ask your peer to tap "Start Encounter" and send or show their Offer URI.',
            ),
            const SizedBox(height: 16),
            EncounterPayloadInput(
              key: const ValueKey('responder_offer_input'),
              title: 'Step 1: Paste Peer\'s Offer Payload (QR 1)',
              hintText: 'mesh:encounter:...',
              submitLabel: 'Accept Offer & Create Response',
              inlineError: session.inlineError,
              enabled: !session.isBusy,
              qrScanner: widget.qrScanner,
              scanTitle: 'Scan Offer QR (QR 1)',
              scanInstruction:
                  'Point your camera at your peer\'s Step 1 Offer QR code.',
              sessionListenable: widget.controller,
              isSessionActive: () => widget.controller.hasActiveEncounter,
              textFieldKey: const Key('encounter_offer_field'),
              pasteButtonKey: const Key('encounter_paste_button'),
              submitButtonKey: const Key('encounter_submit_button'),
              onSubmit: (uri) {
                unawaited(widget.controller.submitEncounterOffer(uri));
              },
            ),
          ],
        );

      case EncounterPhase.responderShowingResponse:
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const _StepHeader(
              stepNumber: 2,
              totalSteps: 3,
              title: 'Share Response (QR 2) & Import Reveal (QR 3)',
              subtitle:
                  'Give your Response URI below to your peer, then paste back '
                  'their Reveal URI to unlock the 6-digit verification code.',
            ),
            const SizedBox(height: 16),
            EncounterPayloadCard(
              title: 'Step 2: Your Response Payload (QR 2)',
              subtitle: 'Share this QR code or payload URI with your peer.',
              payloadUri: session.outgoingUri!,
              copyButtonLabel: 'Copy Response URI',
              copyButtonKey: const Key('encounter_copy_payload_button'),
            ),
            const SizedBox(height: 16),
            EncounterPayloadInput(
              key: const ValueKey('responder_reveal_input'),
              title: 'Step 3: Paste Peer\'s Reveal Payload (QR 3)',
              hintText: 'mesh:encounter:...',
              submitLabel: 'Complete Exchange & Show Code',
              inlineError: session.inlineError,
              enabled: !session.isBusy,
              qrScanner: widget.qrScanner,
              scanTitle: 'Scan Reveal QR (QR 3)',
              scanInstruction:
                  'Point your camera at your peer\'s Step 3 Reveal QR code.',
              sessionListenable: widget.controller,
              isSessionActive: () => widget.controller.hasActiveEncounter,
              textFieldKey: const Key('encounter_reveal_field'),
              pasteButtonKey: const Key('encounter_paste_button'),
              submitButtonKey: const Key('encounter_submit_button'),
              onSubmit: (uri) {
                unawaited(widget.controller.submitEncounterReveal(uri));
              },
            ),
          ],
        );

      case EncounterPhase.initiatorShowingRevealAndCompare:
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const _StepHeader(
              stepNumber: 3,
              totalSteps: 3,
              title: 'Share Reveal (QR 3) & Compare 6-Digit Codes',
              subtitle:
                  'Share your Reveal URI with your peer so they see their 6-digit code, '
                  'then verify every digit in person before confirming.',
            ),
            const SizedBox(height: 16),
            EncounterPayloadCard(
              title: 'Share Reveal Payload (QR 3)',
              subtitle: 'Your peer must import this Reveal URI to display their 6-digit code.',
              payloadUri: session.outgoingUri!,
              copyButtonLabel: 'Copy Reveal URI',
              copyButtonKey: const Key('encounter_copy_payload_button'),
            ),
            const SizedBox(height: 16),
            SasConfirmationPanel(
              title: 'Step 3: Compare 6-Digit Verification Codes',
              comparison: session.comparison!,
              inlineError: session.inlineError,
              enabled: !session.isBusy,
              codeKey: const Key('encounter_sas_code'),
              inputKey: const Key('encounter_sas_input'),
              confirmButtonKey: const Key('encounter_sas_confirm_button'),
              cancelButtonKey: const Key('encounter_sas_cancel_button'),
              onConfirm: (digits) {
                unawaited(widget.controller.confirmEncounterCode(digits));
              },
              onCancel: () {
                unawaited(widget.controller.cancelActiveEncounter());
              },
            ),
          ],
        );

      case EncounterPhase.responderAwaitingConfirmation:
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const _StepHeader(
              stepNumber: 3,
              totalSteps: 3,
              title: 'Compare 6-Digit Verification Codes',
              subtitle:
                  'Check the 6-digit code shown on your peer\'s screen and type '
                  'all 6 digits carefully below.',
            ),
            const SizedBox(height: 16),
            SasConfirmationPanel(
              title: 'Step 3: Compare 6-Digit Verification Codes',
              comparison: session.comparison!,
              inlineError: session.inlineError,
              enabled: !session.isBusy,
              codeKey: const Key('encounter_sas_code'),
              inputKey: const Key('encounter_sas_input'),
              confirmButtonKey: const Key('encounter_sas_confirm_button'),
              cancelButtonKey: const Key('encounter_sas_cancel_button'),
              onConfirm: (digits) {
                unawaited(widget.controller.confirmEncounterCode(digits));
              },
              onCancel: () {
                unawaited(widget.controller.cancelActiveEncounter());
              },
            ),
          ],
        );

      case EncounterPhase.verified:
        return VerifiedContactCard(
          contact: session.verifiedContact!,
          onDone: () {
            unawaited(_closeScreen());
          },
        );

      case EncounterPhase.cancelled:
        return _TerminalOutcomeCard(
          icon: Icons.cancel_outlined,
          title: 'Ceremony Cancelled',
          message:
              'The encounter ceremony was cancelled and no unverified contact '
              'was saved.',
          primaryLabel: 'Start New Encounter',
          primaryKey: const Key('encounter_restart_button'),
          onPrimary: () => _startCeremony(role),
          onClose: _closeScreen,
        );

      case EncounterPhase.expired:
        return _TerminalOutcomeCard(
          icon: Icons.timer_off_outlined,
          title: 'Ceremony Expired',
          message:
              session.errorMessage ??
              'This 2-minute encounter session timed out. Start a new '
                  'encounter to try again.',
          primaryLabel: 'Start New Encounter',
          primaryKey: const Key('encounter_restart_button'),
          onPrimary: () => _startCeremony(role),
          onClose: _closeScreen,
        );

      case EncounterPhase.failed:
        return _TerminalOutcomeCard(
          icon: Icons.error_outline,
          iconColor: Theme.of(context).colorScheme.error,
          title: 'Encounter Did Not Complete',
          message:
              session.errorMessage ?? 'The encounter could not be completed.',
          notice: session.showLocalOnlyNotice
              ? EncounterUiText.localOnlyConfirmation
              : null,
          primaryLabel: 'Start New Encounter',
          primaryKey: const Key('encounter_restart_button'),
          onPrimary: () => _startCeremony(role),
          onClose: _closeScreen,
        );

      case EncounterPhase.rateLimited:
        final remaining = session.rateLimitRemaining(now) ?? Duration.zero;
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            RateLimitBanner(remaining: remaining),
            const SizedBox(height: 16),
            Align(
              alignment: Alignment.centerRight,
              child: FilledButton(
                onPressed: _closeScreen,
                child: const Text('Close'),
              ),
            ),
          ],
        );
    }
  }
}

class _StepHeader extends StatelessWidget {
  final int stepNumber;
  final int totalSteps;
  final String title;
  final String subtitle;

  const _StepHeader({
    required this.stepNumber,
    required this.totalSteps,
    required this.title,
    required this.subtitle,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Wrap(
          spacing: 10,
          runSpacing: 6,
          crossAxisAlignment: WrapCrossAlignment.center,
          children: [
            Chip(
              label: Text('Step $stepNumber of $totalSteps'),
              visualDensity: VisualDensity.compact,
            ),
            Text(title, style: Theme.of(context).textTheme.titleMedium),
          ],
        ),
        const SizedBox(height: 6),
        Text(
          subtitle,
          style: Theme.of(context).textTheme.bodyMedium
              ?.copyWith(color: colorScheme.onSurfaceVariant),
        ),
      ],
    );
  }
}

class _TerminalOutcomeCard extends StatelessWidget {
  final IconData icon;
  final Color? iconColor;
  final String title;
  final String message;
  final String? notice;
  final String primaryLabel;
  final Key primaryKey;
  final VoidCallback onPrimary;
  final VoidCallback onClose;

  const _TerminalOutcomeCard({
    required this.icon,
    required this.title,
    required this.message,
    required this.primaryLabel,
    required this.primaryKey,
    required this.onPrimary,
    required this.onClose,
    this.iconColor,
    this.notice,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Icon(icon, size: 32, color: iconColor ?? colorScheme.primary),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    title,
                    style: Theme.of(context).textTheme.titleLarge,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            Text(message, style: Theme.of(context).textTheme.bodyMedium),
            if (notice != null) ...[
              const SizedBox(height: 12),
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: colorScheme.surfaceContainerHighest,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: colorScheme.outlineVariant),
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(
                      Icons.info_outline,
                      size: 18,
                      color: colorScheme.onSurfaceVariant,
                    ),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        notice!,
                        style: Theme.of(context).textTheme.bodySmall,
                      ),
                    ),
                  ],
                ),
              ),
            ],
            const SizedBox(height: 20),
            Wrap(
              spacing: 12,
              runSpacing: 8,
              alignment: WrapAlignment.end,
              children: [
                OutlinedButton(onPressed: onClose, child: const Text('Close')),
                FilledButton(
                  key: primaryKey,
                  onPressed: onPrimary,
                  child: Text(primaryLabel),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
