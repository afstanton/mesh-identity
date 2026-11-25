import 'dart:async';
import 'dart:typed_data';

import 'package:material_ui/material_ui.dart';
import 'package:mesh_identity/mesh_identity.dart';

import '../../services/ble_encounter_transport.dart';
import '../../services/encounter_session.dart';
import '../../services/identity_controller.dart';
import '../../services/qr_scanner_service.dart';
import 'camera_qr_scanner_screen.dart';
import 'widgets/ble_encounter_panel.dart';
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
  final BleEncounterTransport? bleTransport;

  const TwoDeviceEncounterScreen({
    super.key,
    required this.controller,
    required this.initialRole,
    this.qrScanner = const ZxingQrScannerService(),
    this.bleTransport,
  });

  @override
  State<TwoDeviceEncounterScreen> createState() =>
      _TwoDeviceEncounterScreenState();
}

class _TwoDeviceEncounterScreenState extends State<TwoDeviceEncounterScreen>
    with WidgetsBindingObserver {
  Timer? _ticker;
  late EncounterRole _currentRole;
  late final BleEncounterTransport _bleTransport;
  late final bool _ownsBleTransport;
  StreamSubscription<BleTransportStatus>? _bleStatusSub;
  StreamSubscription<List<BlePeerDiscovery>>? _blePeersSub;
  BleTransportStatus _bleStatus = BleTransportStatus.idle;
  List<BlePeerDiscovery> _blePeers = const [];

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _currentRole = widget.initialRole;
    _ownsBleTransport = widget.bleTransport == null;
    _bleTransport = widget.bleTransport ?? BluetoothLowEnergyTransport();
    _bleStatus = _bleTransport.status;
    _bleStatusSub = _bleTransport.statusStream.listen((next) {
      if (!mounted) return;
      setState(() => _bleStatus = next);
    });
    _blePeersSub = _bleTransport.discoveredPeersStream.listen((peers) {
      if (!mounted) return;
      setState(() => _blePeers = peers);
    });
    unawaited(_bleTransport.probeAvailability());
    widget.controller.addListener(_onControllerChanged);

    _ticker = Timer.periodic(const Duration(seconds: 1), _onTick);
    if (!widget.controller.hasActiveEncounter) {
      _startCeremony(_currentRole);
    }
  }

  void _onControllerChanged() {
    final phase = widget.controller.encounterSession.phase;
    final isTerminalAbort =
        phase == EncounterPhase.verified ||
        phase == EncounterPhase.cancelled ||
        phase == EncounterPhase.expired ||
        phase == EncounterPhase.failed ||
        phase == EncounterPhase.rateLimited;
    final isSasHandover =
        phase == EncounterPhase.initiatorShowingRevealAndCompare ||
        phase == EncounterPhase.responderAwaitingConfirmation;
    final isActiveAny =
        _bleStatus == BleTransportStatus.advertising ||
        _bleStatus == BleTransportStatus.scanning ||
        _bleStatus == BleTransportStatus.connecting ||
        _bleStatus == BleTransportStatus.exchanging;
    final isIdleDiscoverable =
        _bleStatus == BleTransportStatus.advertising ||
        _bleStatus == BleTransportStatus.scanning;

    if ((isTerminalAbort && isActiveAny) ||
        (isSasHandover && isIdleDiscoverable)) {
      unawaited(_bleTransport.stop());
    }
  }

  Future<void> _toggleBle(
    EncounterSessionState session,
    EncounterRole role,
  ) async {
    try {
      if (_bleStatus == BleTransportStatus.advertising ||
          _bleStatus == BleTransportStatus.scanning) {
        await _bleTransport.stop();
        return;
      }
      if (role == EncounterRole.initiator) {
        final offerUri = session.outgoingUri;
        if (offerUri == null) return;
        final offerBytes = Uint8List.fromList(QrTransport.decodeUri(offerUri));
        await _bleTransport.startInitiatorPeripheral(
          offerBytes: offerBytes,
          onResponseReceived: (responseBytes) async {
            await widget.controller.submitEncounterResponse(
              QrTransport.encodeUri(responseBytes),
            );
            final updated = widget.controller.encounterSession;
            final revealUri = updated.outgoingUri;
            if (updated.phase !=
                    EncounterPhase.initiatorShowingRevealAndCompare ||
                revealUri == null) {
              throw StateError(
                updated.inlineError ?? 'Response payload was rejected.',
              );
            }
            return Uint8List.fromList(QrTransport.decodeUri(revealUri));
          },
        );
      } else {
        await _bleTransport.startResponderScan();
      }
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('BLE action failed: $e')));
    }
  }

  Future<void> _connectBlePeer(BlePeerDiscovery peer) async {
    try {
      await _bleTransport.connectAndExchangeAsResponder(
        peerId: peer.id,
        onOfferReceived: (offerBytes) async {
          await widget.controller.submitEncounterOffer(
            QrTransport.encodeUri(offerBytes),
          );
          final updated = widget.controller.encounterSession;
          final responseUri = updated.outgoingUri;
          if (updated.phase != EncounterPhase.responderShowingResponse ||
              responseUri == null) {
            throw StateError(
              updated.inlineError ?? 'Offer payload was rejected.',
            );
          }
          return Uint8List.fromList(QrTransport.decodeUri(responseUri));
        },
        onRevealReceived: (revealBytes) async {
          await widget.controller.submitEncounterReveal(
            QrTransport.encodeUri(revealBytes),
          );
          final updated = widget.controller.encounterSession;
          if (updated.phase != EncounterPhase.responderAwaitingConfirmation ||
              updated.comparison == null) {
            throw StateError(
              updated.inlineError ?? 'Reveal payload was rejected.',
            );
          }
        },
      );
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context)
          .showSnackBar(SnackBar(content: Text('BLE connection failed: $e')));
    }
  }

  Future<void> _requestBlePermission() async {
    try {
      await _bleTransport.requestPermission();
    } catch (e) {
      if (!mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Bluetooth permission request failed: $e')),
      );
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
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.resumed &&
        (_bleStatus == BleTransportStatus.permissionDenied ||
            _bleStatus == BleTransportStatus.bluetoothOff)) {
      unawaited(_bleTransport.probeAvailability());
    }
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _ticker?.cancel();
    _bleStatusSub?.cancel();
    _blePeersSub?.cancel();
    widget.controller.removeListener(_onControllerChanged);
    if (_ownsBleTransport) {
      _bleTransport.dispose();
    } else {
      unawaited(_bleTransport.stop());
    }
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
    final isWaitingOffer =
        session.phase == EncounterPhase.responderAwaitingOffer;
    final labelText = isWaitingOffer
        ? 'Waiting · ${formatCountdown(remaining)}'
        : formatCountdown(remaining);
    return Padding(
      padding: const EdgeInsets.only(right: 4),
      child: Tooltip(
        message: isWaitingOffer
            ? 'Session expires in ${formatCountdown(remaining)} — scan or paste your peer\'s code'
            : 'Session time remaining',
        child: Chip(
          key: const Key('encounter_expiry_chip'),
          avatar: Icon(
            Icons.timer_outlined,
            size: 16,
            color: urgent ? colorScheme.error : colorScheme.onSurfaceVariant,
          ),
          label: Text(
            labelText,
            style: TextStyle(
              fontFamily: 'monospace',
              fontWeight: FontWeight.w600,
              color: urgent ? colorScheme.error : null,
            ),
          ),
          visualDensity: VisualDensity.compact,
        ),
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
            BleEncounterPanel(
              role: role,
              transport: _bleTransport,
              status: _bleStatus,
              discoveredPeers: _blePeers,
              onToggleBle: () => unawaited(_toggleBle(session, role)),
              onRequestPermission: () => unawaited(_requestBlePermission()),
              onConnectPeer: (peer) => unawaited(_connectBlePeer(peer)),
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
            BleEncounterPanel(
              role: role,
              transport: _bleTransport,
              status: _bleStatus,
              discoveredPeers: _blePeers,
              onToggleBle: () => unawaited(_toggleBle(session, role)),
              onRequestPermission: () => unawaited(_requestBlePermission()),
              onConnectPeer: (peer) => unawaited(_connectBlePeer(peer)),
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
            BleEncounterPanel(
              role: role,
              transport: _bleTransport,
              status: _bleStatus,
              discoveredPeers: _blePeers,
              onToggleBle: () => unawaited(_toggleBle(session, role)),
              onRequestPermission: () => unawaited(_requestBlePermission()),
              onConnectPeer: (peer) => unawaited(_connectBlePeer(peer)),
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
            BleEncounterPanel(
              role: role,
              transport: _bleTransport,
              status: _bleStatus,
              discoveredPeers: _blePeers,
              onToggleBle: () => unawaited(_toggleBle(session, role)),
              onRequestPermission: () => unawaited(_requestBlePermission()),
              onConnectPeer: (peer) => unawaited(_connectBlePeer(peer)),
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
