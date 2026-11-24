import 'dart:async';

import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/theme.dart';
import '../../services/encounter_session.dart';
import '../../services/identity_controller.dart';
import '../../services/qr_scanner_service.dart';
import '../encounter/camera_qr_scanner_screen.dart';
import '../encounter/practice_encounter_screen.dart';
import '../encounter/two_device_encounter_screen.dart';
import '../encounter/widgets/statutory_notices.dart';

/// Primary Encounter hub displaying active persona details, node summary,
/// and launch actions for two-device encounters and single-device Practice Mode.
class EncounterHomeView extends StatefulWidget {
  final IdentityController controller;
  final QrScannerService qrScanner;

  const EncounterHomeView({
    super.key,
    required this.controller,
    this.qrScanner = const ZxingQrScannerService(),
  });

  @override
  State<EncounterHomeView> createState() => _EncounterHomeViewState();
}

class _EncounterHomeViewState extends State<EncounterHomeView> {
  Timer? _rateLimitTicker;

  @override
  void initState() {
    super.initState();
    widget.controller.addListener(_onControllerChanged);
    _syncRateLimitTicker();
  }

  @override
  void didUpdateWidget(covariant EncounterHomeView oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.controller != oldWidget.controller) {
      oldWidget.controller.removeListener(_onControllerChanged);
      widget.controller.addListener(_onControllerChanged);
      _syncRateLimitTicker();
    }
  }

  void _onControllerChanged() {
    if (!mounted) return;
    _syncRateLimitTicker();
    setState(() {});
  }

  void _syncRateLimitTicker() {
    final until = widget.controller.rateLimitedUntil;
    final paused =
        until != null && widget.controller.currentTime.isBefore(until);
    if (paused && _rateLimitTicker == null) {
      _rateLimitTicker = Timer.periodic(const Duration(seconds: 1), (_) {
        if (!mounted || widget.controller.isDisposed) return;
        unawaited(widget.controller.checkEncounterExpiry());
        _syncRateLimitTicker();
        setState(() {});
      });
    } else if (!paused && _rateLimitTicker != null) {
      _rateLimitTicker?.cancel();
      _rateLimitTicker = null;
    }
  }

  @override
  void dispose() {
    _rateLimitTicker?.cancel();
    widget.controller.removeListener(_onControllerChanged);
    super.dispose();
  }

  Future<void> _copyPublicKey(BuildContext context, String hexKey) async {
    await Clipboard.setData(ClipboardData(text: hexKey));
    if (!context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Public key copied to clipboard')),
    );
  }

  void _openTwoDeviceEncounter(EncounterRole role) {
    Navigator.of(context).push(
      MaterialPageRoute<void>(
        builder: (_) => TwoDeviceEncounterScreen(
          controller: widget.controller,
          initialRole: role,
          qrScanner: widget.qrScanner,
        ),
      ),
    );
  }

  void _openPracticeMode() {
    Navigator.of(context).push(
      MaterialPageRoute<void>(builder: (_) => const PracticeEncounterScreen()),
    );
  }

  @override
  Widget build(BuildContext context) {
    final selectedKey = widget.controller.selectedIdentity;
    final fullHex = selectedKey == null
        ? 'Unavailable'
        : formatHexKey(selectedKey);
    final shortHex = selectedKey == null
        ? 'Unavailable'
        : shortHexKey(selectedKey);

    final rateLimitedUntil = widget.controller.rateLimitedUntil;
    final now = widget.controller.currentTime;
    final isPaused = rateLimitedUntil != null && now.isBefore(rateLimitedUntil);
    final pauseRemaining = isPaused
        ? rateLimitedUntil.difference(now)
        : Duration.zero;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 760),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(
                            Icons.verified_user_outlined,
                            color: Theme.of(context).colorScheme.primary,
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Text(
                              'Active Persona',
                              style: Theme.of(context).textTheme.titleMedium,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 12),
                      Text(
                        shortHex,
                        style: AppTheme.monospaceStyle(
                          context,
                        ).copyWith(fontSize: 18, fontWeight: FontWeight.w600),
                      ),
                      const SizedBox(height: 8),
                      SelectableText(
                        fullHex,
                        style: AppTheme.monospaceStyle(context).copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                      ),
                      if (selectedKey != null) ...[
                        const SizedBox(height: 16),
                        OutlinedButton.icon(
                          onPressed: () => _copyPublicKey(context, fullHex),
                          icon: const Icon(Icons.copy_outlined, size: 18),
                          label: const Text('Copy Public Key'),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Node Summary',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                      const SizedBox(height: 12),
                      Wrap(
                        spacing: 12,
                        runSpacing: 8,
                        children: [
                          Chip(
                            avatar: const Icon(Icons.badge_outlined, size: 18),
                            label: Text(
                              'Personas: ${widget.controller.identities.length}',
                            ),
                          ),
                          Chip(
                            avatar: const Icon(Icons.people_outline, size: 18),
                            label: Text(
                              'Contacts: ${widget.controller.contactsCount}',
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(
                            Icons.qr_code_2_outlined,
                            color: Theme.of(context).colorScheme.primary,
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Text(
                              'In-Person Encounter',
                              style: Theme.of(context).textTheme.titleMedium,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      Text(
                        'Exchange cryptographic Offer, Response, and Reveal payloads '
                        'between two devices via QR display and clipboard URI import, '
                        'then confirm the 6-digit SAS code together. Hardware camera '
                        'scanning arrives in Slice 5.',
                        style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                      ),
                      if (isPaused) ...[
                        const SizedBox(height: 14),
                        RateLimitBanner(remaining: pauseRemaining),
                      ],
                      const SizedBox(height: 16),
                      Wrap(
                        spacing: 12,
                        runSpacing: 12,
                        children: [
                          FilledButton.icon(
                            key: const Key('start_encounter_button'),
                            onPressed: isPaused
                                ? null
                                : () => _openTwoDeviceEncounter(
                                    EncounterRole.initiator,
                                  ),
                            icon: const Icon(Icons.qr_code_2, size: 18),
                            label: const Text('Start Encounter'),
                          ),
                          FilledButton.tonalIcon(
                            key: const Key('join_encounter_button'),
                            onPressed: isPaused
                                ? null
                                : () => _openTwoDeviceEncounter(
                                    EncounterRole.responder,
                                  ),
                            icon: const Icon(
                              Icons.playlist_add_check_outlined,
                              size: 18,
                            ),
                            label: const Text('Join Encounter'),
                          ),
                          OutlinedButton.icon(
                            key: const Key('practice_mode_button'),
                            onPressed: _openPracticeMode,
                            icon: const Icon(Icons.science_outlined, size: 18),
                            label: const Text('Practice Mode'),
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
      ),
    );
  }
}
