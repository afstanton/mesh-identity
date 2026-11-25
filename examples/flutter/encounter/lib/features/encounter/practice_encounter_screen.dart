import 'package:material_ui/material_ui.dart';

import '../../core/theme.dart';
import '../../services/encounter_session.dart';
import 'practice_encounter_controller.dart';
import 'widgets/encounter_qr_view.dart';
import 'widgets/sas_confirmation_panel.dart';
import 'widgets/statutory_notices.dart';

/// Isolated single-device Alice & Bob Practice Mode screen demonstrating the
/// complete 3-frame QR handshake and dual 6-digit SAS verification without
/// touching persisted device keys or contacts.
class PracticeEncounterScreen extends StatefulWidget {
  final PracticeEncounterController? controller;

  const PracticeEncounterScreen({super.key, this.controller});

  @override
  State<PracticeEncounterScreen> createState() =>
      _PracticeEncounterScreenState();
}

class _PracticeEncounterScreenState extends State<PracticeEncounterScreen> {
  late PracticeEncounterController _controller;
  late bool _ownsController;
  final ScrollController _scrollController = ScrollController();
  late PracticeStep _lastStep;
  late PracticePartyOutcome _lastAliceOutcome;
  bool _mobileComparingAlice = true;

  @override
  void initState() {
    super.initState();
    _ownsController = widget.controller == null;
    _controller = widget.controller ?? PracticeEncounterController();
    _lastStep = _controller.step;
    _lastAliceOutcome = _controller.aliceOutcome;
    _controller.addListener(_onControllerChanged);
  }

  @override
  void didUpdateWidget(covariant PracticeEncounterScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.controller != oldWidget.controller) {
      _controller.removeListener(_onControllerChanged);
      if (_ownsController) {
        _controller.dispose();
      }
      _ownsController = widget.controller == null;
      _controller = widget.controller ?? PracticeEncounterController();
      _lastStep = _controller.step;
      _lastAliceOutcome = _controller.aliceOutcome;
      _mobileComparingAlice = true;
      _controller.addListener(_onControllerChanged);
    }
  }

  @override
  void dispose() {
    _controller.removeListener(_onControllerChanged);
    _scrollController.dispose();
    if (_ownsController) {
      _controller.dispose();
    }
    super.dispose();
  }

  void _scrollToTop() {
    if (_scrollController.hasClients) {
      _scrollController.jumpTo(0);
    }
  }

  void _onControllerChanged() {
    final stepChanged = _controller.step != _lastStep;
    final aliceJustFinished =
        _controller.step == PracticeStep.comparing &&
        _lastAliceOutcome == PracticePartyOutcome.pending &&
        _controller.aliceOutcome != PracticePartyOutcome.pending;

    _lastStep = _controller.step;
    _lastAliceOutcome = _controller.aliceOutcome;

    if (stepChanged) {
      _mobileComparingAlice = true;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) _scrollToTop();
      });
    } else if (aliceJustFinished && _mobileComparingAlice) {
      setState(() => _mobileComparingAlice = false);
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) _scrollToTop();
      });
    }
  }

  String _stepSummaryText(PracticeStep step) => switch (step) {
    PracticeStep.offerReady =>
      'Step 1 of 4: Alice generated Offer (QR 1). Send it to Bob.',
    PracticeStep.responseReady =>
      'Step 2 of 4: Bob generated Response (QR 2). Send it back to Alice.',
    PracticeStep.revealReady =>
      'Step 3 of 4: Alice emitted Reveal (QR 3). Send it to Bob.',
    PracticeStep.comparing =>
      'Step 4 of 4: Compare 6-digit SAS codes and confirm each side manually.',
  };

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Practice Mode'),
        actions: [
          TextButton.icon(
            key: const Key('practice_restart_button'),
            onPressed: _controller.restart,
            icon: const Icon(Icons.refresh, size: 18),
            label: const Text('Restart'),
          ),
        ],
      ),
      body: SafeArea(
        child: ListenableBuilder(
          listenable: _controller,
          builder: (context, _) {
            final colorScheme = Theme.of(context).colorScheme;
            return Center(
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 960),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Padding(
                      padding: const EdgeInsets.fromLTRB(20, 16, 20, 0),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          Container(
                            padding: const EdgeInsets.all(14),
                            decoration: BoxDecoration(
                              color: colorScheme.secondaryContainer,
                              borderRadius: BorderRadius.circular(12),
                            ),
                            child: Row(
                              children: [
                                Icon(
                                  Icons.science_outlined,
                                  color: colorScheme.onSecondaryContainer,
                                ),
                                const SizedBox(width: 10),
                                Expanded(
                                  child: Text(
                                    'Practice Mode — Uses temporary in-memory keys. '
                                    'Nothing is saved to your device.',
                                    style: Theme.of(context)
                                        .textTheme
                                        .bodyMedium
                                        ?.copyWith(
                                          color:
                                              colorScheme.onSecondaryContainer,
                                          fontWeight: FontWeight.w500,
                                        ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                          const SizedBox(height: 12),
                          Card(
                            key: const Key('practice_step_banner'),
                            child: Padding(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 16,
                                vertical: 12,
                              ),
                              child: Text(
                                _stepSummaryText(_controller.step),
                                style: Theme.of(context).textTheme.titleSmall,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                    Expanded(
                      child: SingleChildScrollView(
                        controller: _scrollController,
                        padding: const EdgeInsets.fromLTRB(20, 16, 20, 20),
                        child: LayoutBuilder(
                          builder: (context, constraints) {
                            final sideBySide = constraints.maxWidth >= 700;
                            final alicePane = _buildAlicePane(context);
                            final bobPane = _buildBobPane(context);
                            if (sideBySide) {
                              return Row(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Expanded(child: alicePane),
                                  const SizedBox(width: 16),
                                  Expanded(child: bobPane),
                                ],
                              );
                            }
                            return switch (_controller.step) {
                              PracticeStep.offerReady ||
                              PracticeStep.revealReady => alicePane,
                              PracticeStep.responseReady => bobPane,
                              PracticeStep.comparing => Column(
                                crossAxisAlignment: CrossAxisAlignment.stretch,
                                children: [
                                  SegmentedButton<bool>(
                                    key: const Key('practice_party_selector'),
                                    segments: const [
                                      ButtonSegment<bool>(
                                        value: true,
                                        label: Text('Alice'),
                                        icon: Icon(Icons.person_outline),
                                      ),
                                      ButtonSegment<bool>(
                                        value: false,
                                        label: Text('Bob'),
                                        icon: Icon(
                                          Icons.person_pin_circle_outlined,
                                        ),
                                      ),
                                    ],
                                    selected: {_mobileComparingAlice},
                                    onSelectionChanged: (selection) {
                                      setState(
                                        () => _mobileComparingAlice =
                                            selection.first,
                                      );
                                      _scrollToTop();
                                    },
                                  ),
                                  const SizedBox(height: 16),
                                  _mobileComparingAlice ? alicePane : bobPane,
                                ],
                              ),
                            };
                          },
                        ),
                      ),
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

  Widget _buildAlicePane(BuildContext context) {
    final aliceFingerprint = shortHexKey(_controller.alicePublicKey);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _ParticipantHeader(
          name: 'Alice (Initiator)',
          fingerprint: aliceFingerprint,
          icon: Icons.person_outline,
        ),
        const SizedBox(height: 10),
        switch (_controller.step) {
          PracticeStep.offerReady => Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              EncounterPayloadCard(
                title: 'Alice Offer (QR 1)',
                subtitle: 'Alice displays QR 1 so Bob can start the exchange.',
                payloadUri: _controller.offerUri!,
                copyButtonLabel: 'Copy Alice Offer URI',
              ),
              const SizedBox(height: 12),
              FilledButton.icon(
                key: const Key('practice_send_offer'),
                onPressed: _controller.deliverOfferToBob,
                icon: const Icon(Icons.send_outlined, size: 18),
                label: const Text('Send Offer to Bob'),
              ),
            ],
          ),
          PracticeStep.responseReady => const _WaitingStatusCard(
            title: 'Waiting for Bob\'s Response (QR 2)',
            message: 'Send Bob\'s Response payload back to Alice to advance.',
          ),
          PracticeStep.revealReady => Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              EncounterPayloadCard(
                title: 'Alice Reveal (QR 3)',
                subtitle: 'Alice emits QR 3 so Bob can derive the shared 6-digit SAS code.',
                payloadUri: _controller.revealUri!,
                copyButtonLabel: 'Copy Alice Reveal URI',
              ),
              const SizedBox(height: 12),
              FilledButton.icon(
                key: const Key('practice_send_reveal'),
                onPressed: _controller.deliverRevealToBob,
                icon: const Icon(Icons.send_outlined, size: 18),
                label: const Text('Send Reveal to Bob'),
              ),
            ],
          ),
          PracticeStep.comparing => switch (_controller.aliceOutcome) {
            PracticePartyOutcome.pending => SasConfirmationPanel(
              key: ValueKey('alice_sas_$aliceFingerprint'),
              title: 'Alice: Verify Bob\'s 6-Digit Code',
              codeLabel: 'Alice\'s 6-digit code:',
              comparison: _controller.aliceComparison!,
              inlineError: _controller.aliceError,
              confirmLabel: 'Confirm Alice Side',
              codeKey: const Key('practice_alice_sas'),
              inputKey: const Key('practice_alice_input'),
              confirmButtonKey: const Key('practice_alice_confirm'),
              onConfirm: _controller.confirmAlice,
            ),
            PracticePartyOutcome.verified => VerifiedContactCard(
              title: 'Alice Verified Bob',
              contact: _controller.aliceVerifiedContact!,
              isPractice: true,
            ),
            PracticePartyOutcome.failed => _ParticipantFailureCard(
              title: 'Alice Cancelled',
              message:
                  _controller.aliceError ??
                  'Practice encounter failed on Alice\'s side.',
            ),
          },
        },
      ],
    );
  }

  Widget _buildBobPane(BuildContext context) {
    final bobFingerprint = shortHexKey(_controller.bobPublicKey);
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _ParticipantHeader(
          name: 'Bob (Responder)',
          fingerprint: bobFingerprint,
          icon: Icons.person_pin_circle_outlined,
        ),
        const SizedBox(height: 10),
        switch (_controller.step) {
          PracticeStep.offerReady => const _WaitingStatusCard(
            title: 'Waiting for Alice\'s Offer (QR 1)',
            message: 'Bob is ready to scan Alice\'s Offer payload.',
          ),
          PracticeStep.responseReady => Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              EncounterPayloadCard(
                title: 'Bob Response (QR 2)',
                subtitle:
                    'Bob accepted QR 1 and generated QR 2 Response for Alice.',
                payloadUri: _controller.responseUri!,
                copyButtonLabel: 'Copy Bob Response URI',
              ),
              const SizedBox(height: 12),
              FilledButton.icon(
                key: const Key('practice_send_response'),
                onPressed: _controller.deliverResponseToAlice,
                icon: const Icon(Icons.send_outlined, size: 18),
                label: const Text('Send Response to Alice'),
              ),
            ],
          ),
          PracticeStep.revealReady => const _WaitingStatusCard(
            title: 'Waiting for Alice\'s Reveal (QR 3)',
            message: 'Send Alice\'s Reveal payload to Bob to display Bob\'s 6-digit code.',
          ),
          PracticeStep.comparing => switch (_controller.bobOutcome) {
            PracticePartyOutcome.pending => SasConfirmationPanel(
              key: ValueKey('bob_sas_$bobFingerprint'),
              title: 'Bob: Verify Alice\'s 6-Digit Code',
              codeLabel: 'Bob\'s 6-digit code:',
              comparison: _controller.bobComparison!,
              inlineError: _controller.bobError,
              confirmLabel: 'Confirm Bob Side',
              codeKey: const Key('practice_bob_sas'),
              inputKey: const Key('practice_bob_input'),
              confirmButtonKey: const Key('practice_bob_confirm'),
              onConfirm: _controller.confirmBob,
            ),
            PracticePartyOutcome.verified => VerifiedContactCard(
              title: 'Bob Verified Alice',
              contact: _controller.bobVerifiedContact!,
              isPractice: true,
            ),
            PracticePartyOutcome.failed => _ParticipantFailureCard(
              title: 'Bob Cancelled',
              message:
                  _controller.bobError ??
                  'Practice encounter failed on Bob\'s side.',
            ),
          },
        },
      ],
    );
  }
}

class _ParticipantHeader extends StatelessWidget {
  final String name;
  final String fingerprint;
  final IconData icon;

  const _ParticipantHeader({
    required this.name,
    required this.fingerprint,
    required this.icon,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: colorScheme.outlineVariant),
      ),
      child: Row(
        children: [
          Icon(icon, color: colorScheme.primary, size: 20),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(name, style: Theme.of(context).textTheme.titleSmall),
                Text(
                  fingerprint,
                  style: AppTheme.monospaceStyle(
                    context,
                  ).copyWith(fontSize: 12, color: colorScheme.onSurfaceVariant),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class _WaitingStatusCard extends StatelessWidget {
  final String title;
  final String message;

  const _WaitingStatusCard({required this.title, required this.message});

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.hourglass_empty_outlined,
                  size: 20,
                  color: colorScheme.onSurfaceVariant,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    title,
                    style: Theme.of(context).textTheme.titleSmall,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              message,
              style: Theme.of(context).textTheme.bodyMedium
                  ?.copyWith(color: colorScheme.onSurfaceVariant),
            ),
          ],
        ),
      ),
    );
  }
}

class _ParticipantFailureCard extends StatelessWidget {
  final String title;
  final String message;

  const _ParticipantFailureCard({required this.title, required this.message});

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Icon(Icons.error_outline, color: colorScheme.error),
            const SizedBox(width: 10),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(title, style: Theme.of(context).textTheme.titleSmall),
                  const SizedBox(height: 4),
                  Text(message, style: Theme.of(context).textTheme.bodyMedium),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
