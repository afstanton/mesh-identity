import 'dart:async';

import 'package:material_ui/material_ui.dart';

import 'core/config.dart';
import 'services/identity_controller.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  runApp(const EncounterApp());
}

/// Root widget for the Encounter reference application.
class EncounterApp extends StatefulWidget {
  /// Optional injected controller (primarily for deterministic widget testing).
  final IdentityController? controller;

  const EncounterApp({super.key, this.controller});

  @override
  State<EncounterApp> createState() => _EncounterAppState();
}

class _EncounterAppState extends State<EncounterApp> {
  late IdentityController _controller;
  late bool _ownsController;
  AppLifecycleListener? _lifecycleListener;

  @override
  void initState() {
    super.initState();
    _ownsController = widget.controller == null;
    _controller = widget.controller ?? IdentityController();
    _lifecycleListener = AppLifecycleListener(
      onPause: _handlePersistLifecycle,
      onHide: _handlePersistLifecycle,
      onDetach: _handlePersistLifecycle,
    );
    if (_controller.status == IdentityStatus.uninitialized) {
      unawaited(_controller.initialize());
    }
  }

  @override
  void didUpdateWidget(covariant EncounterApp oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.controller != oldWidget.controller) {
      if (_ownsController) {
        _controller.dispose();
      }
      _ownsController = widget.controller == null;
      _controller = widget.controller ?? IdentityController();
      if (_controller.status == IdentityStatus.uninitialized) {
        unawaited(_controller.initialize());
      }
    }
  }

  void _handlePersistLifecycle() {
    if (_controller.isReady) {
      unawaited(_controller.persist());
    }
  }

  @override
  void dispose() {
    _lifecycleListener?.dispose();
    if (_ownsController) {
      _controller.dispose();
    }
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: AppConfig.appName,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.teal),
        useMaterial3: true,
      ),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: Colors.teal,
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: _HomeScreen(controller: _controller),
    );
  }
}

class _HomeScreen extends StatelessWidget {
  final IdentityController controller;

  const _HomeScreen({required this.controller});

  static String _shortFingerprint(List<int>? bytes) {
    if (bytes == null || bytes.isEmpty) return 'None';
    final hex = bytes
        .take(8)
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
    return '$hex...';
  }

  Future<void> _confirmReset(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Reset Identity?'),
        content: const Text(
          'Your corrupted snapshot will be archived for diagnostics, '
          'existing signing keys will be cleared, and a new identity will be created. '
          'This action cannot be undone.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(false),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.of(dialogContext).pop(true),
            child: const Text('Confirm Reset'),
          ),
        ],
      ),
    );
    if (confirmed == true) {
      await controller.resetCorruptedState(confirmDestructiveReset: true);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text(AppConfig.appName)),
      body: ListenableBuilder(
        listenable: controller,
        builder: (context, _) {
          return switch (controller.status) {
            IdentityStatus.uninitialized ||
            IdentityStatus.initializing => const Center(
              child: Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  CircularProgressIndicator(),
                  SizedBox(height: 16),
                  Text('Initializing local identity...'),
                ],
              ),
            ),
            IdentityStatus.corrupted => Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 480),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(
                        Icons.warning_amber_rounded,
                        size: 48,
                        color: Colors.amber,
                      ),
                      const SizedBox(height: 16),
                      Text(
                        'Identity Recovery Required',
                        style: Theme.of(context).textTheme.headlineSmall,
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 12),
                      Text(
                        controller.errorMessage ??
                            'Stored identity state could not be restored.',
                        textAlign: TextAlign.center,
                      ),
                      const SizedBox(height: 24),
                      FilledButton(
                        onPressed: () => _confirmReset(context),
                        child: const Text('Reset Identity'),
                      ),
                    ],
                  ),
                ),
              ),
            ),
            IdentityStatus.ready => Center(
              child: Padding(
                padding: const EdgeInsets.all(24),
                child: ConstrainedBox(
                  constraints: const BoxConstraints(maxWidth: 480),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.verified_user_outlined, size: 48),
                      const SizedBox(height: 16),
                      Text(
                        'Active Persona',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                      const SizedBox(height: 8),
                      SelectableText(
                        _shortFingerprint(controller.selectedIdentity),
                        style: Theme.of(context).textTheme.headlineSmall,
                      ),
                      const SizedBox(height: 16),
                      Text(
                        'Personas: ${controller.identities.length}  •  '
                        'Contacts: ${controller.contactsCount}',
                      ),
                    ],
                  ),
                ),
              ),
            ),
          };
        },
      ),
    );
  }
}
