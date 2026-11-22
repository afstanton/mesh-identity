import 'dart:async';

import 'package:material_ui/material_ui.dart';

import 'core/config.dart';
import 'core/theme.dart';
import 'features/about/about_view.dart';
import 'features/overview/encounter_home_view.dart';
import 'features/placeholders/slice_placeholder_view.dart';
import 'services/identity_controller.dart';
import 'services/link_launcher.dart';
import 'shell/adaptive_shell.dart';
import 'shell/app_destination.dart';
import 'shell/macos_menu_bar.dart';
import 'shell/theme_controller.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  AppConfig.registerAppLicense();
  runApp(const EncounterApp());
}

/// Root widget for the Encounter reference application.
class EncounterApp extends StatefulWidget {
  /// Optional injected identity controller (primarily for testing).
  final IdentityController? controller;

  /// Optional injected theme controller (primarily for testing).
  final ThemeController? themeController;

  /// Optional injected external link launcher (primarily for testing).
  final LinkLauncher? linkLauncher;

  /// Initial shell destination when ready.
  final AppDestination initialDestination;

  const EncounterApp({
    super.key,
    this.controller,
    this.themeController,
    this.linkLauncher,
    this.initialDestination = AppDestination.encounter,
  });

  @override
  State<EncounterApp> createState() => _EncounterAppState();
}

class _EncounterAppState extends State<EncounterApp> {
  late IdentityController _controller;
  late bool _ownsController;
  late ThemeController _themeController;
  late bool _ownsThemeController;
  late LinkLauncher _linkLauncher;
  late AppDestination _selectedDestination;
  AppLifecycleListener? _lifecycleListener;

  @override
  void initState() {
    super.initState();
    AppConfig.registerAppLicense();

    _ownsController = widget.controller == null;
    _controller = widget.controller ?? IdentityController();

    _ownsThemeController = widget.themeController == null;
    _themeController = widget.themeController ?? ThemeController();

    _linkLauncher = widget.linkLauncher ?? const UrlLinkLauncher();
    _selectedDestination = widget.initialDestination;

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
    if (widget.themeController != oldWidget.themeController) {
      if (_ownsThemeController) {
        _themeController.dispose();
      }
      _ownsThemeController = widget.themeController == null;
      _themeController = widget.themeController ?? ThemeController();
    }
    if (widget.linkLauncher != oldWidget.linkLauncher) {
      _linkLauncher = widget.linkLauncher ?? const UrlLinkLauncher();
    }
  }

  void _handlePersistLifecycle() {
    if (_controller.isReady) {
      unawaited(_controller.persist());
    }
  }

  void _openRepositoryFromMenu() {
    final uri = AppConfig.repoUri;
    if (uri != null) {
      unawaited(_linkLauncher.openExternalUri(uri));
    }
  }

  @override
  void dispose() {
    _lifecycleListener?.dispose();
    if (_ownsController) {
      _controller.dispose();
    }
    if (_ownsThemeController) {
      _themeController.dispose();
    }
    super.dispose();
  }

  static String? _shortFingerprint(List<int>? bytes) {
    if (bytes == null || bytes.isEmpty) return null;
    final hex = bytes
        .take(6)
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
    return '$hex...';
  }

  Widget _buildDestinationBody() {
    return switch (_selectedDestination) {
      AppDestination.encounter => EncounterHomeView(controller: _controller),
      AppDestination.contacts => ContactsPlaceholderView(
        controller: _controller,
      ),
      AppDestination.groups => const GroupsPlaceholderView(),
      AppDestination.identity => IdentityOverviewView(controller: _controller),
      AppDestination.about => AboutView(linkLauncher: _linkLauncher),
    };
  }

  @override
  Widget build(BuildContext context) {
    return ValueListenableBuilder<ThemeMode>(
      valueListenable: _themeController,
      builder: (context, themeMode, _) {
        return MaterialApp(
          title: AppConfig.appName,
          theme: AppTheme.light(),
          darkTheme: AppTheme.dark(),
          themeMode: themeMode,
          home: ListenableBuilder(
            listenable: _controller,
            builder: (context, _) {
              final ready = _controller.isReady;
              final Widget content = switch (_controller.status) {
                IdentityStatus.uninitialized ||
                IdentityStatus.initializing => const _InitializingScreen(),
                IdentityStatus.unavailable => _UnavailableScreen(
                  controller: _controller,
                ),
                IdentityStatus.corrupted => _CorruptedRecoveryScreen(
                  controller: _controller,
                ),
                IdentityStatus.ready => AdaptiveShell(
                  selectedDestination: _selectedDestination,
                  onDestinationSelected: (destination) {
                    setState(() {
                      _selectedDestination = destination;
                    });
                  },
                  themeController: _themeController,
                  activePersonaFingerprint: _shortFingerprint(
                    _controller.selectedIdentity,
                  ),
                  body: _buildDestinationBody(),
                ),
              };

              return MacOsMenuBar(
                navigationEnabled: ready,
                onSelectDestination: (destination) {
                  setState(() {
                    _selectedDestination = destination;
                  });
                },
                themeController: _themeController,
                onOpenRepository: _openRepositoryFromMenu,
                child: content,
              );
            },
          ),
        );
      },
    );
  }
}

class _InitializingScreen extends StatelessWidget {
  const _InitializingScreen();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text(AppConfig.appName)),
      body: const Center(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            CircularProgressIndicator(),
            SizedBox(height: 16),
            Text('Initializing local identity...'),
          ],
        ),
      ),
    );
  }
}

class _UnavailableScreen extends StatelessWidget {
  final IdentityController controller;

  const _UnavailableScreen({required this.controller});

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text(AppConfig.appName)),
      body: Center(
        child: Padding(
          padding: const EdgeInsets.all(24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 480),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(
                  Icons.lock_clock_outlined,
                  size: 48,
                  color: Colors.blueGrey,
                ),
                const SizedBox(height: 16),
                Text(
                  'Identity Temporarily Unavailable',
                  style: Theme.of(context).textTheme.headlineSmall,
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 12),
                Text(
                  controller.errorMessage ??
                      'Local identity storage could not be accessed right now.',
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 24),
                FilledButton(
                  onPressed: controller.initialize,
                  child: const Text('Retry'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _CorruptedRecoveryScreen extends StatelessWidget {
  final IdentityController controller;

  const _CorruptedRecoveryScreen({required this.controller});

  Future<void> _confirmReset(BuildContext context) async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text('Reset Identity?'),
        content: const Text(
          'Resetting permanently erases all local signing keys and creates a '
          'brand-new identity. Your previous identity, personas, and contacts '
          'cannot be recovered after resetting (any corrupted snapshot file is '
          'moved aside for diagnostics only). This action cannot be undone.',
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
      body: Center(
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
    );
  }
}
