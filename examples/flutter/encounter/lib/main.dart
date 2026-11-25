import 'dart:async';

import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import 'core/config.dart';
import 'core/theme.dart';
import 'features/about/about_view.dart';
import 'features/contacts/contacts_view.dart';
import 'features/encounter/camera_qr_scanner_screen.dart';
import 'features/groups/groups_view.dart';
import 'features/identity/identity_view.dart';
import 'features/overview/encounter_home_view.dart';
import 'services/group_controller.dart';
import 'services/identity_controller.dart';
import 'services/link_launcher.dart';
import 'services/qr_scanner_service.dart';
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

  /// Optional injected group controller (primarily for testing).
  final GroupController? groupController;

  /// Optional injected theme controller (primarily for testing).
  final ThemeController? themeController;

  /// Optional injected external link launcher (primarily for testing).
  final LinkLauncher? linkLauncher;

  /// Optional injected QR scanner service (primarily for testing).
  final QrScannerService? qrScanner;

  /// Initial shell destination when ready.
  final AppDestination initialDestination;

  const EncounterApp({
    super.key,
    this.controller,
    this.groupController,
    this.themeController,
    this.linkLauncher,
    this.qrScanner,
    this.initialDestination = AppDestination.encounter,
  });

  @override
  State<EncounterApp> createState() => _EncounterAppState();
}

class _EncounterAppState extends State<EncounterApp> {
  late IdentityController _controller;
  late bool _ownsController;
  late GroupController _groupController;
  late bool _ownsGroupController;
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

    _ownsGroupController = widget.groupController == null;
    _groupController =
        widget.groupController ??
        GroupController(identityController: _controller);

    _ownsThemeController = widget.themeController == null;
    _themeController = widget.themeController ?? ThemeController();

    _linkLauncher = widget.linkLauncher ?? const UrlLinkLauncher();
    _selectedDestination = widget.initialDestination;

    _lifecycleListener = AppLifecycleListener(
      onPause: _handlePersistLifecycle,
      onHide: _handlePersistLifecycle,
      onDetach: _handlePersistLifecycle,
      onResume: _handleResumeLifecycle,
      onShow: _handleResumeLifecycle,
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
    if (widget.groupController != oldWidget.groupController ||
        widget.controller != oldWidget.controller) {
      if (_ownsGroupController) {
        _groupController.dispose();
      }
      _ownsGroupController = widget.groupController == null;
      _groupController =
          widget.groupController ??
          GroupController(identityController: _controller);
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

  void _handleResumeLifecycle() {
    if (_controller.isReady) {
      unawaited(_controller.checkEncounterExpiry());
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
    if (_ownsGroupController) {
      _groupController.dispose();
    }
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

  static String? _activePersonaHeaderLabel(IdentityController controller) {
    final selected = controller.selectedIdentity;
    final short = _shortFingerprint(selected);
    if (selected == null || short == null) return short;
    final label = controller.personaLabel(selected);
    if (label != null && label.isNotEmpty) {
      return '$label ($short)';
    }
    return short;
  }

  Widget _buildDestinationBody() {
    return switch (_selectedDestination) {
      AppDestination.encounter => EncounterHomeView(
        controller: _controller,
        qrScanner: widget.qrScanner ?? const ZxingQrScannerService(),
      ),
      AppDestination.contacts => ContactsView(
        controller: _controller,
        onStartEncounter: () {
          setState(() {
            _selectedDestination = AppDestination.encounter;
          });
        },
      ),
      AppDestination.groups => GroupsView(
        identityController: _controller,
        groupController: _groupController,
      ),
      AppDestination.identity => IdentityView(controller: _controller),
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
          debugShowCheckedModeBanner: false,
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
                  activePersonaFingerprint: _activePersonaHeaderLabel(
                    _controller,
                  ),
                  body: _buildDestinationBody(),
                ),
              };

              return MacOsMenuBar(
                navigationEnabled: ready && !_controller.hasActiveEncounter,
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

  String _friendlySummary(String? rawError) {
    final lower = (rawError ?? '').toLowerCase();
    if (lower.contains('-34018') ||
        lower.contains('-50') ||
        lower.contains('keychain') ||
        lower.contains('security result code')) {
      return 'The OS keychain rejected access for this build (missing '
          'signing/entitlement or keychain parameter mismatch). Check your '
          'system keychain or signing configuration and try again.';
    }
    return 'Local identity storage could not be accessed right now. '
        'Your existing keys have not been modified.';
  }

  @override
  Widget build(BuildContext context) {
    final rawDetails = controller.errorMessage;
    return Scaffold(
      appBar: AppBar(title: const Text(AppConfig.appName)),
      body: Center(
        child: SingleChildScrollView(
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
                  'Identity Storage Unavailable',
                  style: Theme.of(context).textTheme.headlineSmall,
                  textAlign: TextAlign.center,
                ),
                const SizedBox(height: 12),
                Text(_friendlySummary(rawDetails), textAlign: TextAlign.center),
                if (rawDetails != null && rawDetails.trim().isNotEmpty) ...[
                  const SizedBox(height: 16),
                  ExpansionTile(
                    key: const Key('storage_error_details_tile'),
                    title: const Text('Technical Details'),
                    childrenPadding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
                    children: [
                      SelectableText(
                        rawDetails,
                        style: AppTheme.monospaceStyle(context)
                            .copyWith(fontSize: 12),
                      ),
                    ],
                  ),
                ],
                const SizedBox(height: 24),
                Wrap(
                  spacing: 12,
                  runSpacing: 12,
                  alignment: WrapAlignment.center,
                  children: [
                    if (rawDetails != null && rawDetails.trim().isNotEmpty)
                      OutlinedButton.icon(
                        key: const Key('copy_storage_diagnostics_button'),
                        onPressed: () async {
                          await Clipboard.setData(
                            ClipboardData(text: rawDetails),
                          );
                          if (!context.mounted) return;
                          ScaffoldMessenger.of(context).showSnackBar(
                            const SnackBar(
                              content: Text('Diagnostics copied to clipboard.'),
                            ),
                          );
                        },
                        icon: const Icon(Icons.copy_outlined, size: 18),
                        label: const Text('Copy Diagnostics'),
                      ),
                    FilledButton(
                      onPressed: controller.initialize,
                      child: const Text('Retry'),
                    ),
                  ],
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
