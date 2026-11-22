import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import '../../core/config.dart';
import '../../services/link_launcher.dart';

/// Open-source attribution, build metadata, and repository link screen.
class AboutView extends StatelessWidget {
  final LinkLauncher linkLauncher;

  const AboutView({super.key, required this.linkLauncher});

  Future<void> _openRepository(BuildContext context) async {
    final uri = AppConfig.repoUri;
    var opened = false;
    if (uri != null) {
      opened = await linkLauncher.openExternalUri(uri);
    }
    if (!context.mounted) return;
    if (!opened) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text(
            'Could not open repository link. You can copy the URL instead.',
          ),
        ),
      );
    }
  }

  Future<void> _copyRepositoryUrl(BuildContext context) async {
    await Clipboard.setData(const ClipboardData(text: AppConfig.repoUrl));
    if (!context.mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Repository URL copied to clipboard')),
    );
  }

  Future<void> _showMitLicenseDialog(BuildContext context) async {
    await showDialog<void>(
      context: context,
      builder: (dialogContext) => AlertDialog(
        title: const Text(AppConfig.licenseName),
        content: const SingleChildScrollView(
          child: SelectableText(AppConfig.mitLicenseText),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(dialogContext).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final telemetryStatus =
        AppConfig.enableTelemetry || AppConfig.enableCrashReporting
        ? 'Enabled (Build Flag)'
        : 'Disabled (Offline-First)';

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
                  child: Row(
                    children: [
                      Icon(
                        Icons.verified_user_outlined,
                        size: 40,
                        color: Theme.of(context).colorScheme.primary,
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          children: [
                            Text(
                              AppConfig.appName,
                              style: Theme.of(context).textTheme.headlineSmall,
                            ),
                            const SizedBox(height: 4),
                            Text('Version ${AppConfig.appVersion}'),
                            const SizedBox(height: 4),
                            Text(
                              'Cryptographic peer identity and offline encounters',
                              style: Theme.of(context).textTheme.bodyMedium
                                  ?.copyWith(
                                    color: Theme.of(context)
                                        .colorScheme
                                        .onSurfaceVariant,
                                  ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Card(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Padding(
                      padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
                      child: Text(
                        'Engine & Privacy',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                    ),
                    const ListTile(
                      leading: Icon(Icons.extension_outlined),
                      title: Text('mesh_identity Dart Bindings'),
                      trailing: Text(AppConfig.meshIdentityBindingVersion),
                    ),
                    const Divider(height: 1),
                    const ListTile(
                      leading: Icon(Icons.memory_outlined),
                      title: Text('mesh-identity Rust Core'),
                      trailing: Text(AppConfig.meshIdentityCoreVersion),
                    ),
                    const Divider(height: 1),
                    ListTile(
                      leading: const Icon(Icons.privacy_tip_outlined),
                      title: const Text('Telemetry & Crash Reporting'),
                      trailing: Text(telemetryStatus),
                    ),
                  ],
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
                        'Open Source Repository',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                      const SizedBox(height: 8),
                      const SelectableText(AppConfig.repoUrl),
                      const SizedBox(height: 16),
                      Wrap(
                        spacing: 12,
                        runSpacing: 8,
                        children: [
                          FilledButton.icon(
                            onPressed: () => _openRepository(context),
                            icon: const Icon(Icons.open_in_new, size: 18),
                            label: const Text('Open Repository'),
                          ),
                          OutlinedButton.icon(
                            onPressed: () => _copyRepositoryUrl(context),
                            icon: const Icon(Icons.copy_outlined, size: 18),
                            label: const Text('Copy Link'),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Card(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Padding(
                      padding: const EdgeInsets.fromLTRB(16, 16, 16, 4),
                      child: Text(
                        'Licenses',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                    ),
                    ListTile(
                      leading: const Icon(Icons.article_outlined),
                      title: const Text(AppConfig.licenseName),
                      subtitle: const Text(AppConfig.copyrightNotice),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () => _showMitLicenseDialog(context),
                    ),
                    const Divider(height: 1),
                    ListTile(
                      leading: const Icon(Icons.menu_book_outlined),
                      title: const Text('Open-Source Licenses'),
                      subtitle: const Text('Third-party package notices'),
                      trailing: const Icon(Icons.chevron_right),
                      onTap: () => showLicensePage(
                        context: context,
                        applicationName: AppConfig.appName,
                        applicationVersion: AppConfig.appVersion,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
