import 'package:material_ui/material_ui.dart';

import '../core/config.dart';
import '../core/theme.dart';
import 'app_destination.dart';
import 'theme_controller.dart';

/// Responsive navigation container switching between mobile bottom navigation
/// and desktop navigation rail layouts.
class AdaptiveShell extends StatelessWidget {
  /// Viewport width at which navigation switches from bottom bar to side rail.
  static const double railBreakpoint = 720;

  /// Viewport width at which the desktop navigation rail expands to show labels inline.
  static const double extendedRailBreakpoint = 1080;

  final AppDestination selectedDestination;
  final ValueChanged<AppDestination> onDestinationSelected;
  final ThemeController themeController;
  final Widget body;
  final String? activePersonaFingerprint;

  const AdaptiveShell({
    super.key,
    required this.selectedDestination,
    required this.onDestinationSelected,
    required this.themeController,
    required this.body,
    this.activePersonaFingerprint,
  });

  Widget _buildThemeButton() {
    return ValueListenableBuilder<ThemeMode>(
      valueListenable: themeController,
      builder: (context, _, _) {
        return IconButton(
          key: const Key('theme_cycle_button'),
          tooltip: 'Appearance: ${themeController.label}',
          icon: Icon(themeController.icon),
          onPressed: themeController.cycleThemeMode,
        );
      },
    );
  }

  @override
  Widget build(BuildContext context) {
    final width = MediaQuery.sizeOf(context).width;
    final useRail = width >= railBreakpoint;
    final extendedRail = width >= extendedRailBreakpoint;

    if (!useRail) {
      final platform = Theme.of(context).platform;
      final isApple =
          platform == TargetPlatform.iOS || platform == TargetPlatform.macOS;
      return Scaffold(
        appBar: AppBar(
          title: Column(
            crossAxisAlignment: isApple
                ? CrossAxisAlignment.center
                : CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(selectedDestination.label, overflow: TextOverflow.ellipsis),
              if (activePersonaFingerprint != null)
                Text(
                  activePersonaFingerprint!,
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: AppTheme.monospaceStyle(context).copyWith(
                    fontSize: 12,
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
            ],
          ),
          actions: [_buildThemeButton()],
        ),
        body: SafeArea(child: body),
        bottomNavigationBar: NavigationBar(
          selectedIndex: selectedDestination.index,
          onDestinationSelected: (index) {
            onDestinationSelected(AppDestination.values[index]);
          },
          destinations: [
            for (final dest in AppDestination.values)
              NavigationDestination(
                icon: Icon(dest.icon),
                selectedIcon: Icon(dest.selectedIcon),
                label: dest.label,
              ),
          ],
        ),
      );
    }

    return Scaffold(
      body: Row(
        children: [
          NavigationRail(
            extended: extendedRail,
            labelType: extendedRail
                ? NavigationRailLabelType.none
                : NavigationRailLabelType.all,
            selectedIndex: selectedDestination.index,
            onDestinationSelected: (index) {
              onDestinationSelected(AppDestination.values[index]);
            },
            trailingAtBottom: true,
            leading: Padding(
              padding: EdgeInsets.symmetric(
                horizontal: extendedRail ? 16 : 8,
                vertical: 12,
              ),
              child: extendedRail
                  ? Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          Icons.verified_user_outlined,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                        const SizedBox(width: 10),
                        Text(
                          AppConfig.appName,
                          style: Theme.of(context).textTheme.titleMedium,
                        ),
                      ],
                    )
                  : Icon(
                      Icons.verified_user_outlined,
                      color: Theme.of(context).colorScheme.primary,
                    ),
            ),
            trailing: Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: _buildThemeButton(),
            ),
            destinations: [
              for (final dest in AppDestination.values)
                NavigationRailDestination(
                  icon: Icon(dest.icon),
                  selectedIcon: Icon(dest.selectedIcon),
                  label: Text(dest.label),
                ),
            ],
          ),
          const VerticalDivider(width: 1, thickness: 1),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                Container(
                  height: 56,
                  padding: const EdgeInsets.symmetric(horizontal: 20),
                  alignment: Alignment.centerLeft,
                  child: Row(
                    children: [
                      Expanded(
                        child: Text(
                          selectedDestination.label,
                          style: Theme.of(context).textTheme.titleLarge,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      if (activePersonaFingerprint != null) ...[
                        const SizedBox(width: 12),
                        Chip(
                          avatar: const Icon(Icons.key_outlined, size: 16),
                          label: Text(
                            activePersonaFingerprint!,
                            style: AppTheme.monospaceStyle(context),
                          ),
                          visualDensity: VisualDensity.compact,
                        ),
                      ],
                    ],
                  ),
                ),
                const Divider(height: 1),
                Expanded(child: body),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
