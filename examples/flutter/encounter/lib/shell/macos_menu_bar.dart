import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';
import 'package:material_ui/material_ui.dart';

import '../core/config.dart';
import 'app_destination.dart';
import 'theme_controller.dart';

/// Native macOS menu bar wrapper compliant with Apple Human Interface Guidelines.
///
/// On non-macOS platforms, returns [child] unmodified without mounting a
/// [PlatformMenuBar].
class MacOsMenuBar extends StatelessWidget {
  final Widget child;
  final bool navigationEnabled;
  final ValueChanged<AppDestination> onSelectDestination;
  final ThemeController themeController;
  final VoidCallback onOpenRepository;

  const MacOsMenuBar({
    super.key,
    required this.child,
    required this.navigationEnabled,
    required this.onSelectDestination,
    required this.themeController,
    required this.onOpenRepository,
  });

  static const List<LogicalKeyboardKey> _digitKeys = [
    LogicalKeyboardKey.digit1,
    LogicalKeyboardKey.digit2,
    LogicalKeyboardKey.digit3,
    LogicalKeyboardKey.digit4,
    LogicalKeyboardKey.digit5,
  ];

  @override
  Widget build(BuildContext context) {
    if (defaultTargetPlatform != TargetPlatform.macOS) {
      return child;
    }

    return PlatformMenuBar(
      menus: [
        PlatformMenu(
          label: AppConfig.appName,
          menus: [
            PlatformMenuItem(
              label: 'About ${AppConfig.appName}',
              onSelected: navigationEnabled
                  ? () => onSelectDestination(AppDestination.about)
                  : null,
            ),
            PlatformMenuItemGroup(
              members: [
                if (PlatformProvidedMenuItem.hasMenu(
                  PlatformProvidedMenuItemType.hide,
                ))
                  const PlatformProvidedMenuItem(
                    type: PlatformProvidedMenuItemType.hide,
                  ),
                if (PlatformProvidedMenuItem.hasMenu(
                  PlatformProvidedMenuItemType.hideOtherApplications,
                ))
                  const PlatformProvidedMenuItem(
                    type: PlatformProvidedMenuItemType.hideOtherApplications,
                  ),
                if (PlatformProvidedMenuItem.hasMenu(
                  PlatformProvidedMenuItemType.showAllApplications,
                ))
                  const PlatformProvidedMenuItem(
                    type: PlatformProvidedMenuItemType.showAllApplications,
                  ),
              ],
            ),
            PlatformMenuItemGroup(
              members: [
                if (PlatformProvidedMenuItem.hasMenu(
                  PlatformProvidedMenuItemType.quit,
                ))
                  const PlatformProvidedMenuItem(
                    type: PlatformProvidedMenuItemType.quit,
                  ),
              ],
            ),
          ],
        ),
        PlatformMenu(
          label: 'View',
          menus: [
            PlatformMenuItemGroup(
              members: [
                for (var i = 0; i < AppDestination.values.length; i++)
                  PlatformMenuItem(
                    label: AppDestination.values[i].label,
                    shortcut: SingleActivator(_digitKeys[i], meta: true),
                    onSelected: navigationEnabled
                        ? () => onSelectDestination(AppDestination.values[i])
                        : null,
                  ),
              ],
            ),
            PlatformMenu(
              label: 'Appearance',
              menus: [
                PlatformMenuItem(
                  label: 'System',
                  onSelected: () =>
                      themeController.setThemeMode(ThemeMode.system),
                ),
                PlatformMenuItem(
                  label: 'Light',
                  onSelected: () =>
                      themeController.setThemeMode(ThemeMode.light),
                ),
                PlatformMenuItem(
                  label: 'Dark',
                  onSelected: () =>
                      themeController.setThemeMode(ThemeMode.dark),
                ),
              ],
            ),
          ],
        ),
        PlatformMenu(
          label: 'Window',
          menus: [
            PlatformMenuItemGroup(
              members: [
                if (PlatformProvidedMenuItem.hasMenu(
                  PlatformProvidedMenuItemType.minimizeWindow,
                ))
                  const PlatformProvidedMenuItem(
                    type: PlatformProvidedMenuItemType.minimizeWindow,
                  ),
                if (PlatformProvidedMenuItem.hasMenu(
                  PlatformProvidedMenuItemType.zoomWindow,
                ))
                  const PlatformProvidedMenuItem(
                    type: PlatformProvidedMenuItemType.zoomWindow,
                  ),
                if (PlatformProvidedMenuItem.hasMenu(
                  PlatformProvidedMenuItemType.toggleFullScreen,
                ))
                  const PlatformProvidedMenuItem(
                    type: PlatformProvidedMenuItemType.toggleFullScreen,
                  ),
                if (PlatformProvidedMenuItem.hasMenu(
                  PlatformProvidedMenuItemType.arrangeWindowsInFront,
                ))
                  const PlatformProvidedMenuItem(
                    type: PlatformProvidedMenuItemType.arrangeWindowsInFront,
                  ),
              ],
            ),
          ],
        ),
        PlatformMenu(
          label: 'Help',
          menus: [
            PlatformMenuItem(
              label: 'View Source on GitHub',
              onSelected: onOpenRepository,
            ),
          ],
        ),
      ],
      child: child,
    );
  }
}
