import 'package:material_ui/material_ui.dart';

/// Controls the active [ThemeMode] across system, light, and dark appearances.
class ThemeController extends ValueNotifier<ThemeMode> {
  ThemeController({ThemeMode initialMode = ThemeMode.system})
    : super(initialMode);

  /// Sets an explicit [ThemeMode].
  void setThemeMode(ThemeMode mode) {
    if (value != mode) {
      value = mode;
    }
  }

  /// Cycles through `system` -> `light` -> `dark` -> `system`.
  void cycleThemeMode() {
    value = switch (value) {
      ThemeMode.system => ThemeMode.light,
      ThemeMode.light => ThemeMode.dark,
      ThemeMode.dark => ThemeMode.system,
    };
  }

  /// Human-readable label for the current theme mode.
  String get label => switch (value) {
    ThemeMode.system => 'System',
    ThemeMode.light => 'Light',
    ThemeMode.dark => 'Dark',
  };

  /// Representative icon for the current theme mode.
  IconData get icon => switch (value) {
    ThemeMode.system => Icons.brightness_auto_outlined,
    ThemeMode.light => Icons.light_mode_outlined,
    ThemeMode.dark => Icons.dark_mode_outlined,
  };
}
