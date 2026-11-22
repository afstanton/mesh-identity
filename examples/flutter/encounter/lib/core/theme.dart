import 'package:material_ui/material_ui.dart';

/// Adaptive Material 3 light and dark themes for the Encounter app.
abstract final class AppTheme {
  static const Color _seedColor = Color(0xFF0F766E);

  /// Returns the adaptive light theme.
  static ThemeData light() => _build(Brightness.light);

  /// Returns the adaptive dark theme.
  static ThemeData dark() => _build(Brightness.dark);

  static ThemeData _build(Brightness brightness) {
    final colorScheme = ColorScheme.fromSeed(
      seedColor: _seedColor,
      brightness: brightness,
    );

    return ThemeData(
      useMaterial3: true,
      colorScheme: colorScheme,
      cardTheme: CardThemeData(
        elevation: 0,
        margin: EdgeInsets.zero,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: BorderSide(color: colorScheme.outlineVariant),
        ),
      ),
      navigationBarTheme: NavigationBarThemeData(
        indicatorColor: colorScheme.secondaryContainer,
        labelBehavior: NavigationDestinationLabelBehavior.alwaysShow,
      ),
      navigationRailTheme: NavigationRailThemeData(
        indicatorColor: colorScheme.secondaryContainer,
        useIndicator: true,
      ),
    );
  }

  /// Monospace text style for hexadecimal cryptographic keys and fingerprints.
  static TextStyle monospaceStyle(BuildContext context) {
    final base = Theme.of(context).textTheme.bodyMedium;
    return (base ?? const TextStyle()).copyWith(
      fontFamily: 'monospace',
      fontFamilyFallback: const <String>['Menlo', 'Consolas', 'Courier New'],
    );
  }
}
