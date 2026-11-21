/// Application build-time configuration.
///
/// Values default to open-source placeholders and can be overridden at build time via
/// `--dart-define` or `--dart-define-from-file=config/config.local.json`.
abstract final class AppConfig {
  /// User-facing display name of the application.
  static const String appName = String.fromEnvironment(
    'APP_NAME',
    defaultValue: 'Encounter',
  );

  /// Public repository URL for about screen and open source disclosures.
  static const String repoUrl = String.fromEnvironment(
    'REPO_URL',
    defaultValue: 'https://github.com/afstanton/mesh-identity',
  );

  /// Whether analytics tracking is enabled (disabled by default).
  static const bool enableTelemetry = bool.fromEnvironment(
    'ENABLE_ANALYTICS',
    defaultValue: false,
  );

  /// API key / DSN for analytics service if enabled.
  static const String analyticsKey = String.fromEnvironment(
    'ANALYTICS_KEY',
    defaultValue: '',
  );

  /// Whether crash reporting is enabled (disabled by default).
  static const bool enableCrashReporting = bool.fromEnvironment(
    'ENABLE_CRASH_REPORTING',
    defaultValue: false,
  );

  /// DSN for crash reporting service if enabled.
  static const String crashReportingKey = String.fromEnvironment(
    'CRASH_REPORTING_KEY',
    defaultValue: '',
  );
}
