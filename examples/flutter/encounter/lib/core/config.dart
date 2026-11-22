import 'package:flutter/foundation.dart';

/// Application build-time configuration and static release metadata.
///
/// Values default to open-source placeholders and can be overridden at build time via
/// `--dart-define` or `--dart-define-from-file=config/config.local.json`.
abstract final class AppConfig {
  /// User-facing display name of the application.
  static const String appName = String.fromEnvironment(
    'APP_NAME',
    defaultValue: 'Encounter',
  );

  /// Application semantic version and build number matching `pubspec.yaml`.
  static const String appVersion = '1.0.0+1';

  /// Version of the `mesh_identity` Dart binding package on pub.dev.
  static const String meshIdentityBindingVersion = '0.5.0';

  /// Version of the underlying `mesh-identity` Rust crate on crates.io.
  static const String meshIdentityCoreVersion = '0.2.0';

  /// Short license title.
  static const String licenseName = 'MIT License';

  /// Copyright attribution notice.
  static const String copyrightNotice = 'Copyright (c) 2026 Aaron F Stanton';

  /// Full MIT license text matching `LICENSE`.
  static const String mitLicenseText = '''MIT License

Copyright (c) 2026 Aaron F Stanton

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.''';

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

  static bool _licenseRegistered = false;

  /// Parsed repository [Uri], guaranteed to use `https` with a non-empty host, or `null`.
  static Uri? get repoUri {
    final parsed = Uri.tryParse(repoUrl);
    if (parsed == null || parsed.scheme != 'https' || parsed.host.isEmpty) {
      return null;
    }
    return parsed;
  }

  /// Registers the application's MIT license once with Flutter's [LicenseRegistry].
  static void registerAppLicense() {
    if (_licenseRegistered) return;
    _licenseRegistered = true;
    LicenseRegistry.addLicense(
      () => Stream<LicenseEntry>.value(
        const LicenseEntryWithLineBreaks(<String>['encounter'], mitLicenseText),
      ),
    );
  }
}
