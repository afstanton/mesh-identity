import 'dart:io';

import 'package:encounter/core/config.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('AppConfig metadata drift checks', () {
    test('appVersion matches pubspec.yaml version', () {
      final pubspec = File('pubspec.yaml').readAsStringSync();
      final match = RegExp(
        r'^version:\s*(.+)$',
        multiLine: true,
      ).firstMatch(pubspec);
      expect(match, isNotNull);
      expect(AppConfig.appVersion, equals(match!.group(1)!.trim()));
    });

    test(
      'meshIdentityBindingVersion matches pubspec.lock resolved version',
      () {
        final lockfile = File('pubspec.lock').readAsStringSync();
        final match = RegExp(
          r'mesh_identity:\s*\n(?:[ \t]+.*\n)*?[ \t]+version:\s*"([^"]+)"',
        ).firstMatch(lockfile);
        expect(match, isNotNull);
        expect(
          AppConfig.meshIdentityBindingVersion,
          equals(match!.group(1)!.trim()),
        );
      },
    );

    test('mitLicenseText and copyrightNotice match LICENSE file', () {
      final licenseFile = File('LICENSE').readAsStringSync().trim();
      expect(AppConfig.mitLicenseText.trim(), equals(licenseFile));
      expect(AppConfig.mitLicenseText, contains(AppConfig.copyrightNotice));
    });

    test('meshIdentityCoreVersion matches root Cargo.toml when present', () {
      final cargoToml = File('../../../Cargo.toml');
      if (!cargoToml.existsSync()) {
        return;
      }
      final content = cargoToml.readAsStringSync();
      final match = RegExp(
        r'^version\s*=\s*"([^"]+)"',
        multiLine: true,
      ).firstMatch(content);
      expect(match, isNotNull);
      expect(
        AppConfig.meshIdentityCoreVersion,
        equals(match!.group(1)!.trim()),
      );
    });
  });
}
