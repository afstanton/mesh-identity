import 'package:encounter/core/config.dart';
import 'package:encounter/services/link_launcher.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  group('UrlLinkLauncher', () {
    const launcher = UrlLinkLauncher();

    test('rejects non-HTTPS schemes and empty-host HTTPS URIs', () async {
      expect(
        await launcher.openExternalUri(Uri.parse('http://example.com')),
        isFalse,
      );
      expect(
        await launcher.openExternalUri(Uri.parse('file:///etc/passwd')),
        isFalse,
      );
      expect(
        await launcher.openExternalUri(Uri.parse('javascript:alert(1)')),
        isFalse,
      );
      expect(await launcher.openExternalUri(Uri.parse('https://')), isFalse);
    });
  });

  group('AppConfig.repoUri', () {
    test('returns valid HTTPS Uri matching AppConfig.repoUrl', () {
      final uri = AppConfig.repoUri;
      expect(uri, isNotNull);
      expect(uri!.scheme, equals('https'));
      expect(uri.host, isNotEmpty);
      expect(uri.toString(), equals(AppConfig.repoUrl));
    });
  });
}
