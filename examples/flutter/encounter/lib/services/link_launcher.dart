import 'package:url_launcher/url_launcher.dart';

/// Abstraction for opening external HTTPS links (mockable in tests).
abstract interface class LinkLauncher {
  /// Attempts to open [uri] in an external application. Returns `true` if launched.
  Future<bool> openExternalUri(Uri uri);
}

/// Production implementation backed by `url_launcher`, restricting URIs to `https`.
class UrlLinkLauncher implements LinkLauncher {
  const UrlLinkLauncher();

  @override
  Future<bool> openExternalUri(Uri uri) async {
    if (uri.scheme != 'https' || uri.host.isEmpty) {
      return false;
    }
    try {
      return await launchUrl(uri, mode: LaunchMode.externalApplication);
    } catch (_) {
      return false;
    }
  }
}

/// In-memory fake [LinkLauncher] recording attempted launches for tests.
class FakeLinkLauncher implements LinkLauncher {
  /// All URIs passed to [openExternalUri].
  final List<Uri> launchedUris = [];

  /// Configurable result returned by [openExternalUri].
  bool shouldSucceed = true;

  @override
  Future<bool> openExternalUri(Uri uri) async {
    launchedUris.add(uri);
    return shouldSucceed;
  }
}
