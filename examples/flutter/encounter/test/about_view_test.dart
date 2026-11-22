import 'package:encounter/core/config.dart';
import 'package:encounter/features/about/about_view.dart';
import 'package:encounter/services/link_launcher.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

void main() {
  Widget buildSubject(FakeLinkLauncher launcher) {
    return MaterialApp(
      home: Scaffold(body: AboutView(linkLauncher: launcher)),
    );
  }

  group('AboutView', () {
    testWidgets(
      'displays app metadata, engine versions, privacy, and repo URL',
      (WidgetTester tester) async {
        final launcher = FakeLinkLauncher();
        await tester.pumpWidget(buildSubject(launcher));
        await tester.pumpAndSettle();

        expect(find.text(AppConfig.appName), findsOneWidget);
        expect(find.text('Version ${AppConfig.appVersion}'), findsOneWidget);
        expect(find.text(AppConfig.meshIdentityBindingVersion), findsOneWidget);
        expect(find.text(AppConfig.meshIdentityCoreVersion), findsOneWidget);
        expect(find.text('Disabled (Offline-First)'), findsOneWidget);
        expect(find.text(AppConfig.repoUrl), findsOneWidget);
      },
    );

    testWidgets(
      'Open Repository invokes LinkLauncher and handles failure fallback',
      (WidgetTester tester) async {
        final launcher = FakeLinkLauncher();
        await tester.pumpWidget(buildSubject(launcher));
        await tester.pumpAndSettle();

        await tester.ensureVisible(find.text('Open Repository'));
        await tester.tap(find.text('Open Repository'));
        await tester.pumpAndSettle();

        expect(launcher.launchedUris, equals([AppConfig.repoUri]));

        // Now simulate launch failure -> fallback SnackBar shown
        launcher.shouldSucceed = false;
        await tester.tap(find.text('Open Repository'));
        await tester.pumpAndSettle();

        expect(
          find.text(
            'Could not open repository link. You can copy the URL instead.',
          ),
          findsOneWidget,
        );
      },
    );

    testWidgets('MIT License opens dialog with copyright and closes cleanly', (
      WidgetTester tester,
    ) async {
      final launcher = FakeLinkLauncher();
      await tester.pumpWidget(buildSubject(launcher));
      await tester.pumpAndSettle();

      await tester.ensureVisible(find.text(AppConfig.licenseName));
      await tester.tap(find.text(AppConfig.licenseName));
      await tester.pumpAndSettle();

      expect(find.byType(AlertDialog), findsOneWidget);
      expect(find.textContaining(AppConfig.copyrightNotice), findsWidgets);

      await tester.tap(find.text('Close'));
      await tester.pumpAndSettle();
      expect(find.byType(AlertDialog), findsNothing);
    });
  });
}
