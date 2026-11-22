import 'package:encounter/core/config.dart';
import 'package:encounter/features/about/about_view.dart';
import 'package:encounter/features/placeholders/slice_placeholder_view.dart';
import 'package:encounter/main.dart';
import 'package:encounter/services/identity_controller.dart';
import 'package:encounter/services/keyring_service.dart';
import 'package:encounter/services/link_launcher.dart';
import 'package:encounter/services/snapshot_storage.dart';
import 'package:encounter/shell/app_destination.dart';
import 'package:encounter/shell/theme_controller.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:material_ui/material_ui.dart';

List<PlatformMenuItem> _flattenMenuItems(List<PlatformMenuItem> items) {
  final result = <PlatformMenuItem>[];
  for (final item in items) {
    result.add(item);
    if (item is PlatformMenuItemGroup) {
      result.addAll(_flattenMenuItems(item.members));
    } else if (item is PlatformMenu) {
      result.addAll(_flattenMenuItems(item.menus));
    }
  }
  return result;
}

PlatformMenuItem _findMenuItem(PlatformMenu menu, String label) {
  return _flattenMenuItems(menu.menus).firstWhere((m) => m.label == label);
}

void main() {
  Future<IdentityController> createReadyController() async {
    final controller = IdentityController(
      keyring: InMemoryKeyringService(),
      storage: InMemorySnapshotStorageService(),
    );
    await controller.initialize();
    addTearDown(controller.dispose);
    return controller;
  }

  void setViewport(WidgetTester tester, Size size) {
    tester.view.physicalSize = size;
    tester.view.devicePixelRatio = 1.0;
    addTearDown(() {
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    });
  }

  group('AdaptiveShell & MacOsMenuBar', () {
    testWidgets(
      'mobile viewport uses NavigationBar, shows fingerprint in AppBar, and navigates all 5 tabs',
      (WidgetTester tester) async {
        setViewport(tester, const Size(390, 844));
        final controller = await createReadyController();
        final themeController = ThemeController();
        addTearDown(themeController.dispose);

        final selectedKey = controller.selectedIdentity!;
        final expectedPrefix = selectedKey
            .take(6)
            .map((b) => b.toRadixString(16).padLeft(2, '0'))
            .join();

        await tester.pumpWidget(
          EncounterApp(
            controller: controller,
            themeController: themeController,
            linkLauncher: FakeLinkLauncher(),
          ),
        );
        await tester.pumpAndSettle();

        expect(find.byType(NavigationBar), findsOneWidget);
        expect(find.byType(NavigationRail), findsNothing);
        expect(
          find.descendant(
            of: find.byType(AppBar),
            matching: find.text('$expectedPrefix...'),
          ),
          findsOneWidget,
        );

        // Navigate across every destination cleanly
        await tester.tap(
          find.descendant(
            of: find.byType(NavigationBar),
            matching: find.text('Contacts'),
          ),
        );
        await tester.pumpAndSettle();
        expect(find.byType(ContactsPlaceholderView), findsOneWidget);

        await tester.tap(
          find.descendant(
            of: find.byType(NavigationBar),
            matching: find.text('Groups'),
          ),
        );
        await tester.pumpAndSettle();
        expect(find.byType(GroupsPlaceholderView), findsOneWidget);

        await tester.tap(
          find.descendant(
            of: find.byType(NavigationBar),
            matching: find.text('Identity'),
          ),
        );
        await tester.pumpAndSettle();
        expect(find.byType(IdentityOverviewView), findsOneWidget);

        await tester.tap(
          find.descendant(
            of: find.byType(NavigationBar),
            matching: find.text('About'),
          ),
        );
        await tester.pumpAndSettle();
        expect(find.byType(AboutView), findsOneWidget);

        await tester.tap(
          find.descendant(
            of: find.byType(NavigationBar),
            matching: find.text('Encounter'),
          ),
        );
        await tester.pumpAndSettle();
        expect(find.text('Active Persona'), findsOneWidget);
      },
    );

    testWidgets('compact desktop viewport uses collapsed NavigationRail', (
      WidgetTester tester,
    ) async {
      setViewport(tester, const Size(840, 768));
      final controller = await createReadyController();
      final themeController = ThemeController();
      addTearDown(themeController.dispose);

      await tester.pumpWidget(
        EncounterApp(
          controller: controller,
          themeController: themeController,
          linkLauncher: FakeLinkLauncher(),
        ),
      );
      await tester.pumpAndSettle();

      final railFinder = find.byType(NavigationRail);
      expect(railFinder, findsOneWidget);
      expect(find.byType(NavigationBar), findsNothing);
      final rail = tester.widget<NavigationRail>(railFinder);
      expect(rail.extended, isFalse);

      await tester.tap(
        find.descendant(of: railFinder, matching: find.text('About')),
      );
      await tester.pumpAndSettle();
      expect(find.byType(AboutView), findsOneWidget);
    });

    testWidgets(
      'wide desktop viewport uses extended NavigationRail and cycles theme',
      (WidgetTester tester) async {
        setViewport(tester, const Size(1280, 800));
        final controller = await createReadyController();
        final themeController = ThemeController();
        addTearDown(themeController.dispose);

        await tester.pumpWidget(
          EncounterApp(
            controller: controller,
            themeController: themeController,
            linkLauncher: FakeLinkLauncher(),
          ),
        );
        await tester.pumpAndSettle();

        final railFinder = find.byType(NavigationRail);
        expect(railFinder, findsOneWidget);
        final rail = tester.widget<NavigationRail>(railFinder);
        expect(rail.extended, isTrue);

        expect(themeController.value, equals(ThemeMode.system));
        await tester.tap(find.byKey(const Key('theme_cycle_button')));
        await tester.pumpAndSettle();
        expect(themeController.value, equals(ThemeMode.light));

        await tester.tap(find.byKey(const Key('theme_cycle_button')));
        await tester.pumpAndSettle();
        expect(themeController.value, equals(ThemeMode.dark));

        await tester.tap(find.byKey(const Key('theme_cycle_button')));
        await tester.pumpAndSettle();
        expect(themeController.value, equals(ThemeMode.system));
      },
    );

    testWidgets(
      'macOS mounts PlatformMenuBar and invokes About, View, Appearance, and Help actions',
      (WidgetTester tester) async {
        debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
        addTearDown(() {
          debugDefaultTargetPlatformOverride = null;
        });
        setViewport(tester, const Size(1280, 800));

        final controller = await createReadyController();
        final themeController = ThemeController();
        final linkLauncher = FakeLinkLauncher();
        addTearDown(themeController.dispose);

        await tester.pumpWidget(
          EncounterApp(
            controller: controller,
            themeController: themeController,
            linkLauncher: linkLauncher,
          ),
        );
        await tester.pumpAndSettle();

        final menuBarFinder = find.byType(PlatformMenuBar);
        expect(menuBarFinder, findsOneWidget);

        final menuBar = tester.widget<PlatformMenuBar>(menuBarFinder);
        expect(
          menuBar.menus.map((m) => m.label).toList(),
          equals([AppConfig.appName, 'View', 'Window', 'Help']),
        );

        final appMenu = menuBar.menus[0] as PlatformMenu;
        final viewMenu = menuBar.menus[1] as PlatformMenu;
        final helpMenu = menuBar.menus[3] as PlatformMenu;

        // App -> About Encounter
        final aboutItem = _findMenuItem(appMenu, 'About ${AppConfig.appName}');
        expect(aboutItem.onSelected, isNotNull);
        aboutItem.onSelected!();
        await tester.pumpAndSettle();
        expect(find.byType(AboutView), findsOneWidget);

        // View -> Contacts
        final contactsItem = _findMenuItem(viewMenu, 'Contacts');
        expect(contactsItem.onSelected, isNotNull);
        contactsItem.onSelected!();
        await tester.pumpAndSettle();
        expect(find.byType(ContactsPlaceholderView), findsOneWidget);

        // View -> Appearance -> Dark
        final darkItem = _findMenuItem(viewMenu, 'Dark');
        expect(darkItem.onSelected, isNotNull);
        darkItem.onSelected!();
        await tester.pumpAndSettle();
        expect(themeController.value, equals(ThemeMode.dark));

        // Help -> View Source on GitHub
        final helpItem = _findMenuItem(helpMenu, 'View Source on GitHub');
        expect(helpItem.onSelected, isNotNull);
        helpItem.onSelected!();
        expect(linkLauncher.launchedUris, equals([AppConfig.repoUri]));
      },
    );

    testWidgets(
      'macOS disables navigation menu items when identity is corrupted while keeping Help and Appearance active',
      (WidgetTester tester) async {
        debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
        addTearDown(() {
          debugDefaultTargetPlatformOverride = null;
        });
        setViewport(tester, const Size(1280, 800));

        final storage = InMemorySnapshotStorageService();
        await storage.saveSnapshot(Uint8List.fromList([1, 2, 3, 4]));
        final controller = IdentityController(
          keyring: InMemoryKeyringService(),
          storage: storage,
        );
        addTearDown(controller.dispose);
        await controller.initialize();
        expect(controller.status, equals(IdentityStatus.corrupted));

        final themeController = ThemeController();
        addTearDown(themeController.dispose);

        await tester.pumpWidget(
          EncounterApp(
            controller: controller,
            themeController: themeController,
            linkLauncher: FakeLinkLauncher(),
          ),
        );
        await tester.pumpAndSettle();

        final menuBar = tester.widget<PlatformMenuBar>(
          find.byType(PlatformMenuBar),
        );
        final appMenu = menuBar.menus[0] as PlatformMenu;
        final viewMenu = menuBar.menus[1] as PlatformMenu;
        final helpMenu = menuBar.menus[3] as PlatformMenu;

        final aboutItem = _findMenuItem(appMenu, 'About ${AppConfig.appName}');
        expect(aboutItem.onSelected, isNull);

        for (final dest in AppDestination.values) {
          final item = _findMenuItem(viewMenu, dest.label);
          expect(item.onSelected, isNull);
        }

        expect(_findMenuItem(viewMenu, 'Dark').onSelected, isNotNull);
        expect(
          _findMenuItem(helpMenu, 'View Source on GitHub').onSelected,
          isNotNull,
        );
      },
    );

    testWidgets('non-macOS platform does not mount PlatformMenuBar', (
      WidgetTester tester,
    ) async {
      debugDefaultTargetPlatformOverride = TargetPlatform.android;
      addTearDown(() {
        debugDefaultTargetPlatformOverride = null;
      });
      setViewport(tester, const Size(390, 844));

      final controller = await createReadyController();
      await tester.pumpWidget(
        EncounterApp(
          controller: controller,
          linkLauncher: FakeLinkLauncher(),
          initialDestination: AppDestination.encounter,
        ),
      );
      await tester.pumpAndSettle();

      expect(find.byType(PlatformMenuBar), findsNothing);
    });
  });
}
