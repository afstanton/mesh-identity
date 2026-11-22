import 'package:material_ui/material_ui.dart';

/// Top-level navigation destinations in the Encounter shell.
enum AppDestination {
  encounter,
  contacts,
  groups,
  identity,
  about;

  /// Human-readable navigation label.
  String get label => switch (this) {
    AppDestination.encounter => 'Encounter',
    AppDestination.contacts => 'Contacts',
    AppDestination.groups => 'Groups',
    AppDestination.identity => 'Identity',
    AppDestination.about => 'About',
  };

  /// Unselected destination icon.
  IconData get icon => switch (this) {
    AppDestination.encounter => Icons.qr_code_2_outlined,
    AppDestination.contacts => Icons.people_outline,
    AppDestination.groups => Icons.workspaces_outline,
    AppDestination.identity => Icons.badge_outlined,
    AppDestination.about => Icons.info_outline,
  };

  /// Selected destination icon.
  IconData get selectedIcon => switch (this) {
    AppDestination.encounter => Icons.qr_code_2,
    AppDestination.contacts => Icons.people,
    AppDestination.groups => Icons.workspaces,
    AppDestination.identity => Icons.badge,
    AppDestination.about => Icons.info,
  };
}
