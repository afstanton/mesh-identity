import 'dart:typed_data';

import 'package:material_ui/material_ui.dart';

import '../../core/theme.dart';
import '../../services/identity_controller.dart';

/// Placeholder view for contact management until Slice 4 lands.
class ContactsPlaceholderView extends StatelessWidget {
  final IdentityController controller;

  const ContactsPlaceholderView({super.key, required this.controller});

  @override
  Widget build(BuildContext context) {
    return _CenteredSliceCard(
      icon: Icons.people_outline,
      title: 'Contacts',
      badge: 'Planned for Slice 4',
      summary:
          'Active contacts currently recorded for this persona: '
          '${controller.contactsCount}.',
      details:
          'Verified SAS timestamps, peer key fingerprints, alias editing, '
          'and administrative blocking arrive in Slice 4.',
    );
  }
}

/// Placeholder view for Byzantine group admission until Slice 7 lands.
class GroupsPlaceholderView extends StatelessWidget {
  const GroupsPlaceholderView({super.key});

  @override
  Widget build(BuildContext context) {
    return const _CenteredSliceCard(
      icon: Icons.workspaces_outline,
      title: 'Groups',
      badge: 'Planned for Slice 7',
      summary: 'Byzantine group admission and quorum consensus governance.',
      details:
          'Group formation, authenticated genesis export/import, admission '
          'vouchers, and two-phase commit outbox release arrive in Slice 7.',
    );
  }
}

/// Read-only identity overview listing committed personas for this installation.
class IdentityOverviewView extends StatelessWidget {
  final IdentityController controller;

  const IdentityOverviewView({super.key, required this.controller});

  static String _shortHex(Uint8List bytes) {
    final hex = bytes
        .take(12)
        .map((b) => b.toRadixString(16).padLeft(2, '0'))
        .join();
    return '$hex...';
  }

  static bool _bytesEqual(Uint8List? a, Uint8List b) {
    if (a == null || a.length != b.length) return false;
    for (var i = 0; i < a.length; i++) {
      if (a[i] != b[i]) return false;
    }
    return true;
  }

  @override
  Widget build(BuildContext context) {
    final activeKey = controller.selectedIdentity;
    final keys = controller.identities;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 760),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Card(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Padding(
                      padding: const EdgeInsets.fromLTRB(16, 16, 16, 8),
                      child: Text(
                        'Committed Personas (${keys.length})',
                        style: Theme.of(context).textTheme.titleMedium,
                      ),
                    ),
                    for (var i = 0; i < keys.length; i++) ...[
                      if (i > 0) const Divider(height: 1),
                      ListTile(
                        leading: Icon(
                          _bytesEqual(activeKey, keys[i])
                              ? Icons.verified_user
                              : Icons.badge_outlined,
                          color: _bytesEqual(activeKey, keys[i])
                              ? Theme.of(context).colorScheme.primary
                              : null,
                        ),
                        title: Text(
                          _shortHex(keys[i]),
                          style: AppTheme.monospaceStyle(context),
                        ),
                        subtitle: Text(
                          _bytesEqual(activeKey, keys[i])
                              ? 'Active persona'
                              : 'Inactive persona',
                        ),
                      ),
                    ],
                  ],
                ),
              ),
              const SizedBox(height: 16),
              const Card(
                child: Padding(
                  padding: EdgeInsets.all(20),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Upcoming Identity Capabilities',
                        style: TextStyle(fontWeight: FontWeight.w600),
                      ),
                      SizedBox(height: 8),
                      Text(
                        '• Multi-persona creation, switching & removal: Slice 4\n'
                        '• Device-to-device handoff & voting role migration: Slice 6\n'
                        '• OpenPGP export previews & cross-certification: Slice 8',
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _CenteredSliceCard extends StatelessWidget {
  final IconData icon;
  final String title;
  final String badge;
  final String summary;
  final String details;

  const _CenteredSliceCard({
    required this.icon,
    required this.title,
    required this.badge,
    required this.summary,
    required this.details,
  });

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(20),
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 760),
          child: Card(
            child: Padding(
              padding: const EdgeInsets.all(24),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Wrap(
                    spacing: 12,
                    runSpacing: 8,
                    crossAxisAlignment: WrapCrossAlignment.center,
                    children: [
                      Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(
                            icon,
                            size: 32,
                            color: Theme.of(context).colorScheme.primary,
                          ),
                          const SizedBox(width: 12),
                          Flexible(
                            child: Text(
                              title,
                              style: Theme.of(context).textTheme.headlineSmall,
                            ),
                          ),
                        ],
                      ),
                      Chip(
                        label: Text(badge),
                        visualDensity: VisualDensity.compact,
                      ),
                    ],
                  ),
                  const SizedBox(height: 16),
                  Text(summary, style: Theme.of(context).textTheme.bodyLarge),
                  const SizedBox(height: 8),
                  Text(
                    details,
                    style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                      color: Theme.of(context).colorScheme.onSurfaceVariant,
                    ),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
