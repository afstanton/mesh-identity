import 'package:material_ui/material_ui.dart';

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
