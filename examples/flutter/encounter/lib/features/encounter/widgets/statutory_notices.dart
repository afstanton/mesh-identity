import 'package:material_ui/material_ui.dart';
import 'package:mesh_identity/mesh_identity.dart';

import '../../../core/theme.dart';
import '../../../services/encounter_session.dart';

/// Verified contact card displaying peer key fingerprint, encounter metadata,
/// and all statutory safety disclaimers required by `mesh_identity`.
class VerifiedContactCard extends StatelessWidget {
  final Contact contact;
  final String title;
  final bool isPractice;
  final VoidCallback? onDone;

  const VerifiedContactCard({
    super.key,
    required this.contact,
    this.title = 'Contact Verified',
    this.isPractice = false,
    this.onDone,
  });

  static const List<String> _months = [
    'Jan',
    'Feb',
    'Mar',
    'Apr',
    'May',
    'Jun',
    'Jul',
    'Aug',
    'Sep',
    'Oct',
    'Nov',
    'Dec',
  ];

  static String _formatLocalTimestamp(DateTime dt) {
    final local = dt.toLocal();
    final month = _months[local.month - 1];
    final hour12 = local.hour % 12 == 0 ? 12 : local.hour % 12;
    final minute = local.minute.toString().padLeft(2, '0');
    final period = local.hour >= 12 ? 'PM' : 'AM';
    return '${local.day} $month ${local.year}, $hour12:$minute $period';
  }

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    final fullHex = formatHexKey(contact.peerPublicKey);
    final shortHex = shortHexKey(contact.peerPublicKey);
    final verifiedUtc = contact.verifiedAt.toUtc().toIso8601String();
    final verifiedLocal = _formatLocalTimestamp(contact.verifiedAt);

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(20),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Row(
              children: [
                Icon(Icons.verified, color: colorScheme.primary, size: 28),
                const SizedBox(width: 10),
                Expanded(
                  child: Text(
                    title,
                    style: Theme.of(context).textTheme.titleMedium,
                  ),
                ),
                Chip(
                  label: Text(isPractice ? 'Practice' : 'Verified Key'),
                  visualDensity: VisualDensity.compact,
                ),
              ],
            ),
            const SizedBox(height: 12),
            Text(
              'Peer Fingerprint',
              style: Theme.of(context).textTheme.labelMedium
                  ?.copyWith(color: colorScheme.onSurfaceVariant),
            ),
            const SizedBox(height: 4),
            Text(
              shortHex,
              style: AppTheme.monospaceStyle(context)
                  .copyWith(fontSize: 16, fontWeight: FontWeight.w600),
            ),
            const SizedBox(height: 4),
            SelectableText(
              fullHex,
              style: AppTheme.monospaceStyle(context)
                  .copyWith(fontSize: 12, color: colorScheme.onSurfaceVariant),
            ),
            const SizedBox(height: 12),
            Wrap(
              spacing: 12,
              runSpacing: 8,
              children: [
                Chip(
                  avatar: const Icon(Icons.repeat, size: 16),
                  label: Text('Encounters: ${contact.encounterCount}'),
                  visualDensity: VisualDensity.compact,
                ),
                Tooltip(
                  message: 'UTC: $verifiedUtc',
                  child: Chip(
                    avatar: const Icon(Icons.schedule, size: 16),
                    label: Text('Verified: $verifiedLocal'),
                    visualDensity: VisualDensity.compact,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            _NoticeTile(
              icon: Icons.security_outlined,
              label: 'Proximity Notice',
              body: EncounterUiText.proximityDisclaimer,
            ),
            const SizedBox(height: 8),
            _NoticeTile(
              icon: Icons.person_outline,
              label: 'Key vs. Identity Notice',
              body: EncounterUiText.notIdentityProof,
            ),
            const SizedBox(height: 8),
            _NoticeTile(
              icon: Icons.devices_outlined,
              label: 'Local Confirmation Notice',
              body: isPractice
                  ? '${EncounterUiText.localOnlyConfirmation} (Practice Mode: not persisted.)'
                  : EncounterUiText.localOnlyConfirmation,
            ),
            if (onDone != null) ...[
              const SizedBox(height: 16),
              Align(
                alignment: Alignment.centerRight,
                child: FilledButton(
                  onPressed: onDone,
                  child: const Text('Done'),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _NoticeTile extends StatelessWidget {
  final IconData icon;
  final String label;
  final String body;

  const _NoticeTile({
    required this.icon,
    required this.label,
    required this.body,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: colorScheme.outlineVariant),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, size: 18, color: colorScheme.onSurfaceVariant),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  label,
                  style: Theme.of(context).textTheme.labelMedium
                      ?.copyWith(fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 2),
                Text(body, style: Theme.of(context).textTheme.bodySmall),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

/// Warning card shown when `RateLimitedException` pauses new encounters.
class RateLimitBanner extends StatelessWidget {
  final Duration remaining;
  final bool showInterferenceWarning;

  const RateLimitBanner({
    super.key,
    required this.remaining,
    this.showInterferenceWarning = true,
  });

  @override
  Widget build(BuildContext context) {
    final colorScheme = Theme.of(context).colorScheme;
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: colorScheme.errorContainer,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: colorScheme.error.withValues(alpha: 0.4)),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(Icons.timer_outlined, color: colorScheme.onErrorContainer),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Encounters Temporarily Paused',
                  style: Theme.of(context).textTheme.titleSmall?.copyWith(
                    color: colorScheme.onErrorContainer,
                    fontWeight: FontWeight.w600,
                  ),
                ),
                if (showInterferenceWarning) ...[
                  const SizedBox(height: 4),
                  Text(
                    EncounterUiText.interferenceWarning,
                    style: Theme.of(context).textTheme.bodyMedium
                        ?.copyWith(color: colorScheme.onErrorContainer),
                  ),
                ],
                const SizedBox(height: 6),
                Text(
                  'Wait ${formatCountdown(remaining)} before trying again.',
                  style: AppTheme.monospaceStyle(context).copyWith(
                    color: colorScheme.onErrorContainer,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }
}
