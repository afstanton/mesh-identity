import 'package:material_ui/material_ui.dart';

import '../../../services/ble_encounter_codec.dart';
import '../../../services/ble_encounter_transport.dart';
import '../../../services/encounter_session.dart';

/// Compact BLE proximity & exchange panel rendered inside
/// [TwoDeviceEncounterScreen] during active payload-exchange phases.
class BleEncounterPanel extends StatelessWidget {
  final EncounterRole role;
  final BleEncounterTransport transport;
  final BleTransportStatus status;
  final List<BlePeerDiscovery> discoveredPeers;
  final VoidCallback onToggleBle;
  final VoidCallback? onRequestPermission;
  final ValueChanged<BlePeerDiscovery> onConnectPeer;

  const BleEncounterPanel({
    super.key,
    required this.role,
    required this.transport,
    required this.status,
    required this.discoveredPeers,
    required this.onToggleBle,
    this.onRequestPermission,
    required this.onConnectPeer,
  });

  static String _statusLabel(BleTransportStatus status) {
    return switch (status) {
      BleTransportStatus.idle => 'Ready for nearby BLE exchange',
      BleTransportStatus.unsupported => 'BLE unavailable on this platform',
      BleTransportStatus.permissionDenied => 'Bluetooth permission denied',
      BleTransportStatus.bluetoothOff => 'Bluetooth is turned off',
      BleTransportStatus.advertising => 'Advertising nearby to Responder...',
      BleTransportStatus.scanning => 'Scanning for nearby Initiator...',
      BleTransportStatus.connecting => 'Connecting to nearby peer...',
      BleTransportStatus.exchanging => 'Exchanging verification payloads...',
      BleTransportStatus.completed =>
        'BLE exchange complete — verify 6-digit SAS below',
      BleTransportStatus.error => 'BLE exchange error',
    };
  }

  static String _proximityLabel(BleProximityBand band) {
    return switch (band) {
      BleProximityBand.immediate => 'Immediate',
      BleProximityBand.near => 'Near',
      BleProximityBand.far => 'Far',
    };
  }

  bool get _isActive =>
      status == BleTransportStatus.advertising ||
      status == BleTransportStatus.scanning ||
      status == BleTransportStatus.connecting ||
      status == BleTransportStatus.exchanging;

  bool get _isBlocked =>
      status == BleTransportStatus.unsupported ||
      status == BleTransportStatus.permissionDenied ||
      status == BleTransportStatus.bluetoothOff;

  @override
  Widget build(BuildContext context) {
    final theme = Theme.of(context);
    final error = transport.errorMessage;
    return Card.outlined(
      key: const Key('ble_encounter_panel'),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Wrap(
              spacing: 8,
              runSpacing: 8,
              alignment: WrapAlignment.spaceBetween,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Icon(
                      _isActive
                          ? Icons.bluetooth_searching
                          : Icons.bluetooth_outlined,
                      size: 20,
                      color: _isBlocked
                          ? theme.colorScheme.onSurfaceVariant
                          : theme.colorScheme.primary,
                    ),
                    const SizedBox(width: 8),
                    Flexible(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Nearby BLE Transport',
                            style: theme.textTheme.titleSmall,
                          ),
                          Text(
                            _statusLabel(status),
                            key: const Key('ble_status_text'),
                            style: theme.textTheme.bodySmall?.copyWith(
                              color: theme.colorScheme.onSurfaceVariant,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
                if (status == BleTransportStatus.permissionDenied)
                  FilledButton.tonalIcon(
                    key: const Key('ble_grant_permission_button'),
                    onPressed: onRequestPermission,
                    icon: const Icon(Icons.lock_open_outlined, size: 18),
                    label: const Text('Grant Permission'),
                  )
                else
                  FilledButton.tonalIcon(
                    key: const Key('ble_toggle_button'),
                    onPressed:
                        status == BleTransportStatus.exchanging ||
                            status == BleTransportStatus.connecting ||
                            status == BleTransportStatus.unsupported
                        ? null
                        : onToggleBle,
                    icon: Icon(
                      _isActive
                          ? Icons.bluetooth_searching
                          : Icons.bluetooth_outlined,
                      size: 18,
                    ),
                    label: Text(
                      _isActive
                          ? 'Stop BLE'
                          : (role == EncounterRole.initiator
                                ? 'Advertise via BLE'
                                : 'Scan via BLE'),
                    ),
                  ),
              ],
            ),
            if (error != null) ...[
              const SizedBox(height: 8),
              Text(
                error,
                key: const Key('ble_error_text'),
                style: theme.textTheme.bodySmall?.copyWith(
                  color: _isBlocked
                      ? theme.colorScheme.onSurfaceVariant
                      : theme.colorScheme.error,
                ),
              ),
            ],
            if (role == EncounterRole.responder &&
                discoveredPeers.isNotEmpty) ...[
              const SizedBox(height: 10),
              ...discoveredPeers.map(
                (peer) => ListTile(
                  key: Key('ble_peer_${peer.id}'),
                  dense: true,
                  contentPadding: EdgeInsets.zero,
                  leading: const Icon(Icons.devices_outlined, size: 20),
                  title: Text(peer.name),
                  subtitle: Text(
                    'Proximity: ${_proximityLabel(peer.proximity)} (${peer.rssi} dBm)',
                  ),
                  trailing: FilledButton.tonal(
                    key: Key('ble_connect_${peer.id}'),
                    onPressed: status == BleTransportStatus.scanning
                        ? () => onConnectPeer(peer)
                        : null,
                    child: const Text('Connect'),
                  ),
                ),
              ),
            ],
            const SizedBox(height: 8),
            Text(
              'Proximity is an unverified radio cue, not authentication. '
              'BLE payloads broadcast locally like a visible QR; always verify the 6-digit SAS code.',
              key: const Key('ble_security_note'),
              style: theme.textTheme.bodySmall?.copyWith(
                color: theme.colorScheme.onSurfaceVariant,
              ),
            ),
          ],
        ),
      ),
    );
  }
}
