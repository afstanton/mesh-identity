import 'dart:async';
import 'dart:io';

import 'package:bluetooth_low_energy/bluetooth_low_energy.dart';
import 'package:flutter/foundation.dart';

import 'ble_encounter_codec.dart';

/// Lifecycle status of the offline BLE Encounter transport.
enum BleTransportStatus {
  idle,
  unsupported,
  permissionDenied,
  bluetoothOff,
  advertising,
  scanning,
  connecting,
  exchanging,
  completed,
  error,
}

/// Discovered nearby BLE Encounter peer with coarse RSSI proximity.
class BlePeerDiscovery {
  final String id;
  final String name;
  final int rssi;
  final BleProximityBand proximity;
  final DateTime discoveredAt;

  const BlePeerDiscovery({
    required this.id,
    required this.name,
    required this.rssi,
    required this.proximity,
    required this.discoveredAt,
  });
}

/// Platform-agnostic BLE transport contract for offline Encounter ceremonies
/// (`Offer -> Response -> Reveal`, each `<= 512` bytes).
abstract interface class BleEncounterTransport {
  bool get isCentralSupported;
  bool get isPeripheralSupported;
  BleTransportStatus get status;
  String? get errorMessage;

  Stream<BleTransportStatus> get statusStream;
  Stream<List<BlePeerDiscovery>> get discoveredPeersStream;

  Future<void> probeAvailability();

  Future<void> startInitiatorPeripheral({
    required Uint8List offerBytes,
    required Future<Uint8List> Function(Uint8List responseBytes)
    onResponseReceived,
  });

  Future<void> startResponderScan();

  Future<void> connectAndExchangeAsResponder({
    required String peerId,
    required Future<Uint8List> Function(Uint8List offerBytes) onOfferReceived,
    required Future<void> Function(Uint8List revealBytes) onRevealReceived,
  });

  Future<void> stop();
  void dispose();
}

/// Production [BleEncounterTransport] backed by `bluetooth_low_energy`.
class BluetoothLowEnergyTransport implements BleEncounterTransport {
  CentralManager? _central;
  PeripheralManager? _peripheral;

  final StreamController<BleTransportStatus> _statusController =
      StreamController<BleTransportStatus>.broadcast();
  final StreamController<List<BlePeerDiscovery>> _peersController =
      StreamController<List<BlePeerDiscovery>>.broadcast();

  final Map<String, Peripheral> _peripheralsById = {};
  final Map<String, BlePeerDiscovery> _peersById = {};
  final List<StreamSubscription<dynamic>> _subs = [];

  BleTransportStatus _status = BleTransportStatus.idle;
  String? _errorMessage;
  bool _isDisposed = false;
  bool _isAdvertising = false;
  bool _isScanning = false;
  int _operationEpoch = 0;
  Timer? _boundIdleTimer;
  Peripheral? _activeResponderPeripheral;
  VoidCallback? _cancelActiveResponder;

  Future<void> _teardownPeripheral() async {
    _boundIdleTimer?.cancel();
    _boundIdleTimer = null;
    final pm = _peripheral;
    if (pm == null) {
      _isAdvertising = false;
      return;
    }
    if (_isAdvertising) {
      try {
        await pm.stopAdvertising();
      } catch (_) {}
    }
    try {
      await pm.removeAllServices();
    } catch (_) {}
    _isAdvertising = false;
  }

  @override
  bool get isCentralSupported =>
      !kIsWeb &&
      (Platform.isAndroid ||
          Platform.isIOS ||
          Platform.isMacOS ||
          Platform.isLinux ||
          Platform.isWindows);

  @override
  bool get isPeripheralSupported =>
      !kIsWeb &&
      (Platform.isAndroid ||
          Platform.isIOS ||
          Platform.isMacOS ||
          Platform.isWindows);

  @override
  BleTransportStatus get status => _status;

  @override
  String? get errorMessage => _errorMessage;

  @override
  Stream<BleTransportStatus> get statusStream => _statusController.stream;

  @override
  Stream<List<BlePeerDiscovery>> get discoveredPeersStream =>
      _peersController.stream;

  void _setStatus(BleTransportStatus next, [String? error]) {
    if (_isDisposed) return;
    _status = next;
    _errorMessage = error;
    if (!_statusController.isClosed) {
      _statusController.add(next);
    }
  }

  Future<bool> _ensureReadyState(BluetoothLowEnergyManager manager) async {
    var state = manager.state;
    if (state == BluetoothLowEnergyState.unauthorized && Platform.isAndroid) {
      final granted = await manager.authorize();
      if (!granted) {
        _setStatus(
          BleTransportStatus.permissionDenied,
          'Bluetooth permission is required for nearby BLE exchange.',
        );
        return false;
      }
      state = manager.state;
    }

    switch (state) {
      case BluetoothLowEnergyState.poweredOn:
        return true;
      case BluetoothLowEnergyState.poweredOff:
        _setStatus(
          BleTransportStatus.bluetoothOff,
          'Turn on Bluetooth to exchange Encounter payloads nearby.',
        );
        return false;
      case BluetoothLowEnergyState.unauthorized:
        _setStatus(
          BleTransportStatus.permissionDenied,
          'Bluetooth permission was denied. Enable it in system settings.',
        );
        return false;
      case BluetoothLowEnergyState.unsupported:
        _setStatus(
          BleTransportStatus.unsupported,
          'Bluetooth Low Energy is not supported on this device.',
        );
        return false;
      case BluetoothLowEnergyState.unknown:
        // Wait briefly for initial state broadcast on Apple/Linux stacks.
        try {
          final updated = await manager.stateChanged
              .map((e) => e.state)
              .firstWhere((s) => s != BluetoothLowEnergyState.unknown)
              .timeout(const Duration(seconds: 2));
          if (updated == BluetoothLowEnergyState.poweredOn) return true;
        } catch (_) {
          // Fall through to poweredOff/error notice.
        }
        _setStatus(
          BleTransportStatus.bluetoothOff,
          'Bluetooth adapter is not ready. Ensure Bluetooth is turned on.',
        );
        return false;
    }
  }

  @override
  Future<void> probeAvailability() async {
    if (_isDisposed) return;
    if (!isCentralSupported && !isPeripheralSupported) {
      _setStatus(
        BleTransportStatus.unsupported,
        'Bluetooth Low Energy is not supported on this platform.',
      );
      return;
    }
    try {
      final cm = _central ??= CentralManager();
      var state = cm.state;
      if (state == BluetoothLowEnergyState.unknown) {
        try {
          state = await cm.stateChanged
              .map((e) => e.state)
              .firstWhere((s) => s != BluetoothLowEnergyState.unknown)
              .timeout(const Duration(milliseconds: 1500));
        } catch (_) {
          // Keep current state if adapter does not broadcast within 1.5s.
        }
      }
      if (_isDisposed) return;
      if (state == BluetoothLowEnergyState.unsupported) {
        _setStatus(
          BleTransportStatus.unsupported,
          'Bluetooth Low Energy is not supported on this device.',
        );
      } else if (state == BluetoothLowEnergyState.poweredOff) {
        _setStatus(
          BleTransportStatus.bluetoothOff,
          'Turn on Bluetooth to exchange Encounter payloads nearby.',
        );
      } else if (state == BluetoothLowEnergyState.unauthorized) {
        _setStatus(
          BleTransportStatus.permissionDenied,
          'Bluetooth permission is required for nearby BLE exchange.',
        );
      }
    } catch (_) {
      _setStatus(
        BleTransportStatus.unsupported,
        'Bluetooth Low Energy is unavailable on this device.',
      );
    }
  }

  @override
  Future<void> startInitiatorPeripheral({
    required Uint8List offerBytes,
    required Future<Uint8List> Function(Uint8List responseBytes)
    onResponseReceived,
  }) async {
    if (_isDisposed) return;
    if (!isPeripheralSupported) {
      _setStatus(
        BleTransportStatus.unsupported,
        'BLE peripheral advertising is not supported on this platform. '
        'Use QR or Join Encounter (Central) instead.',
      );
      return;
    }

    await stop();
    final epoch = _operationEpoch;
    final pm = _peripheral ??= PeripheralManager();
    if (!await _ensureReadyState(pm)) return;
    if (_isDisposed || epoch != _operationEpoch) return;

    final serviceUuid = UUID.fromString(bleEncounterServiceUuid);
    final offerUuid = UUID.fromString(bleOfferCharUuid);
    final responseUuid = UUID.fromString(bleResponseCharUuid);
    final revealUuid = UUID.fromString(bleRevealCharUuid);

    final offerChar = GATTCharacteristic.mutable(
      uuid: offerUuid,
      properties: [GATTCharacteristicProperty.notify],
      permissions: [GATTCharacteristicPermission.read],
      descriptors: const [],
    );
    final responseChar = GATTCharacteristic.mutable(
      uuid: responseUuid,
      properties: [GATTCharacteristicProperty.write],
      permissions: [GATTCharacteristicPermission.write],
      descriptors: const [],
    );
    final revealChar = GATTCharacteristic.mutable(
      uuid: revealUuid,
      properties: [GATTCharacteristicProperty.notify],
      permissions: [GATTCharacteristicPermission.read],
      descriptors: const [],
    );

    final service = GATTService(
      uuid: serviceUuid,
      isPrimary: true,
      includedServices: const [],
      characteristics: [offerChar, responseChar, revealChar],
    );

    final responseReassembler = BleChunkReassembler();
    final offerChunks = encodeBleChunks(offerBytes);
    Central? boundCentral;
    var exchangeFinished = false;

    void resetBoundIdleTimer() {
      _boundIdleTimer?.cancel();
      _boundIdleTimer = Timer(const Duration(seconds: 20), () {
        if (_isDisposed || epoch != _operationEpoch || exchangeFinished) {
          return;
        }
        boundCentral = null;
        responseReassembler.reset();
        _setStatus(BleTransportStatus.advertising);
      });
    }

    _subs.add(
      pm.characteristicNotifyStateChanged.listen((event) async {
        if (_isDisposed ||
            epoch != _operationEpoch ||
            exchangeFinished ||
            !event.state) {
          return;
        }
        if (boundCentral != null && event.central.uuid != boundCentral!.uuid) {
          return;
        }
        boundCentral ??= event.central;
        resetBoundIdleTimer();
        if (event.characteristic.uuid == offerUuid) {
          _setStatus(BleTransportStatus.exchanging);
          try {
            final maxLen = await pm.getMaximumNotifyLength(event.central);
            final chunks = maxLen >= 184
                ? offerChunks
                : encodeBleChunks(
                    offerBytes,
                    maxChunkPayloadBytes: (maxLen - bleChunkHeaderBytes).clamp(
                      16,
                      180,
                    ),
                  );
            for (final chunk in chunks) {
              if (_isDisposed || epoch != _operationEpoch || exchangeFinished) {
                return;
              }
              await pm.notifyCharacteristic(
                event.central,
                offerChar,
                value: chunk,
              );
            }
          } catch (e) {
            exchangeFinished = true;
            _setStatus(
              BleTransportStatus.error,
              'Failed sending BLE Offer: $e',
            );
            await _teardownPeripheral();
          }
        }
      }),
    );

    _subs.add(
      pm.characteristicWriteRequested.listen((event) async {
        if (_isDisposed ||
            epoch != _operationEpoch ||
            event.characteristic.uuid != responseUuid) {
          return;
        }
        if (exchangeFinished ||
            (boundCentral != null &&
                event.central.uuid != boundCentral!.uuid)) {
          try {
            await pm.respondWriteRequestWithError(
              event.request,
              error: GATTError.writeNotPermitted,
            );
          } catch (_) {}
          return;
        }
        boundCentral ??= event.central;
        resetBoundIdleTimer();
        try {
          final assembled = responseReassembler.addChunk(event.request.value);
          await pm.respondWriteRequest(event.request);
          if (assembled == null) return;

          _setStatus(BleTransportStatus.exchanging);
          final revealBytes = await onResponseReceived(assembled);
          if (_isDisposed || epoch != _operationEpoch) return;
          final central = boundCentral!;
          final maxLen = await pm.getMaximumNotifyLength(central);
          final revealChunks = encodeBleChunks(
            revealBytes,
            maxChunkPayloadBytes: (maxLen - bleChunkHeaderBytes).clamp(16, 180),
          );
          for (final chunk in revealChunks) {
            if (_isDisposed || epoch != _operationEpoch) return;
            await pm.notifyCharacteristic(central, revealChar, value: chunk);
          }
          exchangeFinished = true;
          _boundIdleTimer?.cancel();
          _boundIdleTimer = null;
          _setStatus(BleTransportStatus.completed);
          await _teardownPeripheral();
        } catch (e) {
          exchangeFinished = true;
          _boundIdleTimer?.cancel();
          _boundIdleTimer = null;
          try {
            await pm.respondWriteRequestWithError(
              event.request,
              error: GATTError.invalidPDU,
            );
          } catch (_) {
            // Ignore secondary error response failure.
          }
          _setStatus(
            BleTransportStatus.error,
            'BLE Response exchange failed: $e',
          );
          await _teardownPeripheral();
        }
      }),
    );

    try {
      await pm.removeAllServices();
      if (_isDisposed || epoch != _operationEpoch) return;
      await pm.addService(service);
      if (_isDisposed || epoch != _operationEpoch) {
        await _teardownPeripheral();
        return;
      }
      await pm.startAdvertising(
        Advertisement(
          // Windows WinRT PeripheralManager does not support advertising a local name.
          name: Platform.isWindows ? null : 'MeshEncounter',
          serviceUUIDs: [serviceUuid],
        ),
      );
      _isAdvertising = true;
      if (_isDisposed || epoch != _operationEpoch) {
        await _teardownPeripheral();
        return;
      }
      _setStatus(BleTransportStatus.advertising);
    } catch (e) {
      await _teardownPeripheral();
      if (_isDisposed || epoch != _operationEpoch) return;
      _setStatus(
        BleTransportStatus.error,
        'Failed to start BLE advertising: $e',
      );
    }
  }

  @override
  Future<void> startResponderScan() async {
    if (_isDisposed) return;
    if (!isCentralSupported) {
      _setStatus(
        BleTransportStatus.unsupported,
        'BLE scanning is not supported on this platform.',
      );
      return;
    }

    await stop();
    final epoch = _operationEpoch;
    final cm = _central ??= CentralManager();
    if (!await _ensureReadyState(cm)) return;
    if (_isDisposed || epoch != _operationEpoch) return;

    final serviceUuid = UUID.fromString(bleEncounterServiceUuid);
    _subs.add(
      cm.discovered.listen((args) {
        if (_isDisposed) return;
        final id = args.peripheral.uuid.toString();
        final name = args.advertisement.name?.trim().isNotEmpty == true
            ? args.advertisement.name!.trim()
            : 'Nearby Peer';
        _peripheralsById[id] = args.peripheral;
        _peersById[id] = BlePeerDiscovery(
          id: id,
          name: name,
          rssi: args.rssi,
          proximity: classifyBleProximity(args.rssi),
          discoveredAt: DateTime.now(),
        );
        if (!_peersController.isClosed) {
          final sorted = _peersById.values.toList()
            ..sort((a, b) => b.rssi.compareTo(a.rssi));
          _peersController.add(List.unmodifiable(sorted));
        }
      }),
    );

    try {
      await cm.startDiscovery(serviceUUIDs: [serviceUuid]);
      _isScanning = true;
      if (_isDisposed || epoch != _operationEpoch) {
        try {
          await cm.stopDiscovery();
        } catch (_) {}
        _isScanning = false;
        return;
      }
      _setStatus(BleTransportStatus.scanning);
    } catch (e) {
      if (_isDisposed || epoch != _operationEpoch) return;
      _setStatus(BleTransportStatus.error, 'Failed to start BLE scan: $e');
    }
  }

  @override
  Future<void> connectAndExchangeAsResponder({
    required String peerId,
    required Future<Uint8List> Function(Uint8List offerBytes) onOfferReceived,
    required Future<void> Function(Uint8List revealBytes) onRevealReceived,
  }) async {
    if (_isDisposed) return;
    final epoch = _operationEpoch;
    final cm = _central;
    final peripheral = _peripheralsById[peerId];
    if (cm == null || peripheral == null) {
      _setStatus(BleTransportStatus.error, 'Selected BLE peer is unavailable.');
      return;
    }

    if (_isScanning) {
      try {
        await cm.stopDiscovery();
      } catch (_) {}
      _isScanning = false;
    }
    if (_isDisposed || epoch != _operationEpoch) return;

    _setStatus(BleTransportStatus.connecting);
    final serviceUuid = UUID.fromString(bleEncounterServiceUuid);
    final offerUuid = UUID.fromString(bleOfferCharUuid);
    final responseUuid = UUID.fromString(bleResponseCharUuid);
    final revealUuid = UUID.fromString(bleRevealCharUuid);

    final offerReassembler = BleChunkReassembler();
    final revealReassembler = BleChunkReassembler();
    final offerCompleter = Completer<Uint8List>();
    final revealCompleter = Completer<Uint8List>();
    // Prevent unhandled async error if revealCompleter errors before await.
    unawaited(offerCompleter.future.then<void>((_) {}, onError: (_) {}));
    unawaited(revealCompleter.future.then<void>((_) {}, onError: (_) {}));

    final notifySub = cm.characteristicNotified.listen(
      (event) {
        if (event.peripheral.uuid != peripheral.uuid) return;
        if (event.characteristic.uuid == offerUuid) {
          if (offerCompleter.isCompleted) return;
          try {
            final assembled = offerReassembler.addChunk(event.value);
            if (assembled != null) offerCompleter.complete(assembled);
          } catch (e) {
            if (!offerCompleter.isCompleted) offerCompleter.completeError(e);
          }
        } else if (event.characteristic.uuid == revealUuid) {
          if (revealCompleter.isCompleted) return;
          try {
            final assembled = revealReassembler.addChunk(event.value);
            if (assembled != null) revealCompleter.complete(assembled);
          } catch (e) {
            if (!revealCompleter.isCompleted) revealCompleter.completeError(e);
          }
        }
      },
      onError: (Object error, StackTrace stack) {
        if (!offerCompleter.isCompleted) {
          offerCompleter.completeError(error, stack);
        }
        if (!revealCompleter.isCompleted) {
          revealCompleter.completeError(error, stack);
        }
      },
    );

    _activeResponderPeripheral = peripheral;
    _cancelActiveResponder = () {
      unawaited(notifySub.cancel());
      final cancelError = StateError('BLE exchange cancelled.');
      if (!offerCompleter.isCompleted) {
        offerCompleter.completeError(cancelError);
      }
      if (!revealCompleter.isCompleted) {
        revealCompleter.completeError(cancelError);
      }
    };

    try {
      await cm.connect(peripheral);
      if (_isDisposed || epoch != _operationEpoch) return;
      if (Platform.isAndroid) {
        try {
          await cm.requestMTU(peripheral, mtu: 247);
        } catch (_) {
          // Proceed with default ATT MTU if negotiation fails.
        }
        if (_isDisposed || epoch != _operationEpoch) return;
      }

      final services = await cm.discoverGATT(peripheral);
      if (_isDisposed || epoch != _operationEpoch) return;
      final encService = services.firstWhere((s) => s.uuid == serviceUuid);
      final offerChar = encService.characteristics.firstWhere(
        (c) => c.uuid == offerUuid,
      );
      final responseChar = encService.characteristics.firstWhere(
        (c) => c.uuid == responseUuid,
      );
      final revealChar = encService.characteristics.firstWhere(
        (c) => c.uuid == revealUuid,
      );

      _setStatus(BleTransportStatus.exchanging);
      await cm.setCharacteristicNotifyState(
        peripheral,
        revealChar,
        state: true,
      );
      if (_isDisposed || epoch != _operationEpoch) return;
      await cm.setCharacteristicNotifyState(peripheral, offerChar, state: true);
      if (_isDisposed || epoch != _operationEpoch) return;

      final offerBytes = await offerCompleter.future.timeout(
        const Duration(seconds: 20),
      );
      if (_isDisposed || epoch != _operationEpoch) return;
      final responseBytes = await onOfferReceived(offerBytes);
      if (_isDisposed || epoch != _operationEpoch) return;

      final maxWrite = await cm.getMaximumWriteLength(
        peripheral,
        type: GATTCharacteristicWriteType.withResponse,
      );
      if (_isDisposed || epoch != _operationEpoch) return;
      final responseChunks = encodeBleChunks(
        responseBytes,
        maxChunkPayloadBytes: (maxWrite - bleChunkHeaderBytes).clamp(16, 180),
      );
      for (final chunk in responseChunks) {
        if (_isDisposed || epoch != _operationEpoch) return;
        await cm.writeCharacteristic(
          peripheral,
          responseChar,
          value: chunk,
          type: GATTCharacteristicWriteType.withResponse,
        );
      }

      final revealBytes = await revealCompleter.future.timeout(
        const Duration(seconds: 20),
      );
      if (_isDisposed || epoch != _operationEpoch) return;
      await onRevealReceived(revealBytes);
      if (_isDisposed || epoch != _operationEpoch) return;
      _setStatus(BleTransportStatus.completed);
    } catch (e) {
      if (_isDisposed || epoch != _operationEpoch) return;
      _setStatus(BleTransportStatus.error, 'BLE exchange failed: $e');
    } finally {
      if (_activeResponderPeripheral == peripheral) {
        _activeResponderPeripheral = null;
        _cancelActiveResponder = null;
      }
      await notifySub.cancel();
      try {
        await cm.disconnect(peripheral);
      } catch (_) {
        // Best-effort disconnect.
      }
    }
  }

  @override
  Future<void> stop() async {
    _operationEpoch++;
    _boundIdleTimer?.cancel();
    _boundIdleTimer = null;
    _cancelActiveResponder?.call();
    _cancelActiveResponder = null;
    final activePeripheral = _activeResponderPeripheral;
    _activeResponderPeripheral = null;
    if (activePeripheral != null && _central != null) {
      try {
        await _central!.disconnect(activePeripheral);
      } catch (_) {}
    }
    for (final sub in _subs) {
      await sub.cancel();
    }
    _subs.clear();
    _peripheralsById.clear();
    _peersById.clear();
    if (!_peersController.isClosed) {
      _peersController.add(const []);
    }

    if (_isScanning && _central != null) {
      try {
        await _central!.stopDiscovery();
      } catch (_) {}
      _isScanning = false;
    }
    await _teardownPeripheral();

    if (!_isDisposed) {
      _setStatus(BleTransportStatus.idle);
    }
  }

  @override
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;
    unawaited(stop());
    _statusController.close();
    _peersController.close();
  }
}

/// Shared in-memory radio channel connecting an Initiator and Responder
/// [InMemoryBleEncounterTransport] for deterministic tests.
class InMemoryBleChannel {
  final String peerId;
  final String peerName;
  final int rssi;

  Uint8List? _offerBytes;
  Future<Uint8List> Function(Uint8List responseBytes)? _onResponseReceived;
  bool _advertising = false;

  InMemoryBleChannel({
    this.peerId = 'ble-peer-1',
    this.peerName = 'Nearby Mesh Peer',
    this.rssi = -48,
  });

  InMemoryBleEncounterTransport createInitiatorTransport({
    BleTransportStatus? forcedErrorStatus,
    String? forcedErrorMessage,
  }) => InMemoryBleEncounterTransport._(
    this,
    forcedErrorStatus: forcedErrorStatus,
    forcedErrorMessage: forcedErrorMessage,
  );

  InMemoryBleEncounterTransport createResponderTransport({
    BleTransportStatus? forcedErrorStatus,
    String? forcedErrorMessage,
  }) => InMemoryBleEncounterTransport._(
    this,
    forcedErrorStatus: forcedErrorStatus,
    forcedErrorMessage: forcedErrorMessage,
  );
}

/// Deterministic in-memory [BleEncounterTransport] exercising chunking &
/// reassembly via [InMemoryBleChannel].
class InMemoryBleEncounterTransport implements BleEncounterTransport {
  final InMemoryBleChannel _channel;
  final BleTransportStatus? _forcedErrorStatus;
  final String? _forcedErrorMessage;

  final StreamController<BleTransportStatus> _statusController =
      StreamController<BleTransportStatus>.broadcast();
  final StreamController<List<BlePeerDiscovery>> _peersController =
      StreamController<List<BlePeerDiscovery>>.broadcast();

  BleTransportStatus _status = BleTransportStatus.idle;
  String? _errorMessage;
  bool _isDisposed = false;
  int _operationEpoch = 0;

  InMemoryBleEncounterTransport._(
    this._channel, {
    BleTransportStatus? forcedErrorStatus,
    String? forcedErrorMessage,
  }) : _forcedErrorStatus = forcedErrorStatus,
       _forcedErrorMessage = forcedErrorMessage {
    if (forcedErrorStatus != null) {
      _status = forcedErrorStatus;
      _errorMessage = forcedErrorMessage;
    }
  }

  @override
  bool get isCentralSupported =>
      _forcedErrorStatus != BleTransportStatus.unsupported;

  @override
  bool get isPeripheralSupported =>
      _forcedErrorStatus != BleTransportStatus.unsupported;

  @override
  BleTransportStatus get status => _status;

  @override
  String? get errorMessage => _errorMessage;

  @override
  Stream<BleTransportStatus> get statusStream => _statusController.stream;

  @override
  Stream<List<BlePeerDiscovery>> get discoveredPeersStream =>
      _peersController.stream;

  void _setStatus(BleTransportStatus next, [String? error]) {
    if (_isDisposed) return;
    _status = next;
    _errorMessage = error;
    if (!_statusController.isClosed) {
      _statusController.add(next);
    }
  }

  @override
  Future<void> probeAvailability() async {}

  @override
  Future<void> startInitiatorPeripheral({
    required Uint8List offerBytes,
    required Future<Uint8List> Function(Uint8List responseBytes)
    onResponseReceived,
  }) async {
    if (_forcedErrorStatus != null) {
      _setStatus(_forcedErrorStatus, _forcedErrorMessage);
      return;
    }
    final epoch = _operationEpoch;
    _channel._offerBytes = Uint8List.fromList(offerBytes);
    _channel._onResponseReceived = (responseBytes) async {
      if (_isDisposed || epoch != _operationEpoch) {
        throw StateError('Initiator BLE transport stopped.');
      }
      _setStatus(BleTransportStatus.exchanging);
      final revealBytes = await onResponseReceived(responseBytes);
      if (_isDisposed || epoch != _operationEpoch) {
        throw StateError('Initiator BLE transport stopped before Reveal.');
      }
      _channel._advertising = false;
      _setStatus(BleTransportStatus.completed);
      return revealBytes;
    };
    _channel._advertising = true;
    _setStatus(BleTransportStatus.advertising);
  }

  @override
  Future<void> startResponderScan() async {
    if (_forcedErrorStatus != null) {
      _setStatus(_forcedErrorStatus, _forcedErrorMessage);
      return;
    }
    _setStatus(BleTransportStatus.scanning);
    if (_channel._advertising && !_peersController.isClosed) {
      _peersController.add([
        BlePeerDiscovery(
          id: _channel.peerId,
          name: _channel.peerName,
          rssi: _channel.rssi,
          proximity: classifyBleProximity(_channel.rssi),
          discoveredAt: DateTime.now(),
        ),
      ]);
    }
  }

  @override
  Future<void> connectAndExchangeAsResponder({
    required String peerId,
    required Future<Uint8List> Function(Uint8List offerBytes) onOfferReceived,
    required Future<void> Function(Uint8List revealBytes) onRevealReceived,
  }) async {
    if (_forcedErrorStatus != null) {
      _setStatus(_forcedErrorStatus, _forcedErrorMessage);
      return;
    }
    if (!_channel._advertising ||
        _channel._offerBytes == null ||
        _channel._onResponseReceived == null ||
        peerId != _channel.peerId) {
      _setStatus(BleTransportStatus.error, 'BLE peer not advertising.');
      return;
    }

    final epoch = _operationEpoch;
    _setStatus(BleTransportStatus.connecting);
    _setStatus(BleTransportStatus.exchanging);

    Uint8List reassembleAll(Uint8List raw, int mtu) {
      final reassembler = BleChunkReassembler();
      Uint8List? out;
      for (final chunk in encodeBleChunks(raw, maxChunkPayloadBytes: mtu)) {
        out = reassembler.addChunk(chunk);
      }
      return out!;
    }

    try {
      final offer = reassembleAll(_channel._offerBytes!, 20);
      final response = await onOfferReceived(offer);
      if (_isDisposed || epoch != _operationEpoch) return;
      final responseReassembled = reassembleAll(response, 20);
      final reveal = await _channel._onResponseReceived!(responseReassembled);
      if (_isDisposed || epoch != _operationEpoch) return;
      final revealReassembled = reassembleAll(reveal, 20);
      await onRevealReceived(revealReassembled);
      if (_isDisposed || epoch != _operationEpoch) return;
      _setStatus(BleTransportStatus.completed);
    } catch (e) {
      if (_isDisposed || epoch != _operationEpoch) return;
      _setStatus(BleTransportStatus.error, 'BLE exchange failed: $e');
    }
  }

  @override
  Future<void> stop() async {
    _operationEpoch++;
    _channel._advertising = false;
    if (!_peersController.isClosed) {
      _peersController.add(const []);
    }
    if (!_isDisposed && _forcedErrorStatus == null) {
      _setStatus(BleTransportStatus.idle);
    }
  }

  @override
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;
    _statusController.close();
    _peersController.close();
  }
}
