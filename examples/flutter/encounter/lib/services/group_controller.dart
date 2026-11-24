import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:mesh_identity/mesh_identity.dart';

import 'group_frame_codec.dart';
import 'group_outbox.dart';
import 'identity_controller.dart';

/// Lifecycle status of the Byzantine group governance controller.
enum GroupControllerStatus { uninitialized, initializing, ready, error }

/// Controller coordinating Byzantine group governance on the single
/// authoritative [MeshGroupHandle] owned by [IdentityController], plus durable
/// [GroupOutboxService] persistence and post-commit recovery.
class GroupController extends ChangeNotifier {
  final IdentityController identityController;
  final GroupOutboxService _outbox;
  final DateTime Function() _clock;

  GroupControllerStatus _status = GroupControllerStatus.uninitialized;
  String? _errorMessage;
  String? _outboxError;

  List<GroupView> _cachedGroups = const [];
  List<PendingInvitation> _cachedPendingInvitations = const [];
  final List<StoredOutgoingMessage> _outgoingMessages = [];
  final List<GroupEvent> _recentEvents = [];
  final List<BigInt> _recentOpIds = [];

  Future<void> _queue = Future<void>.value();
  bool _isDisposed = false;
  int _lastNowMs = 0;
  int _unsavedSeq = 0;

  GroupController({
    required this.identityController,
    GroupOutboxService? outbox,
    DateTime Function()? clock,
  }) : _outbox = outbox ?? FileGroupOutboxService(),
       _clock = clock ?? DateTime.now {
    identityController.addListener(_onIdentityChanged);
    identityController.setBeforePersistHook(_flushUnsavedOutgoingForPersist);
  }

  GroupControllerStatus get status => _status;
  bool get isReady =>
      _status == GroupControllerStatus.ready && identityController.isReady;
  bool get isDisposed => _isDisposed;
  String? get errorMessage => _errorMessage;
  String? get outboxError => _outboxError;
  bool get hasUnsavedOutgoing => _outgoingMessages.any((m) => !m.isPersisted);

  List<GroupView> get groups => List.unmodifiable(_cachedGroups);
  List<PendingInvitation> get pendingInvitations =>
      List.unmodifiable(_cachedPendingInvitations);
  List<StoredOutgoingMessage> get outgoingMessages =>
      List.unmodifiable(_outgoingMessages);
  List<GroupEvent> get recentEvents => List.unmodifiable(_recentEvents);
  List<BigInt> get recentOpIds => List.unmodifiable(_recentOpIds);

  DateTime _now() {
    final raw = _clock().millisecondsSinceEpoch;
    final clamped = raw < _lastNowMs ? _lastNowMs : raw;
    _lastNowMs = clamped;
    return DateTime.fromMillisecondsSinceEpoch(clamped);
  }

  Future<T> _serialized<T>(Future<T> Function() action) {
    final completer = Completer<T>();
    _queue = _queue.then((_) async {
      try {
        final result = await action();
        completer.complete(result);
      } catch (e, st) {
        completer.completeError(e, st);
      }
    });
    return completer.future;
  }

  void _notifySafely() {
    if (!_isDisposed) {
      notifyListeners();
    }
  }

  void _onIdentityChanged() {
    if (_isDisposed) return;
    _syncCachedView();
    _notifySafely();
  }

  void _requireReady() {
    if (_isDisposed) {
      throw StateError('GroupController has been disposed');
    }
    if (!isReady) {
      throw StateError('GroupController is not ready (status: $_status)');
    }
  }

  void _syncCachedView() {
    if (_isDisposed || !identityController.isReady) {
      _cachedGroups = const [];
      _cachedPendingInvitations = const [];
      return;
    }
    try {
      identityController.readGroupState((h) {
        final ids = h.getGroupIds()..sort((a, b) => a.compareTo(b));
        final views = <GroupView>[];
        for (final id in ids) {
          final view = h.getGroup(id);
          if (view != null) views.add(view);
        }
        _cachedGroups = views;
        _cachedPendingInvitations = h.getPendingInvitations();
      });
    } catch (_) {
      _cachedGroups = const [];
      _cachedPendingInvitations = const [];
    }
  }

  void _recordEvents(List<GroupEvent> events) {
    if (events.isEmpty) return;
    _recentEvents.insertAll(0, events.reversed);
    const maxEvents = 50;
    if (_recentEvents.length > maxEvents) {
      _recentEvents.removeRange(maxEvents, _recentEvents.length);
    }
  }

  void _recordOpId(BigInt opId) {
    _recentOpIds.remove(opId);
    _recentOpIds.insert(0, opId);
    const maxOps = 10;
    if (_recentOpIds.length > maxOps) {
      _recentOpIds.removeRange(maxOps, _recentOpIds.length);
    }
  }

  /// Initialize the group controller, reload durable outbox frames, and
  /// recover any re-staged frames from an interrupted post-commit outbox write.
  Future<void> initialize() {
    return _serialized(() async {
      if (_isDisposed) return;
      if (_status == GroupControllerStatus.ready &&
          identityController.isReady) {
        return;
      }
      await _initializeInternal();
    });
  }

  /// Retry initialization after an error.
  Future<void> retryInitialize() {
    return _serialized(() async {
      if (_isDisposed) return;
      await _initializeInternal();
    });
  }

  /// Clear the group outbox directory and re-initialize. Useful when the
  /// outbox directory is corrupted and cannot be read.
  Future<void> clearOutboxAndRetry() {
    return _serialized(() async {
      if (_isDisposed) return;
      await _outbox.clearAll();
      await _initializeInternal();
    });
  }

  Future<void> _initializeInternal() async {
    _status = GroupControllerStatus.initializing;
    _errorMessage = null;
    _notifySafely();

    try {
      if (!identityController.isReady) {
        throw StateError('IdentityController must be ready before groups.');
      }

      await _reloadOutbox();
      final now = _now();
      final recovered = await identityController.recoverStagedGroupOutgoing(
        at: now,
      );
      if (recovered.isNotEmpty) {
        final existingUris = _outgoingMessages
            .map((m) => encodeGroupFrame(m.message))
            .toSet();
        final missing = recovered
            .where((m) => !existingUris.contains(encodeGroupFrame(m)))
            .toList(growable: false);
        var recoveryPersisted = true;
        if (missing.isNotEmpty) {
          recoveryPersisted = await _appendReleasedWithRecovery(
            missing,
            at: now,
          );
        }
        if (recoveryPersisted) {
          try {
            await identityController.checkpointGroupSnapshot(at: now);
          } catch (_) {
            // Best-effort checkpoint; outbox already deduplicates on restart.
          }
        }
      }

      _status = GroupControllerStatus.ready;
      _syncCachedView();
      _notifySafely();
    } catch (e) {
      if (_isDisposed) return;
      _status = GroupControllerStatus.error;
      _errorMessage = 'Failed to initialize group state: $e';
      _syncCachedView();
      _notifySafely();
    }
  }

  Future<void> _reloadOutbox() async {
    _outgoingMessages.clear();
    _outboxError = null;
    final loaded = await _outbox.loadAll();
    _outgoingMessages.addAll(loaded.messages);
    if (loaded.directoryError != null) {
      _outboxError = loaded.directoryError;
    } else if (loaded.unreadableCount > 0) {
      _outboxError =
          '${loaded.unreadableCount} outbox message(s) could not be read.';
    }
  }

  /// Append released frames to [_outbox]; on write failure, retain them in
  /// memory with `isPersisted: false` and surface [_outboxError] without throwing.
  Future<bool> _appendReleasedWithRecovery(
    List<OutgoingMessage> messages, {
    required DateTime at,
  }) async {
    try {
      final stored = await _outbox.appendMessages(messages, at: at);
      _outgoingMessages.addAll(stored);
      _outboxError = null;
      return true;
    } catch (e) {
      for (final msg in messages) {
        _unsavedSeq += 1;
        _outgoingMessages.add(
          StoredOutgoingMessage(
            id: 'unsaved_${at.microsecondsSinceEpoch}_$_unsavedSeq',
            message: msg,
            createdAt: at,
            isPersisted: false,
          ),
        );
      }
      _outboxError =
          'Operation committed, but ${messages.length} outgoing frame(s) '
          'could not be saved to outbox ($e). Retry saving or re-send.';
      return false;
    }
  }

  Future<T> _commitTwoPhase<T>(
    T Function(MeshGroupHandle handle) mutate, {
    List<GroupEvent> Function(T result)? immediateEvents,
    bool Function(T result)? recordOp,
  }) async {
    _requireReady();
    final now = _now();
    final committed = await identityController.runGroupTwoPhase(
      mutate,
      at: now,
    );

    if (immediateEvents != null) {
      _recordEvents(immediateEvents(committed.value));
    }
    _recordEvents(committed.confirmedEvents);
    if (recordOp != null &&
        recordOp(committed.value) &&
        committed.value is BigInt) {
      _recordOpId(committed.value as BigInt);
    }

    if (committed.releasedMessages.isNotEmpty) {
      final persisted = await _appendReleasedWithRecovery(
        committed.releasedMessages,
        at: now,
      );
      if (persisted) {
        try {
          await identityController.checkpointGroupSnapshot(at: now);
        } catch (_) {
          // Best-effort clean checkpoint after durable outbox write.
        }
      }
    }

    if (!_isDisposed) {
      _syncCachedView();
      _notifySafely();
    }
    return committed.value;
  }

  /// Flush any unsaved in-memory outgoing frames before [IdentityController]
  /// overwrites the on-disk snapshot. Invoked inside `IdentityController._serialized`,
  /// so this must not call back into [identityController].
  Future<void> _flushUnsavedOutgoingForPersist() async {
    if (_isDisposed) return;
    final unsaved = _outgoingMessages
        .where((m) => !m.isPersisted)
        .toList(growable: false);
    if (unsaved.isEmpty) return;

    final now = _now();
    final stored = await _outbox.appendMessages(
      unsaved.map((m) => m.message).toList(growable: false),
      at: now,
    );
    final unsavedIds = unsaved.map((m) => m.id).toSet();
    _outgoingMessages.removeWhere((m) => unsavedIds.contains(m.id));
    _outgoingMessages.addAll(stored);
    _outboxError = null;
    _notifySafely();
  }

  /// Retry persisting any in-memory outgoing frames whose initial outbox write
  /// failed after commit.
  Future<void> retryPersistUnsavedOutgoing() {
    return _serialized(() async {
      _requireReady();
      final unsaved = _outgoingMessages
          .where((m) => !m.isPersisted)
          .toList(growable: false);
      if (unsaved.isEmpty) return;

      final now = _now();
      final stored = await _outbox.appendMessages(
        unsaved.map((m) => m.message).toList(growable: false),
        at: now,
      );
      final unsavedIds = unsaved.map((m) => m.id).toSet();
      _outgoingMessages.removeWhere((m) => unsavedIds.contains(m.id));
      _outgoingMessages.addAll(stored);
      _outboxError = null;
      try {
        await identityController.checkpointGroupSnapshot(at: now);
      } catch (_) {
        // Best-effort clean checkpoint.
      }
      _notifySafely();
    });
  }

  Future<BigInt> createGroup({List<Uint8List> members = const []}) {
    return _serialized(() {
      return _commitTwoPhase(
        (h) => h.createGroup(members: members),
        recordOp: (_) => true,
      );
    });
  }

  Future<BigInt> importGenesis({
    required Uint8List frame,
    required Uint8List expectedDigest,
  }) {
    return _serialized(() {
      return _commitTwoPhase(
        (h) => h.importGenesis(frame: frame, expectedDigest: expectedDigest),
        recordOp: (_) => true,
      );
    });
  }

  Future<BigInt> invite({
    required BigInt groupId,
    required Uint8List candidateKey,
    Duration lifetime = const Duration(days: 1),
  }) {
    return _serialized(() {
      final now = _now();
      return _commitTwoPhase(
        (h) => h.invite(
          groupId: groupId,
          candidateKey: candidateKey,
          lifetime: lifetime,
          at: now,
        ),
        recordOp: (_) => true,
      );
    });
  }

  Future<BigInt> acceptInvitation(Uint8List invitationBinding) {
    return _serialized(() {
      final now = _now();
      return _commitTwoPhase(
        (h) => h.accept(invitationBinding: invitationBinding, at: now),
        recordOp: (_) => true,
      );
    });
  }

  Future<BigInt> acceptInvitationAuthenticated({
    required Uint8List invitationBinding,
    required Uint8List genesisDigest,
  }) {
    return _serialized(() {
      final now = _now();
      return _commitTwoPhase(
        (h) => h.acceptAuthenticated(
          invitationBinding: invitationBinding,
          genesisDigest: genesisDigest,
          at: now,
        ),
        recordOp: (_) => true,
      );
    });
  }

  Future<BigInt> leaveGroup(BigInt groupId) {
    return _serialized(() {
      final now = _now();
      return _commitTwoPhase(
        (h) => h.leaveGroup(groupId: groupId, at: now),
        recordOp: (_) => true,
      );
    });
  }

  Future<List<GroupEvent>> receiveFrame(
    OutgoingMessage frame, {
    Uint8List? fromPeerKey,
  }) {
    return _serialized(() {
      final now = _now();
      final effectiveFrom = fromPeerKey ?? frame.from;
      return _commitTwoPhase(
        (h) => h.receiveBytes(
          fromPeerKey: effectiveFrom,
          bytes: frame.bytes,
          at: now,
        ),
        immediateEvents: (events) => events,
      );
    });
  }

  Future<void> resendOperation(BigInt opId) {
    return _serialized(() {
      return _commitTwoPhase((h) => h.resend(opId));
    });
  }

  Future<void> markOutgoingSent(String id) {
    return _serialized(() async {
      _requireReady();
      final idx = _outgoingMessages.indexWhere((m) => m.id == id);
      if (idx == -1) return;
      final item = _outgoingMessages[idx];
      if (item.isPersisted) {
        await _outbox.deleteMessage(id);
      }
      _outgoingMessages.removeAt(idx);
      _notifySafely();
    });
  }

  @override
  void dispose() {
    if (_isDisposed) return;
    _isDisposed = true;
    identityController.removeListener(_onIdentityChanged);
    identityController.setBeforePersistHook(null);
    super.dispose();
  }
}
