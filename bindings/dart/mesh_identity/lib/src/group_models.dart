import 'dart:typed_data';

/// The 9 group messaging kinds defined by the Byzantine admission protocol.
enum MessageTag {
  genesis(1),
  invitation(2),
  consent(3),
  admissionVote(4),
  voucher(5),
  rosterVote(6),
  certificate(7),
  departure(8),
  groupSnapshot(9);

  const MessageTag(this.value);
  final int value;

  static MessageTag fromValue(int val) {
    for (final tag in values) {
      if (tag.value == val) return tag;
    }
    throw ArgumentError.value(val, 'val', 'Unknown MessageTag value');
  }
}

/// Token returned by `save()` confirming the durability sequence and incarnation.
class SaveToken {
  const SaveToken({required this.counter, required this.incarnation});

  /// The monotonic sequence counter covered by this save.
  final BigInt counter;

  /// The 32-byte incarnation identifier of the handle session.
  final Uint8List incarnation;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is SaveToken &&
          other.counter == counter &&
          _bytesEqual(other.incarnation, incarnation);

  @override
  int get hashCode => Object.hash(counter, Object.hashAll(incarnation));

  @override
  String toString() =>
      'SaveToken(counter: $counter, incarnation: ${_toHex(incarnation)})';
}

/// The result of saving group handle state.
class GroupSaveResult {
  const GroupSaveResult({required this.token, required this.blob});

  /// The save token that must be passed to `confirmSaved` once durable.
  final SaveToken token;

  /// The serialized snapshot blob encoding the handle and all groups.
  final Uint8List blob;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is GroupSaveResult &&
          other.token == token &&
          _bytesEqual(other.blob, blob);

  @override
  int get hashCode => Object.hash(token, Object.hashAll(blob));

  @override
  String toString() =>
      'GroupSaveResult(token: $token, blob: ${blob.length} bytes)';
}

/// An outgoing network message produced by the group state machine.
class OutgoingMessage {
  const OutgoingMessage({
    required this.from,
    required this.to,
    required this.tag,
    required this.bytes,
    this.authenticator,
  });

  /// The 32-byte public key of the local sender.
  final Uint8List from;

  /// The 32-byte public keys of the intended recipients (empty = all/broadcast).
  final List<Uint8List> to;

  /// The message kind.
  final MessageTag tag;

  /// The framed message bytes.
  final Uint8List bytes;

  /// Optional SHA-256 authenticator digest (e.g. for genesis frames).
  final Uint8List? authenticator;

  factory OutgoingMessage.fromJson(Map<String, dynamic> json) {
    final from = _hexToBytes(json['from'] as String, 'from', 32);
    final toList =
        (json['to'] as List<dynamic>)
            .map((e) => _hexToBytes(e as String, 'to', 32))
            .toList();
    final tagInt = json['tag'] as int;
    final tag = MessageTag.fromValue(tagInt);
    final bytes = _bytesFromHex(json['bytes'] as String);
    final authHex = json['authenticator'] as String?;
    final auth =
        authHex != null ? _hexToBytes(authHex, 'authenticator', 32) : null;
    return OutgoingMessage(
      from: from,
      to: toList,
      tag: tag,
      bytes: bytes,
      authenticator: auth,
    );
  }

  @override
  bool operator ==(Object other) {
    if (identical(this, other)) return true;
    if (other is! OutgoingMessage) return false;
    if (!_bytesEqual(other.from, from)) return false;
    if (other.tag != tag) return false;
    if (!_bytesEqual(other.bytes, bytes)) return false;
    if (!_bytesEqual(other.authenticator, authenticator)) return false;
    if (other.to.length != to.length) return false;
    for (var i = 0; i < to.length; i++) {
      if (!_bytesEqual(other.to[i], to[i])) return false;
    }
    return true;
  }

  @override
  int get hashCode {
    var toHash = 0;
    for (final key in to) {
      toHash = Object.hash(toHash, Object.hashAll(key));
    }
    return Object.hash(
      Object.hashAll(from),
      toHash,
      tag,
      Object.hashAll(bytes),
      authenticator != null ? Object.hashAll(authenticator!) : 0,
    );
  }

  @override
  String toString() =>
      'OutgoingMessage(from: ${_toHex(from)}, to: ${to.length} peers, tag: $tag, bytes: ${bytes.length})';
}

/// Reasons why an inbound frame was rejected by the group state machine.
enum FrameRejectReason {
  malformed,
  tooLarge,
  unknownTag,
  unsupported,
  needsAuthentication,
  invalid,
  full,
  expired,
  stale,
  unknownContact,
  unknown,
  conflict;

  static FrameRejectReason parse(String str) {
    switch (str.toLowerCase()) {
      case 'malformed':
        return FrameRejectReason.malformed;
      case 'toolarge':
      case 'too_large':
        return FrameRejectReason.tooLarge;
      case 'unknowntag':
      case 'unknown_tag':
        return FrameRejectReason.unknownTag;
      case 'unsupported':
        return FrameRejectReason.unsupported;
      case 'needsauthentication':
      case 'needs_authentication':
        return FrameRejectReason.needsAuthentication;
      case 'invalid':
        return FrameRejectReason.invalid;
      case 'full':
        return FrameRejectReason.full;
      case 'expired':
        return FrameRejectReason.expired;
      case 'stale':
        return FrameRejectReason.stale;
      case 'unknowncontact':
      case 'unknown_contact':
        return FrameRejectReason.unknownContact;
      case 'unknown':
        return FrameRejectReason.unknown;
      case 'conflict':
        return FrameRejectReason.conflict;
      default:
        return FrameRejectReason.invalid;
    }
  }
}

/// Base sealed class for all events emitted by the group state machine upon save confirmation.
sealed class GroupEvent {
  const GroupEvent();

  static GroupEvent fromJson(Map<String, dynamic> json) {
    final type = json['type'] as String;
    switch (type) {
      case 'GroupCreated':
        return GroupCreatedEvent(BigInt.parse(json['group'] as String));
      case 'GroupImported':
        return GroupImportedEvent(BigInt.parse(json['group'] as String));
      case 'GroupFormed':
        return GroupFormedEvent(BigInt.parse(json['group'] as String));
      case 'InvitationSent':
        return InvitationSentEvent(BigInt.parse(json['op'] as String));
      case 'InvitationReceived':
        return InvitationReceivedEvent(
          groupId: BigInt.parse(json['group'] as String),
          invitationBinding: _hexToBytes(
            json['invitation'] as String,
            'invitation',
            32,
          ),
        );
      case 'AcceptanceSent':
        return AcceptanceSentEvent(BigInt.parse(json['op'] as String));
      case 'ConsentReceived':
        return ConsentReceivedEvent(BigInt.parse(json['op'] as String));
      case 'Admitted':
        return AdmittedEvent(BigInt.parse(json['op'] as String));
      case 'Joined':
        return JoinedEvent(BigInt.parse(json['group'] as String));
      case 'MemberAdmitted':
        return MemberAdmittedEvent(
          groupId: BigInt.parse(json['group'] as String),
          memberKey: _hexToBytes(json['member'] as String, 'member', 32),
        );
      case 'Left':
        return LeftEvent(BigInt.parse(json['group'] as String));
      case 'MemberDeparted':
        return MemberDepartedEvent(
          groupId: BigInt.parse(json['group'] as String),
          memberKey: _hexToBytes(json['member'] as String, 'member', 32),
        );
      case 'FrameRejected':
        return FrameRejectedEvent(
          FrameRejectReason.parse(json['reason'] as String),
        );
      default:
        throw FormatException('Unknown GroupEvent type: $type', json);
    }
  }
}

final class GroupCreatedEvent extends GroupEvent {
  const GroupCreatedEvent(this.groupId);
  final BigInt groupId;

  @override
  String toString() => 'GroupCreatedEvent(group: $groupId)';
}

final class GroupImportedEvent extends GroupEvent {
  const GroupImportedEvent(this.groupId);
  final BigInt groupId;

  @override
  String toString() => 'GroupImportedEvent(group: $groupId)';
}

final class GroupFormedEvent extends GroupEvent {
  const GroupFormedEvent(this.groupId);
  final BigInt groupId;

  @override
  String toString() => 'GroupFormedEvent(group: $groupId)';
}

final class InvitationSentEvent extends GroupEvent {
  const InvitationSentEvent(this.opId);
  final BigInt opId;

  @override
  String toString() => 'InvitationSentEvent(op: $opId)';
}

final class InvitationReceivedEvent extends GroupEvent {
  const InvitationReceivedEvent({
    required this.groupId,
    required this.invitationBinding,
  });
  final BigInt groupId;
  final Uint8List invitationBinding;

  @override
  String toString() =>
      'InvitationReceivedEvent(group: $groupId, binding: ${_toHex(invitationBinding)})';
}

final class AcceptanceSentEvent extends GroupEvent {
  const AcceptanceSentEvent(this.opId);
  final BigInt opId;

  @override
  String toString() => 'AcceptanceSentEvent(op: $opId)';
}

final class ConsentReceivedEvent extends GroupEvent {
  const ConsentReceivedEvent(this.opId);
  final BigInt opId;

  @override
  String toString() => 'ConsentReceivedEvent(op: $opId)';
}

final class AdmittedEvent extends GroupEvent {
  const AdmittedEvent(this.opId);
  final BigInt opId;

  @override
  String toString() => 'AdmittedEvent(op: $opId)';
}

final class JoinedEvent extends GroupEvent {
  const JoinedEvent(this.groupId);
  final BigInt groupId;

  @override
  String toString() => 'JoinedEvent(group: $groupId)';
}

final class MemberAdmittedEvent extends GroupEvent {
  const MemberAdmittedEvent({required this.groupId, required this.memberKey});
  final BigInt groupId;
  final Uint8List memberKey;

  @override
  String toString() =>
      'MemberAdmittedEvent(group: $groupId, member: ${_toHex(memberKey)})';
}

final class LeftEvent extends GroupEvent {
  const LeftEvent(this.groupId);
  final BigInt groupId;

  @override
  String toString() => 'LeftEvent(group: $groupId)';
}

final class MemberDepartedEvent extends GroupEvent {
  const MemberDepartedEvent({required this.groupId, required this.memberKey});
  final BigInt groupId;
  final Uint8List memberKey;

  @override
  String toString() =>
      'MemberDepartedEvent(group: $groupId, member: ${_toHex(memberKey)})';
}

final class FrameRejectedEvent extends GroupEvent {
  const FrameRejectedEvent(this.reason);
  final FrameRejectReason reason;

  @override
  String toString() => 'FrameRejectedEvent(reason: $reason)';
}

/// The status of an asynchronous group operation.
class GroupOpState {
  const GroupOpState._({required this.status, this.reason});

  factory GroupOpState.fromJson(Map<String, dynamic> json) {
    final status = json['status'] as String;
    final reasonStr = json['reason'] as String?;
    final reason =
        reasonStr != null ? FrameRejectReason.parse(reasonStr) : null;
    return GroupOpState._(status: status, reason: reason);
  }

  final String status;
  final FrameRejectReason? reason;

  bool get isPending => status == 'Pending';
  bool get isCompleted => status == 'Completed';
  bool get isRejected => status == 'Rejected';
  bool get isRetryable => status == 'Retryable';

  @override
  String toString() =>
      'GroupOpState(status: $status, reason: ${reason ?? "none"})';
}

/// An invitation waiting for acceptance by this installation.
class PendingInvitation {
  const PendingInvitation({
    required this.binding,
    required this.groupId,
    required this.inviterKey,
  });

  factory PendingInvitation.fromJson(Map<String, dynamic> json) {
    return PendingInvitation(
      binding: _hexToBytes(json['binding'] as String, 'binding', 32),
      groupId: BigInt.parse(json['group'] as String),
      inviterKey: _hexToBytes(json['inviter'] as String, 'inviter', 32),
    );
  }

  /// The 32-byte unique decision binding for this invitation.
  final Uint8List binding;

  /// The 64-bit group ID.
  final BigInt groupId;

  /// The 32-byte public key of the verified inviter contact.
  final Uint8List inviterKey;

  @override
  String toString() =>
      'PendingInvitation(binding: ${_toHex(binding)}, group: $groupId, inviter: ${_toHex(inviterKey)})';
}

/// An authenticated public view of an active group's roster and policy.
class GroupView {
  const GroupView({
    required this.groupId,
    required this.revision,
    required this.policy,
    required this.members,
  });

  factory GroupView.fromJson(Map<String, dynamic> json) {
    final rawMembers = json['members'] as List<dynamic>;
    final members = rawMembers
        .map((m) => _hexToBytes(m as String, 'member', 32))
        .toList(growable: false);
    return GroupView(
      groupId: BigInt.parse(json['id'] as String),
      revision: BigInt.parse(json['revision'] as String),
      policy: json['policy'] as String,
      members: members,
    );
  }

  /// The 64-bit unique group identifier.
  final BigInt groupId;

  /// The monotonically increasing revision number of this roster.
  final BigInt revision;

  /// The admission policy description (e.g. "inviter_only").
  final String policy;

  /// The list of 32-byte public keys of all current members.
  final List<Uint8List> members;

  /// Whether [publicKey] is a member of this group.
  bool isMember(Uint8List publicKey) {
    if (publicKey.length != 32) return false;
    for (final m in members) {
      if (_bytesEqual(m, publicKey)) return true;
    }
    return false;
  }

  @override
  String toString() =>
      'GroupView(id: $groupId, revision: $revision, policy: $policy, members: ${members.length})';
}

bool _bytesEqual(Uint8List? a, Uint8List? b) {
  if (identical(a, b)) return true;
  if (a == null || b == null) return false;
  if (a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

String _toHex(Uint8List bytes) {
  final buffer = StringBuffer();
  for (final b in bytes) {
    buffer.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}

Uint8List _bytesFromHex(String hex) {
  final clean = hex.replaceAll(' ', '');
  if (clean.length.isOdd) {
    throw FormatException('Hex string must have an even length', hex);
  }
  final len = clean.length ~/ 2;
  final bytes = Uint8List(len);
  for (var i = 0; i < len; i++) {
    final b = int.tryParse(clean.substring(i * 2, i * 2 + 2), radix: 16);
    if (b == null) {
      throw FormatException('Non-hexadecimal character in hex string', hex);
    }
    bytes[i] = b;
  }
  return bytes;
}

Uint8List _hexToBytes(String hex, String fieldName, int expectedByteLen) {
  if (hex.length != expectedByteLen * 2) {
    throw FormatException(
      '$fieldName must be a ${expectedByteLen * 2}-character hex string',
      hex,
    );
  }
  final bytes = Uint8List(expectedByteLen);
  for (var i = 0; i < hex.length; i += 2) {
    final b = int.tryParse(hex.substring(i, i + 2), radix: 16);
    if (b == null) {
      throw FormatException(
        '$fieldName contains non-hexadecimal character',
        hex,
      );
    }
    bytes[i ~/ 2] = b;
  }
  return bytes;
}
