# mesh_identity

Pure Dart bindings for [`mesh-identity`](https://crates.io/crates/mesh-identity) — peer identity, offline encounters, and Byzantine group admission governance for Dart and Flutter applications.

Built using **Dart Native Assets** (`dart:ffi`), compiling the native Rust engine directly into your Dart or Flutter application without manual shared library bundling.

---

## Features

- **Installation Lifecycle**: Create and manage local nodes with Ed25519 cryptographic identities.
- **Multiple Personas**: Add, select, and manage multiple pseudonymous local personas within a single node.
- **Durable Snapshots**: Byte-for-byte deterministic serialization and authenticated checkpoint restoration.
- **Contact Management**: Private local contact records, peer public key importation, and administrative blocking.
- **Device-to-Device Handoff**: Monotonic voting role migration, voter lock transfer, gating, and signed takeover statements across physical devices.
- **Byzantine Group Admission & Governance**: Multi-party group formation, verified contact invitations, vouchers, two-phase commit outbox staging (`save` / `confirmSaved` / `takeOutgoing`), and consensus leave workflows.
- **OpenPGP Interoperability Bridge**: OpenPGP certificate inspection (v4 and v6), statutory privacy disclosure export previews, detached document signing, peer cross-certification, peer public key contact import, and passphrase-unlocked owned secret key import.
- **Memory Safety & Zeroization**: Native panics are caught at the FFI boundary, pointers and lengths are strictly bounded before allocation, and native memory buffers for seeds are securely zeroized upon release. (Callers are responsible for zeroizing their own `Uint8List` seed copies with `fillRange(0, 32, 0)` when no longer needed.)
- **Concurrency**: Instances wrap raw native pointers without internal locks; do not access the same `MeshInstallation` concurrently across multiple isolates.

---

## Prerequisites

Because `mesh_identity` builds native code through Dart Native Assets, you must have the Rust toolchain installed:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

---

## Usage

### 1. Create an Installation

```dart
import 'dart:typed_data';
import 'package:mesh_identity/mesh_identity.dart';

void main() {
  // Generate a cryptographically secure 32-byte signing seed
  final rootSeed = MeshInstallation.generateSeed();

  // Create an installation with an initial root persona
  final installation = MeshInstallation(seed: rootSeed);
  print('Selected public key: ${installation.selectedIdentity}');

  installation.dispose();
}
```

### 2. Manage Personas

```dart
final installation = MeshInstallation(seed: rootSeed);

// Add a secondary persona from a private seed
final personaSeed = Uint8List(32)..fillRange(0, 32, 7);
final personaKey = installation.addIdentity(personaSeed);

// Switch the active persona
installation.selectIdentity(personaKey);
assert(installation.selectedIdentity == personaKey);

// Return to root identity
installation.selectIdentity(installation.identities.first);

// Remove inactive persona
installation.removeIdentity(personaKey);
```

### 3. Checkpoints & Restoration

```dart
// Serialize to an authenticated byte snapshot
final snapshot = installation.save();

// Restore from bytes and known identity signing seeds
final restored = MeshInstallation.restore(
  snapshotBytes: snapshot,
  signingKeySeeds: [rootSeed],
);
```

### 4. Contacts

```dart
// Import an unverified peer public key
installation.importPeerKey(peerPublicKey);

// Lookup a contact
final contact = installation.getContact(peerPublicKey);
if (contact != null) {
  print('Contact status: ${contact.status}, verified: ${contact.isVerified}');
}

// Block a contact
installation.blockContact(peerPublicKey);
```

### 5. In-Person Encounter Ceremonies (SAS Verification)

```dart
// Alice starts as initiator
final start = alice.startEncounter();
final offerQrUri = QrTransport.encodeUri(start.offerPayload);

// Bob opens scanner as responder and scans Alice's QR offer
final bobCeremony = bob.openScanner();
final offerPayload = QrTransport.decodeUri(offerQrUri);
final responsePayload = bob.scanOffer(bobCeremony, offerPayload);

// Alice scans Bob's response and generates reveal
final revealPayload = alice.scanResponse(start.ceremony, responsePayload);

// Bob scans Alice's reveal
bob.scanReveal(bobCeremony, revealPayload);

// Both display the 6-digit SAS comparison code for mutual human verification
final aliceSas = alice.getComparison(start.ceremony)!;
final bobSas = bob.getComparison(bobCeremony)!;
assert(aliceSas.code == bobSas.code);
print('Compare SAS codes: ${aliceSas.formattedCode} == ${bobSas.formattedCode}');

// Both confirm each other's code to persist a verified contact
final aliceContact = alice.confirmAndSave(start.ceremony, bobSas.code);
final bobContact = bob.confirmAndSave(bobCeremony, aliceSas.code);
assert(aliceContact.isVerified && bobContact.isVerified);
```

### 6. Device-to-Device Handoff

Transfer an identity's voting role from an old device to a new device with monotonic counters and signed handoff bundles:

```dart
// Old device is currently in VotingState.voting
assert(oldDevice.getVotingState() == VotingState.voting);

// New device generates its unique physical device nonce and saves it
final newDeviceNonce = newDevice.getDeviceNonce();
await secureStorage.write('device_b_snapshot', newDevice.save());

// Old device creates a handoff bundle and produces the post-handoff snapshot.
// The snapshot MUST be persisted BEFORE the bundle is transmitted to prevent equivocation.
final handoff = oldDevice.beginHandoff(
  newDeviceNonce,
  onPersist: (snapshotBytes) => secureStorage.writeSync('device_a_snapshot', snapshotBytes),
);
assert(oldDevice.getVotingState() == VotingState.stopped);

// Bundle can be serialized and transferred over QR, local network, or BLE
final rawBytes = handoff.bundle.toBytes();
final receivedBundle = HandoffBundle.fromBytes(rawBytes);

// New device accepts the bundle, assumes the voting role, and persists merged locks
final acceptResult = newDevice.acceptHandoff(
  receivedBundle,
  onPersist: (snapshotBytes) => secureStorage.writeSync('device_b_snapshot', snapshotBytes),
);
assert(acceptResult.state == VotingState.voting);
assert(newDevice.getVotingRecord().counter == handoff.bundle.counter);
```

### 7. Byzantine Group Admission & Governance

```dart
// Transition an existing installation (with verified contacts) to a group handle
final groupHandle = MeshGroupHandle.fromInstallation(installation);

// Form a new Byzantine group
final opId = groupHandle.createGroup();

// Two-phase commit outbox staging:
// CRITICAL: Frames are strictly withheld and MUST NOT be sent before confirmSaved!
// 1. Save the snapshot blob to durable storage
final saveResult = groupHandle.save();
await secureStorage.write('group_snapshot', saveResult.blob);

// 2. Confirm durability to release staged frames and receive events
final events = groupHandle.confirmSaved(saveResult.token);
final createdEvent = events.whereType<GroupCreatedEvent>().first;
final groupId = createdEvent.groupId;

// 3. Only now drain and send outgoing frames over the network
final outgoingMessages = groupHandle.takeOutgoing();
for (final msg in outgoingMessages) {
  await networkTransport.send(to: msg.to, tag: msg.tag, bytes: msg.bytes);
}

// Invite a verified contact candidate to the group
groupHandle.invite(groupId: groupId, candidateKey: verifiedContactKey);
```

### 8. OpenPGP Interoperability Bridge

```dart
// 1. Inspect an external OpenPGP certificate (v4 or v6)
final cert = MeshInstallation.inspectOpenPgpCertificate(peerCertBytes);
print('Inspected OpenPGP key: ${cert.fingerprint} (v${cert.version})');

// 2. Prepare an export preview for the selected persona
final preview = installation.createOpenPgpPreview(
  profile: OpenPgpProfile.v4,
  userId: 'alice@example.com',
  document: documentBytes,
  // Optional: cross-certify a peer certificate
  peerCertificate: peerCertBytes,
  peerUserId: 'bob@example.com',
);

// CRITICAL: Display the statutory privacy warning to the user before confirming
print('Privacy disclosure: ${preview.warning}');

// 3. Confirm preview to generate transferable certificate and detached signature
final artifacts = preview.confirm(installation);
await fileSystem.write('alice.asc', artifacts.certificate);
await fileSystem.write('document.sig', artifacts.detachedSignature);

// 4. Import a peer's OpenPGP certificate as an unverified contact
final provenance = installation.importOpenPgpPeer(
  certificate: peerCertBytes,
  expectedPublicKey: peerMeshPublicKey,
  userId: 'bob@example.com',
);
print('Imported peer contact with OpenPGP fingerprint: ${provenance.primaryFingerprint}');

// 5. Import an owned OpenPGP secret key and retain the seed for snapshot restoration
final ownedResult = installation.importOpenPgpOwned(
  secretKeyCertificate: secretKeyBytes,
  expectedPublicKey: myMeshPublicKey,
  userId: 'alice@example.com',
  passphrase: 'secret-passphrase',
);
await secureStorage.write('imported_seed', ownedResult.seed);

// Later, restore installation with all persona seeds:
final restored = MeshInstallation.restore(
  snapshotBytes: savedSnapshot,
  signingKeySeeds: [rootSeed, ownedResult.seed],
);
```

---

## Roadmap

This package is being built in verified, incremental slices:
- [x] **Slice 1**: Installation lifecycle, personas, snapshots, contact store, and defensive C-FFI boundary.
- [x] **Slice 2**: Cryptographic Encounter protocol (initiator / responder, SAS verification, QR transport).
- [x] **Slice 3**: Device-to-device handoff (identity migration and voter lock transfer).
- [x] **Slice 4**: Byzantine group admission governance, voting ceremonies, and state machines.
- [x] **Slice 5**: OpenPGP cross-signing and trust bridging.

---

## License

MIT
