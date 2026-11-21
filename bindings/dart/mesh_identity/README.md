# mesh_identity

Pure Dart bindings for [`mesh-identity`](https://crates.io/crates/mesh-identity) — peer identity, offline encounters, and Byzantine group admission governance for Dart and Flutter applications.

Built using **Dart Native Assets** (`dart:ffi`), compiling the native Rust engine directly into your Dart or Flutter application without manual shared library bundling.

---

## Features

- **Installation Lifecycle**: Create and manage local nodes with Ed25519 cryptographic identities.
- **Multiple Personas**: Add, select, and manage multiple pseudonymous local personas within a single node.
- **Durable Snapshots**: Byte-for-byte deterministic serialization and authenticated checkpoint restoration.
- **Contact Management**: Private local contact records, peer public key importation, and administrative blocking.
- **Memory Safety & Zeroization**: Native panics are caught at the FFI boundary, pointers and lengths are strictly bounded before allocation, and native seed buffers are zeroized upon release. (Callers should zeroize their own `Uint8List` seeds with `fillRange(0, 32, 0)` when no longer needed.)
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

---

## Roadmap

This package is being built in verified, incremental slices:
- [x] **Slice 1**: Installation lifecycle, personas, snapshots, contact store, and defensive C-FFI boundary.
- [x] **Slice 2**: Cryptographic Encounter protocol (initiator / responder, SAS verification, QR transport).
- [ ] **Slice 3**: Device-to-device handoff (identity migration and voter lock transfer).
- [ ] **Slice 4**: Byzantine group admission governance, voting ceremonies, and state machines.
- [ ] **Slice 5**: OpenPGP cross-signing and trust bridging.

---

## License

MIT
