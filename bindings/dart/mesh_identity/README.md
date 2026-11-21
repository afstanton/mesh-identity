# mesh_identity

Pure Dart bindings for [`mesh-identity`](https://crates.io/crates/mesh-identity) — peer identity, offline encounters, and Byzantine group admission governance for Dart and Flutter applications.

Built using **Dart Native Assets** (`dart:ffi`), compiling the native Rust engine directly into your Dart or Flutter application without manual shared library bundling.

---

## Features

- **Installation Lifecycle**: Create and manage local nodes with Ed25519 cryptographic identities.
- **Multiple Personas**: Add, select, and manage multiple pseudonymous local personas within a single node.
- **Durable Snapshots**: Byte-for-byte deterministic serialization and authenticated checkpoint restoration.
- **Contact Management**: Private local contact records, peer public key importation, and administrative blocking.
- **Memory Safety & Zeroization**: Native panics are caught at the FFI boundary, pointers and lengths are strictly bounded, and sensitive private seeds are zeroized upon allocation release.

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
  // Generate an installation with a random Ed25519 root identity
  final installation = MeshInstallation.create();
  print('Selected public key: ${installation.selectedIdentity}');

  // Or create deterministically from a 32-byte signing seed:
  final seed = Uint8List(32)..fillRange(0, 32, 42);
  final deterministic = MeshInstallation.create(seed: seed);

  installation.dispose();
  deterministic.dispose();
}
```

### 2. Manage Personas

```dart
final installation = MeshInstallation.create();

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

---

## Roadmap

This package is being built in verified, incremental slices:
- [x] **Slice 1**: Installation lifecycle, personas, snapshots, contact store, and defensive C-FFI boundary.
- [ ] **Slice 2**: Cryptographic Encounter protocol (initiator / responder, SAS verification, transport abstraction).
- [ ] **Slice 3**: Byzantine group admission governance, voting ceremonies, and state machines.
- [ ] **Slice 4**: OpenPGP cross-signing and trust bridging.

---

## License

MIT
