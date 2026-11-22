# Encounter (Flutter Reference App) — Implementation Roadmap

This roadmap breaks down the development of **Encounter** (`code/mesh-identity/examples/flutter/encounter`) into 9 discrete, testable slices. Each slice delivers verifiable functionality, adheres to store guidelines, and preserves strict parameterization for proprietary store identifiers.

---

## Architecture & Design Guardrails

1. **Standalone Package Dependency**: Always depend on `mesh_identity: ^0.5.1` from pub.dev. Never use local path dependencies.
2. **Confidentiality Invariant**: All store bundle IDs, proprietary company names, signing keystores, and telemetry keys are gitignored and injected at build time. Default build uses `org.mesh.identity.encounter`.
3. **Single-Isolate Native Handles**: Keep `MeshInstallation` and `MeshGroupHandle` inside a single dedicated service/controller on the main UI isolate.
4. **Seed & Secret Zeroization**: All caller-managed seeds and passphrases in Dart must be securely handled and zeroed when discarded.
5. **Universal Fallback**: Core flows (especially Encounter ceremonies) must always support single-device practice and manual/QR payload import so every platform (macOS, Windows, Linux, iOS, Android) is functional without mandatory hardware sensors.

---

## Slice Breakdown

- [x] **Slice 1: Core Node Controller & Persistence Architecture**
  - Establish `SecureKeyringService` (secure seed storage) and `SnapshotStorageService` (atomic `.tmp` + rename file persistence).
  - Single `IdentityController` (`ChangeNotifier`) owning the live `MeshInstallation`.
  - Cold-start restore, seed generation, persona switching, and corruption recovery states.
  - In-memory service fakes for unit and widget testing.

- [x] **Slice 2: Responsive Shell, Navigation & HIG Compliance**
  - macOS unified top toolbar integration (`toolbarStyle = .unified`) and native `PlatformMenuBar`.
  - Adaptive desktop navigation rail / titlebar vs mobile bottom navigation bar.
  - Store-compliant **About & Open Source Screen** linking to `https://github.com/afstanton/mesh-identity` with MIT license display.
  - Adaptive dark/light themes.

- [x] **Slice 3: In-Person Encounter Ceremony (Practice Mode & Manual/QR Transport)**
  - Single-device "Practice Mode" (Alice & Bob dual ceremony) runnable without camera or secondary device.
  - Optical QR display via `QrTransport.encodeUri` and clipboard/text payload import.
  - Statutory UI: `proximityDisclaimer`, `notIdentityProof`, and `instruction`.
  - Human-typed 6-digit SAS comparison (no auto-confirm) and `cancelCeremony` on exit.

- [x] **Slice 4: Contact Governance & Persona Management**
  - Verified contact detail cards with SAS timestamps, fingerprints, and alias editing.
  - Unverified contact handling and administrative blocking.
  - Multi-persona switcher with fresh seed generation and buffer zeroization.

- [ ] **Slice 5: Hardware Camera Scanning & Platform Entitlements**
  - Cross-platform camera scanner with graceful fallback to on-screen QR and clipboard import.
  - Camera permissions and macOS App Sandbox entitlements.

- [ ] **Slice 6: Device-to-Device Handoff & Monotonic Voting Roles**
  - Persistent device nonce display and voting role indicator (`VotingState`: voting, stopped, gated).
  - Outbox handoff QR bundle generation and receiver handoff acceptance with atomic snapshot updates.

- [ ] **Slice 7: Byzantine Group Admission & Governance UI**
  - Group formation & authenticated genesis export/import.
  - Verified contact admission vouchers (`invite`, `acceptAuthenticated`).
  - Two-phase commit outbox staging & confirmation (`save(now)` $\to$ `confirmSaved(token)`).

- [ ] **Slice 8: OpenPGP Interoperability Bridge & Cross-Certification**
  - Certificate inspection (v4 and v6 public keys, algorithms, user IDs).
  - Export preview screen with statutory privacy disclosure warnings.
  - Peer cross-certification signature generation and secret key import with seed recovery.

- [ ] **Slice 9: Bluetooth Low Energy (BLE) Transport**
  - Offline BLE advertisement & GATT characteristic exchange for Encounter ceremony payloads ($\le 512$ bytes).
  - Proximity indicator and seamless handover to SAS 6-digit confirmation screen.
