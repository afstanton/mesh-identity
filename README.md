# mesh-identity

A self-contained, standalone Rust library for peer identity, offline in-person encounters, pairwise link disclosure, and Byzantine group admission governance.

`mesh-identity` provides cryptographic identity and consensus building blocks without depending on centralized servers or external runtime engines.

---

## Architecture & Features

The crate is designed with strict layering: Core identity is always built, with group governance and OpenPGP compatibility available as optional Cargo features.

```
mesh-identity
├── Core (always enabled)      Identity, personas, in-person Encounter (SAS/QR/BLE), contacts, snapshots
├── [groups]                   Byzantine group admission, rosters, quorum certificates, evidence, handle
├── [openpgp]                  Pure-Rust OpenPGP key import and detached signing via rpgp
└── [test-support]             Simulation-only authority and signing hooks for testing
```

### Feature Flags

* `default = []`: Builds the Core identity library with zero external group or OpenPGP dependencies.
* `groups`: Enables group admission, PBFT-style roster consensus, quorum certificates, handle state machines, and evidence.
* `openpgp`: Enables OpenPGP interoperability powered by `rpgp` (pure Rust, MIT/Apache-2.0, zero C/OpenSSL dependencies).
* `test-support`: Enables test-only simulation fixtures and reduced SAS campaign moduli. Never enabled in production.

---

## Capabilities & Roadmap

### 1. Peer Identity & Encounters (Core — Milestone X2)
* **Local Personas:** Ed25519 signing keys and X25519 Diffie-Hellman key agreements.
* **Offline Encounter Protocol:** Two-device mutual authentication over QR codes or chunked BLE frames with Short Authentication String (SAS) human verification.
* **Pairwise Link Disclosure:** Proving and linking multiple local personas belonging to the same individual without global identifiers (`LinkedPersonContacts`).
* **Installation Persistence:** Atomic snapshot save/restore with deterministic CBOR (`cbor2`) ensuring state is bounded and restorable within a 64 MiB ceiling.
* **Resource Invariants:** Strictly enforced ceilings on contacts (100k aggregate), aliases (64 B), seen transcripts (262k aggregate with oldest eviction), and handoff bundles (5 MiB).
* **Cooperative Handoff:** Secure transfer of group signing roles between devices without equivocation.

### 2. Group Admission & Roster Governance (`groups` — Milestone X3)
* **Byzantine Agreement:** Quorum-based roster changes with prepare, commit, and round-change phases.
* **Proof-Carrying Certificates:** Verifiable membership certificates supporting up to 192 members and 128 signers per phase.
* **Equivocation Protection:** Persistent voter lock tables (`roster_locks`, bounded at 8,192 parents) preventing signers from issuing contradictory votes across restarts.
* **Group Handle:** Complete high-level facade for creating groups, issuing invitations, voting, and processing incoming wire bytes.
* **Member Local State:** Manages local departures, tombstones, and backup-roster acknowledgements (`MemberLocalState`).

### 3. OpenPGP Interoperability (`openpgp` — Milestone X4)
* **Key Import:** Import existing Ed25519 OpenPGP secret keys into local `mesh-identity` personas using `rpgp`.
* **Detached Signatures:** Issue standard OpenPGP document signatures and peer certifications using the local identity.
* **Revocation Tracking:** Bounded memory (`PeerRevocations`) tracking key, subkey, and user ID revocations, persisted atomically with snapshots.

### 4. API Disambiguation & Parity (Milestone X5)
* Disambiguated `LinkedPersonContacts` (retaining `PersonGroup` alias) and `MemberLocalState` (retaining `LocalInstallation` alias).
* 100% test parity with reference baselines and verified 88.1% line / 91.7% region coverage.

---

## Building & Testing

Requires Rust edition 2024.

```bash
# Build core library
cargo build

# Run core test suite (107 tests)
cargo test

# Test with OpenPGP interoperability enabled (107 tests, including 18 import/export integration tests)
cargo test --features openpgp

# Build and test with group admission enabled (243 tests)
cargo test --features groups

# Run full test matrix with all features and strict warnings denied (532 tests)
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

---

## Constraints

* **Self-Contained:** Published dependencies only. No path or git dependencies.
* **Standalone Architecture:** Completely decoupled from external domain logic; consumers interact purely through byte buffers, hashes, and minimal consumer-defined traits.
* **Bounded Resources:** Enforces defensive ceilings on contact counts, seen transcripts, handoff bundles, and frame sizes to prevent memory exhaustion and DoS attacks.
