# AGENTS.md: Developer & Agent Guidelines for `mesh_identity` (Dart Bindings)

> **PRIMARY DIRECTIVE FOR ALL AGENTS:**
> The `mesh_identity` Dart package is a **pure Dart binding** with **Dart Native Assets** (`dart:ffi`) for the standalone `mesh-identity` Rust library.
> It must be **completely self-contained**, maintain **zero Flutter framework dependencies**, and project the underlying Rust cryptography and protocol state machines into idiomatic, defensive Dart without introducing speculative abstractions.

---

## 1. Architectural Principles & Boundaries

1. **Pure Dart (Framework Agnostic):**
   - Do **NOT** introduce `flutter` or any UI framework dependencies. The library must run identically in Flutter, Dart CLI tools, background isolates, and server-side environments.

2. **Defensive FFI & Memory Safety:**
   - **Zero Raw Panics Crossing C-ABI:** Every `extern "C"` function in `native/src/lib.rs` must be enclosed in `std::panic::catch_unwind(AssertUnwindSafe(|| { ... }))`.
   - **Handle Poisoning:** Any native panic must mark the owning handle as poisoned (`handle.is_poisoned = true`), record the panic message, and return `MESH_ERR_PANIC`. Subsequent calls on that handle must immediately fail with `NativePanicException`.
   - **Pre-Allocation Input Validation:** Always enforce defensive bounds on untrusted input in Dart *before* allocating native memory (e.g. `using((Arena arena) { ... })`) or copying buffers:
     - Frames & Payloads: $\le 512$ bytes (`MAX_FRAME_BYTES`).
     - Snapshot Bytes: $\le 64\text{ MiB}$ (`MAX_SNAPSHOT_BYTES`).
     - Signing Seeds: exactly 32 bytes each, count $\le 2048$ (`MAX_SEEDS_CEILING`).
     - Timestamps: non-negative (post-1970).
   - **Error Channel Hygiene:** Every native entry point must invoke `clear_last_error()` immediately upon entry to prevent stale TLS error text leakage.
   - **Secret Zeroization:** Native seed buffers must be explicitly zeroized upon release. The API must require caller-managed seeds so that personas can always be recovered from snapshots.
   - **Concurrency Constraint:** Native handles wrap raw pointers without internal locking. `MeshInstallation` instances must not be accessed concurrently across multiple Dart isolates.

3. **Strict Library Privacy:**
   - Raw pointers (`ffi.Pointer<ffi.Void>`) and internal state machine handles must never be exposed to consumers.
   - Internal constructors must use leading underscores (`EncounterCeremony._fromHandle`) and share scope via Dart `part` / `part of` directives so they cannot be instantiated with arbitrary pointers from outside the package.

4. **Package Self-Containment & Dependency Invariants:**
   - `native/Cargo.toml` must depend only on published crates from `crates.io` with zero `path` dependencies.
   - Local development overrides belong exclusively in `.cargo/config.toml` at the repository root and must never leak into distributed manifests.

---

## 2. Roadmap Slices

Bindings are implemented in 5 strictly scoped, verified slices:

- [x] **Slice 1: Core Node Lifecycle & Multi-Persona Store**
  - Node installation, deterministic/random persona creation, multi-persona selection/removal.
  - Durable snapshot serialization and byte-for-byte restore.
  - Basic contact records, unverified key importation, and administrative blocking.
- [x] **Slice 2: In-Person Encounter Ceremonies & Transport**
  - Cryptographic Encounter ceremony state machine (initiator and responder roles).
  - Short Authentication String (SAS) 6-digit comparison codes with display-before-confirm gating.
  - Optical QR Code transport (`QrTransport.encodeUri` / `decodeUri`) bounded to 512 bytes.
  - Pre-allocation checks, required caller seeds, and cancellation lifecycle.
- [ ] **Slice 3: Device-to-Device Handoff (Current Target)**
  - `begin_handoff`, `accept_handoff`, and `cancel_handoff` flows.
  - Generating, validating, and applying authenticated CBOR handoff bundles.
  - Anti-equivocation voter lock table migration (`roster_locks.rs`) and device nonce transitions.
- [ ] **Slice 4: Byzantine Group Admission & Governance**
  - Group lifecycle handles (`FormingGroup`, `JoiningGroup`, `LeavingGroup`, `VotingGroup`).
  - Quorum certificate verification and admission vouchers.
- [ ] **Slice 5: OpenPGP Interoperability**
  - Pure-Rust OpenPGP detached signing and key importation.

---

## 3. Working Standards & Verification

Before presenting changes or submitting pull requests, **all** of the following must pass cleanly with zero warnings:

```bash
# 1. Native crate verification
cargo fmt --manifest-path native/Cargo.toml --check
cargo clippy --manifest-path native/Cargo.toml --all-targets -- -D warnings

# 2. Dart package verification
dart format --output=none --set-exit-if-changed .
dart analyze --fatal-infos
dart test

# 3. Upstream repository manifest guard
cargo test --manifest-path ../../../Cargo.toml --test manifest_guard
```
