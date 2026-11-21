# AGENTS.md: Developer & Agent Guidelines for `mesh-identity`

> **CRITICAL DIRECTIVE FOR AGENTS:**
> `mesh-identity` must be **completely self-contained** with a **very tightly focused scope**.
> Do **NOT** expand scope, introduce speculative abstractions, create new functionality, or invent protocol state machines or format migrations unless strictly directed.

---

## 1. Core Principles & Boundaries

1. **Self-Contained Library (External Crates Only):**
   - `mesh-identity` is an independent, standalone library crate (`afstanton/mesh-identity`).
   - It **MUST NOT** have any `path` or `git` dependencies.
   - All runtime dependencies must be published external crates from crates.io.

2. **Strict Scope Control — No Feature Creep:**
   - **Do not invent new protocol state machines:** Do not design unproven retention algorithms, speculative watermark state machines (such as `retired_below`), or unneeded protocol states (such as `behind`).
   - **Do not rewrite wire formats:** Preserve the established wire formats and binary encodings. The group admission layer uses hand-laid binary formats (`to_be_bytes`/`from_be_bytes`); do not migrate them to a unified CBOR schema DSL.
   - **Keep seams simple:** Do not build dynamic microkernel plugin registries (`FeatureSigner`, `SlotKey`, `SlotMerger`) when simple `pub(crate)` internal Rust module calls are sufficient.

3. **Established Tech Choices:**
   - **CBOR:** Use `cbor2` (pinned, RFC 8949 canonical encoding) for serialization paths that use CBOR (Encounter frames, `InstallationSnapshot`, contact stores). Do not rewrite non-CBOR formats.
   - **OpenPGP:** Use `rpgp` for pure-Rust OpenPGP compatibility under an optional `openpgp` cargo feature. No C dependencies (no OpenSSL), no LGPL.

---

## 2. Feature Layout & Architectural Tiers

The crate is strictly divided into three tiers plus a test hook:

```
mesh-identity
├── Core (always built)        -> Individuals, Personas, Encounters, Contacts, Snapshot
├── Feature "groups"           -> Rosters, Policies, Quorums, Evidence, Handle, Locks
├── Feature "openpgp"          -> Pure-Rust rpgp adapter for key import and detached signing
└── Feature "test-support"     -> Simulation-only hooks and campaign lab fixtures
```

### Tier 1: Core (Always Enabled)
Covers individual identity and pairwise in-person encounters:
* **Identities & Personas:** Generating and managing local Ed25519/X25519 keys.
* **Encounter Protocol:** Offline in-person introduction via QR code, BLE chunking, state machines, Short Authentication Strings (SAS), and transcript hashing.
* **Contacts:** Address book, attempt policies, and recording whether a contact was verified in person.
* **Link Ceremony:** Peer-to-peer link disclosure between two local personas belonging to the same individual.
* **Installation & Snapshot:** Multi-identity management, device nonces, durable snapshot/restore, voter anti-equivocation lock tables (`roster_locks.rs`), and device handoff state (`handoff.rs`).

### Tier 2: `groups` Feature (Optional)
Covers Byzantine group admission governance, PBFT-style Byzantine roster agreement, and evidence:
* **Roster Agreement:** Genesis, membership transitions, threshold policies, prepare/commit rounds.
* **Quorum & Evidence:** Quorum certificate headers (up to 128 signers, 192 members), equivocation proofs (up to 64), assembly, and verification.
* **Lifecycle:** Invitations, candidate vouchers, departures, suspensions, and ejections.
* **Handle Facade:** `GroupHandle`, local network distribution, staging, and group merge coordination.
* **Dependency:** Depends *only* on Core.

### Tier 3: `openpgp` Feature (Optional, Default Off)
* Pure-Rust OpenPGP key import and detached signing using `rpgp`.
* Decoupled from group logic; depends only on Core identity key access.

### Tier 4: `test-support` Feature (Optional, Default Off)
* Simulation hooks (`simulation-signing`, `simulation-authority`, `campaign`).
* Must never weaken or alter default production paths; additive only.

---

## 3. Defensive Limits (Preserve These)

These bounds protect the crate from denial-of-service, memory exhaustion, and snapshot restore failure:

1. **Snapshot Budget (Guarantees the 64 MiB Restore Invariant):**
   - Identities per installation: Configurable budget (default 16, ceiling 2,048).
   - Contacts per installation: 100,000 maximum aggregate across all identities (~20 MB).
   - Alias & label strings: 64 bytes UTF-8 maximum (reject on exceed, never truncate).
   - `seen_transcripts`: 262,144 entries maximum aggregate across all stores (~8 MB, evicts oldest on insert).
   - Roster lock table: 8,192 maximum parent entries (~0.8 MB).
   - Worst-case total: ~30 MiB, ensuring any valid saved snapshot reliably restores well within `MAX_SNAPSHOT_BYTES` (64 MiB).

2. **Handoff Bundle Bounds (Guards Against Untrusted Allocation):**
   - Total bundle cap: 5 MiB.
   - Checkpoints per bundle: 2,048 maximum.
   - Bytes per checkpoint: 64 KiB maximum.
   - Check bounds *before* allocating buffers or collections.

3. **Wire & Quorum Constants:**
   - `MAX_FRAME_BYTES` (Encounter): 512 B.
   - `MAX_FRAME_BYTES` (Group Handle): 128 KiB.
   - `MAX_CERTIFICATE_SIGNERS`: 128 signers.
   - `MAX_MEMBERS`: 192 members (fault bound $f=63$, quorum $Q=128$).
   - `MAX_CERTIFICATE_PROOFS`: 64 proofs.
   - `MAX_GROUPS`: 1,024 active groups per handle.

---

## 4. Testing & Parity Verification

All test suites must maintain strict parity:
* **Core Baseline:** 109 tests default (plus 1 doctest).
* **OpenPGP Baseline:** 128 tests with `--features openpgp` (including 19 OpenPGP import/export integration tests, plus 1 doctest).
* **Groups Baseline:** 379 tests with `--features groups` (379 passed, 1 ignored, plus 1 doctest).
* **All-Features Baseline:** 545 tests with all features (545 passed, 1 ignored long-running sweep, plus 1 doctest).
* Tests and known-answer vectors must be ported alongside the code and run with:
  ```bash
  cargo test
  cargo test --features groups
  cargo test --all-features
  cargo clippy --all-targets --all-features -- -D warnings
  ```
