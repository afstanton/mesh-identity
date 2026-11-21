## 0.2.0

- Added cryptographic in-person Encounter ceremony protocol support (Slice 2).
- Initiator and responder workflows: `startEncounter`, `openScanner`, `scanOffer`, `scanResponse`, and `scanReveal`.
- Short Authentication String (SAS) derivation: `getComparison` returning 6-digit numeric comparison code with formatted string representation and required user-facing confirmation instructions.
- Enforced human SAS display invariant: `confirmAndSave` requires `getComparison` to be retrieved before confirmation, throwing `NoComparisonException` otherwise.
- Verified contact recording: `confirmAndSave` verifying peer SAS codes, updating `VerificationStatus.verified`, and recording transcripts into the identity store.
- Optical QR transport abstraction: `QrTransport.encodeUri` and `decodeUri` for `mesh:encounter:<base64>` payloads with 512-byte frame ceiling.
- Pre-allocation defensive checks: payload frames (> 512 bytes), snapshot payloads (> 64 MiB), and seed counts (> 2048) validated in Dart before native buffer allocation.
- Required caller-managed identity seeds via `MeshInstallation({required Uint8List seed})` and `MeshInstallation.generateSeed()` to ensure all identities can be restored from snapshots.
- Millisecond time units across FFI for session expiry, rate limiting, and attempt policies, with second timestamps reserved for durable contact records.
- Explicit ceremony cancellation: `cancelCeremony` releases installation state and disposes the native handle immediately.
- Added typed exceptions: `CeremonyActiveException`, `StaleCeremonyException`, `EncounterProtocolException`, `RateLimitedException`, `NoComparisonException`, `IndexOutOfBoundsException`, and `DisposedException`.

## 0.1.0

- Initial release of pure Dart bindings for `mesh-identity`.
- Full installation lifecycle: `MeshInstallation` creation (random or deterministic seed), `NativeFinalizer` cleanup, and explicit `.dispose()`.
- Multiple personas support: `addIdentity`, `selectIdentity`, `removeIdentity`, and `identities` listing directly from core installation state.
- Durable authenticated snapshot serialization (`save`) and byte-for-byte state recovery (`restore`).
- Contact store management: `contactsCount`, `getContact`, `blockContact`, and `importPeerKey`.
- Hardened FFI boundary: all `extern "C"` calls wrapped with `catch_unwind`, defensive pointer length bounds, zeroization of signing seeds, and structured numeric error code mapping to typed sealed Dart exceptions.
