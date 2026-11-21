## 0.4.0

- Added Byzantine Group Admission & Governance protocol support (Slice 4).
- Group handle controller: `MeshGroupHandle` initialized with fresh seed, restored from snapshot, or consuming an existing `MeshInstallation` with atomic ownership detachment (`MeshInstallation.finalizeTransfer()`).
- Byzantine group formation & genesis: `createGroup` and `importGenesis` with authenticated SHA-256 genesis digest verification.
- Verified contact admission vouchers: `invite`, `accept`, and `acceptAuthenticated` with out-of-band genesis verification. Enforces prerequisite that candidates must be verified contacts (`IneligibleException`).
- Two-phase commit outbox staging: `save(now)` producing `SaveToken` and snapshot blob, and `confirmSaved(token)` releasing staged frames and returning newly confirmed `GroupEvent`s. Outgoing messages are strictly withheld until durable save is confirmed.
- Network frame transmission: `takeOutgoing()` draining released `OutgoingMessage` instances ready for transport. Value equality and hashing deep-compare all recipient keys and authenticators.
- Group governance: `leaveGroup` initiating Byzantine consensus departure, `receiveBytes` processing inbound peer wire frames with immediate malformed frame rejection (`FrameRejectedEvent`).
- Operation inspection & resend: `resend(opId)` re-staging frames without re-signing, and `getOpState(opId)` tracking operation status.
- Strict defensive bounds: inbound wire frames and genesis frames capped at 128 KiB, snapshot blobs capped at 256 MiB, and genesis membership capped at 192 members before native buffer allocation.
- Lossless 64-bit precision across FFI and JSON: group IDs, sequence counters, and revisions mapped to Dart `BigInt` and JSON decimal strings.
- Added typed group exceptions: `IneligibleException`, `DuplicateGroupException`, `UnsupportedGroupException`, `GroupFormationException`, `GroupTooLargeException`, and `MalformedGroupException`.
- Comprehensive integration tests covering group creation, genesis import, verified invitation/consent/admission/join lifecycle, departure, snapshot persistence across restarts, withheld frames, and bounds validation.

## 0.3.0

- Added device-to-device handoff and voting role migration protocol (Slice 3).
- Device nonce management: lazy generation and retrieval (`getDeviceNonce`, `getCurrentDeviceNonce`) with persistent snapshot tracking.
- Monotonic voting roles: `VotingState` enum (`voting`, `stopped`, `gated`) and `VotingRecord` (lossless `BigInt` counter, state, holder).
- Gating and takeover claims: `gateVoting()` (gating all owned identities on the installation) and `beginTakeover(floor)` generating signed `TakeoverStatement` instances with lossless unsigned 64-bit `BigInt` counters.
- Transactional durable handoff: `beginHandoff(recipientNonce)` and `acceptHandoff(bundle)` returning post-transition snapshot bytes (`HandoffResult` and `AcceptHandoffResult`) with optional synchronous `onPersist` callbacks, preventing double-voting equivocation across node restarts.
- Unauthenticated envelope inspection: `HandoffBundle.fromBytes` decodes the CBOR envelope without authenticating signatures (signatures verified upon `acceptHandoff`).
- Pre-allocation defensive checks: `maxBundleBytes` (5 MiB ceiling), recipient nonces (32 bytes), identity keys (32 bytes), and non-negative floor counters validated in Dart before native FFI memory allocation.
- Invariant enforcement: stopped devices cannot sign or begin handoffs (`NotVotingDeviceException`), wrong recipient nonce rejection (`WrongHandoffRecipientException`), stale counter rejection (`StaleHandoffException`), un-gated takeover rejection (`NotGatedException`).
- Strict panic poisoning: every C-ABI function poisons the handle on caught native panic, including read-only queries.
- Added typed exceptions: `NotVotingDeviceException`, `InvalidHandoffException`, `StaleHandoffException`, `WrongHandoffRecipientException`, `CounterExhaustedException`, `NotGatedException`, and `HandoffWriteFailedException`.
- Added package developer guidelines in `AGENTS.md`.

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
