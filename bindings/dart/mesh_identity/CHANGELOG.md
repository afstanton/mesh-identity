## 0.1.0

- Initial release of pure Dart bindings for `mesh-identity`.
- Full installation lifecycle: `MeshInstallation` creation (random or deterministic seed), `NativeFinalizer` cleanup, and explicit `.dispose()`.
- Multiple personas support: `addIdentity`, `selectIdentity`, `removeIdentity`, and `identities` listing directly from core installation state.
- Durable authenticated snapshot serialization (`save`) and byte-for-byte state recovery (`restore`).
- Contact store management: `contactsCount`, `getContact`, `blockContact`, and `importPeerKey`.
- Hardened FFI boundary: all `extern "C"` calls wrapped with `catch_unwind`, defensive pointer length bounds, zeroization of signing seeds, and structured numeric error code mapping to typed sealed Dart exceptions.
