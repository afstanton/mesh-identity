use ed25519_dalek::SigningKey;
use mesh_identity::contact::{ContactStatus, VerificationStatus};
use mesh_identity::session::Comparison;
use mesh_identity::session::installation::{Ceremony, Installation};
use pgp::types::KeyDetails;
use rand::rngs::OsRng;
use serde::Serialize;
use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::c_char;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;
use std::time::{Duration, SystemTime};
use zeroize::Zeroize;

pub const MESH_OK: i32 = 0;
pub const MESH_ERR_PANIC: i32 = -1;
pub const MESH_ERR_INVALID_ARG: i32 = -2;
pub const MESH_ERR_UNKNOWN_IDENTITY: i32 = -3;
pub const MESH_ERR_SELECTED_IDENTITY: i32 = -4;
pub const MESH_ERR_CAPACITY_EXCEEDED: i32 = -5;
pub const MESH_ERR_INVALID_SNAPSHOT: i32 = -6;
pub const MESH_ERR_NOT_FOUND: i32 = -7;
pub const MESH_ERR_INTERNAL: i32 = -8;
pub const MESH_ERR_CEREMONY_ACTIVE: i32 = -9;
pub const MESH_ERR_STALE_CEREMONY: i32 = -10;
pub const MESH_ERR_PROTOCOL: i32 = -11;
pub const MESH_ERR_RATE_LIMITED: i32 = -12;
pub const MESH_ERR_INDEX_OUT_OF_BOUNDS: i32 = -13;
pub const MESH_ERR_NO_COMPARISON: i32 = -14;
pub const MESH_ERR_NOT_VOTING_DEVICE: i32 = -15;
pub const MESH_ERR_INVALID_HANDOFF: i32 = -16;
pub const MESH_ERR_STALE_HANDOFF: i32 = -17;
pub const MESH_ERR_WRONG_HANDOFF_RECIPIENT: i32 = -18;
pub const MESH_ERR_COUNTER_EXHAUSTED: i32 = -19;
pub const MESH_ERR_NOT_GATED: i32 = -20;
pub const MESH_ERR_HANDOFF_WRITE_FAILED: i32 = -21;
pub const MESH_ERR_UNSUPPORTED: i32 = -22;
pub const MESH_ERR_INELIGIBLE: i32 = -23;
pub const MESH_ERR_DUPLICATE_GROUP: i32 = -24;
pub const MESH_ERR_TOO_LARGE: i32 = -25;
pub const MESH_ERR_MALFORMED: i32 = -26;
pub const MESH_ERR_FORMATION: i32 = -27;
pub const MESH_ERR_ALIAS_CONFLICT: i32 = -28;

// OpenPGP error codes
pub const MESH_ERR_OPENPGP_CERTIFICATE: i32 = -3001;
pub const MESH_ERR_OPENPGP_INVALID_BINDING: i32 = -3002;
pub const MESH_ERR_OPENPGP_KEY_MISMATCH: i32 = -3003;
pub const MESH_ERR_OPENPGP_SECRET_MATERIAL: i32 = -3004;
pub const MESH_ERR_OPENPGP_SECRET_MISSING: i32 = -3005;
pub const MESH_ERR_OPENPGP_REVOCATION_CAPACITY: i32 = -3006;
pub const MESH_ERR_OPENPGP_PREVIEW_EXPIRED: i32 = -3007;

const MAX_SEEDS_CEILING: usize = 2048;
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024; // 64 MiB
const MAX_HANDOFF_BUNDLE_BYTES: usize = 5 * 1024 * 1024; // 5 MiB
const MAX_GROUP_FRAME_BYTES: usize = 128 * 1024; // 128 KiB (matching core MAX_FRAME_BYTES)
const MAX_GROUP_SNAPSHOT_BYTES: usize = 256 * 1024 * 1024; // 256 MiB (matching core MAX_HANDLE_BYTES)
const MAX_GROUP_MEMBERS: usize = 192; // matching core MAX_MEMBERS
const MAX_OPENPGP_CERTIFICATE_BYTES: usize = 256 * 1024; // 256 KiB
const MAX_OPENPGP_DOCUMENT_BYTES: usize = 16 * 1024 * 1024; // 16 MiB
const MAX_OPENPGP_USER_ID_BYTES: usize = 2048;
const MAX_OPENPGP_PASSPHRASE_BYTES: usize = 2048;
const MAX_ALIAS_INPUT_BYTES: usize = 256;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
    static LAST_RATE_LIMIT_UNTIL_MS: RefCell<Option<u64>> = const { RefCell::new(None) };
}

fn clear_last_error() {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = None;
    });
    LAST_RATE_LIMIT_UNTIL_MS.with(|cell| {
        *cell.borrow_mut() = None;
    });
}

fn set_last_error(msg: impl Into<String>) {
    LAST_ERROR.with(|cell| {
        *cell.borrow_mut() = Some(msg.into());
    });
}

fn map_installation_error(err: &mesh_identity::session::installation::Error) -> i32 {
    use mesh_identity::session::installation::Error;
    match err {
        Error::UnknownIdentity => MESH_ERR_UNKNOWN_IDENTITY,
        Error::SelectedIdentity => MESH_ERR_SELECTED_IDENTITY,
        Error::IdentityLimitExceeded | Error::RosterLockCapacityExceeded => {
            MESH_ERR_CAPACITY_EXCEEDED
        }
        Error::DuplicateIdentity | Error::KeyPairMismatch | Error::InvalidConfiguration => {
            MESH_ERR_INVALID_ARG
        }
        Error::InvalidContactLink | Error::InvalidRosterCheckpoint => MESH_ERR_INVALID_SNAPSHOT,
        Error::InvalidHandoff | Error::RosterSigningStateUnconfirmed => MESH_ERR_INVALID_HANDOFF,
        Error::StaleHandoff => MESH_ERR_STALE_HANDOFF,
        Error::WrongHandoffRecipient => MESH_ERR_WRONG_HANDOFF_RECIPIENT,
        Error::NotVotingDevice => MESH_ERR_NOT_VOTING_DEVICE,
        Error::NotGated => MESH_ERR_NOT_GATED,
        Error::CounterExhausted => MESH_ERR_COUNTER_EXHAUSTED,
        Error::HandoffWriteFailed => MESH_ERR_HANDOFF_WRITE_FAILED,
        Error::CeremonyActive => MESH_ERR_CEREMONY_ACTIVE,
        Error::StaleCeremony => MESH_ERR_STALE_CEREMONY,
        Error::Session(mesh_identity::session::SessionError::Attempt(attempt)) => {
            if let mesh_identity::session::AttemptError::Paused { until_ms } = attempt {
                LAST_RATE_LIMIT_UNTIL_MS.with(|cell| {
                    *cell.borrow_mut() = Some(*until_ms);
                });
            }
            MESH_ERR_RATE_LIMITED
        }
        Error::Session(mesh_identity::session::SessionError::Protocol(_)) => MESH_ERR_PROTOCOL,
        Error::Session(mesh_identity::session::SessionError::NoLiveSession) => {
            MESH_ERR_STALE_CEREMONY
        }
        Error::Session(mesh_identity::session::SessionError::StaleComparison) => {
            MESH_ERR_NO_COMPARISON
        }
        Error::Session(mesh_identity::session::SessionError::Store(
            mesh_identity::contact::StoreError::StoreFull,
        )) => MESH_ERR_CAPACITY_EXCEEDED,
        Error::Session(mesh_identity::session::SessionError::Store(
            mesh_identity::contact::StoreError::UnknownContact,
        )) => MESH_ERR_NOT_FOUND,
        Error::Session(mesh_identity::session::SessionError::Store(
            mesh_identity::contact::StoreError::AliasConflict { .. },
        )) => MESH_ERR_ALIAS_CONFLICT,
        Error::Session(mesh_identity::session::SessionError::Store(
            mesh_identity::contact::StoreError::EmptyAlias
            | mesh_identity::contact::StoreError::AliasTooLong,
        )) => MESH_ERR_INVALID_ARG,
        _ => MESH_ERR_INTERNAL,
    }
}

/// Retrieve the last recorded error message on the calling thread.
///
/// # Safety
///
/// - `out_buf` must be a valid, writable pointer to at least `max_len` bytes.
/// - `max_len` must be greater than 0.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_last_error(out_buf: *mut c_char, max_len: usize) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_buf.is_null() || max_len == 0 {
            return MESH_ERR_INVALID_ARG;
        }
        LAST_ERROR.with(|cell| {
            let msg = cell.borrow_mut().take().unwrap_or_default();
            let c_str = match CString::new(msg) {
                Ok(s) => s,
                Err(_) => return MESH_ERR_INTERNAL,
            };
            let bytes = c_str.as_bytes_with_nul();
            let copy_len = bytes.len().min(max_len);
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, out_buf, copy_len);
                if copy_len == max_len {
                    *out_buf.add(max_len - 1) = 0;
                }
            }
            MESH_OK
        })
    }));
    result.unwrap_or(MESH_ERR_PANIC)
}

/// Retrieve and clear the last recorded rate-limit pause deadline (`until_ms`) on the calling thread.
///
/// # Safety
///
/// - `out_until_ms` and `out_has_value` must be valid, non-null writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_last_rate_limit_until_ms(
    out_until_ms: *mut u64,
    out_has_value: *mut bool,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_until_ms.is_null() || out_has_value.is_null() {
            return MESH_ERR_INVALID_ARG;
        }
        LAST_RATE_LIMIT_UNTIL_MS.with(|cell| {
            match cell.borrow_mut().take() {
                Some(until_ms) => unsafe {
                    *out_until_ms = until_ms;
                    *out_has_value = true;
                },
                None => unsafe {
                    *out_until_ms = 0;
                    *out_has_value = false;
                },
            }
            MESH_OK
        })
    }));
    result.unwrap_or(MESH_ERR_PANIC)
}

enum InstallationBacking {
    Owned(Box<Installation>),
    /// Non-owning pointer into a live `MeshGroupHandle`.
    /// Dropping the wrapper box never frees the parent `MeshGroupHandle`.
    BorrowedGroup(*mut MeshGroupHandle),
}

/// Opaque wrapper around a local identity `Installation` (owned or borrowed from `MeshGroupHandle`).
pub struct MeshInstallationHandle {
    backing: InstallationBacking,
    pub is_poisoned: bool,
}

impl MeshInstallationHandle {
    fn owned(installation: Installation) -> Self {
        Self {
            backing: InstallationBacking::Owned(Box::new(installation)),
            is_poisoned: false,
        }
    }

    fn is_borrowed(&self) -> bool {
        matches!(self.backing, InstallationBacking::BorrowedGroup(_))
    }

    fn is_poisoned(&self) -> bool {
        match self.backing {
            InstallationBacking::Owned(_) => self.is_poisoned,
            InstallationBacking::BorrowedGroup(ptr) => {
                self.is_poisoned || unsafe { (&*ptr).is_poisoned }
            }
        }
    }

    fn set_poisoned(&mut self) {
        self.is_poisoned = true;
        if let InstallationBacking::BorrowedGroup(ptr) = self.backing {
            unsafe {
                (*ptr).is_poisoned = true;
            }
        }
    }

    fn installation(&self) -> &Installation {
        match self.backing {
            InstallationBacking::Owned(ref inst) => inst,
            InstallationBacking::BorrowedGroup(ptr) => unsafe {
                (*ptr).group_handle.installation()
            },
        }
    }

    fn installation_mut(&mut self) -> &mut Installation {
        match self.backing {
            InstallationBacking::Owned(ref mut inst) => inst,
            InstallationBacking::BorrowedGroup(ptr) => unsafe {
                (*ptr).group_handle.installation_mut()
            },
        }
    }

    fn into_owned(self) -> Option<Installation> {
        match self.backing {
            InstallationBacking::Owned(inst) => Some(*inst),
            InstallationBacking::BorrowedGroup(_) => None,
        }
    }
}

/// Create a new local `Installation` with an initial Ed25519 identity.
///
/// If `seed_ptr` is null and `seed_len` is 0, a fresh identity is generated using `OsRng`.
/// If a seed is provided, `seed_len` must be exactly 32.
///
/// # Safety
///
/// - `out_handle` must be a valid, non-null pointer to a `*mut MeshInstallationHandle`.
/// - If `seed_ptr` is non-null, it must point to at least `seed_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_create(
    seed_ptr: *const u8,
    seed_len: usize,
    out_handle: *mut *mut MeshInstallationHandle,
) -> i32 {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_handle.is_null() {
            set_last_error("out_handle pointer is null");
            return MESH_ERR_INVALID_ARG;
        }
        if seed_ptr.is_null() || seed_len != 32 {
            set_last_error("seed must be a non-null pointer to exactly 32 bytes");
            return MESH_ERR_INVALID_ARG;
        }

        let bytes = unsafe { slice::from_raw_parts(seed_ptr, 32) };
        let mut seed = [0u8; 32];
        seed.copy_from_slice(bytes);
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();

        let inst = Installation::new(signing_key);
        let handle = Box::into_raw(Box::new(MeshInstallationHandle::owned(inst)));
        unsafe {
            *out_handle = handle;
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        set_last_error("native panic caught at FFI boundary");
        MESH_ERR_PANIC
    })
}

/// Free a `MeshInstallationHandle` previously allocated by `mesh_installation_create` or `mesh_installation_restore`.
///
/// # Safety
///
/// - `handle` must be null or a valid pointer to a `MeshInstallationHandle` that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_free(handle: *mut MeshInstallationHandle) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !handle.is_null() {
            drop(unsafe { Box::from_raw(handle) });
        }
    }));
}

/// Set the maximum number of identities allowed in this installation.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_set_max_identities(
    handle: *mut MeshInstallationHandle,
    limit: usize,
) -> i32 {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_last_error("null handle passed to mesh_installation_set_max_identities");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        match handle.installation_mut().set_max_identities(limit) {
            Ok(()) => MESH_OK,
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle.is_null() {
            unsafe {
                (*handle).set_poisoned();
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Copy the 32-byte public key of the currently selected identity into `out_pk`.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `out_pk` must point to a writable buffer of at least `out_pk_len` bytes.
/// - `out_pk_len` must be at least 32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_selected(
    handle: *const MeshInstallationHandle,
    out_pk: *mut u8,
    out_pk_len: usize,
) -> i32 {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_pk.is_null() || out_pk_len < 32 {
            set_last_error("invalid arguments passed to mesh_installation_selected");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &*handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let selected = handle.installation().selected();
        unsafe {
            std::ptr::copy_nonoverlapping(selected.as_ptr(), out_pk, 32);
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        set_last_error("native panic caught at FFI boundary");
        MESH_ERR_PANIC
    })
}

/// Return the total number of identities registered in this installation.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_identities_count(
    handle: *const MeshInstallationHandle,
) -> usize {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return 0;
        }
        let handle = unsafe { &*handle };
        if handle.is_poisoned() {
            return 0;
        }
        handle.installation().identities().len()
    }));
    result.unwrap_or(0)
}

/// Retrieve the 32-byte public key of the identity at the given zero-based index.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `out_pk` must point to a writable buffer of at least `out_pk_len` bytes.
/// - `out_pk_len` must be at least 32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_identities_get(
    handle: *const MeshInstallationHandle,
    index: usize,
    out_pk: *mut u8,
    out_pk_len: usize,
) -> i32 {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_pk.is_null() || out_pk_len < 32 {
            set_last_error("invalid arguments passed to mesh_installation_identities_get");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &*handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let identities = handle.installation().identities();
        if let Some(pk) = identities.get(index) {
            unsafe {
                std::ptr::copy_nonoverlapping(pk.as_ptr(), out_pk, 32);
            }
            MESH_OK
        } else {
            set_last_error("index out of bounds in mesh_installation_identities_get");
            MESH_ERR_INDEX_OUT_OF_BOUNDS
        }
    }));
    result.unwrap_or_else(|_| {
        set_last_error("native panic caught at FFI boundary");
        MESH_ERR_PANIC
    })
}

/// Switch the active identity to the given public key.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `key_ptr` must point to at least `key_len` readable bytes.
/// - `key_len` must be exactly 32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_select_identity(
    handle: *mut MeshInstallationHandle,
    key_ptr: *const u8,
    key_len: usize,
    now: u64,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || key_ptr.is_null() || key_len != 32 {
            set_last_error("invalid arguments passed to mesh_installation_select_identity");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let bytes = unsafe { slice::from_raw_parts(key_ptr, 32) };
        let mut identity = [0u8; 32];
        identity.copy_from_slice(bytes);

        match handle.installation_mut().select(identity, now) {
            Ok(()) => MESH_OK,
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Add an additional persona identity from a 32-byte Ed25519 signing seed.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `seed_ptr` must point to at least `seed_len` readable bytes.
/// - `seed_len` must be exactly 32.
/// - If `out_pk` is non-null, `out_pk_len` must be at least 32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_add_identity(
    handle: *mut MeshInstallationHandle,
    seed_ptr: *const u8,
    seed_len: usize,
    out_pk: *mut u8,
    out_pk_len: usize,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || seed_ptr.is_null() || seed_len != 32 {
            set_last_error("invalid parameters for mesh_installation_add_identity");
            return MESH_ERR_INVALID_ARG;
        }
        if !out_pk.is_null() && out_pk_len < 32 {
            set_last_error("out_pk buffer too small");
            return MESH_ERR_INVALID_ARG;
        }

        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let bytes = unsafe { slice::from_raw_parts(seed_ptr, 32) };
        let mut seed = [0u8; 32];
        seed.copy_from_slice(bytes);
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let pk = signing_key.verifying_key().to_bytes();

        match handle.installation_mut().add_identity(signing_key) {
            Ok(_) => {
                if !out_pk.is_null() {
                    unsafe {
                        std::ptr::copy_nonoverlapping(pk.as_ptr(), out_pk, 32);
                    }
                }
                MESH_OK
            }
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Remove an inactive identity by its 32-byte public key.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `key_ptr` must point to at least `key_len` readable bytes.
/// - `key_len` must be exactly 32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_remove_identity(
    handle: *mut MeshInstallationHandle,
    key_ptr: *const u8,
    key_len: usize,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || key_ptr.is_null() || key_len != 32 {
            set_last_error("invalid arguments passed to mesh_installation_remove_identity");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let bytes = unsafe { slice::from_raw_parts(key_ptr, 32) };
        let mut identity = [0u8; 32];
        identity.copy_from_slice(bytes);

        match handle.installation_mut().remove_identity(identity) {
            Ok(()) => MESH_OK,
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Serialize the installation into an authenticated snapshot byte buffer.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `out_buf` and `out_len` must be valid, non-null writable pointers.
/// - The buffer written to `*out_buf` must be deallocated via `mesh_buffer_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_save(
    handle: *mut MeshInstallationHandle,
    now: u64,
    out_buf: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_buf.is_null() || out_len.is_null() {
            set_last_error("invalid pointers passed to mesh_installation_save");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        match handle.installation_mut().save_bytes(now) {
            Ok(bytes) => {
                let mut boxed = bytes.into_boxed_slice();
                unsafe {
                    *out_len = boxed.len();
                    *out_buf = boxed.as_mut_ptr();
                }
                std::mem::forget(boxed);
                MESH_OK
            }
            Err(e) => {
                set_last_error(e.to_string());
                match e {
                    mesh_identity::session::installation::SnapshotError::TooLarge => {
                        MESH_ERR_CAPACITY_EXCEEDED
                    }
                    _ => MESH_ERR_INVALID_SNAPSHOT,
                }
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Free a byte buffer allocated by `mesh_installation_save`, `mesh_installation_start`, `mesh_installation_scan_offer`, or `mesh_installation_scan_response`.
///
/// # Safety
///
/// - `buf` must be null or point to a buffer allocated by this library of length `len`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_buffer_free(buf: *mut u8, len: usize) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !buf.is_null() && len > 0 {
            drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(buf, len)) });
        }
    }));
}

/// Restore an installation from snapshot bytes and known signing seeds.
///
/// # Safety
///
/// - `bytes_ptr` must point to at least `bytes_len` readable bytes.
/// - `seeds_ptr` must point to at least `seeds_count * 32` readable bytes.
/// - `out_handle` must be a valid, non-null pointer to a `*mut MeshInstallationHandle`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_restore(
    bytes_ptr: *const u8,
    bytes_len: usize,
    seeds_ptr: *const u8,
    seeds_count: usize,
    out_handle: *mut *mut MeshInstallationHandle,
) -> i32 {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_handle.is_null() {
            set_last_error("out_handle pointer is null");
            return MESH_ERR_INVALID_ARG;
        }
        if bytes_ptr.is_null() || bytes_len == 0 || bytes_len > MAX_SNAPSHOT_BYTES {
            set_last_error("invalid snapshot bytes or length");
            return MESH_ERR_INVALID_SNAPSHOT;
        }
        if seeds_ptr.is_null() || seeds_count == 0 || seeds_count > MAX_SEEDS_CEILING {
            set_last_error("invalid seeds pointer or count exceeds ceiling");
            return MESH_ERR_INVALID_ARG;
        }

        let total_seed_bytes = match seeds_count.checked_mul(32) {
            Some(b) => b,
            None => {
                set_last_error("seed length calculation overflowed");
                return MESH_ERR_INVALID_ARG;
            }
        };

        let snapshot_bytes = unsafe { slice::from_raw_parts(bytes_ptr, bytes_len) };
        let raw_seeds = unsafe { slice::from_raw_parts(seeds_ptr, total_seed_bytes) };

        let mut signing_keys = Vec::with_capacity(seeds_count);
        for chunk in raw_seeds.as_chunks::<32>().0 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(chunk);
            let key = SigningKey::from_bytes(&seed);
            seed.zeroize();
            signing_keys.push(key);
        }

        match Installation::restore_bytes(snapshot_bytes, signing_keys) {
            Ok(inst) => {
                let handle = Box::into_raw(Box::new(MeshInstallationHandle::owned(inst)));
                unsafe {
                    *out_handle = handle;
                }
                MESH_OK
            }
            Err(e) => {
                set_last_error(e.to_string());
                match e {
                    mesh_identity::session::installation::SnapshotError::TooLarge => {
                        MESH_ERR_CAPACITY_EXCEEDED
                    }
                    _ => MESH_ERR_INVALID_SNAPSHOT,
                }
            }
        }
    }));
    result.unwrap_or_else(|_| {
        set_last_error("native panic caught at FFI boundary");
        MESH_ERR_PANIC
    })
}

#[derive(Serialize)]
struct ContactExportJson {
    pub peer_public_key: String,
    pub alias: Option<String>,
    pub status: String,
    pub verification_status: String,
    pub encounter_count: u64,
    pub verified_at: u64,
}

fn contact_to_json(c: &mesh_identity::contact::ContactRecordV1) -> ContactExportJson {
    ContactExportJson {
        peer_public_key: hex::encode(c.peer_ed25519_pk),
        alias: c.local_alias.clone(),
        status: match c.status {
            ContactStatus::Active => "active".into(),
            ContactStatus::Blocked => "blocked".into(),
        },
        verification_status: match c.verification_status {
            VerificationStatus::Verified => "verified".into(),
            VerificationStatus::ImportedUnverified => "imported_unverified".into(),
        },
        encounter_count: c.encounter_count,
        verified_at: c.verified_at,
    }
}

fn resolve_identity_arg(
    installation: &Installation,
    identity_pk: *const u8,
    identity_pk_len: usize,
) -> Result<[u8; 32], i32> {
    if identity_pk.is_null() {
        return Ok(installation.selected());
    }
    if identity_pk_len != 32 {
        set_last_error("identity_pk must be 32 bytes");
        return Err(MESH_ERR_INVALID_ARG);
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(unsafe { slice::from_raw_parts(identity_pk, 32) });
    Ok(pk)
}

/// Return the count of contacts registered for an identity.
///
/// If `identity_pk` is null, uses the selected identity.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - If `identity_pk` is non-null, `identity_pk_len` must be 32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_contacts_count(
    handle: *const MeshInstallationHandle,
    identity_pk: *const u8,
    identity_pk_len: usize,
) -> usize {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return 0;
        }
        let handle = unsafe { &*handle };
        if handle.is_poisoned() {
            return 0;
        }
        let id = if identity_pk.is_null() {
            handle.installation().selected()
        } else {
            if identity_pk_len != 32 {
                return 0;
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(unsafe { slice::from_raw_parts(identity_pk, 32) });
            pk
        };

        handle
            .installation()
            .contacts(id)
            .map(|c| c.count())
            .unwrap_or(0)
    }));
    result.unwrap_or(0)
}

/// Retrieve a contact record formatted as a JSON string.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - If `identity_pk` is non-null, `identity_pk_len` must be 32.
/// - `peer_pk` must point to at least `peer_pk_len` readable bytes (must be 32).
/// - `out_json` must be a valid, non-null writable pointer.
/// - The allocated string in `*out_json` must be freed with `mesh_string_free`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_get_contact(
    handle: *const MeshInstallationHandle,
    identity_pk: *const u8,
    identity_pk_len: usize,
    peer_pk: *const u8,
    peer_pk_len: usize,
    out_json: *mut *mut c_char,
) -> i32 {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || peer_pk.is_null() || peer_pk_len != 32 || out_json.is_null() {
            set_last_error("invalid arguments passed to mesh_installation_get_contact");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &*handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let id = if identity_pk.is_null() {
            handle.installation().selected()
        } else {
            if identity_pk_len != 32 {
                set_last_error("identity_pk must be 32 bytes");
                return MESH_ERR_INVALID_ARG;
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(unsafe { slice::from_raw_parts(identity_pk, 32) });
            pk
        };

        let mut peer = [0u8; 32];
        peer.copy_from_slice(unsafe { slice::from_raw_parts(peer_pk, 32) });

        let store = match handle.installation().contacts(id) {
            Some(s) => s,
            None => {
                set_last_error("unknown identity in mesh_installation_get_contact");
                return MESH_ERR_UNKNOWN_IDENTITY;
            }
        };

        match store.get(&peer) {
            Some(c) => {
                let info = contact_to_json(c);
                let json_str = match serde_json::to_string(&info) {
                    Ok(s) => s,
                    Err(e) => {
                        set_last_error(e.to_string());
                        return MESH_ERR_INTERNAL;
                    }
                };
                let c_str = match CString::new(json_str) {
                    Ok(s) => s,
                    Err(_) => return MESH_ERR_INTERNAL,
                };
                unsafe {
                    *out_json = c_str.into_raw();
                }
                MESH_OK
            }
            None => MESH_ERR_NOT_FOUND,
        }
    }));
    result.unwrap_or_else(|_| {
        set_last_error("native panic caught at FFI boundary");
        MESH_ERR_PANIC
    })
}

/// Free a C string allocated by `mesh_installation_get_contact` or `mesh_installation_confirm_and_save`.
///
/// # Safety
///
/// - `ptr` must be null or point to a C string allocated by this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_string_free(ptr: *mut c_char) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !ptr.is_null() {
            drop(unsafe { CString::from_raw(ptr) });
        }
    }));
}

/// Block a peer contact.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - If `identity_pk` is non-null, `identity_pk_len` must be 32.
/// - `peer_pk` must point to at least `peer_pk_len` readable bytes (`peer_pk_len` must be 32).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_block_contact(
    handle: *mut MeshInstallationHandle,
    identity_pk: *const u8,
    identity_pk_len: usize,
    peer_pk: *const u8,
    peer_pk_len: usize,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || peer_pk.is_null() || peer_pk_len != 32 {
            set_last_error("invalid arguments passed to mesh_installation_block_contact");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let id = if identity_pk.is_null() {
            handle.installation().selected()
        } else {
            if identity_pk_len != 32 {
                set_last_error("identity_pk must be 32 bytes");
                return MESH_ERR_INVALID_ARG;
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(unsafe { slice::from_raw_parts(identity_pk, 32) });
            pk
        };

        let mut peer = [0u8; 32];
        peer.copy_from_slice(unsafe { slice::from_raw_parts(peer_pk, 32) });

        match handle.installation_mut().block_contact(id, peer) {
            Ok(()) => MESH_OK,
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// List all contact records for an identity as a JSON array string in `*out_json`.
///
/// If `identity_pk` is null, uses the selected identity.
/// The string written to `*out_json` must be freed via `mesh_string_free`.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - If `identity_pk` is non-null, `identity_pk_len` must be 32.
/// - `out_json` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_list_contacts(
    handle: *const MeshInstallationHandle,
    identity_pk: *const u8,
    identity_pk_len: usize,
    out_json: *mut *mut c_char,
) -> i32 {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_json.is_null() {
            set_last_error("invalid arguments passed to mesh_installation_list_contacts");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &*handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let id = match resolve_identity_arg(handle.installation(), identity_pk, identity_pk_len) {
            Ok(pk) => pk,
            Err(code) => return code,
        };
        let store = match handle.installation().contacts(id) {
            Some(s) => s,
            None => {
                set_last_error("unknown identity in mesh_installation_list_contacts");
                return MESH_ERR_UNKNOWN_IDENTITY;
            }
        };

        let mut list: Vec<ContactExportJson> = store.iter().map(contact_to_json).collect();
        list.sort_by(|a, b| a.peer_public_key.cmp(&b.peer_public_key));

        let json_str = match serde_json::to_string(&list) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        let c_str = match CString::new(json_str) {
            Ok(s) => s,
            Err(_) => return MESH_ERR_INTERNAL,
        };
        unsafe {
            *out_json = c_str.into_raw();
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        set_last_error("native panic caught at FFI boundary");
        MESH_ERR_PANIC
    })
}

/// Unblock a previously blocked peer contact without altering its verification state.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - If `identity_pk` is non-null, `identity_pk_len` must be 32.
/// - `peer_pk` must point to at least `peer_pk_len` readable bytes (`peer_pk_len` must be 32).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_unblock_contact(
    handle: *mut MeshInstallationHandle,
    identity_pk: *const u8,
    identity_pk_len: usize,
    peer_pk: *const u8,
    peer_pk_len: usize,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || peer_pk.is_null() || peer_pk_len != 32 {
            set_last_error("invalid arguments passed to mesh_installation_unblock_contact");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let id = match resolve_identity_arg(handle.installation(), identity_pk, identity_pk_len) {
            Ok(pk) => pk,
            Err(code) => return code,
        };
        let mut peer = [0u8; 32];
        peer.copy_from_slice(unsafe { slice::from_raw_parts(peer_pk, 32) });

        match handle.installation_mut().unblock_contact(id, peer) {
            Ok(()) => MESH_OK,
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Set or update the local alias for a peer contact.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - If `identity_pk` is non-null, `identity_pk_len` must be 32.
/// - `peer_pk` must point to at least `peer_pk_len` readable bytes (`peer_pk_len` must be 32).
/// - `alias_ptr` must point to at least `alias_len` readable UTF-8 bytes (`alias_len <= 256`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_set_contact_alias(
    handle: *mut MeshInstallationHandle,
    identity_pk: *const u8,
    identity_pk_len: usize,
    peer_pk: *const u8,
    peer_pk_len: usize,
    alias_ptr: *const u8,
    alias_len: usize,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || peer_pk.is_null()
            || peer_pk_len != 32
            || alias_ptr.is_null()
            || alias_len > MAX_ALIAS_INPUT_BYTES
        {
            set_last_error("invalid arguments passed to mesh_installation_set_contact_alias");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let id = match resolve_identity_arg(handle.installation(), identity_pk, identity_pk_len) {
            Ok(pk) => pk,
            Err(code) => return code,
        };
        let mut peer = [0u8; 32];
        peer.copy_from_slice(unsafe { slice::from_raw_parts(peer_pk, 32) });

        let alias_bytes = unsafe { slice::from_raw_parts(alias_ptr, alias_len) };
        let alias_str = match std::str::from_utf8(alias_bytes) {
            Ok(s) => s,
            Err(_) => {
                set_last_error("alias must be valid UTF-8");
                return MESH_ERR_INVALID_ARG;
            }
        };

        match handle
            .installation_mut()
            .set_contact_alias(id, peer, alias_str)
        {
            Ok(()) => MESH_OK,
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Import a peer public key into a local contact store without verification.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - If `local_pk` is non-null, `local_pk_len` must be 32.
/// - `peer_pk` must point to at least `peer_pk_len` readable bytes (`peer_pk_len` must be 32).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_import_peer_key(
    handle: *mut MeshInstallationHandle,
    local_pk: *const u8,
    local_pk_len: usize,
    peer_pk: *const u8,
    peer_pk_len: usize,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || peer_pk.is_null() || peer_pk_len != 32 {
            set_last_error("invalid arguments passed to mesh_installation_import_peer_key");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let local = if local_pk.is_null() {
            handle.installation().selected()
        } else {
            if local_pk_len != 32 {
                set_last_error("local_pk must be 32 bytes");
                return MESH_ERR_INVALID_ARG;
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(unsafe { slice::from_raw_parts(local_pk, 32) });
            pk
        };

        let mut peer = [0u8; 32];
        peer.copy_from_slice(unsafe { slice::from_raw_parts(peer_pk, 32) });

        match handle
            .installation_mut()
            .import_peer_key(local, peer, &mut OsRng)
        {
            Ok(_) => MESH_OK,
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Opaque wrapper around an active Encounter ceremony handle.
pub struct MeshCeremonyHandle {
    pub ceremony: Ceremony,
    pub comparison: Option<Comparison>,
}

/// Free a `MeshCeremonyHandle`.
///
/// # Safety
///
/// - `handle` must be null or a valid pointer to a `MeshCeremonyHandle` that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_ceremony_free(handle: *mut MeshCeremonyHandle) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !handle.is_null() {
            drop(unsafe { Box::from_raw(handle) });
        }
    }));
}

/// Start an in-person Encounter ceremony as initiator.
///
/// Returns an allocated `MeshCeremonyHandle` in `*out_ceremony` and the initial offer payload in `*out_payload`.
/// The buffer in `*out_payload` must be freed with `mesh_buffer_free`.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `out_ceremony`, `out_payload`, and `out_payload_len` must be valid, non-null writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_start(
    handle: *mut MeshInstallationHandle,
    now: u64,
    out_ceremony: *mut *mut MeshCeremonyHandle,
    out_payload: *mut *mut u8,
    out_payload_len: *mut usize,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || out_ceremony.is_null()
            || out_payload.is_null()
            || out_payload_len.is_null()
        {
            set_last_error("invalid arguments passed to mesh_installation_start");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        match handle.installation_mut().start(now, &mut OsRng) {
            Ok((ceremony, payload)) => {
                let ceremony_handle = Box::into_raw(Box::new(MeshCeremonyHandle {
                    ceremony,
                    comparison: None,
                }));
                let mut boxed = payload.into_boxed_slice();
                unsafe {
                    *out_ceremony = ceremony_handle;
                    *out_payload_len = boxed.len();
                    *out_payload = boxed.as_mut_ptr();
                }
                std::mem::forget(boxed);
                MESH_OK
            }
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Open a ceremony scanner as responder.
///
/// Returns an allocated `MeshCeremonyHandle` in `*out_ceremony`.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `out_ceremony` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_open_scanner(
    handle: *mut MeshInstallationHandle,
    now: u64,
    out_ceremony: *mut *mut MeshCeremonyHandle,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_ceremony.is_null() {
            set_last_error("invalid arguments passed to mesh_installation_open_scanner");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        match handle.installation_mut().open_scanner(now) {
            Ok(ceremony) => {
                let ceremony_handle = Box::into_raw(Box::new(MeshCeremonyHandle {
                    ceremony,
                    comparison: None,
                }));
                unsafe {
                    *out_ceremony = ceremony_handle;
                }
                MESH_OK
            }
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Responder scans the initiator's offer payload and produces a response payload.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `ceremony` must be a valid, non-null pointer to a `MeshCeremonyHandle`.
/// - `bytes` must point to at least `bytes_len` readable bytes.
/// - `out_payload` and `out_payload_len` must be valid, non-null writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_scan_offer(
    handle: *mut MeshInstallationHandle,
    ceremony: *mut MeshCeremonyHandle,
    bytes: *const u8,
    bytes_len: usize,
    now: u64,
    out_payload: *mut *mut u8,
    out_payload_len: *mut usize,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || ceremony.is_null()
            || bytes.is_null()
            || out_payload.is_null()
            || out_payload_len.is_null()
        {
            set_last_error("invalid arguments passed to mesh_installation_scan_offer");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let ceremony = unsafe { &mut *ceremony };
        let slice = unsafe { slice::from_raw_parts(bytes, bytes_len) };

        match handle
            .installation_mut()
            .scan_offer(&ceremony.ceremony, slice, now, &mut OsRng)
        {
            Ok(payload) => {
                let mut boxed = payload.into_boxed_slice();
                unsafe {
                    *out_payload_len = boxed.len();
                    *out_payload = boxed.as_mut_ptr();
                }
                std::mem::forget(boxed);
                MESH_OK
            }
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Initiator scans the responder's response payload and produces a reveal payload.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `ceremony` must be a valid, non-null pointer to a `MeshCeremonyHandle`.
/// - `bytes` must point to at least `bytes_len` readable bytes.
/// - `out_payload` and `out_payload_len` must be valid, non-null writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_scan_response(
    handle: *mut MeshInstallationHandle,
    ceremony: *mut MeshCeremonyHandle,
    bytes: *const u8,
    bytes_len: usize,
    now: u64,
    out_payload: *mut *mut u8,
    out_payload_len: *mut usize,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || ceremony.is_null()
            || bytes.is_null()
            || out_payload.is_null()
            || out_payload_len.is_null()
        {
            set_last_error("invalid arguments passed to mesh_installation_scan_response");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let ceremony = unsafe { &mut *ceremony };
        let slice = unsafe { slice::from_raw_parts(bytes, bytes_len) };

        match handle
            .installation_mut()
            .scan_response(&ceremony.ceremony, slice, now)
        {
            Ok(payload) => {
                let mut boxed = payload.into_boxed_slice();
                unsafe {
                    *out_payload_len = boxed.len();
                    *out_payload = boxed.as_mut_ptr();
                }
                std::mem::forget(boxed);
                MESH_OK
            }
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Responder scans the initiator's reveal payload to complete the exchange.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `ceremony` must be a valid, non-null pointer to a `MeshCeremonyHandle`.
/// - `bytes` must point to at least `bytes_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_scan_reveal(
    handle: *mut MeshInstallationHandle,
    ceremony: *mut MeshCeremonyHandle,
    bytes: *const u8,
    bytes_len: usize,
    now: u64,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || ceremony.is_null() || bytes.is_null() {
            set_last_error("invalid arguments passed to mesh_installation_scan_reveal");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let ceremony = unsafe { &mut *ceremony };
        let slice = unsafe { slice::from_raw_parts(bytes, bytes_len) };

        match handle
            .installation_mut()
            .scan_reveal(&ceremony.ceremony, slice, now)
        {
            Ok(()) => MESH_OK,
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Retrieve the 6-digit comparison code if available for the active ceremony.
///
/// If available, writes the code to `*out_code`, caches the comparison in `ceremony`, and returns `MESH_OK`.
/// If not yet ready, returns `MESH_ERR_NO_COMPARISON`.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `ceremony` must be a valid, non-null pointer to a `MeshCeremonyHandle`.
/// - `out_code` must be a valid, non-null writable pointer to a `u32`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_comparison(
    handle: *mut MeshInstallationHandle,
    ceremony: *mut MeshCeremonyHandle,
    now: u64,
    out_code: *mut u32,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || ceremony.is_null() || out_code.is_null() {
            set_last_error("invalid arguments passed to mesh_installation_comparison");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let ceremony = unsafe { &mut *ceremony };

        match handle
            .installation_mut()
            .comparison(&ceremony.ceremony, now)
        {
            Ok(Some(comp)) => {
                unsafe {
                    *out_code = comp.code;
                }
                ceremony.comparison = Some(comp);
                MESH_OK
            }
            Ok(None) => MESH_ERR_NO_COMPARISON,
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Confirm matching peer comparison code and persist the verified contact.
///
/// Writes the verified contact JSON string to `*out_json` (must be freed with `mesh_string_free`).
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `ceremony` must be a valid, non-null pointer to a `MeshCeremonyHandle`.
/// - `out_json` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_confirm_and_save(
    handle: *mut MeshInstallationHandle,
    ceremony: *mut MeshCeremonyHandle,
    peer_code: u32,
    now: u64,
    timestamp: u64,
    out_json: *mut *mut c_char,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || ceremony.is_null() || out_json.is_null() {
            set_last_error("invalid arguments passed to mesh_installation_confirm_and_save");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let ceremony = unsafe { &mut *ceremony };

        let comp = match ceremony.comparison {
            Some(c) => c,
            None => {
                set_last_error(
                    "no comparison available to confirm; comparison must be retrieved and displayed before confirmation",
                );
                return MESH_ERR_NO_COMPARISON;
            }
        };

        match handle.installation_mut().confirm_and_save(
            &ceremony.ceremony,
            comp,
            peer_code,
            now,
            timestamp,
            &mut OsRng,
        ) {
            Ok(record) => {
                let info = contact_to_json(&record);
                let json_str = match serde_json::to_string(&info) {
                    Ok(s) => s,
                    Err(e) => {
                        set_last_error(e.to_string());
                        return MESH_ERR_INTERNAL;
                    }
                };
                let c_str = match CString::new(json_str) {
                    Ok(s) => s,
                    Err(_) => return MESH_ERR_INTERNAL,
                };
                unsafe {
                    *out_json = c_str.into_raw();
                }
                MESH_OK
            }
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Cancel an active ceremony.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `ceremony` must be a valid, non-null pointer to a `MeshCeremonyHandle`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_cancel_ceremony(
    handle: *mut MeshInstallationHandle,
    ceremony: *mut MeshCeremonyHandle,
    now: u64,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || ceremony.is_null() {
            set_last_error("invalid arguments passed to mesh_installation_cancel_ceremony");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let ceremony = unsafe { &mut *ceremony };

        match handle.installation_mut().cancel(&ceremony.ceremony, now) {
            Ok(()) => MESH_OK,
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

#[derive(Serialize)]
struct TakeoverStatementJson {
    identity: String,
    counter: String,
    nonce: String,
    signature: String,
}

#[derive(Serialize)]
struct HandoffBundleInspectJson {
    identity: String,
    counter: String,
    recipient: String,
    statement: TakeoverStatementJson,
}

fn voting_state_to_i32(state: mesh_identity::session::installation::VotingState) -> i32 {
    use mesh_identity::session::installation::VotingState;
    match state {
        VotingState::Voting => 0,
        VotingState::Stopped => 1,
        VotingState::Gated => 2,
    }
}

/// Retrieve or lazily generate the local device nonce (32 bytes).
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `out_nonce` must be a valid, writable pointer to at least 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_device_nonce(
    handle: *mut MeshInstallationHandle,
    out_nonce: *mut u8,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_nonce.is_null() {
            set_last_error("invalid arguments passed to mesh_installation_device_nonce");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let nonce = handle.installation_mut().device_nonce(&mut OsRng);
        unsafe {
            std::ptr::copy_nonoverlapping(nonce.as_ptr(), out_nonce, 32);
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Check the current device nonce without generating one if absent.
///
/// If a nonce exists, writes 32 bytes to `out_nonce` and sets `*out_has_nonce = true`.
/// Otherwise, sets `*out_has_nonce = false`.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `out_nonce` must point to at least 32 writable bytes.
/// - `out_has_nonce` must point to a writable `bool`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_current_device_nonce(
    handle: *mut MeshInstallationHandle,
    out_nonce: *mut u8,
    out_has_nonce: *mut bool,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_nonce.is_null() || out_has_nonce.is_null() {
            set_last_error("invalid arguments passed to mesh_installation_current_device_nonce");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &*handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        match handle.installation().current_device_nonce() {
            Some(nonce) => unsafe {
                std::ptr::copy_nonoverlapping(nonce.as_ptr(), out_nonce, 32);
                *out_has_nonce = true;
            },
            None => unsafe {
                *out_has_nonce = false;
            },
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Query the voting state of an identity (or selected identity if `key_ptr` is null).
///
/// Writes `0` (Voting), `1` (Stopped), or `2` (Gated) to `*out_state`.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `out_state` must be a valid, non-null pointer to an `i32`.
/// - If `key_ptr` is non-null, `key_len` must be 32.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_voting_state(
    handle: *mut MeshInstallationHandle,
    key_ptr: *const u8,
    key_len: usize,
    out_state: *mut i32,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_state.is_null() {
            set_last_error("invalid arguments passed to mesh_installation_voting_state");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &*handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }

        let state = if key_ptr.is_null() || key_len == 0 {
            handle.installation().voting_state()
        } else {
            if key_len != 32 {
                set_last_error("key must be exactly 32 bytes");
                return MESH_ERR_INVALID_ARG;
            }
            let mut id = [0u8; 32];
            unsafe {
                std::ptr::copy_nonoverlapping(key_ptr, id.as_mut_ptr(), 32);
            }
            if !handle.installation().identities().contains(&id) {
                set_last_error("unknown identity specified");
                return MESH_ERR_UNKNOWN_IDENTITY;
            }
            handle.installation().voting_record(id).state
        };

        unsafe {
            *out_state = voting_state_to_i32(state);
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Query the complete voting record of an identity (or selected identity if `key_ptr` is null).
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `out_counter`, `out_state`, `out_holder`, `out_has_holder` must be valid, non-null writable pointers.
/// - `out_holder` must point to at least 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_voting_record(
    handle: *mut MeshInstallationHandle,
    key_ptr: *const u8,
    key_len: usize,
    out_counter: *mut u64,
    out_state: *mut i32,
    out_holder: *mut u8,
    out_has_holder: *mut bool,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || out_counter.is_null()
            || out_state.is_null()
            || out_holder.is_null()
            || out_has_holder.is_null()
        {
            set_last_error("invalid arguments passed to mesh_installation_voting_record");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &*handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }

        let record = if key_ptr.is_null() || key_len == 0 {
            handle
                .installation()
                .voting_record(handle.installation().selected())
        } else {
            if key_len != 32 {
                set_last_error("key must be exactly 32 bytes");
                return MESH_ERR_INVALID_ARG;
            }
            let mut id = [0u8; 32];
            unsafe {
                std::ptr::copy_nonoverlapping(key_ptr, id.as_mut_ptr(), 32);
            }
            if !handle.installation().identities().contains(&id) {
                set_last_error("unknown identity specified");
                return MESH_ERR_UNKNOWN_IDENTITY;
            }
            handle.installation().voting_record(id)
        };

        unsafe {
            *out_counter = record.counter;
            *out_state = voting_state_to_i32(record.state);
            match record.holder {
                Some(h) => {
                    std::ptr::copy_nonoverlapping(h.as_ptr(), out_holder, 32);
                    *out_has_holder = true;
                }
                None => {
                    *out_has_holder = false;
                }
            }
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Explicitly gate voting on this device.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_gate_voting(handle: *mut MeshInstallationHandle) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_last_error("handle is null in mesh_installation_gate_voting");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        handle.installation_mut().gate_voting();
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Begin a takeover claim for the selected identity while in the Gated state.
///
/// Writes JSON string representing `TakeoverStatement` to `*out_json`.
/// Must be freed using `mesh_string_free`.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `out_json` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_begin_takeover(
    handle: *mut MeshInstallationHandle,
    floor: u64,
    out_json: *mut *mut c_char,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_json.is_null() {
            set_last_error("invalid arguments passed to mesh_installation_begin_takeover");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }

        match handle.installation_mut().begin_takeover(&mut OsRng, floor) {
            Ok(statement) => {
                let json = TakeoverStatementJson {
                    identity: hex::encode(statement.identity),
                    counter: statement.counter.to_string(),
                    nonce: hex::encode(statement.nonce),
                    signature: hex::encode(statement.signature),
                };
                let s = match serde_json::to_string(&json) {
                    Ok(s) => s,
                    Err(e) => {
                        set_last_error(e.to_string());
                        return MESH_ERR_INTERNAL;
                    }
                };
                let c_str = match CString::new(s) {
                    Ok(c) => c,
                    Err(e) => {
                        set_last_error(e.to_string());
                        return MESH_ERR_INTERNAL;
                    }
                };
                unsafe {
                    *out_json = c_str.into_raw();
                }
                MESH_OK
            }
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Begin a handoff of the selected identity's voting role to the recipient device nonce.
///
/// On success, the local device is permanently Stopped at this counter, and the signed
/// `HandoffBundle` bytes are returned in `*out_bundle_ptr` and `*out_bundle_len`.
/// Simultaneously, the updated installation snapshot recording this Stopped role is
/// generated and returned in `*out_snapshot_ptr` and `*out_snapshot_len`.
/// Both buffers must be freed with `mesh_buffer_free`.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `recipient_ptr` must point to at least `recipient_len` readable bytes (must be 32).
/// - `out_bundle_ptr`, `out_bundle_len`, `out_snapshot_ptr`, and `out_snapshot_len` must be valid, non-null writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_begin_handoff(
    handle: *mut MeshInstallationHandle,
    recipient_ptr: *const u8,
    recipient_len: usize,
    now: u64,
    out_bundle_ptr: *mut *mut u8,
    out_bundle_len: *mut usize,
    out_snapshot_ptr: *mut *mut u8,
    out_snapshot_len: *mut usize,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || recipient_ptr.is_null()
            || recipient_len != 32
            || out_bundle_ptr.is_null()
            || out_bundle_len.is_null()
            || out_snapshot_ptr.is_null()
            || out_snapshot_len.is_null()
        {
            set_last_error("invalid arguments passed to mesh_installation_begin_handoff");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }

        let mut recipient = [0u8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(recipient_ptr, recipient.as_mut_ptr(), 32);
        }

        // Pre-validate that save_bytes succeeds before mutating voting state
        if let Err(e) = handle.installation_mut().save_bytes(now) {
            set_last_error(e.to_string());
            return MESH_ERR_INVALID_SNAPSHOT;
        }

        match handle
            .installation_mut()
            .begin_handoff(recipient, |_, _| Ok(()))
        {
            Ok(bundle) => {
                let snapshot = match handle.installation_mut().save_bytes(now) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        set_last_error(e.to_string());
                        return MESH_ERR_INVALID_SNAPSHOT;
                    }
                };
                let mut bundle_bytes = bundle.to_bytes().into_boxed_slice();
                let mut snapshot_bytes = snapshot.into_boxed_slice();
                unsafe {
                    *out_bundle_len = bundle_bytes.len();
                    *out_bundle_ptr = bundle_bytes.as_mut_ptr();
                    *out_snapshot_len = snapshot_bytes.len();
                    *out_snapshot_ptr = snapshot_bytes.as_mut_ptr();
                }
                std::mem::forget(bundle_bytes);
                std::mem::forget(snapshot_bytes);
                MESH_OK
            }
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Accept an authenticated handoff bundle addressed to this device.
///
/// On success, merges voter locks and transitions to `Voting` (or `Gated` if conflict).
/// Writes resulting `VotingState` integer to `*out_new_state`, and writes the updated
/// post-handoff installation snapshot to `*out_snapshot_ptr` and `*out_snapshot_len`.
/// The snapshot buffer must be freed with `mesh_buffer_free`.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `bundle_ptr` must point to at least `bundle_len` readable bytes.
/// - `out_new_state`, `out_snapshot_ptr`, and `out_snapshot_len` must be valid, non-null writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_accept_handoff(
    handle: *mut MeshInstallationHandle,
    bundle_ptr: *const u8,
    bundle_len: usize,
    now: u64,
    out_new_state: *mut i32,
    out_snapshot_ptr: *mut *mut u8,
    out_snapshot_len: *mut usize,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || bundle_ptr.is_null()
            || bundle_len == 0
            || bundle_len > MAX_HANDOFF_BUNDLE_BYTES
            || out_new_state.is_null()
            || out_snapshot_ptr.is_null()
            || out_snapshot_len.is_null()
        {
            set_last_error("invalid arguments passed to mesh_installation_accept_handoff");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }

        let bytes = unsafe { slice::from_raw_parts(bundle_ptr, bundle_len) };
        let bundle = match mesh_identity::session::installation::HandoffBundle::from_bytes(bytes) {
            Ok(b) => b,
            Err(e) => {
                set_last_error(e.to_string());
                return map_installation_error(&e);
            }
        };

        // Pre-validate that save_bytes succeeds before mutating voting state
        if let Err(e) = handle.installation_mut().save_bytes(now) {
            set_last_error(e.to_string());
            return MESH_ERR_INVALID_SNAPSHOT;
        }

        match handle
            .installation_mut()
            .accept_handoff(&bundle, |_| Ok(()))
        {
            Ok(state) => {
                let snapshot = match handle.installation_mut().save_bytes(now) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        set_last_error(e.to_string());
                        return MESH_ERR_INVALID_SNAPSHOT;
                    }
                };
                let mut snapshot_bytes = snapshot.into_boxed_slice();
                unsafe {
                    *out_new_state = voting_state_to_i32(state);
                    *out_snapshot_len = snapshot_bytes.len();
                    *out_snapshot_ptr = snapshot_bytes.as_mut_ptr();
                }
                std::mem::forget(snapshot_bytes);
                MESH_OK
            }
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Inspect a serialized handoff bundle without an installation handle.
///
/// Returns JSON representing the bundle header and takeover statement to `*out_json`.
/// Must be freed using `mesh_string_free`.
///
/// # Safety
///
/// - `bundle_ptr` must point to at least `bundle_len` readable bytes.
/// - `out_json` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_handoff_bundle_inspect(
    bundle_ptr: *const u8,
    bundle_len: usize,
    out_json: *mut *mut c_char,
) -> i32 {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if bundle_ptr.is_null()
            || bundle_len == 0
            || bundle_len > MAX_HANDOFF_BUNDLE_BYTES
            || out_json.is_null()
        {
            set_last_error("invalid arguments passed to mesh_handoff_bundle_inspect");
            return MESH_ERR_INVALID_ARG;
        }

        let bytes = unsafe { slice::from_raw_parts(bundle_ptr, bundle_len) };
        let bundle = match mesh_identity::session::installation::HandoffBundle::from_bytes(bytes) {
            Ok(b) => b,
            Err(e) => {
                set_last_error(e.to_string());
                return map_installation_error(&e);
            }
        };

        let statement = match bundle.statement() {
            Ok(st) => st,
            Err(e) => {
                set_last_error(e.to_string());
                return map_installation_error(&e);
            }
        };

        let inspect = HandoffBundleInspectJson {
            identity: hex::encode(bundle.identity()),
            counter: bundle.counter().to_string(),
            recipient: hex::encode(statement.nonce),
            statement: TakeoverStatementJson {
                identity: hex::encode(statement.identity),
                counter: statement.counter.to_string(),
                nonce: hex::encode(statement.nonce),
                signature: hex::encode(statement.signature),
            },
        };

        let s = match serde_json::to_string(&inspect) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        let c_str = match CString::new(s) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        unsafe {
            *out_json = c_str.into_raw();
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        set_last_error("native panic caught at FFI boundary");
        MESH_ERR_PANIC
    })
}

// ---------------------------------------------------------------------------
// Slice 4: Byzantine Group Admission & Governance Handles
// ---------------------------------------------------------------------------

pub struct MeshGroupHandle {
    pub group_handle: mesh_identity::groups::handle::GroupHandle,
    pub is_poisoned: bool,
}

impl MeshGroupHandle {
    fn is_poisoned(&self) -> bool {
        self.is_poisoned
    }
}

#[derive(Serialize)]
struct GroupViewJson {
    id: String,
    revision: String,
    policy: String,
    members: Vec<String>,
}

#[derive(Serialize)]
struct OutgoingJson {
    from: String,
    to: Vec<String>,
    tag: u8,
    bytes: String,
    authenticator: Option<String>,
}

#[derive(Serialize)]
struct PendingInvitationJson {
    binding: String,
    group: String,
    inviter: String,
}

#[derive(Serialize)]
struct OpStateJson {
    status: String,
    reason: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum EventJson {
    GroupCreated { group: String },
    GroupImported { group: String },
    GroupFormed { group: String },
    InvitationSent { op: String },
    InvitationReceived { group: String, invitation: String },
    AcceptanceSent { op: String },
    ConsentReceived { op: String },
    Admitted { op: String },
    Joined { group: String },
    MemberAdmitted { group: String, member: String },
    Left { group: String },
    MemberDeparted { group: String, member: String },
    FrameRejected { reason: String },
}

fn event_to_json(e: &mesh_identity::groups::handle::Event) -> EventJson {
    use mesh_identity::groups::handle::Event;
    match e {
        Event::GroupCreated(id) => EventJson::GroupCreated {
            group: id.to_string(),
        },
        Event::GroupImported(id) => EventJson::GroupImported {
            group: id.to_string(),
        },
        Event::GroupFormed(id) => EventJson::GroupFormed {
            group: id.to_string(),
        },
        Event::InvitationSent(op) => EventJson::InvitationSent {
            op: op.0.to_string(),
        },
        Event::InvitationReceived { group, invitation } => EventJson::InvitationReceived {
            group: group.to_string(),
            invitation: hex::encode(invitation),
        },
        Event::AcceptanceSent(op) => EventJson::AcceptanceSent {
            op: op.0.to_string(),
        },
        Event::ConsentReceived(op) => EventJson::ConsentReceived {
            op: op.0.to_string(),
        },
        Event::Admitted(op) => EventJson::Admitted {
            op: op.0.to_string(),
        },
        Event::Joined(id) => EventJson::Joined {
            group: id.to_string(),
        },
        Event::MemberAdmitted { group, member } => EventJson::MemberAdmitted {
            group: group.to_string(),
            member: hex::encode(member),
        },
        Event::Left(id) => EventJson::Left {
            group: id.to_string(),
        },
        Event::MemberDeparted { group, member } => EventJson::MemberDeparted {
            group: group.to_string(),
            member: hex::encode(member),
        },
        Event::FrameRejected(r) => EventJson::FrameRejected {
            reason: reason_to_str(*r).to_string(),
        },
    }
}

fn reason_to_str(r: mesh_identity::groups::handle::Reason) -> &'static str {
    use mesh_identity::groups::handle::Reason::*;
    match r {
        Malformed => "malformed",
        TooLarge => "tooLarge",
        UnknownTag => "unknownTag",
        Unsupported => "unsupported",
        NeedsAuthentication => "needsAuthentication",
        Invalid => "invalid",
        Full => "full",
        Expired => "expired",
        Stale => "stale",
        UnknownContact => "unknownContact",
        Unknown => "unknown",
        Conflict => "conflict",
    }
}

fn handle_error_to_str(err: &mesh_identity::groups::handle::HandleError) -> String {
    use mesh_identity::groups::handle::HandleError::*;
    match err {
        Full => "group capacity exceeded".to_string(),
        Invalid => "invalid argument or operation".to_string(),
        UnknownOp => "unknown operation".to_string(),
        Unknown => "unknown group or invitation".to_string(),
        UnsupportedPolicy => "unsupported group policy".to_string(),
        Ineligible => {
            "identity is ineligible (not a member, not a verified contact, or gated)".to_string()
        }
        Installation(e) => format!("installation snapshot error: {e}"),
        Group(e) => format!("group snapshot error: {e:?}"),
        Malformed => "malformed group handle snapshot".to_string(),
        UnsupportedVersion(v) => format!("unsupported group snapshot version: {v}"),
        TooLarge => "group snapshot exceeds size ceiling".to_string(),
        Duplicate => "duplicate group".to_string(),
        Formation(f) => format!("formation error: {f:?}"),
    }
}

fn map_handle_error(err: &mesh_identity::groups::handle::HandleError) -> i32 {
    use mesh_identity::groups::handle::HandleError;
    match err {
        HandleError::Full => MESH_ERR_CAPACITY_EXCEEDED,
        HandleError::Invalid => MESH_ERR_INVALID_ARG,
        HandleError::UnknownOp | HandleError::Unknown => MESH_ERR_NOT_FOUND,
        HandleError::UnsupportedPolicy | HandleError::UnsupportedVersion(_) => MESH_ERR_UNSUPPORTED,
        HandleError::Ineligible => MESH_ERR_INELIGIBLE,
        HandleError::Duplicate => MESH_ERR_DUPLICATE_GROUP,
        HandleError::TooLarge => MESH_ERR_TOO_LARGE,
        HandleError::Malformed => MESH_ERR_MALFORMED,
        HandleError::Installation(_) | HandleError::Group(_) => MESH_ERR_INVALID_SNAPSHOT,
        HandleError::Formation(_) => MESH_ERR_FORMATION,
    }
}

/// Create a new `MeshGroupHandle` from an initial root identity seed.
///
/// # Safety
///
/// - `seed_ptr` must point to at least 32 readable bytes.
/// - `out_handle` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_create(
    seed_ptr: *const u8,
    seed_len: usize,
    out_handle: *mut *mut MeshGroupHandle,
) -> i32 {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if seed_ptr.is_null() || seed_len != 32 || out_handle.is_null() {
            set_last_error("invalid arguments passed to mesh_group_handle_create");
            return MESH_ERR_INVALID_ARG;
        }

        let mut seed = [0u8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(seed_ptr, seed.as_mut_ptr(), 32);
        }
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();

        let installation = mesh_identity::session::installation::Installation::new(signing_key);
        let group_handle = mesh_identity::groups::handle::GroupHandle::new(installation);

        let handle = Box::into_raw(Box::new(MeshGroupHandle {
            group_handle,
            is_poisoned: false,
        }));
        unsafe {
            *out_handle = handle;
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        set_last_error("native panic caught at FFI boundary");
        MESH_ERR_PANIC
    })
}

/// Create a `MeshGroupHandle` consuming an existing `MeshInstallationHandle`.
///
/// On success, takes ownership of and deallocates `inst_handle`, transferring its
/// underlying `Installation` into a new `MeshGroupHandle`. On failure, `inst_handle`
/// is preserved and remains valid.
///
/// # Safety
///
/// - `inst_handle` must be a valid, non-null pointer to a `MeshInstallationHandle`.
/// - `out_handle` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_from_installation(
    inst_handle: *mut MeshInstallationHandle,
    out_handle: *mut *mut MeshGroupHandle,
) -> i32 {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if inst_handle.is_null() || out_handle.is_null() {
            set_last_error("invalid arguments passed to mesh_group_handle_from_installation");
            return MESH_ERR_INVALID_ARG;
        }
        let inst_ref = unsafe { &mut *inst_handle };
        if inst_ref.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        if inst_ref.is_borrowed() {
            set_last_error("cannot transfer ownership of a borrowed MeshInstallation view");
            return MESH_ERR_INVALID_ARG;
        }

        let inst_box = unsafe { Box::from_raw(inst_handle) };
        let Some(owned_inst) = inst_box.into_owned() else {
            set_last_error("cannot transfer ownership of a borrowed MeshInstallation view");
            return MESH_ERR_INVALID_ARG;
        };
        let group_handle = mesh_identity::groups::handle::GroupHandle::new(owned_inst);
        let handle = Box::into_raw(Box::new(MeshGroupHandle {
            group_handle,
            is_poisoned: false,
        }));
        unsafe {
            *out_handle = handle;
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        set_last_error("native panic caught at FFI boundary");
        MESH_ERR_PANIC
    })
}

/// Create a borrowed `MeshInstallationHandle` view into a live `MeshGroupHandle`.
///
/// The returned handle does not own the underlying `Installation`; its lifetime is
/// bounded by the parent `MeshGroupHandle` and must be invalidated before freeing
/// the parent `MeshGroupHandle`.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `out_inst_handle` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_installation_view(
    handle: *mut MeshGroupHandle,
    out_inst_handle: *mut *mut MeshInstallationHandle,
) -> i32 {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_inst_handle.is_null() {
            set_last_error("invalid arguments passed to mesh_group_handle_installation_view");
            return MESH_ERR_INVALID_ARG;
        }
        let group_ref = unsafe { &mut *handle };
        if group_ref.is_poisoned {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let view = Box::into_raw(Box::new(MeshInstallationHandle {
            backing: InstallationBacking::BorrowedGroup(handle),
            is_poisoned: false,
        }));
        unsafe {
            *out_inst_handle = view;
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        set_last_error("native panic caught at FFI boundary");
        MESH_ERR_PANIC
    })
}

/// Free a `MeshGroupHandle`.
///
/// # Safety
///
/// - `handle` must be a valid pointer allocated by `mesh_group_handle_*`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_free(handle: *mut MeshGroupHandle) {
    if !handle.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| unsafe {
            drop(Box::from_raw(handle));
        }));
    }
}

/// Get the 32-byte public key of the currently selected identity in this group handle.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `out_pk` must point to at least 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_selected_identity(
    handle: *mut MeshGroupHandle,
    out_pk: *mut u8,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_pk.is_null() {
            set_last_error("invalid arguments passed to mesh_group_handle_selected_identity");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let pk = handle.group_handle.installation().selected();
        unsafe {
            std::ptr::copy_nonoverlapping(pk.as_ptr(), out_pk, 32);
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Create a new group with the selected identity and optional initial members.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `members_ptr` must point to at least `members_count * 32` readable bytes if `members_count > 0`.
/// - `out_op_id` must be a valid, non-null writable pointer to a `u64`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_create_group(
    handle: *mut MeshGroupHandle,
    members_ptr: *const u8,
    members_count: usize,
    out_op_id: *mut u64,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_op_id.is_null() {
            set_last_error("invalid arguments passed to mesh_group_handle_create_group");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        if members_count >= MAX_GROUP_MEMBERS {
            set_last_error("members count exceeds maximum allowable members (192)");
            return MESH_ERR_TOO_LARGE;
        }
        let mut members = Vec::with_capacity(members_count);
        if members_count > 0 {
            if members_ptr.is_null() {
                set_last_error("members_ptr is null but members_count > 0");
                return MESH_ERR_INVALID_ARG;
            }
            for i in 0..members_count {
                let mut pk = [0u8; 32];
                unsafe {
                    std::ptr::copy_nonoverlapping(members_ptr.add(i * 32), pk.as_mut_ptr(), 32);
                }
                members.push(pk);
            }
        }
        match handle.group_handle.create(
            mesh_identity::groups::Policy::InviterOnly,
            &members,
            &mut OsRng,
        ) {
            Ok(op_id) => {
                unsafe {
                    *out_op_id = op_id.0;
                }
                MESH_OK
            }
            Err(e) => {
                set_last_error(handle_error_to_str(&e));
                map_handle_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Import a group from an authenticated genesis frame and expected digest.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `frame_ptr` must point to at least `frame_len` readable bytes.
/// - `digest_ptr` must point to at least 32 readable bytes.
/// - `out_op_id` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_import_genesis(
    handle: *mut MeshGroupHandle,
    frame_ptr: *const u8,
    frame_len: usize,
    digest_ptr: *const u8,
    out_op_id: *mut u64,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || frame_ptr.is_null()
            || frame_len == 0
            || frame_len > MAX_GROUP_FRAME_BYTES
            || digest_ptr.is_null()
            || out_op_id.is_null()
        {
            set_last_error("invalid arguments passed to mesh_group_handle_import_genesis");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let frame = unsafe { slice::from_raw_parts(frame_ptr, frame_len) };
        let mut expected_digest = [0u8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(digest_ptr, expected_digest.as_mut_ptr(), 32);
        }
        match handle.group_handle.import_genesis(frame, expected_digest) {
            Ok(op_id) => {
                unsafe {
                    *out_op_id = op_id.0;
                }
                MESH_OK
            }
            Err(e) => {
                set_last_error(handle_error_to_str(&e));
                map_handle_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Invite a verified contact candidate to an active group.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `candidate_ptr` must point to at least 32 readable bytes.
/// - `out_op_id` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_invite(
    handle: *mut MeshGroupHandle,
    group_id: u64,
    candidate_ptr: *const u8,
    lifetime_ms: u64,
    now: u64,
    out_op_id: *mut u64,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || candidate_ptr.is_null() || out_op_id.is_null() {
            set_last_error("invalid arguments passed to mesh_group_handle_invite");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let mut candidate = [0u8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(candidate_ptr, candidate.as_mut_ptr(), 32);
        }
        match handle
            .group_handle
            .invite(group_id, candidate, lifetime_ms, now)
        {
            Ok(op_id) => {
                unsafe {
                    *out_op_id = op_id.0;
                }
                MESH_OK
            }
            Err(e) => {
                set_last_error(handle_error_to_str(&e));
                map_handle_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Accept a received invitation by its 32-byte binding.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `invitation_binding_ptr` must point to at least 32 readable bytes.
/// - `out_op_id` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_accept(
    handle: *mut MeshGroupHandle,
    invitation_binding_ptr: *const u8,
    now: u64,
    out_op_id: *mut u64,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || invitation_binding_ptr.is_null() || out_op_id.is_null() {
            set_last_error("invalid arguments passed to mesh_group_handle_accept");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let mut invitation = [0u8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(invitation_binding_ptr, invitation.as_mut_ptr(), 32);
        }
        match handle.group_handle.accept(invitation, now) {
            Ok(op_id) => {
                unsafe {
                    *out_op_id = op_id.0;
                }
                MESH_OK
            }
            Err(e) => {
                set_last_error(handle_error_to_str(&e));
                map_handle_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Accept an invitation with out-of-band genesis authentication.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `invitation_binding_ptr` and `genesis_digest_ptr` must point to 32 readable bytes.
/// - `out_op_id` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_accept_authenticated(
    handle: *mut MeshGroupHandle,
    invitation_binding_ptr: *const u8,
    genesis_digest_ptr: *const u8,
    now: u64,
    out_op_id: *mut u64,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || invitation_binding_ptr.is_null()
            || genesis_digest_ptr.is_null()
            || out_op_id.is_null()
        {
            set_last_error("invalid arguments passed to mesh_group_handle_accept_authenticated");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let mut invitation = [0u8; 32];
        let mut digest = [0u8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(invitation_binding_ptr, invitation.as_mut_ptr(), 32);
            std::ptr::copy_nonoverlapping(genesis_digest_ptr, digest.as_mut_ptr(), 32);
        }
        match handle
            .group_handle
            .accept_authenticated(invitation, digest, now)
        {
            Ok(op_id) => {
                unsafe {
                    *out_op_id = op_id.0;
                }
                MESH_OK
            }
            Err(e) => {
                set_last_error(handle_error_to_str(&e));
                map_handle_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Leave an active group.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `out_op_id` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_leave(
    handle: *mut MeshGroupHandle,
    group_id: u64,
    now: u64,
    out_op_id: *mut u64,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_op_id.is_null() {
            set_last_error("invalid arguments passed to mesh_group_handle_leave");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        match handle.group_handle.leave(group_id, now) {
            Ok(op_id) => {
                unsafe {
                    *out_op_id = op_id.0;
                }
                MESH_OK
            }
            Err(e) => {
                set_last_error(handle_error_to_str(&e));
                map_handle_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Ingest inbound network bytes from a peer.
///
/// Outputs JSON array of immediate rejection events (or empty if accepted/staged).
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `from_ptr` must point to at least 32 readable bytes.
/// - `bytes_ptr` must point to at least `bytes_len` readable bytes.
/// - `out_events_json` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_receive_bytes(
    handle: *mut MeshGroupHandle,
    from_ptr: *const u8,
    bytes_ptr: *const u8,
    bytes_len: usize,
    now: u64,
    out_events_json: *mut *mut c_char,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || from_ptr.is_null()
            || bytes_ptr.is_null()
            || bytes_len == 0
            || bytes_len > MAX_GROUP_FRAME_BYTES
            || out_events_json.is_null()
        {
            set_last_error("invalid arguments passed to mesh_group_handle_receive_bytes");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let mut from = [0u8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(from_ptr, from.as_mut_ptr(), 32);
        }
        let bytes = unsafe { slice::from_raw_parts(bytes_ptr, bytes_len) };
        let events = handle.group_handle.receive_bytes(from, bytes, now);
        let json_events: Vec<EventJson> = events.iter().map(event_to_json).collect();
        let s = match serde_json::to_string(&json_events) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        let c_str = match CString::new(s) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        unsafe {
            *out_events_json = c_str.into_raw();
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Get a JSON list of all active group IDs held by the selected persona.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `out_json` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_group_ids(
    handle: *mut MeshGroupHandle,
    out_json: *mut *mut c_char,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_json.is_null() {
            set_last_error("invalid arguments passed to mesh_group_handle_group_ids");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let ids: Vec<String> = handle
            .group_handle
            .group_ids()
            .into_iter()
            .map(|id| id.to_string())
            .collect();
        let s = match serde_json::to_string(&ids) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        let c_str = match CString::new(s) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        unsafe {
            *out_json = c_str.into_raw();
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Query public view of a held group by ID.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `out_json` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_get_group(
    handle: *mut MeshGroupHandle,
    group_id: u64,
    out_json: *mut *mut c_char,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_json.is_null() {
            set_last_error("invalid arguments passed to mesh_group_handle_get_group");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let view = match handle.group_handle.group(group_id) {
            Some(v) => v,
            None => {
                set_last_error("group not found");
                return MESH_ERR_NOT_FOUND;
            }
        };
        let members: Vec<String> = view.member_keys().into_iter().map(hex::encode).collect();
        let view_json = GroupViewJson {
            id: view.id().to_string(),
            revision: view.revision().to_string(),
            policy: format!("{:?}", view.policy()),
            members,
        };
        let s = match serde_json::to_string(&view_json) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        let c_str = match CString::new(s) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        unsafe {
            *out_json = c_str.into_raw();
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Query pending invitations waiting for acceptance by the selected identity.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `out_json` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_pending_invitations(
    handle: *mut MeshGroupHandle,
    out_json: *mut *mut c_char,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_json.is_null() {
            set_last_error("invalid arguments passed to mesh_group_handle_pending_invitations");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let items: Vec<PendingInvitationJson> = handle
            .group_handle
            .pending_invitations()
            .into_iter()
            .map(|(binding, group, inviter)| PendingInvitationJson {
                binding: hex::encode(binding),
                group: group.to_string(),
                inviter: hex::encode(inviter),
            })
            .collect();
        let s = match serde_json::to_string(&items) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        let c_str = match CString::new(s) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        unsafe {
            *out_json = c_str.into_raw();
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Save the complete group handle state to an authenticated CBOR blob.
///
/// Returns `(token_counter, token_incarnation)` and the blob buffer (must be freed with `mesh_buffer_free`).
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `out_token_counter`, `out_token_incarnation` (32 bytes), `out_blob_ptr`, and `out_blob_len` must be writable pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_save(
    handle: *mut MeshGroupHandle,
    now: u64,
    out_token_counter: *mut u64,
    out_token_incarnation: *mut u8,
    out_blob_ptr: *mut *mut u8,
    out_blob_len: *mut usize,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || out_token_counter.is_null()
            || out_token_incarnation.is_null()
            || out_blob_ptr.is_null()
            || out_blob_len.is_null()
        {
            set_last_error("invalid arguments passed to mesh_group_handle_save");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        match handle.group_handle.save(now) {
            Ok((token, blob)) => {
                let mut boxed = blob.into_boxed_slice();
                unsafe {
                    *out_token_counter = token.counter();
                    std::ptr::copy_nonoverlapping(
                        token.incarnation().as_ptr(),
                        out_token_incarnation,
                        32,
                    );
                    *out_blob_len = boxed.len();
                    *out_blob_ptr = boxed.as_mut_ptr();
                }
                std::mem::forget(boxed);
                MESH_OK
            }
            Err(e) => {
                set_last_error(handle_error_to_str(&e));
                map_handle_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Confirm a saved blob is durable, releasing staged outgoing frames and returning resulting events.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `token_incarnation_ptr` must point to at least 32 readable bytes.
/// - `out_events_json` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_confirm_saved(
    handle: *mut MeshGroupHandle,
    token_counter: u64,
    token_incarnation_ptr: *const u8,
    out_events_json: *mut *mut c_char,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || token_incarnation_ptr.is_null() || out_events_json.is_null() {
            set_last_error("invalid arguments passed to mesh_group_handle_confirm_saved");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let mut incarnation = [0u8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(token_incarnation_ptr, incarnation.as_mut_ptr(), 32);
        }
        let token = mesh_identity::groups::handle::SaveToken::new(token_counter, incarnation);
        let events = handle.group_handle.confirm_saved(token);
        let json_events: Vec<EventJson> = events.iter().map(event_to_json).collect();
        let s = match serde_json::to_string(&json_events) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        let c_str = match CString::new(s) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        unsafe {
            *out_events_json = c_str.into_raw();
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Retrieve and remove all released outgoing frames ready to transmit over the network.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `out_outgoing_json` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_take_outgoing(
    handle: *mut MeshGroupHandle,
    out_outgoing_json: *mut *mut c_char,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_outgoing_json.is_null() {
            set_last_error("invalid arguments passed to mesh_group_handle_take_outgoing");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let outgoing = handle.group_handle.take_outgoing();
        let json_outgoing: Vec<OutgoingJson> = outgoing
            .iter()
            .map(|o| OutgoingJson {
                from: hex::encode(o.from),
                to: o.to.iter().map(hex::encode).collect(),
                tag: o.kind as u8,
                bytes: hex::encode(&o.bytes),
                authenticator: o.authenticator.map(hex::encode),
            })
            .collect();
        let s = match serde_json::to_string(&json_outgoing) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        let c_str = match CString::new(s) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        unsafe {
            *out_outgoing_json = c_str.into_raw();
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Re-stage the frames of an operation without re-signing.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_resend(handle: *mut MeshGroupHandle, op_id: u64) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            set_last_error("handle is null in mesh_group_handle_resend");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        match handle
            .group_handle
            .resend(mesh_identity::groups::handle::OpId(op_id))
        {
            Ok(()) => MESH_OK,
            Err(e) => {
                set_last_error(handle_error_to_str(&e));
                map_handle_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Query the execution state of an operation by ID.
///
/// # Safety
///
/// - `handle` must be a valid, non-null pointer to a `MeshGroupHandle`.
/// - `out_json` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_op_state(
    handle: *mut MeshGroupHandle,
    op_id: u64,
    out_json: *mut *mut c_char,
) -> i32 {
    clear_last_error();
    let handle_ptr = handle;
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_json.is_null() {
            set_last_error("invalid arguments passed to mesh_group_handle_op_state");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("group handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let state = match handle
            .group_handle
            .op_state(mesh_identity::groups::handle::OpId(op_id))
        {
            Some(s) => s,
            None => {
                set_last_error("operation not found");
                return MESH_ERR_NOT_FOUND;
            }
        };
        use mesh_identity::groups::handle::OpState;
        let op_json = match state {
            OpState::Pending => OpStateJson {
                status: "Pending".to_string(),
                reason: None,
            },
            OpState::Completed => OpStateJson {
                status: "Completed".to_string(),
                reason: None,
            },
            OpState::Rejected(r) => OpStateJson {
                status: "Rejected".to_string(),
                reason: Some(reason_to_str(r).to_string()),
            },
            OpState::Retryable(r) => OpStateJson {
                status: "Retryable".to_string(),
                reason: Some(reason_to_str(r).to_string()),
            },
        };
        let s = match serde_json::to_string(&op_json) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        let c_str = match CString::new(s) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };
        unsafe {
            *out_json = c_str.into_raw();
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Restore a `MeshGroupHandle` from a snapshot blob and known identity seeds.
///
/// # Safety
///
/// - `blob_ptr` must point to at least `blob_len` readable bytes.
/// - `seeds_ptr` must point to at least `seeds_count * 32` readable bytes.
/// - `out_handle` must be a valid, non-null writable pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_group_handle_restore(
    blob_ptr: *const u8,
    blob_len: usize,
    seeds_ptr: *const u8,
    seeds_count: usize,
    out_handle: *mut *mut MeshGroupHandle,
) -> i32 {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if blob_ptr.is_null()
            || blob_len == 0
            || blob_len > MAX_GROUP_SNAPSHOT_BYTES
            || seeds_ptr.is_null()
            || seeds_count == 0
            || seeds_count > MAX_SEEDS_CEILING
            || out_handle.is_null()
        {
            set_last_error("invalid arguments passed to mesh_group_handle_restore");
            return MESH_ERR_INVALID_ARG;
        }

        let total_seed_bytes = match seeds_count.checked_mul(32) {
            Some(n) => n,
            None => {
                set_last_error("seeds_count calculation overflowed");
                return MESH_ERR_INVALID_ARG;
            }
        };

        let blob = unsafe { slice::from_raw_parts(blob_ptr, blob_len) };
        let raw_seeds = unsafe { slice::from_raw_parts(seeds_ptr, total_seed_bytes) };
        let mut keys = Vec::with_capacity(seeds_count);
        for chunk in raw_seeds.as_chunks::<32>().0 {
            let mut seed_copy = *chunk;
            keys.push(SigningKey::from_bytes(&seed_copy));
            seed_copy.zeroize();
        }

        match mesh_identity::groups::handle::GroupHandle::restore(blob, keys) {
            Ok(group_handle) => {
                let handle = Box::into_raw(Box::new(MeshGroupHandle {
                    group_handle,
                    is_poisoned: false,
                }));
                unsafe {
                    *out_handle = handle;
                }
                MESH_OK
            }
            Err(e) => {
                set_last_error(handle_error_to_str(&e));
                map_handle_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        set_last_error("native panic caught at FFI boundary");
        MESH_ERR_PANIC
    })
}

// ============================================================================
// OpenPGP Interoperability Bridge (Slice 5)
// ============================================================================

fn map_import_error(err: &mesh_identity::openpgp::ImportError) -> i32 {
    use mesh_identity::openpgp::ImportError::*;
    match err {
        Certificate(_) => MESH_ERR_OPENPGP_CERTIFICATE,
        InvalidBinding => MESH_ERR_OPENPGP_INVALID_BINDING,
        KeyMismatch => MESH_ERR_OPENPGP_KEY_MISMATCH,
        SecretMaterial => MESH_ERR_OPENPGP_SECRET_MATERIAL,
        SecretMissing | UnlockFailed | InvalidSecret => MESH_ERR_OPENPGP_SECRET_MISSING,
        Contact(e) => map_installation_error(e),
        RevocationCapacity => MESH_ERR_OPENPGP_REVOCATION_CAPACITY,
    }
}

fn extract_public_key_bytes(pub_params: &pgp::types::PublicParams) -> Option<&[u8]> {
    match pub_params {
        pgp::types::PublicParams::EdDSALegacy(pgp::types::EddsaLegacyPublicParams::Ed25519 {
            key,
        }) => Some(key.as_bytes()),
        pgp::types::PublicParams::Ed25519(pgp::types::Ed25519PublicParams { key }) => {
            Some(key.as_bytes())
        }
        _ => None,
    }
}

fn algorithm_to_str(algo: pgp::crypto::public_key::PublicKeyAlgorithm) -> &'static str {
    match algo {
        pgp::crypto::public_key::PublicKeyAlgorithm::EdDSALegacy => "EdDSALegacy",
        pgp::crypto::public_key::PublicKeyAlgorithm::Ed25519 => "Ed25519",
        pgp::crypto::public_key::PublicKeyAlgorithm::RSA => "RSA",
        pgp::crypto::public_key::PublicKeyAlgorithm::DSA => "DSA",
        pgp::crypto::public_key::PublicKeyAlgorithm::ECDSA => "ECDSA",
        pgp::crypto::public_key::PublicKeyAlgorithm::ECDH => "ECDH",
        _ => "Unknown",
    }
}

#[derive(Serialize)]
struct OpenPgpSubkeyJson {
    fingerprint: String,
    algorithm: String,
    key_bytes: String,
}

#[derive(Serialize)]
struct OpenPgpCertificateJson {
    fingerprint: String,
    version: i32,
    algorithm: String,
    primary_key_bytes: String,
    user_ids: Vec<String>,
    subkeys: Vec<OpenPgpSubkeyJson>,
}

#[derive(Serialize)]
struct OpenPgpProvenanceJson {
    primary_fingerprint: String,
    signing_key_fingerprint: String,
    user_id: String,
}

#[derive(Serialize)]
struct PeerSignatureJson {
    label: String,
    signature_hex: String,
}

/// Opaque wrapper for a pending OpenPGP export preview.
pub struct MeshOpenPgpPreviewHandle {
    pub preview: Option<mesh_identity::openpgp::ExportPreview>,
}

/// Parse and inspect an OpenPGP public key or certificate.
///
/// Returns a JSON string describing the certificate metadata in `*out_json`.
/// The returned string must be freed with `mesh_string_free`.
///
/// # Safety
///
/// - `cert_ptr` must point to `cert_len` readable bytes.
/// - `out_json` must be a valid, writable pointer to `*mut c_char`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_openpgp_inspect_certificate(
    cert_ptr: *const u8,
    cert_len: usize,
    out_json: *mut *mut c_char,
) -> i32 {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if cert_ptr.is_null()
            || cert_len == 0
            || cert_len > MAX_OPENPGP_CERTIFICATE_BYTES
            || out_json.is_null()
        {
            set_last_error("invalid arguments passed to mesh_openpgp_inspect_certificate");
            return MESH_ERR_INVALID_ARG;
        }

        let cert_bytes = unsafe { slice::from_raw_parts(cert_ptr, cert_len) };
        let cert = match mesh_identity::openpgp::parse_public_peer(cert_bytes) {
            Ok(c) => c,
            Err(e) => {
                set_last_error(format!("{e}"));
                return map_import_error(&e);
            }
        };

        let version = match cert.primary_key.version() {
            pgp::types::KeyVersion::V2 => 2,
            pgp::types::KeyVersion::V3 => 3,
            pgp::types::KeyVersion::V4 => 4,
            pgp::types::KeyVersion::V5 => 5,
            pgp::types::KeyVersion::V6 => 6,
            pgp::types::KeyVersion::Other(v) => i32::from(v),
        };
        let algorithm = algorithm_to_str(cert.primary_key.algorithm()).to_string();
        let primary_key_bytes = extract_public_key_bytes(cert.primary_key.public_params())
            .map(hex::encode)
            .unwrap_or_default();
        let user_ids: Vec<String> = cert
            .details
            .users
            .iter()
            .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
            .collect();
        let subkeys: Vec<OpenPgpSubkeyJson> = cert
            .public_subkeys
            .iter()
            .map(|sub| {
                let key_bytes = extract_public_key_bytes(sub.key.public_params())
                    .map(hex::encode)
                    .unwrap_or_default();
                OpenPgpSubkeyJson {
                    fingerprint: hex::encode(sub.key.fingerprint().as_bytes()),
                    algorithm: algorithm_to_str(sub.key.algorithm()).to_string(),
                    key_bytes,
                }
            })
            .collect();

        let json_struct = OpenPgpCertificateJson {
            fingerprint: hex::encode(cert.primary_key.fingerprint().as_bytes()),
            version,
            algorithm,
            primary_key_bytes,
            user_ids,
            subkeys,
        };

        let s = match serde_json::to_string(&json_struct) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };

        let cstr = match CString::new(s) {
            Ok(c) => c,
            Err(_) => {
                set_last_error("failed to create CString from certificate inspection JSON");
                return MESH_ERR_INTERNAL;
            }
        };

        unsafe {
            *out_json = cstr.into_raw();
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        set_last_error("native panic caught at FFI boundary");
        MESH_ERR_PANIC
    })
}

/// Import an OpenPGP peer certificate into this installation as an unverified contact.
///
/// Returns the provenance metadata JSON in `*out_provenance_json`.
/// Must be freed with `mesh_string_free`.
///
/// # Safety
///
/// - `handle` must be a valid pointer to a `MeshInstallationHandle`.
/// - `cert_ptr`, `expected_pk_ptr`, `uid_ptr`, and `out_provenance_json` must be valid non-null pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_openpgp_import_peer(
    handle: *mut MeshInstallationHandle,
    cert_ptr: *const u8,
    cert_len: usize,
    expected_pk_ptr: *const u8,
    expected_pk_len: usize,
    uid_ptr: *const u8,
    uid_len: usize,
    timestamp_secs: u64,
    out_provenance_json: *mut *mut c_char,
) -> i32 {
    let handle_ptr = handle;
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || cert_ptr.is_null()
            || cert_len == 0
            || cert_len > MAX_OPENPGP_CERTIFICATE_BYTES
            || expected_pk_ptr.is_null()
            || expected_pk_len != 32
            || uid_ptr.is_null()
            || uid_len == 0
            || uid_len > MAX_OPENPGP_USER_ID_BYTES
            || out_provenance_json.is_null()
        {
            set_last_error("invalid arguments passed to mesh_installation_openpgp_import_peer");
            return MESH_ERR_INVALID_ARG;
        }

        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }

        let cert = unsafe { slice::from_raw_parts(cert_ptr, cert_len) };
        let mut expected = [0u8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(expected_pk_ptr, expected.as_mut_ptr(), 32);
        }
        let uid = unsafe { slice::from_raw_parts(uid_ptr, uid_len) };
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp_secs);

        let (_record, provenance) = match mesh_identity::openpgp::import_peer(
            handle.installation_mut(),
            cert,
            expected,
            uid,
            time,
            &mut OsRng,
        ) {
            Ok(res) => res,
            Err(e) => {
                set_last_error(format!("{e}"));
                return map_import_error(&e);
            }
        };

        let prov_struct = OpenPgpProvenanceJson {
            primary_fingerprint: hex::encode(provenance.primary.as_bytes()),
            signing_key_fingerprint: hex::encode(provenance.signing_key.as_bytes()),
            user_id: String::from_utf8_lossy(&provenance.user_id).into_owned(),
        };

        let s = match serde_json::to_string(&prov_struct) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };

        let cstr = match CString::new(s) {
            Ok(c) => c,
            Err(_) => {
                set_last_error("failed to create CString from provenance JSON");
                return MESH_ERR_INTERNAL;
            }
        };

        unsafe {
            *out_provenance_json = cstr.into_raw();
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Import an OpenPGP secret key as an owned identity in this installation.
///
/// Returns provenance metadata JSON in `*out_provenance_json`.
/// Must be freed with `mesh_string_free`.
///
/// # Safety
///
/// - `handle` must be a valid pointer to a `MeshInstallationHandle`.
/// - `cert_ptr`, `expected_pk_ptr`, `uid_ptr`, `out_provenance_json`, and `out_seed` must be valid non-null pointers.
/// - `out_seed` must point to at least 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_openpgp_import_owned(
    handle: *mut MeshInstallationHandle,
    cert_ptr: *const u8,
    cert_len: usize,
    expected_pk_ptr: *const u8,
    expected_pk_len: usize,
    uid_ptr: *const u8,
    uid_len: usize,
    timestamp_secs: u64,
    passphrase_ptr: *const u8,
    passphrase_len: usize,
    out_provenance_json: *mut *mut c_char,
    out_seed: *mut u8,
) -> i32 {
    let handle_ptr = handle;
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || cert_ptr.is_null()
            || cert_len == 0
            || cert_len > MAX_OPENPGP_CERTIFICATE_BYTES
            || expected_pk_ptr.is_null()
            || expected_pk_len != 32
            || uid_ptr.is_null()
            || uid_len == 0
            || uid_len > MAX_OPENPGP_USER_ID_BYTES
            || passphrase_len > MAX_OPENPGP_PASSPHRASE_BYTES
            || out_provenance_json.is_null()
            || out_seed.is_null()
        {
            set_last_error("invalid arguments passed to mesh_installation_openpgp_import_owned");
            return MESH_ERR_INVALID_ARG;
        }

        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }

        let cert = unsafe { slice::from_raw_parts(cert_ptr, cert_len) };
        let mut expected = [0u8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(expected_pk_ptr, expected.as_mut_ptr(), 32);
        }
        let uid = unsafe { slice::from_raw_parts(uid_ptr, uid_len) };
        let passphrase = if passphrase_ptr.is_null() || passphrase_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(passphrase_ptr, passphrase_len) }
        };
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp_secs);

        let (mut seed, provenance) = match mesh_identity::openpgp::import_owned_with_seed(
            handle.installation_mut(),
            cert,
            expected,
            uid,
            time,
            passphrase,
        ) {
            Ok(res) => res,
            Err(e) => {
                set_last_error(format!("{e}"));
                return map_import_error(&e);
            }
        };

        unsafe {
            std::ptr::copy_nonoverlapping(seed.as_ptr(), out_seed, 32);
        }
        seed.fill(0);

        let prov_struct = OpenPgpProvenanceJson {
            primary_fingerprint: hex::encode(provenance.primary.as_bytes()),
            signing_key_fingerprint: hex::encode(provenance.signing_key.as_bytes()),
            user_id: String::from_utf8_lossy(&provenance.user_id).into_owned(),
        };

        let s = match serde_json::to_string(&prov_struct) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };

        let cstr = match CString::new(s) {
            Ok(c) => c,
            Err(_) => {
                set_last_error("failed to create CString from provenance JSON");
                return MESH_ERR_INTERNAL;
            }
        };

        unsafe {
            *out_provenance_json = cstr.into_raw();
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Standalone extraction of the 32-byte Ed25519 signing seed from an OpenPGP secret key certificate.
///
/// Copies exactly 32 bytes into `out_seed`.
///
/// # Safety
///
/// - `cert_ptr`, `expected_pk_ptr`, `uid_ptr`, and `out_seed` must be valid non-null pointers.
/// - `out_seed` must point to at least 32 writable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_openpgp_extract_secret_seed(
    cert_ptr: *const u8,
    cert_len: usize,
    expected_pk_ptr: *const u8,
    expected_pk_len: usize,
    uid_ptr: *const u8,
    uid_len: usize,
    timestamp_secs: u64,
    passphrase_ptr: *const u8,
    passphrase_len: usize,
    out_seed: *mut u8,
) -> i32 {
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if cert_ptr.is_null()
            || cert_len == 0
            || cert_len > MAX_OPENPGP_CERTIFICATE_BYTES
            || expected_pk_ptr.is_null()
            || expected_pk_len != 32
            || uid_ptr.is_null()
            || uid_len == 0
            || uid_len > MAX_OPENPGP_USER_ID_BYTES
            || passphrase_len > MAX_OPENPGP_PASSPHRASE_BYTES
            || out_seed.is_null()
        {
            set_last_error("invalid arguments passed to mesh_openpgp_extract_secret_seed");
            return MESH_ERR_INVALID_ARG;
        }

        let cert = unsafe { slice::from_raw_parts(cert_ptr, cert_len) };
        let mut expected = [0u8; 32];
        unsafe {
            std::ptr::copy_nonoverlapping(expected_pk_ptr, expected.as_mut_ptr(), 32);
        }
        let uid = unsafe { slice::from_raw_parts(uid_ptr, uid_len) };
        let passphrase = if passphrase_ptr.is_null() || passphrase_len == 0 {
            &[][..]
        } else {
            unsafe { slice::from_raw_parts(passphrase_ptr, passphrase_len) }
        };
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp_secs);

        let mut seed = match mesh_identity::openpgp::extract_secret_seed(
            cert, expected, uid, time, passphrase,
        ) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(format!("{e}"));
                return map_import_error(&e);
            }
        };

        unsafe {
            std::ptr::copy_nonoverlapping(seed.as_ptr(), out_seed, 32);
        }
        seed.fill(0);
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        set_last_error("native panic caught at FFI boundary in mesh_openpgp_extract_secret_seed");
        MESH_ERR_PANIC
    })
}

/// Create an OpenPGP export preview session awaiting user confirmation.
///
/// Returns an allocated `MeshOpenPgpPreviewHandle` in `*out_preview`, statutory warning string
/// in `*out_warning` (must be freed with `mesh_string_free`), and optional peer fingerprint string in `*out_peer_fp`.
///
/// # Safety
///
/// - `handle` must be a valid pointer to a `MeshInstallationHandle`.
/// - `uid_ptr`, `doc_ptr`, `out_preview`, and `out_warning` must be valid non-null pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_openpgp_preview(
    handle: *mut MeshInstallationHandle,
    profile_i32: i32,
    uid_ptr: *const u8,
    uid_len: usize,
    created_secs: u32,
    doc_ptr: *const u8,
    doc_len: usize,
    peer_cert_ptr: *const u8,
    peer_cert_len: usize,
    peer_uid_ptr: *const u8,
    peer_uid_len: usize,
    out_preview: *mut *mut MeshOpenPgpPreviewHandle,
    out_warning: *mut *mut c_char,
    out_peer_fp: *mut *mut c_char,
) -> i32 {
    let handle_ptr = handle;
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || uid_ptr.is_null()
            || uid_len == 0
            || uid_len > MAX_OPENPGP_USER_ID_BYTES
            || doc_ptr.is_null()
            || doc_len > MAX_OPENPGP_DOCUMENT_BYTES
            || out_preview.is_null()
            || out_warning.is_null()
            || out_peer_fp.is_null()
        {
            set_last_error("invalid arguments passed to mesh_installation_openpgp_preview");
            return MESH_ERR_INVALID_ARG;
        }

        let profile = match profile_i32 {
            0 => mesh_identity::openpgp::ExportProfile::V4,
            1 => mesh_identity::openpgp::ExportProfile::V6,
            _ => {
                set_last_error("invalid OpenPGP profile (must be 0 for v4 or 1 for v6)");
                return MESH_ERR_INVALID_ARG;
            }
        };

        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }

        let uid = unsafe { slice::from_raw_parts(uid_ptr, uid_len) };
        let doc = unsafe { slice::from_raw_parts(doc_ptr, doc_len) };

        let peer = if !peer_cert_ptr.is_null() && peer_cert_len > 0 {
            if peer_cert_len > MAX_OPENPGP_CERTIFICATE_BYTES
                || peer_uid_ptr.is_null()
                || peer_uid_len == 0
                || peer_uid_len > MAX_OPENPGP_USER_ID_BYTES
            {
                set_last_error("invalid peer certificate arguments for cross-certification");
                return MESH_ERR_INVALID_ARG;
            }
            let peer_cert = unsafe { slice::from_raw_parts(peer_cert_ptr, peer_cert_len) };
            let peer_uid = unsafe { slice::from_raw_parts(peer_uid_ptr, peer_uid_len) };
            Some((peer_cert.to_vec(), peer_uid.to_vec()))
        } else {
            None
        };

        let preview = match mesh_identity::openpgp::ExportPreview::new(
            handle.installation_mut(),
            profile,
            uid.to_vec(),
            created_secs,
            doc.to_vec(),
            peer,
        ) {
            Ok(p) => p,
            Err(e) => {
                set_last_error(format!("{e}"));
                return map_import_error(&e);
            }
        };

        let warning_cstr = match CString::new(mesh_identity::openpgp::ExportPreview::WARNING) {
            Ok(c) => c,
            Err(_) => {
                set_last_error("failed to create warning CString");
                return MESH_ERR_INTERNAL;
            }
        };

        let peer_fp_cstr = if let Some((fp, _)) = preview.certification_target() {
            CString::new(hex::encode(fp.as_bytes())).ok()
        } else {
            None
        };

        unsafe {
            *out_preview = Box::into_raw(Box::new(MeshOpenPgpPreviewHandle {
                preview: Some(preview),
            }));
            *out_warning = warning_cstr.into_raw();
            *out_peer_fp = peer_fp_cstr
                .map(CString::into_raw)
                .unwrap_or(std::ptr::null_mut());
        }
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Confirm an OpenPGP export preview, consuming the preview handle and issuing artifacts.
///
/// Returns allocated certificate buffer, detached signature buffer, and peer cross-certification JSON.
/// Buffers must be freed with `mesh_buffer_free` and `mesh_string_free`.
///
/// # Safety
///
/// - `preview_handle` must be a valid, non-null pointer to `MeshOpenPgpPreviewHandle`.
/// - `installation_handle` must be a valid, non-null pointer to `MeshInstallationHandle`.
/// - Out pointers must be valid and non-null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_openpgp_preview_confirm(
    preview_handle: *mut MeshOpenPgpPreviewHandle,
    installation_handle: *mut MeshInstallationHandle,
    out_cert_ptr: *mut *mut u8,
    out_cert_len: *mut usize,
    out_detached_ptr: *mut *mut u8,
    out_detached_len: *mut usize,
    out_peer_signatures_json: *mut *mut c_char,
) -> i32 {
    let inst_ptr = installation_handle;
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if preview_handle.is_null() {
            set_last_error("preview_handle is null in mesh_openpgp_preview_confirm");
            return MESH_ERR_INVALID_ARG;
        }

        // Take ownership immediately so preview_handle is reliably deallocated on any return path.
        let mut boxed_preview = unsafe { Box::from_raw(preview_handle) };

        if installation_handle.is_null()
            || out_cert_ptr.is_null()
            || out_cert_len.is_null()
            || out_detached_ptr.is_null()
            || out_detached_len.is_null()
            || out_peer_signatures_json.is_null()
        {
            set_last_error("invalid arguments passed to mesh_openpgp_preview_confirm");
            return MESH_ERR_INVALID_ARG;
        }

        let inst = unsafe { &mut *installation_handle };
        if inst.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }

        let preview = match boxed_preview.preview.take() {
            Some(p) => p,
            None => {
                set_last_error("OpenPGP export preview has already been confirmed or disposed");
                return MESH_ERR_OPENPGP_PREVIEW_EXPIRED;
            }
        };

        let artifacts = match preview.confirm(inst.installation_mut()) {
            Ok(a) => a,
            Err(e) => {
                let err_str = e.to_string();
                set_last_error(err_str.clone());
                if err_str.contains("no longer current") {
                    return MESH_ERR_OPENPGP_PREVIEW_EXPIRED;
                } else if err_str.contains("selected identity does not match") {
                    return MESH_ERR_OPENPGP_KEY_MISMATCH;
                } else {
                    return MESH_ERR_OPENPGP_CERTIFICATE;
                }
            }
        };

        let mut cert_boxed = artifacts.certificate.into_boxed_slice();
        let mut detached_boxed = artifacts.detached.into_boxed_slice();

        let peer_sigs: Vec<PeerSignatureJson> = artifacts
            .peer_signatures
            .into_iter()
            .map(|(label, bytes)| PeerSignatureJson {
                label: label.to_string(),
                signature_hex: hex::encode(bytes),
            })
            .collect();

        let peer_sigs_json = match serde_json::to_string(&peer_sigs) {
            Ok(s) => s,
            Err(e) => {
                set_last_error(e.to_string());
                return MESH_ERR_INTERNAL;
            }
        };

        let peer_sigs_cstr = match CString::new(peer_sigs_json) {
            Ok(c) => c,
            Err(_) => {
                set_last_error("failed to create CString from peer signatures JSON");
                return MESH_ERR_INTERNAL;
            }
        };

        unsafe {
            *out_cert_ptr = cert_boxed.as_mut_ptr();
            *out_cert_len = cert_boxed.len();
            *out_detached_ptr = detached_boxed.as_mut_ptr();
            *out_detached_len = detached_boxed.len();
            *out_peer_signatures_json = peer_sigs_cstr.into_raw();
        }

        std::mem::forget(cert_boxed);
        std::mem::forget(detached_boxed);
        MESH_OK
    }));
    result.unwrap_or_else(|_| {
        if !inst_ptr.is_null() {
            unsafe {
                (*inst_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}

/// Free an unconfirmed `MeshOpenPgpPreviewHandle`.
///
/// # Safety
///
/// - `handle` must be null or a valid pointer to a `MeshOpenPgpPreviewHandle` that has not yet been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_openpgp_preview_free(handle: *mut MeshOpenPgpPreviewHandle) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !handle.is_null() {
            drop(unsafe { Box::from_raw(handle) });
        }
    }));
}

/// Remember OpenPGP peer revocation signatures in this installation.
///
/// # Safety
///
/// - `handle` must be a valid pointer to a `MeshInstallationHandle`.
/// - `rev_ptr` must point to `rev_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mesh_installation_openpgp_remember_revocations(
    handle: *mut MeshInstallationHandle,
    rev_ptr: *const u8,
    rev_len: usize,
) -> i32 {
    let handle_ptr = handle;
    clear_last_error();
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null()
            || rev_ptr.is_null()
            || rev_len == 0
            || rev_len > MAX_OPENPGP_CERTIFICATE_BYTES
        {
            set_last_error(
                "invalid arguments passed to mesh_installation_openpgp_remember_revocations",
            );
            return MESH_ERR_INVALID_ARG;
        }

        let handle = unsafe { &mut *handle };
        if handle.is_poisoned() {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }

        let rev_bytes = unsafe { slice::from_raw_parts(rev_ptr, rev_len) };
        match mesh_identity::openpgp::remember_peer_revocations(
            handle.installation_mut(),
            rev_bytes,
        ) {
            Ok(_) => MESH_OK,
            Err(e) => {
                set_last_error(format!("{e}"));
                map_import_error(&e)
            }
        }
    }));
    result.unwrap_or_else(|_| {
        if !handle_ptr.is_null() {
            unsafe {
                (*handle_ptr).is_poisoned = true;
            }
        }
        set_last_error("native panic caught at FFI boundary; handle is now poisoned");
        MESH_ERR_PANIC
    })
}
