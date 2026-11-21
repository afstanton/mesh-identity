use ed25519_dalek::SigningKey;
use mesh_identity::contact::{ContactStatus, VerificationStatus};
use mesh_identity::session::Comparison;
use mesh_identity::session::installation::{Ceremony, Installation};
use rand::rngs::OsRng;
use serde::Serialize;
use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::c_char;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::slice;
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

const MAX_SEEDS_CEILING: usize = 2048;
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn clear_last_error() {
    LAST_ERROR.with(|cell| {
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
        Error::InvalidContactLink | Error::InvalidRosterCheckpoint | Error::InvalidHandoff => {
            MESH_ERR_INVALID_SNAPSHOT
        }
        Error::CeremonyActive => MESH_ERR_CEREMONY_ACTIVE,
        Error::StaleCeremony => MESH_ERR_STALE_CEREMONY,
        Error::Session(mesh_identity::session::SessionError::Attempt(_)) => MESH_ERR_RATE_LIMITED,
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

/// Opaque wrapper around a local identity `Installation`.
pub struct MeshInstallationHandle {
    pub installation: Installation,
    pub is_poisoned: bool,
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
        let handle = Box::into_raw(Box::new(MeshInstallationHandle {
            installation: inst,
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let selected = handle.installation.selected();
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
        if handle.is_poisoned {
            return 0;
        }
        handle.installation.identities().len()
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let identities = handle.installation.identities();
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let bytes = unsafe { slice::from_raw_parts(key_ptr, 32) };
        let mut identity = [0u8; 32];
        identity.copy_from_slice(bytes);

        match handle.installation.select(identity, now) {
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let bytes = unsafe { slice::from_raw_parts(seed_ptr, 32) };
        let mut seed = [0u8; 32];
        seed.copy_from_slice(bytes);
        let signing_key = SigningKey::from_bytes(&seed);
        seed.zeroize();
        let pk = signing_key.verifying_key().to_bytes();

        match handle.installation.add_identity(signing_key) {
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let bytes = unsafe { slice::from_raw_parts(key_ptr, 32) };
        let mut identity = [0u8; 32];
        identity.copy_from_slice(bytes);

        match handle.installation.remove_identity(identity) {
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        match handle.installation.save_bytes(now) {
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
                let handle = Box::into_raw(Box::new(MeshInstallationHandle {
                    installation: inst,
                    is_poisoned: false,
                }));
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
        if handle.is_poisoned {
            return 0;
        }
        let id = if identity_pk.is_null() {
            handle.installation.selected()
        } else {
            if identity_pk_len != 32 {
                return 0;
            }
            let mut pk = [0u8; 32];
            pk.copy_from_slice(unsafe { slice::from_raw_parts(identity_pk, 32) });
            pk
        };

        handle
            .installation
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let id = if identity_pk.is_null() {
            handle.installation.selected()
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

        let store = match handle.installation.contacts(id) {
            Some(s) => s,
            None => {
                set_last_error("unknown identity in mesh_installation_get_contact");
                return MESH_ERR_UNKNOWN_IDENTITY;
            }
        };

        match store.get(&peer) {
            Some(c) => {
                let info = ContactExportJson {
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
                };
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let id = if identity_pk.is_null() {
            handle.installation.selected()
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

        match handle.installation.block_contact(id, peer) {
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let local = if local_pk.is_null() {
            handle.installation.selected()
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

        match handle.installation.import_peer_key(local, peer, &mut OsRng) {
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        match handle.installation.start(now, &mut OsRng) {
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        match handle.installation.open_scanner(now) {
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let ceremony = unsafe { &mut *ceremony };
        let slice = unsafe { slice::from_raw_parts(bytes, bytes_len) };

        match handle
            .installation
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let ceremony = unsafe { &mut *ceremony };
        let slice = unsafe { slice::from_raw_parts(bytes, bytes_len) };

        match handle
            .installation
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let ceremony = unsafe { &mut *ceremony };
        let slice = unsafe { slice::from_raw_parts(bytes, bytes_len) };

        match handle
            .installation
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let ceremony = unsafe { &mut *ceremony };

        match handle.installation.comparison(&ceremony.ceremony, now) {
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
        if handle.is_poisoned {
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

        match handle.installation.confirm_and_save(
            &ceremony.ceremony,
            comp,
            peer_code,
            now,
            timestamp,
            &mut OsRng,
        ) {
            Ok(record) => {
                let info = ContactExportJson {
                    peer_public_key: hex::encode(record.peer_ed25519_pk),
                    alias: record.local_alias.clone(),
                    status: match record.status {
                        ContactStatus::Active => "active".into(),
                        ContactStatus::Blocked => "blocked".into(),
                    },
                    verification_status: match record.verification_status {
                        VerificationStatus::Verified => "verified".into(),
                        VerificationStatus::ImportedUnverified => "imported_unverified".into(),
                    },
                    encounter_count: record.encounter_count,
                    verified_at: record.verified_at,
                };
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
        if handle.is_poisoned {
            set_last_error("installation handle is poisoned from a prior panic");
            return MESH_ERR_PANIC;
        }
        let ceremony = unsafe { &mut *ceremony };

        match handle.installation.cancel(&ceremony.ceremony, now) {
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
