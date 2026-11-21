use ed25519_dalek::SigningKey;
use mesh_identity::contact::{ContactStatus, VerificationStatus};
use mesh_identity::session::installation::Installation;
use rand::rngs::OsRng;
use serde::Serialize;
use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
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

const MAX_SEEDS_CEILING: usize = 2048;
const MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
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
    let result = catch_unwind(AssertUnwindSafe(|| {
        if out_handle.is_null() {
            set_last_error("out_handle pointer is null");
            return MESH_ERR_INVALID_ARG;
        }

        let signing_key = if seed_ptr.is_null() || seed_len == 0 {
            SigningKey::generate(&mut OsRng)
        } else {
            if seed_len != 32 {
                set_last_error("seed must be exactly 32 bytes");
                return MESH_ERR_INVALID_ARG;
            }
            let bytes = unsafe { slice::from_raw_parts(seed_ptr, 32) };
            let mut seed = [0u8; 32];
            seed.copy_from_slice(bytes);
            let key = SigningKey::from_bytes(&seed);
            seed.zeroize();
            key
        };

        let inst = Installation::new(signing_key);
        let handle = Box::into_raw(Box::new(MeshInstallationHandle {
            installation: inst,
        }));
        unsafe {
            *out_handle = handle;
        }
        MESH_OK
    }));
    result.unwrap_or(MESH_ERR_PANIC)
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
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_pk.is_null() || out_pk_len < 32 {
            set_last_error("invalid arguments passed to mesh_installation_selected");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &*handle };
        let selected = handle.installation.selected();
        unsafe {
            std::ptr::copy_nonoverlapping(selected.as_ptr(), out_pk, 32);
        }
        MESH_OK
    }));
    result.unwrap_or(MESH_ERR_PANIC)
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
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return 0;
        }
        let handle = unsafe { &*handle };
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
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_pk.is_null() || out_pk_len < 32 {
            set_last_error("invalid arguments passed to mesh_installation_identities_get");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &*handle };
        let identities = handle.installation.identities();
        if let Some(pk) = identities.get(index) {
            unsafe {
                std::ptr::copy_nonoverlapping(pk.as_ptr(), out_pk, 32);
            }
            MESH_OK
        } else {
            set_last_error("index out of bounds in mesh_installation_identities_get");
            MESH_ERR_NOT_FOUND
        }
    }));
    result.unwrap_or(MESH_ERR_PANIC)
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
    timestamp: u64,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || key_ptr.is_null() || key_len != 32 {
            set_last_error("invalid arguments passed to mesh_installation_select_identity");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        let bytes = unsafe { slice::from_raw_parts(key_ptr, 32) };
        let mut identity = [0u8; 32];
        identity.copy_from_slice(bytes);

        match handle.installation.select(identity, timestamp) {
            Ok(()) => MESH_OK,
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or(MESH_ERR_PANIC)
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
    result.unwrap_or(MESH_ERR_PANIC)
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
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || key_ptr.is_null() || key_len != 32 {
            set_last_error("invalid arguments passed to mesh_installation_remove_identity");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
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
    result.unwrap_or(MESH_ERR_PANIC)
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
    timestamp: u64,
    out_buf: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out_buf.is_null() || out_len.is_null() {
            set_last_error("invalid pointers passed to mesh_installation_save");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
        match handle.installation.save_bytes(timestamp) {
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
                MESH_ERR_INVALID_SNAPSHOT
            }
        }
    }));
    result.unwrap_or(MESH_ERR_PANIC)
}

/// Free a byte buffer allocated by `mesh_installation_save`.
///
/// # Safety
///
/// - `buf` must be null or point to a buffer allocated by `mesh_installation_save` of length `len`.
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
                }));
                unsafe {
                    *out_handle = handle;
                }
                MESH_OK
            }
            Err(e) => {
                set_last_error(e.to_string());
                MESH_ERR_INVALID_SNAPSHOT
            }
        }
    }));
    result.unwrap_or(MESH_ERR_PANIC)
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
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            return 0;
        }
        let handle = unsafe { &*handle };
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
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || peer_pk.is_null() || peer_pk_len != 32 || out_json.is_null() {
            set_last_error("invalid arguments passed to mesh_installation_get_contact");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &*handle };
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
            None => {
                set_last_error("contact not found");
                MESH_ERR_NOT_FOUND
            }
        }
    }));
    result.unwrap_or(MESH_ERR_PANIC)
}

/// Free a C string allocated by `mesh_installation_get_contact`.
///
/// # Safety
///
/// - `ptr` must be null or point to a C string allocated by `mesh_installation_get_contact`.
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
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || peer_pk.is_null() || peer_pk_len != 32 {
            set_last_error("invalid arguments passed to mesh_installation_block_contact");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
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
    result.unwrap_or(MESH_ERR_PANIC)
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
    let result = catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || peer_pk.is_null() || peer_pk_len != 32 {
            set_last_error("invalid arguments passed to mesh_installation_import_peer_key");
            return MESH_ERR_INVALID_ARG;
        }
        let handle = unsafe { &mut *handle };
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

        match handle
            .installation
            .import_peer_key(local, peer, &mut OsRng)
        {
            Ok(_) => MESH_OK,
            Err(e) => {
                set_last_error(e.to_string());
                map_installation_error(&e)
            }
        }
    }));
    result.unwrap_or(MESH_ERR_PANIC)
}
