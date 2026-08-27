//! C ABI for Dart FRB wire / `dart:ffi`. Keep JSON-string oriented.

use crate::crypto_ffi::{
    ffi_generate_key_and_csr_json, ffi_materialize_mtls_client_json,
    ffi_sign_client_cert_from_csr_json, ffi_sign_json_b64url_json,
    ffi_verify_ed25519_cert_json,
};
use crate::ffi::{
    ffi_ensure_billing_context_json, ffi_error_codes, ffi_init_license_json,
    ffi_normalize_api_base_url, ffi_parse_session_json, ffi_should_poll_json,
    ffi_sync_license_json, ffi_validate_config_json, ffi_verify_license_json,
};
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

unsafe fn cstr_to_string(ptr: *const c_char) -> Option<String> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok().map(|s| s.to_owned())
}

fn to_c_string(s: String) -> *mut c_char {
    CString::new(s.replace('\0', ""))
        .map(|c| c.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Free a string returned by this ABI.
///
/// # Safety
/// `ptr` must be null or a pointer previously returned by this crate's C API.
#[no_mangle]
pub unsafe extern "C" fn two_key_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    drop(CString::from_raw(ptr));
}

/// Normalize API base URL. Caller must `two_key_string_free` the result.
///
/// # Safety
/// `input` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn two_key_normalize_api_base_url(input: *const c_char) -> *mut c_char {
    let Some(s) = cstr_to_string(input) else {
        return std::ptr::null_mut();
    };
    to_c_string(ffi_normalize_api_base_url(s))
}

/// Verify license JWT → JSON. Caller must free the result.
///
/// # Safety
/// `pem` and `jwt` must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn two_key_verify_license_json(
    pem: *const c_char,
    jwt: *const c_char,
) -> *mut c_char {
    let Some(pem) = cstr_to_string(pem) else {
        return to_c_string(r#"{"ok":false,"code":"config","message":"null pem"}"#.into());
    };
    let Some(jwt) = cstr_to_string(jwt) else {
        return to_c_string(
            r#"{"ok":false,"code":"license_malformed","message":"null jwt"}"#.into(),
        );
    };
    to_c_string(ffi_verify_license_json(pem, jwt))
}

/// Offline init (alias of verify). Caller must free the result.
///
/// # Safety
/// Pointers must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn two_key_init_license_json(
    pem: *const c_char,
    jwt: *const c_char,
) -> *mut c_char {
    let Some(pem) = cstr_to_string(pem) else {
        return to_c_string(r#"{"ok":false,"code":"config","message":"null pem"}"#.into());
    };
    let Some(jwt) = cstr_to_string(jwt) else {
        return to_c_string(
            r#"{"ok":false,"code":"license_malformed","message":"null jwt"}"#.into(),
        );
    };
    to_c_string(ffi_init_license_json(pem, jwt))
}

/// Online license sync → JSON. Caller must free the result.
///
/// # Safety
/// All pointers must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn two_key_sync_license_json(
    api_base_url: *const c_char,
    pem: *const c_char,
    session_json: *const c_char,
) -> *mut c_char {
    let api = cstr_to_string(api_base_url).unwrap_or_default();
    let pem = cstr_to_string(pem).unwrap_or_default();
    let session = cstr_to_string(session_json).unwrap_or_default();
    to_c_string(ffi_sync_license_json(api, pem, session))
}

/// Bootstrap billing context → JSON. Caller must free the result.
///
/// # Safety
/// Pointers must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn two_key_ensure_billing_context_json(
    api_base_url: *const c_char,
    access_token: *const c_char,
) -> *mut c_char {
    let api = cstr_to_string(api_base_url).unwrap_or_default();
    let token = cstr_to_string(access_token).unwrap_or_default();
    to_c_string(ffi_ensure_billing_context_json(api, token))
}

/// Should-poll hint → JSON. Caller must free the result.
///
/// # Safety
/// `pem` must be a valid NUL-terminated C string. `license_jwt` may be null.
#[no_mangle]
pub unsafe extern "C" fn two_key_should_poll_json(
    pem: *const c_char,
    license_jwt: *const c_char,
) -> *mut c_char {
    let pem = cstr_to_string(pem).unwrap_or_default();
    let jwt = cstr_to_string(license_jwt);
    to_c_string(ffi_should_poll_json(pem, jwt))
}

/// Validate session JSON shape. Caller must free the result.
///
/// # Safety
/// `session_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn two_key_parse_session_json(session_json: *const c_char) -> *mut c_char {
    let session = cstr_to_string(session_json).unwrap_or_default();
    to_c_string(ffi_parse_session_json(session))
}

/// Validate config → JSON. Caller must free the result.
///
/// # Safety
/// All pointers must be valid NUL-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn two_key_validate_config_json(
    api_base_url: *const c_char,
    public_key_pem: *const c_char,
    storage_prefix: *const c_char,
) -> *mut c_char {
    let api = cstr_to_string(api_base_url).unwrap_or_default();
    let pem = cstr_to_string(public_key_pem).unwrap_or_default();
    let prefix = cstr_to_string(storage_prefix).unwrap_or_default();
    to_c_string(ffi_validate_config_json(api, pem, prefix))
}

/// Comma-separated error codes. Caller must free the result.
#[no_mangle]
pub extern "C" fn two_key_error_codes() -> *mut c_char {
    to_c_string(ffi_error_codes().join(","))
}

/// Generate device key + CSR → JSON. Caller must free the result.
///
/// # Safety
/// `input_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn two_key_crypto_generate_key_and_csr_json(
    input_json: *const c_char,
) -> *mut c_char {
    let input = cstr_to_string(input_json).unwrap_or_default();
    to_c_string(ffi_generate_key_and_csr_json(input))
}

/// Sign CSR with CA → JSON leaf + chain. Caller must free the result.
///
/// # Safety
/// `input_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn two_key_crypto_sign_client_cert_from_csr_json(
    input_json: *const c_char,
) -> *mut c_char {
    let input = cstr_to_string(input_json).unwrap_or_default();
    to_c_string(ffi_sign_client_cert_from_csr_json(input))
}

/// Verify Ed25519 leaf against issuer PEM → JSON `{ valid: bool }`.
///
/// # Safety
/// `input_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn two_key_crypto_verify_ed25519_cert_json(
    input_json: *const c_char,
) -> *mut c_char {
    let input = cstr_to_string(input_json).unwrap_or_default();
    to_c_string(ffi_verify_ed25519_cert_json(input))
}

/// Materialize mTLS client PEM from identity JSON.
///
/// # Safety
/// `identity_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn two_key_crypto_materialize_mtls_client_json(
    identity_json: *const c_char,
) -> *mut c_char {
    let input = cstr_to_string(identity_json).unwrap_or_default();
    to_c_string(ffi_materialize_mtls_client_json(input))
}

/// Sign JSON with Ed25519 private PEM (agent PoP).
///
/// # Safety
/// `input_json` must be a valid NUL-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn two_key_crypto_sign_json_b64url_json(
    input_json: *const c_char,
) -> *mut c_char {
    let input = cstr_to_string(input_json).unwrap_or_default();
    to_c_string(ffi_sign_json_b64url_json(input))
}
