//! FRB-oriented API surface (flutter_rust_bridge 2.11.x).
//!
//! These free functions are the stable entrypoints for codegen. They wrap
//! [crate::ffi] JSON helpers so Dart owns storage while Rust owns verify +
//! online sync.
//!
//! Codegen (private repo):
//! ```text
//! flutter_rust_bridge_codegen generate --config-file flutter_rust_bridge.yaml
//! ```
//! Vendor generated Dart into `2key-billing-sdks/packages/dart/lib/src/frb/`.
//! Until codegen is wired in CI, the Dart package calls the matching C ABI
//! symbols (`two_key_*`) via the vendored FRB wire adapter.

use crate::ffi::{
    ffi_ensure_billing_context_json, ffi_error_codes, ffi_init_license_json,
    ffi_normalize_api_base_url, ffi_parse_session_json, ffi_should_poll_json,
    ffi_sync_license_json, ffi_validate_config_json, ffi_verify_license_json,
};

/// Normalize billing API base URL.
pub fn frb_normalize_api_base_url(input: String) -> String {
    ffi_normalize_api_base_url(input)
}

/// Offline license verify / init → JSON.
pub fn frb_verify_license(public_key_pem: String, jwt: String) -> String {
    ffi_verify_license_json(public_key_pem, jwt)
}

/// Offline license init (same as verify) → JSON.
pub fn frb_init_license(public_key_pem: String, jwt: String) -> String {
    ffi_init_license_json(public_key_pem, jwt)
}

/// Online license sync → JSON (`status`: `updated` | `not_modified`).
pub fn frb_sync_license(api_base_url: String, public_key_pem: String, session_json: String) -> String {
    ffi_sync_license_json(api_base_url, public_key_pem, session_json)
}

/// Bootstrap `subscriptions/me` → JSON.
pub fn frb_ensure_billing_context(api_base_url: String, access_token: String) -> String {
    ffi_ensure_billing_context_json(api_base_url, access_token)
}

/// Background poll recommendation → JSON.
pub fn frb_should_poll(public_key_pem: String, license_jwt: Option<String>) -> String {
    ffi_should_poll_json(public_key_pem, license_jwt)
}

/// Validate config → JSON.
pub fn frb_validate_config(
    api_base_url: String,
    public_key_pem: String,
    storage_prefix: String,
) -> String {
    ffi_validate_config_json(api_base_url, public_key_pem, storage_prefix)
}

/// Validate session JSON → JSON.
pub fn frb_parse_session(session_json: String) -> String {
    ffi_parse_session_json(session_json)
}

/// Stable error codes.
pub fn frb_error_codes() -> Vec<String> {
    ffi_error_codes()
}
