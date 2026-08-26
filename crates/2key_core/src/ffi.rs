//! Stable string-oriented helpers for FRB / UniFFI / C ABI bindings.
//!
//! Keep this surface JSON-friendly so generated bindings do not leak
//! internal Rust types. Dart owns secure storage; session blobs are passed
//! as JSON (no OS keyring inside these helpers).

use crate::api::{ApiClient, SyncResult};
use crate::config::SdkConfig;
use crate::error::{ErrorCode, Result, TwoKeyError};
use crate::license::{LicenseVerifier, VerifyOutcome};
use crate::ports::SystemClock;
use crate::session::AccountSession;
use crate::url::normalize_api_base_url;
use std::time::Duration;

/// Normalize a billing API base URL (FFI-friendly).
pub fn ffi_normalize_api_base_url(input: String) -> String {
    normalize_api_base_url(&input)
}

/// Verify a license JWT; on success returns JSON claims payload summary.
///
/// Success JSON shape:
/// `{ "ok": true, "paying_party_id": "...", "subscription_count": N }`
/// Failure JSON shape:
/// `{ "ok": false, "code": "license_invalid", "message": "..." }`
pub fn ffi_verify_license_json(public_key_pem: String, jwt: String) -> String {
    match verify_inner(&public_key_pem, &jwt) {
        Ok(summary) => summary,
        Err(e) => serde_json::json!({
            "ok": false,
            "code": e.code.as_str(),
            "message": e.message,
        })
        .to_string(),
    }
}

fn verify_inner(pem: &str, jwt: &str) -> Result<String> {
    let verifier = LicenseVerifier::from_pem(pem)?;
    match verifier.verify_and_decode(jwt, &SystemClock) {
        VerifyOutcome::Success(p) => {
            // Re-decode JWT payload JSON for wrappers that need full claims.
            let claims = jwt_payload_json(jwt)?;
            Ok(serde_json::json!({
                "ok": true,
                "paying_party_id": p.paying_party.id,
                "subscription_count": p.subscriptions.len(),
                "payload_version": p.payload_version,
                "claims": claims,
            })
            .to_string())
        }
        VerifyOutcome::Failure { code, message } => Err(TwoKeyError::new(code, message)),
    }
}

fn jwt_payload_json(jwt: &str) -> Result<serde_json::Value> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let parts: Vec<&str> = jwt.trim().split('.').collect();
    if parts.len() != 3 {
        return Err(TwoKeyError::new(
            ErrorCode::LicenseMalformed,
            "Invalid JWT shape",
        ));
    }
    let bytes = URL_SAFE_NO_PAD.decode(parts[1].as_bytes()).map_err(|e| {
        TwoKeyError::new(ErrorCode::LicenseMalformed, "Invalid JWT payload encoding")
            .with_detail(e.to_string())
    })?;
    serde_json::from_slice(&bytes).map_err(|e| {
        TwoKeyError::new(ErrorCode::LicenseMalformed, "Invalid JWT payload JSON")
            .with_detail(e.to_string())
    })
}

/// Validate required config fields; returns normalized `api_base_url` or error JSON.
pub fn ffi_validate_config_json(
    api_base_url: String,
    public_key_pem: String,
    storage_prefix: String,
) -> String {
    let cfg = SdkConfig {
        api_base_url,
        public_key_pem,
        storage_prefix,
        portal_base_url: None,
        shop_path: "/shop".into(),
        deep_link_scheme: None,
        license_poll_interval: Duration::from_secs(6 * 3600),
    };
    match cfg.validate() {
        Ok(c) => serde_json::json!({
            "ok": true,
            "api_base_url": c.api_base_url,
            "storage_prefix": c.storage_prefix,
        })
        .to_string(),
        Err(e) => serde_json::json!({
            "ok": false,
            "code": e.code.as_str(),
            "message": e.message,
        })
        .to_string(),
    }
}

/// List of stable error code strings for wrappers.
pub fn ffi_error_codes() -> Vec<String> {
    [
        ErrorCode::Config,
        ErrorCode::Network,
        ErrorCode::Unauthorized,
        ErrorCode::Offline,
        ErrorCode::LicenseInvalid,
        ErrorCode::LicenseExpired,
        ErrorCode::LicenseMalformed,
        ErrorCode::NotModified,
        ErrorCode::InvalidResponse,
        ErrorCode::Unknown,
    ]
    .into_iter()
    .map(|c| c.as_str().to_string())
    .collect()
}

fn err_json(e: TwoKeyError) -> String {
    serde_json::json!({
        "ok": false,
        "code": e.code.as_str(),
        "message": e.message,
        "detail": e.detail,
    })
    .to_string()
}

fn parse_session(session_json: &str) -> Result<AccountSession> {
    serde_json::from_str(session_json).map_err(|e| {
        TwoKeyError::new(ErrorCode::Unknown, "Invalid session JSON").with_detail(e.to_string())
    })
}

fn session_to_json(session: &AccountSession) -> Result<String> {
    serde_json::to_string(session).map_err(|e| {
        TwoKeyError::new(ErrorCode::Unknown, "Failed to serialize session")
            .with_detail(e.to_string())
    })
}

/// Offline init: verify JWT and return claims (Dart persists the session).
///
/// Success: `{ "ok": true, "paying_party_id", "subscription_count", "payload_version", "claims" }`
pub fn ffi_init_license_json(public_key_pem: String, jwt: String) -> String {
    ffi_verify_license_json(public_key_pem, jwt)
}

/// Online license sync. Dart supplies session JSON; Rust talks to `/api/v1/license`.
///
/// `session_json` fields: `account_key`, `access_token`, `license_jwt`,
/// `license_etag`, `paying_party_id_header` (snake_case, matching [AccountSession]).
///
/// Success (200): `{ "ok": true, "status": "updated", "session": {...}, "claims": {...} }`
/// Success (304): `{ "ok": true, "status": "not_modified", "session": {...}, "claims": {...} }`
pub fn ffi_sync_license_json(
    api_base_url: String,
    public_key_pem: String,
    session_json: String,
) -> String {
    match sync_license_inner(&api_base_url, &public_key_pem, &session_json) {
        Ok(s) => s,
        Err(e) => err_json(e),
    }
}

fn sync_license_inner(api_base_url: &str, pem: &str, session_json: &str) -> Result<String> {
    let mut session = parse_session(session_json)?;
    let token = session
        .access_token
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| TwoKeyError::new(ErrorCode::Unauthorized, "No access token in session"))?;

    let api = ApiClient::new(api_base_url);
    let verifier = LicenseVerifier::from_pem(pem)?;
    let result = api.fetch_license(
        token,
        session.paying_party_id_header.as_deref(),
        session.license_etag.as_deref(),
    )?;

    match result {
        SyncResult::NotModified { etag } => {
            if let Some(e) = etag {
                session.license_etag = Some(e);
            }
            let jwt = session.license_jwt.as_deref().ok_or_else(|| {
                TwoKeyError::new(
                    ErrorCode::NotModified,
                    "License not modified but no cached JWT",
                )
            })?;
            let claims = match verifier.verify_and_decode(jwt, &SystemClock) {
                VerifyOutcome::Success(_) => jwt_payload_json(jwt)?,
                VerifyOutcome::Failure { code, message } => {
                    return Err(TwoKeyError::new(code, message));
                }
            };
            Ok(serde_json::json!({
                "ok": true,
                "status": "not_modified",
                "session": serde_json::to_value(&session).map_err(|e| {
                    TwoKeyError::new(ErrorCode::Unknown, "serialize session")
                        .with_detail(e.to_string())
                })?,
                "claims": claims,
            })
            .to_string())
        }
        SyncResult::Success {
            signed_token,
            etag,
        } => {
            let claims = match verifier.verify_and_decode(&signed_token, &SystemClock) {
                VerifyOutcome::Success(_) => jwt_payload_json(&signed_token)?,
                VerifyOutcome::Failure { code, message } => {
                    return Err(TwoKeyError::new(code, message));
                }
            };
            session.license_jwt = Some(signed_token);
            session.license_etag = etag;
            Ok(serde_json::json!({
                "ok": true,
                "status": "updated",
                "session": serde_json::to_value(&session).map_err(|e| {
                    TwoKeyError::new(ErrorCode::Unknown, "serialize session")
                        .with_detail(e.to_string())
                })?,
                "claims": claims,
            })
            .to_string())
        }
    }
}

/// Bootstrap `GET /api/v1/subscriptions/me` → JSON.
pub fn ffi_ensure_billing_context_json(api_base_url: String, access_token: String) -> String {
    match ensure_billing_inner(&api_base_url, &access_token) {
        Ok(s) => s,
        Err(e) => err_json(e),
    }
}

fn ensure_billing_inner(api_base_url: &str, access_token: &str) -> Result<String> {
    let api = ApiClient::new(api_base_url);
    match api.ensure_billing_context(access_token)? {
        crate::api::BootstrapResult::Success(data) => Ok(serde_json::json!({
            "ok": true,
            "data": data,
        })
        .to_string()),
    }
}

/// Whether background poll is recommended given a license JWT.
pub fn ffi_should_poll_json(public_key_pem: String, license_jwt: Option<String>) -> String {
    let Some(jwt) = license_jwt.filter(|s| !s.trim().is_empty()) else {
        return r#"{"ok":true,"should_poll":false}"#.into();
    };
    match LicenseVerifier::from_pem(&public_key_pem) {
        Ok(v) => match v.verify_and_decode(&jwt, &SystemClock) {
            VerifyOutcome::Success(p) => serde_json::json!({
                "ok": true,
                "should_poll": !p.subscriptions.is_empty(),
            })
            .to_string(),
            VerifyOutcome::Failure { .. } => {
                r#"{"ok":true,"should_poll":false}"#.into()
            }
        },
        Err(e) => err_json(e),
    }
}

/// Round-trip session JSON helper (validates shape for FRB hosts).
pub fn ffi_parse_session_json(session_json: String) -> String {
    match parse_session(&session_json).and_then(|s| session_to_json(&s)) {
        Ok(s) => serde_json::json!({ "ok": true, "session": serde_json::from_str::<serde_json::Value>(&s).unwrap_or_default() }).to_string(),
        Err(e) => err_json(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_config_json_ok() {
        let out = ffi_validate_config_json(
            "https://billing.example.com/api/v1".into(),
            "pem".into(),
            "app".into(),
        );
        assert!(out.contains("\"ok\":true"));
        assert!(out.contains("billing.example.com"));
    }

    #[test]
    fn error_codes_non_empty() {
        assert!(ffi_error_codes().contains(&"license_invalid".into()));
    }

    #[test]
    fn sync_license_rejects_missing_token() {
        let session = r#"{"account_key":"u1","access_token":null,"license_jwt":null,"license_etag":null,"paying_party_id_header":null}"#;
        let out = ffi_sync_license_json(
            "https://billing.example.com".into(),
            "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----".into(),
            session.into(),
        );
        assert!(out.contains("\"ok\":false"));
        assert!(out.contains("unauthorized") || out.contains("No access token"));
    }

    #[test]
    fn should_poll_false_without_jwt() {
        let out = ffi_should_poll_json("pem".into(), None);
        assert!(out.contains("\"should_poll\":false"));
    }

    #[test]
    fn parse_session_roundtrip() {
        let session = r#"{"account_key":"u1","access_token":"tok","license_jwt":null,"license_etag":null,"paying_party_id_header":null}"#;
        let out = ffi_parse_session_json(session.into());
        assert!(out.contains("\"ok\":true"));
        assert!(out.contains("u1"));
    }
}
