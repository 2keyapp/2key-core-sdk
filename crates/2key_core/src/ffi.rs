//! Stable string-oriented helpers for future FRB / UniFFI bindings.
//!
//! Keep this surface small and JSON-friendly so generated bindings do not
//! leak internal Rust types.

use crate::config::SdkConfig;
use crate::error::{ErrorCode, Result, TwoKeyError};
use crate::license::{LicenseVerifier, VerifyOutcome};
use crate::ports::SystemClock;
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
}
