//! JSON-oriented crypto FFI for device x.509 / mTLS / PoP (wraps `dp-rust-mtls`).

use dp_rust_mtls::{
    generate_key_and_csr, materialize_mtls_client, sign_client_cert_from_csr,
    sign_json_b64url, verify_ed25519_cert_against_issuer, DeviceIdentity,
    SignClientCertFromCsrParams,
};
use serde_json::{json, Value};

fn crypto_ok(value: Value) -> String {
    serde_json::json!({ "ok": true, "data": value }).to_string()
}

fn crypto_err(message: impl AsRef<str>) -> String {
    serde_json::json!({
        "ok": false,
        "code": "crypto",
        "message": message.as_ref(),
    })
    .to_string()
}

/// Generate Ed25519 key + PKCS#10 CSR.
///
/// Input JSON: `{ "host": "camera.example.com", "commonName": "optional" }`
/// Output JSON: `{ ok, data: { ski, publicJwk, privateJwk, csrPem } }`
pub fn ffi_generate_key_and_csr_json(input_json: String) -> String {
    let input: Value = match serde_json::from_str(&input_json) {
        Ok(v) => v,
        Err(e) => return crypto_err(format!("invalid input JSON: {e}")),
    };
    let host = input.get("host").and_then(|v| v.as_str()).unwrap_or("");
    if host.is_empty() {
        return crypto_err("host is required");
    }
    let common_name = input
        .get("commonName")
        .and_then(|v| v.as_str())
        .unwrap_or(host);

    match generate_key_and_csr(common_name, Some(host)) {
        Ok(generated) => crypto_ok(json!({
            "ski": generated.ski,
            "publicJwk": generated.public_jwk,
            "privateJwk": generated.private_jwk,
            "csrPem": generated.csr_pem,
        })),
        Err(e) => crypto_err(e.to_string()),
    }
}

/// Sign a device CSR with a CA private JWK.
///
/// Input JSON fields: csrPem, caCertPem, caPrivateJwk, caCommonName, ski, host?, notAfterDays?
pub fn ffi_sign_client_cert_from_csr_json(input_json: String) -> String {
    let input: Value = match serde_json::from_str(&input_json) {
        Ok(v) => v,
        Err(e) => return crypto_err(format!("invalid input JSON: {e}")),
    };

    let Some(csr_pem) = input.get("csrPem").and_then(|v| v.as_str()) else {
        return crypto_err("csrPem is required");
    };
    let Some(ca_cert_pem) = input.get("caCertPem").and_then(|v| v.as_str()) else {
        return crypto_err("caCertPem is required");
    };
    let Some(ca_private_jwk) = input.get("caPrivateJwk") else {
        return crypto_err("caPrivateJwk is required");
    };
    let Some(ca_common_name) = input.get("caCommonName").and_then(|v| v.as_str()) else {
        return crypto_err("caCommonName is required");
    };
    let Some(ski) = input.get("ski").and_then(|v| v.as_str()) else {
        return crypto_err("ski is required");
    };
    let host = input.get("host").and_then(|v| v.as_str());
    let not_after_days = input.get("notAfterDays").and_then(|v| v.as_i64());

    match sign_client_cert_from_csr(SignClientCertFromCsrParams {
        csr_pem,
        ca_cert_pem,
        ca_private_jwk,
        ca_common_name,
        ski,
        host,
        not_after_days,
    }) {
        Ok(signed) => crypto_ok(json!({
            "leafPem": signed.leaf_pem,
            "chainPem": signed.chain_pem,
        })),
        Err(e) => crypto_err(e.to_string()),
    }
}

/// Verify leaf cert signature against issuer PEM.
///
/// Input JSON: `{ "leafPem": "...", "issuerPem": "..." }`
pub fn ffi_verify_ed25519_cert_json(input_json: String) -> String {
    let input: Value = match serde_json::from_str(&input_json) {
        Ok(v) => v,
        Err(e) => return crypto_err(format!("invalid input JSON: {e}")),
    };
    let Some(leaf_pem) = input.get("leafPem").and_then(|v| v.as_str()) else {
        return crypto_err("leafPem is required");
    };
    let Some(issuer_pem) = input.get("issuerPem").and_then(|v| v.as_str()) else {
        return crypto_err("issuerPem is required");
    };

    match verify_ed25519_cert_against_issuer(leaf_pem, issuer_pem) {
        Ok(valid) => crypto_ok(json!({ "valid": valid })),
        Err(e) => crypto_err(e.to_string()),
    }
}

/// Materialize mTLS client PEM material from a device identity JSON blob.
pub fn ffi_materialize_mtls_client_json(identity_json: String) -> String {
    let input: Value = match serde_json::from_str(&identity_json) {
        Ok(v) => v,
        Err(e) => return crypto_err(format!("invalid identity JSON: {e}")),
    };

    let Some(ski) = input.get("ski").and_then(|v| v.as_str()) else {
        return crypto_err("ski is required");
    };
    let Some(private_jwk) = input.get("privateJwk") else {
        return crypto_err("privateJwk is required");
    };

    let credential = match input.get("credential") {
        Some(c) => match serde_json::from_value(c.clone()) {
            Ok(v) => v,
            Err(e) => return crypto_err(format!("invalid credential: {e}")),
        },
        None => {
            return crypto_err("credential is required");
        }
    };

    let identity = DeviceIdentity {
        ski: ski.to_string(),
        private_jwk: private_jwk.clone(),
        credential,
        cert_pem: input.get("certPem").and_then(|v| v.as_str()).map(str::to_string),
        chain_pem: input
            .get("chainPem")
            .and_then(|v| v.as_str())
            .map(str::to_string),
    };

    match materialize_mtls_client(&identity) {
        Ok(material) => crypto_ok(json!({
            "certPem": material.cert_pem,
            "keyPem": material.key_pem,
            "ski": material.ski,
            "chainPem": material.chain_pem,
        })),
        Err(e) => crypto_err(e.to_string()),
    }
}

/// Sign JSON payload with Ed25519 private PEM (agent PoP).
///
/// Input JSON: `{ "privatePem": "...", "payloadJson": "{...}" }`
pub fn ffi_sign_json_b64url_json(input_json: String) -> String {
    let input: Value = match serde_json::from_str(&input_json) {
        Ok(v) => v,
        Err(e) => return crypto_err(format!("invalid input JSON: {e}")),
    };
    let Some(private_pem) = input.get("privatePem").and_then(|v| v.as_str()) else {
        return crypto_err("privatePem is required");
    };
    let Some(payload_json) = input.get("payloadJson").and_then(|v| v.as_str()) else {
        return crypto_err("payloadJson is required");
    };

    match sign_json_b64url(private_pem, payload_json) {
        Ok(signature) => crypto_ok(json!({ "signature": signature })),
        Err(e) => crypto_err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key_and_csr_roundtrip() {
        let out = ffi_generate_key_and_csr_json(
            r#"{"host":"camera.acme.example"}"#.to_string(),
        );
        let parsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed.get("ok"), Some(&json!(true)));
        let data = parsed.get("data").unwrap();
        assert!(data.get("csrPem").unwrap().as_str().unwrap().contains("CERTIFICATE REQUEST"));
    }
}
