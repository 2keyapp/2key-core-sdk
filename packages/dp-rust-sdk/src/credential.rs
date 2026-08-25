//! CapabilityCredential JWS (EdDSA compact), matching `@2key/dp-ts` `canonicalPayload`.

use dp_rust::{Capability, CapabilityCredential, CredentialKind, EntityPackage};
use dp_rust_mtls::{compact_jws_sign, compact_jws_verify, private_pem_from_jwk};
use serde_json::{json, Value};

use crate::error::Result;

/// JSON bytes signed as the JWS payload — key order matches the TypeScript SDK.
pub fn canonical_credential_payload(credential: &CapabilityCredential) -> Result<Vec<u8>> {
    let payload = json!({
        "version": credential.version,
        "kind": credential.kind,
        "entityId": credential.entity_id,
        "ski": credential.ski,
        "publicJwk": credential.public_jwk,
        "permissions": credential.permissions,
        "zone": credential.zone.clone().map(Value::String).unwrap_or(Value::Null),
        "host": credential.host.clone().map(Value::String).unwrap_or(Value::Null),
        "issuerSki": credential.issuer_ski,
        "notBefore": credential.not_before,
        "notAfter": credential.not_after,
        "package": credential.package,
    });
    Ok(serde_json::to_vec(&payload)?)
}

/// Sign `credential` (except `signature` / `platformCosign`) with the issuer private key.
pub fn sign_credential(
    mut credential: CapabilityCredential,
    issuer_private_jwk: &Value,
) -> Result<CapabilityCredential> {
    credential.signature.clear();
    credential.platform_cosign = None;
    let payload = canonical_credential_payload(&credential)?;
    let pem = private_pem_from_jwk(issuer_private_jwk)?;
    credential.signature = compact_jws_sign(&pem, &payload)?;
    Ok(credential)
}

pub fn verify_credential_signature(
    credential: &CapabilityCredential,
    issuer_public_jwk: &Value,
) -> Result<bool> {
    let payload = canonical_credential_payload(credential)?;
    Ok(compact_jws_verify(
        issuer_public_jwk,
        &credential.signature,
        &payload,
    )?)
}

pub fn default_machine_permissions(machine_name: &str) -> Vec<Capability> {
    vec![Capability {
        action: "machine.connect".into(),
        scope: json!({ "name": machine_name }),
        delegable: false,
    }]
}

/// Demo / IDR `root_admin` profile (matches better-auth `seeds/demo.ts`).
pub fn root_admin_permissions() -> Vec<Capability> {
    vec![
        cap("admin.invite", json!({}), true),
        cap("cert.issue", json!({ "name": "" }), true),
        cap("zone.ns", json!({ "name": "" }), true),
        cap("zone.delegate", json!({ "name": "" }), true),
        cap("machine.bind", json!({ "name": "" }), true),
        cap("machine.connect", json!({ "name": "" }), true),
        cap("seat.bind", json!({}), true),
        cap("resource.access", json!({ "service": ["*"] }), true),
        cap("entity.read", json!({}), true),
    ]
}

pub fn personal_root_permissions() -> Vec<Capability> {
    vec![
        cap("cert.issue", json!({ "name": "" }), true),
        cap("machine.bind", json!({ "name": "" }), true),
        cap("machine.connect", json!({ "name": "" }), true),
        cap("seat.bind", json!({}), true),
        cap("resource.access", json!({ "service": ["*"] }), true),
        cap("entity.read", json!({}), true),
    ]
}

pub fn kickstart_permissions(package: &str) -> Vec<Capability> {
    if package.eq_ignore_ascii_case("personal") {
        personal_root_permissions()
    } else {
        root_admin_permissions()
    }
}

pub fn with_entity_scope(permissions: Vec<Capability>, entity_id: &str) -> Vec<Capability> {
    permissions
        .into_iter()
        .map(|mut p| {
            match &mut p.scope {
                Value::Object(map) => {
                    map.insert("entity".into(), json!(entity_id));
                }
                other => {
                    p.scope = json!({ "entity": entity_id, "value": other });
                }
            }
            p
        })
        .collect()
}

fn cap(action: &str, scope: Value, delegable: bool) -> Capability {
    Capability {
        action: action.into(),
        scope,
        delegable,
    }
}

pub fn unsigned_credential(
    kind: CredentialKind,
    entity_id: &str,
    ski: String,
    public_jwk: Value,
    issuer_ski: String,
    permissions: Vec<Capability>,
    not_before: String,
    not_after: String,
    host: Option<String>,
    zone: Option<String>,
    package: Option<EntityPackage>,
) -> CapabilityCredential {
    CapabilityCredential {
        version: 1,
        kind,
        entity_id: entity_id.to_string(),
        ski,
        public_jwk,
        permissions,
        zone,
        host,
        issuer_ski,
        not_before,
        not_after,
        package,
        platform_cosign: None,
        signature: String::new(),
    }
}

pub fn unsigned_machine_credential(
    entity_id: &str,
    ski: String,
    public_jwk: Value,
    host: Option<String>,
    issuer_ski: String,
    permissions: Vec<Capability>,
    not_before: String,
    not_after: String,
) -> CapabilityCredential {
    unsigned_credential(
        CredentialKind::Machine,
        entity_id,
        ski,
        public_jwk,
        issuer_ski,
        permissions,
        not_before,
        not_after,
        host,
        None,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use dp_rust_mtls::generate_ed25519;

    #[test]
    fn sign_and_verify_roundtrip() {
        let issuer = generate_ed25519().unwrap();
        let device = generate_ed25519().unwrap();
        let cred = unsigned_machine_credential(
            "acme.com",
            device.ski.clone(),
            device.public_jwk.clone(),
            Some("db1--acme.com".into()),
            issuer.ski.clone(),
            default_machine_permissions("db1"),
            "2026-01-01T00:00:00Z".into(),
            "2027-01-01T00:00:00Z".into(),
        );
        let signed = sign_credential(cred, &issuer.private_jwk).unwrap();
        assert!(signed.signature.matches('.').count() == 2);
        assert!(verify_credential_signature(&signed, &issuer.public_jwk).unwrap());
    }

    #[test]
    fn canonical_payload_key_order_matches_ts() {
        let issuer = generate_ed25519().unwrap();
        let device = generate_ed25519().unwrap();
        let cred = unsigned_machine_credential(
            "acme.com",
            device.ski,
            device.public_jwk,
            Some("db1--acme.com".into()),
            issuer.ski,
            default_machine_permissions("db1"),
            "2026-01-01T00:00:00Z".into(),
            "2027-01-01T00:00:00Z".into(),
        );
        let json = String::from_utf8(canonical_credential_payload(&cred).unwrap()).unwrap();
        let version = json.find("\"version\"").unwrap();
        let kind = json.find("\"kind\"").unwrap();
        let entity = json.find("\"entityId\"").unwrap();
        let package = json.find("\"package\"").unwrap();
        assert!(version < kind && kind < entity && entity < package);
        assert!(json.contains("\"zone\":null"));
        assert!(json.contains("\"package\":null"));
    }
}
