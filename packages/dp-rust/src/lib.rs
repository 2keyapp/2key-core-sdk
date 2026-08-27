//! Device/Agent SDK types for Delegate Permissions (Option B credentials).
//! Crypto (Ed25519 / JWS) will land in a follow-up; this crate establishes the
//! shared wire types with `@2key/dp-spec` / Better Auth.
//!
//! Pure AuthZ algebra lives in [`authorize`] — mirrors `@2key/dp-authorize`
//! and `conformance/dp-authz/fixtures.json`.

pub mod authorize;

pub use authorize::{
    action_covers, assert_subset, authorize, dns_prefix_subset, path_prefix_subset,
    semver_range_subset, semver_satisfies, ActionDef, AuthzOutcome, Catalog,
    ScopeDimensionDef,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    EntityRoot,
    RootAdmin,
    InterimAdmin,
    ZoneAuthority,
    Machine,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EntityPackage {
    Personal,
    Enterprise,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Capability {
    pub action: String,
    pub scope: Value,
    pub delegable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PlatformCosign {
    pub kid: String,
    #[serde(rename = "signedAt")]
    pub signed_at: String,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CapabilityCredential {
    pub version: u8,
    pub kind: CredentialKind,
    #[serde(rename = "entityId")]
    pub entity_id: String,
    pub ski: String,
    #[serde(rename = "publicJwk")]
    pub public_jwk: Value,
    pub permissions: Vec<Capability>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(rename = "issuerSki")]
    pub issuer_ski: String,
    #[serde(rename = "notBefore")]
    pub not_before: String,
    #[serde(rename = "notAfter")]
    pub not_after: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<EntityPackage>,
    #[serde(
        rename = "platformCosign",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub platform_cosign: Option<PlatformCosign>,
    pub signature: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_minimal_machine_json() {
        let json = r#"{
            "version": 1,
            "kind": "machine",
            "entityId": "acme.example",
            "ski": "abc",
            "publicJwk": {"kty":"OKP","crv":"Ed25519","x":"x"},
            "permissions": [{"action":"machine.connect","scope":{"name":"db1"},"delegable":false}],
            "host": "db1--acme.example",
            "issuerSki": "issuer",
            "notBefore": "2026-01-01T00:00:00.000Z",
            "notAfter": "2027-01-01T00:00:00.000Z",
            "signature": "hdr.payload.sig"
        }"#;
        let cred: CapabilityCredential = serde_json::from_str(json).unwrap();
        assert_eq!(cred.kind, CredentialKind::Machine);
        assert_eq!(cred.host.as_deref(), Some("db1--acme.example"));
        let out = serde_json::to_string(&cred).unwrap();
        assert!(!out.contains("\"platformCosign\""));
    }
}
