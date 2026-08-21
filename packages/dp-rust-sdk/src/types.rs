use serde::{Deserialize, Serialize};
use serde_json::Value;

use dp_rust::{Capability, CapabilityCredential};

/// Machine kind sent on enroll-create / enroll-instant.
///
/// Serialized as the plugin aliases `target` / `source` (accepted by
/// `enrollKindSchema` and normalized to `machine_target` / `machine_source`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MachineKind {
    #[default]
    Target,
    Source,
}

impl MachineKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Target => "target",
            Self::Source => "source",
        }
    }
}

/// Key algorithm for machine key generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum KeyAlgo {
    #[default]
    Ed25519,
    P256,
}

impl KeyAlgo {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::P256 => "p256",
        }
    }
}

/// Persisted enrollment / lifecycle status (`state.json`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentStatus {
    Uninitialized,
    KeyGenerated,
    CsrCreated,
    EnrollmentSubmitted,
    PendingAdmin,
    Rejected,
    Signed,
    CertReceived,
    CertVerified,
    Active,
    Renewing,
    Rotating,
    Revoked,
    Decommissioned,
}

impl EnrollmentStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Uninitialized => "uninitialized",
            Self::KeyGenerated => "key_generated",
            Self::CsrCreated => "csr_created",
            Self::EnrollmentSubmitted => "enrollment_submitted",
            Self::PendingAdmin => "pending_admin",
            Self::Rejected => "rejected",
            Self::Signed => "signed",
            Self::CertReceived => "cert_received",
            Self::CertVerified => "cert_verified",
            Self::Active => "active",
            Self::Renewing => "renewing",
            Self::Rotating => "rotating",
            Self::Revoked => "revoked",
            Self::Decommissioned => "decommissioned",
        }
    }

    /// Whether this status may start a fresh `machine enroll`.
    pub fn allows_enroll(self) -> bool {
        matches!(
            self,
            Self::Uninitialized | Self::Rejected | Self::Decommissioned | Self::Revoked
        )
    }

    /// Whether the machine currently has a usable cert.
    pub fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    /// Legal next states from `self`.
    pub fn can_transition_to(self, next: Self) -> bool {
        use EnrollmentStatus::*;
        matches!(
            (self, next),
            (Uninitialized, KeyGenerated)
                | (KeyGenerated, CsrCreated)
                | (CsrCreated, EnrollmentSubmitted)
                | (EnrollmentSubmitted, PendingAdmin)
                | (PendingAdmin, Rejected)
                | (PendingAdmin, Signed)
                | (Signed, CertReceived)
                | (CertReceived, CertVerified)
                | (CertVerified, Active)
                | (Active, Renewing)
                | (Active, Rotating)
                | (Active, Revoked)
                | (Active, Decommissioned)
                | (Renewing, Active)
                | (Rotating, Active)
                | (Renewing, Decommissioned)
                | (Rotating, Decommissioned)
                | (Renewing, Revoked)
                | (Rotating, Revoked)
                | (Renewing, Rejected)
                | (Rotating, Rejected)
        )
    }
}

impl std::fmt::Display for EnrollmentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// On-disk machine metadata. No private keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MachineState {
    pub machine_identity: String,
    pub entity_id: String,
    pub machine_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ski: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_token: Option<String>,
    pub status: EnrollmentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_serial: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_expires_at: Option<String>,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub renewed_from_ski: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<MachineKind>,
}

impl MachineState {
    pub fn transition(&mut self, next: EnrollmentStatus) -> crate::Result<()> {
        if !self.status.can_transition_to(next) {
            return Err(crate::Error::enrollment(format!(
                "illegal transition {} → {}",
                self.status, next
            )));
        }
        self.status = next;
        Ok(())
    }
}

/// Cert / credential material returned by enroll, pull, approve, renew.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IssuedCerts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<CapabilityCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_cert_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_root_pem: Option<String>,
    /// Envelope cert co-sign (`platformCertPem` + `platformRootPem`), not the
    /// credential JWS `platformCosign` `{kid,signedAt,signature}`.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        rename = "platformCertCosign"
    )]
    pub platform_cert_cosign: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KickstartRequest {
    pub entity_id: String,
    pub package: String,
    /// Client-generated Entity Root public JWK (production). All five client
    /// fields must be sent together or the plugin falls back to server keygen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_public_jwk: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_public_jwk: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_credential: Option<CapabilityCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admin_credential: Option<CapabilityCredential>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert_pem: Option<String>,
}

impl KickstartRequest {
    pub fn is_client_keyed(&self) -> bool {
        self.root_public_jwk.is_some()
            && self.admin_public_jwk.is_some()
            && self.root_credential.is_some()
            && self.admin_credential.is_some()
            && self.ca_cert_pem.is_some()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KickstartKeyMaterial {
    #[serde(default)]
    pub credential: Option<CapabilityCredential>,
    #[serde(default)]
    pub private_jwk: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct KickstartResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_cert_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_ca_cert_pem: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_root_pem: Option<String>,
    #[serde(default)]
    pub root: Option<KickstartKeyMaterial>,
    #[serde(default)]
    pub root_admin: Option<KickstartKeyMaterial>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityResponse {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollCreateRequest {
    pub entity_id: String,
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<MachineKind>,
    /// RFC 7638 JWK thumbprint. Must match better-auth `bindCsrToPublicJwk`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ski: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_jwk: Option<Value>,
    pub csr_pem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollCreateResponse {
    #[serde(default, alias = "id")]
    pub enroll_id: Option<String>,
    #[serde(default)]
    pub pull_token: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default, alias = "subjectSki")]
    pub ski: Option<String>,
    #[serde(flatten)]
    pub issued: IssuedCerts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollInviteRequest {
    pub entity_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<MachineKind>,
    /// Seconds until expiry. Omit to use the plugin `inviteExpiresIn` (default 7d; capped by `inviteMaxExpiresIn`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    /// Redeem cap. Default 1. `0` = unlimited until expiresAt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollInviteResponse {
    #[serde(default, alias = "id")]
    pub invite_id: Option<String>,
    #[serde(default)]
    pub invite_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default)]
    pub entity_id: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    /// `0` = unlimited until expiry.
    #[serde(default)]
    pub max_uses: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollInstantRequest {
    pub entity_id: String,
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<MachineKind>,
    pub csr_pem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_jwk: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject_ski: Option<String>,
    pub leaf_pem: String,
    pub chain_pem: String,
    pub credential: CapabilityCredential,
    pub issuer_ski: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollInstantResponse {
    #[serde(default, alias = "id")]
    pub enroll_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default, alias = "subjectSki")]
    pub ski: Option<String>,
    #[serde(flatten)]
    pub issued: IssuedCerts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollPullResponse {
    pub status: String,
    #[serde(default)]
    pub enroll_id: Option<String>,
    #[serde(flatten)]
    pub issued: IssuedCerts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollApproveRequest {
    pub enroll_id: String,
    pub leaf_pem: String,
    pub chain_pem: String,
    pub credential: CapabilityCredential,
    pub issuer_ski: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollApproveResponse {
    #[serde(default)]
    pub enroll_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(flatten)]
    pub issued: IssuedCerts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnrollListItem {
    #[serde(default, alias = "id")]
    pub enroll_id: Option<String>,
    #[serde(default)]
    pub entity_id: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default, alias = "subjectSki")]
    pub ski: Option<String>,
    #[serde(default)]
    pub csr_pem: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachinePermissionsRequest {
    pub entity_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<MachineKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ski: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<Capability>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachinePermissionsResponse {
    #[serde(default)]
    pub permissions: Vec<Capability>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialStatusResponse {
    #[serde(default)]
    pub ski: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub credential: Option<CapabilityCredential>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialListItem {
    #[serde(default)]
    pub ski: Option<String>,
    #[serde(default)]
    pub entity_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevokeResponse {
    #[serde(default)]
    pub ski: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineRenewRequest {
    pub ski: String,
    pub csr_pem: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_jwk: Option<Value>,
    pub leaf_pem: String,
    pub chain_pem: String,
    pub credential: CapabilityCredential,
    pub issuer_ski: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineRenewResponse {
    #[serde(default, alias = "newSki")]
    pub ski: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(flatten)]
    pub issued: IssuedCerts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecommissionResponse {
    #[serde(default)]
    pub ski: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlatformRootResponse {
    #[serde(default)]
    pub platform_root_pem: Option<String>,
    #[serde(default)]
    pub ski: Option<String>,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

impl PlatformRootResponse {
    /// PEM block, accepting either `platformRootPem` or a top-level `pem` field.
    pub fn pem(&self) -> Option<&str> {
        self.platform_root_pem.as_deref().or_else(|| {
            self.extra
                .get("pem")
                .and_then(|v| v.as_str())
                .or_else(|| self.extra.get("pemPem").and_then(|v| v.as_str()))
        })
    }
}

/// Normalize a CA PEM for HAProxy `ca-file` (trimmed, trailing newline).
pub fn normalize_ca_file_pem(pem: &str) -> Option<String> {
    if !pem.contains("BEGIN CERTIFICATE") {
        return None;
    }
    let mut out = pem.trim().to_string();
    out.push('\n');
    Some(out)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CatalogResponse {
    #[serde(flatten)]
    pub extra: serde_json::Map<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrollment_status_roundtrip() {
        let s = EnrollmentStatus::PendingAdmin;
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "\"pending_admin\"");
        let back: EnrollmentStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, EnrollmentStatus::PendingAdmin);
    }

    #[test]
    fn active_cannot_enroll() {
        assert!(!EnrollmentStatus::Active.allows_enroll());
        assert!(EnrollmentStatus::Rejected.allows_enroll());
        assert!(EnrollmentStatus::Active.can_transition_to(EnrollmentStatus::Renewing));
        assert!(!EnrollmentStatus::PendingAdmin.can_transition_to(EnrollmentStatus::Active));
    }

    #[test]
    fn enroll_create_serializes_camel_case() {
        let req = EnrollCreateRequest {
            entity_id: "acme.com".into(),
            host: "db1--acme.com".into(),
            kind: Some(MachineKind::Target),
            subject_ski: None,
            public_jwk: None,
            csr_pem: "-----BEGIN CERTIFICATE REQUEST-----\n".into(),
            invite_token: None,
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["entityId"], "acme.com");
        assert_eq!(v["csrPem"], req.csr_pem);
        assert_eq!(v["kind"], "target");
        assert!(v.get("subjectSki").is_none());
        assert!(v.get("inviteToken").is_none());
    }

    #[test]
    fn enroll_invite_serializes_camel_case() {
        let req = EnrollInviteRequest {
            entity_id: "acme.com".into(),
            kind: Some(MachineKind::Target),
            expires_in: Some(86400),
            max_uses: Some(50),
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["entityId"], "acme.com");
        assert_eq!(v["expiresIn"], 86400);
        assert_eq!(v["maxUses"], 50);
        assert_eq!(v["kind"], "target");
        assert!(v.get("host").is_none());
    }

    #[test]
    fn kickstart_client_keyed_serializes_plugin_fields() {
        let req = KickstartRequest {
            entity_id: "smoke.test".into(),
            package: "enterprise".into(),
            root_public_jwk: Some(serde_json::json!({"kty":"OKP"})),
            admin_public_jwk: Some(serde_json::json!({"kty":"OKP"})),
            root_credential: None,
            admin_credential: None,
            ca_cert_pem: Some("-----BEGIN CERTIFICATE-----\n".into()),
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["entityId"], "smoke.test");
        assert!(v.get("rootPublicJwk").is_some());
        assert!(v.get("publicJwk").is_none());
        assert!(!req.is_client_keyed());
    }

    #[test]
    fn ca_file_pem_has_trailing_newline() {
        let pem = "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----";
        let out = normalize_ca_file_pem(pem).unwrap();
        assert!(out.ends_with('\n'));
        assert!(out.contains("BEGIN CERTIFICATE"));
        assert!(normalize_ca_file_pem("not a cert").is_none());
    }
}
