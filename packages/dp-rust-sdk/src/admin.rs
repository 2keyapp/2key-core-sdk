//! Admin enrollment: Entity CA persistence, list/show, local CSR signing, approve/reject.

use dp_rust::{Capability, CredentialKind, EntityPackage};
use dp_rust_mtls::{
    create_self_signed_ca, generate_ed25519, jwk_thumbprint_sha256, private_pem_from_jwk,
    public_jwk_from_csr_pem, sign_client_cert_from_csr, SignClientCertFromCsrParams,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};

use crate::client::DpClient;
use crate::credential::{
    default_machine_permissions, kickstart_permissions, sign_credential, unsigned_credential,
    unsigned_machine_credential, with_entity_scope,
};
use crate::error::{Error, Result};
use crate::identity::MachineIdentity;
use crate::keystore::{self, KeyStore};
use crate::types::{
    EnrollApproveRequest, EnrollApproveResponse, EnrollListItem, KickstartRequest,
    KickstartResponse,
};

#[derive(Debug, Clone)]
pub struct EntityCaMaterial {
    pub entity_id: String,
    pub ski: String,
    pub common_name: String,
    pub private_jwk: Value,
    pub public_jwk: Value,
    pub ca_cert_pem: String,
    /// Root Admin SKI used as machine-credential issuer (plugin `getCredential`).
    pub admin_ski: Option<String>,
    pub admin_private_jwk: Option<Value>,
    pub admin_public_jwk: Option<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EntityCaMeta {
    entity_id: String,
    ski: String,
    common_name: String,
    private_jwk: Value,
    public_jwk: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admin_ski: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admin_private_jwk: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admin_public_jwk: Option<Value>,
}

pub fn admin_ca_key(entity_id: &str) -> Result<String> {
    Ok(format!(
        "admin/{}/entity-ca.key",
        sanitize_entity_id(entity_id)?
    ))
}

pub fn admin_ca_cert(entity_id: &str) -> Result<String> {
    Ok(format!(
        "admin/{}/entity-ca.crt",
        sanitize_entity_id(entity_id)?
    ))
}

pub fn admin_ca_meta(entity_id: &str) -> Result<String> {
    Ok(format!(
        "admin/{}/entity-ca.json",
        sanitize_entity_id(entity_id)?
    ))
}

fn sanitize_entity_id(entity_id: &str) -> Result<&str> {
    if entity_id.is_empty() || entity_id.contains('/') || entity_id.contains("..") {
        return Err(Error::admin(format!("illegal entity id {entity_id:?}")));
    }
    Ok(entity_id)
}

/// Create a new Entity CA and persist it. Refuses to overwrite an existing CA.
pub fn create_entity_ca(store: &impl KeyStore, entity_id: &str) -> Result<EntityCaMaterial> {
    if load_entity_ca(store, entity_id)?.is_some() {
        return Err(Error::admin(format!(
            "entity CA already exists for {entity_id} — delete admin/{entity_id}/ to rotate"
        )));
    }
    let cn = format!("{entity_id} Entity CA");
    let ca = create_self_signed_ca(&cn)?;
    let material = EntityCaMaterial {
        entity_id: entity_id.to_string(),
        ski: ca.ski,
        common_name: ca.common_name,
        private_jwk: ca.private_jwk,
        public_jwk: ca.public_jwk,
        ca_cert_pem: ca.ca_cert_pem,
        admin_ski: None,
        admin_private_jwk: None,
        admin_public_jwk: None,
    };
    save_entity_ca(store, &material)?;
    Ok(material)
}

pub fn save_entity_ca(store: &impl KeyStore, ca: &EntityCaMaterial) -> Result<()> {
    let pem = private_pem_from_jwk(&ca.private_jwk)?;
    store.save_string(&admin_ca_key(&ca.entity_id)?, &pem)?;
    store.save_string(&admin_ca_cert(&ca.entity_id)?, &ca.ca_cert_pem)?;
    let meta = EntityCaMeta {
        entity_id: ca.entity_id.clone(),
        ski: ca.ski.clone(),
        common_name: ca.common_name.clone(),
        private_jwk: ca.private_jwk.clone(),
        public_jwk: ca.public_jwk.clone(),
        admin_ski: ca.admin_ski.clone(),
        admin_private_jwk: ca.admin_private_jwk.clone(),
        admin_public_jwk: ca.admin_public_jwk.clone(),
    };
    store.save_string(
        &admin_ca_meta(&ca.entity_id)?,
        &serde_json::to_string_pretty(&meta)?,
    )?;
    Ok(())
}

pub fn load_entity_ca(store: &impl KeyStore, entity_id: &str) -> Result<Option<EntityCaMaterial>> {
    let Some(raw) = store.load_string(&admin_ca_meta(entity_id)?)? else {
        return Ok(None);
    };
    let meta: EntityCaMeta = serde_json::from_str(&raw)?;
    let cert = store
        .load_string(&admin_ca_cert(entity_id)?)?
        .ok_or_else(|| Error::admin(format!("missing Entity CA cert for {entity_id}")))?;
    Ok(Some(EntityCaMaterial {
        entity_id: meta.entity_id,
        ski: meta.ski,
        common_name: meta.common_name,
        private_jwk: meta.private_jwk,
        public_jwk: meta.public_jwk,
        ca_cert_pem: cert,
        admin_ski: meta.admin_ski,
        admin_private_jwk: meta.admin_private_jwk,
        admin_public_jwk: meta.admin_public_jwk,
    }))
}

pub fn require_entity_ca(store: &impl KeyStore, entity_id: &str) -> Result<EntityCaMaterial> {
    load_entity_ca(store, entity_id)?.ok_or_else(|| {
        Error::admin(format!(
            "no Entity CA for {entity_id} — run `init {entity_id}` first"
        ))
    })
}

/// Generate Entity Root + Root Admin + CA locally (keys never leave this process).
pub fn prepare_client_keyed_kickstart(
    entity_id: &str,
    package: &str,
) -> Result<(EntityCaMaterial, KickstartRequest)> {
    let entity_id = entity_id.to_ascii_lowercase();
    let pkg = parse_package(package)?;
    let cn = format!("{entity_id} Entity CA");
    let ca = create_self_signed_ca(&cn)?;
    let admin = generate_ed25519()?;
    let permissions = with_entity_scope(kickstart_permissions(package), &entity_id);
    let (not_before, not_after) = validity_rfc3339(365);

    let root_unsigned = unsigned_credential(
        CredentialKind::EntityRoot,
        &entity_id,
        ca.ski.clone(),
        strip_private_jwk(&ca.public_jwk),
        ca.ski.clone(),
        permissions.clone(),
        not_before.clone(),
        not_after.clone(),
        None,
        None,
        Some(pkg.clone()),
    );
    let root_credential = sign_credential(root_unsigned, &ca.private_jwk)?;

    let admin_unsigned = unsigned_credential(
        CredentialKind::RootAdmin,
        &entity_id,
        admin.ski.clone(),
        strip_private_jwk(&admin.public_jwk),
        ca.ski.clone(),
        permissions,
        not_before,
        not_after,
        None,
        Some(String::new()),
        Some(pkg),
    );
    let admin_credential = sign_credential(admin_unsigned, &ca.private_jwk)?;

    let material = EntityCaMaterial {
        entity_id: entity_id.clone(),
        ski: ca.ski,
        common_name: ca.common_name,
        private_jwk: ca.private_jwk,
        public_jwk: ca.public_jwk.clone(),
        ca_cert_pem: ca.ca_cert_pem.clone(),
        admin_ski: Some(admin.ski),
        admin_private_jwk: Some(admin.private_jwk),
        admin_public_jwk: Some(admin.public_jwk.clone()),
    };
    let request = KickstartRequest {
        entity_id,
        package: package.to_ascii_lowercase(),
        root_public_jwk: Some(strip_private_jwk(&ca.public_jwk)),
        admin_public_jwk: Some(strip_private_jwk(&admin.public_jwk)),
        root_credential: Some(root_credential),
        admin_credential: Some(admin_credential),
        ca_cert_pem: Some(ca.ca_cert_pem),
    };
    Ok((material, request))
}

/// Persist CA (+ admin issuer) returned by server-keygen kickstart.
pub fn persist_kickstart_response(
    store: &impl KeyStore,
    entity_id: &str,
    res: &KickstartResponse,
) -> Result<EntityCaMaterial> {
    let ca_cert_pem = res
        .ca_cert_pem
        .clone()
        .ok_or_else(|| Error::admin("kickstart response missing caCertPem"))?;
    let root = res
        .root
        .as_ref()
        .ok_or_else(|| Error::admin("kickstart response missing root key material"))?;
    let private_jwk = root.private_jwk.clone().ok_or_else(|| {
        Error::admin(
            "kickstart did not return root.privateJwk — use client-keyed init (default) so keys stay local",
        )
    })?;
    let public_jwk = strip_private_jwk(&private_jwk);
    let ski = root
        .credential
        .as_ref()
        .map(|c| c.ski.clone())
        .unwrap_or_else(|| jwk_thumbprint_sha256(&public_jwk).unwrap_or_else(|_| "unknown".into()));
    let admin = res.root_admin.as_ref();
    let material = EntityCaMaterial {
        entity_id: entity_id.to_ascii_lowercase(),
        ski,
        common_name: format!("{entity_id} Entity CA"),
        private_jwk,
        public_jwk,
        ca_cert_pem,
        admin_ski: admin.and_then(|a| a.credential.as_ref().map(|c| c.ski.clone())),
        admin_private_jwk: admin.and_then(|a| a.private_jwk.clone()),
        admin_public_jwk: admin.and_then(|a| {
            a.private_jwk
                .as_ref()
                .map(strip_private_jwk)
                .or_else(|| a.credential.as_ref().map(|c| c.public_jwk.clone()))
        }),
    };
    save_entity_ca(store, &material)?;
    if let Some(root_pem) = &res.platform_root_pem {
        store.save_string(keystore::KEY_PLATFORM_CA, root_pem)?;
    }
    Ok(material)
}

fn parse_package(package: &str) -> Result<EntityPackage> {
    match package.to_ascii_lowercase().as_str() {
        "personal" => Ok(EntityPackage::Personal),
        "enterprise" => Ok(EntityPackage::Enterprise),
        other => Err(Error::admin(format!(
            "package must be personal or enterprise, got {other}"
        ))),
    }
}

fn strip_private_jwk(jwk: &Value) -> Value {
    let mut out = jwk.clone();
    if let Value::Object(map) = &mut out {
        map.remove("d");
    }
    out
}

fn validity_rfc3339(days: i64) -> (String, String) {
    let now = OffsetDateTime::now_utc();
    let not_before = now.format(&Rfc3339).unwrap_or_else(|_| now.to_string());
    let not_after = (now + Duration::days(days))
        .format(&Rfc3339)
        .unwrap_or_else(|_| now.to_string());
    (not_before, not_after)
}

impl EntityCaMaterial {
    pub fn issuer_ski(&self) -> &str {
        self.admin_ski.as_deref().unwrap_or(&self.ski)
    }

    pub fn issuer_private_jwk(&self) -> &Value {
        self.admin_private_jwk.as_ref().unwrap_or(&self.private_jwk)
    }
}

pub fn csr_fingerprint(csr_pem: &str) -> String {
    let digest = Sha256::digest(csr_pem.as_bytes());
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

pub fn enrollment_id(item: &EnrollListItem) -> Result<&str> {
    item.enroll_id
        .as_deref()
        .or_else(|| item.extra.get("id").and_then(|v| v.as_str()))
        .filter(|s| !s.is_empty())
        .ok_or_else(|| Error::admin("enrollment is missing enrollId"))
}

pub fn requester_label(item: &EnrollListItem) -> Option<String> {
    for key in ["requester", "requestedBy", "createdBy", "actor", "userId"] {
        if let Some(v) = item.extra.get(key) {
            if let Some(s) = v.as_str() {
                return Some(s.to_string());
            }
            return Some(v.to_string());
        }
    }
    None
}

pub async fn fetch_enrollment(
    client: &DpClient,
    enroll_id: &str,
    entity_id: Option<&str>,
) -> Result<EnrollListItem> {
    match client.enroll_get(enroll_id).await {
        Ok(item) => Ok(item),
        Err(err) => {
            let Some(entity_id) = entity_id else {
                return Err(Error::admin(format!(
                    "could not fetch enrollment {enroll_id} ({err}); pass --org <entity-id> to search enroll-list"
                )));
            };
            let list = client.enroll_list(entity_id, Some("all")).await?;
            list.into_iter()
                .find(|item| enrollment_id(item).ok() == Some(enroll_id))
                .ok_or_else(|| {
                    Error::admin(format!(
                        "enrollment {enroll_id} not found in enroll-list for {entity_id}"
                    ))
                })
        }
    }
}

pub async fn approve_enrollment(
    client: &DpClient,
    ca: &EntityCaMaterial,
    enroll: &EnrollListItem,
    separator: &str,
    permissions: Option<Vec<Capability>>,
    not_after_days: i64,
) -> Result<EnrollApproveResponse> {
    let enroll_id = enrollment_id(enroll)?.to_string();
    let csr_pem = enroll
        .csr_pem
        .as_deref()
        .ok_or_else(|| Error::admin(format!("enrollment {enroll_id} has no csrPem")))?;
    let (_public_jwk, ski) = public_jwk_from_csr_pem(csr_pem)?;
    if let Some(listed) = &enroll.ski {
        if listed != &ski {
            return Err(Error::admin(format!(
                "enrollment SKI {listed} does not match CSR thumbprint {ski}"
            )));
        }
    }
    let entity_id = enroll
        .entity_id
        .clone()
        .unwrap_or_else(|| ca.entity_id.clone());
    if entity_id != ca.entity_id {
        return Err(Error::admin(format!(
            "enrollment entity {entity_id} does not match Entity CA {}",
            ca.entity_id
        )));
    }

    let signed = issue_machine_leaf(
        ca,
        csr_pem,
        &entity_id,
        enroll.host.as_deref(),
        separator,
        permissions,
        not_after_days,
    )?;

    let req = EnrollApproveRequest {
        enroll_id,
        leaf_pem: signed.leaf_pem,
        chain_pem: signed.chain_pem,
        credential: signed.credential,
        issuer_ski: signed.issuer_ski,
    };
    client.enroll_approve(&req).await
}

/// Sign a machine CSR with the Entity CA and issue a CapabilityCredential.
#[derive(Debug, Clone)]
pub struct IssuedMachineLeaf {
    pub leaf_pem: String,
    pub chain_pem: String,
    pub credential: dp_rust::CapabilityCredential,
    pub issuer_ski: String,
}

pub fn issue_machine_leaf(
    ca: &EntityCaMaterial,
    csr_pem: &str,
    entity_id: &str,
    host: Option<&str>,
    separator: &str,
    permissions: Option<Vec<Capability>>,
    not_after_days: i64,
) -> Result<IssuedMachineLeaf> {
    let (public_jwk, ski) = public_jwk_from_csr_pem(csr_pem)?;
    let machine_name = host
        .and_then(|h| MachineIdentity::parse(h, separator).ok())
        .map(|id| id.machine_name)
        .or_else(|| host.map(str::to_string))
        .unwrap_or_else(|| ski.clone());

    let signed = sign_client_cert_from_csr(SignClientCertFromCsrParams {
        csr_pem,
        ca_cert_pem: &ca.ca_cert_pem,
        ca_private_jwk: &ca.private_jwk,
        ca_common_name: &ca.common_name,
        ski: &ski,
        host,
        not_after_days: Some(not_after_days),
    })?;

    let now = OffsetDateTime::now_utc();
    let not_before = now.format(&Rfc3339).unwrap_or_else(|_| now.to_string());
    let not_after = (now + Duration::days(not_after_days))
        .format(&Rfc3339)
        .unwrap_or_else(|_| now.to_string());
    let perms = permissions.unwrap_or_else(|| default_machine_permissions(&machine_name));
    let (issuer_ski, issuer_jwk) = (ca.issuer_ski().to_string(), ca.issuer_private_jwk().clone());
    let unsigned = unsigned_machine_credential(
        entity_id,
        ski.clone(),
        public_jwk,
        host.map(str::to_string),
        issuer_ski.clone(),
        perms,
        not_before,
        not_after,
    );
    let credential = sign_credential(unsigned, &issuer_jwk)?;
    Ok(IssuedMachineLeaf {
        leaf_pem: signed.leaf_pem,
        chain_pem: signed.chain_pem,
        credential,
        issuer_ski,
    })
}

pub async fn reject_enrollment(client: &DpClient, enroll_id: &str) -> Result<()> {
    client.enroll_reject(enroll_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::MemoryKeyStore;
    use dp_rust_mtls::generate_key_and_csr;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn entity_ca_persists() {
        let store = MemoryKeyStore::new();
        let ca = create_entity_ca(&store, "acme.com").unwrap();
        assert_eq!(ca.entity_id, "acme.com");
        let loaded = load_entity_ca(&store, "acme.com").unwrap().unwrap();
        assert_eq!(loaded.ski, ca.ski);
        assert!(create_entity_ca(&store, "acme.com").is_err());
    }

    #[test]
    fn client_keyed_kickstart_has_plugin_fields() {
        let (ca, req) = prepare_client_keyed_kickstart("Smoke.TEST", "enterprise").unwrap();
        assert_eq!(ca.entity_id, "smoke.test");
        assert!(req.is_client_keyed());
        assert_eq!(req.entity_id, "smoke.test");
        assert!(req.ca_cert_pem.unwrap().contains("BEGIN CERTIFICATE"));
        assert_eq!(
            req.root_credential.unwrap().kind,
            CredentialKind::EntityRoot
        );
        assert_eq!(
            req.admin_credential.unwrap().kind,
            CredentialKind::RootAdmin
        );
        assert!(ca.admin_ski.is_some());
    }

    #[tokio::test]
    async fn approve_posts_leaf_and_signed_credential() {
        let store = MemoryKeyStore::new();
        let ca = create_entity_ca(&store, "acme.com").unwrap();
        let device = generate_key_and_csr("db1--acme.com", Some("db1--acme.com")).unwrap();

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/delegate-permissions/enroll-approve"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "enrollId": "e1",
                "status": "approved",
                "platformCertPem": "-----BEGIN CERTIFICATE-----\nP\n-----END CERTIFICATE-----\n"
            })))
            .mount(&server)
            .await;

        let client = DpClient::new(&server.uri());
        let enroll = EnrollListItem {
            enroll_id: Some("e1".into()),
            entity_id: Some("acme.com".into()),
            host: Some("db1--acme.com".into()),
            status: Some("pending".into()),
            kind: Some("target".into()),
            ski: Some(device.ski.clone()),
            csr_pem: Some(device.csr_pem.clone()),
            extra: serde_json::Map::new(),
        };
        let res = approve_enrollment(&client, &ca, &enroll, "--", None, 365)
            .await
            .unwrap();
        assert_eq!(res.status.as_deref(), Some("approved"));
        assert!(res.issued.platform_cert_pem.is_some());
    }
}
