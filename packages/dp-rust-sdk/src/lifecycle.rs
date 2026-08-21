//! Renew, rotate, and decommission. HTTP + local keystore transitions.

use dp_rust_mtls::{build_csr_from_private_pem, generate_ed25519, jwks_from_private_pem};

use crate::admin::{issue_machine_leaf, EntityCaMaterial};
use crate::client::DpClient;
use crate::enrollment::{load_state, save_state};
use crate::error::{Error, Result};
use crate::keystore::{self, KeyStore};
use crate::types::{EnrollmentStatus, IssuedCerts, MachineRenewRequest, MachineState};

pub struct RenewParams {
    pub leaf_pem: String,
    pub chain_pem: String,
    pub credential: dp_rust::CapabilityCredential,
    pub issuer_ski: String,
}

/// Generate a replacement key + CSR. Old key stays active until [`complete_renewal`].
///
/// Crash-safe: if status is already `renewing`/`rotating` and `machine.key.new`
/// exists, the existing material is reused.
pub fn prepare_renewal(store: &impl KeyStore) -> Result<(MachineState, String, String)> {
    let mut state = load_state(store)?.ok_or_else(|| Error::lifecycle("no local machine state"))?;
    match state.status {
        EnrollmentStatus::Renewing | EnrollmentStatus::Rotating
            if store.exists(keystore::KEY_MACHINE_KEY_NEW)?
                && store.exists(keystore::KEY_MACHINE_CSR)? =>
        {
            let pem = store
                .load_string(keystore::KEY_MACHINE_KEY_NEW)?
                .ok_or_else(|| Error::lifecycle("missing identity/machine.key.new"))?;
            let csr = store
                .load_string(keystore::KEY_MACHINE_CSR)?
                .ok_or_else(|| Error::lifecycle("missing identity/machine.csr"))?;
            let (_p, _u, ski) = jwks_from_private_pem(&pem)?;
            return Ok((state, ski, csr));
        }
        EnrollmentStatus::Active => {}
        other => {
            return Err(Error::lifecycle(format!(
                "machine must be active to renew (currently {other})"
            )));
        }
    }
    let generated = generate_ed25519()?;
    store.save_string(keystore::KEY_MACHINE_KEY_NEW, &generated.private_pem)?;
    let csr_pem = build_csr_from_private_pem(&generated.private_pem, &state.machine_identity)?;
    store.save_string(keystore::KEY_MACHINE_CSR, &csr_pem)?;
    state.transition(EnrollmentStatus::Renewing)?;
    save_state(store, &state)?;
    Ok((state, generated.ski, csr_pem))
}

pub async fn complete_renewal(
    client: &DpClient,
    store: &impl KeyStore,
    params: RenewParams,
) -> Result<MachineState> {
    let mut state = load_state(store)?.ok_or_else(|| Error::lifecycle("no local machine state"))?;
    if state.status != EnrollmentStatus::Renewing && state.status != EnrollmentStatus::Rotating {
        return Err(Error::lifecycle(format!(
            "machine is not in a renewal transition (currently {})",
            state.status
        )));
    }
    let old_ski = state
        .ski
        .clone()
        .ok_or_else(|| Error::lifecycle("state.json is missing ski"))?;
    let new_pem = store
        .load_string(keystore::KEY_MACHINE_KEY_NEW)?
        .ok_or_else(|| {
            Error::lifecycle("missing identity/machine.key.new — run prepare_renewal")
        })?;
    let (_priv, public_jwk, new_ski) = jwks_from_private_pem(&new_pem)?;
    if params.credential.ski != new_ski {
        return Err(Error::lifecycle(
            "renewal credential SKI does not match machine.key.new",
        ));
    }

    let req = MachineRenewRequest {
        ski: old_ski.clone(),
        csr_pem: store
            .load_string(keystore::KEY_MACHINE_CSR)?
            .ok_or_else(|| Error::lifecycle("missing CSR"))?,
        public_jwk: Some(public_jwk),
        leaf_pem: params.leaf_pem.clone(),
        chain_pem: params.chain_pem.clone(),
        credential: params.credential.clone(),
        issuer_ski: params.issuer_ski.clone(),
    };
    let res = client.machine_renew(&req).await?;
    persist_renewed(store, &mut state, &new_pem, &old_ski, &res.issued, &params)?;
    Ok(state)
}

/// Prepare a new key, sign with the Entity CA, POST `/machine-renew`, swap keys.
pub async fn renew_machine(
    client: &DpClient,
    store: &impl KeyStore,
    ca: &EntityCaMaterial,
    separator: &str,
    not_after_days: i64,
) -> Result<MachineState> {
    let state = load_state(store)?.ok_or_else(|| Error::lifecycle("no local machine state"))?;
    if ca.entity_id != state.entity_id {
        return Err(Error::lifecycle(format!(
            "Entity CA {} does not match machine entity {}",
            ca.entity_id, state.entity_id
        )));
    }
    let host = state.machine_identity.clone();
    let (_state, _ski, csr_pem) = prepare_renewal(store)?;
    let issued = issue_machine_leaf(
        ca,
        &csr_pem,
        &state.entity_id,
        Some(&host),
        separator,
        None,
        not_after_days,
    )?;
    complete_renewal(
        client,
        store,
        RenewParams {
            leaf_pem: issued.leaf_pem,
            chain_pem: issued.chain_pem,
            credential: issued.credential,
            issuer_ski: issued.issuer_ski,
        },
    )
    .await
}

fn persist_renewed(
    store: &impl KeyStore,
    state: &mut MachineState,
    new_pem: &str,
    old_ski: &str,
    issued: &IssuedCerts,
    submitted: &RenewParams,
) -> Result<()> {
    let leaf = issued
        .cert_pem
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&submitted.leaf_pem);
    store.save_string(keystore::KEY_MACHINE_CRT, leaf)?;
    let chain = issued
        .chain_pem
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(&submitted.chain_pem);
    store.save_string(keystore::KEY_CHAIN, chain)?;
    crate::enrollment::store_platform_endorsement(
        store,
        issued.platform_root_pem.as_deref(),
        issued.platform_cert_pem.as_deref(),
    )?;
    let credential = issued.credential.as_ref().unwrap_or(&submitted.credential);
    store.save_string(keystore::KEY_MACHINE_KEY, new_pem)?;
    store.secure_delete(keystore::KEY_MACHINE_KEY_NEW)?;
    store.save_string(
        keystore::KEY_CREDENTIAL,
        &serde_json::to_string_pretty(credential)?,
    )?;
    state.renewed_from_ski = Some(old_ski.to_string());
    state.ski = Some(credential.ski.clone());
    state.cert_expires_at = Some(credential.not_after.clone());
    state.transition(EnrollmentStatus::Active)?;
    save_state(store, state)?;
    Ok(())
}

/// Self-decommission: revoke remotely, wipe keys, keep `state.json` as audit metadata.
pub async fn decommission_machine(
    client: &DpClient,
    store: &impl KeyStore,
    reason: &str,
) -> Result<MachineState> {
    let mut state = load_state(store)?.ok_or_else(|| Error::lifecycle("no local machine state"))?;
    let ski = state
        .ski
        .clone()
        .ok_or_else(|| Error::lifecycle("state.json is missing ski"))?;
    if !matches!(
        state.status,
        EnrollmentStatus::Active | EnrollmentStatus::Renewing | EnrollmentStatus::Rotating
    ) {
        return Err(Error::lifecycle(format!(
            "machine cannot be decommissioned from status {}",
            state.status
        )));
    }
    let _ = client.machine_decommission(&ski, reason).await?;
    wipe_secrets(store)?;
    state.transition(EnrollmentStatus::Decommissioned)?;
    state.pull_token = None;
    save_state(store, &state)?;
    Ok(state)
}

fn wipe_secrets(store: &impl KeyStore) -> Result<()> {
    for key in [
        keystore::KEY_MACHINE_KEY,
        keystore::KEY_MACHINE_KEY_NEW,
        keystore::KEY_MACHINE_CSR,
        keystore::KEY_MACHINE_CRT,
        keystore::KEY_ORG_CA,
        keystore::KEY_PLATFORM_CA,
        keystore::KEY_PLATFORM_ENDORSED,
        keystore::KEY_CHAIN,
        keystore::KEY_CREDENTIAL,
    ] {
        store.secure_delete(key)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::create_entity_ca;
    use crate::enrollment::now_rfc3339;
    use crate::keystore::MemoryKeyStore;
    use crate::types::MachineKind;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn active_state() -> MachineState {
        MachineState {
            machine_identity: "db1--acme.com".into(),
            entity_id: "acme.com".into(),
            machine_name: "db1".into(),
            ski: Some("oldski".into()),
            enrollment_id: None,
            pull_token: Some("tok".into()),
            status: EnrollmentStatus::Active,
            cert_serial: None,
            cert_expires_at: None,
            created_at: now_rfc3339(),
            renewed_from_ski: None,
            kind: Some(MachineKind::Target),
        }
    }

    #[test]
    fn prepare_renewal_requires_active() {
        let store = MemoryKeyStore::new();
        let mut state = active_state();
        state.status = EnrollmentStatus::PendingAdmin;
        save_state(&store, &state).unwrap();
        assert!(prepare_renewal(&store).is_err());
    }

    #[test]
    fn prepare_renewal_writes_new_key_and_resumes() {
        let store = MemoryKeyStore::new();
        save_state(&store, &active_state()).unwrap();
        let (updated, ski, csr) = prepare_renewal(&store).unwrap();
        assert_eq!(updated.status, EnrollmentStatus::Renewing);
        assert!(!ski.is_empty());
        assert!(csr.contains("BEGIN CERTIFICATE REQUEST"));
        let (again, ski2, _) = prepare_renewal(&store).unwrap();
        assert_eq!(again.status, EnrollmentStatus::Renewing);
        assert_eq!(ski, ski2);
    }

    #[tokio::test]
    async fn renew_machine_swaps_key_and_returns_active() {
        let store = MemoryKeyStore::new();
        save_state(&store, &active_state()).unwrap();
        let ca = create_entity_ca(&store, "acme.com").unwrap();

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/delegate-permissions/machine-renew"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "status": "renewed",
                "newSki": "newski"
            })))
            .mount(&server)
            .await;

        let client = DpClient::new(&server.uri());
        let state = renew_machine(&client, &store, &ca, "--", 365)
            .await
            .unwrap();
        assert_eq!(state.status, EnrollmentStatus::Active);
        assert_eq!(state.renewed_from_ski.as_deref(), Some("oldski"));
        assert_ne!(state.ski.as_deref(), Some("oldski"));
        assert!(!store.exists(keystore::KEY_MACHINE_KEY_NEW).unwrap());
        assert!(store.exists(keystore::KEY_MACHINE_KEY).unwrap());
        assert!(store.exists(keystore::KEY_MACHINE_CRT).unwrap());
    }

    #[tokio::test]
    async fn decommission_wipes_secrets_and_keeps_state() {
        let store = MemoryKeyStore::new();
        save_state(&store, &active_state()).unwrap();
        store
            .save_string(keystore::KEY_MACHINE_KEY, "secret")
            .unwrap();
        store
            .save_string(keystore::KEY_MACHINE_CRT, "cert")
            .unwrap();

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/delegate-permissions/machine-decommission"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ski": "oldski",
                "status": "decommissioned"
            })))
            .mount(&server)
            .await;

        let client = DpClient::new(&server.uri());
        let state = decommission_machine(&client, &store, "decommissioned")
            .await
            .unwrap();
        assert_eq!(state.status, EnrollmentStatus::Decommissioned);
        assert!(state.pull_token.is_none());
        assert!(!store.exists(keystore::KEY_MACHINE_KEY).unwrap());
        assert!(!store.exists(keystore::KEY_MACHINE_CRT).unwrap());
        assert!(store.exists(keystore::KEY_STATE).unwrap());
    }
}
