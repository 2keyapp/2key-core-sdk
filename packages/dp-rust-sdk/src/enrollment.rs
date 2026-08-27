//! Enrollment state machine. Persisted in `state.json` so `machine enroll --wait`
//! (or a later `machine pull`) can resume after the process exits.

use std::time::Duration;

use dp_rust_mtls::{
    build_csr_from_private_pem, generate_ed25519, jwks_from_private_pem,
    verify_ed25519_cert_against_issuer,
};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::admin::{issue_machine_leaf, load_entity_ca, EntityCaMaterial};
use crate::client::DpClient;
use crate::error::{Error, Result};
use crate::machine_authn_port::MachineAuthnPort;
use crate::identity::MachineIdentity;
use crate::keystore::{self, KeyStore};
use crate::types::{
    EnrollCreateRequest, EnrollInstantRequest, EnrollPullResponse, EnrollmentStatus, IssuedCerts,
    KeyAlgo, MachineKind, MachinePermissionsRequest, MachineState,
};

pub struct EnrollParams {
    pub entity_id: String,
    pub machine_name: String,
    pub kind: MachineKind,
    pub key_algo: KeyAlgo,
    pub wait: bool,
    pub wait_interval: Duration,
    pub separator: String,
    /// Localhost ceremony: sign with the local Entity CA and POST enroll-instant.
    pub instant: bool,
    /// Redeem a push-invite instead of an uninvited pull enroll.
    pub invite_token: Option<String>,
}

pub fn load_state(store: &impl KeyStore) -> Result<Option<MachineState>> {
    match store.load_string(keystore::KEY_STATE)? {
        None => Ok(None),
        Some(raw) => Ok(Some(serde_json::from_str(&raw)?)),
    }
}

pub fn save_state(store: &impl KeyStore, state: &MachineState) -> Result<()> {
    let json = serde_json::to_string_pretty(state)?;
    store.save_string(keystore::KEY_STATE, &json)
}

pub async fn enroll_machine(
    client: &DpClient,
    store: &impl KeyStore,
    params: EnrollParams,
) -> Result<MachineState> {
    if params.key_algo != KeyAlgo::Ed25519 {
        return Err(Error::Unsupported(format!(
            "{} keys are not implemented yet (use ed25519)",
            params.key_algo.as_str()
        )));
    }

    let identity =
        MachineIdentity::new(&params.machine_name, &params.entity_id, &params.separator)?;

    if let Some(existing) = load_state(store)? {
        if !existing.status.allows_enroll() {
            return Err(Error::enrollment(format!(
                "machine {} is already {} — use `machine pull` or `machine status`",
                existing.machine_identity, existing.status
            )));
        }
    }

    let generated = generate_ed25519()?;
    store.save_string(keystore::KEY_MACHINE_KEY, &generated.private_pem)?;
    let mut state = MachineState {
        machine_identity: identity.as_str(),
        entity_id: identity.entity_id.clone(),
        machine_name: identity.machine_name.clone(),
        ski: Some(generated.ski.clone()),
        enrollment_id: None,
        pull_token: None,
        status: EnrollmentStatus::KeyGenerated,
        cert_serial: None,
        cert_expires_at: None,
        created_at: now_rfc3339(),
        renewed_from_ski: None,
        kind: Some(params.kind),
    };
    save_state(store, &state)?;

    let host = identity.as_str();
    let csr_pem = build_csr_from_private_pem(&generated.private_pem, &host)?;
    store.save_string(keystore::KEY_MACHINE_CSR, &csr_pem)?;
    state.transition(EnrollmentStatus::CsrCreated)?;
    save_state(store, &state)?;

    if params.instant {
        if params.invite_token.is_some() {
            return Err(Error::enrollment(
                "invite enroll cannot use --local / --instant",
            ));
        }
        if let Some(ca) = load_entity_ca(store, &identity.entity_id)? {
            return enroll_instant_local(
                client,
                store,
                &mut state,
                &ca,
                &identity,
                &host,
                params.kind,
                &csr_pem,
                &generated.public_jwk,
            )
            .await;
        }
        return Err(Error::enrollment(format!(
            "instant enroll needs a local Entity CA — run `init {}` first (or omit --instant)",
            identity.entity_id
        )));
    }

    let req = EnrollCreateRequest {
        entity_id: identity.entity_id.clone(),
        host: host.clone(),
        kind: Some(params.kind),
        subject_ski: Some(generated.ski.clone()),
        public_jwk: Some(generated.public_jwk.clone()),
        csr_pem,
        invite_token: params.invite_token.clone(),
    };
    let res = client.enroll_create(&req).await?;
    state.transition(EnrollmentStatus::EnrollmentSubmitted)?;
    state.enrollment_id = res.enroll_id.clone();
    state.pull_token = res.pull_token.clone();

    let status_hint = res
        .status
        .as_deref()
        .unwrap_or("pending")
        .to_ascii_lowercase();
    if status_hint == "approved" || status_hint == "signed" || res.issued.credential.is_some() {
        state.transition(EnrollmentStatus::PendingAdmin)?;
        state.transition(EnrollmentStatus::Signed)?;
        apply_issued(store, &mut state, &res.issued)?;
        save_state(store, &state)?;
        return Ok(state);
    }

    state.transition(EnrollmentStatus::PendingAdmin)?;
    save_state(store, &state)?;

    if params.wait {
        return wait_for_approval(client, store, params.wait_interval).await;
    }
    Ok(state)
}

pub async fn pull_enrollment(
    client: &impl MachineAuthnPort,
    store: &impl KeyStore,
) -> Result<MachineState> {
    let mut state = load_state(store)?.ok_or_else(|| {
        Error::enrollment("no local enrollment state — run `machine enroll` first")
    })?;
    let token = state.pull_token.clone().ok_or_else(|| {
        Error::enrollment("no pull token in state.json — re-run `machine enroll`")
    })?;
    let res = client.enroll_pull(&token).await?;
    apply_pull(store, &mut state, res)?;
    save_state(store, &state)?;
    Ok(state)
}

pub async fn wait_for_approval(
    client: &impl MachineAuthnPort,
    store: &impl KeyStore,
    interval: Duration,
) -> Result<MachineState> {
    loop {
        let state = pull_enrollment(client, store).await?;
        match state.status {
            EnrollmentStatus::Active => return Ok(state),
            EnrollmentStatus::Rejected => {
                return Err(Error::enrollment("enrollment was rejected"));
            }
            _ => tokio::time::sleep(interval).await,
        }
    }
}

fn apply_pull(
    store: &impl KeyStore,
    state: &mut MachineState,
    res: EnrollPullResponse,
) -> Result<()> {
    let status = res.status.to_ascii_lowercase();
    if status == "pending" || status == "submitted" {
        return Ok(());
    }
    if status == "rejected" || status == "denied" {
        state.transition(EnrollmentStatus::Rejected)?;
        return Ok(());
    }
    if status == "approved" || status == "signed" || res.issued.credential.is_some() {
        if state.status == EnrollmentStatus::PendingAdmin {
            state.transition(EnrollmentStatus::Signed)?;
        }
        apply_issued(store, state, &res.issued)?;
        return Ok(());
    }
    Err(Error::enrollment(format!(
        "unexpected enroll-pull status {status:?}"
    )))
}

fn apply_issued(
    store: &impl KeyStore,
    state: &mut MachineState,
    issued: &IssuedCerts,
) -> Result<()> {
    if let Some(pem) = &issued.cert_pem {
        store.save_string(keystore::KEY_MACHINE_CRT, pem)?;
        state.transition(EnrollmentStatus::CertReceived)?;
    } else if issued.credential.is_some() {
        // Instant enroll may return a credential without a CA-issued leaf.
        state.transition(EnrollmentStatus::CertReceived)?;
    } else {
        return Err(Error::enrollment(
            "approved enrollment did not include a leaf certificate or credential",
        ));
    }

    if let Some(chain) = &issued.chain_pem {
        store.save_string(keystore::KEY_CHAIN, chain)?;
        if let Some(org_ca) = last_pem_block(chain) {
            store.save_string(keystore::KEY_ORG_CA, &org_ca)?;
        }
    }
    store_platform_endorsement(
        store,
        issued.platform_root_pem.as_deref(),
        issued.platform_cert_pem.as_deref(),
    )?;
    if let Some(cred) = &issued.credential {
        store.save_string(
            keystore::KEY_CREDENTIAL,
            &serde_json::to_string_pretty(cred)?,
        )?;
        state.ski = Some(cred.ski.clone());
        state.cert_expires_at = Some(cred.not_after.clone());
        verify_local_key(store, cred)?;
        state.transition(EnrollmentStatus::CertVerified)?;
        state.transition(EnrollmentStatus::Active)?;
    } else {
        verify_local_key_present(store)?;
        state.transition(EnrollmentStatus::CertVerified)?;
        state.transition(EnrollmentStatus::Active)?;
    }
    Ok(())
}

async fn enroll_instant_local(
    client: &DpClient,
    store: &impl KeyStore,
    state: &mut MachineState,
    ca: &EntityCaMaterial,
    identity: &MachineIdentity,
    host: &str,
    kind: MachineKind,
    csr_pem: &str,
    public_jwk: &serde_json::Value,
) -> Result<MachineState> {
    let perms = client
        .enroll_machine_permissions(&MachinePermissionsRequest {
            entity_id: identity.entity_id.clone(),
            host: Some(host.to_string()),
            kind: Some(kind),
            ski: None,
            permissions: vec![],
        })
        .await
        .ok()
        .map(|r| r.permissions)
        .filter(|p| !p.is_empty());

    let signed = issue_machine_leaf(
        ca,
        csr_pem,
        &identity.entity_id,
        Some(host),
        &identity.separator,
        perms,
        365,
    )?;

    let req = EnrollInstantRequest {
        entity_id: identity.entity_id.clone(),
        host: host.to_string(),
        kind: Some(kind),
        csr_pem: csr_pem.to_string(),
        public_jwk: Some(public_jwk.clone()),
        subject_ski: Some(signed.credential.ski.clone()),
        leaf_pem: signed.leaf_pem,
        chain_pem: signed.chain_pem,
        credential: signed.credential,
        issuer_ski: signed.issuer_ski,
    };
    let res = client.enroll_instant(&req).await?;
    state.transition(EnrollmentStatus::EnrollmentSubmitted)?;
    state.enrollment_id = res.enroll_id.clone();
    if let Some(ski) = &res.ski {
        state.ski = Some(ski.clone());
    }
    state.transition(EnrollmentStatus::PendingAdmin)?;
    state.transition(EnrollmentStatus::Signed)?;
    apply_issued(store, state, &res.issued)?;
    save_state(store, state)?;
    Ok(state.clone())
}

/// Persist Platform Root + endorsement and verify the HAProxy litmus:
/// the endorsed cert must verify against the single Platform Root.
pub(crate) fn store_platform_endorsement(
    store: &impl KeyStore,
    platform_root_pem: Option<&str>,
    platform_cert_pem: Option<&str>,
) -> Result<()> {
    if let Some(root) = platform_root_pem {
        store.save_string(keystore::KEY_PLATFORM_CA, root)?;
    }
    let Some(endorsed) = platform_cert_pem else {
        return Ok(());
    };
    store.save_string(keystore::KEY_PLATFORM_ENDORSED, endorsed)?;
    let stored_root = store.load_string(keystore::KEY_PLATFORM_CA)?;
    let root = platform_root_pem.or(stored_root.as_deref());
    let Some(root) = root else {
        return Err(Error::enrollment(
            "platform endorsement arrived without a Platform Root (HAProxy ca-file)",
        ));
    };
    if !verify_ed25519_cert_against_issuer(endorsed, root)? {
        return Err(Error::enrollment(
            "platform endorsement does not verify against the Platform Root",
        ));
    }
    Ok(())
}

fn verify_local_key_present(store: &impl KeyStore) -> Result<()> {
    if !store.exists(keystore::KEY_MACHINE_KEY)? {
        return Err(Error::enrollment("local private key is missing"));
    }
    Ok(())
}

fn verify_local_key(store: &impl KeyStore, cred: &dp_rust::CapabilityCredential) -> Result<()> {
    let pem = store
        .load_string(keystore::KEY_MACHINE_KEY)?
        .ok_or_else(|| Error::enrollment("local private key is missing"))?;
    let (_priv_jwk, public_jwk, ski) = jwks_from_private_pem(&pem)?;
    if cred.ski != ski {
        return Err(Error::enrollment(format!(
            "issued credential SKI {} does not match local key {ski}",
            cred.ski
        )));
    }
    let local_x = public_jwk.get("x").and_then(|v| v.as_str());
    let cred_x = cred.public_jwk.get("x").and_then(|v| v.as_str());
    if local_x.is_none() || local_x != cred_x {
        return Err(Error::enrollment(
            "issued credential public key does not match the local private key",
        ));
    }
    Ok(())
}

pub(crate) fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".into())
}

pub(crate) fn last_pem_block(pem: &str) -> Option<String> {
    let mut blocks = Vec::new();
    let mut current = String::new();
    let mut in_block = false;
    for line in pem.lines() {
        if line.starts_with("-----BEGIN ") {
            in_block = true;
            current.clear();
            current.push_str(line);
            current.push('\n');
        } else if in_block {
            current.push_str(line);
            current.push('\n');
            if line.starts_with("-----END ") {
                blocks.push(current.clone());
                in_block = false;
            }
        }
    }
    blocks.pop()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::MemoryKeyStore;
    use dp_rust::{Capability, CapabilityCredential, CredentialKind};
    use serde_json::json;

    fn fake_cred(ski: &str, x: &str) -> CapabilityCredential {
        CapabilityCredential {
            version: 1,
            kind: CredentialKind::Machine,
            entity_id: "acme.com".into(),
            ski: ski.into(),
            public_jwk: json!({"kty":"OKP","crv":"Ed25519","x": x}),
            permissions: vec![Capability {
                action: "machine.connect".into(),
                scope: json!({"name":"db1"}),
                delegable: false,
            }],
            zone: None,
            host: Some("db1--acme.com".into()),
            issuer_ski: "issuer".into(),
            not_before: "2026-01-01T00:00:00Z".into(),
            not_after: "2027-01-01T00:00:00Z".into(),
            package: None,
            platform_cosign: None,
            signature: "hdr.payload.sig".into(),
        }
    }

    #[test]
    fn persist_state_roundtrip() {
        let store = MemoryKeyStore::new();
        let state = MachineState {
            machine_identity: "db1--acme.com".into(),
            entity_id: "acme.com".into(),
            machine_name: "db1".into(),
            ski: Some("abc".into()),
            enrollment_id: Some("e1".into()),
            pull_token: Some("tok".into()),
            status: EnrollmentStatus::PendingAdmin,
            cert_serial: None,
            cert_expires_at: None,
            created_at: now_rfc3339(),
            renewed_from_ski: None,
            kind: Some(MachineKind::Target),
        };
        save_state(&store, &state).unwrap();
        let loaded = load_state(&store).unwrap().unwrap();
        assert_eq!(loaded.status, EnrollmentStatus::PendingAdmin);
        assert_eq!(loaded.pull_token.as_deref(), Some("tok"));
    }

    #[test]
    fn apply_issued_rejects_key_mismatch() {
        let store = MemoryKeyStore::new();
        let gen = generate_ed25519().unwrap();
        store
            .save_string(keystore::KEY_MACHINE_KEY, &gen.private_pem)
            .unwrap();
        let mut state = MachineState {
            machine_identity: "db1--acme.com".into(),
            entity_id: "acme.com".into(),
            machine_name: "db1".into(),
            ski: Some(gen.ski.clone()),
            enrollment_id: None,
            pull_token: None,
            status: EnrollmentStatus::Signed,
            cert_serial: None,
            cert_expires_at: None,
            created_at: now_rfc3339(),
            renewed_from_ski: None,
            kind: None,
        };
        let issued = IssuedCerts {
            credential: Some(fake_cred("deadbeef", "not-the-key")),
            cert_pem: Some("-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n".into()),
            ..Default::default()
        };
        let err = apply_issued(&store, &mut state, &issued).unwrap_err();
        assert!(err.to_string().contains("does not match"));
    }

    #[test]
    fn apply_issued_accepts_matching_key() {
        let store = MemoryKeyStore::new();
        let gen = generate_ed25519().unwrap();
        store
            .save_string(keystore::KEY_MACHINE_KEY, &gen.private_pem)
            .unwrap();
        let x = gen.public_jwk.get("x").and_then(|v| v.as_str()).unwrap();
        let mut state = MachineState {
            machine_identity: "db1--acme.com".into(),
            entity_id: "acme.com".into(),
            machine_name: "db1".into(),
            ski: Some(gen.ski.clone()),
            enrollment_id: None,
            pull_token: None,
            status: EnrollmentStatus::Signed,
            cert_serial: None,
            cert_expires_at: None,
            created_at: now_rfc3339(),
            renewed_from_ski: None,
            kind: None,
        };
        let issued = IssuedCerts {
            credential: Some(fake_cred(&gen.ski, x)),
            cert_pem: Some("-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----\n".into()),
            chain_pem: Some(
                "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n".into(),
            ),
            ..Default::default()
        };
        apply_issued(&store, &mut state, &issued).unwrap();
        assert_eq!(state.status, EnrollmentStatus::Active);
        assert!(store.exists(keystore::KEY_ORG_CA).unwrap());
    }

    #[test]
    fn platform_endorsement_must_verify_against_the_platform_root() {
        use dp_rust_mtls::{
            create_self_signed_ca, generate_key_and_csr, sign_client_cert_from_csr,
            SignClientCertFromCsrParams,
        };
        let store = MemoryKeyStore::new();
        let platform = create_self_signed_ca("Platform CA").unwrap();
        let device = generate_key_and_csr("db1--acme.com", Some("db1--acme.com")).unwrap();
        let endorsed = sign_client_cert_from_csr(SignClientCertFromCsrParams {
            csr_pem: &device.csr_pem,
            ca_cert_pem: &platform.ca_cert_pem,
            ca_private_jwk: &platform.private_jwk,
            ca_common_name: &platform.common_name,
            ski: &device.ski,
            host: Some("db1--acme.com"),
            not_after_days: None,
        })
        .unwrap();

        store_platform_endorsement(
            &store,
            Some(&platform.ca_cert_pem),
            Some(&endorsed.leaf_pem),
        )
        .unwrap();

        let other = create_self_signed_ca("Other Root").unwrap();
        let err =
            store_platform_endorsement(&store, Some(&other.ca_cert_pem), Some(&endorsed.leaf_pem))
                .unwrap_err();
        assert!(err.to_string().contains("does not verify"));
    }
}
