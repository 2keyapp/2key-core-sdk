//! HTTP client SDK for billing Machine AuthN (`/api/v1/machine-authn/*`).
//!
//! Wraps [`dp_rust`] wire types and [`dp_rust_mtls`] key/CSR helpers. The CLI
//! (`dp-cli`) is a thin frontend over this crate.

mod admin;
mod agent;
mod client;
mod config;
mod credential;
mod enrollment;
mod error;
mod identity;
mod keystore;
mod lifecycle;
mod session;
mod types;

pub use admin::{
    admin_ca_cert, admin_ca_key, admin_ca_meta, approve_enrollment, create_entity_ca,
    csr_fingerprint, enrollment_id, fetch_enrollment, issue_machine_leaf, load_entity_ca,
    persist_kickstart_response, prepare_client_keyed_kickstart, reject_enrollment, requester_label,
    require_entity_ca, save_entity_ca, EntityCaMaterial, IssuedMachineLeaf,
};
pub use agent::{load_agent_identity, AgentIdentity};
pub use client::DpClient;
pub use config::ResolvedConfig;
pub use credential::{
    canonical_credential_payload, default_machine_permissions, kickstart_permissions,
    personal_root_permissions, root_admin_permissions, sign_credential, unsigned_credential,
    unsigned_machine_credential, verify_credential_signature, with_entity_scope,
};
pub use enrollment::{
    enroll_machine, load_state, pull_enrollment, save_state, wait_for_approval, EnrollParams,
};
pub use error::{Error, Result};
pub use identity::MachineIdentity;
pub use keystore::{
    keys, FileKeyStore, KeyStore, MemoryKeyStore, KEY_CHAIN, KEY_CONFIG, KEY_CREDENTIAL,
    KEY_MACHINE_CRT, KEY_MACHINE_CSR, KEY_MACHINE_KEY, KEY_MACHINE_KEY_NEW, KEY_ORG_CA,
    KEY_PLATFORM_CA, KEY_PLATFORM_ENDORSED, KEY_SESSION, KEY_STATE,
};
pub use lifecycle::{
    complete_renewal, decommission_machine, prepare_renewal, renew_machine, RenewParams,
};
pub use session::{
    delete_session, load_session, save_session, DeviceCodeResponse, DeviceTokenIssued,
    DeviceTokenPoll, GetSessionResponse, SessionTransport, SessionUser, StoredSession,
};
pub use types::{
    normalize_ca_file_pem, CatalogResponse, CredentialListItem, CredentialStatusResponse,
    DecommissionResponse,     EnrollApproveRequest, EnrollApproveResponse, EnrollCreateRequest, EnrollCreateResponse,
    EnrollInstantRequest, EnrollInstantResponse, EnrollInviteRequest, EnrollInviteResponse,
    EnrollListItem,
    EnrollPullResponse, EnrollmentStatus, EntityResponse, IssuedCerts, KeyAlgo,
    KickstartKeyMaterial, KickstartRequest, KickstartResponse, MachineKind,
    MachinePermissionsRequest, MachinePermissionsResponse, MachineRenewRequest,
    MachineRenewResponse, MachineState, PlatformRootResponse, RevokeResponse,
};

pub use dp_rust::{
    Capability, CapabilityCredential, CredentialKind, EntityPackage, PlatformCosign,
};

/// Crate version (same as `CARGO_PKG_VERSION`).
pub fn sdk_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
