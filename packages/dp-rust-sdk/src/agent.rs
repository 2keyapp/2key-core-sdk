//! Machine agent identity: load local keys, verify the Platform-endorsed leaf.

use dp_rust_mtls::verify_ed25519_cert_against_issuer;

use crate::error::{Error, Result};
use crate::keystore::{self, KeyStore};

/// Material the Target/Source agent needs to stay resident and present mTLS.
#[derive(Debug, Clone)]
pub struct AgentIdentity {
    pub machine_identity: String,
    pub endorsed_pem: String,
    pub key_pem: String,
    pub platform_root_pem: String,
}

/// Load `$DP_STATE_DIR/identity` and verify `platform-endorsed.crt` against `platform-ca.crt`.
pub fn load_agent_identity(store: &impl KeyStore) -> Result<AgentIdentity> {
    let key_pem = store
        .load_string(keystore::KEY_MACHINE_KEY)?
        .ok_or_else(|| Error::agent("missing identity/machine.key — run register first"))?;
    let endorsed_pem = store
        .load_string(keystore::KEY_PLATFORM_ENDORSED)?
        .ok_or_else(|| {
            Error::agent(
                "missing identity/platform-endorsed.crt — enroll or pull first",
            )
        })?;
    let platform_root_pem = store
        .load_string(keystore::KEY_PLATFORM_CA)?
        .ok_or_else(|| Error::agent("missing identity/platform-ca.crt — enroll or pull first"))?;

    if !verify_ed25519_cert_against_issuer(&endorsed_pem, &platform_root_pem)? {
        return Err(Error::agent(
            "platform-endorsed.crt does not verify against platform-ca.crt",
        ));
    }

    let machine_identity = crate::enrollment::load_state(store)?
        .map(|s| s.machine_identity)
        .unwrap_or_else(|| "unknown".into());

    Ok(AgentIdentity {
        machine_identity,
        endorsed_pem,
        key_pem,
        platform_root_pem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keystore::MemoryKeyStore;

    #[test]
    fn missing_machine_key_errors() {
        let store = MemoryKeyStore::new();
        let err = load_agent_identity(&store).unwrap_err();
        assert!(err.to_string().contains("machine.key"));
    }
}
