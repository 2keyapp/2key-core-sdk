//! mTLS helpers for Delegate Permissions agents.
//!
//! AuthN = TLS client certificate (SKI in URI SAN).
//! AuthZ = CapabilityCredential presented in-band over the app session.
//!
//! Enable `rustls-config` to build a full `rustls::ClientConfig` (needs a C toolchain
//! for `ring` on some platforms, e.g. Windows ARM).

use std::io::Cursor;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use dp_rust::CapabilityCredential;
use ed25519_dalek::pkcs8::EncodePrivateKey;
use ed25519_dalek::{Signer, SigningKey};
use pkcs8::LineEnding;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, RemoteKeyPair, SanType, SerialNumber, SignatureAlgorithm, PKCS_ED25519,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use thiserror::Error;

/// Client-held DP identity (keys stay local).
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    pub ski: String,
    /// Ed25519 private JWK (`kty=OKP`, `crv=Ed25519`, `d`, `x`).
    pub private_jwk: serde_json::Value,
    pub credential: CapabilityCredential,
}

/// PEM cert/key ready for rustls / OpenSSL-style clients.
#[derive(Debug, Clone)]
pub struct MtlsClientMaterial {
    pub cert_pem: String,
    pub key_pem: String,
    pub ski: String,
    pub credential: CapabilityCredential,
}

/// Parsed client auth material for any TLS stack that accepts rustls-pki-types.
#[derive(Debug)]
pub struct LoadedClientAuth {
    pub certs: Vec<CertificateDer<'static>>,
    pub key: PrivateKeyDer<'static>,
}

#[derive(Debug, Error)]
pub enum MtlsError {
    #[error("private JWK missing Ed25519 d parameter")]
    MissingPrivateKey,
    #[error("invalid base64 in JWK: {0}")]
    Base64(String),
    #[error("invalid Ed25519 key length")]
    BadKeyLength,
    #[error("pkcs8 encode failed: {0}")]
    Pkcs8(String),
    #[error("rcgen failed: {0}")]
    Rcgen(String),
    #[error("rustls config failed: {0}")]
    Rustls(String),
    #[error("pem parse failed: {0}")]
    Pem(String),
}

pub fn ski_san_uri(ski: &str) -> String {
    format!("urn:dp:ski:{ski}")
}

fn signing_key_from_jwk(private_jwk: &serde_json::Value) -> Result<SigningKey, MtlsError> {
    let d = private_jwk
        .get("d")
        .and_then(|v| v.as_str())
        .ok_or(MtlsError::MissingPrivateKey)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(d)
        .map_err(|e| MtlsError::Base64(e.to_string()))?;
    let seed: [u8; 32] = bytes
        .try_into()
        .map_err(|_| MtlsError::BadKeyLength)?;
    Ok(SigningKey::from_bytes(&seed))
}

/// Signs via ed25519-dalek so rcgen does not need its `ring` feature.
struct DalekRemoteKey {
    signing: SigningKey,
    public: Vec<u8>,
}

impl RemoteKeyPair for DalekRemoteKey {
    fn public_key(&self) -> &[u8] {
        &self.public
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.signing.sign(msg).to_bytes().to_vec())
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ED25519
    }
}

/// Build a self-signed Ed25519 client cert from DeviceIdentity.
pub fn materialize_mtls_client(
    identity: &DeviceIdentity,
) -> Result<MtlsClientMaterial, MtlsError> {
    let signing_key = signing_key_from_jwk(&identity.private_jwk)?;
    let key_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| MtlsError::Pkcs8(e.to_string()))?
        .to_string();

    let public = signing_key.verifying_key().to_bytes().to_vec();
    let remote = DalekRemoteKey {
        signing: signing_key,
        public,
    };
    let key_pair = KeyPair::from_remote(Box::new(remote))
        .map_err(|e| MtlsError::Rcgen(e.to_string()))?;

    let mut params = CertificateParams::new(vec![identity.ski.clone()])
        .map_err(|e| MtlsError::Rcgen(e.to_string()))?;
    params.serial_number = Some(SerialNumber::from(1u64));
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, &identity.ski);
    params.distinguished_name = dn;

    let uri = ski_san_uri(&identity.ski);
    params.subject_alt_names = vec![SanType::URI(
        uri.try_into()
            .map_err(|e: rcgen::Error| MtlsError::Rcgen(e.to_string()))?,
    )];

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| MtlsError::Rcgen(e.to_string()))?;

    Ok(MtlsClientMaterial {
        cert_pem: cert.pem(),
        key_pem,
        ski: identity.ski.clone(),
        credential: identity.credential.clone(),
    })
}

fn load_certs(pem: &str) -> Result<Vec<CertificateDer<'static>>, MtlsError> {
    let mut reader = Cursor::new(pem.as_bytes());
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| MtlsError::Pem(e.to_string()))
}

fn load_private_key(pem: &str) -> Result<PrivateKeyDer<'static>, MtlsError> {
    let mut reader = Cursor::new(pem.as_bytes());
    let keys: Vec<PrivatePkcs8KeyDer<'static>> = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| MtlsError::Pem(e.to_string()))?;
    let key = keys
        .into_iter()
        .next()
        .ok_or_else(|| MtlsError::Pem("no PKCS8 private key in PEM".into()))?;
    Ok(PrivateKeyDer::Pkcs8(key))
}

/// Parse PEM client cert + key into rustls-pki-types (no native crypto required).
pub fn load_client_auth(material: &MtlsClientMaterial) -> Result<LoadedClientAuth, MtlsError> {
    Ok(LoadedClientAuth {
        certs: load_certs(&material.cert_pem)?,
        key: load_private_key(&material.key_pem)?,
    })
}

/// Load PEM trust roots as DER certificates.
pub fn load_root_certs(root_pems: &[&str]) -> Result<Vec<CertificateDer<'static>>, MtlsError> {
    let mut out = Vec::new();
    for pem in root_pems {
        out.extend(load_certs(pem)?);
    }
    Ok(out)
}

/// Build a rustls client config with optional PEM trust roots and client cert auth.
///
/// Requires the `rustls-config` feature (pulls in `ring`, which needs a C toolchain
/// on some hosts).
#[cfg(feature = "rustls-config")]
pub fn build_rustls_client_config(
    material: &MtlsClientMaterial,
    root_pems: &[&str],
) -> Result<std::sync::Arc<rustls::ClientConfig>, MtlsError> {
    use rustls::{ClientConfig, RootCertStore};

    let mut roots = RootCertStore::empty();
    for cert in load_root_certs(root_pems)? {
        roots
            .add(cert)
            .map_err(|e| MtlsError::Rustls(e.to_string()))?;
    }

    let auth = load_client_auth(material)?;
    let config = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_client_auth_cert(auth.certs, auth.key)
        .map_err(|e| MtlsError::Rustls(e.to_string()))?;

    Ok(std::sync::Arc::new(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use dp_rust::{Capability, CapabilityCredential, CredentialKind};

    fn test_identity() -> DeviceIdentity {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let d = URL_SAFE_NO_PAD.encode(signing.to_bytes());
        let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
        let ski = "testski0123456789abcdef012345".to_string();
        let private_jwk = serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "d": d,
            "x": x,
            "alg": "EdDSA"
        });
        DeviceIdentity {
            ski: ski.clone(),
            private_jwk,
            credential: CapabilityCredential {
                version: 1,
                kind: CredentialKind::Machine,
                entity_id: "acme.example".into(),
                ski: ski.clone(),
                public_jwk: serde_json::json!({"kty":"OKP","crv":"Ed25519","x": x}),
                permissions: vec![Capability {
                    action: "machine.connect".into(),
                    scope: serde_json::json!({"name":"db1"}),
                    delegable: false,
                }],
                zone: None,
                host: Some("db1--acme.example".into()),
                issuer_ski: "issuer".into(),
                not_before: "2026-01-01T00:00:00.000Z".into(),
                not_after: "2027-01-01T00:00:00.000Z".into(),
                package: None,
                platform_cosign: None,
                signature: "hdr.payload.sig".into(),
            },
        }
    }

    #[test]
    fn materialize_embeds_ski_and_loads_client_auth() {
        let identity = test_identity();
        let material = materialize_mtls_client(&identity).expect("materialize");
        assert_eq!(material.ski, identity.ski);
        assert!(material.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(material.key_pem.contains("BEGIN PRIVATE KEY"));
        let auth = load_client_auth(&material).expect("load auth");
        assert!(!auth.certs.is_empty());
        let roots = load_root_certs(&[&material.cert_pem]).expect("roots");
        assert_eq!(roots.len(), 1);
    }
}
