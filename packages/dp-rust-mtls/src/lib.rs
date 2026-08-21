//! mTLS helpers for Delegate Permissions agents.
//!
//! AuthN = TLS client certificate (SKI in URI SAN).
//! AuthZ = CapabilityCredential presented in-band over the app session.
//!
//! Enable `rustls-config` to build a full `rustls::ClientConfig` (needs a C toolchain
//! for `ring` on some platforms, e.g. Windows ARM).

use std::io::Cursor;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use dp_rust::CapabilityCredential;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pkcs8::LineEnding;
use rand::rngs::OsRng;
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, PublicKeyData, RemoteKeyPair, SanType, SerialNumber,
    SignatureAlgorithm, PKCS_ED25519,
};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use time::{Duration, OffsetDateTime};

/// Client-held DP identity (keys stay local).
///
/// `cert_pem`/`chain_pem` are optional: when a deployment issues CA-signed
/// mTLS certs (via `sign_client_cert_from_csr`), the issued cert/chain is
/// carried here so `materialize_mtls_client` uses it as-is instead of
/// minting a self-signed dev certificate.
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    pub ski: String,
    /// Ed25519 private JWK (`kty=OKP`, `crv=Ed25519`, `d`, `x`).
    pub private_jwk: serde_json::Value,
    pub credential: CapabilityCredential,
    /// PEM leaf certificate issued by a CA for this device's key, if any.
    pub cert_pem: Option<String>,
    /// PEM chain (leaf + intermediates/CA) for `cert_pem`, if any.
    pub chain_pem: Option<String>,
}

/// PEM cert/key ready for rustls / OpenSSL-style clients.
#[derive(Debug, Clone)]
pub struct MtlsClientMaterial {
    /// Cert presented on the wire: the full chain when `chain_pem` is set, else the leaf alone.
    pub cert_pem: String,
    /// PEM chain (leaf + intermediates/CA), when the identity carries a CA-issued cert.
    pub chain_pem: Option<String>,
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
    let seed: [u8; 32] = bytes.try_into().map_err(|_| MtlsError::BadKeyLength)?;
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

fn key_pair_from_signing_key(signing_key: SigningKey) -> Result<KeyPair, MtlsError> {
    let public = signing_key.verifying_key().to_bytes().to_vec();
    let remote = DalekRemoteKey {
        signing: signing_key,
        public,
    };
    KeyPair::from_remote(Box::new(remote)).map_err(|e| MtlsError::Rcgen(e.to_string()))
}

fn subject_alt_names(ski: &str, host: Option<&str>) -> Result<Vec<SanType>, MtlsError> {
    let uri = ski_san_uri(ski);
    let mut names = vec![SanType::URI(
        uri.try_into()
            .map_err(|e: rcgen::Error| MtlsError::Rcgen(e.to_string()))?,
    )];
    if let Some(host) = host {
        names.push(SanType::DnsName(
            host.to_string()
                .try_into()
                .map_err(|e: rcgen::Error| MtlsError::Rcgen(e.to_string()))?,
        ));
    }
    Ok(names)
}

/// Build a self-signed Ed25519 client cert from DeviceIdentity.
///
/// If `identity.cert_pem` is set (issued by a CA via `sign_client_cert_from_csr`),
/// it is used as-is (chained with `identity.chain_pem` when present). Otherwise
/// a self-signed dev certificate is minted from `identity.private_jwk`.
pub fn materialize_mtls_client(identity: &DeviceIdentity) -> Result<MtlsClientMaterial, MtlsError> {
    let signing_key = signing_key_from_jwk(&identity.private_jwk)?;
    let key_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| MtlsError::Pkcs8(e.to_string()))?
        .to_string();

    if let Some(cert_pem) = &identity.cert_pem {
        return Ok(MtlsClientMaterial {
            cert_pem: identity
                .chain_pem
                .clone()
                .unwrap_or_else(|| cert_pem.clone()),
            chain_pem: identity.chain_pem.clone(),
            key_pem,
            ski: identity.ski.clone(),
            credential: identity.credential.clone(),
        });
    }

    let key_pair = key_pair_from_signing_key(signing_key)?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| MtlsError::Rcgen(e.to_string()))?;
    params.serial_number = Some(SerialNumber::from(1u64));
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, &identity.ski);
    params.distinguished_name = dn;
    params.subject_alt_names = subject_alt_names(&identity.ski, None)?;

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| MtlsError::Rcgen(e.to_string()))?;

    Ok(MtlsClientMaterial {
        cert_pem: cert.pem(),
        chain_pem: None,
        key_pem,
        ski: identity.ski.clone(),
        credential: identity.credential.clone(),
    })
}

// --- CSR generation, CA issuance, and CSR-signing -------------------------
//
// `rcgen`'s CSR *parsing* API (`CertificateSigningRequestParams::from_pem`)
// requires its `x509-parser` feature. To keep this crate's dependency
// footprint minimal (and avoid a heavier ASN.1 parser), CSRs produced by
// `generate_key_and_csr` (here or from `@2key/dp-mtls`) are parsed by hand
// via `parse_ed25519_csr`, which understands exactly the shapes emitted for
// Ed25519 (RFC 2986 / RFC 8410): SEQUENCE { certificationRequestInfo,
// signatureAlgorithm, signature BIT STRING }.

/// Fresh, device-local Ed25519 keypair + PKCS#10 CSR. The private key never
/// leaves this struct; callers should keep `private_jwk` on-device and only
/// ship `csr_pem` to a CA.
#[derive(Debug, Clone)]
pub struct GeneratedKeyAndCsr {
    pub ski: String,
    pub private_jwk: serde_json::Value,
    pub public_jwk: serde_json::Value,
    pub csr_pem: String,
}

/// Self-signed Ed25519 CA (dev/test issuer for `sign_client_cert_from_csr`).
#[derive(Debug, Clone)]
pub struct SelfSignedCa {
    pub ski: String,
    pub private_jwk: serde_json::Value,
    pub public_jwk: serde_json::Value,
    pub ca_cert_pem: String,
    /// Common name the CA was created with; required by `sign_client_cert_from_csr`.
    pub common_name: String,
}

/// Parameters for signing a device CSR into a DP client leaf certificate.
pub struct SignClientCertFromCsrParams<'a> {
    pub csr_pem: &'a str,
    pub ca_cert_pem: &'a str,
    /// CA's Ed25519 private JWK. Never returned; used only to sign in-process.
    pub ca_private_jwk: &'a serde_json::Value,
    /// Must equal `SelfSignedCa::common_name` from when the CA was created.
    /// Used (with `ca_private_jwk`) to re-derive the CA's rcgen `Certificate`
    /// handle in-process instead of parsing `ca_cert_pem` (see module note).
    pub ca_common_name: &'a str,
    /// Subject key id to embed in the issued leaf's SAN (trusted by the CA, not the CSR).
    pub ski: &'a str,
    pub host: Option<&'a str>,
    /// Leaf certificate validity, in days. Default 365.
    pub not_after_days: Option<i64>,
}

/// Issued leaf certificate (+ chain) from `sign_client_cert_from_csr`.
#[derive(Debug, Clone)]
pub struct SignedClientCert {
    pub leaf_pem: String,
    pub chain_pem: String,
}

/// Public key extracted from a CSR (or otherwise known raw Ed25519 point),
/// for use as the `signed_by` subject key without needing a full `KeyPair`.
struct CsrPublicKey {
    raw: Vec<u8>,
}

impl PublicKeyData for CsrPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ED25519
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Legacy 32-hex DP SKI (`sha256({"kty","crv","x"})` truncated).
///
/// Enrollment against the better-auth plugin uses [`jwk_thumbprint_sha256`]
/// (RFC 7638). Do not send this value as `subjectSki`.
pub fn ski_from_public_jwk_parts(kty: &str, crv: &str, x: &str) -> String {
    let material = format!(
        "{{\"kty\":{},\"crv\":{},\"x\":{}}}",
        serde_json::to_string(kty).unwrap_or_default(),
        serde_json::to_string(crv).unwrap_or_default(),
        serde_json::to_string(x).unwrap_or_default(),
    );
    let digest = Sha256::digest(material.as_bytes());
    to_hex(&digest)[..32].to_string()
}

/// RFC 7638 JWK thumbprint (SHA-256, base64url). Matches `jose` `calculateJwkThumbprint`
/// and better-auth `bindCsrToPublicJwk` — this is the canonical enrollment SKI.
pub fn jwk_thumbprint_sha256(public_jwk: &serde_json::Value) -> Result<String, MtlsError> {
    let kty = public_jwk
        .get("kty")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MtlsError::Pem("public JWK missing kty".into()))?;
    let crv = public_jwk
        .get("crv")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MtlsError::Pem("public JWK missing crv".into()))?;
    let x = public_jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or_else(|| MtlsError::Pem("public JWK missing x".into()))?;
    let material = format!(
        "{{\"crv\":{},\"kty\":{},\"x\":{}}}",
        serde_json::to_string(crv).unwrap_or_default(),
        serde_json::to_string(kty).unwrap_or_default(),
        serde_json::to_string(x).unwrap_or_default(),
    );
    let digest = Sha256::digest(material.as_bytes());
    Ok(URL_SAFE_NO_PAD.encode(digest))
}

fn canonical_ski_ed25519(x: &str) -> String {
    jwk_thumbprint_sha256(&serde_json::json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
    }))
    .expect("OKP Ed25519 JWK always has kty/crv/x")
}

fn jwk_pair_from_signing_key(
    signing_key: &SigningKey,
) -> (serde_json::Value, serde_json::Value, String) {
    let d = URL_SAFE_NO_PAD.encode(signing_key.to_bytes());
    let x = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
    let ski = canonical_ski_ed25519(&x);
    let public_jwk = serde_json::json!({
        "kty": "OKP", "crv": "Ed25519", "x": x, "kid": ski, "alg": "EdDSA",
    });
    let private_jwk = serde_json::json!({
        "kty": "OKP", "crv": "Ed25519", "d": d, "x": x, "kid": ski, "alg": "EdDSA",
    });
    (private_jwk, public_jwk, ski)
}

fn base_params(common_name: &str) -> Result<CertificateParams, MtlsError> {
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| MtlsError::Rcgen(e.to_string()))?;
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, common_name);
    params.distinguished_name = dn;
    Ok(params)
}

fn random_serial() -> SerialNumber {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    SerialNumber::from_slice(&bytes)
}

fn ca_params(common_name: &str) -> Result<CertificateParams, MtlsError> {
    let mut params = base_params(common_name)?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.serial_number = Some(random_serial());
    let now = OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + Duration::days(3650);
    Ok(params)
}

/// Ed25519 key material for host SDKs (PEM + JWK). Private key stays on device.
#[derive(Debug, Clone)]
pub struct GeneratedEd25519 {
    pub ski: String,
    pub private_pem: String,
    pub public_pem: String,
    pub public_b64url: String,
    pub public_jwk: serde_json::Value,
    pub private_jwk: serde_json::Value,
}

fn signing_key_from_private_pem(private_pem: &str) -> Result<SigningKey, MtlsError> {
    SigningKey::from_pkcs8_pem(private_pem.trim()).map_err(|e| MtlsError::Pem(e.to_string()))
}

fn pem_pair_from_signing_key(signing_key: &SigningKey) -> Result<(String, String), MtlsError> {
    let private_pem = signing_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| MtlsError::Pkcs8(e.to_string()))?
        .to_string();
    let public_pem = signing_key
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .map_err(|e| MtlsError::Pkcs8(e.to_string()))?;
    Ok((private_pem, public_pem))
}

/// Recover JWK pair + SKI from a PKCS#8 Ed25519 private key PEM.
pub fn jwks_from_private_pem(
    private_pem: &str,
) -> Result<(serde_json::Value, serde_json::Value, String), MtlsError> {
    let signing_key = signing_key_from_private_pem(private_pem)?;
    Ok(jwk_pair_from_signing_key(&signing_key))
}

/// PKCS#8 PEM from an Ed25519 private JWK (`d` / `x`).
pub fn private_pem_from_jwk(private_jwk: &serde_json::Value) -> Result<String, MtlsError> {
    let signing_key = signing_key_from_jwk(private_jwk)?;
    let (private_pem, _public_pem) = pem_pair_from_signing_key(&signing_key)?;
    Ok(private_pem)
}

/// Fresh Ed25519 keypair as PEM + JWK (no CSR).
pub fn generate_ed25519() -> Result<GeneratedEd25519, MtlsError> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let (private_jwk, public_jwk, ski) = jwk_pair_from_signing_key(&signing_key);
    let (private_pem, public_pem) = pem_pair_from_signing_key(&signing_key)?;
    let public_b64url = public_jwk
        .get("x")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(GeneratedEd25519 {
        ski,
        private_pem,
        public_pem,
        public_b64url,
        public_jwk,
        private_jwk,
    })
}

/// Build a PKCS#10 CSR for an existing Ed25519 private key (PKCS#8 PEM).
pub fn build_csr_from_private_pem(private_pem: &str, fqhn: &str) -> Result<String, MtlsError> {
    let signing_key = signing_key_from_private_pem(private_pem)?;
    let (_private_jwk, _public_jwk, ski) = jwk_pair_from_signing_key(&signing_key);
    let key_pair = key_pair_from_signing_key(signing_key)?;
    let host = fqhn.trim();
    let cn = if host.is_empty() { "device" } else { host };

    let mut params = base_params(cn)?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyAgreement,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.subject_alt_names =
        subject_alt_names(&ski, if host.is_empty() { None } else { Some(host) })?;

    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| MtlsError::Rcgen(e.to_string()))?;
    csr.pem().map_err(|e| MtlsError::Rcgen(e.to_string()))
}

/// Ed25519 sign → base64url (no pad) signature.
pub fn sign_message_b64url(private_pem: &str, message: &[u8]) -> Result<String, MtlsError> {
    let signing_key = signing_key_from_private_pem(private_pem)?;
    let sig = signing_key.sign(message);
    Ok(URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// Sign UTF-8 JSON bytes → base64url (no pad).
pub fn sign_json_b64url(private_pem: &str, json: &str) -> Result<String, MtlsError> {
    sign_message_b64url(private_pem, json.as_bytes())
}

/// Compact JWS (RFC 7515) with `alg=EdDSA`, matching `jose` `CompactSign`.
pub fn compact_jws_sign(private_pem: &str, payload: &[u8]) -> Result<String, MtlsError> {
    let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"EdDSA\"}");
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
    let signing_input = format!("{header}.{payload_b64}");
    let sig = sign_message_b64url(private_pem, signing_input.as_bytes())?;
    Ok(format!("{signing_input}.{sig}"))
}

/// Verify a compact EdDSA JWS and check the payload matches `expected_payload`.
pub fn compact_jws_verify(
    public_jwk: &serde_json::Value,
    jws: &str,
    expected_payload: &[u8],
) -> Result<bool, MtlsError> {
    let mut parts = jws.split('.');
    let (Some(header_b64), Some(payload_b64), Some(sig_b64), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(MtlsError::Pem("JWS must have three compact parts".into()));
    };
    let payload = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|e| MtlsError::Base64(e.to_string()))?;
    if payload != expected_payload {
        return Ok(false);
    }
    let _header = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|e| MtlsError::Base64(e.to_string()))?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| MtlsError::Base64(e.to_string()))?;
    let sig_arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| MtlsError::Pem("JWS signature must be 64 bytes".into()))?;
    let verifying = verifying_key_from_public_jwk(public_jwk)?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    Ok(verifying
        .verify(signing_input.as_bytes(), &Signature::from_bytes(&sig_arr))
        .is_ok())
}

fn verifying_key_from_public_jwk(
    public_jwk: &serde_json::Value,
) -> Result<VerifyingKey, MtlsError> {
    let x = public_jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or(MtlsError::MissingPrivateKey)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|e| MtlsError::Base64(e.to_string()))?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| MtlsError::BadKeyLength)?;
    VerifyingKey::from_bytes(&arr).map_err(|e| MtlsError::Rcgen(e.to_string()))
}

/// Canonical SKI (RFC 7638 thumbprint) from raw public key (`x` coordinate, base64url).
pub fn ski_from_public_b64url(public_b64url: &str) -> String {
    canonical_ski_ed25519(public_b64url.trim())
}

/// Generate a device-local Ed25519 keypair and a PKCS#10 CSR for it.
/// The private key never leaves this function's return value.
pub fn generate_key_and_csr(
    common_name: &str,
    host: Option<&str>,
) -> Result<GeneratedKeyAndCsr, MtlsError> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let (private_jwk, public_jwk, ski) = jwk_pair_from_signing_key(&signing_key);
    let key_pair = key_pair_from_signing_key(signing_key)?;

    let mut params = base_params(common_name)?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyAgreement,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.subject_alt_names = subject_alt_names(&ski, host)?;

    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| MtlsError::Rcgen(e.to_string()))?;
    let csr_pem = csr.pem().map_err(|e| MtlsError::Rcgen(e.to_string()))?;

    Ok(GeneratedKeyAndCsr {
        ski,
        private_jwk,
        public_jwk,
        csr_pem,
    })
}

/// Create a self-signed Ed25519 CA (dev/test issuer for `sign_client_cert_from_csr`).
pub fn create_self_signed_ca(common_name: &str) -> Result<SelfSignedCa, MtlsError> {
    let signing_key = SigningKey::generate(&mut OsRng);
    let (private_jwk, public_jwk, ski) = jwk_pair_from_signing_key(&signing_key);
    let key_pair = key_pair_from_signing_key(signing_key)?;

    let cert = ca_params(common_name)?
        .self_signed(&key_pair)
        .map_err(|e| MtlsError::Rcgen(e.to_string()))?;

    Ok(SelfSignedCa {
        ski,
        private_jwk,
        public_jwk,
        ca_cert_pem: cert.pem(),
        common_name: common_name.to_string(),
    })
}

/// Rebuild a self-signed CA cert PEM from an existing Ed25519 private JWK + CN.
/// Used when callers store only the CA JWK (no `ca_cert_pem`) and need a chain.
pub fn ca_cert_pem_from_private_jwk(
    private_jwk: &serde_json::Value,
    common_name: &str,
) -> Result<String, MtlsError> {
    let signing_key = signing_key_from_jwk(private_jwk)?;
    let key_pair = key_pair_from_signing_key(signing_key)?;
    let cert = ca_params(common_name)?
        .self_signed(&key_pair)
        .map_err(|e| MtlsError::Rcgen(e.to_string()))?;
    Ok(cert.pem())
}

/// SKI of the Ed25519 public key embedded in a PKCS#10 CSR.
pub fn ski_from_csr_pem(csr_pem: &str) -> Result<String, MtlsError> {
    let (_tbs, pubkey_raw, _sig) = parse_ed25519_csr(csr_pem)?;
    Ok(ski_from_public_b64url(&URL_SAFE_NO_PAD.encode(pubkey_raw)))
}

/// Public JWK + SKI from a PKCS#10 CSR (key order matches `@2key/dp-mtls`).
pub fn public_jwk_from_csr_pem(csr_pem: &str) -> Result<(serde_json::Value, String), MtlsError> {
    let (_tbs, pubkey_raw, _sig) = parse_ed25519_csr(csr_pem)?;
    let x = URL_SAFE_NO_PAD.encode(pubkey_raw);
    let ski = ski_from_public_b64url(&x);
    let mut jwk = serde_json::Map::new();
    jwk.insert("kty".into(), serde_json::Value::String("OKP".into()));
    jwk.insert("crv".into(), serde_json::Value::String("Ed25519".into()));
    jwk.insert("x".into(), serde_json::Value::String(x));
    jwk.insert("kid".into(), serde_json::Value::String(ski.clone()));
    jwk.insert("alg".into(), serde_json::Value::String("EdDSA".into()));
    Ok((serde_json::Value::Object(jwk), ski))
}

fn pem_to_der(pem: &str, label: &str) -> Result<Vec<u8>, MtlsError> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let start = pem
        .find(&begin)
        .ok_or_else(|| MtlsError::Pem(format!("missing {begin}")))?
        + begin.len();
    let stop = pem[start..]
        .find(&end)
        .ok_or_else(|| MtlsError::Pem(format!("missing {end}")))?
        + start;
    let body: String = pem[start..stop]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    STANDARD
        .decode(body)
        .map_err(|e| MtlsError::Base64(e.to_string()))
}

struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
}

/// Read one DER TLV from `input`, returning it plus the total bytes consumed
/// (header + value).
fn read_tlv(input: &[u8]) -> Result<(Tlv<'_>, usize), MtlsError> {
    if input.len() < 2 {
        return Err(MtlsError::Pem("truncated DER TLV".into()));
    }
    let tag = input[0];
    let mut idx = 1usize;
    let len_byte = input[idx];
    idx += 1;
    let len = if len_byte & 0x80 == 0 {
        len_byte as usize
    } else {
        let n = (len_byte & 0x7f) as usize;
        if n == 0 || n > 4 || input.len() < idx + n {
            return Err(MtlsError::Pem("invalid DER length".into()));
        }
        let mut len = 0usize;
        for b in &input[idx..idx + n] {
            len = (len << 8) | *b as usize;
        }
        idx += n;
        len
    };
    if input.len() < idx + len {
        return Err(MtlsError::Pem("truncated DER value".into()));
    }
    Ok((
        Tlv {
            tag,
            value: &input[idx..idx + len],
        },
        idx + len,
    ))
}

/// SEQUENCE { OBJECT IDENTIFIER 1.3.101.112 } (Ed25519, RFC 8410, no parameters).
const ED25519_SPKI_ALG: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

/// Minimal PKCS#10 CSR parser for Ed25519-only CSRs, avoiding rcgen's
/// `x509-parser` feature. Returns `(certificationRequestInfo DER bytes,
/// raw 32-byte public key, 64-byte signature)`.
fn parse_ed25519_csr(csr_pem: &str) -> Result<(Vec<u8>, [u8; 32], [u8; 64]), MtlsError> {
    let der = pem_to_der(csr_pem, "CERTIFICATE REQUEST")?;

    let (outer, outer_total) = read_tlv(&der)?;
    if outer.tag != 0x30 || outer_total != der.len() {
        return Err(MtlsError::Pem("CSR is not a single DER SEQUENCE".into()));
    }
    let body = outer.value;

    let (cri, cri_total) = read_tlv(body)?;
    if cri.tag != 0x30 {
        return Err(MtlsError::Pem(
            "CSR missing certificationRequestInfo".into(),
        ));
    }
    let cri_bytes = body[..cri_total].to_vec();

    let after_cri = &body[cri_total..];
    let (_sig_alg, sig_alg_total) = read_tlv(after_cri)?;
    let after_sig_alg = &after_cri[sig_alg_total..];
    let (sig_bits, _) = read_tlv(after_sig_alg)?;
    if sig_bits.tag != 0x03 || sig_bits.value.is_empty() || sig_bits.value[0] != 0 {
        return Err(MtlsError::Pem(
            "CSR signature is not a byte-aligned BIT STRING".into(),
        ));
    }
    let sig_bytes = &sig_bits.value[1..];
    if sig_bytes.len() != 64 {
        return Err(MtlsError::Pem(
            "CSR signature must be 64 bytes (Ed25519)".into(),
        ));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(sig_bytes);

    let (_version, v_total) = read_tlv(cri.value)?;
    let after_version = &cri.value[v_total..];
    let (_subject, s_total) = read_tlv(after_version)?;
    let after_subject = &after_version[s_total..];
    let (spki, _) = read_tlv(after_subject)?;
    if spki.tag != 0x30 {
        return Err(MtlsError::Pem("CSR missing subjectPKInfo".into()));
    }
    let (alg, alg_total) = read_tlv(spki.value)?;
    if alg.tag != 0x30 || spki.value[..alg_total] != ED25519_SPKI_ALG {
        return Err(MtlsError::Pem("CSR public key is not Ed25519".into()));
    }
    let after_alg = &spki.value[alg_total..];
    let (pk_bits, _) = read_tlv(after_alg)?;
    if pk_bits.tag != 0x03 || pk_bits.value.is_empty() || pk_bits.value[0] != 0 {
        return Err(MtlsError::Pem(
            "CSR public key is not a byte-aligned BIT STRING".into(),
        ));
    }
    let pk_bytes = &pk_bits.value[1..];
    if pk_bytes.len() != 32 {
        return Err(MtlsError::Pem(
            "CSR public key must be 32 bytes (Ed25519)".into(),
        ));
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(pk_bytes);

    Ok((cri_bytes, public_key, signature))
}

fn parse_ed25519_signed_cert(cert_pem: &str) -> Result<(Vec<u8>, [u8; 64]), MtlsError> {
    let der = pem_to_der(cert_pem, "CERTIFICATE")?;
    let (outer, outer_total) = read_tlv(&der)?;
    if outer.tag != 0x30 || outer_total != der.len() {
        return Err(MtlsError::Pem(
            "certificate is not a single DER SEQUENCE".into(),
        ));
    }
    let body = outer.value;
    let (tbs, tbs_total) = read_tlv(body)?;
    if tbs.tag != 0x30 {
        return Err(MtlsError::Pem("certificate missing tbsCertificate".into()));
    }
    let tbs_bytes = body[..tbs_total].to_vec();
    let after_tbs = &body[tbs_total..];
    let (_sig_alg, sig_alg_total) = read_tlv(after_tbs)?;
    let after_sig_alg = &after_tbs[sig_alg_total..];
    let (sig_bits, _) = read_tlv(after_sig_alg)?;
    if sig_bits.tag != 0x03 || sig_bits.value.is_empty() || sig_bits.value[0] != 0 {
        return Err(MtlsError::Pem(
            "certificate signature is not a byte-aligned BIT STRING".into(),
        ));
    }
    let sig_bytes = &sig_bits.value[1..];
    if sig_bytes.len() != 64 {
        return Err(MtlsError::Pem(
            "certificate signature must be 64 bytes (Ed25519)".into(),
        ));
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(sig_bytes);
    Ok((tbs_bytes, signature))
}

fn ed25519_pubkey_from_cert_pem(cert_pem: &str) -> Result<[u8; 32], MtlsError> {
    let der = pem_to_der(cert_pem, "CERTIFICATE")?;
    let mut search = 0usize;
    while search + ED25519_SPKI_ALG.len() < der.len() {
        let Some(rel) = der[search..]
            .windows(ED25519_SPKI_ALG.len())
            .position(|w| w == ED25519_SPKI_ALG)
        else {
            break;
        };
        let pos = search + rel;
        let after = &der[pos + ED25519_SPKI_ALG.len()..];
        if let Ok((pk_bits, _)) = read_tlv(after) {
            // SPKI key is 32 bytes; the outer signature BIT STRING is 64.
            if pk_bits.tag == 0x03 && pk_bits.value.len() == 33 && pk_bits.value[0] == 0 {
                let mut public_key = [0u8; 32];
                public_key.copy_from_slice(&pk_bits.value[1..]);
                return Ok(public_key);
            }
        }
        search = pos + 1;
    }
    Err(MtlsError::Pem("certificate has no Ed25519 SPKI".into()))
}

/// HAProxy litmus: `cert_pem` verifies as an Ed25519 signature against `issuer_pem`.
///
/// Used for Platform-endorsed leaves against the single Platform Root (`ca-file`).
pub fn verify_ed25519_cert_against_issuer(
    cert_pem: &str,
    issuer_pem: &str,
) -> Result<bool, MtlsError> {
    let (tbs, signature) = parse_ed25519_signed_cert(cert_pem)?;
    let issuer_raw = ed25519_pubkey_from_cert_pem(issuer_pem)?;
    let verifying = VerifyingKey::from_bytes(&issuer_raw)
        .map_err(|e| MtlsError::Rcgen(format!("invalid issuer public key: {e}")))?;
    Ok(verifying
        .verify_strict(&tbs, &Signature::from_bytes(&signature))
        .is_ok())
}

/// Sign a PKCS#10 CSR with a CA private key, producing a DP client leaf cert.
/// The SAN (SKI URI + optional host) is set from trusted `params`, not copied
/// from the CSR, so a compromised/incorrect CSR cannot forge its own identity.
pub fn sign_client_cert_from_csr(
    params: SignClientCertFromCsrParams<'_>,
) -> Result<SignedClientCert, MtlsError> {
    let (tbs, pubkey_raw, signature) = parse_ed25519_csr(params.csr_pem)?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_raw)
        .map_err(|e| MtlsError::Rcgen(format!("invalid CSR public key: {e}")))?;
    verifying_key
        .verify_strict(&tbs, &Signature::from_bytes(&signature))
        .map_err(|_| MtlsError::Rcgen("CSR signature verification failed".into()))?;

    let ca_signing_key = signing_key_from_jwk(params.ca_private_jwk)?;
    let ca_key_pair = key_pair_from_signing_key(ca_signing_key)?;
    let ca_cert = ca_params(params.ca_common_name)?
        .self_signed(&ca_key_pair)
        .map_err(|e| MtlsError::Rcgen(e.to_string()))?;

    let mut leaf_params = base_params(params.ski)?;
    leaf_params.is_ca = IsCa::NoCa;
    leaf_params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyAgreement,
    ];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    leaf_params.subject_alt_names = subject_alt_names(params.ski, params.host)?;
    leaf_params.serial_number = Some(random_serial());
    let now = OffsetDateTime::now_utc();
    leaf_params.not_before = now;
    leaf_params.not_after = now + Duration::days(params.not_after_days.unwrap_or(365));

    let leaf_public_key = CsrPublicKey {
        raw: pubkey_raw.to_vec(),
    };
    let leaf_cert = leaf_params
        .signed_by(&leaf_public_key, &ca_cert, &ca_key_pair)
        .map_err(|e| MtlsError::Rcgen(e.to_string()))?;

    let leaf_pem = leaf_cert.pem();
    let mut chain_pem = leaf_pem.clone();
    if !chain_pem.ends_with('\n') {
        chain_pem.push('\n');
    }
    chain_pem.push_str(params.ca_cert_pem);
    if !chain_pem.ends_with('\n') {
        chain_pem.push('\n');
    }

    Ok(SignedClientCert {
        leaf_pem,
        chain_pem,
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
            cert_pem: None,
            chain_pem: None,
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

    #[test]
    fn generate_key_and_csr_embeds_ski_and_host() {
        let generated = generate_key_and_csr("device-1", Some("db1--acme.example"))
            .expect("generate_key_and_csr");
        assert!(generated.csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
        assert_eq!(generated.ski.len(), 43);
        assert_eq!(
            generated.ski,
            jwk_thumbprint_sha256(&generated.public_jwk).expect("thumbprint")
        );
        assert!(generated.private_jwk.get("d").is_some());
        assert!(generated.public_jwk.get("x").is_some());
    }

    #[test]
    fn create_self_signed_ca_produces_ca_cert() {
        let ca = create_self_signed_ca("DP Test CA").expect("create_self_signed_ca");
        assert!(ca.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(ca.common_name, "DP Test CA");
        assert_eq!(ca.ski.len(), 43);
    }

    #[test]
    fn sign_client_cert_from_csr_issues_leaf_chained_to_ca() {
        let ca = create_self_signed_ca("DP Test CA").expect("create_self_signed_ca");
        let device = generate_key_and_csr("device-2", Some("db1--acme.example"))
            .expect("generate_key_and_csr");

        let signed = sign_client_cert_from_csr(SignClientCertFromCsrParams {
            csr_pem: &device.csr_pem,
            ca_cert_pem: &ca.ca_cert_pem,
            ca_private_jwk: &ca.private_jwk,
            ca_common_name: &ca.common_name,
            ski: &device.ski,
            host: Some("db1--acme.example"),
            not_after_days: None,
        })
        .expect("sign_client_cert_from_csr");

        assert!(signed.leaf_pem.contains("BEGIN CERTIFICATE"));
        assert!(signed.chain_pem.contains(&signed.leaf_pem));
        assert!(signed.chain_pem.contains(ca.ca_cert_pem.trim()));
        assert!(
            verify_ed25519_cert_against_issuer(&signed.leaf_pem, &ca.ca_cert_pem)
                .expect("leaf verifies against Entity CA")
        );
        assert!(
            verify_ed25519_cert_against_issuer(&ca.ca_cert_pem, &ca.ca_cert_pem)
                .expect("CA is self-signed")
        );

        let identity = DeviceIdentity {
            ski: device.ski.clone(),
            private_jwk: device.private_jwk.clone(),
            cert_pem: Some(signed.leaf_pem.clone()),
            chain_pem: Some(signed.chain_pem.clone()),
            credential: CapabilityCredential {
                version: 1,
                kind: CredentialKind::Machine,
                entity_id: "acme.example".into(),
                ski: device.ski.clone(),
                public_jwk: device.public_jwk.clone(),
                permissions: vec![],
                zone: None,
                host: Some("db1--acme.example".into()),
                issuer_ski: ca.ski.clone(),
                not_before: "2026-01-01T00:00:00.000Z".into(),
                not_after: "2027-01-01T00:00:00.000Z".into(),
                package: None,
                platform_cosign: None,
                signature: "hdr.payload.sig".into(),
            },
        };
        let material = materialize_mtls_client(&identity).expect("materialize");
        assert_eq!(material.cert_pem, signed.chain_pem);
        assert_eq!(material.chain_pem, Some(signed.chain_pem.clone()));
    }

    #[test]
    fn sign_client_cert_from_csr_rejects_tampered_csr() {
        let ca = create_self_signed_ca("DP Test CA").expect("create_self_signed_ca");
        let device = generate_key_and_csr("device-3", None).expect("generate_key_and_csr");

        // Flip a byte inside the base64 body (not a BEGIN/END line) so the
        // signature check fails.
        let mut lines: Vec<&str> = device.csr_pem.lines().collect();
        let body_idx = lines
            .iter()
            .position(|line| !line.is_empty() && !line.contains("-----"))
            .expect("CSR PEM has a base64 body line");
        let mut body_bytes = lines[body_idx].as_bytes().to_vec();
        body_bytes[0] = if body_bytes[0] == b'A' { b'B' } else { b'A' };
        let tampered_body = String::from_utf8(body_bytes).unwrap();
        lines[body_idx] = &tampered_body;
        let tampered = lines.join("\n");

        let result = sign_client_cert_from_csr(SignClientCertFromCsrParams {
            csr_pem: &tampered,
            ca_cert_pem: &ca.ca_cert_pem,
            ca_private_jwk: &ca.private_jwk,
            ca_common_name: &ca.common_name,
            ski: "deadbeef",
            host: None,
            not_after_days: None,
        });
        assert!(result.is_err());
    }

    #[test]
    fn jwks_from_private_pem_roundtrips() {
        let gen = generate_ed25519().expect("generate_ed25519");
        let (private_jwk, public_jwk, ski) =
            jwks_from_private_pem(&gen.private_pem).expect("jwks_from_private_pem");
        assert_eq!(ski, gen.ski);
        assert_eq!(private_jwk.get("d"), gen.private_jwk.get("d"));
        assert_eq!(public_jwk.get("x"), gen.public_jwk.get("x"));
    }

    #[test]
    fn compact_jws_roundtrip() {
        let gen = generate_ed25519().expect("generate_ed25519");
        let payload = br#"{"hello":"world"}"#;
        let jws = compact_jws_sign(&gen.private_pem, payload).expect("sign");
        assert_eq!(jws.matches('.').count(), 2);
        assert!(compact_jws_verify(&gen.public_jwk, &jws, payload).expect("verify"));
        assert!(!compact_jws_verify(&gen.public_jwk, &jws, b"other").expect("mismatch"));
    }

    #[test]
    fn public_jwk_from_csr_matches_generated() {
        let device = generate_key_and_csr("device-jwk", Some("db1--acme.com")).expect("csr");
        let (jwk, ski) = public_jwk_from_csr_pem(&device.csr_pem).expect("public_jwk_from_csr");
        assert_eq!(ski, device.ski);
        assert_eq!(jwk.get("x"), device.public_jwk.get("x"));
        let pem = private_pem_from_jwk(&device.private_jwk).expect("pem");
        assert!(pem.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn rfc7638_thumbprint_is_base64url_sha256() {
        let gen = generate_ed25519().expect("generate_ed25519");
        let tp = jwk_thumbprint_sha256(&gen.public_jwk).expect("thumbprint");
        assert_eq!(tp.len(), 43);
        assert!(!tp.contains('='));
        assert_eq!(tp, gen.ski);
        assert_ne!(
            tp,
            ski_from_public_jwk_parts("OKP", "Ed25519", gen.public_jwk["x"].as_str().unwrap())
        );
    }
}
