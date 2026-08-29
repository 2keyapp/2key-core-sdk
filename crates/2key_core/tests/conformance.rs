//! Integration-style unit tests + conformance fixture parsing.

use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::{EncodePublicKey, LineEnding};
use rand_core::OsRng;
use serde_json::{json, Value};
use sha2::Digest;
use two_key_core::{
    normalize_api_base_url, ErrorCode, InMemoryStorage, LicensePayload, SdkConfig, SystemClock,
    TwoKeyClient, VerifyOutcome,
};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/fixtures")
}

fn load_fixture_claims() -> Value {
    let path = fixtures_dir().join("license_payload_v1.json");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {:?}: {e}", path));
    let v: Value = serde_json::from_str(&raw).expect("fixture json");
    v.get("claims").cloned().expect("claims")
}

struct FixedClock(i64);
impl two_key_core::Clock for FixedClock {
    fn unix_seconds(&self) -> i64 {
        self.0
    }
}

fn generate_es256_pem_pair() -> (SigningKey, String) {
    let signing = SigningKey::random(&mut OsRng);
    let pub_pem = signing
        .verifying_key()
        .to_public_key_pem(LineEnding::LF)
        .expect("pub pem");
    (signing, pub_pem)
}

fn sign_jwt(signing: &SigningKey, claims: &Value) -> String {
    let header = json!({"alg": "ES256", "typ": "JWT"});
    let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
    let p = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    let signing_input = format!("{h}.{p}");
    let sig: Signature = signing.sign(signing_input.as_bytes());
    let s = URL_SAFE_NO_PAD.encode(sig.to_bytes());
    format!("{signing_input}.{s}")
}

#[test]
fn normalize_strips_suffix() {
    assert_eq!(
        normalize_api_base_url("https://x.example/api/v1"),
        "https://x.example"
    );
}

#[test]
fn fixture_claims_parse() {
    let claims = load_fixture_claims();
    let payload = LicensePayload::from_claims(&claims).expect("parse");
    assert_eq!(payload.payload_version, 1);
    assert_eq!(payload.paying_party.id, "pp_test_1");
    assert_eq!(payload.subscriptions.len(), 2);
    assert!(payload.active_subscriptions().count() >= 1);
    assert!(payload
        .subscriptions
        .iter()
        .any(|s| s.addon_code.as_deref() == Some("ai_assistant")));
}

#[test]
fn fixture_claims_parse_v3_entitlements() {
    let path = fixtures_dir().join("license_payload_v3.json");
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {:?}: {e}", path));
    let v: Value = serde_json::from_str(&raw).expect("fixture json");
    let claims = v.get("claims").cloned().expect("claims");
    let payload = LicensePayload::from_claims(&claims).expect("parse v3");
    assert_eq!(payload.payload_version, 3);
    assert_eq!(payload.subscriptions[0].quantity, 2);
    assert_eq!(payload.max_devices(1_700_000_000), 10);
    assert_eq!(payload.resource_for_product("prod_mail", "max_devices"), 10);
    assert!(payload.has_addon("scomm_connector", 1_700_000_000));
}

#[test]
fn verify_signed_license_es256() {
    let (signing, pub_pem) = generate_es256_pem_pair();
    let mut claims = load_fixture_claims();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    claims["iat"] = json!(now);
    claims["exp"] = json!(now + 3600);

    let token = sign_jwt(&signing, &claims);

    let cfg = SdkConfig {
        api_base_url: "https://billing.example.com".into(),
        public_key_pem: pub_pem,
        storage_prefix: "test_app".into(),
        portal_base_url: None,
        shop_path: "/shop".into(),
        deep_link_scheme: Some("myapp".into()),
        license_poll_interval: std::time::Duration::from_secs(6 * 3600),
    };

    let client = TwoKeyClient::new(cfg, InMemoryStorage::new(), FixedClock(now)).unwrap();
    match client.verify_license(&token) {
        VerifyOutcome::Success(p) => assert_eq!(p.paying_party.billing_email, "billing@example.com"),
        VerifyOutcome::Failure { code, message } => panic!("{code:?}: {message}"),
    }
}

#[test]
fn verify_rejects_wrong_key() {
    let (signing, _) = generate_es256_pem_pair();
    let (_, other_pub) = generate_es256_pem_pair();
    let claims = load_fixture_claims();
    let token = sign_jwt(&signing, &claims);

    let cfg = SdkConfig {
        api_base_url: "https://billing.example.com".into(),
        public_key_pem: other_pub,
        storage_prefix: "test_app".into(),
        portal_base_url: None,
        shop_path: "/shop".into(),
        deep_link_scheme: None,
        license_poll_interval: std::time::Duration::from_secs(6 * 3600),
    };
    let client = TwoKeyClient::new(cfg, InMemoryStorage::new(), SystemClock).unwrap();
    match client.verify_license(&token) {
        VerifyOutcome::Failure { code, .. } => {
            assert!(matches!(
                code,
                ErrorCode::LicenseInvalid | ErrorCode::LicenseMalformed
            ));
        }
        VerifyOutcome::Success(_) => panic!("expected failure"),
    }
}

#[test]
fn session_roundtrip() {
    let (_, pub_pem) = generate_es256_pem_pair();
    let cfg = SdkConfig {
        api_base_url: "https://billing.example.com/api/v1".into(),
        public_key_pem: pub_pem,
        storage_prefix: "billing_test".into(),
        portal_base_url: None,
        shop_path: "/shop".into(),
        deep_link_scheme: None,
        license_poll_interval: std::time::Duration::from_secs(1),
    };
    let client = TwoKeyClient::with_memory(cfg).unwrap();
    let mut session = two_key_core::AccountSession::new("user-1");
    session.access_token = Some("tok".into());
    client.save_session(&session).unwrap();
    let loaded = client.load_session("user-1").unwrap().unwrap();
    assert_eq!(loaded.access_token.as_deref(), Some("tok"));
    client.clear_session("user-1").unwrap();
    assert!(client.load_session("user-1").unwrap().is_none());
}

#[test]
fn config_requires_storage_prefix() {
    let (_, pub_pem) = generate_es256_pem_pair();
    let cfg = SdkConfig {
        api_base_url: "https://billing.example.com".into(),
        public_key_pem: pub_pem,
        storage_prefix: "  ".into(),
        portal_base_url: None,
        shop_path: "/shop".into(),
        deep_link_scheme: None,
        license_poll_interval: std::time::Duration::from_secs(1),
    };
    assert!(TwoKeyClient::with_memory(cfg).is_err());
}

#[test]
fn sha256_smoke() {
    // Keep sha2 linked for future JWS helpers.
    let _ = sha2::Sha256::digest(b"2key");
}
