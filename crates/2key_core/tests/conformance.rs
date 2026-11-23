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
    normalize_api_base_url, ErrorCode, InMemoryStorage, LicensePayload, OfferingCatalog, SdkConfig,
    SystemClock,
    TwoKeyClient, VerifyOutcome,
};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance/fixtures")
}

fn load_fixture_claims() -> Value {
    let path = fixtures_dir().join("license_payload_v4.json");
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

fn read_fixture(name: &str) -> Value {
    let path = fixtures_dir().join(name);
    let raw = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {:?}: {e}", path));
    serde_json::from_str(&raw).expect("fixture json")
}

fn fixture_claims(name: &str) -> Value {
    read_fixture(name).get("claims").cloned().expect("claims")
}

fn str_list(v: &Value) -> Vec<&str> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_str().unwrap())
        .collect()
}

fn case_license(spec: &Value) -> LicensePayload {
    let mut claims = fixture_claims(spec["file"].as_str().unwrap());
    if let Some(only) = spec.get("subscriptions").filter(|v| v.is_array()) {
        let keep = str_list(only);
        let subs: Vec<Value> = claims["subscriptions"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|s| keep.contains(&s["subscription_id"].as_str().unwrap()))
            .cloned()
            .collect();
        claims["subscriptions"] = Value::Array(subs);
    }
    LicensePayload::from_claims(&claims).expect("parse case license")
}

#[test]
fn v4_fixture_claims_parse() {
    let payload =
        LicensePayload::from_claims(&fixture_claims("license_payload_v4.json")).expect("parse v4");
    assert_eq!(payload.payload_version, 4);
    assert_eq!(payload.paying_party.id, "pp_acme_1");
    assert_eq!(payload.using_party.member_id.as_deref(), Some("member-1"));
    assert_eq!(payload.devices.len(), 2);
    assert_eq!(payload.subscriptions.len(), 5);
    let bundle = &payload.subscriptions[1];
    assert_eq!(bundle.plan.code, "pro_bundle");
    assert!(bundle.plan.is_bundle);
    assert_eq!(bundle.offerings["storage"], 4);
    assert_eq!(bundle.resources["disk_space_gb"], 40.0);
}

#[test]
fn payload_versions_other_than_4_are_refused() {
    for version in [1, 3, 5] {
        let mut claims = fixture_claims("license_payload_v4.json");
        claims["payload_version"] = json!(version);
        let err = LicensePayload::from_claims(&claims).expect_err("refused");
        assert!(
            err.message.contains(&format!("payload_version {version}")),
            "{}",
            err.message
        );
    }
}

#[test]
fn device_binding_follows_the_device_list() {
    let payload = LicensePayload::from_claims(&fixture_claims("license_payload_v4.json")).unwrap();
    assert!(payload.allows_local_device("ski-laptop"));
    assert!(!payload.allows_local_device("ski-other"));
    let mut claims = fixture_claims("license_payload_v4.json");
    claims["devices"] = json!([]);
    let unbound = LicensePayload::from_claims(&claims).unwrap();
    assert!(unbound.allows_local_device("any"));
}

#[test]
fn v4_processor_conformance() {
    let doc = read_fixture("license_v4_expected.json");
    let now = doc["now"].as_i64().unwrap();
    let catalog_text =
        fs::read_to_string(fixtures_dir().join(doc["catalogFile"].as_str().unwrap())).unwrap();
    let catalog = OfferingCatalog::parse(&catalog_text).expect("catalog");

    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let licenses: Vec<LicensePayload> = case["licenses"]
            .as_array()
            .unwrap()
            .iter()
            .map(case_license)
            .collect();
        let payload = LicensePayload::merge(&licenses).expect("licenses");
        let narrowed;
        let catalog_ref = match case.get("catalog").filter(|c| !c.is_null()) {
            None => None,
            Some(spec) => match spec["host"].as_str() {
                None => Some(&catalog),
                Some(host) => {
                    narrowed = catalog.for_host(host).expect("host");
                    Some(&narrowed)
                }
            },
        };
        let p = payload.processor(catalog_ref);
        let e = &case["expected"];

        assert_eq!(json!(p.plans(now)), e["plans"], "{name}: plans");
        assert_eq!(json!(p.offerings(now)), e["offerings"], "{name}: offerings");
        let resources = p.resources(now);
        let want_resources = e["resources"].as_object().unwrap();
        assert_eq!(resources.len(), want_resources.len(), "{name}: resources keys");
        for (key, amount) in want_resources {
            assert_eq!(
                resources.get(key).copied(),
                amount.as_f64(),
                "{name}: resources {key}"
            );
        }
        for (code, n) in e["offeringCount"].as_object().unwrap() {
            assert_eq!(
                p.offering_count(code, now),
                n.as_i64().unwrap(),
                "{name}: offeringCount {code}"
            );
        }
        for (key, n) in e["resourceAmount"].as_object().unwrap() {
            assert_eq!(
                p.resource_amount(key, now),
                n.as_f64().unwrap(),
                "{name}: resourceAmount {key}"
            );
        }
        for (code, v) in e["holdsPlan"].as_object().unwrap() {
            assert_eq!(
                p.holds_plan(code, now),
                v.as_bool().unwrap(),
                "{name}: holdsPlan {code}"
            );
        }
        for (code, v) in e["holds"].as_object().unwrap() {
            assert_eq!(p.holds(code, now), v.as_bool().unwrap(), "{name}: holds {code}");
        }
        for (code, ids) in e["sources"].as_object().unwrap() {
            let got: Vec<&str> = p
                .sources(code, now)
                .iter()
                .map(|s| s.subscription_id.as_str())
                .collect();
            assert_eq!(got, str_list(ids), "{name}: sources {code}");
        }
        for (code, unix) in e["expiry"].as_object().unwrap() {
            assert_eq!(
                p.expiry_for(code, now),
                unix.as_i64(),
                "{name}: expiryFor {code}"
            );
        }
        assert_eq!(
            payload.all_subscriptions_ended(now),
            e["allSubscriptionsEnded"].as_bool().unwrap(),
            "{name}: allSubscriptionsEnded"
        );
        if let Some(ids) = e.get("subscriptionIds") {
            assert_eq!(payload.subscription_ids(), str_list(ids), "{name}: subscriptionIds");
        }
        if let Some(skis) = e.get("deviceSkis") {
            let got: Vec<&str> = payload.devices.iter().map(|d| d.ski.as_str()).collect();
            assert_eq!(got, str_list(skis), "{name}: deviceSkis");
        }
        if let Some(id) = e.get("payingPartyId") {
            assert_eq!(payload.paying_party.id, id.as_str().unwrap(), "{name}: payingPartyId");
        }
    }
}

#[test]
fn processor_follows_the_clock() {
    let payload = LicensePayload::from_claims(&fixture_claims("license_payload_v4.json")).unwrap();
    let p = payload.processor(None);
    assert_eq!(p.offering_count("storage", 1_800_000_000), 4);
    assert_eq!(p.offering_count("storage", 4_000_000_000), 0);
    assert_eq!(p.offering_count("base", 4_000_000_000), 3);
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
        VerifyOutcome::Success(p) => assert_eq!(p.paying_party.billing_email, "billing@acme.example"),
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
