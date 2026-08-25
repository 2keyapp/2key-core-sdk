//! Paying party + top-level license payload.

use serde::Deserialize;
use serde_json::Value;

use super::subscription::BillingSubscription;
use crate::error::{ErrorCode, Result, TwoKeyError};

fn get_key<'a>(m: &'a serde_json::Map<String, Value>, snake: &str, camel: &str) -> Option<&'a Value> {
    m.get(snake).or_else(|| m.get(camel))
}

fn as_string(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn as_i64(v: Option<&Value>) -> Option<i64> {
    match v {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        _ => None,
    }
}

/// Paying party (org) from license JWT `paying_party`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayingParty {
    /// Org id.
    pub id: String,
    /// IdP name.
    pub identity_provider: String,
    /// IdP subject.
    pub identity_subject: String,
    /// Billing email.
    pub billing_email: String,
    /// Optional org display name.
    pub organization_name: Option<String>,
}

impl PayingParty {
    /// Parse from JWT object (snake or camel keys).
    pub fn from_value(v: &Value) -> Result<Self> {
        let m = v.as_object().ok_or_else(|| {
            TwoKeyError::new(ErrorCode::LicenseMalformed, "paying_party object required")
        })?;
        let id = as_string(get_key(m, "id", "id")).filter(|s| !s.is_empty()).ok_or_else(
            || TwoKeyError::new(ErrorCode::LicenseMalformed, "paying_party.id required"),
        )?;
        let billing_email = as_string(get_key(m, "billing_email", "billingEmail")).ok_or_else(
            || {
                TwoKeyError::new(
                    ErrorCode::LicenseMalformed,
                    "paying_party.billing_email required",
                )
            },
        )?;
        let identity_provider = as_string(get_key(m, "identity_provider", "identityProvider"));
        let identity_subject = as_string(get_key(m, "identity_subject", "identitySubject"));
        let sso_legacy = as_string(get_key(m, "sso_id", "ssoId"));

        let (provider, subject) = match (
            identity_provider.filter(|s| !s.is_empty()),
            identity_subject.filter(|s| !s.is_empty()),
            sso_legacy.filter(|s| !s.is_empty()),
        ) {
            (Some(p), Some(s), _) => (p, s),
            (_, _, Some(sso)) => ("legacy".into(), sso),
            _ => {
                return Err(TwoKeyError::new(
                    ErrorCode::LicenseMalformed,
                    "paying_party: identity_provider and identity_subject required (or legacy sso_id)",
                ));
            }
        };

        let organization_name = as_string(get_key(m, "organization_name", "organizationName"));

        Ok(Self {
            id,
            identity_provider: provider,
            identity_subject: subject,
            billing_email,
            organization_name,
        })
    }
}

/// Decoded billing license token payload.
#[derive(Debug, Clone, PartialEq)]
pub struct LicensePayload {
    /// Schema version.
    pub payload_version: i64,
    /// JWT `exp` (unix); default far-future if absent.
    pub expires_at_unix: i64,
    /// JWT `iat` if present.
    pub issued_at_unix: Option<i64>,
    /// JWT `iss`.
    pub issuer: Option<String>,
    /// JWT `aud`.
    pub audience: Option<String>,
    /// Paying party.
    pub paying_party: PayingParty,
    /// Subscriptions.
    pub subscriptions: Vec<BillingSubscription>,
}

impl LicensePayload {
    /// Parse from JWT claims JSON object.
    pub fn from_claims(claims: &Value) -> Result<Self> {
        let m = claims.as_object().ok_or_else(|| {
            TwoKeyError::new(ErrorCode::LicenseMalformed, "Expected JSON object payload")
        })?;

        let payload_version = as_i64(get_key(m, "payload_version", "payloadVersion")).ok_or_else(
            || {
                TwoKeyError::new(
                    ErrorCode::LicenseMalformed,
                    "payload_version (number) required",
                )
            },
        )?;

        let expires_at_unix = as_i64(m.get("exp")).unwrap_or(4_102_444_800); // 2099-12-31 UTC approx
        let issued_at_unix = as_i64(m.get("iat"));
        let issuer = as_string(m.get("iss"));
        let audience = match m.get("aud") {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Array(arr)) => arr
                .first()
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            _ => None,
        };

        let paying_raw = get_key(m, "paying_party", "payingParty").ok_or_else(|| {
            TwoKeyError::new(ErrorCode::LicenseMalformed, "paying_party object required")
        })?;
        let paying_party = PayingParty::from_value(paying_raw)?;

        let subs_raw = m.get("subscriptions").ok_or_else(|| {
            TwoKeyError::new(ErrorCode::LicenseMalformed, "subscriptions array required")
        })?;
        let subs_arr = subs_raw.as_array().ok_or_else(|| {
            TwoKeyError::new(ErrorCode::LicenseMalformed, "subscriptions array required")
        })?;

        let mut subscriptions = Vec::with_capacity(subs_arr.len());
        for (i, item) in subs_arr.iter().enumerate() {
            subscriptions.push(
                BillingSubscription::from_value(item).map_err(|e| {
                    TwoKeyError::new(
                        ErrorCode::LicenseMalformed,
                        format!("subscriptions[{i}]: {}", e.message),
                    )
                })?,
            );
        }

        Ok(Self {
            payload_version,
            expires_at_unix,
            issued_at_unix,
            issuer,
            audience,
            paying_party,
            subscriptions,
        })
    }

    /// Active or trialing subscriptions.
    pub fn active_subscriptions(&self) -> impl Iterator<Item = &BillingSubscription> {
        self.subscriptions.iter().filter(|s| s.is_active())
    }

    /// Whether expired relative to `now_unix`.
    pub fn is_expired(&self, now_unix: i64) -> bool {
        now_unix > self.expires_at_unix
    }
}

/// Helper for serde round-trip of fixture JSON files.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct LicensePayloadFixture {
    /// Raw claims object.
    pub claims: Value,
}
