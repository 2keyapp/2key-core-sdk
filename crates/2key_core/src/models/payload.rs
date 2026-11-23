//! Paying party, using party, devices and the top-level license payload (v4).

use serde::Deserialize;
use serde_json::Value;

use super::subscription::{as_i64, id_string, BillingSubscription};
use crate::error::{ErrorCode, Result, TwoKeyError};

/// The only license payload version this SDK reads.
pub const SUPPORTED_PAYLOAD_VERSION: i64 = 4;

fn malformed(message: impl Into<String>) -> TwoKeyError {
    TwoKeyError::new(ErrorCode::LicenseMalformed, message)
}

fn non_empty_string(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Paying party from the license `paying_party` claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayingParty {
    /// Paying party id.
    pub id: String,
    /// Billing email (empty when absent).
    pub billing_email: String,
    /// Organization display name, when present.
    pub organization_name: Option<String>,
}

impl PayingParty {
    /// Parse from the JWT object.
    pub fn from_value(v: &Value) -> Result<Self> {
        let m = v
            .as_object()
            .ok_or_else(|| malformed("paying_party object required"))?;
        let id = id_string(m.get("id")).ok_or_else(|| malformed("paying_party.id required"))?;
        Ok(Self {
            id,
            billing_email: non_empty_string(m.get("billing_email")).unwrap_or_default(),
            organization_name: non_empty_string(m.get("organization_name")),
        })
    }
}

/// The person the license is for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsingParty {
    /// Identity provider name.
    pub identity_provider: String,
    /// Subject at the provider.
    pub identity_subject: String,
    /// Organization membership this license belongs to; absent on an
    /// identity-wide snapshot.
    pub member_id: Option<String>,
    /// Email, when present.
    pub email: Option<String>,
}

impl UsingParty {
    /// Parse from the JWT object.
    pub fn from_value(v: &Value) -> Result<Self> {
        let m = v
            .as_object()
            .ok_or_else(|| malformed("using_party object required"))?;
        Ok(Self {
            identity_provider: non_empty_string(m.get("identity_provider"))
                .ok_or_else(|| malformed("using_party.identity_provider required"))?,
            identity_subject: non_empty_string(m.get("identity_subject"))
                .ok_or_else(|| malformed("using_party.identity_subject required"))?,
            member_id: id_string(m.get("member_id")),
            email: non_empty_string(m.get("email")),
        })
    }
}

/// A computer the license covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseDevice {
    /// Subject key identifier of the device key.
    pub ski: String,
    /// Device id (empty when absent).
    pub device_id: String,
    /// Platform, when present.
    pub platform: Option<String>,
    /// User-chosen label, when present.
    pub friendly_name: Option<String>,
}

impl LicenseDevice {
    fn from_value(v: &Value) -> Result<Self> {
        let m = v
            .as_object()
            .ok_or_else(|| malformed("devices[] must be an object"))?;
        Ok(Self {
            ski: non_empty_string(m.get("ski")).ok_or_else(|| malformed("devices[].ski required"))?,
            device_id: id_string(m.get("device_id")).unwrap_or_default(),
            platform: non_empty_string(m.get("platform")),
            friendly_name: non_empty_string(m.get("friendly_name"))
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty()),
        })
    }
}

/// Decoded billing license token payload (version 4).
#[derive(Debug, Clone, PartialEq)]
pub struct LicensePayload {
    /// Schema version (always 4).
    pub payload_version: i64,
    /// JWT `exp` (unix); far future when absent.
    pub expires_at_unix: i64,
    /// JWT `iat` if present.
    pub issued_at_unix: Option<i64>,
    /// JWT `iss`.
    pub issuer: Option<String>,
    /// JWT `aud`.
    pub audience: Option<String>,
    /// Paying party.
    pub paying_party: PayingParty,
    /// The person the license is for.
    pub using_party: UsingParty,
    /// Computers the license covers.
    pub devices: Vec<LicenseDevice>,
    /// Subscriptions, in license order.
    pub subscriptions: Vec<BillingSubscription>,
}

impl LicensePayload {
    /// Parse from JWT claims JSON. Refuses any `payload_version` other than 4.
    pub fn from_claims(claims: &Value) -> Result<Self> {
        let m = claims
            .as_object()
            .ok_or_else(|| malformed("Expected JSON object payload"))?;

        let payload_version = as_i64(m.get("payload_version"))
            .ok_or_else(|| malformed("payload_version (number) required"))?;
        if payload_version != SUPPORTED_PAYLOAD_VERSION {
            return Err(malformed(format!(
                "Unsupported license payload_version {payload_version}; this SDK reads version \
                 {SUPPORTED_PAYLOAD_VERSION} only. Get a new license from the billing portal."
            )));
        }

        let paying_party = PayingParty::from_value(
            m.get("paying_party")
                .ok_or_else(|| malformed("paying_party object required"))?,
        )?;
        let using_party = UsingParty::from_value(
            m.get("using_party")
                .ok_or_else(|| malformed("using_party object required"))?,
        )?;

        let devices_raw = m
            .get("devices")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("devices array required"))?;
        let devices = devices_raw
            .iter()
            .map(LicenseDevice::from_value)
            .collect::<Result<Vec<_>>>()?;

        let subs_raw = m
            .get("subscriptions")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed("subscriptions array required"))?;
        let mut subscriptions = Vec::with_capacity(subs_raw.len());
        for (i, item) in subs_raw.iter().enumerate() {
            subscriptions.push(
                BillingSubscription::from_value(item)
                    .map_err(|e| malformed(format!("subscriptions[{i}]: {}", e.message)))?,
            );
        }

        let audience = match m.get("aud") {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Array(arr)) => arr.first().and_then(|v| v.as_str()).map(str::to_string),
            _ => None,
        };

        Ok(Self {
            payload_version,
            expires_at_unix: as_i64(m.get("exp")).unwrap_or(4_102_444_800), // 2100-01-01
            issued_at_unix: as_i64(m.get("iat")),
            issuer: non_empty_string(m.get("iss")),
            audience,
            paying_party,
            using_party,
            devices,
            subscriptions,
        })
    }

    /// One view over several verified licenses for the same device (billing
    /// signs one per organization membership).
    ///
    /// Subscriptions are joined in order and a repeated `subscription_id`
    /// keeps the first. Devices are joined and deduplicated by SKI. The
    /// paying party, using party and issuer fields come from the first
    /// license. Returns `None` for an empty list.
    pub fn merge(payloads: &[LicensePayload]) -> Option<LicensePayload> {
        let first = payloads.first()?;
        if payloads.len() == 1 {
            return Some(first.clone());
        }
        let mut seen_subs = std::collections::HashSet::new();
        let mut seen_skis = std::collections::HashSet::new();
        let subscriptions = payloads
            .iter()
            .flat_map(|p| p.subscriptions.iter())
            .filter(|s| seen_subs.insert(s.subscription_id.clone()))
            .cloned()
            .collect();
        let devices = payloads
            .iter()
            .flat_map(|p| p.devices.iter())
            .filter(|d| seen_skis.insert(d.ski.clone()))
            .cloned()
            .collect();
        Some(LicensePayload {
            subscriptions,
            devices,
            ..first.clone()
        })
    }

    /// Whether expired relative to `now_unix`.
    pub fn is_expired(&self, now_unix: i64) -> bool {
        now_unix > self.expires_at_unix
    }

    /// Subscription ids in license order.
    pub fn subscription_ids(&self) -> Vec<&str> {
        self.subscriptions
            .iter()
            .map(|s| s.subscription_id.as_str())
            .collect()
    }

    /// True when the license has subscriptions and every one has ended at
    /// [now_unix]. A license with at least one subscription not ended is
    /// usable; ended subscriptions are simply not counted.
    pub fn all_subscriptions_ended(&self, now_unix: i64) -> bool {
        !self.subscriptions.is_empty()
            && self.subscriptions.iter().all(|s| s.has_ended_at(now_unix))
    }

    /// True when [ski] is one of the license's devices.
    pub fn lists_ski(&self, ski: &str) -> bool {
        let needle = ski.trim();
        !needle.is_empty() && self.devices.iter().any(|d| d.ski == needle)
    }

    /// True when [local_ski] is listed, or when no device is bound yet.
    pub fn allows_local_device(&self, local_ski: &str) -> bool {
        self.devices.is_empty() || self.lists_ski(local_ski)
    }
}

/// Helper for serde round-trip of fixture JSON files.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct LicensePayloadFixture {
    /// Raw claims object.
    pub claims: Value,
}
