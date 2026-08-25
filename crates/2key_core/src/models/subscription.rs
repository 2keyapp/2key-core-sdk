//! Subscription claim.

use serde_json::Value;

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

/// Subscription status helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubscriptionStatus {
    /// Billable active.
    Active,
    /// Trialing.
    Trialing,
    /// Other / inactive.
    Other,
}

impl SubscriptionStatus {
    /// Parse from server string.
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "active" => Self::Active,
            "trialing" => Self::Trialing,
            _ => Self::Other,
        }
    }

    /// Active entitlement.
    pub fn is_entitled(self) -> bool {
        matches!(self, Self::Active | Self::Trialing)
    }
}

/// One element of `subscriptions[]` in the license JWT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BillingSubscription {
    /// Subscription id.
    pub subscription_id: String,
    /// Plan id.
    pub plan_id: String,
    /// Product id.
    pub product_id: String,
    /// Plan display name.
    pub plan_name: String,
    /// Product display name.
    pub product_name: String,
    /// Raw status string.
    pub subscription_status: String,
    /// Period end (unix).
    pub valid_until_unix: i64,
    /// Period start (unix).
    pub valid_from_unix: Option<i64>,
    /// `monthly` / `annual`.
    pub billing_interval: Option<String>,
    /// Add-on code metadata.
    pub addon_code: Option<String>,
    /// Using-party IdP.
    pub using_party_identity_provider: Option<String>,
    /// Using-party subject.
    pub using_party_identity_subject: Option<String>,
    /// Using-party email.
    pub using_party_email: Option<String>,
    /// Assigned user party id.
    pub assigned_user_party_id: Option<String>,
}

impl BillingSubscription {
    /// Parse from JSON object.
    pub fn from_value(v: &Value) -> Result<Self> {
        let m = v.as_object().ok_or_else(|| {
            TwoKeyError::new(ErrorCode::LicenseMalformed, "subscription must be an object")
        })?;

        let require = |snake: &str, camel: &str| -> Result<String> {
            as_string(get_key(m, snake, camel)).ok_or_else(|| {
                TwoKeyError::new(
                    ErrorCode::LicenseMalformed,
                    format!("subscriptions[].{snake} required"),
                )
            })
        };

        let valid_until_unix = as_i64(get_key(m, "valid_until", "validUntil")).ok_or_else(|| {
            TwoKeyError::new(
                ErrorCode::LicenseMalformed,
                "subscriptions[].valid_until required (Unix timestamp)",
            )
        })?;

        Ok(Self {
            subscription_id: require("subscription_id", "subscriptionId")?,
            plan_id: require("plan_id", "planId")?,
            product_id: require("product_id", "productId")?,
            plan_name: require("plan_name", "planName")?,
            product_name: require("product_name", "productName")?,
            subscription_status: require("subscription_status", "subscriptionStatus")?,
            valid_until_unix,
            valid_from_unix: as_i64(get_key(m, "valid_from", "validFrom")),
            billing_interval: as_string(get_key(m, "billing_interval", "billingInterval"))
                .filter(|s| !s.trim().is_empty()),
            addon_code: as_string(get_key(m, "addon_code", "addonCode")).filter(|s| !s.is_empty()),
            using_party_identity_provider: as_string(get_key(
                m,
                "using_party_identity_provider",
                "usingPartyIdentityProvider",
            ))
            .filter(|s| !s.is_empty()),
            using_party_identity_subject: as_string(get_key(
                m,
                "using_party_identity_subject",
                "usingPartyIdentitySubject",
            ))
            .filter(|s| !s.is_empty()),
            using_party_email: as_string(get_key(m, "using_party_email", "usingPartyEmail"))
                .filter(|s| !s.is_empty()),
            assigned_user_party_id: as_string(get_key(
                m,
                "assigned_user_party_id",
                "assignedUserPartyId",
            ))
            .filter(|s| !s.is_empty()),
        })
    }

    /// Active / trialing.
    pub fn is_active(&self) -> bool {
        SubscriptionStatus::parse(&self.subscription_status).is_entitled()
    }
}
