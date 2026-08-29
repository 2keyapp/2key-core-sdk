//! Subscription claim.

use serde_json::{Map, Value};

use crate::error::{ErrorCode, Result, TwoKeyError};

fn get_key<'a>(m: &'a Map<String, Value>, snake: &str, camel: &str) -> Option<&'a Value> {
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

/// Offering grant inside a subscription (payload_version >= 3).
#[derive(Debug, Clone, PartialEq)]
pub struct LicenseOfferingClaim {
    /// Offering id.
    pub offering_id: String,
    /// Stable offering code.
    pub offering_code: String,
    /// Product id.
    pub product_id: String,
    /// Optional product name.
    pub product_name: Option<String>,
    /// Units per plan.
    pub units: i64,
    /// Resource map.
    pub resources: Map<String, Value>,
}

impl LicenseOfferingClaim {
    fn from_value(v: &Value) -> Result<Self> {
        let m = v.as_object().ok_or_else(|| {
            TwoKeyError::new(ErrorCode::LicenseMalformed, "offering must be an object")
        })?;
        let offering_id = as_string(get_key(m, "offering_id", "offeringId"))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                TwoKeyError::new(ErrorCode::LicenseMalformed, "offerings[].offering_id required")
            })?;
        let offering_code = as_string(get_key(m, "offering_code", "offeringCode"))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                TwoKeyError::new(ErrorCode::LicenseMalformed, "offerings[].offering_code required")
            })?;
        let product_id = as_string(get_key(m, "product_id", "productId"))
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                TwoKeyError::new(ErrorCode::LicenseMalformed, "offerings[].product_id required")
            })?;
        let resources = match m.get("resources") {
            Some(Value::Object(obj)) => obj.clone(),
            _ => Map::new(),
        };
        Ok(Self {
            offering_id,
            offering_code,
            product_id,
            product_name: as_string(get_key(m, "product_name", "productName")),
            units: as_i64(get_key(m, "units", "units")).unwrap_or(1).max(1),
            resources,
        })
    }

    /// Addon code from resources when present.
    pub fn addon_code(&self) -> Option<String> {
        as_string(self.resources.get("addon_code"))
            .or_else(|| as_string(self.resources.get("addonCode")))
            .filter(|s| !s.is_empty())
    }
}

/// One element of `subscriptions[]` in the license JWT.
#[derive(Debug, Clone, PartialEq)]
pub struct BillingSubscription {
    /// Subscription id.
    pub subscription_id: String,
    /// Plan id.
    pub plan_id: String,
    /// Product id (may be empty when only offerings are present).
    pub product_id: String,
    /// Plan display name.
    pub plan_name: String,
    /// Product display name.
    pub product_name: String,
    /// Purchase quantity (resource multiplier).
    pub quantity: i64,
    /// Raw status string.
    pub subscription_status: String,
    /// Period end (unix).
    pub valid_until_unix: i64,
    /// Period start (unix).
    pub valid_from_unix: Option<i64>,
    /// `monthly` / `quarterly` / `annual`.
    pub billing_interval: Option<String>,
    /// Add-on code metadata.
    pub addon_code: Option<String>,
    /// Using-party membership id.
    pub member_id: Option<String>,
    /// Max active app devices for this seat.
    pub max_devices: Option<i64>,
    /// Offerings (v3).
    pub offerings: Vec<LicenseOfferingClaim>,
    /// Bound device SKIs for this seat.
    pub device_skis: Vec<String>,
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

        let mut offerings = Vec::new();
        if let Some(Value::Array(arr)) = get_key(m, "offerings", "offerings") {
            for item in arr {
                offerings.push(LicenseOfferingClaim::from_value(item)?);
            }
        }

        let mut product_id = as_string(get_key(m, "product_id", "productId")).unwrap_or_default();
        let mut product_name =
            as_string(get_key(m, "product_name", "productName")).unwrap_or_default();
        if product_id.is_empty() {
            if let Some(o) = offerings.first() {
                product_id = o.product_id.clone();
            }
        }
        if product_name.is_empty() {
            if let Some(o) = offerings.first() {
                product_name = o.product_name.clone().unwrap_or_default();
            }
        }
        if product_id.is_empty() {
            return Err(TwoKeyError::new(
                ErrorCode::LicenseMalformed,
                "subscriptions[].product_id required",
            ));
        }
        if product_name.is_empty() && offerings.is_empty() {
            return Err(TwoKeyError::new(
                ErrorCode::LicenseMalformed,
                "subscriptions[].product_name required",
            ));
        }

        let mut device_skis = Vec::new();
        if let Some(Value::Array(arr)) = get_key(m, "devices", "devices") {
            for item in arr {
                if let Some(obj) = item.as_object() {
                    if let Some(ski) = as_string(obj.get("ski")) {
                        if !ski.is_empty() {
                            device_skis.push(ski);
                        }
                    }
                }
            }
        }

        let mut addon_code =
            as_string(get_key(m, "addon_code", "addonCode")).filter(|s| !s.is_empty());
        if addon_code.is_none() {
            for o in &offerings {
                if let Some(a) = o.addon_code() {
                    addon_code = Some(a);
                    break;
                }
            }
        }

        Ok(Self {
            subscription_id: require("subscription_id", "subscriptionId")?,
            plan_id: require("plan_id", "planId")?,
            product_id: product_id.clone(),
            plan_name: require("plan_name", "planName")?,
            product_name: if product_name.is_empty() {
                product_id
            } else {
                product_name
            },
            quantity: as_i64(get_key(m, "quantity", "quantity")).unwrap_or(1).max(1),
            subscription_status: require("subscription_status", "subscriptionStatus")?,
            valid_until_unix,
            valid_from_unix: as_i64(get_key(m, "valid_from", "validFrom")),
            billing_interval: as_string(get_key(m, "billing_interval", "billingInterval"))
                .filter(|s| !s.trim().is_empty()),
            addon_code,
            member_id: as_string(get_key(m, "member_id", "memberId")).filter(|s| !s.is_empty()),
            max_devices: as_i64(get_key(m, "max_devices", "maxDevices")),
            offerings,
            device_skis,
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

    /// True when this seat lists devices and [local_ski] is among them.
    pub fn allows_device(&self, local_ski: &str) -> bool {
        if self.device_skis.is_empty() {
            return true;
        }
        self.device_skis.iter().any(|s| s == local_ski)
    }
}
