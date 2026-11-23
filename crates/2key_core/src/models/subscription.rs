//! Subscription claim (license payload v4).
//!
//! The server has already multiplied every grant by the purchased quantity:
//! `offerings` is `code -> quantity x units`, `resources` is
//! `key -> quantity x sum(units x amount)`. Nothing here recomputes them.

use std::collections::BTreeMap;

use serde_json::{Map, Value};

use crate::error::{ErrorCode, Result, TwoKeyError};

fn malformed(message: impl Into<String>) -> TwoKeyError {
    TwoKeyError::new(ErrorCode::LicenseMalformed, message)
}

/// A string, or a number written as its decimal text (ids may be either).
pub(crate) fn id_string(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    }
}

pub(crate) fn as_i64(v: Option<&Value>) -> Option<i64> {
    match v {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        _ => None,
    }
}

/// Product or plan reference with a display name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeName {
    /// Stable catalog code.
    pub code: String,
    /// Display name (the code when the license carries none).
    pub name: String,
}

/// Plan reference with the bundle flag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanClaim {
    /// Stable plan code.
    pub code: String,
    /// Display name.
    pub name: String,
    /// More than one offering: bought as a bundle.
    pub is_bundle: bool,
}

/// One element of `subscriptions[]` in the license JWT.
#[derive(Debug, Clone, PartialEq)]
pub struct BillingSubscription {
    /// Subscription id.
    pub subscription_id: String,
    /// Paying party that pays for it (an organization or the person).
    pub paying_party_id: String,
    /// Product.
    pub product: CodeName,
    /// Plan.
    pub plan: PlanClaim,
    /// Purchased quantity.
    pub quantity: i64,
    /// Raw status string.
    pub status: String,
    /// `monthly` / `quarterly` / `annual`; empty when absent.
    pub billing_interval: String,
    /// Period start (unix seconds).
    pub valid_from_unix: i64,
    /// Period end (unix seconds).
    pub valid_until_unix: i64,
    /// Offering code -> granted units.
    pub offerings: BTreeMap<String, i64>,
    /// Resource key -> granted amount.
    pub resources: BTreeMap<String, f64>,
}

fn code_name(m: &Map<String, Value>, what: &str) -> Result<CodeName> {
    let code = id_string(m.get("code"))
        .ok_or_else(|| malformed(format!("subscriptions[].{what}.code required")))?;
    let name = match m.get("name") {
        Some(Value::String(s)) if !s.is_empty() => s.clone(),
        _ => code.clone(),
    };
    Ok(CodeName { code, name })
}

fn object<'a>(m: &'a Map<String, Value>, key: &str) -> Result<&'a Map<String, Value>> {
    m.get(key)
        .and_then(Value::as_object)
        .ok_or_else(|| malformed(format!("subscriptions[].{key} object required")))
}

impl BillingSubscription {
    /// Parse from a JSON object (snake_case keys, as billing signs them).
    pub fn from_value(v: &Value) -> Result<Self> {
        let m = v
            .as_object()
            .ok_or_else(|| malformed("subscription must be an object"))?;

        let require = |key: &str| -> Result<String> {
            id_string(m.get(key)).ok_or_else(|| malformed(format!("subscriptions[].{key} required")))
        };
        let require_int = |key: &str| -> Result<i64> {
            as_i64(m.get(key))
                .ok_or_else(|| malformed(format!("subscriptions[].{key} required (number)")))
        };

        let product = code_name(object(m, "product")?, "product")?;
        let plan_obj = object(m, "plan")?;
        let plan_base = code_name(plan_obj, "plan")?;
        let plan = PlanClaim {
            code: plan_base.code,
            name: plan_base.name,
            is_bundle: plan_obj.get("is_bundle") == Some(&Value::Bool(true)),
        };

        let mut offerings = BTreeMap::new();
        for (code, value) in object(m, "offerings")? {
            let n = as_i64(Some(value)).ok_or_else(|| {
                malformed(format!("subscriptions[].offerings.{code} must be a number"))
            })?;
            offerings.insert(code.clone(), n);
        }
        let mut resources = BTreeMap::new();
        for (key, value) in object(m, "resources")? {
            let n = value.as_f64().ok_or_else(|| {
                malformed(format!("subscriptions[].resources.{key} must be a number"))
            })?;
            resources.insert(key.clone(), n);
        }

        Ok(Self {
            subscription_id: require("subscription_id")?,
            paying_party_id: require("paying_party_id")?,
            product,
            plan,
            quantity: require_int("quantity")?,
            status: require("status")?,
            billing_interval: id_string(m.get("billing_interval")).unwrap_or_default(),
            valid_from_unix: require_int("valid_from")?,
            valid_until_unix: require_int("valid_until")?,
            offerings,
            resources,
        })
    }

    /// Status `active` or `trialing`.
    pub fn has_active_status(&self) -> bool {
        let s = self.status.to_ascii_lowercase();
        s == "active" || s == "trialing"
    }

    /// The current period has ended at [now_unix] (`valid_until` is not after it).
    pub fn has_ended_at(&self, now_unix: i64) -> bool {
        self.valid_until_unix <= now_unix
    }

    /// Counted at [now_unix]: active or trialing, and not ended.
    pub fn is_live_at(&self, now_unix: i64) -> bool {
        self.has_active_status() && !self.has_ended_at(now_unix)
    }
}
