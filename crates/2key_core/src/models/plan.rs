//! Public plan catalog model.

use serde::Deserialize;
use serde_json::Value;

use crate::error::{ErrorCode, Result, TwoKeyError};

/// Public catalog plan from `GET /api/v1/plans`.
#[derive(Debug, Clone, PartialEq)]
pub struct Plan {
    /// Plan id.
    pub id: i64,
    /// Product id.
    pub product_id: i64,
    /// Name.
    pub name: String,
    /// Description.
    pub description: Option<String>,
    /// `monthly` / `annual`.
    pub billing_interval: String,
    /// Base price.
    pub base_price: f64,
    /// Currency code.
    pub currency: String,
    /// Feature strings.
    pub features: Vec<String>,
    /// Optional features JSON object.
    pub features_json: Option<Value>,
    /// Addon code.
    pub addon_code: Option<String>,
    /// Active flag.
    pub is_active: bool,
}

impl Plan {
    /// Parse one plan object.
    pub fn from_value(v: &Value) -> Result<Self> {
        let m = v.as_object().ok_or_else(|| {
            TwoKeyError::new(ErrorCode::InvalidResponse, "plan must be an object")
        })?;

        let parse_i64 = |k: &str, camel: &str| -> i64 {
            m.get(k)
                .or_else(|| m.get(camel))
                .and_then(|x| {
                    x.as_i64()
                        .or_else(|| x.as_f64().map(|f| f as i64))
                        .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
                })
                .unwrap_or(0)
        };

        let name = m
            .get("name")
            .and_then(|x| x.as_str())
            .ok_or_else(|| TwoKeyError::new(ErrorCode::InvalidResponse, "plan.name required"))?
            .to_string();

        let billing_interval = m
            .get("billing_interval")
            .or_else(|| m.get("billingInterval"))
            .and_then(|x| x.as_str())
            .ok_or_else(|| {
                TwoKeyError::new(ErrorCode::InvalidResponse, "plan.billing_interval required")
            })?
            .to_string();

        let base_price = m
            .get("base_price")
            .or_else(|| m.get("basePrice"))
            .and_then(|x| x.as_f64().or_else(|| x.as_i64().map(|i| i as f64)))
            .ok_or_else(|| {
                TwoKeyError::new(ErrorCode::InvalidResponse, "plan.base_price required")
            })?;

        let currency = m
            .get("currency")
            .and_then(|x| x.as_str())
            .ok_or_else(|| TwoKeyError::new(ErrorCode::InvalidResponse, "plan.currency required"))?
            .to_string();

        let features_raw = m.get("features_json").or_else(|| m.get("featuresJson"));
        let mut features: Vec<String> = m
            .get("features")
            .and_then(|x| x.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| e.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let mut features_json = None;
        if let Some(Value::Object(obj)) = features_raw {
            features_json = Some(Value::Object(obj.clone()));
            if features.is_empty() {
                if let Some(Value::Array(nested)) = obj.get("features") {
                    features = nested
                        .iter()
                        .filter_map(|e| e.as_str().map(|s| s.to_string()))
                        .collect();
                }
            }
        } else if let Some(Value::Array(arr)) = features_raw {
            if features.is_empty() {
                features = arr
                    .iter()
                    .filter_map(|e| e.as_str().map(|s| s.to_string()))
                    .collect();
            }
        }

        let addon_code = m
            .get("addon_code")
            .or_else(|| m.get("addonCode"))
            .and_then(|x| x.as_str())
            .map(|s| s.to_string());

        let is_active = m
            .get("is_active")
            .or_else(|| m.get("isActive"))
            .and_then(|x| x.as_bool())
            .unwrap_or(true);

        Ok(Self {
            id: parse_i64("id", "id"),
            product_id: parse_i64("product_id", "productId"),
            name,
            description: m
                .get("description")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
            billing_interval,
            base_price,
            currency,
            features,
            features_json,
            addon_code,
            is_active,
        })
    }
}

/// Wrapper for deserializing fixture lists.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct PlansFixture {
    /// Plans array.
    pub plans: Vec<Value>,
}
