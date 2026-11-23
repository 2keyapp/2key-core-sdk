//! Host catalog read from the billing catalog export (`billing-seed export`,
//! `exportVersion` 1).
//!
//! A host bundles that JSON at build time (it never fetches it). Passed to
//! [`LicenseProcessor`](super::LicenseProcessor), codes the catalog does not
//! know are dropped (fail closed). [`OfferingCatalog::for_host`] narrows it to
//! one host's surfaces. Only what license processing needs is read: codes,
//! offering settings, resources, plan offerings and host rules.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value};

use crate::error::{ErrorCode, Result, TwoKeyError};

/// The export format version this SDK reads.
pub const SUPPORTED_EXPORT_VERSION: i64 = 1;

fn bad(message: impl Into<String>) -> TwoKeyError {
    TwoKeyError::new(ErrorCode::Config, message)
}

fn object<'a>(v: Option<&'a Value>, label: &str) -> Result<&'a Map<String, Value>> {
    static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
    match v {
        None | Some(Value::Null) => Ok(EMPTY.get_or_init(Map::new)),
        Some(Value::Object(m)) => Ok(m),
        _ => Err(bad(format!("catalog {label} must be an object"))),
    }
}

fn strings(v: Option<&Value>, label: &str) -> Result<Vec<String>> {
    match v {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(arr)) => arr
            .iter()
            .map(|x| {
                x.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| bad(format!("catalog {label} must be an array of strings")))
            })
            .collect(),
        _ => Err(bad(format!("catalog {label} must be an array of strings"))),
    }
}

/// One host rule from the export (`hosts.<key>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogHost {
    /// Surfaces the host sells.
    pub surfaces: Vec<String>,
    /// Platforms the host does not sell on.
    pub exclude_platforms: Vec<String>,
    /// Device platforms the host licenses; `None` means all.
    pub licensed_platforms: Option<Vec<String>>,
}

impl CatalogHost {
    fn from_value(v: &Value, label: &str) -> Result<Self> {
        let m = object(Some(v), label)?;
        Ok(Self {
            surfaces: strings(m.get("surfaces"), &format!("{label}.surfaces"))?,
            exclude_platforms: strings(
                m.get("excludePlatforms"),
                &format!("{label}.excludePlatforms"),
            )?,
            licensed_platforms: match m.get("licensedPlatforms") {
                None | Some(Value::Null) => None,
                other => Some(strings(other, &format!("{label}.licensedPlatforms"))?),
            },
        })
    }

    /// The host sells [offering]: a surface matches and the offering's
    /// platforms are not all excluded.
    pub fn sells(&self, offering: &CatalogOffering) -> bool {
        let surfaces = offering.setting_strings("surfaces");
        if !self.surfaces.iter().any(|s| surfaces.contains(s)) {
            return false;
        }
        let platforms = offering.setting_strings("platforms");
        if self.exclude_platforms.is_empty() || platforms.is_empty() {
            return true;
        }
        !platforms.iter().all(|p| self.exclude_platforms.contains(p))
    }

    /// True when the host licenses devices on [platform].
    pub fn licenses_platform(&self, platform: &str) -> bool {
        self.licensed_platforms
            .as_ref()
            .is_none_or(|list| list.iter().any(|p| p == platform))
    }
}

/// An offering from the export.
#[derive(Debug, Clone, PartialEq)]
pub struct CatalogOffering {
    /// Offering code.
    pub code: String,
    /// Product code.
    pub product_code: String,
    /// Resource key -> amount one unit grants.
    pub resources: BTreeMap<String, f64>,
    /// Offering settings as exported (seed camelCase), including tenant values.
    pub settings: Map<String, Value>,
}

impl CatalogOffering {
    fn setting_strings(&self, key: &str) -> Vec<String> {
        match self.settings.get(key) {
            Some(Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            _ => Vec::new(),
        }
    }

    /// Offering codes this one requires (`settings.requiresOfferings`).
    pub fn requires_offerings(&self) -> Vec<String> {
        self.setting_strings("requiresOfferings")
    }

    /// Offering codes this one also counts as (`settings.satisfiesOfferings`).
    pub fn satisfies_offerings(&self) -> Vec<String> {
        self.setting_strings("satisfiesOfferings")
    }
}

/// A plan from the export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogPlan {
    /// Plan code.
    pub code: String,
    /// Product code.
    pub product_code: String,
    /// Offering code -> units in one plan.
    pub offerings: BTreeMap<String, i64>,
}

/// A resource from the export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogResource {
    /// Resource key.
    pub key: String,
    /// Product code.
    pub product_code: String,
    /// Unit label, e.g. `GB`.
    pub unit: String,
}

/// The host catalog.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct OfferingCatalog {
    /// Host rules by host key.
    pub hosts: BTreeMap<String, CatalogHost>,
    /// Offerings by code (all products).
    pub offerings: BTreeMap<String, CatalogOffering>,
    /// Plans by code (all products).
    pub plans: BTreeMap<String, CatalogPlan>,
    /// Resources by key (all products).
    pub resources: BTreeMap<String, CatalogResource>,
    /// Set when this catalog was narrowed with [`OfferingCatalog::for_host`].
    pub host_key: Option<String>,
}

impl OfferingCatalog {
    /// Parse the export JSON text.
    pub fn parse(json_text: &str) -> Result<Self> {
        let v: Value = serde_json::from_str(json_text)
            .map_err(|e| bad("catalog export is not valid JSON").with_detail(e.to_string()))?;
        Self::from_value(&v)
    }

    /// Parse the decoded export object.
    pub fn from_value(v: &Value) -> Result<Self> {
        let root = object(Some(v), "export")?;
        let version = root.get("exportVersion").and_then(Value::as_i64);
        if version != Some(SUPPORTED_EXPORT_VERSION) {
            return Err(bad(format!(
                "catalog exportVersion {} is not supported; expected {SUPPORTED_EXPORT_VERSION}",
                version.map_or("missing".to_string(), |n| n.to_string())
            )));
        }

        let mut hosts = BTreeMap::new();
        for (key, value) in object(root.get("hosts"), "hosts")? {
            hosts.insert(key.clone(), CatalogHost::from_value(value, &format!("hosts.{key}"))?);
        }

        let mut offerings = BTreeMap::new();
        let mut plans = BTreeMap::new();
        let mut resources = BTreeMap::new();
        for (product_code, raw) in object(root.get("products"), "products")? {
            let product = object(Some(raw), &format!("products.{product_code}"))?;
            for (key, row) in object(product.get("resources"), "resources")? {
                let row = object(Some(row), &format!("resources.{key}"))?;
                resources.entry(key.clone()).or_insert_with(|| CatalogResource {
                    key: key.clone(),
                    product_code: product_code.clone(),
                    unit: row
                        .get("unit")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_string(),
                });
            }
            for (code, row) in object(product.get("offerings"), "offerings")? {
                if offerings.contains_key(code) {
                    continue;
                }
                let row = object(Some(row), &format!("offerings.{code}"))?;
                let mut granted = BTreeMap::new();
                for (key, amount) in object(row.get("resources"), "offerings.resources")? {
                    let n = amount.as_f64().ok_or_else(|| {
                        bad(format!("offerings.{code}.resources.{key} must be a number"))
                    })?;
                    granted.insert(key.clone(), n);
                }
                offerings.insert(
                    code.clone(),
                    CatalogOffering {
                        code: code.clone(),
                        product_code: product_code.clone(),
                        resources: granted,
                        settings: object(row.get("settings"), "offerings.settings")?.clone(),
                    },
                );
            }
            for (code, row) in object(product.get("plans"), "plans")? {
                if plans.contains_key(code) {
                    continue;
                }
                let row = object(Some(row), &format!("plans.{code}"))?;
                let mut units = BTreeMap::new();
                for (offering, n) in object(row.get("offerings"), "plans.offerings")? {
                    let n = n.as_f64().ok_or_else(|| {
                        bad(format!("plans.{code}.offerings.{offering} must be a number"))
                    })?;
                    units.insert(offering.clone(), n as i64);
                }
                plans.insert(
                    code.clone(),
                    CatalogPlan {
                        code: code.clone(),
                        product_code: product_code.clone(),
                        offerings: units,
                    },
                );
            }
        }

        Ok(Self {
            hosts,
            offerings,
            plans,
            resources,
            host_key: None,
        })
    }

    /// This catalog narrowed to the offerings host [key] sells. Plans stay
    /// when any of their offerings stays; resources stay when a kept offering
    /// grants them. Errors for an unknown host.
    pub fn for_host(&self, key: &str) -> Result<Self> {
        let host = self
            .hosts
            .get(key)
            .ok_or_else(|| bad(format!("unknown catalog host {key}")))?;
        let offerings: BTreeMap<_, _> = self
            .offerings
            .iter()
            .filter(|(_, o)| host.sells(o))
            .map(|(c, o)| (c.clone(), o.clone()))
            .collect();
        let plans = self
            .plans
            .iter()
            .filter(|(_, p)| p.offerings.keys().any(|o| offerings.contains_key(o)))
            .map(|(c, p)| (c.clone(), p.clone()))
            .collect();
        let granted: BTreeSet<&String> = offerings.values().flat_map(|o| o.resources.keys()).collect();
        let resources = self
            .resources
            .iter()
            .filter(|(k, _)| granted.contains(k))
            .map(|(k, r)| (k.clone(), r.clone()))
            .collect();
        Ok(Self {
            hosts: self.hosts.clone(),
            offerings,
            plans,
            resources,
            host_key: Some(key.to_string()),
        })
    }

    /// The host rule this catalog was narrowed to, if any.
    pub fn host(&self) -> Option<&CatalogHost> {
        self.host_key.as_ref().and_then(|k| self.hosts.get(k))
    }

    /// The catalog knows offering [code].
    pub fn knows_offering(&self, code: &str) -> bool {
        self.offerings.contains_key(code)
    }

    /// The catalog knows plan [code].
    pub fn knows_plan(&self, code: &str) -> bool {
        self.plans.contains_key(code)
    }

    /// The catalog knows resource [key].
    pub fn knows_resource(&self, key: &str) -> bool {
        self.resources.contains_key(key)
    }

    /// Offering codes [code] requires.
    pub fn required_offerings(&self, code: &str) -> Vec<String> {
        self.offerings
            .get(code)
            .map(CatalogOffering::requires_offerings)
            .unwrap_or_default()
    }

    /// Offering codes whose `satisfiesOfferings` contains [code] (e.g. a
    /// retired offering that still counts as [code]), in code order.
    pub fn satisfied_by(&self, code: &str) -> Vec<String> {
        self.offerings
            .values()
            .filter(|o| o.code != code && o.satisfies_offerings().iter().any(|s| s == code))
            .map(|o| o.code.clone())
            .collect()
    }
}
