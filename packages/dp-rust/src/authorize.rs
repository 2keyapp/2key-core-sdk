//! Pure Delegate Permissions AuthZ algebra (mirrors `@2key/dp-authorize`).

use serde::Deserialize;
use serde_json::Value;
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Deserialize)]
pub struct ActionDef {
    pub action: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScopeDimensionDef {
    pub dimension: String,
    pub algebra: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Catalog {
    pub service_id: String,
    pub generation: u64,
    pub actions: Vec<ActionDef>,
    pub scope_dimensions: Vec<ScopeDimensionDef>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Capability {
    pub action: String,
    pub scope: HashMap<String, Value>,
    pub delegable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthzOutcome {
    Ok,
    Denied { code: String },
}

fn as_string_list(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::String(s) => Some(vec![s.clone()]),
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                out.push(v.as_str()?.to_string());
            }
            Some(out)
        }
        _ => None,
    }
}

pub fn action_covers(granted: &str, requested: &str) -> bool {
    if granted == requested {
        return true;
    }
    if let Some(prefix) = granted.strip_suffix(".*") {
        if prefix.is_empty() {
            return false;
        }
        return requested == prefix || requested.starts_with(&format!("{prefix}."));
    }
    false
}

pub fn dns_prefix_subset(child: &str, parent: &str) -> bool {
    if parent.is_empty() {
        return true;
    }
    if child == parent {
        return true;
    }
    child.ends_with(&format!(".{parent}"))
}

fn scope_value_subset(child: &Value, parent: &Value, algebra: &str) -> bool {
    let Some(c) = as_string_list(child) else {
        return false;
    };
    let Some(p) = as_string_list(parent) else {
        return false;
    };
    match algebra {
        "exact" => c.len() == 1 && p.len() == 1 && c[0] == p[0],
        "dns_prefix" => c.len() == 1 && p.len() == 1 && dns_prefix_subset(&c[0], &p[0]),
        "set" => {
            let set: HashSet<&str> = p.iter().map(|s| s.as_str()).collect();
            c.iter().all(|m| set.contains(m.as_str()))
        }
        _ => false,
    }
}

fn algebra_map(catalog: &Catalog) -> HashMap<&str, &str> {
    catalog
        .scope_dimensions
        .iter()
        .map(|d| (d.dimension.as_str(), d.algebra.as_str()))
        .collect()
}

fn resource_satisfies_scope(
    resource: &HashMap<String, Value>,
    grant_scope: &HashMap<String, Value>,
    algebras: &HashMap<&str, &str>,
) -> bool {
    for (dimension, grant_value) in grant_scope {
        let Some(resource_value) = resource.get(dimension) else {
            return false;
        };
        let Some(algebra) = algebras.get(dimension.as_str()).copied() else {
            return false;
        };
        if !scope_value_subset(resource_value, grant_value, algebra) {
            return false;
        }
    }
    true
}

/// Authorize `action` on `resource` against grants (client or server PEP).
pub fn authorize(
    grants: &[Capability],
    action: &str,
    resource: &HashMap<String, Value>,
    catalog: &Catalog,
) -> AuthzOutcome {
    if !catalog.actions.iter().any(|a| a.action == action) {
        return AuthzOutcome::Denied {
            code: "UNKNOWN_ACTION".into(),
        };
    }
    for dimension in resource.keys() {
        if !catalog
            .scope_dimensions
            .iter()
            .any(|d| d.dimension == *dimension)
        {
            return AuthzOutcome::Denied {
                code: "UNKNOWN_SCOPE_DIMENSION".into(),
            };
        }
    }
    let algebras = algebra_map(catalog);
    for grant in grants {
        if !action_covers(&grant.action, action) {
            continue;
        }
        if resource_satisfies_scope(resource, &grant.scope, &algebras) {
            return AuthzOutcome::Ok;
        }
    }
    AuthzOutcome::Denied {
        code: "NOT_AUTHORIZED".into(),
    }
}

fn scope_map_subset(
    child: &HashMap<String, Value>,
    parent: &HashMap<String, Value>,
    algebras: &HashMap<&str, &str>,
) -> bool {
    let mut dims: HashSet<&str> = child.keys().map(|s| s.as_str()).collect();
    dims.extend(parent.keys().map(|s| s.as_str()));
    for dimension in dims {
        let parent_value = parent.get(dimension);
        let child_value = child.get(dimension);
        if parent_value.is_none() {
            continue;
        }
        let Some(child_value) = child_value else {
            return false;
        };
        let Some(algebra) = algebras.get(dimension).copied() else {
            return false;
        };
        if !scope_value_subset(child_value, parent_value.unwrap(), algebra) {
            return false;
        }
    }
    true
}

fn action_known(catalog: &Catalog, action: &str) -> bool {
    if catalog.actions.iter().any(|a| a.action == action) {
        return true;
    }
    if let Some(prefix) = action.strip_suffix(".*") {
        return catalog.actions.iter().any(|a| {
            a.action == prefix || a.action.starts_with(&format!("{prefix}."))
        });
    }
    false
}

/// Assert child CapabilitySet ⊆ parent (attenuation).
pub fn assert_subset(
    child: &[Capability],
    parent: &[Capability],
    catalog: &Catalog,
) -> AuthzOutcome {
    let algebras = algebra_map(catalog);
    for cap in child {
        if !action_known(catalog, &cap.action) {
            return AuthzOutcome::Denied {
                code: "UNKNOWN_ACTION".into(),
            };
        }
        for dimension in cap.scope.keys() {
            if !catalog
                .scope_dimensions
                .iter()
                .any(|d| d.dimension == *dimension)
            {
                return AuthzOutcome::Denied {
                    code: "UNKNOWN_SCOPE_DIMENSION".into(),
                };
            }
        }
        let mut covered = false;
        for p in parent {
            if !p.delegable {
                continue;
            }
            if !action_covers(&p.action, &cap.action) {
                continue;
            }
            if scope_map_subset(&cap.scope, &p.scope, &algebras) {
                covered = true;
                break;
            }
        }
        if !covered {
            return AuthzOutcome::Denied {
                code: "SUBSET_VIOLATION".into(),
            };
        }
    }
    AuthzOutcome::Ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixtures_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../conformance/dp-authz/fixtures.json")
    }

    #[derive(Deserialize)]
    struct Fixtures {
        catalog: Catalog,
        #[serde(rename = "actionCovers")]
        action_covers: Vec<ActionCoverCase>,
        #[serde(rename = "dnsPrefixSubset")]
        dns_prefix_subset: Vec<DnsCase>,
        authorize: Vec<AuthorizeCase>,
        #[serde(rename = "assertSubset")]
        assert_subset: Vec<SubsetCase>,
    }

    #[derive(Deserialize)]
    struct ActionCoverCase {
        granted: String,
        requested: String,
        ok: bool,
    }

    #[derive(Deserialize)]
    struct DnsCase {
        child: String,
        parent: String,
        ok: bool,
    }

    #[derive(Deserialize)]
    struct AuthorizeCase {
        grants: Vec<Capability>,
        action: String,
        resource: HashMap<String, Value>,
        ok: bool,
        code: Option<String>,
    }

    #[derive(Deserialize)]
    struct SubsetCase {
        parent: Vec<Capability>,
        child: Vec<Capability>,
        ok: bool,
        code: Option<String>,
    }

    #[test]
    fn conformance_fixtures() {
        let raw = std::fs::read_to_string(fixtures_path()).expect("fixtures");
        let fx: Fixtures = serde_json::from_str(&raw).expect("parse fixtures");

        for row in &fx.action_covers {
            assert_eq!(
                action_covers(&row.granted, &row.requested),
                row.ok,
                "{} → {}",
                row.granted,
                row.requested
            );
        }
        for row in &fx.dns_prefix_subset {
            assert_eq!(
                dns_prefix_subset(&row.child, &row.parent),
                row.ok,
                "{} ⊆ {}",
                row.child,
                row.parent
            );
        }
        for row in &fx.authorize {
            let outcome = authorize(&row.grants, &row.action, &row.resource, &fx.catalog);
            match (&outcome, row.ok) {
                (AuthzOutcome::Ok, true) => {}
                (AuthzOutcome::Denied { code }, false) => {
                    if let Some(expected) = &row.code {
                        assert_eq!(code, expected);
                    }
                }
                _ => panic!("authorize mismatch: {:?}", row.action),
            }
        }
        for row in &fx.assert_subset {
            let outcome = assert_subset(&row.child, &row.parent, &fx.catalog);
            match (&outcome, row.ok) {
                (AuthzOutcome::Ok, true) => {}
                (AuthzOutcome::Denied { code }, false) => {
                    if let Some(expected) = &row.code {
                        assert_eq!(code, expected);
                    }
                }
                _ => panic!("assert_subset mismatch"),
            }
        }
    }
}
