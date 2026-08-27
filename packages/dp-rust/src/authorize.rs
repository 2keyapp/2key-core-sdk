//! Pure Delegate Permissions AuthZ algebra (mirrors `@2key/dp-authorize`).
//!
//! v2: `path_prefix`, `semver`, and explicit deny (`effect`).

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
    #[serde(default)]
    pub effect: Option<String>,
}

fn effect_of(cap: &Capability) -> &str {
    match cap.effect.as_deref() {
        Some("deny") => "deny",
        _ => "allow",
    }
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

pub fn path_prefix_subset(child: &str, parent: &str) -> bool {
    if parent.is_empty() {
        return true;
    }
    if child == parent {
        return true;
    }
    child.starts_with(&format!("{parent}/"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SemVerFull {
    major: u64,
    minor: u64,
    patch: u64,
    prerelease: Option<String>,
}

#[derive(Debug, Clone)]
struct SemVerInterval {
    lo: SemVerFull,
    hi: Option<SemVerFull>,
    lo_inclusive: bool,
    hi_inclusive: bool,
}

fn parse_exact_version(input: &str) -> Option<SemVerFull> {
    let raw = input.trim();
    let (core, pre) = match raw.split_once('-') {
        Some((c, p)) => (c, Some(p.to_string())),
        None => (raw, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let major = parts[0].parse().ok()?;
    let minor = parts[1].parse().ok()?;
    let patch = parts[2].parse().ok()?;
    // reject leading zeros except 0
    for p in parts {
        if p.len() > 1 && p.starts_with('0') {
            return None;
        }
        if p.is_empty() || !p.chars().all(|c| c.is_ascii_digit()) {
            return None;
        }
    }
    Some(SemVerFull {
        major,
        minor,
        patch,
        prerelease: pre,
    })
}

fn is_exact_version(input: &str) -> bool {
    parse_exact_version(input).is_some()
}

fn cmp_core(a: &SemVerFull, b: &SemVerFull) -> std::cmp::Ordering {
    a.major
        .cmp(&b.major)
        .then(a.minor.cmp(&b.minor))
        .then(a.patch.cmp(&b.patch))
}

fn cmp_semver(a: &SemVerFull, b: &SemVerFull) -> std::cmp::Ordering {
    match cmp_core(a, b) {
        std::cmp::Ordering::Equal => {}
        o => return o,
    }
    match (&a.prerelease, &b.prerelease) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(x), Some(y)) => x.cmp(y),
    }
}

fn ver(major: u64, minor: u64, patch: u64) -> SemVerFull {
    SemVerFull {
        major,
        minor,
        patch,
        prerelease: None,
    }
}

fn bump_major(v: &SemVerFull) -> SemVerFull {
    ver(v.major + 1, 0, 0)
}

fn bump_minor(v: &SemVerFull) -> SemVerFull {
    ver(v.major, v.minor + 1, 0)
}

fn is_closed_point(iv: &SemVerInterval) -> bool {
    iv.hi
        .as_ref()
        .is_some_and(|hi| iv.lo_inclusive && iv.hi_inclusive && cmp_semver(&iv.lo, hi).is_eq())
}

fn parse_range_to_interval(range: &str) -> Option<SemVerInterval> {
    let raw = range.trim();
    if raw.is_empty() {
        return None;
    }

    if let Some(exact) = parse_exact_version(raw) {
        return Some(SemVerInterval {
            lo: exact.clone(),
            hi: Some(exact),
            lo_inclusive: true,
            hi_inclusive: true,
        });
    }

    if let Some(rest) = raw.strip_prefix('^') {
        let lo = parse_exact_version(rest)?;
        if lo.prerelease.is_some() {
            return None;
        }
        let hi = if lo.major == 0 {
            if lo.minor == 0 {
                ver(0, 0, lo.patch + 1)
            } else {
                bump_minor(&lo)
            }
        } else {
            bump_major(&lo)
        };
        return Some(SemVerInterval {
            lo,
            hi: Some(hi),
            lo_inclusive: true,
            hi_inclusive: false,
        });
    }

    if let Some(rest) = raw.strip_prefix('~') {
        let lo = parse_exact_version(rest)?;
        if lo.prerelease.is_some() {
            return None;
        }
        return Some(SemVerInterval {
            lo: lo.clone(),
            hi: Some(bump_minor(&lo)),
            lo_inclusive: true,
            hi_inclusive: false,
        });
    }

    // >=A <B
    if raw.starts_with(">=") {
        let parts: Vec<&str> = raw.split_whitespace().collect();
        if parts.len() == 2 && parts[0].starts_with(">=") && parts[1].starts_with('<') {
            let lo = parse_exact_version(parts[0].trim_start_matches(">="))?;
            let hi = parse_exact_version(parts[1].trim_start_matches('<'))?;
            if lo.prerelease.is_some() || hi.prerelease.is_some() {
                return None;
            }
            return Some(SemVerInterval {
                lo,
                hi: Some(hi),
                lo_inclusive: true,
                hi_inclusive: false,
            });
        }
    }

    // wildcards: 1.x, 1.*, 1.2.x, 1.2.*
    let lower = raw.to_ascii_lowercase();
    let wild_parts: Vec<&str> = lower.split('.').collect();
    if wild_parts.len() >= 1 && wild_parts.len() <= 3 {
        let major: u64 = wild_parts[0].parse().ok()?;
        if wild_parts.len() == 1
            || wild_parts[1] == "x"
            || wild_parts[1] == "*"
        {
            if wild_parts.len() == 1
                || ((wild_parts[1] == "x" || wild_parts[1] == "*")
                    && (wild_parts.len() == 2
                        || wild_parts[2] == "x"
                        || wild_parts[2] == "*"))
            {
                // 1 or 1.x — but "1" alone isn't in our TS WILDCARD which requires at least major
                // TS: `1.x` or `1.*` — major only with optional minor/patch wildcards
            }
        }
        if wild_parts.len() == 2 && (wild_parts[1] == "x" || wild_parts[1] == "*") {
            return Some(SemVerInterval {
                lo: ver(major, 0, 0),
                hi: Some(ver(major + 1, 0, 0)),
                lo_inclusive: true,
                hi_inclusive: false,
            });
        }
        if wild_parts.len() == 3 {
            if wild_parts[1] == "x" || wild_parts[1] == "*" {
                return None; // invalid 1.x.0 style for v1
            }
            let minor: u64 = wild_parts[1].parse().ok()?;
            if wild_parts[2] == "x" || wild_parts[2] == "*" {
                return Some(SemVerInterval {
                    lo: ver(major, minor, 0),
                    hi: Some(ver(major, minor + 1, 0)),
                    lo_inclusive: true,
                    hi_inclusive: false,
                });
            }
        }
    }

    None
}

fn in_interval(v: &SemVerFull, iv: &SemVerInterval) -> bool {
    if v.prerelease.is_some() {
        return is_closed_point(iv) && cmp_semver(v, &iv.lo).is_eq();
    }
    let lo_cmp = cmp_semver(v, &iv.lo);
    if if iv.lo_inclusive {
        lo_cmp.is_lt()
    } else {
        !lo_cmp.is_gt()
    } {
        return false;
    }
    match &iv.hi {
        None => true,
        Some(hi) => {
            let hi_cmp = cmp_semver(v, hi);
            if iv.hi_inclusive {
                !hi_cmp.is_gt()
            } else {
                hi_cmp.is_lt()
            }
        }
    }
}

pub fn semver_satisfies(version: &str, range: &str) -> bool {
    let Some(v) = parse_exact_version(version) else {
        return false;
    };
    let Some(iv) = parse_range_to_interval(range) else {
        return false;
    };
    in_interval(&v, &iv)
}

fn interval_subset(child: &SemVerInterval, parent: &SemVerInterval) -> bool {
    let lo_cmp = cmp_semver(&child.lo, &parent.lo);
    if lo_cmp.is_lt() {
        return false;
    }
    if lo_cmp.is_eq() && child.lo_inclusive && !parent.lo_inclusive {
        return false;
    }
    match &parent.hi {
        None => true,
        Some(p_hi) => match &child.hi {
            None => false,
            Some(c_hi) => {
                let hi_cmp = cmp_semver(c_hi, p_hi);
                if hi_cmp.is_gt() {
                    return false;
                }
                if hi_cmp.is_eq() && child.hi_inclusive && !parent.hi_inclusive {
                    return false;
                }
                true
            }
        },
    }
}

pub fn semver_range_subset(child_range: &str, parent_range: &str) -> bool {
    let Some(child) = parse_range_to_interval(child_range) else {
        return false;
    };
    let Some(parent) = parse_range_to_interval(parent_range) else {
        return false;
    };
    interval_subset(&child, &parent)
}

fn semver_ranges_overlap(a: &str, b: &str) -> bool {
    let Some(ia) = parse_range_to_interval(a) else {
        return false;
    };
    let Some(ib) = parse_range_to_interval(b) else {
        return false;
    };
    if is_closed_point(&ia) {
        return in_interval(&ia.lo, &ib);
    }
    if is_closed_point(&ib) {
        return in_interval(&ib.lo, &ia);
    }
    let a_lo_before_b_hi = match &ib.hi {
        None => true,
        Some(hi) => {
            let c = cmp_semver(&ia.lo, hi);
            c.is_lt() || (c.is_eq() && ia.lo_inclusive && ib.hi_inclusive)
        }
    };
    let b_lo_before_a_hi = match &ia.hi {
        None => true,
        Some(hi) => {
            let c = cmp_semver(&ib.lo, hi);
            c.is_lt() || (c.is_eq() && ib.lo_inclusive && ia.hi_inclusive)
        }
    };
    a_lo_before_b_hi && b_lo_before_a_hi
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
        "path_prefix" => c.len() == 1 && p.len() == 1 && path_prefix_subset(&c[0], &p[0]),
        "set" => {
            let set: HashSet<&str> = p.iter().map(|s| s.as_str()).collect();
            c.iter().all(|m| set.contains(m.as_str()))
        }
        "semver" => {
            if c.is_empty() || p.is_empty() {
                return false;
            }
            if c.len() == 1 && is_exact_version(&c[0]) {
                return p.iter().any(|range| semver_satisfies(&c[0], range));
            }
            c.iter()
                .all(|cr| p.iter().any(|pr| semver_range_subset(cr, pr)))
        }
        _ => false,
    }
}

fn scope_values_overlap(a: &Value, b: &Value, algebra: &str) -> bool {
    let Some(aa) = as_string_list(a) else {
        return false;
    };
    let Some(bb) = as_string_list(b) else {
        return false;
    };
    match algebra {
        "exact" => aa.len() == 1 && bb.len() == 1 && aa[0] == bb[0],
        "dns_prefix" => {
            aa.len() == 1
                && bb.len() == 1
                && (dns_prefix_subset(&aa[0], &bb[0]) || dns_prefix_subset(&bb[0], &aa[0]))
        }
        "path_prefix" => {
            aa.len() == 1
                && bb.len() == 1
                && (path_prefix_subset(&aa[0], &bb[0]) || path_prefix_subset(&bb[0], &aa[0]))
        }
        "set" => {
            let set_b: HashSet<&str> = bb.iter().map(|s| s.as_str()).collect();
            aa.iter().any(|m| set_b.contains(m.as_str()))
        }
        "semver" => aa
            .iter()
            .any(|x| bb.iter().any(|y| semver_ranges_overlap(x, y))),
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

fn scopes_overlap_deny(
    allow_scope: &HashMap<String, Value>,
    deny_scope: &HashMap<String, Value>,
    algebras: &HashMap<&str, &str>,
) -> bool {
    for (dimension, deny_value) in deny_scope {
        let Some(allow_value) = allow_scope.get(dimension) else {
            continue;
        };
        let Some(algebra) = algebras.get(dimension.as_str()).copied() else {
            return false;
        };
        if !scope_values_overlap(allow_value, deny_value, algebra) {
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
        if effect_of(grant) != "deny" {
            continue;
        }
        if !action_covers(&grant.action, action) {
            continue;
        }
        if resource_satisfies_scope(resource, &grant.scope, &algebras) {
            return AuthzOutcome::Denied {
                code: "EXPLICIT_DENY".into(),
            };
        }
    }

    for grant in grants {
        if effect_of(grant) != "allow" {
            continue;
        }
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

fn parent_deny_blocks_allow(
    child: &Capability,
    parent: &[Capability],
    algebras: &HashMap<&str, &str>,
) -> bool {
    for p in parent {
        if effect_of(p) != "deny" {
            continue;
        }
        if !action_covers(&p.action, &child.action) {
            continue;
        }
        if scopes_overlap_deny(&child.scope, &p.scope, algebras) {
            return true;
        }
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

        if effect_of(cap) == "deny" {
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
            continue;
        }

        // allow
        if parent_deny_blocks_allow(cap, parent, &algebras) {
            return AuthzOutcome::Denied {
                code: "DENY_OVERRIDE_VIOLATION".into(),
            };
        }
        let mut covered = false;
        for p in parent {
            if effect_of(p) != "allow" {
                continue;
            }
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
        #[serde(rename = "pathPrefixSubset")]
        path_prefix_subset: Vec<DnsCase>,
        #[serde(rename = "semverSatisfies")]
        semver_satisfies: Vec<SemverSatCase>,
        #[serde(rename = "semverRangeSubset")]
        semver_range_subset: Vec<DnsCase>,
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
    struct SemverSatCase {
        version: String,
        range: String,
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
        for row in &fx.path_prefix_subset {
            assert_eq!(
                path_prefix_subset(&row.child, &row.parent),
                row.ok,
                "{} ⊆ {}",
                row.child,
                row.parent
            );
        }
        for row in &fx.semver_satisfies {
            assert_eq!(
                semver_satisfies(&row.version, &row.range),
                row.ok,
                "{} ∈ {}",
                row.version,
                row.range
            );
        }
        for row in &fx.semver_range_subset {
            assert_eq!(
                semver_range_subset(&row.child, &row.parent),
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
                        assert_eq!(code, expected, "authorize {}", row.action);
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
