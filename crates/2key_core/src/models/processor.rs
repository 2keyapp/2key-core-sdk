//! Sums and gates over a verified license (payload v4).
//!
//! The server already multiplied every subscription's grants. This only adds
//! up the live subscriptions: status `active` or `trialing` and `valid_until`
//! after now. Ended subscriptions are not counted; the license stays usable.
//!
//! With a catalog, plan codes, offering codes and resource keys it does not
//! know are dropped (fail closed), and an offering whose
//! `settings.satisfiesOfferings` lists a code counts toward that code in
//! [`LicenseProcessor::offering_count`], [`LicenseProcessor::holds`],
//! [`LicenseProcessor::sources`] and [`LicenseProcessor::expiry_for`].
//!
//! Time comes from the caller on every call (`now_unix`), so a long-running
//! host sees a subscription drop out when it ends.

use std::collections::BTreeMap;

use super::catalog::OfferingCatalog;
use super::payload::LicensePayload;
use super::subscription::BillingSubscription;

/// Sums and gates over one (possibly merged) license.
#[derive(Debug, Clone, Copy)]
pub struct LicenseProcessor<'a> {
    payload: &'a LicensePayload,
    catalog: Option<&'a OfferingCatalog>,
}

impl<'a> LicenseProcessor<'a> {
    /// Process [payload], optionally gated by a host [catalog].
    pub fn new(payload: &'a LicensePayload, catalog: Option<&'a OfferingCatalog>) -> Self {
        Self { payload, catalog }
    }

    /// Subscriptions counted at [now_unix], in license order.
    pub fn live_subscriptions(&self, now_unix: i64) -> Vec<&'a BillingSubscription> {
        self.payload
            .subscriptions
            .iter()
            .filter(|s| s.is_live_at(now_unix))
            .collect()
    }

    /// Plan code -> sum of quantity over live subscriptions.
    pub fn plans(&self, now_unix: i64) -> BTreeMap<String, i64> {
        let mut out = BTreeMap::new();
        for s in self.live_subscriptions(now_unix) {
            if self.knows_plan(&s.plan.code) {
                *out.entry(s.plan.code.clone()).or_insert(0) += s.quantity;
            }
        }
        out
    }

    /// Offering code -> sum of granted units over live subscriptions.
    pub fn offerings(&self, now_unix: i64) -> BTreeMap<String, i64> {
        let mut out = BTreeMap::new();
        for s in self.live_subscriptions(now_unix) {
            for (code, units) in &s.offerings {
                if self.knows_offering(code) {
                    *out.entry(code.clone()).or_insert(0) += units;
                }
            }
        }
        out
    }

    /// Resource key -> sum of granted amount over live subscriptions.
    pub fn resources(&self, now_unix: i64) -> BTreeMap<String, f64> {
        let mut out = BTreeMap::new();
        for s in self.live_subscriptions(now_unix) {
            for (key, amount) in &s.resources {
                if self.knows_resource(key) {
                    *out.entry(key.clone()).or_insert(0.0) += amount;
                }
            }
        }
        out
    }

    /// Units granted for [code], plus units of every offering the catalog
    /// says satisfies it.
    pub fn offering_count(&self, code: &str, now_unix: i64) -> i64 {
        let totals = self.offerings(now_unix);
        self.counting_codes(code)
            .iter()
            .map(|c| totals.get(c).copied().unwrap_or(0))
            .sum()
    }

    /// Sum of granted amount of resource [key] (0 when none).
    pub fn resource_amount(&self, key: &str, now_unix: i64) -> f64 {
        self.resources(now_unix).get(key).copied().unwrap_or(0.0)
    }

    /// A live subscription is on plan [code].
    pub fn holds_plan(&self, code: &str, now_unix: i64) -> bool {
        self.plans(now_unix).get(code).copied().unwrap_or(0) > 0
    }

    /// At least one unit of offering [code] (directly or through a
    /// satisfying offering).
    pub fn holds(&self, code: &str, now_unix: i64) -> bool {
        self.offering_count(code, now_unix) >= 1
    }

    /// Live subscriptions granting [offering_code] (directly or through a
    /// satisfying offering), in license order. Each carries `plan.code` and
    /// `plan.is_bundle`, so a host can tell "through a bundle" from "bought
    /// on its own".
    pub fn sources(&self, offering_code: &str, now_unix: i64) -> Vec<&'a BillingSubscription> {
        let codes = self.counting_codes(offering_code);
        self.live_subscriptions(now_unix)
            .into_iter()
            .filter(|s| {
                codes
                    .iter()
                    .any(|c| self.knows_offering(c) && s.offerings.get(c).copied().unwrap_or(0) > 0)
            })
            .collect()
    }

    /// Latest `valid_until` (unix) among [`sources`](Self::sources) of
    /// [offering_code]; `None` if none.
    pub fn expiry_for(&self, offering_code: &str, now_unix: i64) -> Option<i64> {
        self.sources(offering_code, now_unix)
            .iter()
            .map(|s| s.valid_until_unix)
            .max()
    }

    fn counting_codes(&self, code: &str) -> Vec<String> {
        let mut codes = vec![code.to_string()];
        if let Some(catalog) = self.catalog {
            codes.extend(catalog.satisfied_by(code));
        }
        codes
    }

    fn knows_plan(&self, code: &str) -> bool {
        self.catalog.is_none_or(|c| c.knows_plan(code))
    }

    fn knows_offering(&self, code: &str) -> bool {
        self.catalog.is_none_or(|c| c.knows_offering(code))
    }

    fn knows_resource(&self, key: &str) -> bool {
        self.catalog.is_none_or(|c| c.knows_resource(key))
    }
}

impl LicensePayload {
    /// Sums and gates over this license; see [`LicenseProcessor`].
    pub fn processor<'a>(&'a self, catalog: Option<&'a OfferingCatalog>) -> LicenseProcessor<'a> {
        LicenseProcessor::new(self, catalog)
    }
}
