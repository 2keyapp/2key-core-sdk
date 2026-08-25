//! Build-time / runtime configuration (no product-brand defaults).

use crate::error::{ErrorCode, Result, TwoKeyError};
use crate::url::normalize_api_base_url;
use std::time::Duration;

/// Required host configuration for the billing client.
#[derive(Debug, Clone)]
pub struct SdkConfig {
    /// Billing host origin (trailing `/api/v1` stripped if present).
    pub api_base_url: String,
    /// EC public key PEM for license JWT verification (ES256).
    pub public_key_pem: String,
    /// Namespace for persisted session keys (required; host-specific).
    pub storage_prefix: String,
    /// Portal / shop origin; defaults to [Self::api_base_url] when unset.
    pub portal_base_url: Option<String>,
    /// Marketplace path (default `/shop`).
    pub shop_path: String,
    /// Optional deep-link / OAuth scheme for native hosts.
    pub deep_link_scheme: Option<String>,
    /// Background license poll interval (default 6h).
    pub license_poll_interval: Duration,
}

impl SdkConfig {
    /// Validate and normalize.
    pub fn validate(self) -> Result<Self> {
        let api_base_url = normalize_api_base_url(&self.api_base_url);
        if api_base_url.is_empty() {
            return Err(TwoKeyError::new(
                ErrorCode::Config,
                "api_base_url is required",
            ));
        }
        if self.public_key_pem.trim().is_empty() {
            return Err(TwoKeyError::new(
                ErrorCode::Config,
                "public_key_pem is required",
            ));
        }
        if self.storage_prefix.trim().is_empty() {
            return Err(TwoKeyError::new(
                ErrorCode::Config,
                "storage_prefix is required",
            ));
        }
        Ok(Self {
            api_base_url,
            public_key_pem: self.public_key_pem,
            storage_prefix: self.storage_prefix.trim().to_string(),
            portal_base_url: self.portal_base_url,
            shop_path: if self.shop_path.trim().is_empty() {
                "/shop".into()
            } else {
                self.shop_path
            },
            deep_link_scheme: self.deep_link_scheme,
            license_poll_interval: if self.license_poll_interval.is_zero() {
                Duration::from_secs(6 * 3600)
            } else {
                self.license_poll_interval
            },
        })
    }

    /// Resolved portal origin.
    pub fn resolved_portal_base_url(&self) -> &str {
        self.portal_base_url
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(self.api_base_url.as_str())
    }
}
