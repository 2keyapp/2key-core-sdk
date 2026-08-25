//! Minimal HTTP client for license, bootstrap, plans, usage.

use serde_json::Value;

use crate::error::{ErrorCode, Result, TwoKeyError};
use crate::models::Plan;
use crate::url::normalize_api_base_url;

/// Result of `GET /api/v1/license`.
#[derive(Debug, Clone)]
pub enum SyncResult {
    /// New signed token.
    Success {
        /// License JWT.
        signed_token: String,
        /// Response ETag.
        etag: Option<String>,
    },
    /// HTTP 304.
    NotModified {
        /// ETag.
        etag: Option<String>,
    },
}

/// Result of `GET /api/v1/subscriptions/me`.
#[derive(Debug, Clone)]
pub enum BootstrapResult {
    /// Raw JSON data object (host maps to typed stats).
    Success(Value),
}

/// Query for public plans.
#[derive(Debug, Clone, Default)]
pub struct FetchPlansQuery {
    /// Product filter.
    pub product_id: Option<i64>,
    /// Interval filter.
    pub billing_interval: Option<String>,
    /// Include inactive.
    pub include_inactive: bool,
}

/// Body for `POST /api/v1/usage/report`.
#[derive(Debug, Clone)]
pub struct UsageReportRequest {
    /// Meter key.
    pub meter_key: String,
    /// Using party id.
    pub using_party: String,
    /// Paying party id.
    pub paying_party: String,
    /// Idempotency key.
    pub idempotency_key: String,
    /// Reporter type (default relay).
    pub reporter_type: Option<String>,
    /// Optional target FQHN.
    pub target_fqhn: Option<String>,
    /// Bytes to target.
    pub bytes_to_target: Option<serde_json::Value>,
    /// Bytes from target.
    pub bytes_from_target: Option<serde_json::Value>,
    /// Quantity.
    pub quantity: Option<serde_json::Value>,
    /// Reporter id.
    pub reporter_id: Option<String>,
    /// Session id.
    pub session_id: Option<String>,
    /// Dimensions object.
    pub dimensions: Option<serde_json::Value>,
    /// Reported-at timestamp.
    pub reported_at: Option<String>,
}

/// Result of usage report ingest.
#[derive(Debug, Clone)]
pub struct UsageReportResult {
    /// Accepted by server.
    pub accepted: bool,
    /// Duplicate idempotency key.
    pub duplicate: bool,
    /// Remaining balance if returned.
    pub remaining: Option<String>,
    /// Balance generation if returned.
    pub generation: Option<i32>,
    /// Optional actions (e.g. disable_turn).
    pub actions: Vec<String>,
}

/// Blocking HTTP client for SDK routes.
pub struct ApiClient {
    origin: String,
    agent: ureq::Agent,
}

impl ApiClient {
    /// `base_url` is billing origin (normalized).
    pub fn new(base_url: &str) -> Self {
        let origin = normalize_api_base_url(base_url);
        Self {
            origin,
            agent: ureq::Agent::new(),
        }
    }

    fn origin_slash(&self) -> String {
        if self.origin.ends_with('/') {
            self.origin.clone()
        } else {
            format!("{}/", self.origin)
        }
    }

    fn bearer(token: &str) -> String {
        let t = token.trim();
        if t.to_ascii_lowercase().starts_with("bearer ") {
            t.to_string()
        } else {
            format!("Bearer {t}")
        }
    }

    fn read_etag(res: &ureq::Response) -> Option<String> {
        res.header("etag")
            .or_else(|| res.header("ETag"))
            .map(|s| s.to_string())
    }

    /// GET `/api/v1/license`.
    pub fn fetch_license(
        &self,
        authorization_token: &str,
        paying_party_id: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<SyncResult> {
        if authorization_token.trim().is_empty() {
            return Err(TwoKeyError::new(
                ErrorCode::Unauthorized,
                "Authorization token is required.",
            ));
        }

        let url = format!("{}api/v1/license", self.origin_slash());
        let mut req = self
            .agent
            .get(&url)
            .set("Authorization", &Self::bearer(authorization_token));

        if let Some(party) = paying_party_id.map(str::trim).filter(|s| !s.is_empty()) {
            req = req.set("X-Paying-Party-Id", party);
        }
        if let Some(etag) = if_none_match.map(str::trim).filter(|s| !s.is_empty()) {
            let value = if etag.starts_with('"') {
                etag.to_string()
            } else {
                format!("\"{etag}\"")
            };
            req = req.set("If-None-Match", &value);
        }

        let res = req.call().map_err(|e| map_transport(e))?;
        let status = res.status();
        let response_etag = Self::read_etag(&res);

        if status == 304 {
            return Ok(SyncResult::NotModified {
                etag: response_etag.or_else(|| if_none_match.map(|s| s.to_string())),
            });
        }

        if status == 200 {
            let body: Value = res.into_json().map_err(|e| {
                TwoKeyError::new(ErrorCode::InvalidResponse, "Invalid license response JSON")
                    .with_detail(e.to_string())
            })?;
            let data = unwrap_data(&body);
            let signed = data
                .get("signedToken")
                .or_else(|| data.get("signed_token"))
                .or_else(|| data.get("token"))
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty());

            if let Some(signed_token) = signed {
                return Ok(SyncResult::Success {
                    signed_token: signed_token.to_string(),
                    etag: response_etag,
                });
            }
            return Err(TwoKeyError::new(
                ErrorCode::InvalidResponse,
                "Invalid response from billing server. Try again or report this issue.",
            )
            .with_detail("fetch_license: 200 without signedToken"));
        }

        Err(http_status_error(status, "fetch_license"))
    }

    /// GET `/api/v1/subscriptions/me`.
    pub fn ensure_billing_context(&self, authorization_token: &str) -> Result<BootstrapResult> {
        if authorization_token.trim().is_empty() {
            return Err(TwoKeyError::new(
                ErrorCode::Unauthorized,
                "Authorization token is required.",
            ));
        }
        let url = format!("{}api/v1/subscriptions/me", self.origin_slash());
        let res = self
            .agent
            .get(&url)
            .set("Authorization", &Self::bearer(authorization_token))
            .call()
            .map_err(map_transport)?;

        let status = res.status();
        if status == 200 {
            let body: Value = res.into_json().map_err(|e| {
                TwoKeyError::new(ErrorCode::InvalidResponse, "Invalid billing summary response.")
                    .with_detail(e.to_string())
            })?;
            return Ok(BootstrapResult::Success(unwrap_data(&body).clone()));
        }
        Err(http_status_error(status, "ensure_billing_context"))
    }

    /// GET `/api/v1/plans` (public).
    pub fn fetch_plans(&self, query: &FetchPlansQuery) -> Result<Vec<Plan>> {
        let mut url = format!("{}api/v1/plans", self.origin_slash());
        let mut qs = Vec::new();
        if let Some(id) = query.product_id {
            qs.push(format!("productId={id}"));
        }
        if let Some(ref interval) = query.billing_interval {
            qs.push(format!("billingInterval={interval}"));
        }
        if query.include_inactive {
            qs.push("includeInactive=true".into());
        }
        if !qs.is_empty() {
            url.push('?');
            url.push_str(&qs.join("&"));
        }

        let res = self.agent.get(&url).call().map_err(map_transport)?;
        let status = res.status();
        if status != 200 {
            return Err(http_status_error(status, "fetch_plans"));
        }
        let body: Value = res.into_json().map_err(|e| {
            TwoKeyError::new(ErrorCode::InvalidResponse, "Invalid plans response")
                .with_detail(e.to_string())
        })?;

        let list = body
            .get("data")
            .and_then(|d| d.as_array())
            .or_else(|| body.get("items").and_then(|d| d.as_array()))
            .or_else(|| body.as_array())
            .ok_or_else(|| {
                TwoKeyError::new(ErrorCode::InvalidResponse, "plans list missing in response")
            })?;

        list.iter().map(Plan::from_value).collect()
    }

    /// POST `/api/v1/usage/report` (reporter token — not end-user JWT).
    pub fn report_usage(
        &self,
        reporter_token: &str,
        body: &UsageReportRequest,
    ) -> Result<UsageReportResult> {
        if reporter_token.trim().is_empty() {
            return Err(TwoKeyError::new(
                ErrorCode::Unauthorized,
                "Reporter token is required.",
            ));
        }
        let url = format!("{}api/v1/usage/report", self.origin_slash());
        let payload = serde_json::json!({
            "meter_key": body.meter_key,
            "using_party": body.using_party,
            "paying_party": body.paying_party,
            "idempotency_key": body.idempotency_key,
            "reporter_type": body.reporter_type.as_deref().unwrap_or("relay"),
            "target_fqhn": body.target_fqhn,
            "bytes_to_target": body.bytes_to_target,
            "bytes_from_target": body.bytes_from_target,
            "quantity": body.quantity,
            "reporter_id": body.reporter_id,
            "session_id": body.session_id,
            "dimensions": body.dimensions.clone().unwrap_or_else(|| serde_json::json!({})),
            "reported_at": body.reported_at,
        });

        let res = self
            .agent
            .post(&url)
            .set("Authorization", &Self::bearer(reporter_token))
            .set("Content-Type", "application/json")
            .send_json(payload)
            .map_err(map_transport)?;

        let status = res.status();
        if status == 401 || status == 403 {
            return Err(http_status_error(status, "report_usage"));
        }
        if status != 200 {
            return Err(http_status_error(status, "report_usage"));
        }
        let body: Value = res.into_json().map_err(|e| {
            TwoKeyError::new(ErrorCode::InvalidResponse, "Invalid usage report response")
                .with_detail(e.to_string())
        })?;
        let data = unwrap_data(&body);
        Ok(UsageReportResult {
            accepted: data
                .get("accepted")
                .and_then(|v| v.as_bool())
                .unwrap_or(true),
            duplicate: data
                .get("duplicate")
                .and_then(|v| v.as_bool())
                .unwrap_or(false),
            remaining: data
                .get("remaining")
                .and_then(|v| {
                    v.as_str()
                        .map(|s| s.to_string())
                        .or_else(|| v.as_i64().map(|n| n.to_string()))
                }),
            generation: data.get("generation").and_then(|v| {
                v.as_i64()
                    .map(|n| n as i32)
                    .or_else(|| v.as_u64().map(|n| n as i32))
            }),
            actions: data
                .get("actions")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
        })
    }
}

fn unwrap_data(body: &Value) -> &Value {
    body.get("data").unwrap_or(body)
}

fn map_transport(err: ureq::Error) -> TwoKeyError {
    TwoKeyError::new(ErrorCode::Network, "Network error talking to billing server")
        .with_detail(err.to_string())
}

fn http_status_error(status: u16, operation: &str) -> TwoKeyError {
    let code = match status {
        401 | 403 => ErrorCode::Unauthorized,
        _ => ErrorCode::Unknown,
    };
    TwoKeyError::new(
        code,
        format!("Billing request failed (HTTP {status})."),
    )
    .with_detail(format!("{operation} status={status}"))
}
