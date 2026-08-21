//! HTTP client for better-auth `delegate-permissions` endpoints.

use std::sync::Arc;

use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE, COOKIE, USER_AGENT};
use reqwest::{Client, Method, StatusCode};
use rustls::ClientConfig as RustlsClientConfig;
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{Error, Result};
use crate::keystore::{self, KeyStore};
use crate::sdk_version;
use crate::types::*;

const PLUGIN: &str = "delegate-permissions";

pub struct DpClient {
    http: Client,
    base_url: String,
    auth_token: Option<String>,
    extra_headers: HeaderMap,
    user_agent: String,
    client_pem: Option<Vec<u8>>,
}

impl DpClient {
    pub fn new(base_url: &str) -> Self {
        let user_agent = format!("dp-rust-sdk/{sdk_version}", sdk_version = sdk_version());
        let http = build_http(&user_agent, None, None).expect("reqwest client");
        Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            auth_token: None,
            extra_headers: HeaderMap::new(),
            user_agent,
            client_pem: None,
        }
    }

    pub fn with_user_agent(mut self, ua: impl Into<String>) -> Self {
        self.user_agent = ua.into();
        if let Ok(http) = build_http(&self.user_agent, self.client_pem.as_deref(), None) {
            self.http = http;
        }
        self
    }

    pub fn with_auth(mut self, token: &str) -> Self {
        self.auth_token = Some(token.to_string());
        self
    }

    /// Present a client certificate (leaf + key PEM concatenated or separate).
    pub fn with_client_cert(mut self, cert_pem: &str, key_pem: &str) -> Result<Self> {
        let mut pem = String::new();
        pem.push_str(cert_pem.trim());
        pem.push('\n');
        pem.push_str(key_pem.trim());
        pem.push('\n');
        self.client_pem = Some(pem.into_bytes());
        self.rebuild_http()?;
        Ok(self)
    }

    /// Use a preconfigured rustls client config (mTLS + custom roots).
    pub fn with_mtls(mut self, tls_config: RustlsClientConfig) -> Result<Self> {
        self.http = Client::builder()
            .user_agent(&self.user_agent)
            .use_preconfigured_tls(tls_config)
            .build()?;
        Ok(self)
    }

    /// Present the locally stored machine leaf (or chain) + private key.
    pub fn with_stored_mtls(self, store: &impl KeyStore) -> Result<Self> {
        let key = store
            .load_string(keystore::KEY_MACHINE_KEY)?
            .ok_or_else(|| {
                Error::lifecycle("missing identity/machine.key — cannot authenticate with mTLS")
            })?;
        let cert = store
            .load_string(keystore::KEY_CHAIN)?
            .filter(|s| !s.trim().is_empty())
            .or(store.load_string(keystore::KEY_MACHINE_CRT)?)
            .ok_or_else(|| {
                Error::lifecycle("missing identity/machine.crt — enroll or pull first")
            })?;
        self.with_client_cert(&cert, &key)
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    fn rebuild_http(&mut self) -> Result<()> {
        self.http = build_http(&self.user_agent, self.client_pem.as_deref(), None)?;
        Ok(())
    }

    fn url(&self, path: &str) -> String {
        join_url(&self.base_url, path)
    }

    fn plugin_path(&self, name: &str) -> String {
        format!("{PLUGIN}/{name}")
    }

    fn headers(&self) -> Result<HeaderMap> {
        let mut headers = self.extra_headers.clone();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.user_agent)
                .unwrap_or_else(|_| HeaderValue::from_static("dp-rust-sdk")),
        );
        if let Some(token) = &self.auth_token {
            if looks_like_cookie(token) {
                let cookie = token
                    .trim()
                    .strip_prefix("Cookie:")
                    .or_else(|| token.trim().strip_prefix("cookie:"))
                    .unwrap_or(token)
                    .trim();
                headers.insert(
                    COOKIE,
                    HeaderValue::from_str(cookie)
                        .map_err(|e| Error::Message(format!("invalid session cookie: {e}")))?,
                );
            } else {
                let value = if token.contains(' ') {
                    token.clone()
                } else {
                    format!("Bearer {token}")
                };
                headers.insert(
                    AUTHORIZATION,
                    HeaderValue::from_str(&value)
                        .map_err(|e| Error::Message(format!("invalid auth token: {e}")))?,
                );
            }
        }
        Ok(headers)
    }

    pub(crate) async fn request_text<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<(StatusCode, String)> {
        let url = self.url(path);
        let mut req = self.http.request(method, &url).headers(self.headers()?);
        if let Some(body) = body {
            req = req.json(body);
        }
        let res = req.send().await?;
        let status = res.status();
        let text = res.text().await?;
        Ok((status, text))
    }

    async fn send_json<B: Serialize, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&B>,
    ) -> Result<T> {
        let url = self.url(path);
        let mut req = self.http.request(method, &url).headers(self.headers()?);
        if !query.is_empty() {
            req = req.query(query);
        }
        if let Some(body) = body {
            req = req.json(body);
        }
        let res = req.send().await?;
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() {
            return Err(Error::Http {
                status: status.as_u16(),
                body: truncate_body(&text),
            });
        }
        if text.trim().is_empty() {
            return serde_json::from_str("null")
                .map_err(|_| Error::Message(format!("empty response from {url} ({status})")));
        }
        serde_json::from_str(&text)
            .map_err(|e| Error::Message(format!("JSON from {url}: {e}: {text}")))
    }

    async fn send_unit<B: Serialize>(
        &self,
        method: Method,
        path: &str,
        query: &[(&str, &str)],
        body: Option<&B>,
    ) -> Result<()> {
        let url = self.url(path);
        let mut req = self
            .http
            .request(method.clone(), &url)
            .headers(self.headers()?);
        if !query.is_empty() {
            req = req.query(query);
        }
        if let Some(body) = body {
            req = req.json(body);
        }
        let res = req.send().await?;
        let status = res.status();
        let text = res.text().await?;
        if !status.is_success() && status != StatusCode::NO_CONTENT {
            return Err(Error::Http {
                status: status.as_u16(),
                body: truncate_body(&text),
            });
        }
        Ok(())
    }

    // --- Entity -----------------------------------------------------------

    pub async fn kickstart_entity(&self, req: &KickstartRequest) -> Result<KickstartResponse> {
        self.send_json(
            Method::POST,
            &self.plugin_path("kickstart-entity"),
            &[],
            Some(req),
        )
        .await
    }

    pub async fn get_entity(&self, entity_id: &str) -> Result<EntityResponse> {
        self.send_json(
            Method::GET,
            &self.plugin_path("entity"),
            &[("entityId", entity_id)],
            None::<&()>,
        )
        .await
    }

    // --- Enrollment -------------------------------------------------------

    pub async fn enroll_create(&self, req: &EnrollCreateRequest) -> Result<EnrollCreateResponse> {
        self.send_json(
            Method::POST,
            &self.plugin_path("enroll-create"),
            &[],
            Some(req),
        )
        .await
    }

    pub async fn enroll_invite(&self, req: &EnrollInviteRequest) -> Result<EnrollInviteResponse> {
        self.send_json(
            Method::POST,
            &self.plugin_path("enroll-invite"),
            &[],
            Some(req),
        )
        .await
    }

    pub async fn get_enroll_invite(&self, invite_token: &str) -> Result<EnrollInviteResponse> {
        self.send_json(
            Method::GET,
            &self.plugin_path("enroll-invite"),
            &[("inviteToken", invite_token)],
            None::<&()>,
        )
        .await
    }

    pub async fn enroll_instant(
        &self,
        req: &EnrollInstantRequest,
    ) -> Result<EnrollInstantResponse> {
        self.send_json(
            Method::POST,
            &self.plugin_path("enroll-instant"),
            &[],
            Some(req),
        )
        .await
    }

    pub async fn seed_catalog(&self) -> Result<serde_json::Value> {
        self.send_json(
            Method::POST,
            &self.plugin_path("seed-catalog"),
            &[],
            Some(&serde_json::json!({})),
        )
        .await
    }

    pub async fn enroll_pull(&self, pull_token: &str) -> Result<EnrollPullResponse> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            pull_token: &'a str,
        }
        self.send_json(
            Method::POST,
            &self.plugin_path("enroll-pull"),
            &[],
            Some(&Body { pull_token }),
        )
        .await
    }

    pub async fn enroll_approve(
        &self,
        req: &EnrollApproveRequest,
    ) -> Result<EnrollApproveResponse> {
        self.send_json(
            Method::POST,
            &self.plugin_path("enroll-approve"),
            &[],
            Some(req),
        )
        .await
    }

    pub async fn enroll_reject(&self, enroll_id: &str) -> Result<()> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            enroll_id: &'a str,
        }
        self.send_unit(
            Method::POST,
            &self.plugin_path("enroll-reject"),
            &[],
            Some(&Body { enroll_id }),
        )
        .await
    }

    pub async fn enroll_list(
        &self,
        entity_id: &str,
        status: Option<&str>,
    ) -> Result<Vec<EnrollListItem>> {
        let status = status.filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all"));
        let mut query = vec![("entityId", entity_id)];
        if let Some(status) = status {
            query.push(("status", status));
        }
        let value: serde_json::Value = self
            .send_json(
                Method::GET,
                &self.plugin_path("enroll-list"),
                &query,
                None::<&()>,
            )
            .await?;
        parse_named_list(value, &["enrollments", "items", "requests", "data"])
    }

    pub async fn enroll_get(&self, enroll_id: &str) -> Result<EnrollListItem> {
        let value: serde_json::Value = self
            .send_json(
                Method::GET,
                &self.plugin_path("enroll-get"),
                &[("enrollId", enroll_id)],
                None::<&()>,
            )
            .await?;
        parse_enroll_item(value)
    }

    pub async fn enroll_machine_permissions(
        &self,
        req: &MachinePermissionsRequest,
    ) -> Result<MachinePermissionsResponse> {
        self.send_json(
            Method::POST,
            &self.plugin_path("enroll-machine-permissions"),
            &[],
            Some(req),
        )
        .await
    }

    // --- Lifecycle --------------------------------------------------------

    pub async fn credential_status(&self, ski: &str) -> Result<CredentialStatusResponse> {
        self.send_json(
            Method::GET,
            &self.plugin_path("credential-status"),
            &[("ski", ski)],
            None::<&()>,
        )
        .await
    }

    pub async fn credential_list(
        &self,
        entity_id: &str,
        status: Option<&str>,
    ) -> Result<Vec<CredentialListItem>> {
        let status = status.filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all"));
        let mut query = vec![("entityId", entity_id)];
        if let Some(status) = status {
            query.push(("status", status));
        }
        let value: serde_json::Value = self
            .send_json(
                Method::GET,
                &self.plugin_path("credential-list"),
                &query,
                None::<&()>,
            )
            .await?;
        parse_named_list(value, &["credentials", "items", "data", "results"])
    }

    pub async fn credential_revoke(&self, ski: &str, reason: &str) -> Result<RevokeResponse> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            ski: &'a str,
            reason: &'a str,
        }
        self.send_json(
            Method::POST,
            &self.plugin_path("credential-revoke"),
            &[],
            Some(&Body { ski, reason }),
        )
        .await
    }

    pub async fn machine_renew(&self, req: &MachineRenewRequest) -> Result<MachineRenewResponse> {
        self.send_json(
            Method::POST,
            &self.plugin_path("machine-renew"),
            &[],
            Some(req),
        )
        .await
    }

    pub async fn machine_decommission(
        &self,
        ski: &str,
        reason: &str,
    ) -> Result<DecommissionResponse> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Body<'a> {
            ski: &'a str,
            reason: &'a str,
        }
        self.send_json(
            Method::POST,
            &self.plugin_path("machine-decommission"),
            &[],
            Some(&Body { ski, reason }),
        )
        .await
    }

    // --- Platform ---------------------------------------------------------

    pub async fn platform_root(&self) -> Result<PlatformRootResponse> {
        self.send_json(
            Method::GET,
            &self.plugin_path("platform-root"),
            &[],
            None::<&()>,
        )
        .await
    }

    pub async fn catalog(&self) -> Result<CatalogResponse> {
        self.send_json(Method::GET, &self.plugin_path("catalog"), &[], None::<&()>)
            .await
    }

    /// GET an arbitrary URL with this client's TLS identity (optional mTLS probe).
    pub async fn probe_url(&self, url: &str) -> Result<u16> {
        let res = self
            .http
            .get(url)
            .headers(self.headers()?)
            .send()
            .await?;
        Ok(res.status().as_u16())
    }
}

fn build_http(
    user_agent: &str,
    client_pem: Option<&[u8]>,
    rustls_config: Option<Arc<RustlsClientConfig>>,
) -> Result<Client> {
    if let Some(cfg) = rustls_config {
        return Ok(Client::builder()
            .user_agent(user_agent)
            .use_preconfigured_tls((*cfg).clone())
            .build()?);
    }
    let mut builder = Client::builder().user_agent(user_agent);
    if let Some(pem) = client_pem {
        let identity = reqwest::Identity::from_pem(pem)?;
        builder = builder.identity(identity);
    }
    Ok(builder.build()?)
}

pub(crate) fn join_url(base: &str, path: &str) -> String {
    format!(
        "{}/{}",
        base.trim_end_matches('/'),
        path.trim_start_matches('/')
    )
}

fn looks_like_cookie(token: &str) -> bool {
    let t = token.trim();
    let lower = t.to_ascii_lowercase();
    lower.starts_with("cookie:") || t.contains("session_token=")
}

pub(crate) fn truncate_body(body: &str) -> String {
    const MAX: usize = 2048;
    if body.len() <= MAX {
        body.to_string()
    } else {
        format!("{}…", &body[..MAX])
    }
}

fn parse_named_list<T: DeserializeOwned>(
    value: serde_json::Value,
    keys: &[&str],
) -> Result<Vec<T>> {
    match value {
        serde_json::Value::Array(arr) => Ok(serde_json::from_value(serde_json::Value::Array(arr))?),
        serde_json::Value::Object(map) => {
            for key in keys {
                if let Some(arr) = map.get(*key) {
                    if arr.is_array() {
                        return Ok(serde_json::from_value(arr.clone())?);
                    }
                }
            }
            Err(Error::Message(format!(
                "expected an array (or one of {keys:?}) in list response"
            )))
        }
        other => Err(Error::Message(format!(
            "expected JSON array or object, got {other}"
        ))),
    }
}

fn parse_enroll_item(value: serde_json::Value) -> Result<EnrollListItem> {
    if let Some(inner) = value
        .get("enrollment")
        .or_else(|| value.get("request"))
        .or_else(|| value.get("item"))
    {
        return Ok(serde_json::from_value(inner.clone())?);
    }
    Ok(serde_json::from_value(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn join_url_keeps_auth_prefix() {
        assert_eq!(
            join_url(
                "https://api.example.com/api/auth",
                "delegate-permissions/enroll-create"
            ),
            "https://api.example.com/api/auth/delegate-permissions/enroll-create"
        );
    }

    #[tokio::test]
    async fn enroll_create_posts_camel_case() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/delegate-permissions/enroll-create"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "enrollId": "e1",
                "pullToken": "tok",
                "status": "pending"
            })))
            .mount(&server)
            .await;

        let client = DpClient::new(&server.uri());
        let res = client
            .enroll_create(&EnrollCreateRequest {
                entity_id: "acme.com".into(),
                host: "db1--acme.com".into(),
                kind: Some(MachineKind::Target),
                subject_ski: None,
                public_jwk: None,
                csr_pem: "CSR".into(),
                invite_token: None,
            })
            .await
            .unwrap();
        assert_eq!(res.enroll_id.as_deref(), Some("e1"));
        assert_eq!(res.pull_token.as_deref(), Some("tok"));
        assert_eq!(res.status.as_deref(), Some("pending"));
    }

    #[tokio::test]
    async fn enroll_invite_posts_and_looks_up() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/delegate-permissions/enroll-invite"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "inviteId": "i1",
                "inviteToken": "tok",
                "entityId": "acme.com",
                "kind": "machine_target"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/delegate-permissions/enroll-invite"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "inviteId": "i1",
                "entityId": "acme.com",
                "kind": "machine_target"
            })))
            .mount(&server)
            .await;

        let client = DpClient::new(&server.uri());
        let created = client
            .enroll_invite(&EnrollInviteRequest {
                entity_id: "acme.com".into(),
                kind: Some(MachineKind::Target),
                expires_in: None,
                max_uses: None,
            })
            .await
            .unwrap();
        assert_eq!(created.invite_token.as_deref(), Some("tok"));
        let preview = client.get_enroll_invite("tok").await.unwrap();
        assert_eq!(preview.entity_id.as_deref(), Some("acme.com"));
    }

    #[tokio::test]
    async fn http_error_includes_status() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/delegate-permissions/platform-root"))
            .respond_with(ResponseTemplate::new(503).set_body_string("nope"))
            .mount(&server)
            .await;
        let client = DpClient::new(&server.uri());
        let err = client.platform_root().await.unwrap_err();
        match err {
            Error::Http { status, body } => {
                assert_eq!(status, 503);
                assert_eq!(body, "nope");
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[tokio::test]
    async fn enroll_list_accepts_wrapped_array() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/delegate-permissions/enroll-list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "enrollments": [{
                    "enrollId": "e1",
                    "entityId": "acme.com",
                    "host": "db1--acme.com",
                    "status": "pending"
                }]
            })))
            .mount(&server)
            .await;
        let client = DpClient::new(&server.uri());
        let list = client
            .enroll_list("acme.com", Some("pending"))
            .await
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].enroll_id.as_deref(), Some("e1"));
    }

    #[tokio::test]
    async fn enroll_get_unwraps_enrollment_object() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/delegate-permissions/enroll-get"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "enrollment": {
                    "id": "e1",
                    "host": "db1--acme.com",
                    "csrPem": "CSR"
                }
            })))
            .mount(&server)
            .await;
        let client = DpClient::new(&server.uri());
        let item = client.enroll_get("e1").await.unwrap();
        assert_eq!(item.enroll_id.as_deref(), Some("e1"));
        assert_eq!(item.csr_pem.as_deref(), Some("CSR"));
    }

    #[tokio::test]
    async fn credential_list_accepts_wrapped_array() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/delegate-permissions/credential-list"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "credentials": [{
                    "ski": "abc",
                    "entityId": "acme.com",
                    "host": "db1--acme.com",
                    "status": "active",
                    "kind": "machine"
                }]
            })))
            .mount(&server)
            .await;
        let client = DpClient::new(&server.uri());
        let list = client
            .credential_list("acme.com", Some("active"))
            .await
            .unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].ski.as_deref(), Some("abc"));
        assert_eq!(list[0].host.as_deref(), Some("db1--acme.com"));
    }

    #[tokio::test]
    async fn credential_revoke_posts_reason() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/delegate-permissions/credential-revoke"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ski": "abc",
                "status": "revoked"
            })))
            .mount(&server)
            .await;
        let client = DpClient::new(&server.uri());
        let res = client
            .credential_revoke("abc", "key_compromise")
            .await
            .unwrap();
        assert_eq!(res.status.as_deref(), Some("revoked"));
        assert_eq!(res.ski.as_deref(), Some("abc"));
    }

    #[tokio::test]
    async fn platform_root_returns_pem_and_ski() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/delegate-permissions/platform-root"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "platformRootPem": "-----BEGIN CERTIFICATE-----\nMII\n-----END CERTIFICATE-----",
                "ski": "rootski"
            })))
            .mount(&server)
            .await;
        let client = DpClient::new(&server.uri());
        let res = client.platform_root().await.unwrap();
        let pem = crate::normalize_ca_file_pem(res.pem().unwrap()).unwrap();
        assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(pem.ends_with('\n'));
        assert_eq!(res.ski.as_deref(), Some("rootski"));
    }
}
