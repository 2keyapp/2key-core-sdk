//! Human Better Auth session (device-code / pasted cookie). Not machine mTLS.

use std::time::Duration;

use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};

use crate::client::DpClient;
use crate::error::{Error, Result};
use crate::keystore::{self, KeyStore};

const COOKIE_NAME: &str = "better-auth.session_token";
const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SessionTransport {
    /// Raw `session.token` from `/device/token` — send `Authorization: Bearer`.
    /// Product auth should enable `bearer()` so `/get-session` accepts it.
    Bearer,
    /// Browser cookie paste (`better-auth.session_token=…`).
    Cookie,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionUser {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredSession {
    #[serde(default = "session_schema")]
    pub schema: u32,
    pub token: String,
    pub transport: SessionTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<SessionUser>,
}

fn session_schema() -> u32 {
    1
}

impl StoredSession {
    pub fn from_device_token(access_token: &str, expires_in: Option<u64>) -> Self {
        let expires_at = expires_in.and_then(|secs| {
            time::OffsetDateTime::now_utc()
                .checked_add(time::Duration::seconds(secs as i64))
                .and_then(|t| {
                    t.format(&time::format_description::well_known::Rfc3339)
                        .ok()
                })
        });
        Self {
            schema: 1,
            token: access_token.trim().to_string(),
            transport: SessionTransport::Bearer,
            expires_at,
            user: None,
        }
    }

    pub fn from_pasted(raw: &str) -> Result<Self> {
        let t = raw.trim();
        if t.is_empty() {
            return Err(Error::auth("empty token"));
        }
        let lower = t.to_ascii_lowercase();
        if lower.starts_with("cookie:") || t.contains("session_token=") {
            let cookie = t
                .strip_prefix("Cookie:")
                .or_else(|| t.strip_prefix("cookie:"))
                .unwrap_or(t)
                .trim()
                .to_string();
            return Ok(Self {
                schema: 1,
                token: cookie,
                transport: SessionTransport::Cookie,
                expires_at: None,
                user: None,
            });
        }
        let token = t
            .strip_prefix("Bearer ")
            .or_else(|| t.strip_prefix("bearer "))
            .unwrap_or(t)
            .trim()
            .to_string();
        Ok(Self {
            schema: 1,
            token,
            transport: SessionTransport::Bearer,
            expires_at: None,
            user: None,
        })
    }

    /// Value for [`DpClient::with_auth`]: cookie header or raw bearer token.
    pub fn to_client_auth(&self) -> String {
        match self.transport {
            SessionTransport::Cookie => {
                if self.token.contains('=') {
                    self.token.clone()
                } else {
                    format!("{COOKIE_NAME}={}", self.token)
                }
            }
            SessionTransport::Bearer => self.token.clone(),
        }
    }
}

pub fn load_session(store: &impl KeyStore) -> Result<Option<StoredSession>> {
    match store.load_string(keystore::KEY_SESSION)? {
        None => Ok(None),
        Some(raw) => Ok(Some(serde_json::from_str(&raw)?)),
    }
}

pub fn save_session(store: &impl KeyStore, session: &StoredSession) -> Result<()> {
    store.save_string(
        keystore::KEY_SESSION,
        &serde_json::to_string_pretty(session)?,
    )
}

pub fn delete_session(store: &impl KeyStore) -> Result<()> {
    if store.exists(keystore::KEY_SESSION)? {
        store.secure_delete(keystore::KEY_SESSION)?;
    }
    Ok(())
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceCodeResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    #[serde(default)]
    pub verification_uri_complete: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
    #[serde(default)]
    pub interval: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DeviceTokenIssued {
    pub access_token: String,
    #[serde(default)]
    pub token_type: Option<String>,
    #[serde(default)]
    pub expires_in: Option<u64>,
}

#[derive(Debug, Clone)]
pub enum DeviceTokenPoll {
    Pending,
    SlowDown,
    Issued(DeviceTokenIssued),
}

#[derive(Debug, Clone, Deserialize)]
pub struct GetSessionResponse {
    #[serde(default)]
    pub user: Option<SessionUser>,
    #[serde(default)]
    pub session: Option<serde_json::Value>,
}

impl DpClient {
    pub async fn device_code(
        &self,
        client_id: &str,
        scope: Option<&str>,
    ) -> Result<DeviceCodeResponse> {
        #[derive(Serialize)]
        struct Body<'a> {
            client_id: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            scope: Option<&'a str>,
        }
        let (status, text) = self
            .request_text(
                Method::POST,
                "device/code",
                Some(&Body { client_id, scope }),
            )
            .await?;
        if !status.is_success() {
            return Err(device_http_error(status, &text, "device/code"));
        }
        serde_json::from_str(&text).map_err(|e| {
            Error::auth(format!(
                "device/code JSON: {e}: {}",
                crate::client::truncate_body(&text)
            ))
        })
    }

    pub async fn poll_device_token_once(
        &self,
        client_id: &str,
        device_code: &str,
    ) -> Result<DeviceTokenPoll> {
        #[derive(Serialize)]
        struct Body<'a> {
            grant_type: &'static str,
            device_code: &'a str,
            client_id: &'a str,
        }
        let (status, text) = self
            .request_text(
                Method::POST,
                "device/token",
                Some(&Body {
                    grant_type: DEVICE_GRANT,
                    device_code,
                    client_id,
                }),
            )
            .await?;
        if status.is_success() {
            let issued: DeviceTokenIssued = serde_json::from_str(&text)
                .map_err(|e| Error::auth(format!("device/token JSON: {e}")))?;
            if issued.access_token.is_empty() {
                return Err(Error::auth("device/token returned an empty access_token"));
            }
            return Ok(DeviceTokenPoll::Issued(issued));
        }
        match oauth_error_code(&text).as_deref() {
            Some("authorization_pending") => Ok(DeviceTokenPoll::Pending),
            Some("slow_down") => Ok(DeviceTokenPoll::SlowDown),
            Some("expired_token") => Err(Error::auth("device code expired — run auth login again")),
            Some("access_denied") => Err(Error::auth("authorization denied")),
            _ => Err(device_http_error(status, &text, "device/token")),
        }
    }

    pub async fn poll_device_token(
        &self,
        client_id: &str,
        device_code: &str,
        mut interval: Duration,
        timeout: Duration,
    ) -> Result<DeviceTokenIssued> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::auth("timed out waiting for authorization"));
            }
            tokio::time::sleep(interval).await;
            match self.poll_device_token_once(client_id, device_code).await? {
                DeviceTokenPoll::Pending => {}
                DeviceTokenPoll::SlowDown => {
                    interval += Duration::from_secs(5);
                }
                DeviceTokenPoll::Issued(issued) => return Ok(issued),
            }
        }
    }

    pub async fn get_session(&self) -> Result<Option<GetSessionResponse>> {
        let (status, text) = self
            .request_text(Method::GET, "get-session", None::<&()>)
            .await?;
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Ok(None);
        }
        if !status.is_success() {
            return Err(device_http_error(status, &text, "get-session"));
        }
        let trimmed = text.trim();
        if trimmed.is_empty() || trimmed == "null" {
            return Ok(None);
        }
        Ok(Some(serde_json::from_str(trimmed).map_err(|e| {
            Error::auth(format!("get-session JSON: {e}"))
        })?))
    }

    pub async fn sign_out(&self) -> Result<()> {
        let (status, text) = self
            .request_text(Method::POST, "sign-out", Some(&serde_json::json!({})))
            .await?;
        if status.is_success() || status == StatusCode::UNAUTHORIZED {
            return Ok(());
        }
        Err(device_http_error(status, &text, "sign-out"))
    }
}

fn oauth_error_code(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    v.get("error").and_then(|e| e.as_str()).map(str::to_string)
}

fn device_http_error(status: StatusCode, body: &str, path: &str) -> Error {
    let code = oauth_error_code(body);
    let desc = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| {
            v.get("error_description")
                .or_else(|| v.get("message"))
                .and_then(|m| m.as_str())
                .map(str::to_string)
        });
    match (code.as_deref(), desc) {
        (Some(code), Some(desc)) => Error::auth(format!("{path}: {code} ({desc})")),
        (Some(code), None) => Error::auth(format!("{path}: {code}")),
        (None, Some(desc)) => Error::Http {
            status: status.as_u16(),
            body: format!("{path}: {desc}"),
        },
        (None, None) => Error::Http {
            status: status.as_u16(),
            body: format!("{path}: {}", crate::client::truncate_body(body)),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryKeyStore;
    use serde_json::json;
    use wiremock::matchers::{body_partial_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[test]
    fn paste_cookie_and_bearer() {
        let cookie = StoredSession::from_pasted("better-auth.session_token=abc").unwrap();
        assert_eq!(cookie.transport, SessionTransport::Cookie);
        assert!(cookie.to_client_auth().contains("session_token=abc"));
        let bearer = StoredSession::from_pasted("Bearer tok123").unwrap();
        assert_eq!(bearer.transport, SessionTransport::Bearer);
        assert_eq!(bearer.to_client_auth(), "tok123");
    }

    #[test]
    fn session_file_roundtrip() {
        let store = MemoryKeyStore::new();
        let mut s = StoredSession::from_device_token("raw-token", Some(60));
        s.user = Some(SessionUser {
            id: Some("u1".into()),
            email: Some("a@b.c".into()),
            name: None,
        });
        save_session(&store, &s).unwrap();
        let loaded = load_session(&store).unwrap().unwrap();
        assert_eq!(loaded.token, "raw-token");
        assert_eq!(loaded.user.unwrap().email.as_deref(), Some("a@b.c"));
        delete_session(&store).unwrap();
        assert!(load_session(&store).unwrap().is_none());
    }

    #[tokio::test]
    async fn device_code_and_pending_then_token() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/device/code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "device_code": "dc",
                "user_code": "ABCD-EFGH",
                "verification_uri": "http://example/device",
                "expires_in": 600,
                "interval": 0
            })))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/device/token"))
            .and(body_partial_json(json!({ "device_code": "dc" })))
            .respond_with(ResponseTemplate::new(400).set_body_json(json!({
                "error": "authorization_pending"
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/device/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "sess-1",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(&server)
            .await;

        let client = DpClient::new(&server.uri());
        let code = client.device_code("idr-cli", None).await.unwrap();
        assert_eq!(code.user_code, "ABCD-EFGH");
        let first = client
            .poll_device_token_once("idr-cli", "dc")
            .await
            .unwrap();
        assert!(matches!(first, DeviceTokenPoll::Pending));
        let issued = client
            .poll_device_token_once("idr-cli", "dc")
            .await
            .unwrap();
        match issued {
            DeviceTokenPoll::Issued(t) => assert_eq!(t.access_token, "sess-1"),
            other => panic!("{other:?}"),
        }
    }
}
