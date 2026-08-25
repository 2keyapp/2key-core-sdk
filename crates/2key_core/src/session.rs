//! Persisted account session + sync orchestration.

use serde::{Deserialize, Serialize};

use crate::api::{ApiClient, SyncResult};
use crate::config::SdkConfig;
use crate::error::{ErrorCode, Result, TwoKeyError};
use crate::license::{LicenseVerifier, VerifyOutcome};
use crate::models::LicensePayload;
use crate::ports::{Clock, Storage, SystemClock};

/// Cached account billing session (JSON-serializable).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AccountSession {
    /// Account / user key.
    pub account_key: String,
    /// Billing API access token (opaque).
    pub access_token: Option<String>,
    /// Signed license JWT.
    pub license_jwt: Option<String>,
    /// Last license ETag.
    pub license_etag: Option<String>,
    /// Optional paying party header.
    pub paying_party_id_header: Option<String>,
}

impl AccountSession {
    /// Empty session for account.
    pub fn new(account_key: impl Into<String>) -> Self {
        Self {
            account_key: account_key.into(),
            access_token: None,
            license_jwt: None,
            license_etag: None,
            paying_party_id_header: None,
        }
    }
}

/// Manages session persistence and license sync.
pub struct SessionManager<S: Storage, C: Clock = SystemClock> {
    config: SdkConfig,
    storage: S,
    clock: C,
    verifier: LicenseVerifier,
    api: ApiClient,
}

impl<S: Storage> SessionManager<S, SystemClock> {
    /// Create with system clock.
    pub fn new(config: SdkConfig, storage: S) -> Result<Self> {
        Self::with_clock(config, storage, SystemClock)
    }
}

impl<S: Storage, C: Clock> SessionManager<S, C> {
    /// Create with custom clock.
    pub fn with_clock(config: SdkConfig, storage: S, clock: C) -> Result<Self> {
        let config = config.validate()?;
        let verifier = LicenseVerifier::from_pem(&config.public_key_pem)?;
        let api = ApiClient::new(&config.api_base_url);
        Ok(Self {
            config,
            storage,
            clock,
            verifier,
            api,
        })
    }

    fn session_key(&self, account_key: &str) -> String {
        format!("{}:session:{}", self.config.storage_prefix, sanitize(account_key))
    }

    /// Load session JSON from storage.
    pub fn load(&self, account_key: &str) -> Result<Option<AccountSession>> {
        let raw = self.storage.get(&self.session_key(account_key))?;
        match raw {
            None => Ok(None),
            Some(s) => {
                let session: AccountSession = serde_json::from_str(&s).map_err(|e| {
                    TwoKeyError::new(ErrorCode::Unknown, "Corrupt session data")
                        .with_detail(e.to_string())
                })?;
                Ok(Some(session))
            }
        }
    }

    /// Persist session.
    pub fn save(&self, session: &AccountSession) -> Result<()> {
        let raw = serde_json::to_string(session).map_err(|e| {
            TwoKeyError::new(ErrorCode::Unknown, "Failed to serialize session")
                .with_detail(e.to_string())
        })?;
        self.storage.set(&self.session_key(&session.account_key), &raw)
    }

    /// Clear session for account.
    pub fn clear(&self, account_key: &str) -> Result<()> {
        self.storage.delete(&self.session_key(account_key))
    }

    /// Verify without converting to Result (for facade).
    pub fn verify_raw(&self, jwt: &str) -> VerifyOutcome {
        self.verifier.verify_and_decode(jwt, &self.clock)
    }

    /// Verify cached license JWT offline.
    pub fn init_license(&self, jwt: &str) -> Result<LicensePayload> {
        match self.verify_raw(jwt) {
            VerifyOutcome::Success(p) => Ok(p),
            VerifyOutcome::Failure { code, message } => Err(TwoKeyError::new(code, message)),
        }
    }

    /// Online license sync using stored access token + ETag.
    pub fn sync_license(&self, session: &mut AccountSession) -> Result<LicensePayload> {
        let token = session
            .access_token
            .as_deref()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                TwoKeyError::new(ErrorCode::Unauthorized, "No access token in session")
            })?;

        let result = self.api.fetch_license(
            token,
            session.paying_party_id_header.as_deref(),
            session.license_etag.as_deref(),
        )?;

        match result {
            SyncResult::NotModified { etag } => {
                if let Some(e) = etag {
                    session.license_etag = Some(e);
                }
                let jwt = session.license_jwt.as_deref().ok_or_else(|| {
                    TwoKeyError::new(
                        ErrorCode::NotModified,
                        "License not modified but no cached JWT",
                    )
                })?;
                self.init_license(jwt)
            }
            SyncResult::Success {
                signed_token,
                etag,
            } => {
                let payload = self.init_license(&signed_token)?;
                session.license_jwt = Some(signed_token);
                session.license_etag = etag;
                self.save(session)?;
                Ok(payload)
            }
        }
    }

    /// Whether polling is recommended (has subscriptions in license).
    pub fn should_poll(&self, session: &AccountSession) -> bool {
        let Some(jwt) = session.license_jwt.as_deref() else {
            return false;
        };
        matches!(
            self.verifier.verify_and_decode(jwt, &self.clock),
            VerifyOutcome::Success(p) if !p.subscriptions.is_empty()
        )
    }

    /// Config accessor.
    pub fn config(&self) -> &SdkConfig {
        &self.config
    }

    /// API client accessor.
    pub fn api(&self) -> &ApiClient {
        &self.api
    }

    /// Verifier accessor.
    pub fn verifier(&self) -> &LicenseVerifier {
        &self.verifier
    }
}

fn sanitize(account_key: &str) -> String {
    account_key
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' })
        .collect()
}
