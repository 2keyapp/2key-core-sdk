//! Stable facade intended for FFI wrappers (FRB / UniFFI).

use crate::api::{BootstrapResult, FetchPlansQuery};
use crate::config::SdkConfig;
use crate::error::Result;
use crate::license::VerifyOutcome;
use crate::models::{LicensePayload, Plan};
use crate::ports::{Clock, InMemoryStorage, Storage, SystemClock};
use crate::session::{AccountSession, SessionManager};

/// High-level client used by language wrappers.
pub struct TwoKeyClient<S: Storage = InMemoryStorage, C: Clock = SystemClock> {
    sessions: SessionManager<S, C>,
}

impl TwoKeyClient<InMemoryStorage, SystemClock> {
    /// Construct with in-memory storage (tests / CLI prototypes).
    pub fn with_memory(config: SdkConfig) -> Result<Self> {
        Ok(Self {
            sessions: SessionManager::new(config, InMemoryStorage::new())?,
        })
    }
}

impl<S: Storage, C: Clock> TwoKeyClient<S, C> {
    /// Construct with injected storage + clock.
    pub fn new(config: SdkConfig, storage: S, clock: C) -> Result<Self> {
        Ok(Self {
            sessions: SessionManager::with_clock(config, storage, clock)?,
        })
    }

    /// Verified config.
    pub fn config(&self) -> &SdkConfig {
        self.sessions.config()
    }

    /// Verify a license JWT offline.
    pub fn verify_license(&self, jwt: &str) -> VerifyOutcome {
        self.sessions.verify_raw(jwt)
    }

    /// Init license (errors as [crate::error::TwoKeyError]).
    pub fn init_license(&self, jwt: &str) -> Result<LicensePayload> {
        self.sessions.init_license(jwt)
    }

    /// Load persisted session.
    pub fn load_session(&self, account_key: &str) -> Result<Option<AccountSession>> {
        self.sessions.load(account_key)
    }

    /// Save session.
    pub fn save_session(&self, session: &AccountSession) -> Result<()> {
        self.sessions.save(session)
    }

    /// Clear session.
    pub fn clear_session(&self, account_key: &str) -> Result<()> {
        self.sessions.clear(account_key)
    }

    /// Sync license from server (updates session in place + persist on success).
    pub fn sync_license(&self, session: &mut AccountSession) -> Result<LicensePayload> {
        self.sessions.sync_license(session)
    }

    /// Bootstrap billing context JSON.
    pub fn ensure_billing_context(&self, access_token: &str) -> Result<BootstrapResult> {
        self.sessions.api().ensure_billing_context(access_token)
    }

    /// Public plan catalog.
    pub fn fetch_plans(&self, query: FetchPlansQuery) -> Result<Vec<Plan>> {
        self.sessions.api().fetch_plans(&query)
    }

    /// Whether background poll is recommended.
    pub fn should_poll(&self, session: &AccountSession) -> bool {
        self.sessions.should_poll(session)
    }
}
