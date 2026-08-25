//! Platform ports injected by wrappers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{ErrorCode, Result, TwoKeyError};

/// Opaque key-value persistence (secure storage on device).
pub trait Storage: Send + Sync {
    /// Read a value by key.
    fn get(&self, key: &str) -> Result<Option<String>>;
    /// Write a value by key.
    fn set(&self, key: &str, value: &str) -> Result<()>;
    /// Delete a key.
    fn delete(&self, key: &str) -> Result<()>;
}

/// Clock for expiry checks (injectable in tests).
pub trait Clock: Send + Sync {
    /// Unix seconds (UTC).
    fn unix_seconds(&self) -> i64;
}

/// Auth adapter — host/wrapper supplies token mint (Better Auth, CLI paste, etc.).
pub trait AuthPort: Send + Sync {
    /// Mint or return a billing API access token (`aud=billing`).
    fn acquire_api_token(&self) -> Result<String>;
    /// Clear local auth session when supported.
    fn sign_out(&self) -> Result<()> {
        Ok(())
    }
}

/// Static / pasted token for CLI and tests.
#[derive(Debug, Clone)]
pub struct StaticTokenAuth {
    /// Bearer token value (without `Bearer ` prefix required).
    pub access_token: String,
}

impl AuthPort for StaticTokenAuth {
    fn acquire_api_token(&self) -> Result<String> {
        let t = self.access_token.trim();
        if t.is_empty() {
            return Err(TwoKeyError::new(
                ErrorCode::Unauthorized,
                "Access token is empty",
            ));
        }
        Ok(t.to_string())
    }
}

/// System clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_seconds(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

/// In-memory storage for tests / CLI prototypes.
#[derive(Debug, Default, Clone)]
pub struct InMemoryStorage {
    inner: Arc<Mutex<HashMap<String, String>>>,
}

impl InMemoryStorage {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Storage for InMemoryStorage {
    fn get(&self, key: &str) -> Result<Option<String>> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| TwoKeyError::new(ErrorCode::Unknown, "storage lock poisoned"))?;
        Ok(guard.get(key).cloned())
    }

    fn set(&self, key: &str, value: &str) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| TwoKeyError::new(ErrorCode::Unknown, "storage lock poisoned"))?;
        guard.insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn delete(&self, key: &str) -> Result<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| TwoKeyError::new(ErrorCode::Unknown, "storage lock poisoned"))?;
        guard.remove(key);
        Ok(())
    }
}
