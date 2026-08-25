//! OS keyring-backed [two_key_core::Storage].

use keyring::Entry;
use two_key_core::{ErrorCode, Result, Storage, TwoKeyError};

/// Stores each key as a separate credential under service `two-key` + prefix.
pub struct KeyringStorage {
    service: String,
}

impl KeyringStorage {
    /// `service` is typically `two-key` or host-specific.
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, key: &str) -> Result<Entry> {
        Entry::new(&self.service, key).map_err(|e| {
            TwoKeyError::new(ErrorCode::Unknown, "Failed to open keyring entry")
                .with_detail(e.to_string())
        })
    }
}

impl Storage for KeyringStorage {
    fn get(&self, key: &str) -> Result<Option<String>> {
        let entry = self.entry(key)?;
        match entry.get_password() {
            Ok(v) => Ok(Some(v)),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(TwoKeyError::new(ErrorCode::Unknown, "keyring get failed")
                .with_detail(e.to_string())),
        }
    }

    fn set(&self, key: &str, value: &str) -> Result<()> {
        let entry = self.entry(key)?;
        entry.set_password(value).map_err(|e| {
            TwoKeyError::new(ErrorCode::Unknown, "keyring set failed").with_detail(e.to_string())
        })
    }

    fn delete(&self, key: &str) -> Result<()> {
        let entry = self.entry(key)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(TwoKeyError::new(ErrorCode::Unknown, "keyring delete failed")
                .with_detail(e.to_string())),
        }
    }
}
