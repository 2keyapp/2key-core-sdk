//! Shared error taxonomy for wrappers (Dart, TS, CLI, UniFFI).

use thiserror::Error;

/// Stable machine-readable codes — keep in sync with `docs/error-codes.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    /// Missing or invalid SDK configuration.
    Config,
    /// Network / transport failure.
    Network,
    /// HTTP 401 / missing auth.
    Unauthorized,
    /// Offline / no connectivity policy path.
    Offline,
    /// License JWT signature invalid.
    LicenseInvalid,
    /// License JWT expired (`exp`).
    LicenseExpired,
    /// License JWT malformed or missing required claims.
    LicenseMalformed,
    /// License lists devices but this device SKI is not among them.
    LicenseDeviceMismatch,
    /// License sync returned 304 Not Modified.
    NotModified,
    /// Unexpected server response shape.
    InvalidResponse,
    /// Generic / unclassified.
    Unknown,
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl ErrorCode {
    /// Snake string for FFI / JSON.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Config => "config",
            Self::Network => "network",
            Self::Unauthorized => "unauthorized",
            Self::Offline => "offline",
            Self::LicenseInvalid => "license_invalid",
            Self::LicenseExpired => "license_expired",
            Self::LicenseMalformed => "license_malformed",
            Self::LicenseDeviceMismatch => "license_device_mismatch",
            Self::NotModified => "not_modified",
            Self::InvalidResponse => "invalid_response",
            Self::Unknown => "unknown",
        }
    }
}

/// SDK error with stable [ErrorCode] and human message.
#[derive(Debug, Error)]
#[error("{code}: {message}")]
pub struct TwoKeyError {
    /// Stable code for wrappers.
    pub code: ErrorCode,
    /// User- or developer-facing message.
    pub message: String,
    /// Optional technical detail (logging).
    pub detail: Option<String>,
}

impl TwoKeyError {
    /// Construct with code + message.
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            detail: None,
        }
    }

    /// Attach technical detail.
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// Result alias.
pub type Result<T> = std::result::Result<T, TwoKeyError>;
