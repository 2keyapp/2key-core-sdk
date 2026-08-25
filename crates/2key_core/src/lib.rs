//! 2key Billing native client core (`two-key-core` / `2key_core`).
//!
//! Language wrappers (Dart FRB, UniFFI, CLI) should call the [facade] module.
//! Host apps must not depend on this crate directly.

#![deny(missing_docs)]

pub mod api;
pub mod c_api;
pub mod config;
pub mod error;
pub mod facade;
pub mod ffi;
pub mod license;
pub mod models;
pub mod ports;
pub mod session;
pub mod url;

pub use config::SdkConfig;
pub use error::{ErrorCode, Result, TwoKeyError};
pub use facade::TwoKeyClient;
pub use license::{LicenseVerifier, VerifyOutcome};
pub use models::{
    BillingSubscription, LicensePayload, PayingParty, Plan, SubscriptionStatus,
};
pub use ports::{
    AuthPort, Clock, InMemoryStorage, StaticTokenAuth, Storage, SystemClock,
};
pub use session::{AccountSession, SessionManager};
pub use url::normalize_api_base_url;
