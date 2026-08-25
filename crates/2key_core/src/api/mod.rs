//! Billing HTTP API client (`/api/v1`).

mod client;

pub use client::{
    ApiClient, BootstrapResult, FetchPlansQuery, SyncResult,
};
