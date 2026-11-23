use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    /// `Display` shows the status and the server error code only (never the body, which can
    /// carry tokens); the body stays available on the field for callers that need it.
    #[error("HTTP {status}{}", http_code_suffix(.body))]
    Http { status: u16, body: String },

    #[error("request failed: {0}")]
    Request(#[from] reqwest::Error),

    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),

    #[error("mTLS: {0}")]
    Mtls(#[from] dp_rust_mtls::MtlsError),

    #[error("invalid machine identity: {0}")]
    Identity(String),

    #[error("keystore: {0}")]
    Keystore(String),

    #[error("enrollment: {0}")]
    Enrollment(String),

    #[error("lifecycle: {0}")]
    Lifecycle(String),

    #[error("admin: {0}")]
    Admin(String),

    #[error("auth: {0}")]
    Auth(String),

    #[error("agent: {0}")]
    Agent(String),

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("{0}")]
    Message(String),
}

impl From<billing_http::BillingHttpError> for Error {
    fn from(value: billing_http::BillingHttpError) -> Self {
        match value {
            billing_http::BillingHttpError::Http { status, body } => Self::Http { status, body },
            billing_http::BillingHttpError::Message(msg) => Self::Message(msg),
            billing_http::BillingHttpError::Reqwest(e) => Self::Request(e),
            billing_http::BillingHttpError::Json(e) => Self::Json(e),
        }
    }
}

impl Error {
    pub fn enrollment(msg: impl Into<String>) -> Self {
        Self::Enrollment(msg.into())
    }

    pub fn identity(msg: impl Into<String>) -> Self {
        Self::Identity(msg.into())
    }

    pub fn keystore(msg: impl Into<String>) -> Self {
        Self::Keystore(msg.into())
    }

    pub fn lifecycle(msg: impl Into<String>) -> Self {
        Self::Lifecycle(msg.into())
    }

    pub fn admin(msg: impl Into<String>) -> Self {
        Self::Admin(msg.into())
    }

    pub fn auth(msg: impl Into<String>) -> Self {
        Self::Auth(msg.into())
    }

    pub fn agent(msg: impl Into<String>) -> Self {
        Self::Agent(msg.into())
    }
}

/// `": <code>"` from a JSON body's `code` or `error` field when it is a short identifier.
fn http_code_suffix(body: &str) -> String {
    let code = serde_json::from_str::<serde_json::Value>(body).ok().and_then(|v| {
        ["code", "error"]
            .iter()
            .find_map(|k| v.get(*k).and_then(|c| c.as_str()).map(str::to_string))
    });
    match code {
        Some(c) if !c.is_empty() && c.len() <= 64 && c.chars().all(|ch| ch.is_ascii_alphanumeric() || "_.-".contains(ch)) => {
            format!(": {c}")
        }
        _ => String::new(),
    }
}

#[cfg(test)]
mod display_tests {
    use super::Error;

    #[test]
    fn http_display_never_contains_the_body() {
        let e = Error::Http { status: 401, body: r#"{"code":"token_expired","token":"eyJhbGciOi.secret.sig"}"#.into() };
        assert_eq!(e.to_string(), "HTTP 401: token_expired");
        let e = Error::Http { status: 502, body: "<html>upstream Bearer abc123</html>".into() };
        assert_eq!(e.to_string(), "HTTP 502");
    }
}
