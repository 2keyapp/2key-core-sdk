use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("HTTP {status}: {body}")]
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
