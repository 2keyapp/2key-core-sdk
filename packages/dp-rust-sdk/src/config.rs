use std::path::PathBuf;

/// Compile-time defaults, overridable at runtime via `DP_*` environment variables.
pub struct ResolvedConfig {
    /// Billing Machine AuthN base (`…/api/v1`).
    pub backend_url: String,
    /// Better Auth mount (`…/api/auth`). Derived from `backend_url` unless `DP_AUTH_URL` is set.
    pub auth_url: String,
    pub product_name: String,
    pub separator: String,
    pub state_dir: PathBuf,
    pub auth_token: Option<String>,
    /// OAuth device-flow `client_id`. Default `{product}-cli`.
    pub client_id: String,
}

impl ResolvedConfig {
    pub fn from_env() -> Self {
        let product_name = env_or("DP_PRODUCT_NAME", option_env!("DP_PRODUCT_NAME"), "dp");
        let backend_url = env_or(
            "DP_BACKEND_URL",
            option_env!("DP_BACKEND_URL"),
            "http://localhost:3000/api/v1",
        );
        let auth_url = env_or(
            "DP_AUTH_URL",
            option_env!("DP_AUTH_URL"),
            &default_auth_url(&backend_url),
        );
        let separator = env_or("DP_SEPARATOR", option_env!("DP_SEPARATOR"), "--");
        let state_dir = std::env::var("DP_STATE_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_state_dir(&product_name));
        let auth_token = std::env::var("DP_AUTH_TOKEN")
            .ok()
            .filter(|s| !s.is_empty());
        let client_id = env_or(
            "DP_CLIENT_ID",
            option_env!("DP_CLIENT_ID"),
            &format!("{product_name}-cli"),
        );
        Self {
            backend_url,
            auth_url,
            product_name,
            separator,
            state_dir,
            auth_token,
            client_id,
        }
    }

    /// Update Machine AuthN base. Re-derives `auth_url` unless `DP_AUTH_URL` is set.
    pub fn set_backend_url(&mut self, url: String) {
        self.backend_url = url;
        let explicit = std::env::var("DP_AUTH_URL")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                option_env!("DP_AUTH_URL")
                    .map(str::to_string)
                    .filter(|s| !s.is_empty())
            });
        if explicit.is_none() {
            self.auth_url = default_auth_url(&self.backend_url);
        }
    }

    /// Fill `auth_token` from `$DP_STATE_DIR/session` when env/flags did not set one.
    pub fn apply_stored_session(&mut self) {
        if self.auth_token.is_some() {
            return;
        }
        if let Ok(store) = crate::FileKeyStore::open(&self.state_dir) {
            if let Ok(Some(session)) = crate::session::load_session(&store) {
                self.auth_token = Some(session.to_client_auth());
            }
        }
    }
}

fn env_or(var: &str, compiled: Option<&'static str>, fallback: &str) -> String {
    std::env::var(var)
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| compiled.map(str::to_string))
        .unwrap_or_else(|| fallback.to_string())
}

/// Login lives at `/api/auth` on the same host as Machine AuthN `/api/v1`.
pub fn default_auth_url(backend_url: &str) -> String {
    let base = backend_url.trim_end_matches('/');
    if let Some(host) = base.strip_suffix("/api/v1") {
        return format!("{host}/api/auth");
    }
    if base.ends_with("/api/auth") {
        return base.to_string();
    }
    format!("{base}/api/auth")
}

fn default_state_dir(product: &str) -> PathBuf {
    let name = if product.is_empty() { "dp" } else { product };
    if let Some(dirs) = directories::UserDirs::new() {
        return dirs.home_dir().join(format!(".{name}"));
    }
    PathBuf::from(format!("/var/lib/{name}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_state_dir_is_dot_product() {
        let dir = default_state_dir("idr");
        assert!(dir.ends_with(".idr") || dir.ends_with("idr"));
    }

    #[test]
    fn auth_url_from_api_v1() {
        assert_eq!(
            default_auth_url("https://billing.idr.to/api/v1"),
            "https://billing.idr.to/api/auth"
        );
        assert_eq!(
            default_auth_url("http://localhost:3000/api/v1/"),
            "http://localhost:3000/api/auth"
        );
    }

    #[test]
    fn auth_url_keeps_explicit_auth_mount() {
        assert_eq!(
            default_auth_url("https://billing.idr.to/api/auth"),
            "https://billing.idr.to/api/auth"
        );
    }
}
