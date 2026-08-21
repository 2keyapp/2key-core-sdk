use std::path::PathBuf;

/// Compile-time defaults, overridable at runtime via `DP_*` environment variables.
pub struct ResolvedConfig {
    pub backend_url: String,
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
            "http://localhost:3000/api/auth",
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
            product_name,
            separator,
            state_dir,
            auth_token,
            client_id,
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
}
