//! URL helpers.

/// Strip trailing slashes and optional `/api/v1` or legacy `/api/billing`.
pub fn normalize_api_base_url(input: &str) -> String {
    let mut s = input.trim().to_string();
    while s.ends_with('/') {
        s.pop();
    }
    let lower = s.to_ascii_lowercase();
    for suffix in ["/api/v1", "/api/billing"] {
        if lower.ends_with(suffix) {
            s.truncate(s.len() - suffix.len());
            while s.ends_with('/') {
                s.pop();
            }
            break;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_api_v1() {
        assert_eq!(
            normalize_api_base_url("https://billing.example.com/api/v1/"),
            "https://billing.example.com"
        );
    }
}
