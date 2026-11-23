//! Key material must never appear in `Debug` output (agent docs/observability/07 R-PRIV-1).

#[test]
fn generated_keys_do_not_leak_through_debug() {
    let g = dp_rust_mtls::generate_ed25519().expect("keygen");
    let printed = format!("{g:?}");
    let d = g.private_jwk["d"].as_str().expect("private scalar");
    assert!(!printed.contains(&g.private_pem), "private PEM leaked: {printed}");
    assert!(!printed.contains(d), "private JWK leaked: {printed}");
    assert!(printed.contains("[REDACTED]") && printed.contains(&g.ski), "{printed}");

    let ca = dp_rust_mtls::create_self_signed_ca("debug-test").expect("ca");
    let printed = format!("{ca:?}");
    assert!(!printed.contains(ca.private_jwk["d"].as_str().unwrap()), "CA key leaked: {printed}");
}
