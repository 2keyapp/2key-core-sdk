# TypeScript packages moved

`@2key/dp-*` and `@2key/catalog-*` now live in
[`2key-browser-sdk`](https://github.com/2keyapp/2key-browser-sdk).

This directory retains **Rust** crates only (`dp-rust`, `dp-rust-mtls`, `dp-rust-sdk`, `dp-cli`).

**Billing HTTP** (`/api/v1/machine-authn/*`) is implemented in public
[`2key-billing-sdks/crates/billing_http`](https://github.com/2keyapp/2key-billing-sdks).
`dp-rust-sdk` delegates live server routes to that crate; crypto stays in `dp-rust-mtls`.
