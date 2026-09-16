# TypeScript packages moved

`@2key/dp-*` and `@2key/catalog-*` now live in
[`2key-billing-sdks`](https://github.com/2keyapp/2key-billing-sdks) under `packages/javascript/`.

This directory retains **Rust** crates only (`dp-rust`, `dp-rust-mtls`, `dp-rust-sdk`, `dp-cli`).

`dp-cli` is a **library** so a tenant repo can wrap it (IDR: [`idr-agent`](https://github.com/2keyapp/idr-agent)) and bake `DP_PRODUCT_NAME` / `DP_BACKEND_URL`.

**Billing HTTP** (`/api/v1/machine-authn/*`) is implemented in public
[`2key-billing-sdks`](https://github.com/2keyapp/2key-billing-sdks) (`billing_http` git dep).
`dp-rust-sdk` delegates live server routes to that crate; crypto stays in `dp-rust-mtls`.
