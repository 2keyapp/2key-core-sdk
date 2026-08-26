# 2key-core-sdk

**Private** native platform core for 2key Auth + Billing.

| Concern | Location | Role |
|---------|----------|------|
| **Billing native core** | `crates/2key_core` (`two-key-core`) | License verify/sync, session orchestration, FFI/C ABI — **binary-private** |
| **Billing CLI** | `crates/2key_cli` (`two-key`) | Desktop CLI (Windows / macOS / Linux) |
| **DP Rust** | `packages/dp-rust*` / `dp-cli` | AuthZ algebra, mTLS, HTTP client, product CLIs (`idr`, …) |

**TypeScript / browser SDK** lives in public [`2key-browser-sdk`](https://github.com/2keyapp/2key-browser-sdk)
(`@2key/browser-sdk` = AuthN + AuthZ + Billing). Do **not** add TS packages here.

Public consumers never depend on this repo's Rust source. They use:

- Prebuilt **`two-key` CLI** and **`libtwo_key_core`** from Releases → [`2key-billing-sdks`](https://github.com/2keyapp/2key-billing-sdks)
- Browser / SPA: [`2key-browser-sdk`](https://github.com/2keyapp/2key-browser-sdk)

## Binary Private Core

1. Develop and test `two-key-core` / `two-key-cli` **here**.
2. CI releases tagged assets (`two-key-{os}-{arch}`, `libtwo_key_core-*`) with checksums.
3. Public `2key-billing-sdks` **downloads** those artifacts — no `cargo` path to this source for ISVs.

## Quick start (internal)

```bash
cargo test -p two-key-core
cargo test -p dp-rust -p dp-rust-mtls
cargo run -p two-key-cli -- version
```

## Packages (Rust Delegate Permissions)

| Package | Path | Role |
|---------|------|------|
| `dp-rust` | `packages/dp-rust` | Wire types + AuthZ algebra (parity with `@2key/dp-authorize`) |
| `dp-rust-mtls` | `packages/dp-rust-mtls` | mTLS leaf / PEM / optional rustls |
| `dp-rust-sdk` | `packages/dp-rust-sdk` | HTTP client + enrollment/lifecycle |
| `dp-cli` | `packages/dp-cli` | Lifecycle CLI (`idr` / `dp-cli`) + agent |

## AuthZ conformance sync

`conformance/dp-authz/fixtures.json` must stay in sync with the **canonical** copy in
`2key-browser-sdk`. Change algebra in both `@2key/dp-authorize` and `dp-rust` together.

Dual client/server AuthZ notes: see `2key-browser-sdk/docs/DP-AUTHZ.md` (also mirrored under [`docs/DP-AUTHZ.md`](docs/DP-AUTHZ.md)).

## Tenant catalogs

Canonical catalog packages: **`2key-browser-sdk/catalogs/*`**. See that repo’s `docs/TENANTS.md`.

## Rust CLI (branded binary)

See [`.env.example`](.env.example) and [docs/CLI-PRODUCT.md](docs/CLI-PRODUCT.md).

## Related repos

| Repo | Visibility | Role |
|------|------------|------|
| `2keyapp/2key-core-sdk` | **Private** | This repo — Rust native core |
| `2keyapp/2key-browser-sdk` | **Public** | TypeScript / browser AuthN + AuthZ + Billing |
| `2keyapp/2key-billing-sdks` | **Public** | CLI fetch + Dart wrappers + OpenAPI |
| `2keyapp/2key-billing` | Private | Auth + Billing server |
| `2keyapp/better-auth` | Public fork | Auth engine (sync from upstream) |

## Secret storage

DP packages **never** persist private keys. See [docs/SECRET_STORAGE.md](docs/SECRET_STORAGE.md).
