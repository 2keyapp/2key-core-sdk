# 2key-core-sdk

**Private** native platform core for 2key Auth + Billing.

| Concern | Location | Role |
|---------|----------|------|
| **Billing native core** | `crates/2key_core` (`two-key-core`) | License verify/sync, session orchestration, FFI/C ABI — **binary-private** |
| **Billing CLI** | `crates/2key_cli` (`two-key`) | Desktop CLI (Windows / macOS / Linux) |
| **DP Rust** | `packages/dp-rust*` / `dp-cli` | AuthZ algebra, mTLS, HTTP client, generic lifecycle CLI |

**TypeScript / browser SDK** lives in public [`2key-billing-sdks`](https://github.com/2keyapp/2key-billing-sdks) under `packages/javascript/`
(`@2key/browser-sdk` = AuthN + AuthZ + Billing). The old `2key-browser-sdk` repo is merged there. Do **not** add TS packages here.

**IDR-labelled binaries** (`idr`, `idr-agent`) are a thin tenant wrap in [`2keyapp/idr-agent`](https://github.com/2keyapp/idr-agent) that depends on `dp-cli` and bakes `https://billing.idr.to`.

Public consumers never depend on this repo's Rust source. They use:

- Prebuilt **`two-key` CLI** and **`libtwo_key_core`** from Releases → [`2key-billing-sdks`](https://github.com/2keyapp/2key-billing-sdks)
- Browser / SPA: `@2key/browser-sdk` in `2key-billing-sdks/packages/javascript/`

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

IDR product build (sibling repo):

```bash
cd ../idr-agent
cargo build --release --bin idr --bin idr-agent
./target/release/idr version
```

## Packages (Rust Delegate Permissions)

| Package | Path | Role |
|---------|------|------|
| `dp-rust` | `packages/dp-rust` | Wire types + AuthZ algebra (parity with `@2key/dp-authorize`) |
| `dp-rust-mtls` | `packages/dp-rust-mtls` | mTLS leaf / PEM / optional rustls |
| `dp-rust-sdk` | `packages/dp-rust-sdk` | HTTP client + enrollment/lifecycle |
| `dp-cli` | `packages/dp-cli` | Library + bins (`dp-cli` / `idr`, `dp-agent` / `idr-agent`) |

## AuthZ conformance sync

`conformance/dp-authz/fixtures.json` must stay in sync with the **canonical** copy in
`2key-billing-sdks`. Change algebra in both `@2key/dp-authorize` and `dp-rust` together.

Dual client/server AuthZ notes: see [`docs/DP-AUTHZ.md`](docs/DP-AUTHZ.md).

## Tenant catalogs

Canonical catalog packages: **`2key-billing-sdks/packages/javascript/catalogs/*`**. See that repo’s `docs/TENANTS.md`.

Shop JSON (prices, SKUs) is a **different** file: tenant seed forks such as `2key-idr-seed-templates`.

## Rust CLI (branded binary)

Generic CLI: [`.env.example`](.env.example) and [docs/CLI-PRODUCT.md](docs/CLI-PRODUCT.md).  
IDR constants: sibling `idr-agent` (`.cargo/config.toml`).

## Related repos

| Repo | Visibility | Role |
|------|------------|------|
| `2keyapp/2key-core-sdk` | **Private** | This repo — Rust native core |
| `2keyapp/idr-agent` | Private | IDR-branded `idr` + `idr-agent` wrap |
| `2keyapp/2key-billing-sdks` | **Public** | Dart + JS SDKs, catalogs, OpenAPI, CLI fetch |
| `2keyapp/2key-billing` | Private | Auth + Billing server (`/api/v1/machine-authn/*`) |
| `2keyapp/better-auth` | Public fork | Auth engine (sync from upstream) |

## Secret storage

DP packages **never** persist private keys. See [docs/SECRET_STORAGE.md](docs/SECRET_STORAGE.md).
