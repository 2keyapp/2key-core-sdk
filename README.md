# 2key-core-sdk

**Private** platform core for 2key Auth + Billing.

| Concern | Location | Role |
|---------|----------|------|
| **Billing native core** | `crates/2key_core` (`two-key-core`) | License verify/sync, session orchestration, FFI/C ABI — **binary-private**; never published as source to ISVs |
| **Billing CLI** | `crates/2key_cli` (`two-key`) | Desktop CLI (Windows / macOS / Linux) built and released as binaries |
| **Delegate Permissions** | `packages/*`, `catalogs/*` | CapabilityCredentials, mTLS presentation, tenant catalogs |

Public consumers never depend on this repo's Rust source. They use:

- Prebuilt **`two-key` CLI** and **`libtwo_key_core`** artifacts from Releases
- Language wrappers in public [`2key-billing-sdks`](https://github.com/2keyapp/2key-billing-sdks)

## Binary Private Core

1. Develop and test `two-key-core` / `two-key-cli` **here**.
2. CI releases tagged assets (`two-key-{os}-{arch}`, `libtwo_key_core-*`) with checksums.
3. Public `2key-billing-sdks` **downloads** those artifacts (see `core-binaries.lock.json` there) — no `cargo` path to this source for ISVs.

## Quick start (internal)

```bash
# Billing core + CLI
cargo test -p two-key-core
cargo run -p two-key-cli -- version

# Delegate Permissions (TS)
pnpm install && pnpm test
```

## Packages (Delegate Permissions)

| Package | Path | Role |
|---------|------|------|
| `@2key/dp-spec` | `packages/dp-spec` | Shared types + JSON Schema for CapabilityCredentials |
| `@2key/dp-presentation` | `packages/dp-presentation` | Ports: `PepSession`, `PepConnector`, `CredentialPresenter`, `DeviceIdentity` |
| `@2key/dp-mtls` | `packages/dp-mtls` | Node mTLS: self-signed client cert + `tls.ConnectionOptions` |
| `@2key/dp-ts` | `packages/dp-ts` | TypeScript Admin (+ Device) SDK |
| `dp-rust` | `packages/dp-rust` | Rust credential wire types |
| `dp-rust-mtls` | `packages/dp-rust-mtls` | Rust mTLS: `rcgen` leaf + PEM load; `rustls::ClientConfig` via `--features rustls-config` |
| `dp-rust-sdk` | `packages/dp-rust-sdk` | HTTP client + enrollment/lifecycle against `delegate-permissions` |
| `dp-cli` | `packages/dp-cli` | Lifecycle CLI (`idr` / `dp-cli`) + resident agent (`idr-agent`) |

> **Naming:** This repository is **`2key-core-sdk`** everywhere (docs, remotes, CI). Historical "dp-sdk" refers only to the Delegate Permissions *packages* under `packages/dp-*`, not a separate product repo.

## Rust CLI (branded binary)

Same source for every product. Bake the backend and product name into the exe, then copy/rename it (`idr`, `acme`, …). See [`.env.example`](.env.example) for required vs optional variables.

**Required at product build**

| Variable | Example | Role |
|----------|---------|------|
| `DP_BACKEND_URL` | `https://api.idr.to/api/auth` | Better Auth base (no trailing slash) |
| `DP_PRODUCT_NAME` | `idr` | Help text, user-agent, default `~/.{name}` |

**Optional at product build**

| Variable | Default | Role |
|----------|---------|------|
| `DP_SEPARATOR` | `--` | Machine identity `{name}{sep}{entity}` |

**Runtime only** (never compiled in; also `--token` / `--state-dir` / `--backend-url`)

| Variable | Required when | Role |
|----------|----------------|------|
| `DP_AUTH_TOKEN` | `org`, admin, enroll-instant | Optional override. Prefer `idr auth login` (`$DP_STATE_DIR/session`). Cookie `better-auth.session_token=...` or Bearer |
| `DP_STATE_DIR` | optional | Keys + `state.json`. Default `~/.${DP_PRODUCT_NAME}` |
| `DP_BACKEND_URL` / `DP_PRODUCT_NAME` / `DP_SEPARATOR` | optional | Override compiled defaults |

Cargo does not load `.env`. Export the vars (or put build vars in `.cargo/config.toml`):

```bash
set -a && source .env && set +a
DP_BACKEND_URL="https://api.idr.to/api/auth" DP_PRODUCT_NAME="idr" \
  cargo build --release -p dp-cli --bin dp-cli --bin idr --bin idr-agent
# or: cp target/release/dp-cli idr
```

Product CLI (`auth login`, `signup`, `register`, `csr`, `invite`) plus power commands (`org`, `machine`, `init` / `gen`) and the resident agent (`idr-agent`): [docs/CLI-PRODUCT.md](docs/CLI-PRODUCT.md).

What to run for each use case (plugin tests, `idr init`/`register --local`, openssl, delegations, HAProxy handshake): [docs/TEST-USECASES.md](docs/TEST-USECASES.md).

## Tenant catalogs

See [`TENANTS.md`](TENANTS.md) and [`catalogs/`](catalogs/).

## Related repos

| Repo | Visibility | Role |
|------|------------|------|
| `2keyapp/2key-core-sdk` | **Private** | This repo — core source + DP |
| `2keyapp/2key-billing` | Private | Auth + Billing server |
| `2keyapp/2key-billing-sdks` | **Public** | CLI install docs, language wrappers, OpenAPI |
| `2keyapp/better-auth` | Public fork | Auth engine (sync from upstream) |

## Secret storage

Delegate Permissions packages **never** persist private keys. See [docs/SECRET_STORAGE.md](docs/SECRET_STORAGE.md).
