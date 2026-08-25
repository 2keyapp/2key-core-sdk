# 2key-core-sdk

**Private** platform core for 2key Auth + Billing.

| Concern | Location | Role |
|---------|----------|------|
| **Billing native core** | `crates/2key_core` (`two-key-core`) | License verify/sync, session orchestration, FFI/C ABI — **binary-private**; never published as source to ISVs |
| **Billing CLI** | `crates/2key_cli` (`two-key`) | Desktop CLI (Windows / macOS / Linux) built and released as binaries |
| **Delegate Permissions** | `packages/*`, `catalogs/*` | CapabilityCredentials, mTLS presentation, tenant catalogs |

Public consumers never depend on this repo’s Rust source. They use:

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
| `dp-rust-mtls` | `packages/dp-rust-mtls` | Rust mTLS helpers |

> **Naming:** This repository is **`2key-core-sdk`** everywhere (docs, remotes, CI). Historical “dp-sdk” refers only to the Delegate Permissions *packages* under `packages/dp-*`, not a separate product repo.

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

## License

MIT (packages). Billing core release binaries are distributed under the terms set by 2key for ISV SDK packages — source remains private.
