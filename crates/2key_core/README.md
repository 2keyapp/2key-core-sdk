# two-key-core (`2key_core`)

**Private** native behavioral core for 2key Billing clients. Lives in **`2key-core-sdk`**.

- License JWT verify (ES256) + entitlement decode
- `/api/v1` HTTP (license ETag/304, subscriptions/me, plans)
- Session orchestration over injected storage ports
- C ABI / FFI surface for language wrappers (`c_api`, `ffi`, `facade`)

## Distribution

ISVs and the public [`2key-billing-sdks`](https://github.com/2keyapp/2key-billing-sdks) monorepo receive **prebuilt binaries only** (cdylib / static lib), not this source tree.

Host apps must **not** depend on this crate — use `2key_dart_sdk`, the `two-key` CLI, etc.

## Dev

```bash
cargo test -p two-key-core
cargo build -p two-key-core --release
```
