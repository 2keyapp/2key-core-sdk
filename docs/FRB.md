# FRB (flutter_rust_bridge 2.11.x)

Private `two-key-core` exposes [frb_api](../crates/2key_core/src/frb_api.rs) for
offline license verify and online license sync. Dart hosts own secure storage;
session JSON crosses the bridge.

## Generate (maintainers)

```bash
cargo install flutter_rust_bridge_codegen --version 2.11.1 --locked
flutter_rust_bridge_codegen generate --config-file flutter_rust_bridge.yaml
```

Vendor generated Dart into `2key-billing-sdks/packages/dart/lib/src/frb/`.
Until full codegen is committed, the public Dart SDK uses a wire adapter that
calls the matching C ABI (`two_key_*`) with the same JSON shapes.

## Offline / online

| Mode | FRB / FFI entry | Network |
|------|-----------------|---------|
| Offline | `frb_verify_license` / `frb_init_license` | No |
| Online | `frb_ensure_billing_context` + `frb_sync_license` | Yes |

## Releases

Ship `libtwo_key_core` / `two_key_core.dll` with Binary Private Core tags.
Public SDKs fetch via `core-binaries.lock.json`.
