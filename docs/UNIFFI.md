# UniFFI (Phase 7) — private core notes

Public scaffolding lives in `2key-billing-sdks/bindings/uniffi/`.

When adding UniFFI here:

1. Prefer exposing `facade::TwoKeyClient` + JSON helpers already used by `ffi` / `c_api`.
2. Keep ABI versioning aligned with Binary Private Core releases.
3. Do not publish Rust source; ship generated Kotlin/Swift with release binaries.

Status: **not started** (C ABI only).
