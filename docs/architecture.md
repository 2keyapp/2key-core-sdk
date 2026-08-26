# Architecture — Binary Private Core (native)

**Repo:** `2key-core-sdk` (private, **Rust only**)  
**Browser TS:** public [`2key-browser-sdk`](https://github.com/2keyapp/2key-browser-sdk)  
**Wrappers / CLI fetch:** public [`2key-billing-sdks`](https://github.com/2keyapp/2key-billing-sdks)

```
┌─────────────────────────────────────────────────────────┐
│ PRIVATE: 2key-core-sdk                                  │
│  crates/2key_core  →  cdylib + rlib                     │
│  crates/2key_cli   →  two-key (Win / macOS / Linux)     │
│  packages/dp-rust* · dp-cli                             │
│  Release assets + SHA256SUMS                            │
└───────────────────────┬─────────────────────────────────┘
                        │ binaries only
                        ▼
┌─────────────────────────────────────────────────────────┐
│ PUBLIC: 2key-billing-sdks                               │
│  scripts/fetch-binaries.*  →  bin/two-key               │
│  packages/dart, openapi, fixtures                       │
└─────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────┐
│ PUBLIC: 2key-browser-sdk                                │
│  @2key/browser-sdk · @2key/dp-* · catalogs              │
│  AuthN + AuthZ + Billing (TypeScript parity)            │
└─────────────────────────────────────────────────────────┘
```

Naming: see [NAMING.md](NAMING.md). Product server: `2key-billing`. Auth fork: `better-auth`.
