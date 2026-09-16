# Architecture — Binary Private Core (native)

**Repo:** `2key-core-sdk` (private, **Rust only**)  
**Browser TS:** public [`2key-billing-sdks`](https://github.com/2keyapp/2key-billing-sdks) `packages/javascript/`  
**IDR wrap:** [`2keyapp/idr-agent`](https://github.com/2keyapp/idr-agent) (bakes `billing.idr.to`)  
**Wrappers / CLI fetch:** public [`2key-billing-sdks`](https://github.com/2keyapp/2key-billing-sdks)

```
┌─────────────────────────────────────────────────────────┐
│ PRIVATE: 2key-core-sdk                                  │
│  crates/2key_core  →  cdylib + rlib                     │
│  crates/2key_cli   →  two-key (Win / macOS / Linux)     │
│  packages/dp-rust* · dp-cli (library + generic bins)    │
│  Release assets + SHA256SUMS                            │
└───────────────┬─────────────────────────┬───────────────┘
                │ binaries only           │ path/git dep
                ▼                         ▼
┌───────────────────────────┐   ┌─────────────────────────┐
│ PUBLIC: 2key-billing-sdks │   │ PRIVATE: idr-agent      │
│  fetch two-key CLI        │   │  bins: idr, idr-agent   │
│  Dart + JS + catalogs     │   │  DP_PRODUCT_NAME=idr    │
└───────────────────────────┘   │  billing.idr.to/api/v1  │
                                └─────────────────────────┘
```

Machine HTTP is billing `/api/v1/machine-authn/*`. Login is Better Auth on the same host at `/api/auth`.

Naming: see [NAMING.md](NAMING.md). Product server: `2key-billing`. Auth fork: `better-auth`.
