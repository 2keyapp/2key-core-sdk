# Architecture — Binary Private Core

**Repo:** `2key-core-sdk` (private)  
**Related public:** `2key-billing-sdks` (CLI + wrappers only)

```
┌─────────────────────────────────────────────────────────┐
│ PRIVATE: 2key-core-sdk                                  │
│  crates/2key_core  →  cdylib + rlib                     │
│  crates/2key_cli   →  two-key (Win / macOS / Linux)     │
│  packages/@2key/dp-*  catalogs/*                        │
│  Release assets + SHA256SUMS                            │
└───────────────────────┬─────────────────────────────────┘
                        │ binaries only
                        ▼
┌─────────────────────────────────────────────────────────┐
│ PUBLIC: 2key-billing-sdks                               │
│  scripts/fetch-binaries.*  →  bin/two-key               │
│  packages/dart, packages/ts, openapi, fixtures          │
└─────────────────────────────────────────────────────────┘
```

Naming: see [NAMING.md](NAMING.md). Product server: `2key-billing`. Auth fork: `better-auth`.
