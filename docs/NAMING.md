# Naming: 2key-core-sdk

This repository is **`2key-core-sdk`** in all remotes, docs, and CI — **Rust native only**.

| Historical term | Current meaning |
|-----------------|-----------------|
| `dp-sdk` | Deprecated **repo** name. Rust DP lives here. TS lives in `2key-billing-sdks/packages/javascript/`. |
| `@2key/dp-*` | Delegate Permissions **npm packages** in **`2key-billing-sdks/packages/javascript/`**. |
| `@2key/browser-sdk` | Unified browser AuthN + AuthZ + Billing SDK (same JS workspace). |
| `2key-browser-sdk` | **Merged** into `2key-billing-sdks`. Do not open PRs there. |
| `two-key-core` | Private billing native core crate (Binary Private Core). |
| `two-key` / `two-key-cli` | Desktop **license** CLI released from this repo. |
| `idr` / `idr-agent` | IDR-branded DP lifecycle CLI + resident agent (`idr-agent` tenant repo wraps `dp-cli`). |

Do not create a separate public or private repo named `dp-sdk`.
