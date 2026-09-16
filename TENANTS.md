# Platform tenants

Canonical tenant registry and CatalogSeed packages (AuthZ actions/profiles) live in
**[`2key-billing-sdks`](https://github.com/2keyapp/2key-billing-sdks)** (`docs/TENANTS.md`, `packages/javascript/catalogs/`).

This private repo keeps Rust DP clients/CLIs only. Wire catalogs from npm/`@2key/catalog-*` at deploy time.

Shop prices/SKUs are **not** that AuthZ catalog. They live in tenant seed forks (`2key-idr-seed-templates`, …) as `catalog.json`.
