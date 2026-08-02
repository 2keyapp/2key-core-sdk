# Tenant catalogs

Named **CatalogSeed** packages for hosted Auth + Billing tenants. Each folder slug is the stable `serviceId`.

| Slug | Display | Package | Status |
|------|---------|---------|--------|
| `demo` | Demo | `@2key/catalog-demo` | Example hierarchical-host seed |
| `scomm` | Scomm | `@2key/catalog-scomm` | Placeholder — Auth+Billing model TBD |
| `idr` | IDR | `@2key/catalog-idr` | Populated — see `catalogs/idr/README.md` |
| `os20` | OS20 | `@2key/catalog-os20` | Placeholder — Auth+Billing model TBD |
| `stemsketch` | StemSketch | `@2key/catalog-stemsketch` | Placeholder — Auth+Billing model TBD |
| `mnms` | MnMs | `@2key/catalog-mnms` | Placeholder — Auth+Billing model TBD |

## Usage

```ts
import { CATALOG_SEED, SERVICE_ID } from "@2key/catalog-idr";

delegatePermissions({
  serviceId: SERVICE_ID,
  seed: CATALOG_SEED,
});
```

Do **not** add tenant string shortcuts (`"idr"`, `"scomm"`, …) to the Better Auth plugin. Wire the catalog package at deploy time.

See [TENANTS.md](../TENANTS.md) for Auth + Billing model notes per tenant.
