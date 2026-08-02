# Platform tenants

Hosted multi-tenant Auth + Billing products. Each tenant is typically **one app deployment / one Postgres DB** (merchant isolation), with its own DP catalog seed in [`catalogs/`](catalogs/).

AuthN = Better Auth · AuthZ = `delegate-permissions` CapabilitySets · Entitlement = Billing seats (human + machine).

| Slug | Display | Catalog package | Auth + Billing model |
|------|---------|-----------------|----------------------|
| `demo` | Demo | `@2key/catalog-demo` | Example only — hierarchical host / machine seats |
| `scomm` | Scomm | `@2key/catalog-scomm` | **TBD** — discuss Auth + Billing |
| `idr` | IDR | `@2key/catalog-idr` | **TBD** — discuss Auth + Billing (DP PKI / Presence PEPs expected) |
| `os20` | OS20 | `@2key/catalog-os20` | **TBD** — discuss Auth + Billing |
| `stemsketch` | StemSketch | `@2key/catalog-stemsketch` | **TBD** — discuss Auth + Billing |
| `mnms` | MnMs | `@2key/catalog-mnms` | **TBD** — discuss Auth + Billing |

## Per-tenant checklist (when populating)

For each tenant, decide and document here:

1. **AuthN** — humans (email/OAuth/org/SCIM?), machines (mTLS + CapabilityCredential?)
2. **AuthZ catalog** — actions, scope dimensions, profiles → fill `catalogs/<slug>`
3. **Billing** — human seats vs machine seats, plan packaging, paying-party model
4. **PEPs** — where capability `authorize` + entitlement are enforced (product repos)
5. **Transports** — mTLS agent path vs browser WebRTC (app `PepConnector`)

## Related servers

- Better Auth fork — generic `delegate-permissions` (no product seeds in core)
- Billing — one merchant DB per deployment; wire `seatBinder` when machine seats apply
- Product / agent / web SDKs — tenant-owned; depend on `@2key/catalog-<slug>` + `dp-sdk`
