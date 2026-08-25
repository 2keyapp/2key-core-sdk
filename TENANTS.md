# Platform tenants

Hosted multi-tenant Auth + Billing products. Each tenant is typically **one app deployment / one Postgres DB** (merchant isolation), with its own DP catalog seed in [`catalogs/`](catalogs/).

AuthN = Better Auth · AuthZ = `delegate-permissions` CapabilitySets · Entitlement = Billing seats (human + machine).

| Slug | Display | Catalog package | Auth + Billing model |
|------|---------|-----------------|----------------------|
| `demo` | Demo | `@2key/catalog-demo` | Example only — hierarchical host / machine seats |
| `scomm` | Scomm | `@2key/catalog-scomm` | **TBD** — discuss Auth + Billing |
| `idr` | IDR | `@2key/catalog-idr` | **Populated** — Personal/Enterprise/SP + Data Transfer UBB; see `catalogs/idr/BILLING_PACKAGES.md` |
| `os20` | OS20 | `@2key/catalog-os20` | **TBD** — discuss Auth + Billing |
| `stemsketch` | StemSketch | `@2key/catalog-stemsketch` | **TBD** — discuss Auth + Billing |
| `mnms` | MnMs | `@2key/catalog-mnms` | **TBD** — discuss Auth + Billing |

## IDR (detailed)

Canonical notes: [`catalogs/idr/README.md`](catalogs/idr/README.md).

1. **AuthN** — Humans: Better Auth. Machines (Target/Source): CapabilityCredential + client cert; platform cosign on Entity Root + Machine leaf.
2. **AuthZ** — `@2key/catalog-idr` (FQHN `dns_prefix` hierarchy; Presence/session/TURN/ACL actions).
3. **Billing** — Human seats + permanent machine seats; Presence mux `entitlement_check` with `using_party` / `paying_party`.
4. **PEP** — Presence (QUIC primary / WSS fallback); compose `capability AND entitlement`.
5. **Transports** — Target→Presence: QUIC/WSS + cert (SDK mTLS helpers). WebRTC Source path: app `PepConnector` + in-band credential presenter.

## Related servers

- Better Auth fork — generic `delegate-permissions` (no product seeds in core)
- Billing — one merchant DB per deployment; wire `seatBinder` when machine seats apply
- Product / agent / web SDKs — tenant-owned; depend on `@2key/catalog-<slug>` + packages from **`2key-core-sdk`** (`@2key/dp-*`)
