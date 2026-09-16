# DP AuthZ — dual enforcement & package split

**Status:** In progress (algebra extracted)  
**Canonical pure algebra:** `@2key/dp-authorize` (TS in `2key-billing-sdks/packages/javascript`) + `dp_rust::authorize` (Rust, this repo)  
**Conformance:** `conformance/dp-authz/fixtures.json` (keep in sync with `2key-billing-sdks` — that copy is canonical for TS)

## Model

```
Issue / revoke / enroll     →  billing `/api/v1/machine-authn/*` + `devices`
Local PEP (offline)         →  @2key/dp-authorize / dp-rust  (same fixtures)
Server PEP (mandatory)      →  same algebra in billing middleware
```

- Client `enforceLocally` / `authorize` filters requests for performance and offline UX.
- Server **always** re-checks. Client allow ≠ server allow if revoked/stale.
- Do **not** run a separate Rust AuthZ **server** next to Express; server stays TS.

### Algebra v2

| Algebra | Use |
|---------|-----|
| `exact` | Identity equality |
| `dns_prefix` | IDR FQHN / leftward labels |
| `path_prefix` | Rightward paths (`@acme/pkg/...`); segment-bounded |
| `set` | Enumerated membership |
| `semver` | Exact version vs range; range ⊆ range (closed v1 grammar) |

Capabilities may set `effect: "deny"` (default `"allow"`). Matching deny wins (`EXPLICIT_DENY`). See better-auth `docs/adr/0002-dp-algebra-v2.md`.

## Packages

| Package | Repo | Role |
|---------|------|------|
| `@2key/dp-authorize` | `2key-billing-sdks` JS workspace | Pure authorize + subset + `enforceLocally` |
| `dp-rust` (`authorize` mod) | `2key-core-sdk` | Same algebra for CLI/agents |
| `@2key/dp-ts` | `2key-billing-sdks` JS workspace | TS clients (call algebra before HTTP) |
| `dp-cli` | `2key-core-sdk` | Rust CLI / agents (tenants wrap, e.g. `idr-agent`) |
| Machine AuthN HTTP + `devices` | **billing** | Issue, enroll, CSR approve (owner-only) |
| Catalogs (AuthZ) | `2key-billing-sdks/packages/javascript/catalogs/*` | Tenant action/profile seeds |

## Client usage (gate before service call)

```ts
import { enforceLocally, assertAuthorized } from "@2key/dp-authorize";

const result = enforceLocally({
  grants: credential.permissions,
  action: "machine.connect",
  resource: { name: "db1.zone6.us-east", entity: "amazon.com" },
  catalog,
  credentialCatalogGeneration: catalog.generation,
});
if (!result.ok) return; // do not call the service

// or:
assertAuthorized({ ... }); // throws DpNotAuthorizedError
await fetch(serviceUrl, ...);
```

## Server usage (billing)

Machine AuthN HTTP already lives in billing (`/api/v1/machine-authn/*`). Middleware should:

1. Authenticate (session JWT or mTLS → principal).
2. Load CapabilitySet (session grant or cert-bound permissions).
3. `authorize(grants, action, resource, catalog)` from `@2key/dp-authorize`.
4. Only then run business logic / proxy upstream.

CSR approve / enroll-invite remain **owner only** (`OWNER_REQUIRED`).

## Better Auth (utility only)

`better-auth/plugins/delegate-permissions` exports **algebra + PKI helpers**. Billing does not mount the HTTP plugin (`plugin.ts` is in-repo BA tests only). Machine AuthN HTTP, `devices` / Org CA, Host cosign, and owner-only CSR approve stay on billing `/api/v1/machine-authn/*`. Do not add `/delegate-permissions/*` routes.

## Sync rule

Change AuthZ rules only in `@2key/dp-authorize` + `conformance/dp-authz/fixtures.json` + Rust `authorize` together. Confirm `2key-billing-sdks` TS tests and core-sdk `cargo test -p dp-rust` both pass.
