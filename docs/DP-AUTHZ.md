# DP AuthZ — dual enforcement & package split

**Status:** In progress (algebra extracted)  
**Canonical pure algebra:** `@2key/dp-authorize` (TS) + `dp_rust::authorize` (Rust)  
**Conformance:** `conformance/dp-authz/fixtures.json`

## Model

```
Issue / revoke / enroll     →  server (billing host + BA plugin, moving into billing)
Local PEP (offline)         →  @2key/dp-authorize / dp-rust  (same fixtures)
Server PEP (mandatory)      →  same algebra in billing middleware / plugin
```

- Client `enforceLocally` / `authorize` filters requests for performance and offline UX.
- Server **always** re-checks. Client allow ≠ server allow if revoked/stale.
- Do **not** run a separate Rust AuthZ **server** next to Express; server stays TS.

## Packages

| Package | Repo | Role |
|---------|------|------|
| `@2key/dp-authorize` | `2key-core-sdk` | Pure authorize + subset + `enforceLocally` |
| `dp-rust` (`authorize` mod) | `2key-core-sdk` | Same algebra for CLI/agents |
| `@2key/dp-ts` / `dp-cli` | `2key-core-sdk` | Clients (call algebra before HTTP) |
| `delegate-permissions` plugin | better-auth → **move to billing** | Issue, DB, enroll, HTTP endpoints |
| Catalogs | `2key-core-sdk/catalogs/*` | Tenant seeds |

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

After the plugin lives in billing, middleware should:

1. Authenticate (session JWT or mTLS → principal).
2. Load CapabilitySet (session grant or cert-bound permissions).
3. `authorize(grants, action, resource, catalog)` from `@2key/dp-authorize` (path/git dep on core-sdk until published).
4. Only then run business logic / proxy upstream.

## Move plugin to billing — checklist

1. Copy `better-auth/.../delegate-permissions` → `2key-billing/packages/delegate-permissions` (or `src/plugins/`).
2. Depend on `better-auth` / `@better-auth/core` as peers; depend on `@2key/dp-authorize` for algebra (replace inlined `capability/*`).
3. Point billing `delegate-permissions.ts` imports at the local package.
4. Delete plugin from better-auth fork; keep only AuthN + `@2key/auth-native`.
5. CI: Vitest plugin tests in billing; conformance fixtures green in core-sdk (TS + Rust).

## Sync rule

Change AuthZ rules only in `@2key/dp-authorize` + `conformance/dp-authz/fixtures.json` + Rust `authorize` together.

Until the BA plugin imports `@2key/dp-authorize` (or moves to billing):

1. Edit algebra in `@2key/dp-authorize` first.
2. Mirror the same change into `better-auth/.../capability/*`.
3. Copy fixtures → `better-auth/.../capability/conformance.fixtures.json`.
4. Confirm BA `conformance.test.ts` and core-sdk TS/Rust fixture tests pass.
