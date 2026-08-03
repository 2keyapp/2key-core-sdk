# IDR catalog (`@2key/catalog-idr`)

## Auth + Billing model

| Layer | Role |
|-------|------|
| **AuthN (humans)** | Better Auth sessions (admin console, SSO/org as needed) |
| **AuthN (machines)** | CapabilityCredential + client cert (mTLS / QUIC); platform cosign on Entity Root + Machine |
| **AuthZ** | `delegate-permissions` CapabilitySets from this catalog (`dns_prefix` FQHN hierarchy) |
| **Entitlement** | Billing human seats + permanent **machine seats** (`seatBinder`); Target Agent mints Presence entitlement JWT; Data Transfer UBB |
| **PEP** | **Presence** — Target registers over QUIC (`idr-presence-v1`) or WSS fallback; JWKS-verify JWT and authorize actions in-process |

```text
Target Agent
  → POST https://auth.idr.to/api/auth/agent/token
       (CapabilityCredential + EdDSA PoP)
  → Auth+Billing mints Presence entitlement JWT (aud=presence)
  → QUIC/WSS register_target { entitlement_jwt, … }
  → Presence (PEP)
       ├─ verify JWT via GET /api/auth/jwks
       ├─ cache claims on TargetSession
       └─ authorize(register | accept_session | ensure_relay | mint_turn)
```

There is **no** Presence↔Billing WSS mux / `entitlement_check` RPC. Relay/TURN still report usage via HTTP `POST /api/v1/usage/report`.

**Remaining (catalog/billing ops):** wire this package into the Billing DP plugin (still demo seed today); production `auth.idr.to` reverse-proxy DNS; re-add remote disconnect, dynamic CA-root push, and domain-alias push on a new channel.

## Commercial packages

See [BILLING_PACKAGES.md](./BILLING_PACKAGES.md).

| Package | Price (list) | Notes |
|---------|--------------|-------|
| Personal Bundle | US$10 / yr | ≤5 Targets; Source mTLS; same-entity ACL; single-label hosts |
| Enterprise Bundle | US$50 / yr | ≤5 Targets; hierarchy, multi-admin, SCIM, separate payer |
| Service Provider Target | US$50 / yr / Target | Optional CNAME; **anonymous Sources allowed** |
| Data Transfer | US$10 / TB (1 yr) | **Target pays**; to+from Target; Sources not billed |

## FQHN hierarchy

- Scope dimension `name` uses **dns_prefix** (DNS-like attenuation under the entity).
- **Personal:** single-label host only; same entity → same entity AuthZ.
- **Enterprise:** full hierarchy; ZA XOR Machine on a name; Machine requires fully-qualified host.
- Presence registry keys Targets by FQHN; aliases (custom domains) use `domain.alias` (**alias push to Presence not yet re-implemented** after mux removal).

## Profiles

| Profile | Use |
|---------|-----|
| `root_admin` / `personal_root` | Entity kickstart (enterprise vs personal) |
| `interim_admin` | Invite-only admin (Enterprise) |
| `zone_delegate` | Zone Authority (Enterprise) |
| `machine` | Target Agent leaf |
| `machine_source` | Source Agent / browser Source (mTLS for Personal/Enterprise) |

See `ENTITLEMENT_ACTION_MAP` in `src/index.ts` for Presence ↔ catalog action names.
