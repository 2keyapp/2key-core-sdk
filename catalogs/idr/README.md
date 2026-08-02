# IDR catalog (`@2key/catalog-idr`)

## Auth + Billing model

| Layer | Role |
|-------|------|
| **AuthN (humans)** | Better Auth sessions (admin console, SSO/org as needed) |
| **AuthN (machines)** | CapabilityCredential + client cert (mTLS / QUIC); platform cosign on Entity Root + Machine |
| **AuthZ** | `delegate-permissions` CapabilitySets from this catalog (`dns_prefix` FQHN hierarchy) |
| **Entitlement** | Billing human seats + permanent **machine seats** (`seatBinder`); Presence mux `entitlement_check`; Data Transfer UBB |
| **PEP** | **Presence** — Target registers over QUIC (`idr-presence-v1`) or WSS fallback; compose capability AND entitlement |

```text
Target Agent
  → QUIC/WSS + client cert / credential
  → Presence (PEP)
       ├─ authorize(CapabilitySet, action, { entity, name, … })
       └─ entitlement_check → Auth+Billing (using_party / paying_party + target_fqhn)
```

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
- Presence registry keys Targets by FQHN; aliases (custom domains) use `domain.alias`.

## Profiles

| Profile | Use |
|---------|-----|
| `root_admin` / `personal_root` | Entity kickstart (enterprise vs personal) |
| `interim_admin` | Invite-only admin (Enterprise) |
| `zone_delegate` | Zone Authority (Enterprise) |
| `machine` | Target Agent leaf |
| `machine_source` | Source Agent / browser Source (mTLS for Personal/Enterprise) |

See `ENTITLEMENT_ACTION_MAP` in `src/index.ts` for Presence ↔ catalog action names.
