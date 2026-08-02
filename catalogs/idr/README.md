# IDR catalog (`@2key/catalog-idr`)

## Auth + Billing model

| Layer | Role |
|-------|------|
| **AuthN (humans)** | Better Auth sessions (admin console, SSO/org as needed) |
| **AuthN (machines)** | CapabilityCredential + client cert (mTLS / QUIC); platform cosign on Entity Root + Machine |
| **AuthZ** | `delegate-permissions` CapabilitySets from this catalog (`dns_prefix` FQHN hierarchy) |
| **Entitlement** | Billing human seats + permanent **machine seats** (`seatBinder`); Presence mux `entitlement_check` |
| **PEP** | **Presence** — Target registers over QUIC (`idr-presence-v1`) or WSS fallback with client identity; Presence calls Auth+Billing mux before allow |

```text
Target Agent
  → QUIC/WSS + client cert / credential
  → Presence (PEP)
       ├─ authorize(CapabilitySet, action, { entity, name, … })
       └─ entitlement_check → Auth+Billing (using_party / paying_party + target_fqhn)
```

## FQHN hierarchy

- Scope dimension `name` uses **dns_prefix** (DNS-like attenuation under the entity).
- Issue rules: ZA XOR Machine on a name; Machine requires fully-qualified host.
- Presence registry keys Targets by FQHN; aliases (custom domains) use `domain.alias`.

## Profiles

| Profile | Use |
|---------|-----|
| `root_admin` / `personal_root` | Entity kickstart |
| `interim_admin` | Invite-only admin |
| `zone_delegate` | Zone Authority |
| `machine` | Target Agent leaf |
| `machine_source` | Source Agent / browser Source |

See `ENTITLEMENT_ACTION_MAP` in `src/index.ts` for Presence ↔ catalog action names.
