# IDR Billing packages (catalog view)

Canonical commercial contract: [`2keyapp/billing` `IDR_BILLING_PACKAGES.md`](https://github.com/2keyapp/billing/blob/delegate_permissions/IDR_BILLING_PACKAGES.md).

| Package | Source AuthN | AuthZ summary |
|---------|--------------|---------------|
| Personal | mTLS required | Same-entity only; single-label host; profile `personal_root` / `machine` |
| Enterprise | mTLS required | Hierarchy, ZA, multi-admin, SCIM; `root_admin` / `zone_delegate` |
| Service Provider | Anonymous Sources allowed | Per-Target seat + optional `domain.alias` |
| Data Transfer | N/A | Target pays; to+from Target bytes on Relay/TURN |

Seed planCodes: `idr_personal_bundle`, `idr_enterprise_bundle`, `idr_sp_target`, `idr_data_transfer_1tb`.
