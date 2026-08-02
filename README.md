# dp-sdk

Product-neutral **Delegate Permissions** client SDKs for the hosted multi-tenant Auth + Billing platform.

This repo does **not** belong to any single product tenant. Tenants (including IDR) supply their own action/profile catalogs and PEPs; they depend on these SDKs for credential crypto and Admin/Device flows.

## Packages

| Package | Path | Role |
|---------|------|------|
| `@2key/dp-spec` | `packages/dp-spec` | Shared types + JSON Schema for CapabilityCredentials |
| `@2key/dp-ts` | `packages/dp-ts` | TypeScript Admin (+ Device helpers) SDK |
| `dp-rust` | `packages/dp-rust` | Rust Device/Agent SDK crate |
| `@2key/demo-catalog` | `examples/demo-catalog` | Non-product example catalog seed |

## Related servers

- Better Auth fork — `delegate-permissions` plugin (AuthN + AuthZ algebra + PKI issue)
- Billing — human seats + permanent machine seats (`seatBinder`)

## License

MIT
