# dp-sdk

Product-neutral **Delegate Permissions** client SDKs for the hosted multi-tenant Auth + Billing platform.

This repo does **not** belong to any single product tenant. Tenants supply their own action/profile catalogs and PEPs; they depend on these SDKs for credential crypto, Admin/Device flows, and **mTLS presentation**. App transports (WebRTC, signaling, Presence URLs) stay outside this repo behind ports.

## Packages

| Package | Path | Role |
|---------|------|------|
| `@2key/dp-spec` | `packages/dp-spec` | Shared types + JSON Schema for CapabilityCredentials |
| `@2key/dp-presentation` | `packages/dp-presentation` | Ports: `PepSession`, `PepConnector`, `CredentialPresenter`, `DeviceIdentity` |
| `@2key/dp-mtls` | `packages/dp-mtls` | Node mTLS: self-signed client cert + `tls.ConnectionOptions` |
| `@2key/dp-ts` | `packages/dp-ts` | TypeScript Admin (+ Device) SDK; re-exports presentation ports |
| `dp-rust` | `packages/dp-rust` | Rust credential wire types |
| `dp-rust-mtls` | `packages/dp-rust-mtls` | Rust mTLS: `rcgen` leaf + PEM load; `rustls::ClientConfig` via `--features rustls-config` |
| `@2key/demo-catalog` | `examples/demo-catalog` | Non-product example catalog seed |

## Layering

| Concern | Owner |
|---------|--------|
| CapabilityCredential / keys / verify | `dp-spec`, `dp-ts`, `dp-rust` |
| Prove possession over **TLS client auth** | `dp-mtls`, `dp-rust-mtls` |
| Present credential for AuthZ (in-band frame) | `dp-presentation` (`createInBandCredentialPresenter`) |
| Open WebRTC / TCP / product session to PEP | **App** implements `PepConnector` |
| ICE, signaling, Presence URLs | **App / tenant** — not in this SDK |

**AuthN vs AuthZ:** mTLS client cert proves key possession (SKI in URI SAN `urn:dp:ski:…`). CapabilityCredential is sent as the first app frame (`dp.credential.v1`) for AuthZ.

```text
DeviceIdentity
    ├─ materializeMtlsClient()  →  MtlsClientMaterial  →  app PepConnector (TCP+TLS)
    └─ createInBandCredentialPresenter().present(session)
         (also used alone when the app transport is WebRTC / no client certs)
```

### App WebRTC adapter (sketch — not shipped)

```ts
// In the product SDK, not dp-sdk:
const connector: PepConnector = {
  async connect({ entityId, host }) {
    const pc = new RTCPeerConnection(/* app ICE */);
    const dc = pc.createDataChannel("dp");
    // ... product signaling ...
    return {
      send: async (frame) => { dc.send(frame); },
      onFrame: (handler) => { dc.onmessage = (e) => handler(new Uint8Array(e.data)); return () => {}; },
      close: async () => { dc.close(); pc.close(); },
    };
  },
};
await createInBandCredentialPresenter().present(session, identity);
```

## Related servers

- Better Auth fork — `delegate-permissions` plugin (AuthN + AuthZ algebra + PKI issue)
- Billing — human seats + permanent machine seats (`seatBinder`)

## License

MIT
