# dp-sdk

Product-neutral **Delegate Permissions** client SDKs for the hosted multi-tenant Auth + Billing platform.

This repo does **not** belong to any single product tenant. Tenants supply catalogs under [`catalogs/`](catalogs/) and PEPs in product repos; they depend on these SDKs for credential crypto, Admin/Device flows, and **mTLS presentation**.

## Packages

| Package | Path | Role |
|---------|------|------|
| `@2key/dp-spec` | `packages/dp-spec` | Shared types + JSON Schema for CapabilityCredentials |
| `@2key/dp-presentation` | `packages/dp-presentation` | Ports: `PepSession`, `PepConnector`, `CredentialPresenter`, `DeviceIdentity` |
| `@2key/dp-mtls` | `packages/dp-mtls` | Node mTLS: self-signed client cert + `tls.ConnectionOptions` |
| `@2key/dp-ts` | `packages/dp-ts` | TypeScript Admin (+ Device) SDK; re-exports presentation ports |
| `dp-rust` | `packages/dp-rust` | Rust credential wire types |
| `dp-rust-mtls` | `packages/dp-rust-mtls` | Rust mTLS: `rcgen` leaf + PEM load; `rustls::ClientConfig` via `--features rustls-config` |
| `dp-rust-sdk` | `packages/dp-rust-sdk` | HTTP client + enrollment/lifecycle against `delegate-permissions` |
| `dp-cli` | `packages/dp-cli` | Lifecycle CLI (`idr` / `dp-cli`) + resident agent (`idr-agent`) |

## Rust CLI (branded binary)

Same source for every product. Bake the backend and product name into the exe, then copy/rename it (`idr`, `acme`, …). See [`.env.example`](.env.example) for required vs optional variables.

**Required at product build**

| Variable | Example | Role |
|----------|---------|------|
| `DP_BACKEND_URL` | `https://api.idr.to/api/auth` | Better Auth base (no trailing slash) |
| `DP_PRODUCT_NAME` | `idr` | Help text, user-agent, default `~/.{name}` |

**Optional at product build**

| Variable | Default | Role |
|----------|---------|------|
| `DP_SEPARATOR` | `--` | Machine identity `{name}{sep}{entity}` |

**Runtime only** (never compiled in; also `--token` / `--state-dir` / `--backend-url`)

| Variable | Required when | Role |
|----------|----------------|------|
| `DP_AUTH_TOKEN` | `org`, admin, enroll-instant | Optional override. Prefer `idr auth login` (`$DP_STATE_DIR/session`). Cookie `better-auth.session_token=...` or Bearer |
| `DP_STATE_DIR` | optional | Keys + `state.json`. Default `~/.${DP_PRODUCT_NAME}` |
| `DP_BACKEND_URL` / `DP_PRODUCT_NAME` / `DP_SEPARATOR` | optional | Override compiled defaults |

Cargo does not load `.env`. Export the vars (or put build vars in `.cargo/config.toml`):

```bash
set -a && source .env && set +a
DP_BACKEND_URL="https://api.idr.to/api/auth" DP_PRODUCT_NAME="idr" \
  cargo build --release -p dp-cli --bin dp-cli --bin idr --bin idr-agent
# or: cp target/release/dp-cli idr
```

Product CLI (`auth login`, `signup`, `register`, `csr`, `invite`) plus power commands (`org`, `machine`, `init` / `gen`) and the resident agent (`idr-agent`): [docs/CLI-PRODUCT.md](docs/CLI-PRODUCT.md).

What to run for each use case (plugin tests, `idr init`/`register --local`, openssl, delegations, HAProxy handshake): [docs/TEST-USECASES.md](docs/TEST-USECASES.md).

## Tenant catalogs

See [`TENANTS.md`](TENANTS.md) and [`catalogs/`](catalogs/).

| Slug | Package |
|------|---------|
| `demo` | `@2key/catalog-demo` |
| `scomm` | `@2key/catalog-scomm` |
| `idr` | `@2key/catalog-idr` |
| `os20` | `@2key/catalog-os20` |
| `stemsketch` | `@2key/catalog-stemsketch` |
| `mnms` | `@2key/catalog-mnms` |

## Layering

| Concern | Owner |
|---------|--------|
| CapabilityCredential / keys / verify | `dp-spec`, `dp-ts`, `dp-rust` |
| Prove possession over **TLS client auth** | `dp-mtls`, `dp-rust-mtls` |
| Present credential for AuthZ (in-band frame) | `dp-presentation` (`createInBandCredentialPresenter`) |
| Tenant action/profile seeds | `catalogs/<slug>` |
| Open WebRTC / TCP / product session to PEP | **App** implements `PepConnector` |
| Persist private JWKs / credentials | **App** — see [docs/SECRET_STORAGE.md](docs/SECRET_STORAGE.md); Dart example in [`examples/dart-secure-storage`](examples/dart-secure-storage/) |
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

## Secret storage (app-owned)

Library packages (`dp-ts`, `dp-mtls`, `dp-rust`, `dp-rust-mtls`, `dp-rust-sdk`) **do not** persist private keys. The **CLI / agent** is the host: it writes keys under `$DP_STATE_DIR` (`identity/machine.key`, `admin/<entity>/`, `session`). See [docs/SECRET_STORAGE.md](docs/SECRET_STORAGE.md).

Dart/Flutter hosts: copy [`examples/dart-secure-storage`](examples/dart-secure-storage/) and wrap [`flutter_secure_storage`](https://pub.dev/packages/flutter_secure_storage). Other Rust services: OS keyring/DPAPI in the **host**, then inject `DeviceIdentity` into the SDK.

## Related servers

- Better Auth fork — `delegate-permissions` plugin (AuthN + AuthZ algebra + PKI issue)
- Billing — human seats + permanent machine seats (`seatBinder`)

## License

MIT
