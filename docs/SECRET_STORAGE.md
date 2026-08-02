# App-owned secret storage (policy)

**`dp-sdk` does not persist secrets.** Packages accept in-memory `DeviceIdentity` / JWKs / PEMs only.

| Host | Recommended store | Notes |
|------|-------------------|--------|
| Flutter / Dart embed or Flutter CLI | [`flutter_secure_storage`](https://github.com/mogol/flutter_secure_storage) (or compatible forks) | See [`examples/dart-secure-storage`](../examples/dart-secure-storage/) |
| Rust Windows/Linux/macOS **service** | OS keyring / DPAPI via host adapter | Live **outside** `dp-rust`; inject identity at process start |
| Tests | In-memory map | Never log private JWKs |

## Why not inside the SDK?

- Storage backends differ by runtime (Flutter plugin ≠ headless service).
- Flutter secure storage and a standalone agent service **do not share** a vault unless you build an explicit bridge.
- Same pattern as `PepConnector`: app owns the host concern; SDK owns crypto/presentation.

## Stable key names (suggested)

Use a tenant/product prefix so CLI and app agree:

| Key | Value |
|-----|--------|
| `{prefix}.ski` | Subject key id |
| `{prefix}.private_jwk` | JSON Ed25519 private JWK |
| `{prefix}.public_jwk` | JSON public JWK (optional) |
| `{prefix}.credential` | JSON CapabilityCredential |
| `{prefix}.fqhn` | Target/Source host name (optional) |

Example prefix: `idr.dp`.

## Flow

```text
App SecretStore.load()
  → DeviceIdentity (in memory)
  → dp-sdk materializeMtlsClient / presenter
  → app PepConnector → PEP
```

Do **not** add `keyring`, DPAPI, or `flutter_secure_storage` dependencies to `packages/dp-*`.
