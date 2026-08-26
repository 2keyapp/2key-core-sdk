# App-owned secret storage (policy)

**`2key-core-sdk` Rust DP packages do not persist secrets.** They accept in-memory identity / JWKs / PEMs only (`dp-rust`, `dp-rust-mtls`, `dp-rust-sdk`). TypeScript counterparts live in **`2key-browser-sdk`** with the same policy.

The **CLI and agent are the host** for a laptop or server: they write secrets under `$DP_STATE_DIR` (default `~/.{product}`):

| Path | What |
|------|------|
| `identity/machine.key` | Device Ed25519 (0600). Never sent. |
| `admin/<entity>/entity-ca.key` | Entity CA (signup / `org init`) |
| `session` | Human Better Auth cookie or Bearer (not a machine key) |

Do not treat `$DP_STATE_DIR` as a shared vault with a Flutter app. See the table below for embed/service hosts.

| Host | Recommended store | Notes |
|------|-------------------|--------|
| Flutter / Dart embed or Flutter CLI | [`flutter_secure_storage`](https://github.com/mogol/flutter_secure_storage) (or compatible forks) | See [`examples/dart-secure-storage`](../examples/dart-secure-storage/) |
| Rust Windows/Linux/macOS **service** | OS keyring / DPAPI, **or** this repo's CLI file store | `idr-agent` uses `$DP_STATE_DIR`. Other hosts stay outside `dp-rust` and inject identity at start |
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
  → 2key-core-sdk materializeMtlsClient / presenter
  → app PepConnector → PEP
```

Do **not** add `keyring`, DPAPI, or `flutter_secure_storage` dependencies to `packages/dp-*`.
