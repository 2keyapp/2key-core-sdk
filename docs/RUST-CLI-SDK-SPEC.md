# Rust CLI + SDK Specification

> Delegate Permissions — Machine Certificate Lifecycle CLI
>
> Product UX (`signup` / `register` / numbered `csr`, human vs machine vs mTLS)
> lives in [CLI-PRODUCT.md](./CLI-PRODUCT.md). This file is the **wire** contract
> (HTTP, keys, nested power commands). Do not change the plugin to match product
> verbs — map verbs onto these endpoints.

## Overview

A single Rust CLI binary that wraps `dp-rust` + `dp-rust-mtls` to perform the
full machine certificate lifecycle against a better-auth server running the
`delegate-permissions` plugin. Each product compiles with its own backend URL
and renames the binary (e.g. `idr`, `acme-agent`, etc.).

```
┌──────────────────────────────────┐
│  better-auth server              │
│  delegate-permissions plugin     │
│  (HTTP API)                      │
└──────────────┬───────────────────┘
               │
┌──────────────┴───────────────────┐
│  dp-rust-sdk  (library crate)    │
│  - HTTP client for DP endpoints  │
│  - CSR generation (Ed25519)      │
│  - Key storage abstraction       │
│  - Credential JWS sign/verify    │
│  - Enrollment + renew/decommission│
└──────────────┬───────────────────┘
               │
┌──────────────┴───────────────────┐
│  dp-cli  (binaries)              │
│  - Lifecycle: dp-cli / idr       │
│  - Agent: dp-agent / idr-agent   │
│  - Backend URL baked at compile  │
│  - Product renames the binary    │
└──────────────────────────────────┘
```

## Crate Layout

```
packages/
├── dp-rust/              # wire types (CapabilityCredential, etc.)
├── dp-rust-mtls/         # Ed25519, CSR, Entity CA, compact JWS, rustls
├── dp-rust-sdk/          # HTTP client + enrollment/lifecycle/session
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── client.rs     # reqwest → delegate-permissions
│       ├── types.rs      # request/response DTOs
│       ├── keystore.rs   # FileKeyStore + MemoryKeyStore
│       ├── enrollment.rs # enroll-create / enroll-instant state machine
│       ├── admin.rs      # Entity CA + local CSR signing
│       ├── credential.rs # CapabilityCredential JWS
│       ├── lifecycle.rs  # renew, decommission
│       ├── session.rs    # device-code + session file
│       ├── agent.rs      # load + verify platform-endorsed leaf
│       ├── identity.rs   # {name}{sep}{entity}
│       ├── config.rs
│       └── error.rs
└── dp-cli/
    ├── Cargo.toml        # bins: dp-cli, idr, dp-agent, idr-agent
    └── src/
        ├── main.rs       # lifecycle CLI
        ├── bin_agent.rs  # resident agent
        └── commands/     # auth, signup, register, csr, invite, org, …
```

Workspace members (root `Cargo.toml`): `dp-rust`, `dp-rust-mtls`, `dp-rust-sdk`, `dp-cli`.

## Server Endpoints (contract)

The CLI calls billing **Machine AuthN** under `/api/v1` (base URL like
`https://api.example.com/api/v1`). Legacy Better Auth `/api/auth/delegate-permissions/*`
is not used for IDR greenfield.

| CLI action | HTTP endpoint | Method |
|---|---|---|
| `org init` / `signup` / `init` | `/machine-authn/register` | POST |
| `register` / `machine enroll` | `/machine-authn/enroll-create` | POST |
| `register --local` / `gen` | `/machine-authn/enroll-instant` | POST |
| `invite` | `/machine-authn/enroll-invite` | POST |
| `register --invite` (preview) | `/machine-authn/enroll-invite` | GET |
| `machine status` | `/machine-authn/credential-status` | GET |
| `machine pull` | `/machine-authn/enroll-pull` | POST |
| `machine renew` | `/machine-authn/machine-renew` | POST |
| `machine decommission` | `/machine-authn/machine-decommission` | POST |
| `csr list` / `admin machine list` | `/machine-authn/enroll-list` | GET |
| `csr show` | `/machine-authn/enroll-get` (fallback: list) | GET |
| `csr approve` / `admin machine approve` | `/machine-authn/enroll-approve` | POST |
| `csr reject` / `admin machine reject` | `/machine-authn/enroll-reject` | POST |
| `admin machine revoke` | `/machine-authn/credential-revoke` | POST |
| `admin credential list` | `/machine-authn/credential-list` | GET |
| `platform root` | `/machine-authn/platform-root` | GET |
| catalog | `/machine-authn/catalog` | GET |
| enroll permissions (instant) | `/machine-authn/enroll-machine-permissions` | POST |
| `auth login` (device) | `{authBackend}/device/code`, `{authBackend}/device/token` | POST |
| `auth status` | `{authBackend}/get-session` | GET |

Billing v1 currently implements: `register`, `enroll-create` / `approve` / `pull` /
`enroll-invite`, `issue-delegate`, `assert-subset`, `platform-root`, `credential-status`.
Remaining rows are SDK-forward paths until the HTTP surface catches up.

Kickstart is **client-keyed** by default: the CLI generates Entity CA + Root Admin locally and POSTs public JWKs, signed credentials, and `caCertPem`. `--server-keys` on `org init` is test-only (`allowServerKeygen`).

## CLI Command Surface

### Build-time configuration

Copy [`.env.example`](../.env.example) for the full required vs optional list. Cargo does not load `.env` by itself.

**Required at product build** (baked into the binary via `option_env!`): `DP_BACKEND_URL`, `DP_PRODUCT_NAME`.

**Optional at product build:** `DP_SEPARATOR` (default `--`).

**Runtime only:** `DP_AUTH_TOKEN` (SSO cookie or Bearer; required for org/admin/enroll-instant), `DP_STATE_DIR` (default `~/.{product}`). Runtime env always overrides compiled defaults. Flags: `--backend-url`, `--token`, `--state-dir`.

```toml
# .cargo/config.toml (per-product)
[env]
DP_BACKEND_URL = "https://api.example.com/api/v1"
DP_PRODUCT_NAME = "idr"        # shown in --help, user agent
DP_SEPARATOR = "--"             # machine identity separator
```

### Command hierarchy

Product verbs (`auth`, `signup`, `register`, `csr`, `invite`) — see [CLI-PRODUCT.md](./CLI-PRODUCT.md).
Power surface below is the SDK mapping. `init` / `gen` are localhost aliases.

```
<exe>                                 # branded: idr (same crate as dp-cli)
├── init / gen                        # kickstart + enroll-instant
├── auth
│   ├── login [--paste] [--no-browser] [--client-id]
│   ├── status
│   └── logout
├── signup --personal | --domain <name> | --brand <slug>
├── register                          # machine enroll
│   --org <entity-id> <name>|--name
│   [--local]                         # enroll-instant
│   [--invite <token>]                # org from invite; still pass --name
│   [--wait] [--kind target|source]
├── csr                               # numbered enroll inbox
│   ├── list [--org] [--status pending]
│   ├── show <n|enroll-id>
│   ├── approve <n|enroll-id> [--yes]
│   └── reject <n|enroll-id> [--yes]
├── invite --org … [--uses N|--unlimited] [--expires-in]
├── org
│   ├── init <entity-id> [--package] [--server-keys]
│   └── status <entity-id>
│
├── machine
│   ├── enroll                        # Generate key + CSR, submit, wait for approval
│   │   --org <entity-id>
│   │   --name <machine-name>
│   │   [--kind target|source]        # default: target
│   │   [--wait]                      # poll until approved (or ctrl-c)
│   │   [--local|--instant] [--invite <token>]
│   │   [--key-algo ed25519]          # p256: not implemented
│   ├── status                        # Show current machine identity + cert info
│   ├── pull                          # Pull approved cert (if enroll was not --wait)
│   ├── renew                         # Generate new key, CSR, submit renewal
│   ├── rotate-key                    # Alias for renew (explicit key rotation)
│   ├── decommission                  # Self-decommission (authenticated via current cert)
│   ├── certificate                   # Show certificate details
│   │   [--format pem|text|json]
│   └── whoami                        # Print machine identity string
│
├── admin
│   └── machine
│       ├── list <entity-id>          # List pending enrollments
│       │   [--status pending|approved|rejected|all]
│       ├── show <request-id>         # Show enrollment request details
│       ├── approve <request-id>      # Sign CSR with Entity CA + approve
│       │   [--yes]                   # Skip confirmation
│       ├── reject <request-id>       # Reject enrollment
│       ├── revoke <ski>              # Revoke credential
│       │   [--reason <reason>]       # key_compromise|decommissioned|replaced|...
│       ├── decommission <ski>        # Decommission machine remotely
│       └── credentials <entity-id>   # List all credentials for entity
│           [--status active|revoked|all]
│
├── platform
│   └── root                          # Fetch + display Platform Root PEM
│       [--output <file>]             # Write PEM to file (for HAProxy ca-file)
│
└── version

<exe>-agent                           # idr-agent / dp-agent (separate bin)
    [--keep|--detach] [--pep-url]
```

## Machine Identity

```
machine_identity = <machine_name><separator><entity_id>
                    db1--acme.com
                    api.prod.eu--acme.com
                    router-01--acme.com
```

- `separator` is `--` (configurable at build time via `DP_SEPARATOR`)
- `machine_name`: lowercase ASCII, `a-z 0-9 . -`, cannot contain separator
- `entity_id`: lowercase, cannot contain separator
- Parsing is deterministic: split on first `<separator>` from the right

## Key Storage

### Abstraction (`keystore.rs`)

```rust
pub trait KeyStore: Send + Sync {
    fn save(&self, key: &str, value: &[u8]) -> Result<()>;
    fn load(&self, key: &str) -> Result<Option<Vec<u8>>>;
    fn delete(&self, key: &str) -> Result<()>;
    fn exists(&self, key: &str) -> Result<bool>;
}
```

### Default: file-system store

```
$DP_STATE_DIR/                     # default: ~/.dp/ or /var/lib/dp/
├── identity/
│   ├── machine.key                # PRIVATE — never leaves machine
│   ├── machine.csr                # CSR PEM (kept for audit)
│   ├── machine.crt                # Signed leaf certificate
│   ├── org-ca.crt                 # Entity CA certificate
│   ├── platform-ca.crt            # Platform Root certificate
│   ├── platform-endorsed.crt      # Platform-endorsed leaf (for mTLS)
│   └── chain.pem                  # Full chain for TLS presentation
├── admin/<entity>/                # Entity CA (signup / org init)
├── session                        # Human Better Auth session (JSON, 0600) — not machine keys
├── state.json                     # Machine state + enrollment metadata
└── config.json                    # Resolved config (backend URL, entity, etc.)
```

### `state.json`

```json
{
  "machine_identity": "db1--acme.com",
  "entity_id": "acme.com",
  "machine_name": "db1",
  "ski": "<subject-key-identifier>",
  "enrollment_id": "<enroll-id>",
  "pull_token": "<pull-token>",
  "status": "active",
  "cert_serial": "...",
  "cert_expires_at": "2026-11-17T00:00:00Z",
  "created_at": "2026-08-19T09:00:00Z",
  "renewed_from_ski": null
}
```

## Enrollment State Machine

```
UNINITIALIZED
│
│  machine enroll
▼
KEY_GENERATED
│
▼
CSR_CREATED
│
▼
ENROLLMENT_SUBMITTED
│
▼
PENDING_ADMIN
┌──┴────────────┐
│               │
▼               ▼
REJECTED        SIGNED
                │
                ▼
                CERT_RECEIVED
                │
                ▼
                CERT_VERIFIED
                │
                ▼
                ACTIVE
               / | \
              /  |  \
             ▼   ▼   ▼
        RENEWING  ROTATING  REVOKED
             │   │
             └─┬─┘
               ▼
             ACTIVE
               │
               ▼
          DECOMMISSIONED
```

This state machine must be persisted in `state.json` so the CLI can survive
process restarts (enrollment may take hours/days waiting for admin approval).

## Detailed Flows

### 1. `register` / `machine enroll --org acme.com --name db1`

Queued (device + remote admin):

```
1. Validate machine identity: db1--acme.com
2. Check state.json — abort if already enrolled
3. Generate Ed25519 keypair → save machine.key (never sent)
4. Generate PKCS#10 CSR with CN=db1--acme.com, SAN URI
5. POST /enroll-create { entityId, host: "db1--acme.com", kind, csrPem }
6. Save enrollment_id + pull_token to state.json, status=PENDING_ADMIN
7. If --wait: poll POST /enroll-pull until approved/rejected
8. On approved: verify local public key, save machine.crt + platform-endorsed.crt
```

Localhost (`register --local`, `gen`, or `machine enroll --instant`): same keygen, then sign with the local Entity CA and `POST /enroll-instant` (no inbox wait). Requires Entity CA in this `$DP_STATE_DIR`.

### 2. `admin machine approve <request-id>`

```
1. Fetch enrollment details from server
2. Display CSR fingerprint, machine identity, requester
3. Prompt "Approve? [Y/n]" (skip with --yes)
4. Load Entity CA private key (from admin's keystore)
5. Download CSR from enrollment
6. Sign CSR locally with Entity CA → leaf cert PEM
7. POST /enroll-approve { enrollId, leafPem, chainPem, credential, issuerSki }
8. Server platform-cosigns → returns platformCertPem
9. Print approval confirmation
```

### 3. `machine renew`

```
1. Check state.json — must be ACTIVE
2. Authenticate via current mTLS cert (proves identity)
3. Generate new keypair → save to machine.key.new
4. Generate new CSR with same identity
5. Have admin sign (or auto-sign if policy allows)
6. POST /machine-renew { ski, csrPem, leafPem, chainPem, credential, issuerSki }
7. On success:
   - Atomically swap: machine.key.new → machine.key, new certs → active
   - Update state.json: new SKI, status=ACTIVE, renewed_from_ski=old
   - Delete old key material
```

### 4. `machine decommission`

```
1. Authenticate via current mTLS cert
2. POST /machine-decommission { ski, reason: "decommissioned" }
3. Securely delete: machine.key, machine.crt, all cached certs
4. Update state.json status=DECOMMISSIONED
5. Retain state.json as audit metadata (no secrets)
```

### 5. `platform root --output /etc/haproxy/dp-ca.pem`

```
1. GET /platform-root
2. Write platformRootPem to file (or stdout)
3. Print SKI for verification
```

Use for HAProxy:
```
# haproxy.cfg
bind *:443 ssl crt /etc/haproxy/server.pem ca-file /etc/haproxy/dp-ca.pem verify required
```

## dp-rust-sdk Library API

```rust
pub struct DpClient {
    http: reqwest::Client,
    base_url: String,
    auth_token: Option<String>,
}

impl DpClient {
    pub fn new(base_url: &str) -> Self;
    pub fn with_auth(self, token: &str) -> Self; // Bearer or session cookie
    pub fn with_mtls(self, tls_config: rustls::ClientConfig) -> Self;

    // Entity
    pub async fn kickstart_entity(&self, req: &KickstartRequest) -> Result<KickstartResponse>;
    pub async fn get_entity(&self, entity_id: &str) -> Result<EntityResponse>;

    // Enrollment
    pub async fn enroll_create(&self, req: &EnrollCreateRequest) -> Result<EnrollCreateResponse>;
    pub async fn enroll_instant(&self, req: &EnrollInstantRequest) -> Result<EnrollInstantResponse>;
    pub async fn enroll_invite(&self, req: &EnrollInviteRequest) -> Result<EnrollInviteResponse>;
    pub async fn get_enroll_invite(&self, invite_token: &str) -> Result<EnrollInviteResponse>;
    pub async fn enroll_pull(&self, pull_token: &str) -> Result<EnrollPullResponse>;
    pub async fn enroll_approve(&self, req: &EnrollApproveRequest) -> Result<EnrollApproveResponse>;
    pub async fn enroll_reject(&self, enroll_id: &str) -> Result<()>;
    pub async fn enroll_list(&self, entity_id: &str, status: Option<&str>) -> Result<Vec<EnrollListItem>>;
    pub async fn enroll_get(&self, enroll_id: &str) -> Result<EnrollListItem>;
    pub async fn enroll_machine_permissions(&self, req: &MachinePermissionsRequest) -> Result<MachinePermissionsResponse>;

    // Lifecycle
    pub async fn credential_status(&self, ski: &str) -> Result<CredentialStatusResponse>;
    pub async fn credential_list(&self, entity_id: &str, status: Option<&str>) -> Result<Vec<CredentialListItem>>;
    pub async fn credential_revoke(&self, ski: &str, reason: &str) -> Result<RevokeResponse>;
    pub async fn machine_renew(&self, req: MachineRenewRequest) -> Result<MachineRenewResponse>;
    pub async fn machine_decommission(&self, ski: &str, reason: &str) -> Result<DecommissionResponse>;

    // Platform
    pub async fn platform_root(&self) -> Result<PlatformRootResponse>;
    pub async fn catalog(&self) -> Result<CatalogResponse>;

    // Human session (Better Auth, not DP)
    pub async fn device_code(...) -> Result<DeviceCodeResponse>;
    pub async fn get_session(&self) -> Result<Option<GetSessionResponse>>;
    pub async fn sign_out(&self) -> Result<()>;
}
```

## Build & Distribution

### Per-product build

```bash
# IDR
DP_BACKEND_URL="https://api.idr.to/api/auth" \
DP_PRODUCT_NAME="idr" \
cargo build --release -p dp-cli --bin idr --bin idr-agent

# Another product
DP_BACKEND_URL="https://api.acme.com/api/auth" \
DP_PRODUCT_NAME="acme" \
cargo build --release -p dp-cli --bin dp-cli
cp target/release/dp-cli acme
```

### Cross-compilation targets

- `x86_64-unknown-linux-gnu` (Linux servers)
- `x86_64-apple-darwin` / `aarch64-apple-darwin` (macOS)
- `x86_64-pc-windows-msvc` (Windows)
- `aarch64-unknown-linux-gnu` (ARM64 servers / Raspberry Pi)

### CI pipeline

```yaml
# .github/workflows/release.yml
strategy:
  matrix:
    target: [x86_64-unknown-linux-gnu, x86_64-apple-darwin, aarch64-apple-darwin]
steps:
  - cargo build --release --target ${{ matrix.target }} -p dp-cli
  - upload binary as release artifact
```

## Dependencies (dp-rust-sdk)

```toml
[dependencies]
dp-rust = { path = "../dp-rust" }
dp-rust-mtls = { path = "../dp-rust-mtls" }
reqwest = { version = "0.12", features = ["json", "rustls-tls"] }
serde = { version = "1", features = ["derive"] }
serde_json = { version = "1", features = ["preserve_order"] }
thiserror = "2"
tokio = { version = "1", features = ["macros", "rt-multi-thread", "time"] }
directories = "5"                    # default ~/.{product}
```

## Dependencies (dp-cli)

```toml
[dependencies]
dp-rust-sdk = { path = "../dp-rust-sdk" }
dp-rust-mtls = { path = "../dp-rust-mtls" }
clap = { version = "4", features = ["derive", "env"] }
tokio = { version = "1", features = ["full"] }
dialoguer = "0.11"
console = "0.15"
serde_json = "1"
```

## Security Considerations

1. **Private key never leaves the machine.** The CLI generates keys locally;
   only the CSR (public key + identity) is sent to the server.

2. **Admin signs locally.** The Entity CA private key stays with the admin.
   The server is an enrollment broker, not a key holder.

3. **Platform CA cosigns.** HAProxy trusts one Platform Root. The server
   cosigns every approved leaf so the TLS terminator can verify without
   knowing about individual entities or machines.

4. **Atomic key rotation.** During renewal, the old key stays active until
   the new cert is verified. Crash-safe: state.json tracks the transition.

5. **Secure deletion.** On decommission, keys are overwritten before unlink
   where the OS supports it.

6. **No secrets in state.json.** Only metadata (SKI, enrollment ID, status).
   Private keys are separate files with restricted permissions (0600).

## Testing Strategy

Step-by-step checks: [TEST-USECASES.md](./TEST-USECASES.md). There is no in-repo all-in-one live script.

- **Unit tests:** `cargo test -p dp-rust-sdk -p dp-rust-mtls -p dp-cli`
- **Plugin contract:** better-auth `e2e-smoke.test.ts`, `enroll.test.ts`
- **CLI vs a running server:** §2 localhost (`signup` + `register --local`) then `openssl verify` (§4)

## Status

Shipped: HTTP SDK, client-keyed kickstart, queued + instant enroll, numbered CSR inbox, `auth login`, `signup`, `invite`, renew/decommission, `platform root`, resident `idr-agent`.

Not yet: P-256 keys, per-product release CI, an in-repo HAProxy fixture.
