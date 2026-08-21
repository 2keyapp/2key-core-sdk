# Product CLI (`idr`) — spec

This is the source of truth for **how the branded binary should feel**. The Better Auth `delegate-permissions` plugin is **frozen** except enroll-invite (Phase 4). All other work is CLI + `dp-rust-sdk` + a separate agent binary.

Wire protocol, PKI, and HTTP paths stay in [RUST-CLI-SDK-SPEC.md](./RUST-CLI-SDK-SPEC.md). This document is the product layer: **what** the human types, **why** that command exists, **how** it maps onto the plugin, and the **flow** on the machine.

Inspired by `/home/dev2t/Documents/cli.txt` (`gh`-like `signup` / `register` / numbered CSR approve / default-as-service). That note is UX intent, not an API redesign.

---

## 1. What we are building

A single compiled binary per product (`idr`, later `acme`, …) that a person copies onto `PATH`.

Three jobs, in this order of identity:

| Job | Who | AuthN | AuthZ |
|-----|-----|--------|--------|
| Human onboarding | Admin in a browser | Better Auth session (SSO / email) | Principal grant + Root Admin bind |
| Machine enrollment | The device | PKCS#10 CSR → Platform-endorsed leaf | CapabilityCredential issued at approve |
| Machine runtime | Target/Source agent | mTLS to the terminator (HAProxy `ca-file` = Platform Root) | First app frame `dp.credential.v1` |

The CLI today is a **lifecycle tool** (jobs 1–2). Job 3 is the separate `idr-agent` / `dp-agent` binary (`--keep` / `--detach`), not a clap flag on the lifecycle CLI.

### Non-goals (plugin stays as-is)

- Do not add “public JWK attached to PKCE” on the plugin. PKCE/device-code is Better Auth. Kickstart is `POST /delegate-permissions/kickstart-entity` with **client-generated** Entity CA + Root Admin material.
- Do not send machine private keys. Ever.
- Do not use `laptop1.slug.org` on the wire. Plugin host form is `{path}--{entityId}` (see plugin `names.ts`). Display suffixes are product cosmetics, stripped before HTTP.
- Do not make Better Auth terminate client certificates. HAProxy (or equivalent) does mTLS AuthN.

---

## 2. Why three keypairs (do not collapse them)

`cli.txt` said: on signup, generate a keypair and send the public key with the PKCE token. That sentence mixes three keys. If we use one key for all three, HAProxy and Entity CA both break.

```text
Human session          Better Auth user id (cookie / device-code)
        │
        ▼
Entity CA + Root Admin keys     generated on the admin laptop at signup/init
        │                       private keys stay in $DP_STATE_DIR/admin/<entity>/
        ▼
Machine key + CSR               generated on the device at register
                                private key stays in $DP_STATE_DIR/identity/machine.key
        │
        ▼
platform-endorsed.crt           Platform CA X.509-signs the SAME machine public key
                                this is what HAProxy verifies against platform-root
```

**Why:** kickstart binds the **session user** to a Root Admin credential (`bindUserCredential`). The Entity CA signs device leaves. The Platform CA endorses the leaf so every tenant’s machines share one `ca-file`. Mixing signup’s key with the machine key would put the Entity CA on every laptop and make `register` meaningless.

**How (already true in `org init`):** `prepare_client_keyed_kickstart` creates Entity CA + admin JWKs locally, POSTs public JWKs + signed credentials + `caCertPem`. Server never sees admin/machine private keys.

---

## 3. Command surfaces

Two layers, same SDK:

| Surface | Audience | Style |
|---------|----------|--------|
| **Product** | Humans, `gh`-like | `auth login`, `signup`, `register`, `csr`, `csr approve 2` |
| **Power** | Tests, scripts, this repo | `org init`, `machine enroll`, `admin machine approve <id>` |

Power commands stay. Product commands are thin wrappers (Phase 1) then real flows (Phases 2–3). Convenience `init` / `gen` stay for the localhost litmus (`TEST-USECASES.md`).

### Wire names vs display names

| User types | On the wire |
|------------|-------------|
| `laptop1` + org `acme.com` | `host: "laptop1--acme.com"` |
| `mob1` | `mob1--acme.com` |
| Optional product suffix `.idr.to` in UI | Strip before plugin (documented in public plugin docs) |

**Why `--`:** plugin `parseMachineHost` and catalog `dns_prefix` attenuation. Dots inside the **path** are hierarchy (`db1.us-east--acme.com`), not a DNS zone of the SaaS.

---

## 4. End-state command map

```text
<exe>                          # branded: idr
├── auth
│   ├── login                  # Phase 2 — Better Auth device/OAuth → session file
│   ├── status                 # Phase 2 — who is the session user
│   └── logout                 # Phase 2
├── signup                     # Phase 3 — login (if needed) + kickstart-entity
│   ├── [--personal]           # entityId = session email
│   ├── [--domain <name>]      # entityId = domain, package=enterprise
│   └── [--brand <slug>]       # entityId = brand slug, package=enterprise
├── register <name>            # Phase 1 — machine enroll (CSR inbox)
│   ├── --org <entity>
│   ├── [--local]              # enroll-instant (localhost / same host as Entity CA)
│   ├── [--kind target|source]
│   ├── [--wait]
│   └── [--invite <token>]     # Phase 4 — org from invite; still pass --name
├── csr                        # Phase 1 — numbered enrollment inbox
│   ├── list [--org] [--status pending]
│   ├── show <n|id>
│   ├── approve <n|id> [--yes]
│   └── reject <n|id> [--yes]
├── invite --org …             # Phase 4 — org token; device names itself at register
├── idr-agent [--keep|--detach] [--pep-url]   # Phase 5 — default: this terminal until ctrl-c
│
├── org / machine / admin / platform / init / gen / version   # power surface (exists)
└── whoami / status / pull / renew / decommission             # keep under machine
```

Installer (“copy `idr.exe` onto PATH”) is packaging, not this crate.

---

## 5. Phases

### Phase 1 — Product aliases + numbered CSR inbox  **(done)**

**What**

- `register` = today’s `machine enroll`.
- `register --local` = today’s `gen` / `enroll --instant`.
- `csr list` prints a **1-based** table of pending CSRs.
- `csr approve 2` / `csr reject 2` resolve the index against that same filtered list, then call existing `admin machine approve|reject`.
- Nested `org` / `machine` / `admin` commands unchanged.

**Why**

`cli.txt` wants `gh`-shaped verbs and “Approve 2”, not enroll UUIDs. The plugin already has `enroll-list` + `enroll-approve`. Indexing is a CLI presentation concern. Doing this first proves the mapping without inventing HTTP.

**How**

1. Device: `idr register --org acme.com --name laptop1`
   - Generate Ed25519 in `identity/machine.key`.
   - CSR CN/SAN = `laptop1--acme.com`.
   - `POST /delegate-permissions/enroll-create` `{ entityId, host, kind, csrPem }`.
   - Persist `enrollId` + `pullToken` in `state.json`, status pending.
2. Admin (other state dir, or same host for tests): `idr csr list --org acme.com`
   - `GET /delegate-permissions/enroll-list?entityId=acme.com&status=pending`.
   - Print `#`, host, status, enroll id (truncated).
3. Admin: `idr csr approve 2 --org acme.com`
   - Load row 2 (stable order: enroll id).
   - Load Entity CA from `admin/acme.com/`.
   - Sign CSR locally, `POST /enroll-approve`.
   - Server Platform-cosigns; device `idr machine pull` (or `--wait`).

**Org inference:** if `--org` omitted and `$DP_STATE_DIR/admin/` contains exactly one entity, use it. Otherwise require `--org`.

**Index vs id:** if the selector is all digits, treat as 1-based index into the **current** filtered list. Otherwise treat as `enrollId`. Reject out-of-range with the printed table.

**Localhost bypass:** `register --local` requires Entity CA in this state dir (same as `gen`). No new plugin path.

---

### Phase 2 — `auth login` (Better Auth, not DP)  **(done)**

**What**

Replace pasted `DP_AUTH_TOKEN` for humans. Store a session next to keys. `auth status` / `logout`.

**Why**

Kickstart, CSR approve, and signup all need a Better Auth **session**. Today operators paste a cookie. `gh auth login` is the UX we want. That session is **human AuthN**. It is not mTLS and not a machine key.

**How (do not change `delegate-permissions`)**

Preferred: RFC 8628 device authorization (`POST /device/code`, poll `/device/token`). Token is Better Auth `session.token` as `access_token`. Send it as `Authorization: Bearer` — the product auth server should enable **`deviceAuthorization()` and `bearer()`** next to `delegatePermissions()`.

```text
idr auth login
  → POST {backend}/device/code  { client_id }     # default `{product}-cli` or DP_CLIENT_ID
  → print user_code + verification_uri (open browser unless --no-browser)
  → poll /device/token until approved (ctrl-c cancels)
  → write $DP_STATE_DIR/session  (JSON, 0600) — not state.json
  → GET /get-session → print email
```

`--paste`: skip device flow, store a browser cookie (`better-auth.session_token=…`) or Bearer token. Used when the auth server has no device plugin; `auth login` also falls back to paste on 4xx from `/device/code` if stdin is a TTY (`--no-paste` disables that).

Precedence: `--token` / `DP_AUTH_TOKEN` **wins** over the session file. Machine `register` (non-`--local`) still does not need a session.

**Product auth config (outside this crate):** enable `deviceAuthorization()` + `bearer()`. If `validateClient` is set, allow `{product}-cli` (or `DP_CLIENT_ID`).

**Implemented commands:** `idr auth login`, `idr auth status`, `idr auth logout`.

---

### Phase 3 — `signup`  **(done)**

**What**

One verb for “I am a new admin; create my org.”

```text
idr signup --personal              # entityId = session user email, package=personal
idr signup --domain acme.com       # entityId = acme.com, package=enterprise
idr signup --brand acme            # entityId = acme, package=enterprise
```

Flags are mutually exclusive. Requires `auth login`. Always client-keyed (`--server-keys` stays on `org init`). If the entity already exists locally, prints the existing CA.

**Why**

`cli.txt`: register org from email; different signup for domain vs brand slugs. The plugin already takes `entityId` + `package`. Email-as-entity is the **personal** package (`host--email` in IDR notes). Domain/brand are **enterprise** `entityId` strings. There is no slug registry in DP; uniqueness is `createEntity` conflict (`ENTITY_EXISTS`).

**How**

```text
1. Ensure session (auth login if session file missing).
2. GET /get-session → user.email (required for --personal).
3. Resolve entityId:
     --personal → email.lower()
     --domain X / --brand X → X.lower()
4. Same path as org init (client-keyed kickstart):
     generate Entity CA + Root Admin locally
     POST /kickstart-entity { entityId, package, rootPublicJwk, adminPublicJwk,
                              rootCredential, adminCredential, caCertPem }
5. Bind is server-side: session.user.id → Root Admin SKI.
6. Print: org id, ca ski, “next: idr register --name laptop1 --org <entityId>”
```

**Not:** attach a JWK to the PKCE token. Phase 2 already has a session. Kickstart already sends public admin/CA material.

`--server-keys` stays on power `org init` only (dev `allowServerKeygen`). Product `signup` is always client-keyed.

---

### Phase 4 — Invite  **(done)**

**What**

Upstream admin invites a downstream **device into an org**: a token the device redeems so its CSR lands in that org's inbox. The device still chooses its own unique name at `register`.

**Why the plugin needed a table**

Pull enroll is an inbox: anyone who can hit `enroll-create` submits a CSR. An invite is a secret that binds the CSR to one entity so `csr list --org` shows the relevant requests. It does **not** pre-claim a hostname.

**Plugin contract**

```text
POST /delegate-permissions/enroll-invite
  session required
  body: { entityId, expiresIn?, maxUses? }
  → { inviteId, inviteToken, entityId, expiresAt, maxUses }
  expiresAt always set (plugin `inviteExpiresIn`, default 7d; cap `inviteMaxExpiresIn`, default 30d). maxUses from plugin `inviteMaxUses` (default 1); 0 = unlimited until expiry.

GET /delegate-permissions/enroll-invite?inviteToken=
  no session; does not consume a use
  → { entityId, expiresAt, maxUses }

POST /delegate-permissions/enroll-create
  optional: inviteToken
  entityId from the invite; host/name from the device
  reject wrong org / expired / exhausted (whichever hits first)
```

```text
idr invite --org acme.com
  → one redeem, then INVITE_USED (or INVITE_EXPIRED)

idr invite --org acme.com --uses 50 --expires-in 86400
  → fleet / script cap

idr invite --org acme.com --unlimited
  → until expiry only

idr register --invite <token> --name laptop1
  → GET invite for entityId, CSR host laptop1--acme.com

idr csr list --org acme.com
  → pending laptop1--acme.com for the admin to sign
```

Pull enroll without a token is unchanged. Human “invite admin” is a different object (`interim_admin` / `issue-delegate`). Keep it out of `register`.

---

### Phase 5 — Agent as the default runtime (`--keep`)  **(done, bounded)**

**What**

`cli.txt`: SDK as a service should be default; command prompt is for testing. `--keep` / `--detach`. Root vs non-root matters for key paths.

**Why this is not a flag on `dp-cli`**

Lifecycle CLI should exit. A Target Agent must stay up: mTLS to Presence, `presence.register`, accept sessions. Mixing that into `idr register` couples enroll to a product PEP.

**How**

Separate binaries `idr-agent` / `dp-agent` (same crate as the lifecycle CLI):

```text
idr-agent
  → load identity/platform-endorsed.crt + machine.key
  → verify endorsed leaf against platform-ca.crt
  → optional --pep-url mTLS GET probe (not Presence)
  → stay in this terminal until ctrl-c or the terminal closes

idr-agent --keep
idr-agent --detach
  → same load/verify, then daemonize
  → parent prints pid + pidfile and exits; child stays in the background
  → logs $DP_STATE_DIR/agent.log ; pid $DP_STATE_DIR/agent.pid
```

| Privilege | State dir | Why |
|-----------|-----------|-----|
| User | `~/.idr` | Dev, laptop Source |
| Root / service | `/var/lib/idr` | Headless Target; keys not in a login session |

`DP_STATE_DIR` already selects this. Document it on the agent; do not invent a second keystore. See [SECRET_STORAGE.md](./SECRET_STORAGE.md).

`dp-cli` remains the exception: enroll, approve, renew, then exit.

---

## 6. Human vs machine vs mTLS — one picture

```text
                    Better Auth
                    ┌─────────────────────────────────────┐
 Human              │  SSO / email / device-code           │
                    │  session cookie                      │
                    └──────────────┬──────────────────────┘
                                   │ DP_AUTH_TOKEN / session file
                                   ▼
                    delegate-permissions
                    ┌─────────────────────────────────────┐
 Admin CLI          │  kickstart-entity                    │
 signup / org init  │  enroll-approve (signs with Entity CA)│
                    └──────────────┬──────────────────────┘
                                   │
 Device CLI         │  enroll-create (CSR)                 │
 register           │  enroll-pull → certs + credential    │
                    └──────────────┬──────────────────────┘
                                   │ platform-endorsed.crt
                                   ▼
                    TLS terminator (HAProxy)
                    ca-file = GET /platform-root
                    verify required  ← machine AuthN (mTLS)
                                   │
                                   ▼
                    Product PEP (Presence, not this CLI)
                    first frame dp.credential.v1  ← machine AuthZ
```

**Test mapping:** plugin Vitest = HTTP boxes. `openssl verify` = crypto of the endorsed leaf. `openssl s_client` = HAProxy box. Presentation unit test = first frame. There is still no in-repo HAProxy fixture.

---

## 7. Phase 1 acceptance

```bash
# Device
idr register --org acme.com --name laptop1
# → submitted laptop1--acme.com, enroll id printed

# Admin
idr csr list --org acme.com
# →  1  laptop1--acme.com  pending  <enrollId>

idr csr approve 1 --org acme.com --yes
# → approved, platform cosign received

# Device
idr machine pull
idr machine whoami
# → laptop1--acme.com
```

Localhost:

```bash
idr org init acme.com          # or later: idr signup --domain acme.com
idr register --local --org acme.com --name laptop1
# → enrolled (enroll-instant)
```

Power surface still works: `machine enroll`, `admin machine approve <id>`.

---

## 8. What we will not do in Phase 1–3

| Idea | Reason |
|------|--------|
| Plugin PKCE+JWK signup | Wrong layer; session then kickstart |
| Wire name `laptop1.slug.org` | Breaks `parseMachineHost` |
| `idr --keep` on the lifecycle binary | Agent is `idr-agent` |
| Fake invite tokens | Use `enroll-invite` |
| Server-generated keys on `signup` | Production is client-keyed |
