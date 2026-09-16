# Test runbook — machine lifecycle

Step-by-step commands for the intended IDR / DP flow. There is **no** all-in-one live script. Automated coverage in **this** repo is `cargo test`. Live HTTP is billing Machine AuthN (`/api/v1/machine-authn/*`), not Better Auth `/delegate-permissions/*`.

CSR **approve** and **invite** are **organization owner only** (`OWNER_REQUIRED`). Other `admin` members cannot sign machines.

Repos on this machine:

```bash
export CORE=/mnt/dev-drive/docs/2key-core-sdk
export IDR=/mnt/dev-drive/docs/idr-agent
export BILLING=/mnt/dev-drive/docs/billing
export SDKS=/mnt/dev-drive/docs/2key-billing-sdks
export PATH="$HOME/.cargo/bin:$PATH"
```

What each layer actually proves:

| Layer | AuthN | AuthZ |
|-------|--------|--------|
| `cargo test -p dp-rust` | — | catalog grants / subset / deny |
| `cargo test -p dp-rust-sdk` | mocked `/machine-authn/*` | credential stored; not presented to a PEP |
| CLI enroll | CSR + Platform endorsement on disk | credential stored; not presented to a PEP |
| `openssl verify` | leaf chains to Platform Root | nothing |
| HAProxy `verify required` | mTLS (machine is who it claims) | nothing |
| `dp.credential.v1` first frame | — | M2M AuthZ (app / PEP) |

Billing HTTP does **not** terminate client certificates. Real mTLS AuthN needs a TLS terminator that uses `GET /api/v1/machine-authn/platform-root` as `ca-file`. There is no HAProxy fixture in this repo.

**Billing v1 greenfield (current server):** queued enroll only. Implemented: `register`, `enroll-create` / `approve` / `pull`, `enroll-invite`, `issue-delegate`, `assert-subset`, `platform-root`, `credential-status`. Not implemented: `enroll-instant`, `enroll-list` / `enroll-get` / `enroll-reject`, `machine-renew` / `machine-decommission`. `register --local` / `gen` therefore 404. `csr list` 404s until `enroll-list` exists — approve with the **enroll id** printed by `register`.

Bodies on the live server require `payingPartyId` + `memberId` (session JWT via `requireBillingAuth`). The CLI still serializes the older `entityId`-centric kickstart/enroll DTOs; live register/enroll will fail until those fields are mapped from the session.

---

## 0. One-time setup

### 0.1 Build

Generic bins from this repo:

```bash
cd "$CORE"
cp .env.example .env
# edit DP_BACKEND_URL (e.g. https://billing.idr.to/api/v1) / DP_PRODUCT_NAME
set -a && source .env && set +a

cargo build --release -p dp-cli --bin dp-cli --bin dp-agent
export IDR_BIN="$CORE/target/release/dp-cli"
"$IDR_BIN" --help
```

IDR-stamped bins (baked `https://billing.idr.to/api/v1`):

```bash
cd "$IDR"
cargo build --release --bin idr --bin idr-agent
export IDR_BIN="$IDR/target/release/idr"
"$IDR_BIN" version
```

Use a throwaway state dir so you do not clobber `~/.idr`:

```bash
export DP_STATE_DIR=$(mktemp -d /tmp/idr-state-XXXX)
echo "state: $DP_STATE_DIR"
```

### 0.2 Session (`idr auth login`)

Required for `org init`, `signup`, owner `csr approve`, `invite`, and (on billing v1) `register` because `enroll-create` is behind `requireBillingAuth`.

**Preferred** (auth server has `deviceAuthorization()` + `bearer()`):

```bash
"$IDR_BIN" auth login
# visit the printed URL, enter the user code, wait until "logged in"
"$IDR_BIN" auth status
```

Login hits `DP_AUTH_URL` (default: same host as `DP_BACKEND_URL` with `/api/auth`).

**Paste** (browser cookie, or device plugin not enabled):

```bash
"$IDR_BIN" auth login --paste
# paste: better-auth.session_token=...   or a Bearer token
```

`--token` / `DP_AUTH_TOKEN` still override the session file for one command. Session lives at `$DP_STATE_DIR/session` (0600), not in `state.json`.

### 0.3 Billing must be live for CLI / curl

Sanity:

```bash
curl -sS "$DP_BACKEND_URL/machine-authn/platform-root"
# expect JSON with platform root PEM / JWK
# COSIGN_REQUIRED / empty → host has no Platform CA
```

IDR production shape: `DP_BACKEND_URL=https://billing.idr.to/api/v1`.

**Local (this laptop):** Postgres is already on `:5432`. From the billing repo:

```bash
cd /mnt/dev-drive/docs/billing
npm run dev    # http://localhost:3000  Auth: /api/auth  API: /api/v1
```

Sanity: `GET /` 200, `GET /api/v1/machine-authn/platform-root` 200 (`ski` + `publicJwk`; **no PEM** — `idr platform root` will say the server did not return a PEM).

Create an owner session: `POST /api/auth/sign-up/email` → `POST /api/auth/organization/bind` `{ "slug": "me" }` → `GET /api/auth/token`. Billing `/api/v1/*` wants that JWT as `Authorization: Bearer`, not the session cookie.

If `platform-root` on **billing.idr.to** returns HTTP 500, the host Platform CA is not configured yet. Localhost in development mints an ephemeral Host key.

---

## 1. Automated (no live billing)

Fastest check that AuthZ algebra, mTLS helpers, and the HTTP client still hold.

```bash
cd "$CORE"
cargo test -p dp-rust -p dp-rust-mtls -p dp-rust-sdk
cargo test -p two-key-core
```

AuthZ fixtures must stay in sync with `2key-billing-sdks` (`conformance/dp-authz/fixtures.json`).

Billing Machine AuthN unit tests (sibling, not this repo):

```bash
cd "$BILLING"
# e.g. src/__tests__/unit/services/machine-authn-subset.test.ts
```

TS algebra / presentation (sibling):

```bash
cd "$SDKS/packages/javascript"
pnpm exec vitest --run
```

---

## 2. Intended live lifecycle (queued enroll)

Same host may hold the owner session + Entity CA. The **device** still generates `identity/machine.key` and never sends it.

Needs: live billing, owner session (`auth login` or `DP_AUTH_TOKEN`), `DP_BACKEND_URL`, `DP_STATE_DIR`.

```bash
cd "$CORE"
set -a && source .env && set +a
export DP_STATE_DIR=${DP_STATE_DIR:-$(mktemp -d /tmp/idr-state-XXXX)}

"$IDR_BIN" auth login          # or --paste
"$IDR_BIN" signup --domain smoke.test
# or: "$IDR_BIN" org init smoke.test --package enterprise
# expect: kickstarted smoke.test / keys generated locally under admin/smoke.test/

"$IDR_BIN" register --org smoke.test --name db1
# expect: submitted db1--smoke.test, enroll id + pending
# (billing v1: not enroll-instant; do not pass --local)

"$IDR_BIN" csr approve <enrollId> --org smoke.test --yes
# numbered `csr list` needs enroll-list (not on billing v1 yet)
# fails with OWNER_REQUIRED if the session user is not the org owner

"$IDR_BIN" machine pull
"$IDR_BIN" machine whoami
# expect: db1--smoke.test

"$IDR_BIN" machine status
"$IDR_BIN" machine certificate
ls -l "$DP_STATE_DIR/identity/"
```

Pass: these files exist and are non-empty:

- `identity/machine.key` (never leaves the machine)
- `identity/machine.crt` (Entity-CA-signed leaf)
- `identity/org-ca.crt`
- `identity/platform-ca.crt`
- `identity/platform-endorsed.crt` (present this for mTLS)

```bash
"$IDR_BIN" platform root --output /tmp/dp-platform-root.pem
# ski on stderr; PEM in the file
```

Do **not** use `register --local` / `gen` / `machine enroll --instant` against billing v1.

---

## 3. Split enroll (device + owner)

Two state dirs: the device never has the Entity CA private key. Owner laptop keeps `admin/<entity>/`.

```bash
export ADMIN_DIR=$(mktemp -d /tmp/idr-admin-XXXX)
export DEVICE_DIR=$(mktemp -d /tmp/idr-device-XXXX)

# Owner (SSO)
DP_STATE_DIR="$ADMIN_DIR" "$IDR_BIN" auth login
DP_STATE_DIR="$ADMIN_DIR" "$IDR_BIN" org init acme.com --package enterprise

# Device — billing v1 still requires a member JWT on enroll-create
DP_STATE_DIR="$DEVICE_DIR" "$IDR_BIN" auth login   # or share a token
DP_STATE_DIR="$DEVICE_DIR" "$IDR_BIN" register --org acme.com --name laptop
# prints enroll id + pending; keys already in DEVICE_DIR

DP_STATE_DIR="$ADMIN_DIR" "$IDR_BIN" csr approve <enrollId> --org acme.com --yes

DP_STATE_DIR="$DEVICE_DIR" "$IDR_BIN" machine pull
DP_STATE_DIR="$DEVICE_DIR" "$IDR_BIN" machine whoami
# expect: laptop--acme.com
```

Push-invite (owner-only; token binds the **org**; the device still chooses `--name`):

```bash
DP_STATE_DIR="$ADMIN_DIR" "$IDR_BIN" invite --org acme.com
# or fleet: invite --org acme.com --uses 50
# prints invite token (org only — device chooses the name)

DP_STATE_DIR="$DEVICE_DIR" "$IDR_BIN" register --invite <token> --name laptop
DP_STATE_DIR="$ADMIN_DIR" "$IDR_BIN" csr approve <enrollId> --org acme.com --yes
DP_STATE_DIR="$DEVICE_DIR" "$IDR_BIN" machine pull

DP_STATE_DIR="$DEVICE_DIR" "$IDR/target/release/idr-agent"
# stays in this terminal until ctrl-c
# background: "$IDR/target/release/idr-agent" --keep
```

Reject instead of approve (`enroll-reject` is SDK-forward; billing v1 may 404):

```bash
DP_STATE_DIR="$ADMIN_DIR" "$IDR_BIN" csr reject <enrollId> --org acme.com --yes
```

---

## 4. mTLS — crypto (no terminator)

Proves the Platform-endorsed leaf chains to the Platform Root. Run after §2 or §3.

```bash
STATE="${DP_STATE_DIR:-$HOME/.idr}"

# Platform-endorsed leaf (what HAProxy should see)
openssl verify -CAfile "$STATE/identity/platform-ca.crt" \
  "$STATE/identity/platform-endorsed.crt"

# Entity-CA-signed leaf (not the HAProxy ca-file)
openssl verify -CAfile "$STATE/identity/org-ca.crt" \
  "$STATE/identity/machine.crt"

# Same key for both leaves
openssl x509 -in "$STATE/identity/platform-endorsed.crt" -noout -pubkey > /tmp/endorsed.pub
openssl pkey -in "$STATE/identity/machine.key" -pubout > /tmp/machine.pub
diff -q /tmp/endorsed.pub /tmp/machine.pub

openssl x509 -in "$STATE/identity/platform-endorsed.crt" -noout -text | grep -E 'URI:urn:dp:ski:|TLS Web Client Authentication'
```

Must match `GET /machine-authn/platform-root` (not `org-ca.crt`):

```bash
"$IDR_BIN" platform root --output /tmp/dp-platform-root.pem
diff -q /tmp/dp-platform-root.pem "$STATE/identity/platform-ca.crt"
```

Rust unit tests (CSR, SKI thumbprint, rustls materialize, endorsement verify):

```bash
cd "$CORE"
cargo test -p dp-rust-mtls -p dp-rust-sdk
```

---

## 5. mTLS — handshake (needs a terminator)

Billing does not request client certs. To test AuthN you need something like:

```
bind *:443 ssl crt /etc/haproxy/server.pem \
  ca-file /etc/haproxy/dp-platform-root.pem verify required
```

Fill `dp-platform-root.pem` from `idr platform root` (or `curl …/machine-authn/platform-root`).

Then, from the enrolled machine:

```bash
STATE="${DP_STATE_DIR:-$HOME/.idr}"
openssl s_client -connect YOUR_PEP_HOST:443 \
  -cert "$STATE/identity/platform-endorsed.crt" \
  -key "$STATE/identity/machine.key" \
  -CAfile /tmp/dp-platform-root.pem
```

Pass: handshake completes; peer accepted the client cert. Fail: `alert unknown ca` / handshake failure → terminator `ca-file` is not that Platform Root, or you presented `machine.crt` instead of `platform-endorsed.crt`.

`idr machine renew` / `decommission` attach the stored client cert to HTTP. That only authenticates if the **URL’s TLS server** asks for a client cert. Billing v1 may 404 those routes.

---

## 6. M2M AuthN + AuthZ

Intended product loop:

1. **AuthN** — terminator verifies `platform-endorsed.crt` (§5).
2. **AuthZ** — machine sends CapabilityCredential as the first app frame (`dp.credential.v1`).

There is no live PEP in this repo. Unit-test algebra and (in `2key-billing-sdks`) the presentation frame:

```bash
cd "$CORE"
cargo test -p dp-rust

cd "$SDKS/packages/javascript"
pnpm --filter @2key/dp-authorize test
pnpm --filter @2key/dp-presentation test
```

After `enroll-pull`, the credential lives with the identity materials the SDK persists. A product PEP must:

1. Accept mTLS (SKI SAN `urn:dp:ski:…`).
2. Read the first frame.
3. Check the credential (signature, subset, not revoked via `GET /api/v1/machine-authn/credential-status?ski=`).

Human cookie AuthZ is Better Auth session + billing membership (`owner` / `admin` / `member`). Use it in §7. It is not M2M.

---

## 7. Delegations (human / owner HTTP)

The CLI has no `issue-delegate` command. Use curl against a live billing VM (owner session).

Cookie header: the same value as `DP_AUTH_TOKEN` if it is already `better-auth.session_token=…`.

```bash
API="$DP_BACKEND_URL"
H1="cookie: $DP_AUTH_TOKEN"
H2="content-type: application/json"

# 1) Platform root (no session)
curl -sS "$API/machine-authn/platform-root"

# 2) Register Org Root CA (owner; skip if already registered)
# Live body requires payingPartyId + memberId + rootSki + caCertPem.
# Prefer `idr org init` / `idr signup` once the CLI maps those fields.
curl -sS -H "$H1" -H "$H2" -X POST "$API/machine-authn/register" \
  -d '{
    "payingPartyId":"<uuid>",
    "memberId":"<owner member id>",
    "entityId":"amazon.com",
    "package":"enterprise",
    "rootSki":"<ca ski>",
    "caCertPem":"-----BEGIN CERTIFICATE-----\n…\n-----END CERTIFICATE-----\n"
  }'

# 3) Interim / zone delegate
curl -sS -H "$H1" -H "$H2" -X POST "$API/machine-authn/issue-delegate" \
  -d '{
    "payingPartyId":"<uuid>",
    "memberId":"<owner member id>",
    "kind":"zone_authority",
    "zone":"us-east",
    "issuerSki":"<root ski>",
    "credential":{ }
  }'

# 4) Attenuation without persisting
curl -sS -H "$H1" -H "$H2" -X POST "$API/machine-authn/assert-subset" \
  -d '{
    "parent":[{"action":"machine.bind","scope":{"name":"us-east"},"delegable":true}],
    "child":[{"action":"machine.bind","scope":{"name":"zone6.us-east"},"delegable":false}]
  }'
# { "ok": true }  (wrapped as billing `{ data: … }` )

# 5) Credential status
curl -sS -H "$H1" "$API/machine-authn/credential-status?ski=$SKI"
```

CSR machines use §2 / §3, not `issue-delegate`. `issue-machine` is not a billing v1 route.

---

## 8. Lifecycle after a CLI enroll

```bash
STATE="${DP_STATE_DIR:-$HOME/.idr}"
SKI=$(python3 -c "import json; print(json.load(open('$STATE/state.json'))['ski'])")

curl -sS -H "cookie: $DP_AUTH_TOKEN" \
  "$DP_BACKEND_URL/machine-authn/credential-status?ski=$SKI"

# SDK-forward (may 404 on billing v1):
# "$IDR_BIN" machine renew --yes
# "$IDR_BIN" machine decommission --yes
```

---

## Suggested order

| Order | Use case | Command |
|------:|----------|---------|
| 1 | Algebra + HTTP client | §1 `cargo test` |
| 2 | CLI queued enroll | §2 |
| 3 | Platform leaf vs root | §4 |
| 4 | Split enroll | §3 |
| 5 | Delegations | §7 |
| 6 | M2M frame | §6 unit test |
| 7 | Real mTLS AuthN | §5 against a terminator |

If you only have time for one live CLI check: **§2 then §4**. That is the HAProxy litmus without standing up HAProxy: keys never left the machine, SKI is the JWK thumbprint, and `platform-endorsed.crt` verifies against `platform root`.
