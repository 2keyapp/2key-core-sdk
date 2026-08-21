# Test runbook — Delegate Permissions use cases

Step-by-step commands for each flow. There is **no** all-in-one live script (the old `rust-cli.roundtrip.test.ts` was removed). Automated coverage is Vitest + `cargo test`. CLI and curl below assume a **running** Better Auth server with `delegatePermissions` enabled.

Repos on this machine:

```bash
export BA=/mnt/dev-drive/docs/better-auth
export SDK=/mnt/dev-drive/docs/dp-sdk
export PATH="$HOME/.cargo/bin:$PATH"
```

What each layer actually proves:

| Layer | AuthN | AuthZ |
|-------|--------|--------|
| Plugin HTTP tests | session cookie | catalog grants / `authorize` / issued credentials |
| CLI enroll | CSR + Platform endorsement on disk | credential stored; not presented to a PEP |
| `openssl verify` | leaf chains to Platform Root | nothing |
| HAProxy `verify required` | mTLS (machine is who it claims) | nothing |
| `dp.credential.v1` first frame | — | M2M AuthZ (app / PEP) |

The plugin HTTP server does **not** terminate client certificates. Real mTLS AuthN needs a TLS terminator that uses `GET /delegate-permissions/platform-root` as `ca-file`. There is no HAProxy fixture in either repo.

---

## 0. One-time setup

### 0.1 Build the CLI

```bash
cd "$SDK"
cp .env.example .env
# edit DP_BACKEND_URL / DP_PRODUCT_NAME / DP_AUTH_TOKEN
set -a && source .env && set +a

cargo build --release -p dp-cli --bin idr
export IDR="$SDK/target/release/idr"
"$IDR" --help
```

Use a throwaway state dir so you do not clobber `~/.idr`:

```bash
export DP_STATE_DIR=$(mktemp -d /tmp/idr-state-XXXX)
echo "state: $DP_STATE_DIR"
```

### 0.2 Session (`idr auth login`)

Required for `org init`, `signup` (phase 3), admin, and `register --local`.

**Preferred** (auth server has `deviceAuthorization()` + `bearer()`):

```bash
"$IDR" auth login
# visit the printed URL, enter the user code, wait until "logged in"
"$IDR" auth status
```

**Paste** (browser cookie, or device plugin not enabled):

```bash
"$IDR" auth login --paste
# paste: better-auth.session_token=...   or a Bearer token
```

`--token` / `DP_AUTH_TOKEN` still override the session file for one command. Session lives at `$DP_STATE_DIR/session` (0600), not in `state.json`.

### 0.3 Plugin server must be live for CLI / curl

`seed: "demo"` (or your catalog) plus a Platform CA. Local demo CA is enough for enroll; production needs a stable `platformCa`.

Sanity:

```bash
curl -sS "$DP_BACKEND_URL/delegate-permissions/platform-root"
# expect JSON with platformRootPem + ski
# COSIGN_REQUIRED → plugin has no Platform CA
```

---

## 1. Plugin HTTP (no CLI, no TLS)

In-process Better Auth. Fastest check that the plugin contract still holds.

```bash
cd "$BA/packages/better-auth"
```

### 1.1 Catalog, session AuthZ, zone delegate → machine

**Use case:** human session grant; `authorize` allow/deny; `issue-delegate` (zone) then `issue-machine`.

```bash
pnpm exec vitest src/plugins/delegate-permissions/delegate-permissions.test.ts --run
```

Pass: grant + session caps; `machine.bind` allowed; `zone.delegate` denied for personal_root; zone credential then machine with `platformCosign.kid` and `seatId`.

### 1.2 CSR enroll + Platform leaf vs root (“mTLS litmus”)

**Use case:** enroll-create → admin sign → enroll-approve → enroll-pull; `platformCertPem` verifies against `GET /platform-root`. This is **X.509 verify**, not a TLS handshake.

```bash
pnpm exec vitest src/plugins/delegate-permissions/enroll.test.ts --run
```

Pass: `subjectSki` matches CSR; pulled `platformCertPem` verifies against the same PEM HAProxy would use as `ca-file`; mismatched `publicJwk` → `INVALID_CSR`; no `platformCa` → `COSIGN_REQUIRED`; invite redeem matches host, rejects mismatch/expired/reuse; uninvited pull enroll still works.

### 1.3 Full lifecycle smoke

**Use case:** platform-root, seed, kickstart, enroll, pull, status, list, renew, decommission, revoke.

```bash
pnpm exec vitest src/plugins/delegate-permissions/e2e-smoke.test.ts --run
```

Narrower lifecycle only:

```bash
pnpm exec vitest src/plugins/delegate-permissions/lifecycle.test.ts --run
```

### 1.4 Capability algebra (no HTTP)

```bash
pnpm exec vitest src/plugins/delegate-permissions/capability/capability.test.ts --run
```

---

## 2. Localhost enroll (CLI litmus)

Same host holds Entity CA + machine keys. Product path: `auth login` → `signup` → `register --local`. Power path: `org init` then `gen`.

Needs: live plugin server, session (`auth login` or `DP_AUTH_TOKEN`), `DP_BACKEND_URL`, `DP_STATE_DIR`.

```bash
cd "$SDK"
set -a && source .env && set +a
export DP_STATE_DIR=${DP_STATE_DIR:-$(mktemp -d /tmp/idr-state-XXXX)}

"$IDR" auth login          # or --paste
"$IDR" signup --domain smoke.test
# or: "$IDR" org init smoke.test --package enterprise
# expect: kickstarted smoke.test / keys generated locally

"$IDR" org status smoke.test

"$IDR" register --local --org smoke.test --name db1
# same as: "$IDR" gen --org smoke.test --name db1
# expect: enrolled db1--smoke.test + ski (43-char RFC 7638 thumbprint)

"$IDR" machine whoami
# expect: db1--smoke.test

"$IDR" machine status
"$IDR" machine certificate
ls -l "$DP_STATE_DIR/identity/"
```

Pass: these files exist and are non-empty:

- `identity/machine.key` (never leaves the machine)
- `identity/machine.crt` (Entity-CA-signed leaf)
- `identity/org-ca.crt`
- `identity/platform-ca.crt`
- `identity/platform-endorsed.crt` (present this for mTLS)

```bash
"$IDR" platform root --output /tmp/dp-platform-root.pem
# ski on stderr; PEM in the file
```

Equivalent without `gen`:

```bash
"$IDR" machine enroll --org smoke.test --name db1 --instant
```

---

## 3. Split enroll (device + admin)

Two state dirs: device never has the Entity CA private key.

```bash
export ADMIN_DIR=$(mktemp -d /tmp/idr-admin-XXXX)
export DEVICE_DIR=$(mktemp -d /tmp/idr-device-XXXX)

# Admin machine (SSO)
DP_STATE_DIR="$ADMIN_DIR" "$IDR" org init acme.com --package enterprise

# Device (no token needed for enroll-create)
DP_STATE_DIR="$DEVICE_DIR" "$IDR" register --org acme.com --name laptop
# prints enroll id + pending; keys already in DEVICE_DIR

DP_STATE_DIR="$ADMIN_DIR" "$IDR" csr list --org acme.com
DP_STATE_DIR="$ADMIN_DIR" "$IDR" csr show 1 --org acme.com
DP_STATE_DIR="$ADMIN_DIR" "$IDR" csr approve 1 --org acme.com --yes

DP_STATE_DIR="$DEVICE_DIR" "$IDR" machine pull
DP_STATE_DIR="$DEVICE_DIR" "$IDR" machine whoami
# expect: laptop--acme.com
```

Push-invite (same split, device infers org/name from the token):

```bash
DP_STATE_DIR="$ADMIN_DIR" "$IDR" invite --org acme.com
# or fleet: invite --org acme.com --uses 50
# prints invite token (org only — device chooses the name)

DP_STATE_DIR="$DEVICE_DIR" "$IDR" register --invite <token> --name laptop
DP_STATE_DIR="$ADMIN_DIR" "$IDR" csr approve 1 --org acme.com --yes
DP_STATE_DIR="$DEVICE_DIR" "$IDR" machine pull

DP_STATE_DIR="$DEVICE_DIR" "$SDK/target/release/idr-agent"
# stays in this terminal until ctrl-c
# background: "$SDK/target/release/idr-agent" --keep
# or: cargo build -p dp-cli --bin idr-agent
```

Reject instead of approve:

```bash
DP_STATE_DIR="$ADMIN_DIR" "$IDR" csr reject 1 --org acme.com --yes
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

Must match `GET /platform-root` (not `org-ca.crt`):

```bash
"$IDR" platform root --output /tmp/dp-platform-root.pem
diff -q /tmp/dp-platform-root.pem "$STATE/identity/platform-ca.crt"
```

Rust unit tests (CSR, SKI thumbprint, rustls materialize, endorsement verify):

```bash
cd "$SDK"
cargo test -p dp-rust-mtls -p dp-rust-sdk
```

Node mTLS helper (self-signed materialize, not plugin enroll):

```bash
cd "$SDK"
pnpm --filter @2key/dp-mtls test
```

---

## 5. mTLS — handshake (needs a terminator)

Better Auth does not request client certs. To test AuthN you need something like:

```
bind *:443 ssl crt /etc/haproxy/server.pem \
  ca-file /etc/haproxy/dp-platform-root.pem verify required
```

Fill `dp-platform-root.pem` from `idr platform root` (or `curl …/platform-root`).

Then, from the enrolled machine:

```bash
STATE="${DP_STATE_DIR:-$HOME/.idr}"
openssl s_client -connect YOUR_PEP_HOST:443 \
  -cert "$STATE/identity/platform-endorsed.crt" \
  -key "$STATE/identity/machine.key" \
  -CAfile /tmp/dp-platform-root.pem
```

Pass: handshake completes; peer accepted the client cert. Fail: `alert unknown ca` / handshake failure → terminator `ca-file` is not that Platform Root, or you presented `machine.crt` instead of `platform-endorsed.crt`.

`idr machine renew` / `decommission` attach the stored client cert to HTTP. That only authenticates if the **URL’s TLS server** asks for a client cert.

---

## 6. M2M AuthN + AuthZ

Intended product loop:

1. **AuthN** — terminator verifies `platform-endorsed.crt` (§5).
2. **AuthZ** — machine sends CapabilityCredential as the first app frame (`dp.credential.v1`).

There is no live PEP in these repos. Unit-test the frame only:

```bash
cd "$SDK"
pnpm --filter @2key/dp-presentation test
```

Pass: presenter sends `{ type: "dp.credential.v1", credential }`.

After `enroll-pull` / `idr gen`, the credential lives with the identity materials the SDK persists. A product PEP must:

1. Accept mTLS (SKI SAN `urn:dp:ski:…`).
2. Read the first frame.
3. Check the credential (signature, subset, not revoked via `GET /delegate-permissions/credential-status?ski=`).

Session `POST /delegate-permissions/authorize` is **human cookie AuthZ**, not M2M. Use it in §7.

---

## 7. Delegations (human / admin HTTP)

The CLI has no `issue-delegate` command. Use Vitest (§1.1) or curl against a live server.

Cookie header: the same value as `DP_AUTH_TOKEN` if it is already `better-auth.session_token=…`.

```bash
AUTH="$DP_BACKEND_URL"
H1="cookie: $DP_AUTH_TOKEN"
H2="content-type: application/json"

# 1) Catalog
curl -sS -H "$H1" "$AUTH/delegate-permissions/catalog"

# 2) Kickstart (skip if entity exists)
curl -sS -H "$H1" -H "$H2" -X POST "$AUTH/delegate-permissions/kickstart-entity" \
  -d '{"entityId":"amazon.com","package":"enterprise"}'
# save rootAdmin.credential.ski and rootAdmin.privateJwk from the JSON
# (server keygen must be enabled; otherwise keys were created by `idr org init`)

# 3) Zone delegate (attenuation: child ⊆ parent)
curl -sS -H "$H1" -H "$H2" -X POST "$AUTH/delegate-permissions/issue-delegate" \
  -d '{
    "entityId":"amazon.com",
    "kind":"zone_authority",
    "zone":"us-east",
    "issuerSki":"<rootAdmin ski>",
    "issuerPrivateJwk":{ }
  }'
# save credential.ski + privateJwk

# 4) Machine under that zone
curl -sS -H "$H1" -H "$H2" -X POST "$AUTH/delegate-permissions/issue-machine" \
  -d '{
    "entityId":"amazon.com",
    "host":"db1.us-east--amazon.com",
    "issuerSki":"<zone ski>",
    "issuerPrivateJwk":{ }
  }'

# 5) Session grant + authorize (human, not mTLS)
curl -sS -H "$H1" -H "$H2" -X POST "$AUTH/delegate-permissions/principal-grant" \
  -d '{"profile":"personal_root","entityId":"alice@example.com"}'
curl -sS -H "$H1" -H "$H2" -X POST "$AUTH/delegate-permissions/issue-session-capabilities" \
  -d '{}'
curl -sS -H "$H1" -H "$H2" -X POST "$AUTH/delegate-permissions/authorize" \
  -d '{"action":"machine.bind","resource":{"name":"laptop","entity":"alice@example.com"}}'
# { "allowed": true }

curl -sS -H "$H1" -H "$H2" -X POST "$AUTH/delegate-permissions/authorize" \
  -d '{"action":"zone.delegate","resource":{"name":"us-east"}}'
# { "allowed": false, "code": "NOT_AUTHORIZED" }

# 6) Attenuation without persisting
curl -sS -H "$H1" -H "$H2" -X POST "$AUTH/delegate-permissions/assert-subset" \
  -d '{
    "parent":[{"action":"machine.bind","scope":{"name":"us-east"},"delegable":true}],
    "child":[{"action":"machine.bind","scope":{"name":"zone6.us-east"},"delegable":false}]
  }'
# { "ok": true }
```

Prefer §1.1 over hand-filling JWKs. `issue-machine` here is **server-side issue** (not CSR enroll). CSR machines use §2 / §3.

---

## 8. Lifecycle after a CLI enroll

```bash
STATE="${DP_STATE_DIR:-$HOME/.idr}"
SKI=$(python3 -c "import json; print(json.load(open('$STATE/state.json'))['ski'])")

"$IDR" admin machine credentials smoke.test --status active
curl -sS "$DP_BACKEND_URL/delegate-permissions/credential-status?ski=$SKI"

"$IDR" machine renew --yes
"$IDR" machine whoami
"$IDR" admin machine revoke "$SKI" --reason other --yes
# or remote decommission (releases the hostname):
# "$IDR" admin machine decommission "$SKI" --yes
# local self-decommission (deletes keys):
# "$IDR" machine decommission --yes
```

---

## Suggested order

| Order | Use case | Command |
|------:|----------|---------|
| 1 | Plugin contract | §1.1 + §1.2 + §1.3 |
| 2 | CLI localhost enroll | §2 |
| 3 | Platform leaf vs root | §4 |
| 4 | Split enroll | §3 |
| 5 | Delegations | §1.1 or §7 |
| 6 | M2M frame | §6 unit test |
| 7 | Real mTLS AuthN | §5 against a terminator |

If you only have time for one live CLI check: **§2 then §4**. That is the HAProxy litmus without standing up HAProxy: keys never left the machine, SKI is the JWK thumbprint, and `platform-endorsed.crt` verifies against `platform root`.
