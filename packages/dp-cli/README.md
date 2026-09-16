# dp-cli

Same CLI source for every product. Tenants depend on this **library** and bake URL + product name at compile time (IDR: sibling [`idr-agent`](https://github.com/2keyapp/idr-agent)).

Environment variables are documented in the repo-root [`.env.example`](../../.env.example).

## Required at product build

| Variable | Example |
|----------|---------|
| `DP_BACKEND_URL` | `https://billing.idr.to/api/v1` |
| `DP_PRODUCT_NAME` | `idr` |

Optional: `DP_SEPARATOR` (default `--`), `DP_AUTH_URL` (default: same host with `/api/auth` instead of `/api/v1`).

## Runtime

| Variable | When |
|----------|------|
| `DP_AUTH_TOKEN` | Optional override; prefer `idr auth login` |
| `DP_STATE_DIR` | Optional; default `~/.{product}` |
| `DP_BACKEND_URL` / `DP_AUTH_URL` | Optional overrides of compiled defaults |

Flags: `--backend-url`, `--auth-url`, `--token`, `--state-dir`.

CSR **approve** is **organization owner only** (billing `OWNER_REQUIRED`). Other `admin` members can bill; they cannot sign machines.

```bash
idr auth login
idr signup --personal              # or --domain acme.com / --brand acme
idr invite --org <entity>          # owner
# fleet: idr invite --org <entity> --uses 50
idr register --invite <token> --name laptop1
# owner, other state dir:
idr csr list --org <entity>
idr csr approve 1 --org <entity> --yes
idr-agent                          # stays in this terminal until ctrl-c
idr-agent --keep                   # background service (--detach is the same)
```

`register --local` / `gen` need `enroll-instant` on the server. Billing v1 greenfield implements queued enroll (`enroll-create` → owner `enroll-approve` → `enroll-pull`), not instant.

Product verbs: [docs/CLI-PRODUCT.md](../../docs/CLI-PRODUCT.md).  
Runbook: [docs/TEST-USECASES.md](../../docs/TEST-USECASES.md).

```bash
set -a && source .env && set +a   # copy from .env.example first
cargo build --release -p dp-cli --bin dp-cli --bin dp-agent
# IDR-stamped bins: cd ../idr-agent && cargo build --release --bin idr --bin idr-agent
```
