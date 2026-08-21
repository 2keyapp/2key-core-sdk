# dp-cli

Same CLI source for every product. Bake the backend URL and product name into the binary, then rename the exe.

Environment variables are documented in the repo-root [`.env.example`](../../.env.example).

## Required at product build

| Variable | Example |
|----------|---------|
| `DP_BACKEND_URL` | `https://api.idr.to/api/auth` |
| `DP_PRODUCT_NAME` | `idr` |

Optional: `DP_SEPARATOR` (default `--`).

## Runtime

| Variable | When |
|----------|------|
| `DP_AUTH_TOKEN` | Optional override; prefer `idr auth login` |
| `DP_STATE_DIR` | Optional; default `~/.{product}` |

Runtime values override compiled defaults. Flags: `--backend-url`, `--token`, `--state-dir`.

```bash
idr auth login
idr signup --personal              # or --domain acme.com / --brand acme
idr invite --org <entity>
# fleet: idr invite --org <entity> --uses 50
# until expiry: idr invite --org <entity> --unlimited
idr register --invite <token> --name laptop1
# or pull enroll:
idr register --org <entity> --name laptop1
idr-agent                          # stays in this terminal until ctrl-c
idr-agent --keep                   # background service (--detach is the same)

```

Product verbs and phases: [docs/CLI-PRODUCT.md](../../docs/CLI-PRODUCT.md).

Step-by-step checks (plugin HTTP, CLI enroll, openssl verify, delegations, mTLS handshake): [docs/TEST-USECASES.md](../../docs/TEST-USECASES.md).

```bash
set -a && source .env && set +a   # copy from .env.example first
cargo build --release -p dp-cli --bin dp-cli --bin idr --bin idr-agent
cp ../../target/release/dp-cli idr
# idr-agent stays in the terminal by default; `--keep` / `--detach` run in the background
```
