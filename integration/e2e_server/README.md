# x402 e2e interop server (Elixir)

Resource-server component for the official x402 cross-language e2e harness
([x402-foundation/x402 `e2e/`](https://github.com/x402-foundation/x402/tree/main/e2e)),
built on this repository's SDK (`X402.Plug.PaymentGate` + `X402.Facilitator`)
behind Bandit.

- `lib/` — the server: mechanisms-catalog loader (`E2eServer.Catalog`,
  the Elixir analogue of the harness's `servers/python/catalog.py`),
  boot-time config (`E2eServer.Config`), Plug router, supervision tree.
- `upstream/servers/elixir/http/bandit/` — the ready-to-copy component for the
  foundation repo (Hex dependency instead of the local path dep; no tests or
  bundled catalog). Regenerate its `lib/` with `./sync_upstream.sh`.
- `UPSTREAM_PATCHES.md` — every foundation-side change needed to admit the
  component (discovery whitelist, `setup.sh`, catalog `sdks`, CI toolchain).
- `priv/catalog/` — a bundled catalog fixture (upstream
  `mechanisms_global.json` + `mechanisms_evm.json` with `"elixir"` added to
  `/exact/evm/eip3009`'s `sdks`) so the smoke runs without a foundation
  checkout.

## Smoke test

```bash
./verify.sh
```

Boots the real supervision tree against a stub facilitator and asserts the
harness wire contract: unpaid `GET /exact/evm/eip3009` → 402 with a decodable
`PAYMENT-REQUIRED` header; a well-formed `PAYMENT-SIGNATURE` → verify +
settle against the facilitator, 200 with the fixed success body and a
`PAYMENT-RESPONSE` header; `GET /health`; `POST /close` (graceful shutdown);
malformed header → 400; mismatched `accepted` → 402.

## Running manually

```bash
PORT=4021 \
FACILITATOR_URL=http://localhost:4022 \
SERVER_EVM_ADDRESS=0x209693Bc6afc0C5328bA36FaF03C514EF312287C \
mix run --no-halt
```

Optional: `EVM_NETWORK` (CAIP-2, default `eip155:84532`),
`E2E_MECHANISMS_CATALOG` (defaults to walking up for `config/`, then the
bundled `priv/catalog`), `E2E_EXCLUDE_SCHEMES` / `E2E_EXCLUDE_NETWORKS`.
The process prints `Server listening on port N` when ready — the readiness
line the harness waits for.
