# Runnable x402 Facilitator

A complete facilitator for the x402 `exact`/EVM scheme in under 100 lines,
built from `X402.Facilitator.Engine` (verify/settle/supported) served over
Bandit by `X402.Plug.Facilitator`. The Elixir counterpart of the upstream
`examples/typescript/facilitator`.

## Run

```sh
mix deps.get

PRIVATE_KEY=0x...your-fee-payer-key... mix run --no-halt
```

Environment:

| Variable      | Default                    | Meaning                       |
| ------------- | -------------------------- | ----------------------------- |
| `PRIVATE_KEY` | *(required)*               | Fee-payer secp256k1 key (hex) |
| `RPC_URL`     | `https://sepolia.base.org` | JSON-RPC endpoint             |
| `NETWORK`     | `eip155:84532`             | CAIP-2 network served         |
| `PORT`        | `4022`                     | HTTP listen port              |

The fee-payer key pays settlement gas — fund it with a little testnet ETH.
It can never move its own tokens: the engine only signs
`transferWithAuthorization` calls on the verified requirements' asset.

## Try it

```sh
curl http://localhost:4022/supported
curl -X POST http://localhost:4022/verify \
  -H 'content-type: application/json' \
  -d '{"x402Version": 2, "paymentPayload": {...}, "paymentRequirements": {...}}'
```

Point a resource server's facilitator URL (for example
`X402.Plug.PaymentGate` via `X402.Facilitator`) at
`http://localhost:4022`.

## Boot check

Verifies the server boots and answers `/supported` plus a structural
`/verify`, against a stub JSON-RPC node — no chain access needed:

```sh
PRIVATE_KEY="0x$(printf '11%.0s' {1..32})" \
  RPC_URL=http://localhost:4545 mix run check.exs
```

## Production notes

Put TLS termination, real authentication (`:auth_token` is only a
minimal bearer check), and rate limiting in front, and see the
"Run Your Own Facilitator" guide in the library docs.
