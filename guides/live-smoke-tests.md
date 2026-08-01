# Live Smoke Tests

The test suite ships with a live smoke test that exercises the real x402
wire format against Coinbase's hosted facilitator at
`https://api.cdp.coinbase.com/platform/v2/x402`. It is tagged `:smoke` and
excluded from the default test run
(`ExUnit.start(exclude: [:smoke])` in `test/test_helper.exs`).

## What the tests verify

`test/x402/facilitator/auth/cdp_live_test.exs` proves that the JWT built by
`X402.Facilitator.Auth.CDP` is accepted by the real service and that a real
v2 payment round-trips end to end. It is tiered so that a useful subset
runs at every level of setup:

1. **Negative control** — always runs, needs no credentials. Confirms that
   a JWT signed with unknown credentials is rejected with `401`.
 2. **Authentication** — needs only `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET`.
    Proves the JWT itself is accepted: the payment is deliberately invalid
    (signed by a throwaway key) so the facilitator rejects the *payment*, not
    the authentication.
 3. **End-to-end verify** — additionally needs `X402_PAYER_KEY`, a hex
    private key for a wallet funded with the payment asset. Asserts
    `isValid: true` on `POST /verify` and that the reported `payer` matches
    the address derived from the key.
 4. **Settlement** — same requirements plus `X402_SETTLE=1`. Settles the
    verified payment and asserts `success: true` with a transaction hash.

The receiver is never configured by hand and is never the payer itself:
end-to-end payloads default to a fresh throwaway ("burner") wallet. The zero
address is deliberately avoided as a recipient because USDC's
`transferWithAuthorization` reverts on transfers to `address(0)`.

## Prerequisites

- A Coinbase Developer Platform API key pair (`CDP_API_KEY_ID` and
  `CDP_API_KEY_SECRET`).
- For the end-to-end and settlement tiers: a Base Sepolia wallet funded with
  USDC. `X402_PAYER_KEY` is the hex private key of that wallet.

## Configuration

Defaults target USDC on Base Sepolia (`eip155:84532`) at a fixed amount of
1 cent. Payment configuration is built by `X402.TestPayments.from_env/1`
from the facilitator-agnostic `X402_*` variables; facilitator credentials
stay facilitator-specific (`CDP_*`).

| Variable | Default | Purpose |
|----------|---------|---------|
| `CDP_API_KEY_ID` | — | Facilitator credential (required for auth + e2e) |
| `CDP_API_KEY_SECRET` | — | Facilitator credential (required for auth + e2e) |
| `X402_FACILITATOR_URL` | CDP hosted facilitator | Facilitator base URL |
| `X402_PAYER_KEY` | — | Hex private key of the funded payer wallet; enables e2e/settle. The receiver is a fresh burner wallet (never the payer or zero address) |
| `X402_NETWORK` | `eip155:84532` | CAIP-2 network |
| `X402_CONTRACT` | `0x036CbD53842c5426634e7929541eC2318f3dCF7e` | ERC-20 payment asset (USDC on Base Sepolia) |
| `X402_RESOURCE` | `https://x402.org/smoke-test` | Resource URL |
| `X402_MAX_TIMEOUT` | `300` | `maxTimeoutSeconds` |
| `X402_TOKEN_NAME` | `USDC` | EIP-712 domain name |
| `X402_TOKEN_VERSION` | `2` | EIP-712 domain version |
| `X402_SETTLE` | unset | Set to `1` to also settle the verified payment |

## Running

Run the full tiered suite (faucet-fund `X402_PAYER_KEY` first):

```bash
CDP_API_KEY_ID=... CDP_API_KEY_SECRET=... \
  X402_PAYER_KEY=... X402_SETTLE=1 \
  mix test test/x402/facilitator/auth/cdp_live_test.exs --only smoke
```

Run a single tier by pointing `mix test` at its line number:

```bash
# Authentication only — no funded wallet required
mix test test/x402/facilitator/auth/cdp_live_test.exs:75 --only smoke

# Negative control — needs no credentials
mix test test/x402/facilitator/auth/cdp_live_test.exs:59 --only smoke
```

> Note: line numbers may drift as the test file changes.

Settlement transfers real funds on Base Sepolia, so the payer wallet must be
funded and the spend is real.
