# Run Your Own Facilitator

Every x402 resource server needs a facilitator to verify and settle
payments — and until now, running one meant trusting a hosted service or
writing your own from scratch. `X402.Facilitator.Engine` and
`X402.Plug.Facilitator` turn this SDK into the facilitator itself: a
supervised, self-hosted verify/settle service for the `exact`/EVM scheme,
speaking the same wire protocol as the reference facilitators.

The engine assembles pieces you may already use — `X402.Verify.EVM` for the
full local verification checklist, `X402.RPC` for chain access,
`X402.Signer` for the fee-payer key — and adds the settlement pipeline:
EIP-1559 transaction assembly, signing, broadcast, and receipt tracking.

## Quick start

```elixir
# In your supervision tree:
defmodule MyFacilitator.Application do
  use Application

  @impl true
  def start(_type, _args) do
    {:ok, rpc} =
      X402.RPC.new(rpc_url: "https://sepolia.base.org", finch: MyFacilitator.Finch)

    {:ok, signer} = X402.Signer.LocalKey.new(System.fetch_env!("PRIVATE_KEY"))

    {:ok, engine} =
      X402.Facilitator.Engine.new(
        rpc: rpc,
        signer: signer,
        networks: ["eip155:84532"]
      )

    children = [
      {Finch,
       name: MyFacilitator.Finch,
       pools: %{default: X402.Facilitator.HTTP.secure_pool_opts()}},
      {Bandit, plug: {X402.Plug.Facilitator, engine: engine}, port: 4022}
    ]

    Supervisor.start_link(children, strategy: :one_for_one)
  end
end
```

That serves the facilitator API:

```
POST /verify     -> {"isValid": true, "payer": "0x..."}
POST /settle     -> {"success": true, "transaction": "0x...", "network": "eip155:84532", "payer": "0x..."}
GET  /supported  -> {"kinds": [...], "extensions": [], "signers": {"eip155:*": ["0x..."]}}
```

Point any x402 resource server at it — including this SDK's own
`X402.Plug.PaymentGate` through `X402.Facilitator` — or call
`X402.Facilitator.Engine.verify/3` and `settle/3` directly from your own
transport, skipping HTTP entirely.

If you drive this engine through the SDK's `X402.Facilitator` client, keep
the client's `:receive_timeout_ms` (default: `90_000`) comfortably above
the engine's `:receipt_timeout_ms` (default: `60_000`). A shorter client
timeout gives up mid-settlement, and the client's built-in retry can
issue a second `POST /settle` while the first transaction is still in
flight — the payer's authorization is already broadcast, so the retry
races the confirmation and may look like a settlement failure to the
caller.

A complete runnable project lives in `examples/facilitator/`.

## What verify checks

`verify/3` runs `X402.Verify.EVM` at the `:full` level: scheme, network,
and EIP-712 domain requirements; recipient and exact-amount equality; the
validity window; signature verification routed by payer bytecode (EOA
`ecrecover`, strict ERC-1271 `isValidSignature` for deployed smart
wallets); asset bytecode presence; `balanceOf` funding; and an `eth_call`
simulation of the transfer with failure diagnosis. Rejections use the
canonical cross-SDK `invalidReason` strings. See the Local Payment
Verification guide for the full checklist.

## The settlement pipeline

`settle/3` never trusts a prior verify — it re-verifies the payment
independently (the exact-EVM scheme's normative requirement), then:

1. Builds `transferWithAuthorization` calldata with
   `X402.EIP3009.transfer_calldata/2` — the same builder verification
   simulates with, so simulation and settlement cannot diverge.
2. Fetches gas and fee data in one batched RPC round-trip:
   `eth_estimateGas` (a revert here is itself a simulation failure and
   rejects the settlement), `eth_maxPriorityFeePerGas` + `eth_feeHistory`
   for EIP-1559 fees (`eth_gasPrice` fallback for nodes without them), and
   the `pending` nonce.
3. Encodes the EIP-1559 transaction (`X402.Transaction`), signs its keccak
   digest through the configured `X402.Signer`, and broadcasts it via
   `eth_sendRawTransaction`.
4. Polls `eth_getTransactionReceipt` until confirmation or
   `:receipt_timeout_ms`.

A broadcast whose confirmation cannot be established — receipt timeout, or
a transport failure mid-broadcast — returns the spec's **non-terminal**
`"settlement_pending"` with a non-empty transaction hash, so the caller
can reconcile on chain before deciding whether to retry.

## Fee-payer safety

The facilitator's key pays gas for strangers' payments, so what it signs
is structurally constrained:

* Settlement transactions always have `to` set to the *verified*
  requirements' `asset`, `value` `0`, and calldata built exclusively from
  the authorization fields the signature check just proved. There is no
  code path that signs caller-supplied calldata — the key can broadcast
  transfers the payer authorized, and nothing else.
* ERC-6492 **counterfactual** payments (undeployed smart wallets whose
  signature wrapper carries factory deployment calldata) are rejected
  fail-closed at verify *and* at settle's re-verify, because settling them
  would require broadcasting that arbitrary factory calldata. Deployed
  ERC-1271 smart wallets are fully supported.

Even so: fund the fee-payer key with gas money only, and prefer a
KMS-backed `X402.Signer` implementation over `X402.Signer.LocalKey` for
production (the signer must support signing raw 32-byte digests).

## Hooks

`X402.Hooks` callbacks wrap both operations, mirroring the reference
facilitator's lifecycle hooks — payment tracking, allow/deny policies, and
failure recovery without touching the engine:

```elixir
defmodule MyFacilitator.Hooks do
  @behaviour X402.Hooks

  def before_verify(context, _metadata), do: {:cont, context}
  def after_verify(context, _metadata), do: {:cont, context}
  def on_verify_failure(context, _metadata), do: {:cont, context}

  # Only settle payments this facilitator verified in the last minute.
  def before_settle(context, _metadata) do
    case MyFacilitator.Tracker.verified_recently?(context.payload) do
      true -> {:cont, context}
      false -> {:halt, "payment_not_verified"}
    end
  end

  def after_settle(context, _metadata), do: {:cont, context}
  def on_settle_failure(context, _metadata), do: {:cont, context}
end
```

A `before_*` `{:halt, reason}` becomes a rejected wire response (not an
exception), and `on_*_failure` may `{:recover, result}` with a
replacement response.

## Production notes

* **Authentication** — the scaffold's `:auth_token` is a minimal bearer
  check for private deployments. Put real authentication, TLS
  termination, and rate limiting in front of a public facilitator.
* **The wire contract** — protocol-level rejections are `200` responses
  (`isValid: false` / `success: false`); `400`/`413` cover malformed or
  oversized bodies, and `500` (opaque body, details logged) means an
  infrastructure failure such as an unreachable RPC node.
* **`/discovery/resources`** — optional in the facilitator API and not
  served by the scaffold (it answers `404`); bazaar serving is out of
  scope here.
* **Observability** — the engine emits
  `[:x402, :facilitator_engine, :verify]` and
  `[:x402, :facilitator_engine, :settle]` telemetry, and every RPC call
  emits `[:x402, :rpc, :request]`.
* **One settle per payment** — the EIP-3009 nonce makes on-chain replay
  impossible: a second settle of the same payload is rejected by the
  token contract (`nonce_already_used`). A `settlement_pending` result
  should be reconciled against the returned transaction hash rather than
  blindly retried.
