# Local Payment Verification

By default an x402 resource server delegates payment verification to a remote
facilitator: the server's security posture equals the facilitator's, fully.
`X402.Verify.EVM` removes that dependency for EVM `exact`/`eip3009` payments
by running the facilitator verify checklist locally — the same checks the
reference TypeScript, Go, and Python facilitator engines perform, from
EIP-712 signature recovery to on-chain `transferWithAuthorization`
simulation.

Use it to cross-check a facilitator you do not fully trust, to reject junk
before paying for a facilitator round-trip, or as the verification core of
your own facilitator.

## Verification levels

The `:level` option is required and explicit. A level whose capability is
missing returns an error — verification never silently downgrades to a
weaker check.

| Level | Checks | Needs |
|---|---|---|
| `:structural` | scheme, network, EIP-712 domain requirements, payload shape, `payTo` recipient equality, exact amount equality, `validAfter`/`validBefore` with the 6-second settlement buffer | nothing |
| `:signature` | `:structural` + EIP-712 digest recomputation and EOA signature recovery | `ex_keccak`, `ex_secp256k1` (optional deps), else `{:error, :missing_dependency}` |
| `:full` | `:signature` + chain-id cross-check, payer-bytecode signature routing (ECDSA / ERC-1271), ERC-6492 handling, asset bytecode presence, `balanceOf` funding, `eth_call` transfer simulation with failure diagnosis | an `X402.RPC` endpoint, else `{:error, :rpc_not_configured}` |

At `:signature`, smart-wallet signatures (ERC-1271 contracts, ERC-6492
wrappers) are rejected with `{:error, {:invalid, :smart_wallet_requires_rpc}}`
rather than assumed valid — proving them requires the chain.

## Quick start

Add the optional dependencies and a Finch pool:

```elixir
def deps do
  [
    {:x402, "~> 0.6"},
    {:finch, "~> 0.19"},
    {:ex_secp256k1, "~> 0.8"},
    {:ex_keccak, "~> 0.7"}
  ]
end
```

Verify a decoded payment:

```elixir
{:ok, payload} = X402.PaymentSignature.decode_and_validate(header_value, requirements)

{:ok, rpc} =
  X402.RPC.new(
    rpc_url: "https://sepolia.base.org",
    finch: MyApp.Finch
  )

case X402.Verify.EVM.verify(payload, requirements, level: :full, rpc: rpc) do
  {:ok, %{payer: payer, signature_type: type}} ->
    # Every check passed: signature, funding, timing, and a simulated
    # transferWithAuthorization all hold at this instant.
    {:ok, payer, type}

  {:error, {:invalid, reason}} ->
    # The payment is definitively invalid (e.g. :recipient_mismatch,
    # :insufficient_balance, :nonce_already_used).
    {:reject, reason}

  {:error, other} ->
    # Could not verify: :missing_dependency, :rpc_not_configured,
    # {:rpc_error, _}, {:chain_id_mismatch, _, _}. Fail closed.
    {:reject, other}
end
```

`X402.RPC.new/1` enforces `https://` (plain `http://` only for
`localhost`) and rides on your own Finch pool — configure TLS peer
verification as shown in `X402.Facilitator.HTTP.secure_pool_opts/0`.

Pure levels need no RPC at all:

```elixir
{:ok, _} = X402.Verify.EVM.verify(payload, requirements, level: :signature)
```

## Gating requests with the `before_verify` hook

`X402.Plug.PaymentGate` already runs cheap structural prechecks
(`local_prechecks: true`) before every facilitator call. To add cryptographic
verification without waiting for the scheme-behaviour integration, run
`X402.Verify.EVM` from a `before_verify` hook — the gate aborts with a 402
when the hook halts:

```elixir
defmodule MyApp.LocalVerification do
  @behaviour X402.Hooks

  alias X402.Hooks.Context

  @impl true
  def before_verify(%Context{payload: payload, requirements: requirements} = context, _metadata) do
    case X402.Verify.EVM.verify(payload, requirements, level: :signature) do
      {:ok, _verification} -> {:cont, context}
      {:error, reason} -> {:halt, {:local_verification_failed, reason}}
    end
  end

  @impl true
  def after_verify(context, _metadata), do: {:cont, context}
  @impl true
  def on_verify_failure(context, _metadata), do: {:cont, context}
  @impl true
  def before_settle(context, _metadata), do: {:cont, context}
  @impl true
  def after_settle(context, _metadata), do: {:cont, context}
  @impl true
  def on_settle_failure(context, _metadata), do: {:cont, context}
end

plug X402.Plug.PaymentGate,
  accepts: [requirements],
  facilitator: [url: "https://facilitator.example.com", finch: MyApp.Finch],
  hooks: MyApp.LocalVerification
```

`level: :signature` is a good fit here: it proves the EOA signature without
adding RPC latency to the request path, while the facilitator (or a
`level: :full` check) remains the authority on chain state. Payments the
signature level cannot prove — smart-wallet signers — halt fail-closed; relax
that only by running `level: :full` with an `:rpc` config in the hook.

## ERC-6492 counterfactual wallets

A payment signed by a not-yet-deployed smart wallet arrives as an ERC-6492
wrapper: the wallet's inner signature plus the factory call that would deploy
it. Following the reference Go design, such a signature is **never** valid on
the strength of the wrapper alone:

1. The factory must appear in `:eip6492_allowed_factories`. The default is
   `[]`, which rejects every counterfactual payment with
   `{:invalid, :eip6492_factory_not_allowed}` — list only factories you
   trust, since settlement executes their calldata.
2. Validity is proven exclusively by an atomic Multicall3 simulation that
   deploys the wallet and executes the transfer in a single `eth_call`. With
   `simulate: false` counterfactual payments are rejected with
   `{:invalid, :undeployed_smart_wallet}`.

```elixir
X402.Verify.EVM.verify(payload, requirements,
  level: :full,
  rpc: rpc,
  eip6492_allowed_factories: ["0x0BA5ED0c6AA8c49038F819E587E2633c4A9F428a"]
)
```

Deployed smart wallets (including ERC-7702-delegated EOAs) take the strict
ERC-1271 path: `isValidSignature` must return the magic value, with no ECDSA
fallback — the same routing on-chain `SignatureChecker` implementations use,
so a locally accepted signature is one the token contract would accept.

## Failure diagnosis

When the `eth_call` simulation fails, the module mirrors the reference
facilitators' diagnosis: the revert reason is classified first
(nonce already used, expired window, insufficient balance, invalid
signature), and unrecognized failures trigger one batched probe of
`authorizationState`, `name`, `version`, and `balanceOf` to produce the most
specific reason — `:eip3009_not_supported`, `:nonce_already_used`,
`:token_name_mismatch`, `:token_version_mismatch`, `:insufficient_balance`,
or `:simulation_failed`.

`X402.Verify.EVM.reason_string/1` maps each reason atom onto the canonical
cross-SDK `invalidReason` string (for example `:nonce_already_used` →
`"invalid_exact_evm_nonce_already_used"`), so a future facilitator engine can
answer wire-compatible verify responses.

## What local verification cannot tell you

- **Replay across servers.** A valid authorization can be presented to many
  resource servers until it is settled on chain. Local verification proves
  the payment *could* settle — pair it with the payment-identifier replay
  cache and settlement.
- **Race to settlement.** Funding and nonce state hold at the instant of the
  `eth_call`; they can change before you settle. Settlement remains the only
  proof of payment.
- **Non-EVM schemes.** Only `exact` with the default `eip3009` asset transfer
  method is supported; other schemes and networks return
  `{:error, {:invalid, ...}}` rather than guessing.
