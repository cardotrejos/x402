# Local Payment Verification

By default an x402 resource server delegates payment verification to a remote
facilitator: the server's security posture equals the facilitator's, fully.
Two modules remove that dependency by running the facilitator verify
checklist locally — the same checks the reference TypeScript, Go, and Python
facilitator engines perform:

- `X402.Verify.EVM` for EVM `exact`/`eip3009` payments, from EIP-712
  signature recovery to on-chain `transferWithAuthorization` simulation.
- `X402.Verify.SVM` for `exact` payments on `solana:*` networks, from local
  Ed25519 signature verification to `simulateTransaction`.

Use them to cross-check a facilitator you do not fully trust, to reject junk
before paying for a facilitator round-trip, or as the verification core of
your own facilitator — that last use is not hypothetical:
`X402.Facilitator.Engine` verifies through `X402.Verify.EVM` and
`X402.Facilitator.SVMEngine` through `X402.Verify.SVM` (see
[Run Your Own Facilitator](facilitator.html)).

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
    {:x402, "~> 0.6.0"},
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

## Verifying inside the payment gate

`X402.Plug.PaymentGate` runs local verification inline when you pass the
`local_verification:` option — before the facilitator round-trip, on every
exact-EVM payment a gated route matches. A bare level atom is shorthand for
`[level: level]`:

```elixir
plug X402.Plug.PaymentGate,
  facilitator: MyApp.Facilitator,
  local_verification: :signature,
  routes: [...]
```

The keyword form accepts the full `X402.Verify.EVM.verify/3` configuration:
`:level`, `:rpc` (an `X402.RPC` struct), `:simulate`
(`true | false | :counterfactual_only`), `:verify_chain_id`,
`:eip6492_allowed_factories`, and `:multicall_address`:

```elixir
{:ok, rpc} = X402.RPC.new(rpc_url: "https://mainnet.base.org", finch: MyApp.Finch)

plug X402.Plug.PaymentGate,
  facilitator: MyApp.Facilitator,
  local_verification: [level: :full, rpc: rpc],
  routes: [...]
```

Level `:full` requires `:rpc` at `init/1` — the gate raises on the
misconfiguration when the plug initializes rather than answering
`{:error, :rpc_not_configured}` on the first paid request.

Scope and failure semantics:

- **Exact-EVM only.** Local verification runs when the matched requirements
  have scheme `"exact"` and an `eip155:*` network. Every other
  scheme/network combination — `upto`, exact-SVM, custom schemes — skips it
  silently; the facilitator remains the authority for those kinds, and for
  exact-EVM too: it still verifies and settles payments local verification
  accepted.
- **Rejections answer 402.** `{:invalid, reason}` is a definitive verdict
  about the payment: the gate rejects with 402 exactly like a facilitator
  rejection, carrying the canonical `invalidReason` string
  (`X402.Verify.EVM.reason_string/1`) as the rejection reason — the response
  is indistinguishable from the facilitator having rejected it.
- **Infrastructure failures answer 500.** A missing crypto dependency
  (`:missing_dependency`), an unconfigured or unreachable RPC endpoint
  (`:rpc_not_configured`, `{:rpc_error, _}`), or a chain-id mismatch is not
  a verdict about the payment: the gate fails closed with 500 rather than
  silently downgrading the configured level.

`level: :signature` is a good default: it proves the EOA signature with zero
added RPC latency on the request path, while the facilitator remains the
authority on chain state. `level: :full` runs the whole checklist — funding,
nonce state, transfer simulation — at the cost of RPC round-trips per
request. Note that `:signature` rejects smart-wallet signers fail-closed
(`smart_wallet_requires_rpc`); accepting them locally requires `:full`.

### The `before_verify` hook

The hook approach the gate supported before `local_verification:` existed
remains available for custom policy — a different verifier, per-route
levels, or checks on non-EVM schemes. The gate aborts with a 402 when the
hook halts:

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
```

Pass the module as the gate's `hooks:` option. For plain exact-EVM
verification, prefer `local_verification:` — it maps rejections onto the
canonical reason strings and fails closed on infrastructure errors without
any hook code.

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
   deploys the wallet and executes the transfer in a single `eth_call`.

```elixir
X402.Verify.EVM.verify(payload, requirements,
  level: :full,
  rpc: rpc,
  eip6492_allowed_factories: ["0x0BA5ED0c6AA8c49038F819E587E2633c4A9F428a"]
)
```

Because that simulation is the only possible proof, the `:simulate` option
interacts with counterfactual payments in three modes:

- `true` (default) — the EOA/ERC-1271 transfer simulation runs, and
  counterfactual payments get the atomic deploy-and-transfer simulation.
- `false` — no simulation at all; counterfactual payments are rejected with
  `{:invalid, :undeployed_smart_wallet}` rather than accepted unproven.
- `:counterfactual_only` — the EOA/ERC-1271 transfer simulation is skipped
  like `false`, but the atomic counterfactual proof still runs. This is the
  mode `X402.Facilitator.Engine` uses for the independent re-verify inside
  `settle/3`: verify and settle apply the same counterfactual policy without
  paying a second transfer simulation for ordinary payments.

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
`"invalid_exact_evm_nonce_already_used"`), so a facilitator engine built on
it answers wire-compatible verify responses.

## SVM verification

`X402.Verify.SVM` is the Solana counterpart: the facilitator verify
checklist for `exact` payments on `solana:*` networks, following the
exact-SVM scheme specification's *static verification path*. It is
`X402.Facilitator.SVMEngine`'s verification core the way `X402.Verify.EVM`
is the EVM engine's.

| Level | Checks | Needs |
|---|---|---|
| `:structural` | scheme/network match, fee-payer requirements, transaction decoding, Ed25519 verification of every required signer except the fee-payer slot, address-lookup-table rejection, fail-closed requirements validation, and the static instruction whitelist via `X402.Scheme.ExactSVM` | nothing — Ed25519 rides on OTP `:crypto` |
| `:full` | `:structural` + `simulateTransaction` of the exact payload bytes settlement would co-sign | an `X402.RPC` endpoint (called through `X402.Solana.RPC`), else `{:error, :rpc_not_configured}` |

```elixir
{:ok, payload} = X402.PaymentSignature.decode_and_validate(header_value, requirements)

{:ok, rpc} =
  X402.RPC.new(
    rpc_url: "https://api.mainnet-beta.solana.com",
    finch: MyApp.Finch
  )

case X402.Verify.SVM.verify(payload, requirements,
       level: :full,
       rpc: rpc,
       fee_payer: "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu"
     ) do
  {:ok, %{payer: payer}} ->
    # payer is the Base58 authority of the TransferChecked instruction —
    # the account whose tokens move.
    {:ok, payer}

  {:error, {:invalid, reason}} ->
    {:reject, X402.Verify.SVM.reason_string(reason)}

  {:error, other} ->
    # :rpc_not_configured or {:rpc_error, _}. Fail closed.
    {:reject, other}
end
```

The `:fee_payer` option is required at every level: the requirements'
`extra.feePayer` must equal an address you actually control
(`fee_payer_not_managed` otherwise) and must be the transaction's account 0
(`fee_payer_mismatch`) — a facilitator must never co-sign a transaction
whose fee payer it does not manage. The optional
`:max_required_signatures` caps the signature count (each adds 5000
lamports of base fee, paid by the fee payer), and `:commitment` (default
`"confirmed"`) sets the simulation's commitment level.

What the checks guard, and why:

- **Local Ed25519 verification is the signature check, not an
  optimization.** The fee-payer slot (slot 0) stays unsigned until
  settlement co-signs it, so `simulateTransaction` necessarily runs with
  `sigVerify: false` — simulation proves nothing about signatures. Every
  required signer except the fee-payer slot is therefore verified locally
  (pure OTP `:crypto`, no optional dependency) at **every** level; without
  this, a forged payload would pass simulation and only the broadcast would
  reject it.
- **Requirements are validated fail-closed.** `X402.Scheme.ExactSVM`'s
  gate-side pre-check skips comparisons whose requirements field it cannot
  interpret locally, deferring to the facilitator. `X402.Verify.SVM` *is*
  the deferral target, so an uninterpretable `amount`, `asset`, or `payTo`
  is rejected, never skipped — otherwise the skip would silently drop the
  money-matching checks.
- **The static instruction whitelist** (dispatched through
  `X402.Scheme.ExactSVM`) pins the transaction to the reference layout:
  3–7 instructions in the specified order, compute-budget bounds, the
  fee-payer isolation rule (the fee payer must not be the account
  transferring funds), amount / mint / destination-ATA equality against
  the requirements, and memo enforcement.
- **Address lookup tables are rejected fail-closed**
  (`alt_resolution_not_available`): an ALT transaction's account set cannot
  be verified without resolving the tables — the spec's opt-in smart-wallet
  path, currently out of scope.

`X402.Verify.SVM.reason_string/1` maps each reason atom onto the TypeScript
reference's `invalid_exact_svm_*` vocabulary (for example
`:amount_mismatch` → `"invalid_exact_svm_payload_amount_mismatch"`) — the
strings the hosted facilitator emits.

## What local verification cannot tell you

- **Replay across servers.** A valid authorization can be presented to many
  resource servers until it is settled on chain. Local verification proves
  the payment *could* settle — pair it with `X402.Plug.PaymentGate`'s replay
  protection, which claims a canonical key derived from signature-covered
  content for every proof (see
  [Replay protection](plug-integration.html#replay-protection)), and with
  settlement.
- **Race to settlement.** Funding and nonce state hold at the instant of the
  `eth_call`; they can change before you settle. Settlement remains the only
  proof of payment.
- **Other schemes.** `X402.Verify.EVM` understands `exact` with the default
  `eip3009` asset transfer method; `X402.Verify.SVM` understands `exact` on
  `solana:*`. Anything else returns `{:error, {:invalid, ...}}` rather than
  guessing.
