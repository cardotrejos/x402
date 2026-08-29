# Run Your Own Facilitator

Every x402 resource server needs a facilitator to verify and settle
payments — and until now, running one meant trusting a hosted service or
writing your own from scratch. `X402.Facilitator.Engine` (EVM),
`X402.Facilitator.SVMEngine` (Solana), and `X402.Plug.Facilitator` turn
this SDK into the facilitator itself: a supervised, self-hosted
verify/settle service for the `exact` scheme, speaking the same wire
protocol as the reference facilitators.

The engines assemble pieces you may already use — `X402.Verify.EVM` and
`X402.Verify.SVM` for the full local verification checklists, `X402.RPC`
for chain access, `X402.Signer` for the fee-payer key — and add the
settlement pipeline: transaction assembly, signing, broadcast, receipt
tracking, and reconciliation of broadcasts whose confirmation could not
be established.

## Quick start (EVM)

A production-shaped facilitator supervises three processes next to the
engine: the HTTP pool, an `X402.Facilitator.NonceManager` (so concurrent
settlements never race on the fee payer's pending nonce), and an
`X402.Facilitator.PendingSettlementStore.ETS` (so a `settlement_pending`
retry reconciles instead of broadcasting twice):

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
        networks: ["eip155:84532"],
        nonce_manager: MyFacilitator.NonceManager,
        pending_settlement_store:
          {X402.Facilitator.PendingSettlementStore.ETS, MyFacilitator.PendingStore}
      )

    children = [
      {Finch,
       name: MyFacilitator.Finch,
       pools: %{default: X402.Facilitator.HTTP.secure_pool_opts()}},
      {X402.Facilitator.NonceManager, name: MyFacilitator.NonceManager},
      {X402.Facilitator.PendingSettlementStore.ETS, name: MyFacilitator.PendingStore},
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

A complete runnable project lives in `examples/facilitator/`.

## Serve Solana too

`X402.Facilitator.SVMEngine` is the SVM counterpart: `exact` payments on
`solana:*` networks, verified with `X402.Verify.SVM` and settled by
co-signing the fee-payer slot of the client-built transaction. The signer
must implement the `sign_ed25519/2` callback — `X402.Signer.SolanaKey`
does (it accepts a raw 32-byte seed, a 64-byte `solana-keygen` keypair,
or Base58/Base64 encodings of either):

```elixir
{:ok, sol_rpc} =
  X402.RPC.new(rpc_url: "https://api.devnet.solana.com", finch: MyFacilitator.Finch)

{:ok, sol_signer} = X402.Signer.SolanaKey.new(System.fetch_env!("SOLANA_FEE_PAYER_KEY"))

{:ok, svm_engine} =
  X402.Facilitator.SVMEngine.new(
    rpc: sol_rpc,
    signer: sol_signer,
    networks: ["solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"],
    settlement_cache:
      {X402.Extensions.PaymentIdentifier.ETSCache, MyFacilitator.SettlementCache},
    pending_settlement_store:
      {X402.Facilitator.PendingSettlementStore.ETS, MyFacilitator.PendingStore}
  )
```

with the two stores supervised alongside the others:

```elixir
{X402.Extensions.PaymentIdentifier.ETSCache,
 name: MyFacilitator.SettlementCache, ttl_ms: 120_000},
{X402.Facilitator.PendingSettlementStore.ETS, name: MyFacilitator.PendingStore}
```

Configure **both** stores, as above — the pairing the module documentation
recommends. The `:settlement_cache` is the atomic duplicate-settlement
claim: settle computes the transaction's key (SHA-256 of its message
bytes) and claims it before any RPC work, so a concurrent settle of the
same payment is rejected with `duplicate_settlement` instead of racing
the broadcast. The 120-second TTL matches the reference facilitators —
roughly twice the blockhash lifetime, after which the transaction can no
longer land anyway. The `:pending_settlement_store` is what makes the
claim safe under a `settlement_pending` verdict: with a store, the claim
is kept and the retry reconciles against the recorded signature; with a
cache but *no* store, the engine must release the claim so the retry can
re-broadcast the identical wire bytes (collapsed by the network to one
transaction id) rather than dead-end on `duplicate_settlement`. Without
either, duplicate protection is disabled entirely.

### One Plug, both chains

`X402.Plug.Facilitator` serves several engines from one endpoint via
`:engines` (exactly one of `:engine` or `:engines` must be given):

```elixir
{Bandit, plug: {X402.Plug.Facilitator, engines: [engine, svm_engine]}, port: 4022}
```

`POST /verify` and `POST /settle` dispatch to the first engine whose
`supported/1` kinds contain the request's `(scheme, network)` pair; when
none matches, the request is answered with a `200` protocol rejection
(`unsupported_scheme`, or `invalid_network` when some engine serves the
scheme on other networks). `GET /supported` merges the engines'
responses — kinds concatenated, extensions unioned, signer families
merged:

```json
{
  "kinds": [
    {"x402Version": 2, "scheme": "exact", "network": "eip155:84532"},
    {"x402Version": 2, "scheme": "exact",
     "network": "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
     "extra": {"feePayer": "9hSR..."}}
  ],
  "extensions": [],
  "signers": {"eip155:*": ["0x..."], "solana:*": ["9hSR..."]}
}
```

Note the SVM kinds carry `extra.feePayer` — the channel through which
resource servers discover which fee payer to advertise in their 402
challenges (SVM clients must build their transaction around the sponsor's
key, so the gate injects it into the requirements it serves).

## What verify checks

**EVM** — `Engine.verify/3` runs `X402.Verify.EVM` at the `:full` level:
scheme, network, and EIP-712 domain requirements; recipient and
exact-amount equality; the validity window; signature verification routed
by payer bytecode (EOA `ecrecover`, strict ERC-1271 `isValidSignature`
for deployed smart wallets, and — only with a configured
`:eip6492_allowed_factories` allowlist — the atomic Multicall3
deploy-and-transfer simulation for ERC-6492 counterfactual wallets);
asset bytecode presence; `balanceOf` funding; and an `eth_call`
simulation of the transfer with failure diagnosis. Rejections use the
canonical cross-SDK `invalidReason` strings. See the
[Local Payment Verification](local-verification.html) guide for the full
checklist.

**SVM** — `SVMEngine.verify/3` runs `X402.Verify.SVM` at `:full`,
mirroring the exact-SVM specification's static verification path:
fee-payer identity (the requirements' `extra.feePayer` must be this
engine's signer, and account 0 of the transaction must be that fee
payer); **local Ed25519 verification of every required signer except the
fee-payer slot** — mandatory, because the simulation runs with
`sigVerify: false` (the fee-payer slot is unsigned until settlement), so
local verification *is* the signature check; the static instruction
whitelist (compute-budget bounds, `TransferChecked` amount/mint/
destination, memo enforcement, and fee-payer isolation — no instruction
may reference the sponsor's key, so its signature can never move its
funds); and a `simulateTransaction` round-trip. Transactions using
address lookup tables are rejected fail-closed — their account set cannot
be verified without table resolution. Rejections use the TypeScript
reference's `invalid_exact_svm_*` reason strings
(`X402.Verify.SVM.reason_string/1`).

## The settlement pipeline

Both engines' `settle/3` never trusts a prior verify — they re-verify the
payment independently (the exact scheme's normative requirement) before
touching the chain.

**EVM** — after checking the pending store (next section) and
re-verifying:

1. Builds `transferWithAuthorization` calldata with
   `X402.EIP3009.transfer_calldata/3` — the same builder verification
   simulates with, so simulation and settlement cannot diverge. For a
   verified counterfactual payment, the wallet is deployed first (see
   Fee-payer safety below).
2. Fetches gas and fee data in one batched RPC round-trip:
   `eth_estimateGas` (a revert here is itself a simulation failure and
   rejects the settlement), `eth_maxPriorityFeePerGas` + `eth_feeHistory`
   for EIP-1559 fees (`eth_gasPrice` fallback for nodes without them), and
   the `pending` nonce — or a nonce assigned by the configured
   `X402.Facilitator.NonceManager`.
3. Encodes the EIP-1559 transaction (`X402.Transaction`), signs its keccak
   digest through the configured `X402.Signer`, and broadcasts it via
   `eth_sendRawTransaction`.
4. Polls `eth_getTransactionReceipt` until confirmation or
   `:receipt_timeout_ms`.
5. Checks the confirmed receipt for the matching ERC-20 `Transfer` event.
   A confirmed receipt only proves the transaction did not revert; the
   `Transfer(from, to, value)` log — checked against the *signed*
   authorization's `from`, `to`, and `value` and emitted by the
   requirements' `asset` contract — is what proves the payment moved.
   A parseable receipt without the matching event is the terminal
   `invalid_exact_evm_transfer_event_mismatch`; logs the engine cannot
   read structurally leave the transfer unestablished and degrade to the
   non-terminal `settlement_pending` instead.

**SVM** — after the duplicate-settlement claim, the pending-store check,
and the re-verify (which re-simulates by default — the blockhash-freshness
and balance guard right before a preflight-skipping broadcast; see
`:simulate_in_settle`):

1. Signs the transaction's message bytes with the configured signer and
   splices the signature into the fee payer's slot 0
   (`X402.Solana.Transaction.attach_signature/3`).
2. Broadcasts via `X402.Solana.RPC.send_transaction/2` with
   `skipPreflight: true` — verification and simulation already ran.
3. Polls `getSignatureStatuses` until the transaction reaches
   `confirmed`/`finalized` or `:confirm_timeout_ms`.

On both chains, a broadcast whose confirmation cannot be established —
receipt/confirmation timeout, or a transport failure mid-broadcast —
returns the spec's **non-terminal** `"settlement_pending"` with a
non-empty transaction hash (EVM) or Base58 signature (Solana).

## Pending settlements and reconciliation

`settlement_pending` means "a transaction was broadcast, and its fate is
unknown". Without more machinery that knowledge dies with the response: a
client retrying the identical payment would re-verify and re-broadcast a
second transaction. The `X402.Facilitator.PendingSettlementStore`
behaviour closes the loop — before verifying, `settle/3` looks the
payment up in the store and, on a hit, re-awaits the already-broadcast
transaction instead of broadcasting a new one.

What an entry records:

* `:transaction` — the transaction hash (EVM) or Base58 signature (SVM).
* `:provenance` — `:node_acknowledged` when the node returned the hash,
  or `:local_hash` when the transport failed mid-broadcast and the hash
  was computed locally from the signed bytes (the node may never have
  seen it).
* `:raw_transaction` — the raw signed bytes, kept for `:local_hash`
  entries only, so operators can inspect or manually rebroadcast a
  transaction the node may have missed. **The engine itself never
  rebroadcasts** — rebroadcasting a transaction the node may have
  accepted risks a duplicate-spend race, so `:local_hash` entries are
  re-awaited exactly like node-acknowledged ones.

Three details of the design are load-bearing:

* **Delete before reconcile.** On a store hit the entry is deleted first,
  then the recorded transaction is re-awaited. A concurrent retry of the
  same payload therefore misses the store and falls through to the normal
  path, where the chain itself rejects the duplicate — the EIP-3009
  authorization nonce can only be consumed once, and a Solana resend of
  the identical bytes collapses to the same transaction id.
* **Pending keys bind the signed content.** The EVM key hashes the
  payment's signature *together with* every authorization field the
  reconcile path later checks (`from`, `to`, `value`, `validAfter`,
  `validBefore`, `nonce`) and the requirements' `asset`; the SVM key is
  the SHA-256 of the transaction's message bytes. This matters because
  the reconcile fast path runs *without* re-verification: if the key were
  the signature alone, anyone who saw the `PAYMENT-SIGNATURE` header
  could replay it with a mutated authorization, hit the entry, burn it
  (delete-before-reconcile), and turn a confirmed transfer into a
  terminal mismatch. With the full binding, a mutated retry simply misses
  the store and falls through to re-verification, which rejects it — the
  honest retry's entry survives.
* **A failed store write downgrades to a terminal response.** A pending
  answer that was not persisted cannot be made good on — the retry would
  miss the store and double-broadcast. The engine logs a warning and
  answers with a terminal failure that keeps the transaction hash for
  manual reconciliation.

On the resource-server side, `X402.Plug.PaymentGate` complements this
automatically: a `success: false` settle whose `errorReason` is
`"settlement_pending"` *and* that carries a transaction hash is re-settled
exactly once with the identical payload — the retry hits the
facilitator's pending-store fast path and reconciles. A second pending,
and every other failure, follows the normal failure path.

The bundled `X402.Facilitator.PendingSettlementStore.ETS` adapter expires
entries after five minutes and is per-node; a facilitator running several
instances behind a load balancer needs a shared store instead — the
behaviour's documentation includes a Redis adapter sketch.

## Fee-payer safety

The facilitator's key pays gas for strangers' payments, so what it signs
is structurally constrained.

On EVM, settlement transactions always have `to` set to the *verified*
requirements' `asset`, `value` `0`, and calldata built exclusively from
the authorization fields the signature check just proved. With the
default configuration there is no code path that signs caller-supplied
calldata — ERC-6492 **counterfactual** payments (undeployed smart wallets
whose signature wrapper carries factory deployment calldata) are rejected
fail-closed at verify *and* at settle's re-verify, while deployed
ERC-1271 smart wallets are fully supported.

A non-empty `:eip6492_allowed_factories` relaxes exactly that one
constraint, opting into counterfactual *settlement* the way the reference
facilitators support it:

* The wrapper's factory calldata is broadcast as its own transaction
  first — but only when the factory address appears on the allowlist
  (`eip6492_factory_not_allowed` otherwise, re-checked at settle even
  though the re-verify already enforced it), and capped by
  `:max_deploy_gas_limit` (smart-account deployments legitimately cost
  far more than a transfer, so they carry their own ceiling).
* Settle then requires a successful deploy receipt
  (`smart_wallet_deployment_failed` otherwise — terminal but safe: the
  EIP-3009 authorization was not consumed, so the client may retry the
  identical payment) before settling with the unwrapped inner signature.
  A wallet that was deployed since verification skips the deployment
  transaction.
* Verification must predict settlement: the allowlist is threaded into
  verify, where a counterfactual signature is proven by an atomic
  Multicall3 simulation that deploys and transfers in one `eth_call`.
  That proof is the *only* possible check of a counterfactual signature,
  so it runs even when simulation is otherwise off — `X402.Verify.EVM`'s
  `:counterfactual_only` simulate mode, which is what the engine uses
  internally when `:simulate` or `:simulate_in_settle` is `false`.

Independent of the allowlist, `:max_gas_limit` caps every settlement
transaction (a legitimate `transferWithAuthorization` costs well under
100k gas; an estimate above the ceiling means the asset contract is
burning the fee payer's gas, and the settlement is refused with
`settle_gas_limit_exceeded`).

On Solana, the constraint is verification itself: the engine only ever
co-signs a transaction whose account 0 is its own key, whose instructions
match the static whitelist, and in which the fee payer is referenced by
no instruction — the sponsor's signature can never move the sponsor's
funds. `:max_required_signatures` optionally caps the signature count
(each one adds 5000 lamports of base fee, paid by the engine's key).

Even so: fund the fee-payer keys with gas money only, and prefer a
KMS-backed `X402.Signer` implementation over the bundled local-key
signers for production (the EVM signer must support signing raw 32-byte
digests).

## The nonce manager

An EVM engine without a nonce manager reads `eth_getTransactionCount`
(`pending`) per settlement, which races under concurrency: two settles
can read the same nonce, sign two different payments with it, and the
node rejects one even though its EIP-3009 authorization was never used —
a valid payment fails. `X402.Facilitator.NonceManager` assigns nonces
instead: `checkout/3` hands out the next nonce (fetching from the node
only on first use per address), `complete/3` marks it consumed once the
transaction reached the node, and `release/3` returns it when the
settlement failed before the node could have seen the transaction —
rolling the tail nonce straight back, or scheduling a node re-fetch when
releasing a middle nonce would leave a gap that stalls later
transactions. The engine drives this lifecycle itself; you only supervise
the process and pass its name:

```elixir
children = [
  {X402.Facilitator.NonceManager, name: MyFacilitator.NonceManager},
  # ...
]

X402.Facilitator.Engine.new(
  # ...
  nonce_manager: MyFacilitator.NonceManager
)
```

Nonce tracking is per-node: running the same fee-payer key on several
facilitator instances still races at the chain level — use one fee payer
per instance, or coordinate externally.

## Hooks

`X402.Hooks` callbacks wrap both engines' operations, mirroring the
reference facilitator's lifecycle hooks — payment tracking, allow/deny
policies, and failure recovery without touching the engine:

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
  check for private deployments, and the plug warns at init when it is
  not configured — an unauthenticated facilitator lets anyone make its
  fee payer broadcast (gas-capped) settlement transactions. Put real
  authentication, TLS termination, and rate limiting in front of a
  public facilitator.
* **The wire contract** — protocol-level rejections are `200` responses
  (`isValid: false` / `success: false`); `400`/`413` cover malformed or
  oversized bodies, and `500` (opaque body, details logged) means an
  infrastructure failure such as an unreachable RPC node.
* **`/discovery/resources`** — optional in the facilitator API and not
  served by the scaffold (it answers `404`); bazaar serving is out of
  scope here.
* **Observability** — both engines emit
  `[:x402, :facilitator_engine, :verify]` and
  `[:x402, :facilitator_engine, :settle]` telemetry with `:status`
  metadata, and every RPC call emits `[:x402, :rpc, :request]`.
* **One settle per payment** — the chain enforces it: a second settle of
  the same EVM payload is rejected by the token contract
  (`invalid_exact_evm_nonce_already_used`), and a Solana resend of
  identical bytes
  collapses to one transaction id. The engines handle the ambiguous
  middle on their own — a `settlement_pending` retry reconciles against
  the recorded broadcast through the pending store, and the SVM
  settlement cache rejects concurrent duplicates before broadcast — so
  configure the stores rather than reconciling by hand.
* **Stores are per-node with the bundled adapters** — the ETS
  pending-settlement store and the ETS settlement cache both live on the
  local node. Multi-instance facilitators need shared adapters (the
  pending-store behaviour documents a Redis sketch, and
  `X402.Extensions.PaymentIdentifier.RedisCache` covers the settlement
  cache) so a retry routed to a different instance still reconciles.
