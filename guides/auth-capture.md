# Auth-capture on EVM

`auth-capture` separates a payer's authorization from the amount eventually
charged. This guide describes the unreleased implementation, not the published
0.6.1 package. Read the canonical
[EVM binding](https://github.com/x402-foundation/x402/blob/main/specs/schemes/auth-capture/scheme_auth_capture_evm.md)
before configuring an operator.

## Supported paths

| Path | Support |
| --- | --- |
| Client authorization | EIP-3009 `ReceiveWithAuthorization` and witnessless Permit2 |
| Contract encoding | Escrow v1.0 and v1.1, deployment-specific collectors and fees |
| Local verification | Structural, signature, or full pinned-RPC verification |
| Execution | Explicitly consented authorize, charge, capture, void, and refund |
| Resource orchestration | Escrow, synchronous or application-driven deferred capture |
| HTTP / MCP | Explicit local resource, never a facilitator fallback for auth-capture |
| Payer reclaim | Transaction builder; the payer submits it |
| Custom operators / implicit delegation | Not supported by full execution |
| Combined capture-and-void input | Verifier supports it; Engine rejects it. Resource persists two separate legs |

The standard facilitator Plug does not dispatch this engine automatically.
Terminal-charge and standalone-refund APIs are application integrations, not
public routes exposed by the resource adapters.

## Requirements and signers

Set `scheme: "auth-capture"` and a concrete `eip155` network. Requirements bind
the token, receiver, maximum amount, operator, receiver authorizer, deployment,
fee policy, and capture/refund deadlines. `extra.paymentFlow` is `"escrow"` or
`"authorization"`. Only escrow has `extra.captureMode`, `"sync"` by default or
`"deferred"`. The resource and advertised capture mode must agree.

Use `X402.Verify.AuthCaptureEVM.validate_requirements/1` to check static terms.
Build fresh time-bounded advertisements, not permanent boot-time deadlines.
Allow time for funding, bounded handler execution, capture, and void. The
resource checks remaining service time immediately before a never-started
handler, including during recovery. It cannot force arbitrary application
code to finish before a blockchain deadline.

The payer signs the token authorization. The receiver authorizer signs exact
charge/capture/void/refund consent. The gas account signs type-2 transactions
through `X402.Signer.sign_transaction/2`. Remote transaction signers must
implement the dedicated callback, review the supplied transaction, and never
broadcast it themselves. There is no personal-sign or pretend-EIP-712 fallback.

Deployed accounts use ERC-1271 even when an ECDSA key recovers to their address.
Counterfactual payer wallets require an allowlisted factory and successful
full collect simulation. Relevant contracts must have code, but code presence
is not a runtime-code authenticity proof.

## Durable execution

Configure RPC, a dedicated gas account, gas caps, and an application store:

```elixir
{:ok, engine} =
  X402.AuthCapture.Engine.new(
    rpc: rpc,
    signer: gas_signer,
    network: "eip155:8453",
    store: store,
    max_fee_per_gas: 3_000_000_000,
    max_priority_fee_per_gas: 1_000_000_000,
    confirmations: 2
  )

{:ok, resource} =
  X402.AuthCapture.Resource.new(
    engine: engine,
    authorizer: receiver_signer,
    mode: :sync,
    max_records: 1000
  )
```

`store` is `{module, context}` implementing `X402.AuthCapture.Store`. Its
multi-key transactions must be serializable across nodes and durable before
acknowledgement. Mutation callbacks are pure and may be retried. Read failures
must not become missing records; commit timeouts are ambiguous.

`X402.AuthCapture.ETSStore` is volatile development/test storage. Owner death
loses its data. Neither it nor offline concurrency tests demonstrate durable
crash/restart recovery in production.

The journal freezes signed bytes and their locally computed hash before
granting one send. It retains unresolved work and confirmed effects without
TTL eviction or ownership takeover. A confirmed or reverted operation holds
the account scope until its effects are recorded durably and acknowledged:

```elixir
X402.AuthCapture.Engine.execute(engine, envelope, requirements)
X402.AuthCapture.Engine.reconcile(engine)
# After the application durably records the returned payment effects:
X402.AuthCapture.Engine.acknowledge(engine, operation_id)
```

These calls perform one receipt check, not a polling loop. Exact retained
requests can be reconciled after the original authorization expires. Prepared
but undispatched work is not automatically sent during recovery. Interrupted
preparations, expired frozen transactions, missing receipts, and financial
failures require application recovery. Do not blindly resubmit or delete their
records.

Use a dedicated gas account for this executor, or an external global nonce
coordinator spanning every scheme and external writer. Sharing a storage
backend alone does not coordinate independent execution paths.

## Escrow resources

```elixir
X402.AuthCapture.Resource.run(resource, envelope, requirements, fn ->
  {:ok, %{"content" => "metered result"}, 750_000}
end)
```

Before funding, the resource validates and retains a void consent using pinned
EOA/ERC-1271 rules. After confirmed funding it checks the current unconsumed
hold, persists an executing phase, and runs the handler once. Handler output
and the actual nonnegative amount are persisted atomically. Actual usage must
not exceed the maximum. Full usage skips void; zero usage skips capture.

For `:sync`, content returns only after capture and any remainder void are
confirmed. For `:deferred`, positive successful usage returns after durable
metering, before capture. Zero usage and explicit failure still void immediately.
`{:error, reason}` from a handler records an opaque failure and voids the hold.
Exceptions, invalid metering, and uncertain persistence withhold content and
never authorize automatic handler re-execution.

Results must be plain JSON values (no structs or custom encoders), at most
64 levels deep, and fit within one MiB of encoded JSON. Input is bounded before
encoding; oversized buffered iodata is rejected before flattening.
Output is retained separately
from settlement metadata and written once. Payment records have a per-network,
gas-account quota (`max_records`, default 1000); journal history has a separate
limit (default 10,000). Neither limit evicts replay or recovery records.
Applications must plan capacity and safe archival outside this implementation.

Recover from application-owned, authenticated jobs:

```elixir
X402.AuthCapture.Resource.resume(resource, payment_info_hash)
```

Provide the optional handler argument only for funding that never entered
execution. Recovery will recheck the current hold and deadline. It cannot
reconstruct a crashed handler's lost output or metering. Do not expose `resume`
as a client endpoint, run it as an unauthenticated retry, or treat a historical
funding receipt as proof that a hold remains available.

## Plug

Build local handler options and pass `auth_capture: auth_capture_options`
to `X402.Plug.PaymentGate.init/1` for escrow routes:

```elixir
auth_capture_options = [
  resource: resource,
  handler: fn conn ->
    {:ok, conn} = X402.Plug.PaymentGate.put_settlement_amount(conn, 750_000)
    Plug.Conn.resp(conn, 200, "metered result")
  end
]
```

The gate invokes this handler itself and returns a sent, halted connection.
It buffers the body, headers, cookies, and before-send callbacks. Callbacks
run once before metering; they can set the actual amount. The amount is required,
not implicitly the maximum. Streaming, files, upgrades, and early hints are
rejected. The stored response is JSON containing Base64 body bytes, so its
encoding overhead counts toward the result limit. Handler assigns and private
process state are not persisted as output. Live request-body adapter updates
are preserved separately, including when a handler raises or settlement stays
pending.

Verified rate limits run before funding. Generic payment-id binding and claims
use a canonical token-authorization identity rather than the encoded header.
Durable resource admission prevents another handler run even if a cache entry
expires. Preverification, limiter rejection, or consent preparation that never
reaches admission releases only the attempt's claims. After an admission write
is attempted, failures and
pending results retain them for application recovery. Pending work returns
503; other local resource failures return an opaque 500, with no paid headers,
body, or success receipt.

Successful receipts include `paymentInfoHash`, `fundingTransaction`, actual
`amount`, and `settlementStatus`. `"deferred"` means metered, not captured.
Deferred results do not create SIWX payment grants. Only successful synchronous
completion grants method-and-full-URL-scoped access.

## MCP

Configure `auth_capture_resource: resource` on `X402.MCP.Server.init/1`.
Its auth-capture handler contract is explicit:

```elixir
X402.MCP.Server.call(request, config, fn _request ->
  {:ok, %{"content" => [%{"type" => "text", "text" => "metered result"}]}, 750_000}
end)
```

The result map is withheld until synchronous completion or durable deferred
metering. Pending work, tool errors, and uncertain execution return an opaque
error without paid content or a success receipt. Application recovery uses the
same resource API. Ordinary non-auth-capture handlers keep their existing map
return contract.

## Client budgets and refund policy

`X402.Client`, `X402.Client.Finch`, and `X402.MCP.Client` recognize this scheme.
Optional `auth_capture: [now: ..., salt: ..., salt_nonce: ...]` controls signing;
normally use fresh random salt. Pin trusted receivers, assets, networks, and
operator terms with selection policies and a maximum amount.

After dispatch, **every outcome retains the whole maximum budget reservation**,
including HTTP errors, MCP timeouts, and renewed challenges. The server may
already hold or have charged funds. A lower metered amount or failed transport
is not permission to release exposure. Reconcile trusted payment state once
before explicitly adjusting the application budget.

Refund execution additionally requires a request-specific `refund_authorize`
callback and existing funding/allowance. It receives account-aware verified
consent, but that partial check does not prove liquidity or authorize execution.
Return `:ok` only for an exact application funding agreement; full verification
and simulation follow. The engine never obtains refund funding automatically.

## Operational limits

Use trusted RPC with canonical EIP-1898 reads. Combined verifier simulation
requires ordered `eth_simulateV1` support; it never falls back to independent
calls. Confirmation depth and a canonical inclusion check are not independent
finality guarantees or protection against deeper reorgs.

Schedule reconciliation, bound handler runtime, protect stored paid output,
monitor capacity/deadlines, and provide explicit incident recovery. There is no
automatic financial unwind scheduler, transaction replacement service,
production store adapter, live interoperability certification, or independent
security audit supplied by these modules.
