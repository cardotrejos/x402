# Paying for x402 Resources from Elixir

x402 has two halves: servers that require payment, and clients that pay. This
guide covers the payer side — calling an x402-protected API from Elixir and
letting the SDK handle the `402 → sign → retry` dance.

## How a payment happens

1. Your client requests a protected resource and receives **402 Payment
   Required** with a `PAYMENT-REQUIRED` header describing acceptable payments.
2. The client picks one entry from `accepts`, signs an
   [EIP-3009](https://eips.ethereum.org/EIPS/eip-3009)
   `TransferWithAuthorization` for it (an off-chain signature — no gas, no
   transaction), and retries the request with the signed payment in a
   `PAYMENT-SIGNATURE` header.
3. The server verifies and settles the payment through its facilitator and
   responds with the resource, plus a `PAYMENT-RESPONSE` header containing the
   settlement receipt.

The SDK signs the `exact` scheme (EIP-3009) and the `upto` scheme
(Permit2) on EVM (`eip155:*`) networks, and the `exact` scheme on Solana
(`solana:*`) networks (see below).

## Quick start with Finch

Add the optional dependencies the payer needs — `finch` for HTTP and
`ex_secp256k1`/`ex_keccak` for signing:

```elixir
def deps do
  [
    {:x402, "~> 0.6.1"},
    {:finch, "~> 0.19"},
    {:ex_secp256k1, "~> 0.8.0"},
    {:ex_keccak, "~> 0.7.8"}
  ]
end
```

Start a Finch pool with TLS verification, build a signer, and make the
request:

```elixir
{:ok, _pid} =
  Finch.start_link(
    name: MyApp.Finch,
    pools: %{default: X402.Facilitator.HTTP.secure_pool_opts()}
  )

# A raw secp256k1 private key — load it from a secret store, never from code.
{:ok, signer} = X402.Signer.LocalKey.new(System.fetch_env!("PAYER_PRIVATE_KEY"))

{:ok, %{status: 200, body: body, payment_response: receipt}} =
  X402.Client.Finch.request(MyApp.Finch, "https://api.example.com/premium-data",
    signer: signer,
    max_amount: "10000"
  )

IO.inspect(receipt["transaction"], label: "settlement tx")
```

`request/3` performs the request; when it hits a 402 it builds, signs, and
retries **once** — a payment is never signed or sent twice for the same call.
Responses that do not require payment pass through untouched.

### Spend controls and consent

An automated payer signs whatever a server asks for unless you cap it.
Four options do, and they compose:

- `:max_amount` — an atomic-unit ceiling per payment. Payment options above
  it are never selected; if nothing affordable is offered you get
  `{:error, :no_acceptable_requirements}`.
- `:policies` — selection policies (see "Policies" below).
- `:budget` — a session budget shared across requests (see "Budgets"
  below).
- `:on_payment_required` — a consent hook invoked with the decoded
  `PaymentRequired` map *before* anything is signed. Return `:cancel` to
  abort with `{:error, :payment_cancelled}`:

```elixir
X402.Client.Finch.request(MyApp.Finch, url,
  signer: signer,
  on_payment_required: fn payment_required ->
    case MyApp.Approvals.approve(payment_required["accepts"]) do
      :ok -> :ok
      :denied -> :cancel
    end
  end
)
```

When none of `:max_amount`, `:policies`, or `:budget` is given,
`X402.Client.Finch` and `X402.MCP.Client` log a warning once per VM.

You can also pin the payment with `:network`, `:scheme`, and `:asset` filters.

#### Policies

A policy is a 2-arity function of a candidate `accepts` entry and the
decoded `PaymentRequired` map (`nil` when selecting from a bare list). It
returns `true` to accept the entry, `false` to skip it, or
`{:error, reason}` to abort selection with that error. Policies run last,
after the scheme and `:max_amount` filters, and every policy must accept
an entry for it to be selected. `X402.Client.Policy` ships the common ones:

```elixir
alias X402.Client.Policy

X402.Client.Finch.request(MyApp.Finch, url,
  signer: signer,
  policies: [
    Policy.max_amount("1000000"),
    Policy.networks(["eip155:8453", "solana:*"]),
    Policy.assets(["0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"]),
    Policy.schemes(["exact"]),
    fn requirements, _payment_required ->
      requirements["payTo"] in MyApp.trusted_receivers()
    end
  ]
)
```

`networks/1` accepts a trailing `*` as a prefix wildcard; `assets/1`
compares case-insensitively. The same option is accepted by
`X402.Client.select_requirements/2`, `X402.Client.build_payment/3`, and
`X402.MCP.Client.call/3`.

#### Budgets

`:max_amount` and policies judge one payment at a time. `X402.Client.Budget`
caps what a client commits to across requests: a process with a hard
`:limit` and optional `:per_asset` limits, in atomic units. Start it in
your supervision tree and pass it to the drivers:

```elixir
# In your supervision tree
children = [
  {X402.Client.Budget,
   name: MyApp.PayerBudget,
   limit: "5000000",
   per_asset: %{"0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913" => "1000000"}}
]

# Per request
X402.Client.Finch.request(MyApp.Finch, url,
  signer: signer,
  max_amount: "10000",
  budget: MyApp.PayerBudget
)

X402.Client.Budget.spent(MyApp.PayerBudget)
#=> %{total: 10000, per_asset: %{"0x833589fcd6edb6e08f4c7c32d4f71b54bda02913" => 10000}}
```

The driver reserves the selected amount atomically after the payload is
built and before the paid retry is sent, so concurrent requests cannot
collectively overspend; a reservation that does not fit fails the request
with `{:error, {:budget_exceeded, details}}` (`details.scope` is `:total`
or `:asset`) and nothing is sent. The reservation is released when the
payment is not accepted — a transport error on the retry, or a non-2xx
response without a successful `PAYMENT-RESPONSE` receipt. Everything else
counts as spent, whether or not the facilitator actually settled: the
budget is a cap on what the client has *authorized*, not a ledger of
on-chain transfers. `reserve/3`, `release/3`, and `spent/1` are public for
transports you drive yourself.

### Lifecycle hooks

For anything beyond selection — auditing, pinning a different entry,
recovering from a signing failure — implement `X402.Client.Hooks` and pass
it as `hooks:` to `X402.Client.build_payment/3`,
`X402.Client.Finch.request/3`, or `X402.MCP.Client.call/3`. The callbacks
mirror the reference client's `onBeforePaymentCreation`,
`onAfterPaymentCreation`, and `onPaymentCreationFailure`:

```elixir
defmodule MyApp.PaymentHooks do
  @behaviour X402.Client.Hooks
  require Logger

  @impl true
  def before_payment(context, _metadata) do
    # context.requirements is the selected entry; replace it or halt.
    if context.requirements["payTo"] in MyApp.trusted_receivers(),
      do: {:cont, context},
      else: {:halt, :untrusted_receiver}
  end

  @impl true
  def after_payment(context, metadata) do
    Logger.info("signed payment", scheme: metadata.scheme, network: metadata.network)
    {:cont, context}
  end

  @impl true
  def on_payment_failure(context, _metadata), do: {:cont, context}
end
```

- `before_payment/2` runs after an entry is selected and before anything
  is signed. `{:cont, context}` continues — with `context.requirements`
  replaced, if you changed it; `{:halt, reason}` aborts with
  `{:error, {:hook_halted, :before_payment, reason}}`.
- `after_payment/2` runs once the payload is signed and enriched;
  `context.payload` may be replaced and becomes the returned payload.
- `on_payment_failure/2` runs when signing or enrichment fails;
  `{:cont, context}` continues the failure (with `context.error` possibly
  replaced) and `{:recover, payload}` turns it into `{:ok, payload}`.

Selection failures (`:no_acceptable_requirements`) happen before any hook
runs. A callback that raises yields
`{:error, {:hook_callback_failed, callback, reason}}`, and one returning
outside its contract `{:error, {:hook_invalid_return, callback, value}}`.

## Bring your own HTTP client

`X402.Client` is pure — no processes, no HTTP. Use it with Req, Tesla,
httpc, or anything else:

```elixir
alias X402.{Client, PaymentRequired}

# 1. You made a request and got a 402 with a PAYMENT-REQUIRED header:
{:ok, payment_required} = PaymentRequired.decode(header_value)

# 2. Build and sign the payment:
{:ok, payload} = Client.build_payment(payment_required, signer, max_amount: "10000")
{:ok, header} = Client.encode_payment(payload)

# 3. Retry the request with {"payment-signature", header}.
```

`Client.select_requirements/2` is also public if you want to inspect or
choose the payment option yourself before signing.

## `exact` payments through Permit2

The exact-EVM scheme defines several *asset transfer methods*, selected by
the requirements' `extra.assetTransferMethod`. Absent (or `"eip3009"`)
means the default EIP-3009 `TransferWithAuthorization` flow shown above.
When a server advertises `"permit2"` — for tokens without EIP-3009
support — `build_payment/3` signs a Permit2 `PermitWitnessTransferFrom`
instead, with no change to your code:

```elixir
# One entry of the 402's `accepts`:
%{
  "scheme" => "exact",
  "network" => "eip155:8453",
  "amount" => "10000",
  "asset" => "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "payTo" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
  "maxTimeoutSeconds" => 300,
  "extra" => %{"assetTransferMethod" => "permit2"}
}

{:ok, payload} = X402.Client.build_payment(payment_required, signer)

payload["payload"]
#=> %{
#     "signature" => "0x...",
#     "permit2Authorization" => %{
#       "from" => "0x<payer>",
#       "permitted" => %{"token" => <the requirements' "asset">, "amount" => "10000"},
#       "spender" => "0x402085c248EeA27D92E8b30b2C58ed07f9E20001",
#       "nonce" => "0x...",
#       "deadline" => "1789...",
#       "witness" => %{"to" => "0x2096...287C", "validAfter" => "0"}
#     }
#   }
```

The scheme payload carries `permit2Authorization` rather than
`authorization`. Its `spender` is the `x402ExactPermit2Proxy`
(`X402.Permit2.exact_proxy_address/0`), the only contract able to consume
the permit; the witness binds the server's `payTo`; `permitted.amount` is
the exact amount that will be settled; and the permit is valid immediately
and expires after `maxTimeoutSeconds`. The EIP-712 domain is the canonical
Permit2 domain, so — unlike EIP-3009 — the requirements need no
`extra.name` / `extra.version`. As with `upto`, the payer must have
approved the canonical Permit2 contract for the token once (see the
[gas-sponsoring extensions](#gas-sponsoring-extensions) for
facilitator-funded alternatives), and `X402.Permit2.sign_exact/2` is
available if you want to sign without going through the client.

Any other transfer method is rejected: an `accepts` entry declaring
`"erc7710"` is not signable (`X402.Scheme.ExactEVM.transfer_method/1`
returns `{:error, {:unsupported_transfer_method, "erc7710"}}`), so
selection skips it in favour of another entry — or fails with
`{:error, :no_acceptable_requirements}` when it is the only one — and
signing such requirements directly returns the
`{:unsupported_transfer_method, _}` error.

## Metered `upto` payments

For variable-cost resources (LLM tokens, bandwidth, compute), servers
advertise the `upto` scheme: the client authorizes a **maximum** amount
and the server settles for the actual usage, up to that ceiling. The
SDK signs `upto` requirements out of the box — `build_payment/3` (and
`X402.Client.Finch.request/3`) picks them up like any other entry, with
`:max_amount` guarding the ceiling you are willing to authorize:

```elixir
{:ok, payload} =
  X402.Client.build_payment(payment_required, signer,
    scheme: "upto",
    max_amount: "5000000"
  )
```

Under the hood the client signs a Permit2 `PermitWitnessTransferFrom`
(`X402.Permit2`) against the canonical Permit2 contract, with the
requirements' `amount` as `permitted.amount` (the ceiling) and a witness
binding the server's `payTo` and the facilitator's address, so only that
facilitator can settle it. Two things to know:

- **`extra.facilitatorAddress` is required.** Facilitators announce
  their address via `GET /supported` (`X402.Facilitator.supported/1`)
  and resource servers forward it in each upto entry's `extra`. Entries
  without it are never selected, and signing one directly returns
  `{:error, {:missing_extra, "facilitatorAddress"}}`.
- **Permit2 needs a one-time on-chain approval.** The payer's wallet
  must have approved the canonical Permit2 contract for the token once
  (`approve(Permit2, ...)`); see the gas-sponsoring extensions below for
  facilitator-funded alternatives.

The signed maximum is not what you pay — the server meters actual usage
and settles for less (or nothing). See the
[Plug/Phoenix Integration](plug-integration.html) guide for the server half.

## Gas-sponsoring extensions

Permit2-based payments need a one-time on-chain `approve(Permit2, ...)`
from the payer's wallet — which costs gas the wallet may not have. Two x402
extensions let the facilitator sponsor that approval; when a server
advertises them in its `PAYMENT-REQUIRED` extensions, the client can attach
the corresponding data through `build_payment/3`'s `:extensions` option
(also accepted by `X402.Client.Finch.request/3`).

**EIP-2612 tokens** (`X402.Extensions.EIP2612GasSponsoring`): the client
signs an off-chain EIP-2612 `Permit` authorizing the canonical Permit2
contract, and the facilitator submits it on-chain, paying the gas. The SDK
signs the permit itself — you only supply the owner's current EIP-2612
nonce (read from the token contract's `nonces(owner)`; the SDK has no
chain access):

```elixir
alias X402.Extensions.EIP2612GasSponsoring

{:ok, payload} =
  X402.Client.build_payment(payment_required, signer,
    extensions: [EIP2612GasSponsoring.enricher(signer, nonce: "0")]
  )
```

**Plain ERC-20 tokens** (`X402.Extensions.ERC20ApprovalGasSponsoring`):
tokens without EIP-2612 have no gasless approval, so the client signs — but
does not broadcast — a normal `approve(Permit2, amount)` transaction, and
the facilitator funds the wallet's gas if needed, broadcasts it, and
settles atomically. Signing that transaction needs the wallet's live
on-chain nonce and network fees, so it happens outside the SDK; the
enricher wraps the pre-signed transaction in the extension data:

```elixir
alias X402.Extensions.ERC20ApprovalGasSponsoring

{:ok, payload} =
  X402.Client.build_payment(payment_required, signer,
    extensions: [
      ERC20ApprovalGasSponsoring.enricher(
        from: wallet_address,
        signed_transaction: signed_approve_tx_hex
      )
    ]
  )
```

Both enrichers are no-ops when the server did not advertise the extension,
and both preserve the server's echoed declaration — client data is only
added alongside it, per the spec's append-only rule. Resource servers
declare support with `build_extension/0` and validate a client's echoed
data with `extract_info/1` and `validate_info/1` on either module.

## Payment identifiers

The [payment-identifier extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/payment_identifier.md)
makes a payment idempotent from the client's side: you attach an id you
generated, and a server that sees it again treats the request as the same
one (a retry after a lost response is not charged twice, and the same id
can never be reused for a different request — the server answers 409).
`X402.Extensions.PaymentIdentifier.enricher/1` attaches it through the
same `:extensions` option:

```elixir
alias X402.Extensions.PaymentIdentifier

{:ok, payload} =
  X402.Client.build_payment(payment_required, signer,
    extensions: [PaymentIdentifier.enricher()]
  )

payload["extensions"]["payment-identifier"]["info"]["id"]
#=> "k3Jm9ZQvT2xW8bNcRfLpHsD4aY7eUqGi"
```

Each invocation generates a fresh `X402.Extensions.PaymentIdentifier.generate_id/0`
(32 URL-safe characters); pass `id: my_id` to reuse one across retries —
that is the point of the extension — provided it is 16 to 128 characters
of `[A-Za-z0-9_-]` (`valid_id?/1`), or the enricher returns
`{:error, :invalid_payment_id}`. The enricher echoes the server's
advertisement (`info.required` and the schema) unchanged and only adds
`info.id`; it is a no-op when the server did not advertise the extension
unless you pass `always: true`. A server that advertised
`required: true` rejects payments without an id.

### Which requirements the client selects

`build_payment/3` picks the first `accepts` entry it can sign, in the
server's order, filtered by `:network` and `:scheme`. Entries whose
`extra.paymentFlow` names a flow the client cannot run are skipped: only
the default `"authorization"` flow (explicit or omitted) is recognized —
`upfront` and `escrow` commit funds before the resource executes and the
protocol forbids constructing a payment for a flow you do not implement. A
`PAYMENT-REQUIRED` offering only such entries yields
`{:error, :no_acceptable_requirements}`.

## Builder codes

The [builder-code extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/builder_code.md)
carries ERC-8021 attribution codes that the facilitator encodes into the
settlement transaction's calldata. A server advertises its app code under
`extensions["builder-code"]`; a client echoes it and attaches up to 5
service codes of its own through
`X402.Extensions.BuilderCode.enricher/1`, on the same `:extensions` option:

```elixir
alias X402.Extensions.BuilderCode

{:ok, payload} =
  X402.Client.build_payment(payment_required, signer,
    extensions: [BuilderCode.enricher(service_codes: "my_client")]
  )

payload["extensions"]["builder-code"]["info"]
#=> %{"a" => "my_app", "s" => ["my_client"]}
```

Codes match `^[a-z0-9_]{1,32}$`; the enricher raises on a malformed one.
When the server advertised the extension, its `info` (including `a`) and
`schema` are echoed unchanged and your codes are prepended to any server
codes, client first and deduplicated, as the reference client merges
them. When it did not, only `%{"info" => %{"s" => codes}}` is attached —
never an `a` — as the spec's client behaviour prescribes; pass
`always: false` to make the enricher a no-op for such servers instead.
The resource server validates the echo (a changed `a` is rejected) and
forwards the codes to the facilitator.

## Signing in with X

When a server advertises the
[sign-in-with-x extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/sign-in-with-x.md)
under `extensions["sign-in-with-x"]` of its 402, a wallet that already
paid for the resource can come back and prove its identity instead of
paying again. `X402.Client.Finch.request/3` (and `X402.MCP.Client.call/3`)
drive it automatically with the `:siwx` option:

```elixir
{:ok, %{status: 200, siwx_authenticated: true}} =
  X402.Client.Finch.request(MyApp.Finch, "https://api.example.com/premium-data",
    signer: signer,
    max_amount: "10000",
    siwx: [chain_id: :auto]
  )
```

With `:siwx` set, a 402 that advertises a challenge is answered before
anything is paid: the client signs the challenge
(`X402.Client.SIWX.authenticate/4`) and retries the request with the
`SIGN-IN-WITH-X` header and no payment. A response that is not another
402 comes back as-is, with `siwx_authenticated: true` for a 2xx — the
server remembered your address. A second 402 means the address has not
paid yet (or its record expired): the normal payment flow continues from
that response, and the paid request carries a proof for the new
challenge so the server records the payer for next time. The response's
`siwx_authenticated` is `false` on that path.

The option is a keyword list of `X402.Client.SIWX` options:

- `chain_id:` (required) — the CAIP-2 chain to sign for, or `:auto` to
  pick the first entry of the challenge's `supportedChains` the signer can
  sign (EVM signers map to `eip155:*`, Solana signers to `solana:*`).
- `domain:` — the challenge `domain` you expect. Defaults to the resource
  URL's host on HTTP; required for MCP, where there is no URL.
- `address:` — the address placed in the proof (the signer's when omitted).
- `signature_scheme:` — an optional `signatureScheme` hint copied into the
  proof.

A challenge whose `domain` or `uri` is not bound to the resource's origin
is refused (`{:error, {:siwx, :domain_mismatch}}` /
`{:siwx, :uri_mismatch}`), as is one listing no chain the signer can sign
(`{:siwx, :unsupported_chain}`). Domain matching ignores host case, but
does not ignore port differences. Direct `authenticate/4` calls also
require a trusted `domain:` or `resource_url:`; neither may be inferred
from the untrusted challenge. Every attempt emits
`[:x402, :client, :siwx]` with `:transport`, `:chain_id`, and `:outcome`
(`:authenticated` or `:payment_required`) — or `:reason` on error.

### Signing a challenge yourself

With another HTTP client, or to control the flow, the underlying pieces
are three calls:

```elixir
alias X402.Extensions.SIWX

{:ok, payment_required} = X402.PaymentRequired.decode(header_value)
challenge = payment_required["extensions"]["sign-in-with-x"]

{:ok, signed} = SIWX.sign(challenge, signer, chain_id: "eip155:8453")
{:ok, header} = SIWX.encode_signed(signed)

Finch.build(:get, url, [{"sign-in-with-x", header}])
|> Finch.request(MyApp.Finch)
```

`sign/3` copies the challenge's fields (`domain`, `uri`, `nonce`,
`issuedAt`, `expirationTime`, ...) into the proof, adds your signer's
address and the chain, builds the CAIP-122 message, and signs it — EIP-4361
text with EIP-191 `personal_sign` on `eip155:*` chains
(`X402.Signer.sign_message/2`, implemented by `X402.Signer.LocalKey`), or
Sign-In-With-Solana text with Ed25519 on `solana:*` chains
(`X402.Signer.sign_ed25519/2`, implemented by `X402.Signer.SolanaKey`).
The `:chain_id` must be one the challenge's `supportedChains` lists
(`{:error, :unsupported_chain}` otherwise). Send the encoded proof in the
`SIGN-IN-WITH-X` header of the next request: the server serves it without
payment if the address paid before, or answers 402 with a fresh challenge
(you may send `PAYMENT-SIGNATURE` in the same request to sign in and pay
at once). Challenges are single-use — sign the one from the latest 402,
not a cached copy.

Custom EVM signers implement the optional `c:X402.Signer.sign_message/2`
callback to support this; signers without it return
`{:error, :unsupported_signer}`.

## Paying on Solana (SVM)

The client also signs the `exact` scheme on `solana:*` networks out of the
box, following the x402 SVM scheme specification: it builds a v0 Solana
transaction — compute budget instructions, an SPL Token / Token-2022
`TransferChecked` to the Associated Token Account derived from the server's
`payTo` and `asset`, and a Memo for transaction uniqueness — signs it with
the payer's Ed25519 key, and leaves the fee payer's signature slot empty.
The server's sponsor (`extra.feePayer`, **required** in the advertised
requirements) verifies and co-signs at settlement, so the payer never pays
network fees. On-chain verification and settlement stay with the
facilitator; the signing path never talks to a Solana RPC node. The SDK
can also be that facilitator — see
[Run Your Own Facilitator](facilitator.html).

```elixir
{:ok, signer} = X402.Signer.SolanaKey.new(System.fetch_env!("SOLANA_PAYER_KEY"))

{:ok, payload} =
  X402.Client.build_payment(payment_required, signer,
    network: "solana:*",
    # Only needed when the server's 402 does not include an
    # extra.recentBlockhash hint: bring a blockhash yourself...
    svm_blockhash: recent_blockhash
    # ...or let the client fetch one on demand — see :svm_blockhash_fetcher
    # below.
  )
```

`X402.Signer.SolanaKey.new/1` accepts a raw 32-byte Ed25519 seed, a
64-byte `solana-keygen` keypair, or the Base58/Base64 encoding of either.
Signing uses OTP's `:crypto` — no extra dependencies.

Two option pairs matter for less common setups:

* **Blockhash** — servers should advertise `extra.recentBlockhash` in
  their requirements (it saves the client an RPC round-trip); when they
  do, no option is needed. Otherwise pass `:svm_blockhash`, or
  `:svm_blockhash_fetcher` — a 1-arity fun receiving the CAIP-2 network
  and returning `{:ok, blockhash}`.
* **Asset metadata** — `TransferChecked` needs the mint's decimals and
  owning token program. Well-known stablecoins (USDC, USDT, USDG, PYUSD,
  CASH on mainnet/devnet/testnet) are built in; for other mints pass
  `:svm_decimals` and `:svm_token_program`.

`X402.Solana.RPC.get_latest_blockhash/2` — Solana JSON-RPC over an
`X402.RPC` endpoint — makes a ready-made fetcher:

```elixir
{:ok, rpc} =
  X402.RPC.new(rpc_url: "https://api.mainnet-beta.solana.com", finch: MyApp.Finch)

{:ok, payload} =
  X402.Client.build_payment(payment_required, signer,
    network: "solana:*",
    svm_blockhash_fetcher: fn _network ->
      with {:ok, %{blockhash: blockhash}} <- X402.Solana.RPC.get_latest_blockhash(rpc) do
        {:ok, blockhash}
      end
    end
  )
```

Custom Solana signers implement the optional
`X402.Signer.sign_ed25519/2` callback instead of `sign_eip712/3` — see
below.

## Custom signers

`X402.Signer.LocalKey` holds a raw private key in memory — fine for testing
and low-value automation. For production payers implement the `X402.Signer`
behaviour over your KMS, hardware wallet, or signing service:

```elixir
defmodule MyApp.KMSSigner do
  @behaviour X402.Signer

  defstruct [:key_id, :address]

  @impl true
  def address(%__MODULE__{address: address}), do: {:ok, address}

  @impl true
  def sign_eip712(%__MODULE__{key_id: key_id}, digest, _typed_data) do
    # Ask the KMS to sign the 32-byte digest; return the 65-byte r || s || v
    # signature. Implementations that can only sign full EIP-712 typed data
    # can use the third argument instead of the digest.
    MyApp.KMS.sign(key_id, digest)
  end
end
```

Anything that returns `{:ok, address}` and `{:ok, signature}` plugs into
`X402.Client.build_payment/3` and `X402.Client.Finch.request/3` unchanged.

The chain-family callbacks are optional: implement `sign_eip712/3` for EVM
payments, `sign_ed25519/2` (a 64-byte Ed25519 signature over the Solana
transaction message bytes) for SVM payments, or both. A scheme asked to
sign with a signer that lacks its callback returns
`{:error, :unsupported_signer}`.

## Telemetry

The client emits `[:x402, :client, :select]`, `[:x402, :client, :sign]`,
`[:x402, :client, :build]`, and `[:x402, :client, :request]` events with a
`:status` of `:ok` or `:error`, and `[:x402, :client, :siwx]` when it
answers a Sign-In-With-X challenge — see `X402.Telemetry`.
