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

### Budgets and consent

Two options keep an automated payer in check:

- `:max_amount` — an atomic-unit ceiling. Payment options above it are never
  selected; if nothing affordable is offered you get
  `{:error, :no_acceptable_requirements}`.
- `:on_payment_required` — a hook invoked with the decoded `PaymentRequired`
  map *before* anything is signed. Return `:cancel` to abort with
  `{:error, :payment_cancelled}`:

```elixir
X402.Client.Finch.request(MyApp.Finch, url,
  signer: signer,
  on_payment_required: fn payment_required ->
    case MyApp.Budget.approve(payment_required["accepts"]) do
      :ok -> :ok
      :denied -> :cancel
    end
  end
)
```

You can also pin the payment with `:network`, `:scheme`, and `:asset` filters.

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

## Signing in with X

When a server advertises the
[sign-in-with-x extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/sign-in-with-x.md)
under `extensions["sign-in-with-x"]` of its 402, a wallet that already
paid for the resource can come back and prove its identity instead of
paying again. The client half is manual for now — automatic handling in
`X402.Client.Finch` is planned for 0.8.0 — and takes three calls:

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
`:status` of `:ok` or `:error` — see `X402.Telemetry`.
