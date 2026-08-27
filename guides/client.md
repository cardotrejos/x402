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

The SDK signs the `exact` scheme on EVM (`eip155:*`) networks.

## Quick start with Finch

Add the optional dependencies the payer needs — `finch` for HTTP and
`ex_secp256k1`/`ex_keccak` for signing:

```elixir
def deps do
  [
    {:x402, "~> 0.6"},
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

## Telemetry

The client emits `[:x402, :client, :select]`, `[:x402, :client, :sign]`,
`[:x402, :client, :build]`, and `[:x402, :client, :request]` events with a
`:status` of `:ok` or `:error` — see `X402.Telemetry`.
