# Custom Payment Schemes

Everything scheme-specific in this library — client signing, incoming
payload validation, and the payment gate's local pre-checks — dispatches
through the `X402.Scheme` behaviour. Supporting a new chain or payment
scheme means writing **one module** and passing it as an option; no core
module needs to change.

The built-ins cover `exact` (`X402.Scheme.ExactEVM`) and `upto`
(`X402.Scheme.UptoEVM`) on EVM (`eip155:*`) networks. Resolution — exact
CAIP-2 matches beating wildcards, user modules beating built-ins — is
handled by `X402.Scheme.Registry`.

## Writing a scheme module

Implement `X402.Scheme`. Only `c:X402.Scheme.scheme/0` and
`c:X402.Scheme.networks/0` are required; implement the callbacks for the
roles your scheme plays:

```elixir
defmodule MyApp.SolanaExact do
  @behaviour X402.Scheme

  @impl X402.Scheme
  def scheme, do: "exact"

  @impl X402.Scheme
  def networks, do: ["solana:*"]

  # Client role: build the scheme payload carried as PaymentPayload.payload.
  @impl X402.Scheme
  def sign(requirements, signer, _opts) do
    with {:ok, transaction} <- build_and_sign_transaction(requirements, signer) do
      {:ok, %{"transaction" => transaction}}
    end
  end

  # Server role: structural validation of incoming PAYMENT-SIGNATURE payloads.
  @impl X402.Scheme
  def validate_payload(payload, _requirements, _opts) do
    case get_in(payload, ["payload", "transaction"]) do
      transaction when is_binary(transaction) -> :ok
      _missing -> {:error, {:invalid_scheme_payment, :missing_transaction}}
    end
  end

  # Server role: cheap local pre-checks before the facilitator round-trip.
  @impl X402.Scheme
  def precheck(_payload, _requirements, _opts), do: :ok

  defp build_and_sign_transaction(_requirements, _signer), do: {:error, :not_implemented}
end
```

## Registering it

There is no global registry and no application environment — scheme modules
are passed explicitly wherever you use the SDK, so two gates (or two
clients) in the same VM can support different scheme sets:

```elixir
# Resource server: routes may now use the scheme on its networks.
plug X402.Plug.PaymentGate,
  schemes: [MyApp.SolanaExact],
  routes: [
    %{
      method: :get,
      path: "/api/*",
      scheme: "exact",
      price: "10000",
      network: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
      asset: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      pay_to: "CKPKJWNdJEqa81x7CkZ14BVPiY6y16Sxs7owznqtWYp5"
    }
  ]

# Payer client (also available on X402.Client.Finch.request/3).
X402.Client.build_payment(payment_required, signer, schemes: [MyApp.SolanaExact])

# Standalone header validation.
X402.PaymentSignature.validate(payload, requirements, schemes: [MyApp.SolanaExact])
```

Kinds with no registered module keep their historical neutral behavior:
validation passes through with `:ok`, the gate skips pre-checks (the
facilitator remains the authority), and the client returns
`{:error, {:unsupported_kind, scheme, network}}`.

See the `X402.Scheme` module documentation for the full callback reference
and error conventions.
