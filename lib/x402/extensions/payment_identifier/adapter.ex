defmodule X402.Extensions.PaymentIdentifier.Adapter do
  @moduledoc """
  `X402.Extension` adapter advertising the `payment-identifier` extension.

      plug X402.Plug.PaymentGate,
        routes: [...],
        payment_identifier_cache: MyApp.PaymentCache,
        extensions: [{X402.Extensions.PaymentIdentifier.Adapter, required: true}]

  Every 402 response advertises
  `X402.Extensions.PaymentIdentifier.extension(required: ...)`. Validation
  of the echoed id, the `required` rule, the request-fingerprint binding,
  and the `:x402_payment_id` assign are built into `X402.Plug.PaymentGate`
  and apply to the advertisement this adapter produces exactly as they do
  to a static `extensions: %{"payment-identifier" => ...}` route entry.
  """

  @behaviour X402.Extension

  alias X402.Extensions.PaymentIdentifier

  @opts_schema [
    required: [
      type: :boolean,
      default: false,
      doc: "Whether clients must supply an id (`info.required`)."
    ]
  ]

  @doc since: "0.8.0"
  @doc """
  Returns `"payment-identifier"`.

  ## Examples

      iex> X402.Extensions.PaymentIdentifier.Adapter.key()
      "payment-identifier"
  """
  @impl X402.Extension
  @spec key() :: String.t()
  def key, do: PaymentIdentifier.extension_key()

  @doc since: "0.8.0"
  @doc """
  Validates the adapter options.

  ## Options

  #{NimbleOptions.docs(@opts_schema)}

  ## Examples

      iex> X402.Extensions.PaymentIdentifier.Adapter.init([])
      {:ok, [required: false]}

      iex> {:error, message} = X402.Extensions.PaymentIdentifier.Adapter.init(required: "yes")
      iex> message =~ ":required"
      true
  """
  @impl X402.Extension
  @spec init(keyword()) :: {:ok, keyword()} | {:error, String.t()}
  def init(opts) do
    case NimbleOptions.validate(opts, @opts_schema) do
      {:ok, validated} -> {:ok, validated}
      {:error, error} -> {:error, Exception.message(error)}
    end
  end

  @doc since: "0.8.0"
  @doc """
  Advertises the extension with the configured `required` flag.

  ## Examples

      iex> context = X402.Hooks.RequestContext.new([])
      iex> X402.Extensions.PaymentIdentifier.Adapter.advertise([required: true], context)["info"]
      %{"required" => true}
  """
  @impl X402.Extension
  @spec advertise(keyword(), X402.Hooks.RequestContext.t()) :: map()
  def advertise(opts, _context) do
    PaymentIdentifier.extension(required: Keyword.get(opts, :required, false))
  end
end
