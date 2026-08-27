defmodule X402.Paywall do
  @moduledoc """
  Behaviour for rendering browser-facing HTML paywall pages.

  When `X402.Plug.PaymentGate` is configured with `paywall: module`, 402
  responses to requests that look like a browser page load carry an HTML body
  rendered by the module instead of the default `{}` JSON body. A request is
  treated as a browser page load when its `Accept` header contains
  `text/html` **and** its `User-Agent` contains `Mozilla` — the same
  heuristic the reference x402 middlewares use. The Base64 `PAYMENT-REQUIRED`
  header is identical on both response forms; only the body differs.

  `X402.Paywall.Default` ships a self-contained wallet-enabled page. Custom
  implementations receive the exact v2 `PaymentRequired` payload the gate
  encodes into the `PAYMENT-REQUIRED` header, so
  `X402.PaymentRequired.encode/1` reproduces the header value byte for byte:

      defmodule MyApp.Paywall do
        @behaviour X402.Paywall

        @impl X402.Paywall
        def render(payment_required, _conn_info) do
          {:ok, ~s(<h1>\#{payment_required["resource"]["description"]}</h1>)}
        end
      end

  Returning `{:error, reason}` falls back to the default JSON body, so a
  renderer failure never blocks the payment flow.
  """

  @typedoc """
  Request details passed to `c:render/2`.

  * `:method` — the HTTP request method (for example `"GET"`)
  * `:request_path` — the decoded request path matched by the gate
  * `:status` — the HTTP status of the response being rendered (always 402)
  """
  @type conn_info :: %{
          method: String.t(),
          request_path: String.t(),
          status: pos_integer()
        }

  @doc """
  Renders the HTML paywall page for a v2 `PaymentRequired` payload.

  `payment_required` is the string-keyed map the gate encodes into the
  `PAYMENT-REQUIRED` response header (`x402Version`, `error`, `resource`,
  `accepts`, `extensions`). Returns `{:ok, html}` with the complete page as
  iodata, or `{:error, reason}` to fall back to the JSON body.
  """
  @callback render(payment_required :: map(), conn_info()) ::
              {:ok, iodata()} | {:error, term()}

  @required_callbacks [render: 2]

  @doc false
  @spec validate_module(term()) :: {:ok, module()} | {:error, String.t()}
  def validate_module(module) when is_atom(module) and not is_nil(module) do
    case X402.Behaviour.implements?(module, @required_callbacks) do
      true -> {:ok, module}
      false -> {:error, "expected a module implementing X402.Paywall"}
    end
  end

  def validate_module(_invalid), do: {:error, "expected a module implementing X402.Paywall"}
end
