defmodule X402.Facilitator.Auth do
  @moduledoc """
  Behaviour for facilitator request authentication.

  Some facilitators (for example Coinbase's hosted facilitator, see
  `X402.Facilitator.Auth.CDP`) require per-request authentication headers.
  Implementations of this behaviour build those headers from a stateless
  config struct created once when the facilitator starts.

  Configure a facilitator with the `:auth` option:

      X402.Facilitator.start_link(
        finch: MyFinch,
        url: X402.Facilitator.Auth.CDP.facilitator_url(),
        auth: {X402.Facilitator.Auth.CDP, api_key_id: "...", api_key_secret: "..."}
      )

  The `:auth` option accepts either `nil` (the default, no authentication),
  a module implementing this behaviour (built with default options), or a
  `{module, opts}` tuple.

  Implementations are built once at `start_link` so invalid credentials fail
  fast, and `c:headers/2` is called once per facilitator operation. Transport
  retries reuse those headers within the credential's validity window.
  """

  @typedoc """
  Request context passed to `c:headers/2`.

  The `:host` is derived from the facilitator base URL and includes the port
  when present (matching the `URL.host` semantics used by the CDP SDK). The
  `:path` is the full request path — the base URL's path (if any) combined
  with the operation endpoint (e.g. `/platform/v2/x402/verify`) — so
  implementations can bind time-based credentials to the exact request URI.
  """
  @type request_info :: %{
          method: :get | :post,
          host: String.t(),
          path: String.t()
        }

  @typedoc "Auth implementation state."
  @type t :: struct()

  @doc """
  Builds auth state from options.

  Called once at `start_link` time so invalid credentials fail fast. Return
  `{:ok, state}` on success or `{:error, reason}` otherwise.
  """
  @callback new(keyword()) :: {:ok, t()} | {:error, term()}

  @doc """
  Builds the HTTP headers for a single request.

  Called once per facilitator operation. Returns a list of `{name, value}`
  header tuples.
  """
  @callback headers(t(), request_info()) ::
              {:ok, [{String.t(), String.t()}]} | {:error, term()}

  @doc """
  Normalizes a facilitator `:auth` option into auth state.

  Accepts:

    * `nil` — no authentication
    * a module implementing `X402.Facilitator.Auth` — built with default options
    * `{module, opts}` — built with the given options
  """
  @doc since: "0.5.0"
  @spec new(nil | module() | {module(), keyword()}) :: {:ok, nil | t()} | {:error, term()}
  def new(nil), do: {:ok, nil}

  def new(module) when is_atom(module), do: module.new([])

  def new({module, opts}) when is_atom(module) and is_list(opts), do: module.new(opts)

  @doc """
  Returns the headers for a request.

  When no auth is configured this returns `{:ok, []}`.
  """
  @doc since: "0.5.0"
  @spec headers(nil | t(), request_info()) ::
          {:ok, [{String.t(), String.t()}]} | {:error, term()}
  def headers(nil, _request_info), do: {:ok, []}

  def headers(%module{} = auth, request_info), do: module.headers(auth, request_info)
end
