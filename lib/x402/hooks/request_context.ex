defmodule X402.Hooks.RequestContext do
  @moduledoc """
  Context of a protected request passed to the resource-server lifecycle hooks.

  `X402.Plug.PaymentGate` and `X402.MCP.Server` build one of these for every
  request that reaches a gated route or paid tool and hand it to the optional
  `c:X402.Hooks.on_protected_request/2` and
  `c:X402.Hooks.on_verified_payment_canceled/2` callbacks.

  * `:transport` — `:http` (Plug gate) or `:mcp` (tool call).
  * `:conn` — the `Plug.Conn` for HTTP requests, `nil` for MCP.
  * `:request` — the MCP tool-call params map, `nil` for HTTP.
  * `:route` — the gate's compiled route (HTTP) or the paid-tool
    configuration (MCP), as an opaque map.
  * `:method` / `:path` / `:path_params` — the HTTP request method, decoded
    path, and the values captured by `:param` segments of the route pattern.
  * `:tool` — the MCP tool name.
  * `:requirements` — the string-keyed `PaymentRequirements` maps the
    request advertises (`PaymentRequired.accepts`). A `on_protected_request`
    hook may replace this list to change the terms for the current request.
  * `:extensions` — the `PaymentRequired.extensions` map advertised to the
    client, which the hook may replace as well.
  * `:payload` / `:matched_requirements` — the decoded `PaymentPayload` and
    the requirements it matched; only set once a payment has been verified
    (that is, in `on_verified_payment_canceled`).
  """

  defstruct transport: :http,
            conn: nil,
            request: nil,
            route: nil,
            method: nil,
            path: nil,
            path_params: %{},
            tool: nil,
            requirements: [],
            extensions: %{},
            payload: nil,
            matched_requirements: nil

  @typedoc "Transport the protected request arrived on."
  @type transport :: :http | :mcp

  @type t :: %__MODULE__{
          transport: transport(),
          conn: term() | nil,
          request: map() | nil,
          route: map() | nil,
          method: atom() | nil,
          path: String.t() | nil,
          path_params: %{optional(String.t()) => String.t()},
          tool: String.t() | nil,
          requirements: [map()],
          extensions: map(),
          payload: map() | nil,
          matched_requirements: map() | nil
        }

  @doc since: "0.8.0"
  @doc """
  Builds a request context from a keyword list of fields.

  Unknown keys are ignored so callers can pass through transport metadata.

  ## Examples

      iex> context = X402.Hooks.RequestContext.new(transport: :mcp, tool: "search", requirements: [%{"scheme" => "exact"}])
      iex> {context.transport, context.tool, context.requirements}
      {:mcp, "search", [%{"scheme" => "exact"}]}

      iex> X402.Hooks.RequestContext.new([]).path_params
      %{}
  """
  @spec new(keyword()) :: t()
  def new(fields) when is_list(fields) do
    struct(__MODULE__, fields)
  end

  @doc since: "0.8.0"
  @doc """
  Checks that a value returned by a hook is a well-formed request context.

  A hook may replace `:requirements` (a non-empty list of maps) and
  `:extensions` (a map) but nothing else is validated: the transports treat
  every other field as informational.

  ## Examples

      iex> context = X402.Hooks.RequestContext.new(requirements: [%{"scheme" => "exact"}])
      iex> X402.Hooks.RequestContext.valid?(context)
      true

      iex> X402.Hooks.RequestContext.valid?(X402.Hooks.RequestContext.new(requirements: []))
      false

      iex> X402.Hooks.RequestContext.valid?(%{requirements: [%{}]})
      false
  """
  @spec valid?(term()) :: boolean()
  def valid?(%__MODULE__{requirements: [_ | _] = requirements, extensions: extensions})
      when is_map(extensions) do
    Enum.all?(requirements, &is_map/1)
  end

  def valid?(_context), do: false
end
