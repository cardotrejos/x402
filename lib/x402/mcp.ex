defmodule X402.MCP do
  @moduledoc """
  x402 v2 payment flows over the Model Context Protocol (MCP transport).

  This module implements the
  [x402 MCP transport](https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/mcp.md)
  as pure functions over plain MCP tool-call request/result maps, so it works
  with any Elixir MCP library (or none). The payment data rides in three
  well-known places:

  1. A paid tool called without payment returns a tool result with
     `"isError" => true` whose `"structuredContent"` (and JSON-encoded
     `content[0].text`) carry the `PaymentRequired` object.
  2. The client retries the tool call with the signed `PaymentPayload` in
     request params `_meta["x402/payment"]`.
  3. The server verifies, runs the tool, settles, and attaches the settlement
     receipt to result `_meta["x402/payment-response"]`.

  `X402.MCP.Server` wraps a tool handler with verify → execute → settle;
  `X402.MCP.Client` drives an arbitrary tool-call function through the
  detect → sign → retry-once loop. The helpers here are shared by both halves
  and useful on their own when wiring a concrete MCP library.

  All functions accept maps with string keys (as decoded from JSON) or atom
  keys, but the x402 `_meta` entries themselves always use the spec's string
  keys `"x402/payment"` and `"x402/payment-response"`.

  ## Telemetry

  The MCP transport emits the following events, each with `%{count: 1}`
  measurements:

  - `[:x402, :mcp, :payment_required]` — server advertised payment requirements
  - `[:x402, :mcp, :payment_verified]` — server verified and settled a payment
  - `[:x402, :mcp, :payment_rejected]` — server rejected a payment
    (metadata includes `:reason`)
  - `[:x402, :mcp, :call]` — client drove a tool call
    (metadata includes `:status` and `:paid` or `:reason`)
  """

  alias X402.Utils

  @payment_meta_key "x402/payment"
  @payment_response_meta_key "x402/payment-response"

  # Legacy x402 JSON-RPC error code carrying PaymentRequired in error data.
  @payment_required_code 402
  # SEP-1036 UrlElicitationRequired, designated by MCP for payment flows.
  @elicitation_required_code -32_042

  @meta_keys {"_meta", :_meta}

  @doc since: "0.6.0"
  @doc """
  Returns the request `_meta` key carrying the client's `PaymentPayload`.

  ## Examples

      iex> X402.MCP.payment_meta_key()
      "x402/payment"
  """
  @spec payment_meta_key() :: String.t()
  def payment_meta_key, do: @payment_meta_key

  @doc since: "0.6.0"
  @doc """
  Returns the result `_meta` key carrying the server's settlement receipt.

  ## Examples

      iex> X402.MCP.payment_response_meta_key()
      "x402/payment-response"
  """
  @spec payment_response_meta_key() :: String.t()
  def payment_response_meta_key, do: @payment_response_meta_key

  @doc since: "0.6.0"
  @doc """
  Fetches the `PaymentPayload` from a tool-call request's `_meta`.

  Performs the same minimal structural check as the upstream SDKs — the value
  must be a map with `x402Version` and `payload` — full validation happens
  during verification.

  ## Examples

      iex> payment = %{"x402Version" => 2, "accepted" => %{}, "payload" => %{}}
      iex> request = %{"name" => "search", "_meta" => %{"x402/payment" => payment}}
      iex> X402.MCP.fetch_payment(request)
      {:ok, payment}

      iex> X402.MCP.fetch_payment(%{"name" => "search"})
      :error
  """
  @spec fetch_payment(map()) :: {:ok, map()} | :error
  def fetch_payment(request) when is_map(request) do
    with meta when is_map(meta) <- Utils.map_value(request, @meta_keys),
         %{} = payment <- Map.get(meta, @payment_meta_key),
         true <- payment_payload_structure?(payment) do
      {:ok, payment}
    else
      _other -> :error
    end
  end

  def fetch_payment(_request), do: :error

  @doc since: "0.6.0"
  @doc """
  Attaches a `PaymentPayload` to a tool-call request's `_meta`.

  Existing `_meta` entries are preserved; when the request uses an atom
  `:_meta` key it is kept (avoiding a duplicate key on JSON encoding).

  ## Examples

      iex> request = %{"name" => "search", "arguments" => %{"q" => "x402"}}
      iex> X402.MCP.put_payment(request, %{"x402Version" => 2, "payload" => %{}})
      %{
        "name" => "search",
        "arguments" => %{"q" => "x402"},
        "_meta" => %{"x402/payment" => %{"x402Version" => 2, "payload" => %{}}}
      }
  """
  @spec put_payment(map(), map()) :: map()
  def put_payment(request, payment_payload)
      when is_map(request) and is_map(payment_payload) do
    put_meta_entry(request, @payment_meta_key, payment_payload)
  end

  @doc since: "0.6.0"
  @doc """
  Fetches the settlement receipt from a tool result's `_meta`.

  The receipt must be a map containing `success` (the `SettlementResponse`
  schema).

  ## Examples

      iex> receipt = %{"success" => true, "transaction" => "0xabc", "network" => "eip155:84532"}
      iex> result = %{"content" => [], "_meta" => %{"x402/payment-response" => receipt}}
      iex> X402.MCP.fetch_payment_response(result)
      {:ok, receipt}

      iex> X402.MCP.fetch_payment_response(%{"content" => []})
      :error
  """
  @spec fetch_payment_response(map()) :: {:ok, map()} | :error
  def fetch_payment_response(result) when is_map(result) do
    with meta when is_map(meta) <- Utils.map_value(result, @meta_keys),
         %{} = receipt <- Map.get(meta, @payment_response_meta_key),
         true <- settle_response_structure?(receipt) do
      {:ok, receipt}
    else
      _other -> :error
    end
  end

  def fetch_payment_response(_result), do: :error

  @doc since: "0.6.0"
  @doc """
  Attaches a settlement receipt to a tool result's `_meta`.

  ## Examples

      iex> result = %{"content" => [%{"type" => "text", "text" => "ok"}]}
      iex> X402.MCP.put_payment_response(result, %{"success" => true})
      %{
        "content" => [%{"type" => "text", "text" => "ok"}],
        "_meta" => %{"x402/payment-response" => %{"success" => true}}
      }
  """
  @spec put_payment_response(map(), map()) :: map()
  def put_payment_response(result, settle_response)
      when is_map(result) and is_map(settle_response) do
    put_meta_entry(result, @payment_response_meta_key, settle_response)
  end

  @doc since: "0.6.0"
  @doc """
  Fetches the `PaymentRequired` object from a payment-required tool result.

  Per the MCP transport spec, the result must have `isError: true`.
  `structuredContent` is preferred; `content[0].text` is parsed as JSON when
  structured content is absent. Returns `:error` for any other tool result.

  ## Examples

      iex> payment_required = %{"x402Version" => 2, "error" => "Payment required", "accepts" => []}
      iex> result = %{"isError" => true, "structuredContent" => payment_required, "content" => []}
      iex> X402.MCP.fetch_payment_required(result)
      {:ok, payment_required}

      iex> X402.MCP.fetch_payment_required(%{"content" => [%{"type" => "text", "text" => "hi"}]})
      :error
  """
  @spec fetch_payment_required(map()) :: {:ok, map()} | :error
  def fetch_payment_required(result) when is_map(result) do
    with true <- Utils.map_value(result, {"isError", :isError}) == true,
         {:ok, payment_required} <- extract_payment_required(result) do
      {:ok, payment_required}
    else
      _other -> :error
    end
  end

  def fetch_payment_required(_result), do: :error

  @doc since: "0.6.0"
  @doc """
  Fetches the `PaymentRequired` object from a JSON-RPC error.

  Some MCP stacks surface payment challenges as JSON-RPC errors instead of
  tool results: code `402` (legacy x402) carries `PaymentRequired` directly in
  `data`, and code `-32042` (SEP-1036 `UrlElicitationRequired`, which MCP
  designates for payment/elicitation flows) carries it in `data` or namespaced
  under `data.x402`.

  ## Examples

      iex> payment_required = %{"x402Version" => 2, "accepts" => []}
      iex> error = %{"code" => 402, "message" => "Payment required", "data" => payment_required}
      iex> X402.MCP.fetch_payment_required_from_error(error)
      {:ok, payment_required}

      iex> error = %{
      ...>   "code" => -32042,
      ...>   "message" => "Elicitation required",
      ...>   "data" => %{"x402" => %{"x402Version" => 2, "accepts" => []}}
      ...> }
      iex> X402.MCP.fetch_payment_required_from_error(error)
      {:ok, %{"x402Version" => 2, "accepts" => []}}

      iex> X402.MCP.fetch_payment_required_from_error(%{"code" => -32600})
      :error
  """
  @spec fetch_payment_required_from_error(term()) :: {:ok, map()} | :error
  def fetch_payment_required_from_error(error) when is_map(error) do
    payment_required_from_error(
      Utils.map_value(error, {"code", :code}),
      Utils.map_value(error, {"data", :data})
    )
  end

  def fetch_payment_required_from_error(_error), do: :error

  @spec payment_required_from_error(term(), term()) :: {:ok, map()} | :error
  defp payment_required_from_error(@payment_required_code, data) do
    fetch_payment_required_structure(data)
  end

  defp payment_required_from_error(@elicitation_required_code, data) do
    case fetch_payment_required_structure(data) do
      {:ok, payment_required} -> {:ok, payment_required}
      :error -> fetch_payment_required_structure(namespaced_x402(data))
    end
  end

  defp payment_required_from_error(_code, _data), do: :error

  @spec fetch_payment_required_structure(term()) :: {:ok, map()} | :error
  defp fetch_payment_required_structure(value) do
    case payment_required_structure?(value) do
      true -> {:ok, value}
      false -> :error
    end
  end

  @spec namespaced_x402(term()) :: term()
  defp namespaced_x402(data) when is_map(data), do: Utils.map_value(data, {"x402", :x402})
  defp namespaced_x402(_data), do: nil

  @doc since: "0.6.0"
  @doc """
  Builds the payment-required tool result for a `PaymentRequired` object.

  Per the MCP transport spec the object is provided in **both** formats:
  `structuredContent` carries it directly and `content[0].text` carries the
  same object JSON-encoded, with `isError: true`.

  Returns `{:error, :invalid_payment_required}` when the map lacks the
  `x402Version`/`accepts` structure or cannot be encoded as JSON.

  ## Examples

      iex> payment_required = %{"x402Version" => 2, "error" => "Payment required", "accepts" => []}
      iex> {:ok, result} = X402.MCP.payment_required_result(payment_required)
      iex> {result["isError"], result["structuredContent"] == payment_required}
      {true, true}
      iex> [%{"type" => "text", "text" => text}] = result["content"]
      iex> Jason.decode!(text) == payment_required
      true

      iex> X402.MCP.payment_required_result(%{"accepts" => []})
      {:error, :invalid_payment_required}
  """
  @spec payment_required_result(map()) :: {:ok, map()} | {:error, :invalid_payment_required}
  def payment_required_result(payment_required) when is_map(payment_required) do
    with true <- payment_required_structure?(payment_required),
         {:ok, json} <- Jason.encode(payment_required) do
      {:ok,
       %{
         "isError" => true,
         "structuredContent" => payment_required,
         "content" => [%{"type" => "text", "text" => json}]
       }}
    else
      _other -> {:error, :invalid_payment_required}
    end
  end

  def payment_required_result(_payment_required), do: {:error, :invalid_payment_required}

  # -- Structure checks -------------------------------------------------------

  @spec payment_payload_structure?(map()) :: boolean()
  defp payment_payload_structure?(payment) do
    not is_nil(Utils.map_value(payment, {"x402Version", :x402Version})) and
      not is_nil(Utils.map_value(payment, {"payload", :payload}))
  end

  @spec settle_response_structure?(map()) :: boolean()
  defp settle_response_structure?(receipt) do
    has_key?(receipt, {"success", :success})
  end

  @spec payment_required_structure?(term()) :: boolean()
  defp payment_required_structure?(value) when is_map(value) do
    not is_nil(Utils.map_value(value, {"x402Version", :x402Version})) and
      is_list(Utils.map_value(value, {"accepts", :accepts}))
  end

  defp payment_required_structure?(_value), do: false

  @spec has_key?(map(), {String.t(), atom()}) :: boolean()
  defp has_key?(map, {string_key, atom_key}) do
    Map.has_key?(map, string_key) or Map.has_key?(map, atom_key)
  end

  # -- _meta plumbing ---------------------------------------------------------

  @spec extract_payment_required(map()) :: {:ok, map()} | :error
  defp extract_payment_required(result) do
    structured = Utils.map_value(result, {"structuredContent", :structuredContent})

    case payment_required_structure?(structured) do
      true -> {:ok, structured}
      false -> extract_payment_required_from_content(result)
    end
  end

  @spec extract_payment_required_from_content(map()) :: {:ok, map()} | :error
  defp extract_payment_required_from_content(result) do
    with [first | _rest] <- Utils.map_value(result, {"content", :content}),
         true <- is_map(first),
         "text" <- Utils.map_value(first, {"type", :type}),
         text when is_binary(text) <- Utils.map_value(first, {"text", :text}),
         {:ok, decoded} <- Jason.decode(text),
         true <- payment_required_structure?(decoded) do
      {:ok, decoded}
    else
      _other -> :error
    end
  end

  @spec put_meta_entry(map(), String.t(), map()) :: map()
  defp put_meta_entry(map, key, value) do
    meta =
      case Utils.map_value(map, @meta_keys) do
        existing when is_map(existing) -> existing
        _other -> %{}
      end

    meta_key =
      case Map.has_key?(map, :_meta) and not Map.has_key?(map, "_meta") do
        true -> :_meta
        false -> "_meta"
      end

    Map.put(map, meta_key, Map.put(meta, key, value))
  end
end
