defmodule X402.RPC do
  @moduledoc """
  Minimal Ethereum JSON-RPC client over Finch.

  Provides exactly the read-only RPC surface local payment verification needs:
  `eth_call`, `eth_getCode`, `eth_chainId`, and ordered batch requests. It is
  not a general-purpose Ethereum client — there is no transaction signing, no
  filter/subscription support, and no ABI layer.

  Requires the optional `:finch` dependency at runtime; every request returns
  `{:error, :missing_dependency}` when Finch is unavailable. Users bring their
  own Finch pool, exactly as with `X402.Facilitator.HTTP`:

      {:ok, rpc} =
        X402.RPC.new(
          rpc_url: "https://sepolia.base.org",
          finch: MyApp.Finch
        )

      {:ok, "0x14a34"} = X402.RPC.chain_id(rpc)

  ## TLS Verification

  `rpc_url` must use `https://` (plain `http://` is allowed only for
  `localhost`), and TLS peer verification must be configured on the Finch
  pool — see `X402.Facilitator.HTTP.secure_pool_opts/0` for a ready-made
  configuration.

  ## Telemetry

  Every request emits `[:x402, :rpc, :request]` with `:status` (`:ok` or
  `:error`) and `:method` metadata (the string method name, or `:batch`).
  """

  alias X402.Telemetry
  alias X402.Utils

  @enforce_keys [:rpc_url, :finch]
  defstruct [:rpc_url, :finch, timeout: 5_000]

  @typedoc "A Finch pool identifier, as accepted by `Finch.request/3`."
  @type finch_name :: atom() | pid() | {:via, module(), term()}

  @typedoc "Validated JSON-RPC endpoint configuration built by `new/1`."
  @type t :: %__MODULE__{rpc_url: String.t(), finch: finch_name(), timeout: pos_integer()}

  @typedoc "A JSON-RPC error object returned by the node."
  @type jsonrpc_error :: %{code: integer() | nil, message: String.t() | nil, data: term()}

  @typedoc "Structured request errors."
  @type error ::
          :missing_dependency
          | :insecure_rpc_url
          | {:transport_error, term()}
          | {:http_error, non_neg_integer()}
          | {:invalid_response, term()}
          | {:jsonrpc_error, jsonrpc_error()}

  @typedoc "One request in a batch: a JSON-RPC method name and its params."
  @type batch_request :: {String.t(), list()}

  @typedoc "Per-request outcome inside a successful batch response."
  @type batch_result :: {:ok, term()} | {:error, {:jsonrpc_error, jsonrpc_error()}}

  @config_schema [
    rpc_url: [
      type: :string,
      required: true,
      doc: """
      The JSON-RPC endpoint URL. Must use `https://`; plain `http://` is
      accepted only for `localhost` (local development nodes and tests).
      """
    ],
    finch: [
      type: {:custom, __MODULE__, :validate_finch_name, []},
      required: true,
      doc: "The Finch pool name (atom, pid, or `{:via, module, term}`)."
    ],
    timeout: [
      type: :pos_integer,
      default: 5_000,
      doc: "Receive timeout per HTTP request, in milliseconds."
    ]
  ]

  @json_headers [{"content-type", "application/json"}, {"accept", "application/json"}]

  @doc since: "0.6.0"
  @doc """
  Builds a validated RPC configuration.

  Options are validated with `NimbleOptions`:

  #{NimbleOptions.docs(@config_schema)}

  Returns `{:error, :insecure_rpc_url}` when `rpc_url` does not use
  `https://` (with a `localhost` exemption for development nodes).

  ## Examples

      iex> {:ok, rpc} = X402.RPC.new(rpc_url: "https://sepolia.base.org", finch: MyFinch)
      iex> rpc.timeout
      5000

      iex> X402.RPC.new(rpc_url: "http://rpc.example.com", finch: MyFinch)
      {:error, :insecure_rpc_url}
  """
  @spec new(keyword()) :: {:ok, t()} | {:error, :insecure_rpc_url}
  def new(opts) when is_list(opts) do
    validated = NimbleOptions.validate!(opts, @config_schema)
    rpc_url = Keyword.fetch!(validated, :rpc_url)

    case validate_url_scheme(rpc_url) do
      :ok ->
        {:ok,
         %__MODULE__{
           rpc_url: rpc_url,
           finch: Keyword.fetch!(validated, :finch),
           timeout: Keyword.fetch!(validated, :timeout)
         }}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Performs a single JSON-RPC request.

  Returns the decoded `"result"` value on success, or a structured error —
  node-side failures come back as `{:error, {:jsonrpc_error, %{code: _,
  message: _, data: _}}}` and transport failures as
  `{:error, {:transport_error, reason}}`.
  """
  @spec request(t(), String.t(), list()) :: {:ok, term()} | {:error, error()}
  def request(%__MODULE__{} = rpc, method, params) when is_binary(method) and is_list(params) do
    body = %{"jsonrpc" => "2.0", "id" => 1, "method" => method, "params" => params}

    case post(rpc, body) do
      {:ok, decoded} ->
        emit_result(decode_single(decoded), method)

      {:error, reason} ->
        Telemetry.emit(:rpc, :request, :error, %{method: method, reason: reason})
        {:error, reason}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Performs an ordered JSON-RPC batch request in one HTTP round-trip.

  Takes a list of `{method, params}` tuples and returns `{:ok, results}`
  where `results` has one entry per request, **in request order** (responses
  are re-ordered by id): each entry is `{:ok, result}` or
  `{:error, {:jsonrpc_error, error}}`. Transport-level failures fail the
  whole batch with `{:error, reason}`.

  An empty request list returns `{:ok, []}` without any HTTP call.
  """
  @spec batch(t(), [batch_request()]) :: {:ok, [batch_result()]} | {:error, error()}
  def batch(%__MODULE__{}, []), do: {:ok, []}

  def batch(%__MODULE__{} = rpc, requests) when is_list(requests) do
    body =
      requests
      |> Enum.with_index(1)
      |> Enum.map(fn {{method, params}, id} when is_binary(method) and is_list(params) ->
        %{"jsonrpc" => "2.0", "id" => id, "method" => method, "params" => params}
      end)

    case post(rpc, body) do
      {:ok, responses} ->
        emit_result(decode_batch(responses, length(requests)), :batch)

      {:error, reason} ->
        Telemetry.emit(:rpc, :request, :error, %{method: :batch, reason: reason})
        {:error, reason}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Performs an `eth_call` against the given block (default `"latest"`).

  The call object accepts `:to`, `:data`, and optionally `:from` (atom or
  string keys). Returns the raw `0x`-prefixed return data.
  """
  @spec call(t(), map(), String.t()) :: {:ok, String.t()} | {:error, error()}
  def call(%__MODULE__{} = rpc, call_object, block \\ "latest") when is_map(call_object) do
    request(rpc, "eth_call", [normalize_call_object(call_object), block])
  end

  @doc since: "0.6.0"
  @doc """
  Returns the bytecode at `address` via `eth_getCode` (default block
  `"latest"`).

  A plain externally-owned account returns `{:ok, "0x"}`.
  """
  @spec get_code(t(), String.t(), String.t()) :: {:ok, String.t()} | {:error, error()}
  def get_code(%__MODULE__{} = rpc, address, block \\ "latest") when is_binary(address) do
    request(rpc, "eth_getCode", [address, block])
  end

  @doc since: "0.6.0"
  @doc """
  Returns the chain id via `eth_chainId`, as the node's hex string
  (for example `"0x14a34"` for Base Sepolia).
  """
  @spec chain_id(t()) :: {:ok, String.t()} | {:error, error()}
  def chain_id(%__MODULE__{} = rpc), do: request(rpc, "eth_chainId", [])

  @doc since: "0.6.0"
  @doc """
  Validates that a value is an `%X402.RPC{}` configuration.

  Designed for `NimbleOptions` custom validation (used by
  `X402.Verify.EVM`).
  """
  @spec validate_config(term()) :: {:ok, t()} | {:error, String.t()}
  def validate_config(%__MODULE__{} = rpc), do: {:ok, rpc}

  def validate_config(_other),
    do: {:error, "expected an %X402.RPC{} configuration built with X402.RPC.new/1"}

  @doc false
  @spec validate_finch_name(term()) :: {:ok, finch_name()} | {:error, String.t()}
  def validate_finch_name(name) when is_atom(name) and not is_nil(name), do: {:ok, name}
  def validate_finch_name(pid) when is_pid(pid), do: {:ok, pid}
  def validate_finch_name({:via, module, _term} = via) when is_atom(module), do: {:ok, via}

  def validate_finch_name(_other),
    do: {:error, "expected a Finch pool name (atom, pid, or {:via, module, term})"}

  # -- Transport --------------------------------------------------------------

  @spec post(t(), map() | list()) :: {:ok, term()} | {:error, error()}
  defp post(%__MODULE__{} = rpc, body) do
    with {:ok, finch_module} <- ensure_finch_module(),
         {:ok, encoded} <- encode_body(body),
         {:ok, response_body} <- perform_request(rpc, finch_module, encoded) do
      decode_body(response_body)
    end
  end

  @spec perform_request(t(), module(), iodata()) ::
          {:ok, binary()}
          | {:error, {:transport_error, term()} | {:http_error, non_neg_integer()}}
  defp perform_request(rpc, finch_module, encoded) do
    request = finch_module.build(:post, rpc.rpc_url, @json_headers, encoded)

    response =
      try do
        finch_module.request(request, rpc.finch, receive_timeout: rpc.timeout)
      catch
        :exit, reason -> {:error, reason}
      end

    case response do
      {:ok, %{status: status, body: response_body}} when status in 200..299 ->
        {:ok, response_body}

      {:ok, %{status: status}} when is_integer(status) ->
        {:error, {:http_error, status}}

      {:error, reason} ->
        {:error, {:transport_error, reason}}
    end
  end

  @spec encode_body(term()) :: {:ok, iodata()} | {:error, {:invalid_response, term()}}
  defp encode_body(body) do
    case Jason.encode(body) do
      {:ok, encoded} -> {:ok, encoded}
      {:error, reason} -> {:error, {:invalid_response, reason}}
    end
  end

  @spec decode_body(binary()) :: {:ok, term()} | {:error, {:invalid_response, term()}}
  defp decode_body(body) do
    case Jason.decode(body) do
      {:ok, decoded} -> {:ok, decoded}
      {:error, reason} -> {:error, {:invalid_response, reason}}
    end
  end

  # -- Response decoding ------------------------------------------------------

  @spec decode_single(term()) :: {:ok, term()} | {:error, error()}
  defp decode_single(%{"error" => error}) when is_map(error),
    do: {:error, {:jsonrpc_error, normalize_jsonrpc_error(error)}}

  defp decode_single(%{"result" => result}), do: {:ok, result}
  defp decode_single(other), do: {:error, {:invalid_response, other}}

  @spec decode_batch(term(), pos_integer()) :: {:ok, [batch_result()]} | {:error, error()}
  defp decode_batch(responses, count) when is_list(responses) do
    by_id = Map.new(responses, fn response -> {response_id(response), response} end)

    results =
      Enum.map(1..count, fn id ->
        case Map.fetch(by_id, id) do
          {:ok, response} -> decode_single(response)
          :error -> {:error, {:invalid_response, {:missing_response, id}}}
        end
      end)

    case Enum.find(results, &match?({:error, {:invalid_response, _reason}}, &1)) do
      nil -> {:ok, results}
      {:error, reason} -> {:error, reason}
    end
  end

  defp decode_batch(other, _count), do: {:error, {:invalid_response, other}}

  @spec response_id(term()) :: term()
  defp response_id(%{"id" => id}), do: id
  defp response_id(_response), do: nil

  @spec normalize_jsonrpc_error(map()) :: jsonrpc_error()
  defp normalize_jsonrpc_error(error) do
    %{
      code: normalize_code(Map.get(error, "code")),
      message: normalize_message(Map.get(error, "message")),
      data: Map.get(error, "data")
    }
  end

  defp normalize_code(code) when is_integer(code), do: code
  defp normalize_code(_code), do: nil

  defp normalize_message(message) when is_binary(message), do: message
  defp normalize_message(_message), do: nil

  # -- Helpers ----------------------------------------------------------------

  @spec emit_result({:ok, term()} | {:error, error()}, String.t() | :batch) ::
          {:ok, term()} | {:error, error()}
  defp emit_result({:ok, _result} = ok, method) do
    Telemetry.emit(:rpc, :request, :ok, %{method: method})
    ok
  end

  defp emit_result({:error, reason} = error, method) do
    Telemetry.emit(:rpc, :request, :error, %{method: method, reason: reason})
    error
  end

  @spec normalize_call_object(map()) :: map()
  defp normalize_call_object(call_object) do
    [{"to", :to}, {"data", :data}, {"from", :from}]
    |> Enum.reduce(%{}, fn {string_key, atom_key}, acc ->
      case Utils.map_value(call_object, {string_key, atom_key}) do
        nil -> acc
        value -> Map.put(acc, string_key, value)
      end
    end)
  end

  @spec ensure_finch_module() :: {:ok, module()} | {:error, :missing_dependency}
  defp ensure_finch_module do
    finch_module = Module.concat(["Finch"])

    case Code.ensure_loaded?(finch_module) and function_exported?(finch_module, :request, 3) and
           function_exported?(finch_module, :build, 4) do
      true -> {:ok, finch_module}
      false -> {:error, :missing_dependency}
    end
  end

  # Mirrors X402.Facilitator.HTTP: JSON-RPC requests carry payment payloads,
  # so plaintext transport is refused. Loopback hosts are exempt because they
  # cannot be intercepted by a network attacker (local dev nodes, tests).
  @spec validate_url_scheme(String.t()) :: :ok | {:error, :insecure_rpc_url}
  defp validate_url_scheme(rpc_url) do
    case URI.parse(rpc_url) do
      %URI{scheme: "https"} -> :ok
      %URI{scheme: "http", host: host} when host in ["localhost", "127.0.0.1", "::1"] -> :ok
      _uri -> {:error, :insecure_rpc_url}
    end
  end
end
