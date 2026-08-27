defmodule X402.Extensions.PaymentIdentifier.RedisCache.Command do
  @moduledoc """
  Behaviour for the Redis command layer used by
  `X402.Extensions.PaymentIdentifier.RedisCache`.

  The single callback mirrors `Redix.command/2`: it executes one Redis
  command against a connection and returns the reply. `Redix` itself
  satisfies the behaviour structurally and is the default; tests (or
  alternative Redis clients with a compatible reply shape) can supply their
  own module through the adapter's `:command` option.
  """

  @doc """
  Executes a single Redis command against `conn`.

  Must follow `Redix.command/2` semantics: `{:ok, reply}` with the decoded
  RESP reply (`"OK"`, `nil`, a binary, or an integer for the commands this
  adapter issues), or `{:error, reason}` for connection or protocol errors.
  """
  @callback command(conn :: term(), command :: [String.t()]) ::
              {:ok, term()} | {:error, term()}
end

defmodule X402.Extensions.PaymentIdentifier.RedisCache do
  @moduledoc """
  Redis-backed cache adapter for payment identifier idempotency.

  Implements the `X402.Extensions.PaymentIdentifier.Cache` behaviour over a
  [Redix](https://hexdocs.pm/redix) connection, making the replay-protection
  claim safe across a clustered BEAM deployment: all nodes share one store,
  so a replayed payment proof routed to two nodes is still claimed exactly
  once. The atomic first-writer-wins claim (`put_new/3`) is a single
  `SET key value NX PX ttl` command — Redis guarantees the
  insert-if-absent-with-TTL combination atomically.

  Requires the optional `redix` dependency:

      {:redix, "~> 1.5"}

  ## Usage

  The adapter does **not** own the Redis connection — you start and
  supervise Redix yourself (with your pooling, TLS, and reconnection
  policy) and hand the adapter the connection's pid or registered name:

      # In your supervision tree
      children = [
        {Redix, {System.fetch_env!("REDIS_URL"), name: MyApp.Redis}},
        ...
      ]

      # Build the adapter state and configure the gate
      {:ok, cache} = X402.Extensions.PaymentIdentifier.RedisCache.new(conn: MyApp.Redis)

      plug X402.Plug.PaymentGate,
        payment_identifier_cache: {X402.Extensions.PaymentIdentifier.RedisCache, cache},
        routes: [...]

  ## Failure semantics

  The adapter honors the `X402.Extensions.PaymentIdentifier.Cache` contract:

    * `put_new/3` returns `{:error, :already_exists}` only for a live
      (unexpired) duplicate — Redis expires entries server-side via `PX`,
      so an expired claim never blocks a retry.
    * Connection and Redis errors are returned as `{:error, reason}` (the
      `Redix.ConnectionError` / `Redix.Error` struct), which
      `X402.Plug.PaymentGate` treats as adapter failure and **fails
      closed** — a Redis outage degrades to denying new paid requests, not
      to replay.
    * Live claims are never evicted by the adapter. Configure the Redis
      server with `maxmemory-policy noeviction` so Redis doesn't drop live
      claims either; at capacity, writes then fail with an `OOM` error that
      fails closed like any other adapter error.

  Entries are stored under `namespace <> payment_id` (default namespace
  `"x402:payment_identifier:"`). Cached values are encoded as `"verified"`
  or `"rejected:" <> Base64(term)`; rejection reasons are decoded with
  `:erlang.binary_to_term/2` in `:safe` mode, so they must be composed of
  existing atoms and data terms (which is true for every reason this
  library produces).
  """

  @behaviour X402.Extensions.PaymentIdentifier.Cache

  alias X402.Extensions.PaymentIdentifier.Cache

  @default_ttl_ms :timer.hours(1)
  @default_namespace "x402:payment_identifier:"
  @verified_encoding "verified"
  @rejected_prefix "rejected:"

  @new_opts_schema [
    conn: [
      type: :any,
      required: true,
      doc: """
      The Redix connection: a pid or the name the connection was registered
      under. The adapter never starts or supervises the connection.
      """
    ],
    ttl_ms: [
      type: :pos_integer,
      default: @default_ttl_ms,
      doc: "Time-to-live for entries in milliseconds (Redis `PX`)."
    ],
    namespace: [
      type: :string,
      default: @default_namespace,
      doc: "Prefix for the Redis keys holding payment identifier claims."
    ],
    command: [
      type: {:custom, __MODULE__, :validate_command_module, []},
      doc: """
      Module implementing
      `X402.Extensions.PaymentIdentifier.RedisCache.Command` used to execute
      Redis commands. Defaults to `Redix`. Injectable for testing without a
      live Redis server.
      """
    ]
  ]

  @enforce_keys [:conn, :ttl_ms, :namespace, :command]
  defstruct [:conn, :ttl_ms, :namespace, :command]

  @typedoc """
  Adapter state built by `new/1`.

  Passed as the second element of the `{RedisCache, cache}` adapter tuple
  and handed back to every callback.
  """
  @type t :: %__MODULE__{
          conn: term(),
          ttl_ms: pos_integer(),
          namespace: String.t(),
          command: module()
        }

  @doc since: "0.6.0"
  @doc """
  Builds the adapter state for a running Redix connection.

  Returns `{:error, :missing_dependency}` when the optional `redix`
  dependency is unavailable and no `:command` module was supplied. Raises
  `NimbleOptions.ValidationError` for invalid options (programmer error).

  ## Options

  #{NimbleOptions.docs(@new_opts_schema)}

  ## Examples

      {:ok, cache} =
        X402.Extensions.PaymentIdentifier.RedisCache.new(
          conn: MyApp.Redis,
          ttl_ms: :timer.minutes(30),
          namespace: "myapp:x402:"
        )
  """
  @spec new(keyword()) :: {:ok, t()} | {:error, :missing_dependency}
  def new(opts) when is_list(opts) do
    opts = NimbleOptions.validate!(opts, @new_opts_schema)

    with {:ok, command} <- resolve_command_module(Keyword.get(opts, :command)) do
      {:ok,
       %__MODULE__{
         conn: Keyword.fetch!(opts, :conn),
         ttl_ms: Keyword.fetch!(opts, :ttl_ms),
         namespace: Keyword.fetch!(opts, :namespace),
         command: command
       }}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Looks up a payment identifier (`GET`).

  Returns `:miss` for absent or expired entries — Redis removes expired
  keys server-side. A stored value that cannot be decoded is reported as
  `{:error, {:invalid_cache_entry, raw}}` (fails closed at the gate).
  """
  @impl Cache
  @spec get(t(), Cache.key()) :: Cache.get_result()
  def get(%__MODULE__{} = cache, payment_id) when is_binary(payment_id) do
    case run(cache, ["GET", key(cache, payment_id)]) do
      {:ok, nil} -> :miss
      {:ok, encoded} when is_binary(encoded) -> decode_value(encoded)
      {:ok, other} -> {:error, {:unexpected_response, other}}
      {:error, reason} -> {:error, reason}
    end
  end

  def get(_cache, _payment_id), do: {:error, :invalid_payment_id}

  @doc since: "0.6.0"
  @doc """
  Unconditionally stores a value, resetting its TTL (`SET PX`).
  """
  @impl Cache
  @spec put(t(), Cache.key(), Cache.value()) :: Cache.write_result()
  def put(%__MODULE__{} = cache, payment_id, value) when is_binary(payment_id) do
    with {:ok, encoded} <- encode_value(value) do
      case run(cache, ["SET", key(cache, payment_id), encoded, "PX", ttl(cache)]) do
        {:ok, "OK"} -> :ok
        {:ok, other} -> {:error, {:unexpected_response, other}}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  def put(_cache, _payment_id, _value), do: {:error, :invalid_payment_id}

  @doc since: "0.6.0"
  @doc """
  Atomically claims a payment identifier (`SET NX PX`).

  The insert-if-absent and the TTL are one Redis command, so concurrent
  claims for the same identifier — from any node — resolve to exactly one
  `:ok`; every other caller gets `{:error, :already_exists}`. An expired
  entry never blocks a new claim (Redis expiry is server-side), and a live
  claim is never evicted by the adapter.
  """
  @impl Cache
  @spec put_new(t(), Cache.key(), Cache.value()) :: Cache.put_new_result()
  def put_new(%__MODULE__{} = cache, payment_id, value) when is_binary(payment_id) do
    with {:ok, encoded} <- encode_value(value) do
      case run(cache, ["SET", key(cache, payment_id), encoded, "NX", "PX", ttl(cache)]) do
        {:ok, "OK"} -> :ok
        {:ok, nil} -> {:error, :already_exists}
        {:ok, other} -> {:error, {:unexpected_response, other}}
        {:error, reason} -> {:error, reason}
      end
    end
  end

  def put_new(_cache, _payment_id, _value), do: {:error, :invalid_payment_id}

  @doc since: "0.6.0"
  @doc """
  Removes the entry for a payment identifier (`DEL`), releasing its claim.
  """
  @impl Cache
  @spec delete(t(), Cache.key()) :: Cache.write_result()
  def delete(%__MODULE__{} = cache, payment_id) when is_binary(payment_id) do
    case run(cache, ["DEL", key(cache, payment_id)]) do
      {:ok, count} when is_integer(count) -> :ok
      {:ok, other} -> {:error, {:unexpected_response, other}}
      {:error, reason} -> {:error, reason}
    end
  end

  def delete(_cache, _payment_id), do: {:error, :invalid_payment_id}

  @doc false
  @spec validate_command_module(term()) :: {:ok, module()} | {:error, String.t()}
  def validate_command_module(module) when is_atom(module) and not is_nil(module) do
    case X402.Behaviour.implements?(module, command: 2) do
      true -> {:ok, module}
      false -> {:error, command_module_error(module)}
    end
  end

  def validate_command_module(other), do: {:error, command_module_error(other)}

  # -- Internal ---------------------------------------------------------------

  @spec run(t(), [String.t()]) :: {:ok, term()} | {:error, term()}
  defp run(%__MODULE__{command: command, conn: conn}, redis_command) do
    command.command(conn, redis_command)
  end

  @spec key(t(), Cache.key()) :: String.t()
  defp key(%__MODULE__{namespace: namespace}, payment_id), do: namespace <> payment_id

  @spec ttl(t()) :: String.t()
  defp ttl(%__MODULE__{ttl_ms: ttl_ms}), do: Integer.to_string(ttl_ms)

  @spec encode_value(term()) :: {:ok, String.t()} | {:error, :invalid_cache_value}
  defp encode_value(:verified), do: {:ok, @verified_encoding}

  defp encode_value({:rejected, reason}),
    do: {:ok, @rejected_prefix <> Base.encode64(:erlang.term_to_binary(reason))}

  defp encode_value(_invalid), do: {:error, :invalid_cache_value}

  @spec decode_value(String.t()) ::
          {:hit, Cache.value()} | {:error, {:invalid_cache_entry, String.t()}}
  defp decode_value(@verified_encoding), do: {:hit, :verified}

  defp decode_value(@rejected_prefix <> encoded = raw) do
    with {:ok, binary} <- Base.decode64(encoded),
         {:ok, reason} <- safe_binary_to_term(binary) do
      {:hit, {:rejected, reason}}
    else
      _error -> {:error, {:invalid_cache_entry, raw}}
    end
  end

  defp decode_value(raw), do: {:error, {:invalid_cache_entry, raw}}

  # :safe refuses terms that would allocate new atoms (or carry funs), so a
  # tampered cache entry cannot exhaust the atom table.
  @spec safe_binary_to_term(binary()) :: {:ok, term()} | :error
  defp safe_binary_to_term(binary) do
    {:ok, :erlang.binary_to_term(binary, [:safe])}
  rescue
    ArgumentError -> :error
  end

  # Resolved at runtime via Module.concat so the library compiles without the
  # optional redix dependency (same pattern as X402.Client.Finch).
  @spec resolve_command_module(module() | nil) ::
          {:ok, module()} | {:error, :missing_dependency}
  defp resolve_command_module(nil) do
    redix = Module.concat(["Redix"])

    case Code.ensure_loaded?(redix) and function_exported?(redix, :command, 2) do
      true -> {:ok, redix}
      false -> {:error, :missing_dependency}
    end
  end

  defp resolve_command_module(module), do: {:ok, module}

  @spec command_module_error(term()) :: String.t()
  defp command_module_error(value) do
    "expected a module implementing X402.Extensions.PaymentIdentifier.RedisCache.Command " <>
      "(command/2), got: #{inspect(value)}"
  end
end
