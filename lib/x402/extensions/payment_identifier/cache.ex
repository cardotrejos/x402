defmodule X402.Extensions.PaymentIdentifier.Cache do
  @moduledoc """
  Behaviour and adapter helpers for payment identifier idempotency caches.

  Cache adapters are configured as `{module, cache}` tuples where `module`
  implements this behaviour and `cache` is adapter-specific runtime state
  (for example, a pid, a registered process name, or a connection handle).

  `X402.Plug.PaymentGate` routes all replay-protection calls through this
  behaviour. The claim that prevents a payment proof from being settled twice
  is `c:put_new/3`, so every adapter must implement it with **atomic
  first-writer-wins semantics**: when several processes race to claim the same
  payment identifier, exactly one call may return `:ok` and all others must
  return `{:error, :already_exists}`.

  ## Clustered deployments: double-execution hazard

  > #### Per-node caches do not protect a cluster {: .warning}
  >
  > The bundled `X402.Extensions.PaymentIdentifier.ETSCache` adapter stores
  > claims in a **per-node ETS table**. In a clustered BEAM deployment every
  > node keeps its own table, so a replayed payment proof routed to two
  > different nodes is claimed independently on each — the protected handler
  > (and its side effects) can run **once per node** for a single payment.
  > The facilitator may still reject the duplicate settlement, but by then the
  > resource has already been served twice.
  >
  > If you run more than one node, supply an adapter backed by a shared store
  > (Redis, Mnesia, your database) instead of the default ETS adapter.

  ## Writing a distributed adapter

  `c:put_new/3` must combine "insert if absent" and "expire after TTL" in a
  single atomic operation of the backing store. In Redis that operation is
  `SET key value NX PX ttl`. A minimal adapter sketch:

      defmodule MyApp.RedisPaymentCache do
        @behaviour X402.Extensions.PaymentIdentifier.Cache

        @ttl_ms :timer.hours(1)

        @impl true
        def put_new(conn, payment_id, value) do
          # SET ... NX PX — atomic first-writer-wins with TTL in one command.
          case Redix.command(conn, ["SET", key(payment_id), encode(value), "NX", "PX", @ttl_ms]) do
            {:ok, "OK"} -> :ok
            {:ok, nil} -> {:error, :already_exists}
            {:error, reason} -> {:error, reason}
          end
        end

        @impl true
        def put(conn, payment_id, value) do
          case Redix.command(conn, ["SET", key(payment_id), encode(value), "PX", @ttl_ms]) do
            {:ok, "OK"} -> :ok
            {:error, reason} -> {:error, reason}
          end
        end

        @impl true
        def get(conn, payment_id) do
          case Redix.command(conn, ["GET", key(payment_id)]) do
            {:ok, nil} -> :miss
            {:ok, encoded} -> {:hit, decode(encoded)}
            {:error, reason} -> {:error, reason}
          end
        end

        @impl true
        def delete(conn, payment_id) do
          case Redix.command(conn, ["DEL", key(payment_id)]) do
            {:ok, _count} -> :ok
            {:error, reason} -> {:error, reason}
          end
        end

        defp key(payment_id), do: "x402:payment:" <> payment_id
        # encode/1 and decode/1 map `:verified | {:rejected, reason}` to a
        # string representation of your choice.
      end

  Configure it on the gate as:

      plug X402.Plug.PaymentGate,
        payment_identifier_cache: {MyApp.RedisPaymentCache, MyApp.Redis},
        routes: [...]

  Adapter errors other than `{:error, :already_exists}` fail closed: the gate
  responds with HTTP 500 and the protected handler does not run.
  """

  alias X402.Extensions.PaymentIdentifier

  @typedoc "Payment identifier cache key."
  @type key :: PaymentIdentifier.payment_id()

  @typedoc "Value stored for a given payment identifier."
  @type value :: :verified | {:rejected, term()}

  @typedoc "Adapter tuple accepted by `X402.Plug.PaymentGate`."
  @type adapter :: {module(), term()}

  @typedoc "Result returned by `get/2`."
  @type get_result :: {:hit, value()} | :miss | {:error, term()}

  @typedoc "Result returned by write/delete operations."
  @type write_result :: :ok | {:error, term()}

  @typedoc "Result returned by `put_new/3`."
  @type put_new_result ::
          :ok | {:error, :already_exists} | {:error, :cache_full} | {:error, term()}

  @doc """
  Reads the value stored for `key`, or `:miss` when absent or expired.
  """
  @callback get(cache :: term(), key()) :: get_result()

  @doc """
  Unconditionally stores `value` for `key`, resetting its TTL.
  """
  @callback put(cache :: term(), key(), value()) :: write_result()

  @doc """
  Atomically stores `value` for `key` only when no live entry exists.

  This is the replay-protection claim used by `X402.Plug.PaymentGate`, and it
  must be **atomic first-writer-wins**: under concurrent calls with the same
  `key`, exactly one caller receives `:ok` and every other caller receives
  `{:error, :already_exists}`. Checking existence and inserting in two
  separate store operations is not acceptable — use the backing store's
  atomic primitive (`:ets.insert_new/2`, Redis `SET NX PX`, an `INSERT` with
  a unique constraint, and so on).

  The entry must expire after the adapter's TTL; an expired entry must not
  block a new claim for the same `key`. An adapter with bounded capacity must
  **never evict a live entry to admit a new claim** — a live claim is another
  payment's replay lock; refuse with `{:error, :cache_full}` instead
  (`X402.Plug.PaymentGate` fails closed on it). Return `{:error, :already_exists}`
  only for a live (non-expired) duplicate — any other `{:error, reason}` is
  treated as an adapter failure and fails the request closed.
  """
  @callback put_new(cache :: term(), key(), value()) :: put_new_result()

  @doc """
  Removes the entry for `key`, releasing a previously successful claim.
  """
  @callback delete(cache :: term(), key()) :: write_result()

  @required_callbacks [get: 2, put: 3, put_new: 3, delete: 2]

  @adapter_error "expected a cache adapter tuple {module, cache} where module " <>
                   "implements the X402.Extensions.PaymentIdentifier.Cache callbacks " <>
                   "get/2, put/3, put_new/3, and delete/2"

  @doc since: "0.1.0"
  @doc """
  Validates a cache adapter tuple for `NimbleOptions` custom validation.
  """
  @spec validate_adapter(term()) :: :ok | {:error, String.t()}
  def validate_adapter({module, _cache}) when is_atom(module) do
    case implementation?(module) do
      true -> :ok
      false -> {:error, @adapter_error}
    end
  end

  def validate_adapter(_invalid), do: {:error, @adapter_error}

  @doc since: "0.1.0"
  @doc """
  Validates an optional cache adapter for `NimbleOptions`.

  `nil` disables idempotency caching.
  """
  @spec validate_optional_adapter(term()) :: :ok | {:error, String.t()}
  def validate_optional_adapter(nil), do: :ok
  def validate_optional_adapter(adapter), do: validate_adapter(adapter)

  @doc since: "0.1.0"
  @doc """
  Reads a cached value for a payment identifier.
  """
  @spec get(adapter(), key()) :: get_result()
  def get({module, cache}, payment_id) when is_binary(payment_id) do
    module.get(cache, payment_id)
  end

  def get(_adapter, _payment_id), do: {:error, :invalid_adapter}

  @doc since: "0.1.0"
  @doc """
  Stores a cached value for a payment identifier.
  """
  @spec put(adapter(), key(), value()) :: write_result()
  def put({module, cache}, payment_id, value) when is_binary(payment_id) do
    module.put(cache, payment_id, value)
  end

  def put(_adapter, _payment_id, _value), do: {:error, :invalid_adapter}

  @doc since: "0.6.0"
  @doc """
  Atomically claims a payment identifier through the adapter's `c:put_new/3`.

  Returns `:ok` when this caller won the claim, `{:error, :already_exists}`
  when a live entry already holds it, or `{:error, reason}` on adapter
  failure. See `c:put_new/3` for the atomicity contract.
  """
  @spec put_new(adapter(), key(), value()) :: put_new_result()
  def put_new({module, cache}, payment_id, value) when is_binary(payment_id) do
    module.put_new(cache, payment_id, value)
  end

  def put_new(_adapter, _payment_id, _value), do: {:error, :invalid_adapter}

  @doc since: "0.1.0"
  @doc """
  Deletes a cached value for a payment identifier.
  """
  @spec delete(adapter(), key()) :: write_result()
  def delete({module, cache}, payment_id) when is_binary(payment_id) do
    module.delete(cache, payment_id)
  end

  def delete(_adapter, _payment_id), do: {:error, :invalid_adapter}

  @spec implementation?(module()) :: boolean()
  defp implementation?(module), do: X402.Behaviour.implements?(module, @required_callbacks)
end
