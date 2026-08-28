defmodule X402.Facilitator.PendingSettlementStore do
  @moduledoc """
  Behaviour for pending-settlement reconciliation stores.

  When `X402.Facilitator.Engine.settle/3` broadcasts a transaction but cannot
  establish its confirmation — the receipt poll times out, or the transport
  fails mid-broadcast — it returns the spec's non-terminal
  `"settlement_pending"` response. Without a store that knowledge is lost: a
  client retrying the identical payment would re-verify and re-broadcast a
  second transaction instead of reconciling against the one already in
  flight.

  A pending-settlement store closes that loop, mirroring the reference SDKs'
  `PendingSettlementStore`: before verifying, `settle/3` looks the payment up
  here and, on a hit, **deletes the entry and re-awaits the already-broadcast
  transaction** instead of broadcasting a new one. The delete-before-reconcile
  ordering is load-bearing — a concurrent retry of the same payload misses the
  store and falls through to the normal path, where the chain itself rejects
  the duplicate (the EIP-3009 authorization nonce can only be consumed once).

  Adapters are configured as `{module, store}` tuples where `module`
  implements this behaviour and `store` is adapter-specific runtime state (a
  pid, a registered name, a connection handle). The bundled adapter is
  `X402.Facilitator.PendingSettlementStore.ETS`; multi-instance facilitators
  should supply a shared-store adapter (Redis, database) instead — entries
  must be visible to whichever instance receives the retry.

  ## Entries

  An entry records what is needed to reconcile:

    * `:transaction` — the `0x`-prefixed transaction hash.
    * `:provenance` — `:node_acknowledged` when the hash was returned by
      `eth_sendRawTransaction`, or `:local_hash` when the transport failed
      mid-broadcast and the hash was computed locally from the signed
      transaction (the node may never have seen it).
    * `:raw_transaction` — the raw signed transaction bytes for
      `:local_hash` entries (`nil` otherwise), kept so operators can inspect
      or manually rebroadcast a transaction the node may have missed. The
      engine itself never rebroadcasts.

  Entries must expire on their own (the bundled adapter defaults to five
  minutes) — an entry that outlives its transaction's relevance only delays
  the terminal verdict of a retry.

  ## Writing a distributed adapter

      defmodule MyApp.RedisPendingStore do
        @behaviour X402.Facilitator.PendingSettlementStore

        @ttl_ms :timer.minutes(5)

        @impl true
        def put(conn, key, entry) do
          encoded = Base.encode64(:erlang.term_to_binary(entry))

          case Redix.command(conn, ["SET", "x402:pending:" <> key, encoded, "PX", @ttl_ms]) do
            {:ok, "OK"} -> :ok
            {:error, reason} -> {:error, reason}
          end
        end

        @impl true
        def get(conn, key) do
          case Redix.command(conn, ["GET", "x402:pending:" <> key]) do
            {:ok, nil} -> :miss
            {:ok, encoded} -> {:hit, decode(encoded)}
            {:error, reason} -> {:error, reason}
          end
        end

        @impl true
        def delete(conn, key) do
          case Redix.command(conn, ["DEL", "x402:pending:" <> key]) do
            {:ok, _count} -> :ok
            {:error, reason} -> {:error, reason}
          end
        end

        defp decode(encoded) do
          # `:safe` refuses unknown atoms; entry maps only contain literals
          # this module wrote, so decoding failures indicate store corruption.
          Base.decode64!(encoded) |> :erlang.binary_to_term([:safe])
        end
      end
  """

  @typedoc "Key identifying a payment's settlement attempt (a lowercase hex digest)."
  @type key :: String.t()

  @typedoc "A recorded pending settlement."
  @type entry :: %{
          required(:transaction) => String.t(),
          required(:provenance) => :node_acknowledged | :local_hash,
          required(:raw_transaction) => binary() | nil
        }

  @typedoc "Adapter tuple accepted by `X402.Facilitator.Engine`."
  @type adapter :: {module(), term()}

  @typedoc "Result returned by `get/2`."
  @type get_result :: {:hit, entry()} | :miss | {:error, term()}

  @typedoc "Result returned by write/delete operations."
  @type write_result :: :ok | {:error, term()}

  @doc """
  Reads the entry stored for `key`, or `:miss` when absent or expired.
  """
  @callback get(store :: term(), key()) :: get_result()

  @doc """
  Unconditionally stores `entry` for `key`, resetting its TTL.
  """
  @callback put(store :: term(), key(), entry()) :: write_result()

  @doc """
  Deletes the entry for `key`. Deleting an absent key returns `:ok`.
  """
  @callback delete(store :: term(), key()) :: write_result()

  @required_callbacks [{:get, 2}, {:put, 3}, {:delete, 2}]

  @doc since: "0.6.0"
  @doc """
  Reads `key` through the `{module, store}` adapter.

  Adapter crashes never propagate: a raise, throw, or exit from the adapter
  (a dead, restarting, or overloaded store process, for example) is caught
  and returned as `{:error, {:store_unavailable, reason}}`, so callers can
  apply their documented store-failure handling —
  `X402.Facilitator.Engine.settle/3` treats a failed read as a miss and
  falls through to a normal broadcast.
  """
  @spec get(adapter(), key()) :: get_result()
  def get({module, store}, key) when is_binary(key),
    do: safely(fn -> module.get(store, key) end)

  @doc since: "0.6.0"
  @doc """
  Writes `entry` under `key` through the `{module, store}` adapter.

  Adapter crashes never propagate: a raise, throw, or exit from the adapter
  is caught and returned as `{:error, {:store_unavailable, reason}}` —
  `X402.Facilitator.Engine.settle/3` downgrades a failed write to a
  terminal response that keeps the broadcast transaction hash.
  """
  @spec put(adapter(), key(), entry()) :: write_result()
  def put({module, store}, key, entry) when is_binary(key) and is_map(entry),
    do: safely(fn -> module.put(store, key, entry) end)

  @doc since: "0.6.0"
  @doc """
  Deletes `key` through the `{module, store}` adapter.

  Adapter crashes never propagate: a raise, throw, or exit from the adapter
  is caught and returned as `{:error, {:store_unavailable, reason}}`.
  """
  @spec delete(adapter(), key()) :: write_result()
  def delete({module, store}, key) when is_binary(key),
    do: safely(fn -> module.delete(store, key) end)

  # Adapter processes can be dead, mid-restart, or overloaded — a
  # GenServer.call inside the adapter then EXITS (:noproc/:timeout) rather
  # than returning {:error, _}. Converting every raise/throw/exit into a
  # structured error return keeps the engine's documented store-failure
  # semantics (get -> miss fall-through, put -> downgrade with the
  # transaction hash) intact for every adapter.
  @spec safely((-> term())) :: term() | {:error, {:store_unavailable, term()}}
  defp safely(operation) do
    operation.()
  rescue
    error -> {:error, {:store_unavailable, error}}
  catch
    kind, reason -> {:error, {:store_unavailable, {kind, reason}}}
  end

  @doc since: "0.6.0"
  @doc """
  Validates a `{module, store}` adapter tuple for use as a NimbleOptions
  `{:custom, ...}` validator.

  ## Examples

      iex> X402.Facilitator.PendingSettlementStore.validate_adapter(
      ...>   {X402.Facilitator.PendingSettlementStore.ETS, MyStore}
      ...> )
      {:ok, {X402.Facilitator.PendingSettlementStore.ETS, MyStore}}

      iex> X402.Facilitator.PendingSettlementStore.validate_adapter(:not_a_store)
      {:error, "expected {module, store} with module implementing " <>
        "X402.Facilitator.PendingSettlementStore"}
  """
  @spec validate_adapter(term()) :: {:ok, adapter()} | {:error, String.t()}
  def validate_adapter({module, _store} = adapter) when is_atom(module) do
    case X402.Behaviour.implements?(module, @required_callbacks) do
      true -> {:ok, adapter}
      false -> {:error, invalid_adapter_message()}
    end
  end

  def validate_adapter(_invalid), do: {:error, invalid_adapter_message()}

  @spec invalid_adapter_message() :: String.t()
  defp invalid_adapter_message do
    "expected {module, store} with module implementing " <>
      "X402.Facilitator.PendingSettlementStore"
  end
end
