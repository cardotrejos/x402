defmodule X402.AuthCapture.ETSStore do
  @moduledoc """
  Volatile, serialized auth-capture store for development and tests.

  A dedicated owner serializes mutations over a private ETS table. There is no
  TTL, takeover, or eviction. Losing the owner loses all records and is unsafe
  once payments exist. Do not restart an empty store against funded payments.
  Production applications must implement `X402.AuthCapture.Store` with shared,
  durable storage instead.
  """

  use GenServer

  @behaviour X402.AuthCapture.Store

  alias X402.AuthCapture.Store

  @options [name: [type: :atom]]

  @doc since: "0.9.0"
  @doc "Starts a private store. The optional `:name` must be an atom."
  @spec start_link(keyword()) ::
          GenServer.on_start() | {:error, NimbleOptions.ValidationError.t()}
  def start_link(opts \\ []) do
    with {:ok, validated} <- NimbleOptions.validate(opts, @options) do
      GenServer.start_link(__MODULE__, :ok, validated)
    end
  end

  @doc since: "0.9.0"
  @doc "Reads one record from the owner."
  @impl Store
  @spec fetch(GenServer.server(), term()) :: {:ok, Store.value()}
  def fetch(server, key), do: GenServer.call(server, {:fetch, key})

  @doc since: "0.9.0"
  @doc "Serializes a mutation; callback failure leaves the previous record intact."
  @spec transact(GenServer.server(), term(), Store.mutation()) :: {:ok, term()} | {:error, term()}
  def transact(server, key, mutation), do: Store.transact({__MODULE__, server}, key, mutation)

  @doc since: "0.9.0"
  @doc "Serializes a multi-record snapshot and applies its selected writes atomically."
  @impl Store
  @spec transact_many(GenServer.server(), [term()], Store.multi_mutation()) ::
          {:ok, term()} | {:error, term()}
  def transact_many(server, keys, mutation),
    do: GenServer.call(server, {:transact_many, keys, mutation})

  @doc false
  @impl GenServer
  @spec init(:ok) :: {:ok, :ets.table()}
  def init(:ok), do: {:ok, :ets.new(__MODULE__, [:set, :private])}

  @doc false
  @impl GenServer
  @spec handle_call(term(), GenServer.from(), :ets.table()) ::
          {:reply, term(), :ets.table()}
  def handle_call({:fetch, key}, _from, table) do
    {:reply, {:ok, lookup(table, key)}, table}
  end

  def handle_call({:transact_many, keys, mutation}, _from, table) do
    snapshot = Map.new(keys, &{&1, lookup(table, &1)})

    reply =
      case evaluate(mutation, snapshot) do
        {:commit, changes, reply} ->
          true = :ets.insert(table, Map.to_list(changes))
          {:ok, reply}

        {:keep, reply} ->
          {:ok, reply}

        {:abort, reason} ->
          {:error, reason}
      end

    {:reply, reply, table}
  end

  @spec lookup(:ets.table(), term()) :: Store.value()
  defp lookup(table, key) do
    case :ets.lookup(table, key) do
      [{^key, value}] -> value
      [] -> nil
    end
  end

  @spec evaluate(Store.multi_mutation(), map()) ::
          {:commit, map(), term()} | {:keep, term()} | {:abort, term()}
  defp evaluate(mutation, snapshot) do
    case mutation.(snapshot) do
      {:commit, changes, reply} when is_map(changes) ->
        if valid_changes?(changes, snapshot),
          do: {:commit, changes, reply},
          else: {:abort, :invalid_store_mutation}

      {:keep, reply} ->
        {:keep, reply}

      {:abort, reason} ->
        {:abort, reason}

      _other ->
        {:abort, :invalid_store_mutation}
    end
  catch
    _kind, _reason -> {:abort, :store_callback_failed}
  end

  @spec valid_changes?(map(), map()) :: boolean()
  defp valid_changes?(changes, snapshot),
    do: Enum.all?(changes, fn {key, value} -> Map.has_key?(snapshot, key) and is_map(value) end)
end
