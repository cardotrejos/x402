defmodule X402.Facilitator.PendingSettlementStore.ETS do
  @moduledoc """
  ETS-backed pending-settlement store adapter.

  Entries expire after `:ttl_ms` (default: 5 minutes, matching the reference
  SDKs' pending-settlement TTL). Expired entries are removed by an internal
  periodic cleanup loop.

  > #### Per-node only {: .warning}
  >
  > The ETS table lives on the local node. A facilitator running more than
  > one instance behind a load balancer must supply a shared-store adapter
  > instead — a retried settlement routed to a different node would miss this
  > table and re-broadcast. See the adapter sketch in
  > `X402.Facilitator.PendingSettlementStore`.

  ## Usage

  Add the store to your supervision tree and pass it to the engine:

      children = [
        {X402.Facilitator.PendingSettlementStore.ETS, name: MyApp.PendingStore}
      ]

      {:ok, engine} =
        X402.Facilitator.Engine.new(
          rpc: rpc,
          signer: signer,
          networks: ["eip155:84532"],
          pending_settlement_store:
            {X402.Facilitator.PendingSettlementStore.ETS, MyApp.PendingStore}
        )
  """

  use GenServer

  @behaviour X402.Facilitator.PendingSettlementStore

  alias X402.Facilitator.PendingSettlementStore

  @default_name __MODULE__
  @default_ttl_ms :timer.minutes(5)
  @default_cleanup_interval_ms :timer.minutes(1)
  @default_max_size 10_000

  @start_link_options_schema [
    name: [
      type: :any,
      default: @default_name,
      doc: "Registered name for the store process."
    ],
    ttl_ms: [
      type: :non_neg_integer,
      default: @default_ttl_ms,
      doc: "Time-to-live for entries in milliseconds."
    ],
    cleanup_interval_ms: [
      type: :pos_integer,
      default: @default_cleanup_interval_ms,
      doc: "How often expired entries are cleaned up, in milliseconds."
    ],
    max_size: [
      type: :pos_integer,
      default: @default_max_size,
      doc: "Maximum number of entries in the store."
    ]
  ]

  @typedoc "Server identifier accepted by `GenServer.call/3`."
  @type server :: GenServer.server()

  @typedoc false
  @type state :: %{
          table: :ets.tid() | atom(),
          ttl_ms: non_neg_integer(),
          max_size: pos_integer(),
          cleanup_interval_ms: pos_integer(),
          cleanup_timer: reference()
        }

  @doc """
  Starts an ETS-backed pending-settlement store process.

  ## Options

  #{NimbleOptions.docs(@start_link_options_schema)}
  """
  @doc since: "0.6.0"
  @spec start_link(keyword()) ::
          GenServer.on_start() | {:error, NimbleOptions.ValidationError.t()}
  def start_link(opts \\ []) when is_list(opts) do
    with {:ok, validated_opts} <- NimbleOptions.validate(opts, @start_link_options_schema) do
      name = Keyword.fetch!(validated_opts, :name)
      GenServer.start_link(__MODULE__, validated_opts, name: name)
    end
  end

  @doc """
  Returns a child specification for `X402.Facilitator.PendingSettlementStore.ETS`.
  """
  @doc since: "0.6.0"
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts) when is_list(opts) do
    validated_opts = NimbleOptions.validate!(opts, @start_link_options_schema)

    %{
      id: Keyword.fetch!(validated_opts, :name),
      start: {__MODULE__, :start_link, [validated_opts]},
      type: :worker,
      restart: :permanent,
      shutdown: 5_000
    }
  end

  @doc since: "0.6.0"
  @doc """
  Looks up a pending settlement by key.
  """
  @impl PendingSettlementStore
  @spec get(server(), PendingSettlementStore.key()) :: PendingSettlementStore.get_result()
  def get(store, key) when is_binary(key) do
    if is_atom(store) do
      try do
        lookup(store, key, now_ms())
      rescue
        ArgumentError ->
          GenServer.call(store, {:get, key})
      end
    else
      GenServer.call(store, {:get, key})
    end
  end

  def get(_store, _key), do: {:error, :invalid_key}

  @doc since: "0.6.0"
  @doc """
  Stores a pending settlement entry, resetting its TTL.

  When the table is at `:max_size` and purging expired entries does not free
  a slot, returns `{:error, :store_full}` rather than evicting a live entry —
  evicting a live pending record would silently turn its retry into a second
  broadcast attempt. The engine treats a failed put as "could not persist for
  retry" and reports the settlement accordingly.
  """
  @impl PendingSettlementStore
  @spec put(server(), PendingSettlementStore.key(), PendingSettlementStore.entry()) ::
          PendingSettlementStore.write_result()
  def put(store, key, entry) when is_binary(key) do
    case valid_entry?(entry) do
      true -> GenServer.call(store, {:put, key, entry})
      false -> {:error, :invalid_entry}
    end
  end

  def put(_store, _key, _entry), do: {:error, :invalid_key}

  @doc since: "0.6.0"
  @doc """
  Deletes a pending settlement entry.
  """
  @impl PendingSettlementStore
  @spec delete(server(), PendingSettlementStore.key()) :: PendingSettlementStore.write_result()
  def delete(store, key) when is_binary(key) do
    GenServer.call(store, {:delete, key})
  end

  def delete(_store, _key), do: {:error, :invalid_key}

  @impl true
  @spec init(keyword()) :: {:ok, state()}
  def init(opts) do
    name = Keyword.get(opts, :name, __MODULE__)
    table_opts = [:set, :protected, read_concurrency: true]

    table =
      if is_atom(name) do
        :ets.new(name, [:named_table | table_opts])
      else
        :ets.new(__MODULE__, table_opts)
      end

    state = %{
      table: table,
      ttl_ms: Keyword.fetch!(opts, :ttl_ms),
      max_size: Keyword.fetch!(opts, :max_size),
      cleanup_interval_ms: Keyword.fetch!(opts, :cleanup_interval_ms),
      cleanup_timer: schedule_cleanup(Keyword.fetch!(opts, :cleanup_interval_ms))
    }

    {:ok, state}
  end

  @impl true
  @spec handle_call(term(), GenServer.from(), state()) :: {:reply, term(), state()}
  def handle_call({:get, key}, _from, state) do
    now = now_ms()

    reply =
      case :ets.lookup(state.table, key) do
        [{^key, entry, expires_at_ms}] when expires_at_ms > now ->
          {:hit, entry}

        [{^key, _entry, _expires_at_ms}] ->
          :ets.delete(state.table, key)
          :miss

        [] ->
          :miss
      end

    {:reply, reply, state}
  end

  def handle_call({:put, key, entry}, _from, state) do
    now = now_ms()

    if at_capacity?(state, key) do
      delete_expired_entries(state.table, now)
    end

    reply =
      case at_capacity?(state, key) do
        true ->
          {:error, :store_full}

        false ->
          true = :ets.insert(state.table, {key, entry, now + state.ttl_ms})
          :ok
      end

    {:reply, reply, state}
  end

  def handle_call({:delete, key}, _from, state) do
    true = :ets.delete(state.table, key)
    {:reply, :ok, state}
  end

  @impl true
  @spec handle_info(:cleanup, state()) :: {:noreply, state()}
  def handle_info(:cleanup, state) do
    delete_expired_entries(state.table, now_ms())

    {:noreply, %{state | cleanup_timer: schedule_cleanup(state.cleanup_interval_ms)}}
  end

  @spec lookup(atom(), PendingSettlementStore.key(), non_neg_integer()) ::
          {:hit, PendingSettlementStore.entry()} | :miss
  defp lookup(table, key, now) do
    case :ets.lookup(table, key) do
      [{^key, entry, expires_at_ms}] when expires_at_ms > now -> {:hit, entry}
      _absent_or_expired -> :miss
    end
  end

  @spec schedule_cleanup(pos_integer()) :: reference()
  defp schedule_cleanup(cleanup_interval_ms) do
    Process.send_after(self(), :cleanup, cleanup_interval_ms)
  end

  @spec at_capacity?(state(), term()) :: boolean()
  defp at_capacity?(state, key) do
    :ets.info(state.table, :size) >= state.max_size and
      not :ets.member(state.table, key)
  end

  @spec delete_expired_entries(:ets.tid() | atom(), non_neg_integer()) :: non_neg_integer()
  defp delete_expired_entries(table, now_ms) do
    :ets.select_delete(table, [{{:"$1", :"$2", :"$3"}, [{:"=<", :"$3", now_ms}], [true]}])
  end

  @spec now_ms() :: non_neg_integer()
  defp now_ms, do: System.monotonic_time(:millisecond)

  @spec valid_entry?(term()) :: boolean()
  defp valid_entry?(%{transaction: transaction, provenance: provenance, raw_transaction: raw})
       when is_binary(transaction) and provenance in [:node_acknowledged, :local_hash] and
              (is_binary(raw) or is_nil(raw)),
       do: true

  defp valid_entry?(_invalid), do: false
end
