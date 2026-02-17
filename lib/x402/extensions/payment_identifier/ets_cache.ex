defmodule X402.Extensions.PaymentIdentifier.ETSCache do
  @moduledoc """
  ETS-backed cache adapter for payment identifier idempotency.

  Entries expire after `:ttl_ms` (default: 1 hour). Expired entries are removed
  by an internal periodic cleanup loop.
  """

  use GenServer

  @behaviour X402.Extensions.PaymentIdentifier.Cache

  alias X402.Extensions.PaymentIdentifier.Cache

  @default_name __MODULE__
  @default_ttl_ms :timer.hours(1)
  @default_cleanup_interval_ms :timer.minutes(1)

  @start_link_options_schema [
    name: [
      type: :any,
      default: @default_name,
      doc: "Registered name for the ETS cache process."
    ],
    ttl_ms: [
      type: :pos_integer,
      default: @default_ttl_ms,
      doc: "Time-to-live for entries in milliseconds."
    ],
    cleanup_interval_ms: [
      type: :pos_integer,
      default: @default_cleanup_interval_ms,
      doc: "How often expired entries are cleaned up, in milliseconds."
    ]
  ]

  @typedoc "Server identifier accepted by `GenServer.call/3`."
  @type server :: GenServer.server()

  @typedoc false
  @type state :: %{
          table: :ets.tid(),
          ttl_ms: non_neg_integer(),
          cleanup_interval_ms: pos_integer(),
          cleanup_timer: reference()
        }

  @doc """
  Starts an ETS-backed idempotency cache process.

  ## Options

  #{NimbleOptions.docs(@start_link_options_schema)}
  """
  @doc since: "0.1.0"
  @spec start_link(keyword()) ::
          GenServer.on_start() | {:error, NimbleOptions.ValidationError.t()}
  def start_link(opts \\ []) when is_list(opts) do
    with {:ok, validated_opts} <- NimbleOptions.validate(opts, @start_link_options_schema) do
      name = Keyword.fetch!(validated_opts, :name)
      GenServer.start_link(__MODULE__, validated_opts, name: name)
    end
  end

  @doc """
  Returns a child specification for `X402.Extensions.PaymentIdentifier.ETSCache`.
  """
  @doc since: "0.1.0"
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

  @doc since: "0.1.0"
  @doc """
  Looks up a payment identifier in the cache.
  """
  @impl Cache
  @spec get(server(), Cache.key()) :: Cache.get_result()
  def get(cache, payment_id) when is_binary(payment_id) do
    GenServer.call(cache, {:get, payment_id})
  end

  def get(_cache, _payment_id), do: {:error, :invalid_payment_id}

  @doc since: "0.1.0"
  @doc """
  Stores a payment identifier result in the cache.
  """
  @impl Cache
  @spec put(server(), Cache.key(), Cache.value()) :: Cache.write_result()
  def put(cache, payment_id, value) when is_binary(payment_id) do
    case valid_value?(value) do
      true -> GenServer.call(cache, {:put, payment_id, value})
      false -> {:error, :invalid_cache_value}
    end
  end

  def put(_cache, _payment_id, _value), do: {:error, :invalid_payment_id}

  @doc since: "0.1.0"
  @doc """
  Deletes a payment identifier entry from the cache.
  """
  @impl Cache
  @spec delete(server(), Cache.key()) :: Cache.write_result()
  def delete(cache, payment_id) when is_binary(payment_id) do
    GenServer.call(cache, {:delete, payment_id})
  end

  def delete(_cache, _payment_id), do: {:error, :invalid_payment_id}

  @impl true
  @spec init(keyword()) :: {:ok, state()}
  def init(opts) do
    ttl_ms = Keyword.fetch!(opts, :ttl_ms)
    cleanup_interval_ms = Keyword.fetch!(opts, :cleanup_interval_ms)
    table = :ets.new(__MODULE__, [:set, :private])

    state = %{
      table: table,
      ttl_ms: ttl_ms,
      cleanup_interval_ms: cleanup_interval_ms,
      cleanup_timer: schedule_cleanup(cleanup_interval_ms)
    }

    {:ok, state}
  end

  @impl true
  @spec handle_call(term(), GenServer.from(), state()) :: {:reply, term(), state()}
  def handle_call({:get, payment_id}, _from, state) do
    now_ms = now_ms()

    reply =
      case :ets.lookup(state.table, payment_id) do
        [{^payment_id, value, expires_at_ms}] when expires_at_ms > now_ms ->
          {:hit, value}

        [{^payment_id, _value, _expires_at_ms}] ->
          :ets.delete(state.table, payment_id)
          :miss

        [] ->
          :miss
      end

    {:reply, reply, state}
  end

  def handle_call({:put, payment_id, value}, _from, state) do
    expires_at_ms = now_ms() + state.ttl_ms
    true = :ets.insert(state.table, {payment_id, value, expires_at_ms})
    {:reply, :ok, state}
  end

  def handle_call({:delete, payment_id}, _from, state) do
    true = :ets.delete(state.table, payment_id)
    {:reply, :ok, state}
  end

  @impl true
  @spec handle_info(:cleanup, state()) :: {:noreply, state()}
  def handle_info(:cleanup, state) do
    delete_expired_entries(state.table, now_ms())

    next_state = %{state | cleanup_timer: schedule_cleanup(state.cleanup_interval_ms)}
    {:noreply, next_state}
  end

  @spec schedule_cleanup(pos_integer()) :: reference()
  defp schedule_cleanup(cleanup_interval_ms) do
    Process.send_after(self(), :cleanup, cleanup_interval_ms)
  end

  @spec delete_expired_entries(:ets.tid(), non_neg_integer()) :: non_neg_integer()
  defp delete_expired_entries(table, now_ms) do
    :ets.select_delete(table, [{{:"$1", :"$2", :"$3"}, [{:"=<", :"$3", now_ms}], [true]}])
  end

  @spec now_ms() :: non_neg_integer()
  defp now_ms, do: System.monotonic_time(:millisecond)

  @spec valid_value?(term()) :: boolean()
  defp valid_value?(:verified), do: true
  defp valid_value?({:rejected, _reason}), do: true
  defp valid_value?(_invalid), do: false
end
