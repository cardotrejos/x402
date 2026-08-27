defmodule X402.Facilitator.NonceManager do
  @moduledoc """
  Serializes fee-payer transaction nonces for concurrent settlements.

  `X402.Facilitator.Engine.settle/3` broadcasts an EIP-1559 transaction from
  the facilitator's fee-payer account. Reading `eth_getTransactionCount`
  per settlement races under concurrency: two settles can read the same
  pending nonce, sign two different payments with it, and the node rejects
  one even though its EIP-3009 authorization was never used.

  This process assigns nonces instead, tracking the full lifecycle:

    * `checkout/3` — assigns the next nonce (fetching from the node only on
      first use per address) and marks it in flight.
    * `complete/3` — the transaction reached the node; the nonce is consumed.
    * `release/3` — the settlement failed before the node could have seen
      the transaction. The tail nonce is rolled back so no gap forms; a
      released middle nonce marks the address for a re-fetch once every
      in-flight settlement drains, since a gap would stall later
      transactions at the node.
    * `reset/2` — forget the address (re-fetch on next checkout). With
      settlements still in flight, the reset is deferred until they drain,
      so an in-flight nonce is never reissued.

  Start one manager (state is keyed by address) and pass it to
  `X402.Facilitator.Engine.new/1` via `:nonce_manager`:

      children = [
        {X402.Facilitator.NonceManager, name: MyApp.NonceManager},
        ...
      ]

  > #### Per-node only {: .warning}
  >
  > Nonce tracking lives on the local node. Running the same fee-payer key
  > on several facilitator nodes still races at the chain level — use one
  > fee payer per node, or coordinate externally.
  """

  use GenServer

  @typedoc "Server identifier accepted by `GenServer.call/3`."
  @type server :: GenServer.server()

  @typedoc "A function fetching the current pending nonce from the node."
  @type fetch_fun :: (-> {:ok, non_neg_integer()} | {:error, term()})

  @typedoc false
  @type entry :: %{
          next: non_neg_integer(),
          in_flight: MapSet.t(non_neg_integer()),
          refetch_when_idle: boolean()
        }

  @doc since: "0.6.0"
  @doc """
  Starts a nonce manager.

  ## Options

    * `:name` — optional registered name.
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts \\ []) when is_list(opts) do
    case Keyword.fetch(opts, :name) do
      {:ok, name} -> GenServer.start_link(__MODULE__, :ok, name: name)
      :error -> GenServer.start_link(__MODULE__, :ok)
    end
  end

  @doc since: "0.6.0"
  @doc """
  Checks out the next nonce for `address` and marks it in flight.

  Runs `fetch_fun` (inside the manager — first use per address and after a
  drain-triggered re-fetch) when no nonce is tracked. A fetch error — or a
  raise, which is caught — is returned as an error and nothing is stored.
  """
  @spec checkout(server(), String.t(), fetch_fun()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def checkout(server, address, fetch_fun)
      when is_binary(address) and is_function(fetch_fun, 0) do
    GenServer.call(server, {:checkout, normalize(address), fetch_fun}, 30_000)
  end

  @doc since: "0.6.0"
  @doc """
  Marks `nonce` as consumed: its transaction reached (or may have reached)
  the node.
  """
  @spec complete(server(), String.t(), non_neg_integer()) :: :ok
  def complete(server, address, nonce) when is_binary(address) and is_integer(nonce) do
    GenServer.call(server, {:complete, normalize(address), nonce})
  end

  @doc since: "0.6.0"
  @doc """
  Returns `nonce` unused: its settlement failed before the node could have
  seen the transaction.

  The tail nonce rolls straight back; releasing a middle nonce (later
  checkouts still in flight) marks the address for a node re-fetch once the
  in-flight settlements drain, because the resulting gap would stall later
  transactions.
  """
  @spec release(server(), String.t(), non_neg_integer()) :: :ok
  def release(server, address, nonce) when is_binary(address) and is_integer(nonce) do
    GenServer.call(server, {:release, normalize(address), nonce})
  end

  @doc since: "0.6.0"
  @doc """
  Forgets the tracked nonce state for `address`.

  With settlements still in flight, the reset is deferred until they drain
  so an in-flight nonce is never reissued.
  """
  @spec reset(server(), String.t()) :: :ok
  def reset(server, address) when is_binary(address) do
    GenServer.call(server, {:reset, normalize(address)})
  end

  @impl true
  @spec init(:ok) :: {:ok, %{optional(String.t()) => entry()}}
  def init(:ok), do: {:ok, %{}}

  @impl true
  def handle_call({:checkout, address, fetch_fun}, _from, state) do
    case Map.fetch(state, address) do
      {:ok, entry} ->
        {nonce, entry} = assign(entry)
        {:reply, {:ok, nonce}, Map.put(state, address, entry)}

      :error ->
        case safe_fetch(fetch_fun) do
          {:ok, nonce} ->
            entry = %{next: nonce + 1, in_flight: MapSet.new([nonce]), refetch_when_idle: false}
            {:reply, {:ok, nonce}, Map.put(state, address, entry)}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  def handle_call({:complete, address, nonce}, _from, state) do
    {:reply, :ok, update_entry(state, address, &settle_in_flight(&1, nonce, :complete))}
  end

  def handle_call({:release, address, nonce}, _from, state) do
    {:reply, :ok, update_entry(state, address, &settle_in_flight(&1, nonce, :release))}
  end

  def handle_call({:reset, address}, _from, state) do
    {:reply, :ok,
     update_entry(state, address, fn entry -> %{entry | refetch_when_idle: true} end)}
  end

  @spec assign(entry()) :: {non_neg_integer(), entry()}
  defp assign(%{next: next} = entry) do
    {next, %{entry | next: next + 1, in_flight: MapSet.put(entry.in_flight, next)}}
  end

  @spec settle_in_flight(entry(), non_neg_integer(), :complete | :release) :: entry() | :drop
  defp settle_in_flight(entry, nonce, action) do
    entry = %{entry | in_flight: MapSet.delete(entry.in_flight, nonce)}

    entry =
      case action do
        :complete ->
          entry

        :release when nonce == entry.next - 1 ->
          # Tail rollback: the highest assigned nonce came back unused, so
          # the next checkout can take it again without leaving a gap.
          %{entry | next: nonce}

        :release ->
          # A middle nonce came back unused while later checkouts are in
          # flight — a gap would stall the node. Re-fetch once drained.
          %{entry | refetch_when_idle: true}
      end

    case MapSet.size(entry.in_flight) == 0 and entry.refetch_when_idle do
      true -> :drop
      false -> entry
    end
  end

  @spec update_entry(map(), String.t(), (entry() -> entry() | :drop)) :: map()
  defp update_entry(state, address, fun) do
    case Map.fetch(state, address) do
      :error -> state
      {:ok, entry} -> store_entry(state, address, fun.(entry))
    end
  end

  @spec store_entry(map(), String.t(), entry() | :drop) :: map()
  defp store_entry(state, address, :drop), do: Map.delete(state, address)

  defp store_entry(state, address, %{in_flight: in_flight, refetch_when_idle: true} = entry) do
    case MapSet.size(in_flight) do
      0 -> Map.delete(state, address)
      _positive -> Map.put(state, address, entry)
    end
  end

  defp store_entry(state, address, entry), do: Map.put(state, address, entry)

  @spec safe_fetch(fetch_fun()) :: {:ok, non_neg_integer()} | {:error, term()}
  defp safe_fetch(fetch_fun) do
    case fetch_fun.() do
      {:ok, nonce} when is_integer(nonce) and nonce >= 0 -> {:ok, nonce}
      {:ok, other} -> {:error, {:invalid_nonce, other}}
      {:error, reason} -> {:error, reason}
      other -> {:error, {:invalid_nonce, other}}
    end
  rescue
    exception -> {:error, {:nonce_fetch_failed, exception}}
  end

  @spec normalize(String.t()) :: String.t()
  defp normalize(address), do: String.downcase(address)
end
