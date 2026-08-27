defmodule X402.Facilitator.NonceManager do
  @moduledoc """
  Serializes fee-payer transaction nonces for concurrent settlements.

  `X402.Facilitator.Engine.settle/3` broadcasts an EIP-1559 transaction from
  the facilitator's fee-payer account. Reading `eth_getTransactionCount`
  per settlement races under concurrency: two settles can read the same
  pending nonce, sign two different payments with it, and the node rejects
  one even though its EIP-3009 authorization was never used.

  This process assigns nonces instead: the first checkout for an address
  runs the caller-supplied fetch (one RPC), and subsequent checkouts
  increment locally — so concurrent settlements always receive distinct,
  consecutive nonces. After a broadcast failure that may have been
  nonce-related, the engine calls `reset/2` and the next checkout
  re-fetches from the node.

  Start one manager per fee payer (or share one across fee payers — state
  is keyed by address) and pass it to `X402.Facilitator.Engine.new/1` via
  `:nonce_manager`:

      children = [
        {X402.Facilitator.NonceManager, name: MyApp.NonceManager},
        ...
      ]

      X402.Facilitator.Engine.new(
        rpc: rpc,
        signer: signer,
        networks: ["eip155:84532"],
        nonce_manager: MyApp.NonceManager
      )

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
  Checks out the next nonce for `address`.

  Runs `fetch_fun` (inside the manager — rare: first use per address and
  after `reset/2`) when no nonce is tracked; otherwise increments the
  tracked value. A fetch error is returned as-is and nothing is stored.
  """
  @spec checkout(server(), String.t(), fetch_fun()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def checkout(server, address, fetch_fun)
      when is_binary(address) and is_function(fetch_fun, 0) do
    GenServer.call(server, {:checkout, normalize(address), fetch_fun}, 30_000)
  end

  @doc since: "0.6.0"
  @doc """
  Forgets the tracked nonce for `address`.

  Call after a broadcast failure that may have been nonce-related; the next
  `checkout/3` re-fetches from the node.
  """
  @spec reset(server(), String.t()) :: :ok
  def reset(server, address) when is_binary(address) do
    GenServer.call(server, {:reset, normalize(address)})
  end

  @impl true
  @spec init(:ok) :: {:ok, %{optional(String.t()) => non_neg_integer()}}
  def init(:ok), do: {:ok, %{}}

  @impl true
  def handle_call({:checkout, address, fetch_fun}, _from, state) do
    case Map.fetch(state, address) do
      {:ok, next} ->
        {:reply, {:ok, next}, Map.put(state, address, next + 1)}

      :error ->
        case fetch_fun.() do
          {:ok, nonce} when is_integer(nonce) and nonce >= 0 ->
            {:reply, {:ok, nonce}, Map.put(state, address, nonce + 1)}

          {:ok, other} ->
            {:reply, {:error, {:invalid_nonce, other}}, state}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end
    end
  end

  def handle_call({:reset, address}, _from, state) do
    {:reply, :ok, Map.delete(state, address)}
  end

  @spec normalize(String.t()) :: String.t()
  defp normalize(address), do: String.downcase(address)
end
