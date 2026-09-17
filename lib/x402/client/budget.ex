defmodule X402.Client.Budget do
  @moduledoc """
  A session spend budget shared by payer clients.

  A budget tracks the atomic-unit total a client has committed to paying
  across requests, with a hard `:limit` and optional `:per_asset` limits.
  `X402.Client.Finch.request/3` and `X402.MCP.Client.call/3` take a
  `:budget` and reserve the selected amount before a payment leaves the
  process, so concurrent requests cannot collectively overspend.

  ## Accounting

  `reserve/3` atomically adds an amount to the spent total (and to the
  asset's total) and fails with `{:error, {:budget_exceeded, details}}`
  without changing anything when either limit would be exceeded. The
  drivers reserve after the payload is built and before the paid retry is
  sent, and `release/3` the reservation when the payment is not accepted:

  * a transport error on the paid retry,
  * an HTTP retry that answers with a non-2xx status and no successful
    `PAYMENT-RESPONSE` receipt,
  * an MCP retry that answers with another payment-required result and no
    successful `_meta["x402/payment-response"]` receipt.

  Everything else — a 2xx response, a tool result, or any response carrying
  a `success: true` settlement receipt — counts as spent, whether or not the
  facilitator actually settled: the budget is a safety cap on what the
  client has authorized, not a ledger of on-chain transfers.

  Amounts are atomic units: non-negative integers or integer strings, as in
  `PaymentRequirements.amount`. Assets are compared case-insensitively.

  ## Example

      {:ok, budget} = X402.Client.Budget.start_link(limit: "5000000", per_asset: %{usdc => "1000000"})

      X402.Client.Finch.request(MyApp.Finch, url, signer: signer, budget: budget)

      X402.Client.Budget.spent(budget)
      #=> %{total: 10000, per_asset: %{"0x036cbd53842c5426634e7929541ec2318f3dcf7e" => 10000}}
  """

  use GenServer

  @start_opts_schema [
    name: [
      type: :any,
      doc: "Optional `GenServer` name to register the budget under."
    ],
    limit: [
      type: {:custom, __MODULE__, :validate_amount, []},
      required: true,
      doc: "Total spend limit in atomic units (integer or integer string)."
    ],
    per_asset: [
      type: {:map, :string, {:custom, __MODULE__, :validate_amount, []}},
      default: %{},
      doc: "Per-asset spend limits in atomic units, keyed by asset identifier."
    ]
  ]

  @typedoc "A budget process reference."
  @type budget :: GenServer.server()

  @typedoc "An atomic-unit amount: a non-negative integer or integer string."
  @type amount :: non_neg_integer() | String.t()

  @typedoc "Why a reservation was refused."
  @type exceeded :: %{
          scope: :total | :asset,
          asset: String.t(),
          amount: non_neg_integer(),
          limit: non_neg_integer(),
          spent: non_neg_integer()
        }

  @type reserve_error :: {:budget_exceeded, exceeded()} | :invalid_amount

  @doc since: "0.8.0"
  @doc """
  Starts a budget process.

  ## Options

  #{NimbleOptions.docs(@start_opts_schema)}
  """
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(opts) when is_list(opts) do
    opts = NimbleOptions.validate!(opts, @start_opts_schema)

    case Keyword.fetch(opts, :name) do
      {:ok, name} -> GenServer.start_link(__MODULE__, opts, name: name)
      :error -> GenServer.start_link(__MODULE__, opts)
    end
  end

  @doc since: "0.8.0"
  @doc """
  Reserves `amount` of `asset` against the budget.

  Returns `{:error, {:budget_exceeded, details}}` — with `details.scope`
  telling whether the total or the asset limit was hit — and leaves the
  budget unchanged when the reservation does not fit.

  ## Examples

      iex> {:ok, budget} = X402.Client.Budget.start_link(limit: 100)
      iex> X402.Client.Budget.reserve(budget, "usdc", "60")
      :ok
      iex> X402.Client.Budget.reserve(budget, "usdc", 50)
      {:error, {:budget_exceeded, %{scope: :total, asset: "usdc", amount: 50, limit: 100, spent: 60}}}
      iex> X402.Client.Budget.reserve(budget, "usdc", "0.5")
      {:error, :invalid_amount}
  """
  @spec reserve(budget(), String.t(), amount()) :: :ok | {:error, reserve_error()}
  def reserve(budget, asset, amount) when is_binary(asset) do
    with {:ok, amount} <- parse_amount(amount) do
      GenServer.call(budget, {:reserve, asset, amount})
    end
  end

  @doc since: "0.8.0"
  @doc """
  Releases a previous reservation of `amount` of `asset`.

  Totals never go below zero.

  ## Examples

      iex> {:ok, budget} = X402.Client.Budget.start_link(limit: 100)
      iex> :ok = X402.Client.Budget.reserve(budget, "usdc", 60)
      iex> X402.Client.Budget.release(budget, "usdc", 60)
      :ok
      iex> X402.Client.Budget.spent(budget)
      %{total: 0, per_asset: %{"usdc" => 0}}
  """
  @spec release(budget(), String.t(), amount()) :: :ok | {:error, :invalid_amount}
  def release(budget, asset, amount) when is_binary(asset) do
    with {:ok, amount} <- parse_amount(amount) do
      GenServer.call(budget, {:release, asset, amount})
    end
  end

  @doc since: "0.8.0"
  @doc """
  Returns the amounts currently reserved or spent.

  Asset keys are lowercased.

  ## Examples

      iex> {:ok, budget} = X402.Client.Budget.start_link(limit: 100, per_asset: %{"USDC" => 80})
      iex> :ok = X402.Client.Budget.reserve(budget, "USDC", 30)
      iex> X402.Client.Budget.spent(budget)
      %{total: 30, per_asset: %{"usdc" => 30}}
  """
  @spec spent(budget()) :: %{
          total: non_neg_integer(),
          per_asset: %{String.t() => non_neg_integer()}
        }
  def spent(budget), do: GenServer.call(budget, :spent)

  @doc false
  @spec validate_amount(term()) :: {:ok, non_neg_integer()} | {:error, String.t()}
  def validate_amount(value) do
    case parse_amount(value) do
      {:ok, amount} -> {:ok, amount}
      {:error, :invalid_amount} -> {:error, "expected a non-negative integer or integer string"}
    end
  end

  @doc false
  @spec validate_ref(term()) :: {:ok, budget()} | {:error, String.t()}
  def validate_ref(ref) when is_pid(ref) or (is_atom(ref) and not is_nil(ref)), do: {:ok, ref}
  def validate_ref({:global, _name} = ref), do: {:ok, ref}
  def validate_ref({:via, module, _name} = ref) when is_atom(module), do: {:ok, ref}
  def validate_ref(_ref), do: {:error, "expected a budget pid or registered name"}

  @spec parse_amount(term()) :: {:ok, non_neg_integer()} | {:error, :invalid_amount}
  defp parse_amount(amount) when is_integer(amount) and amount >= 0, do: {:ok, amount}

  defp parse_amount(amount) when is_binary(amount) do
    case Integer.parse(amount) do
      {value, ""} when value >= 0 -> {:ok, value}
      _other -> {:error, :invalid_amount}
    end
  end

  defp parse_amount(_amount), do: {:error, :invalid_amount}

  # -- GenServer --------------------------------------------------------------

  @impl GenServer
  def init(opts) do
    per_asset =
      opts
      |> Keyword.fetch!(:per_asset)
      |> Map.new(fn {asset, limit} -> {String.downcase(asset), limit} end)

    {:ok, %{limit: Keyword.fetch!(opts, :limit), per_asset: per_asset, spent: 0, spent_by: %{}}}
  end

  @impl GenServer
  def handle_call({:reserve, asset, amount}, _from, state) do
    key = String.downcase(asset)
    asset_spent = Map.get(state.spent_by, key, 0)

    cond do
      state.spent + amount > state.limit ->
        details = exceeded(:total, asset, amount, state.limit, state.spent)
        {:reply, {:error, {:budget_exceeded, details}}, state}

      Map.has_key?(state.per_asset, key) and asset_spent + amount > state.per_asset[key] ->
        details = exceeded(:asset, asset, amount, state.per_asset[key], asset_spent)
        {:reply, {:error, {:budget_exceeded, details}}, state}

      true ->
        state = %{
          state
          | spent: state.spent + amount,
            spent_by: Map.put(state.spent_by, key, asset_spent + amount)
        }

        {:reply, :ok, state}
    end
  end

  def handle_call({:release, asset, amount}, _from, state) do
    key = String.downcase(asset)
    asset_spent = Map.get(state.spent_by, key, 0)

    state = %{
      state
      | spent: max(state.spent - amount, 0),
        spent_by: Map.put(state.spent_by, key, max(asset_spent - amount, 0))
    }

    {:reply, :ok, state}
  end

  def handle_call(:spent, _from, state) do
    {:reply, %{total: state.spent, per_asset: state.spent_by}, state}
  end

  @spec exceeded(
          :total | :asset,
          String.t(),
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer()
        ) ::
          exceeded()
  defp exceeded(scope, asset, amount, limit, spent),
    do: %{scope: scope, asset: asset, amount: amount, limit: limit, spent: spent}
end
