defmodule X402.Facilitator do
  @moduledoc """
  Stateful client for x402 facilitator verify and settle operations.
  """

  use GenServer

  alias X402.Facilitator.Error
  alias X402.Facilitator.HTTP

  @default_name __MODULE__
  @default_url "https://x402.org/facilitator"

  @start_link_options_schema [
    name: [
      type: :any,
      default: @default_name,
      doc: "Registered name of the facilitator client process."
    ],
    url: [
      type: :string,
      default: @default_url,
      doc: "Facilitator base URL."
    ],
    finch: [
      type: :any,
      required: true,
      doc: "Finch process name used for HTTP requests."
    ],
    max_retries: [
      type: :non_neg_integer,
      default: 2,
      doc: "Maximum retry count for transient errors."
    ],
    retry_backoff_ms: [
      type: :non_neg_integer,
      default: 100,
      doc: "Initial retry backoff in milliseconds."
    ],
    receive_timeout_ms: [
      type: :non_neg_integer,
      default: 5_000,
      doc: "HTTP receive timeout in milliseconds."
    ]
  ]

  @typedoc "Facilitator server identifier accepted by `GenServer.call/3`."
  @type server :: GenServer.server()

  @type response :: {:ok, %{status: non_neg_integer(), body: map()}} | {:error, Error.t()}

  @type state :: %{
          url: String.t(),
          finch: term(),
          max_retries: non_neg_integer(),
          retry_backoff_ms: non_neg_integer(),
          receive_timeout_ms: non_neg_integer()
        }

  @doc """
  Starts the facilitator client.

  ## Options

  #{NimbleOptions.docs(@start_link_options_schema)}
  """
  @doc since: "0.1.0"
  @spec start_link(keyword()) ::
          GenServer.on_start() | {:error, NimbleOptions.ValidationError.t()}
  def start_link(opts) when is_list(opts) do
    with {:ok, validated_opts} <- NimbleOptions.validate(opts, @start_link_options_schema) do
      name = Keyword.fetch!(validated_opts, :name)
      GenServer.start_link(__MODULE__, validated_opts, name: name)
    end
  end

  @doc """
  Returns a child specification for `X402.Facilitator`.
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

  @doc """
  Verifies a payment using the default facilitator process name.
  """
  @doc group: :verification
  @doc since: "0.1.0"
  @spec verify(map(), map()) :: response()
  def verify(payment_payload, requirements)
      when is_map(payment_payload) and is_map(requirements) do
    verify(@default_name, payment_payload, requirements)
  end

  @doc """
  Verifies a payment using the given facilitator process.
  """
  @doc group: :verification
  @doc since: "0.1.0"
  @spec verify(server(), map(), map()) :: response()
  def verify(server, payment_payload, requirements)
      when is_map(payment_payload) and is_map(requirements) do
    GenServer.call(server, {:verify, payment_payload, requirements})
  end

  @doc """
  Settles a payment using the default facilitator process name.
  """
  @doc group: :verification
  @doc since: "0.1.0"
  @spec settle(map(), map()) :: response()
  def settle(payment_payload, requirements)
      when is_map(payment_payload) and is_map(requirements) do
    settle(@default_name, payment_payload, requirements)
  end

  @doc """
  Settles a payment using the given facilitator process.
  """
  @doc group: :verification
  @doc since: "0.1.0"
  @spec settle(server(), map(), map()) :: response()
  def settle(server, payment_payload, requirements)
      when is_map(payment_payload) and is_map(requirements) do
    GenServer.call(server, {:settle, payment_payload, requirements})
  end

  @impl true
  @spec init(keyword()) :: {:ok, state()}
  def init(opts) do
    state = %{
      url: Keyword.fetch!(opts, :url),
      finch: Keyword.fetch!(opts, :finch),
      max_retries: Keyword.fetch!(opts, :max_retries),
      retry_backoff_ms: Keyword.fetch!(opts, :retry_backoff_ms),
      receive_timeout_ms: Keyword.fetch!(opts, :receive_timeout_ms)
    }

    {:ok, state}
  end

  @impl true
  @spec handle_call(term(), GenServer.from(), state()) :: {:reply, response(), state()}
  def handle_call({:verify, payment_payload, requirements}, _from, state) do
    response = request_with_telemetry(state, :verify, payment_payload, requirements)
    {:reply, response, state}
  end

  def handle_call({:settle, payment_payload, requirements}, _from, state) do
    response = request_with_telemetry(state, :settle, payment_payload, requirements)
    {:reply, response, state}
  end

  defp request_with_telemetry(state, operation, payment_payload, requirements) do
    endpoint = operation_endpoint(operation)

    :telemetry.span(
      [:x402, :facilitator, operation],
      %{operation: operation, endpoint: endpoint},
      fn ->
        result =
          HTTP.request(
            state.finch,
            state.url,
            endpoint,
            %{payload: payment_payload, requirements: requirements},
            max_retries: state.max_retries,
            retry_backoff_ms: state.retry_backoff_ms,
            receive_timeout_ms: state.receive_timeout_ms
          )

        {result, telemetry_result_metadata(result)}
      end
    )
  end

  defp operation_endpoint(:verify), do: "/verify"
  defp operation_endpoint(:settle), do: "/settle"

  defp telemetry_result_metadata({:ok, %{status: status}}),
    do: %{status: status, success: true}

  defp telemetry_result_metadata({:error, %Error{} = error}) do
    %{
      status: error.status,
      success: false,
      error_type: error.type,
      retryable: error.retryable,
      attempt: error.attempt
    }
  end
end
