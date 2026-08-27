defmodule X402.Facilitator do
  @moduledoc """
  Client for the x402 facilitator API: verify, settle, supported, discovery.

  The facilitator process is a supervised configuration holder: it resolves
  and stores connection settings (URL, Finch pool, hooks, retry policy, auth
  state) once at startup. The HTTP work for `verify/2`, `settle/2`,
  `supported/1`, and `list_resources/2` — including retries with backoff,
  lifecycle hooks, telemetry spans, and per-request auth header minting —
  executes in the **calling process**. Concurrent payment operations
  therefore never serialize behind the facilitator process; throughput is
  bounded only by the Finch pool.

  Because operations run in the caller, `X402.Hooks` callbacks are invoked in
  the calling process (not in the facilitator process), and the duration of an
  operation is bounded by the configured `:receive_timeout_ms` and retry
  policy rather than by a `GenServer.call/3` timeout.
  """

  use GenServer

  require Logger

  alias X402.Facilitator.Auth
  alias X402.Facilitator.Error
  alias X402.Facilitator.HTTP
  alias X402.Hooks
  alias X402.Hooks.Context
  alias X402.Hooks.Default
  alias X402.Utils

  @default_name __MODULE__
  @default_url "https://x402.org/facilitator"

  @start_link_options_schema [
    name: [
      type: :any,
      default: @default_name,
      doc: "Registered name of the facilitator client process."
    ],
    otp_app: [
      type: :atom,
      doc:
        "Application that holds this facilitator's configuration. When set, " <>
          "`config :app, <name>` is merged under the given options, with the " <>
          "options taking precedence. Enables the Ecto-style pattern where " <>
          "`config/runtime.exs` is the single source of truth. Available since v0.5.0."
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
    hooks: [
      type: {:custom, Hooks, :validate_module, []},
      default: Default,
      doc: "Lifecycle hook module implementing `X402.Hooks`."
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
    ],
    auth: [
      type: {:custom, __MODULE__, :validate_auth, []},
      default: nil,
      doc:
        "Request authentication. Either `nil` (no authentication), an " <>
          "`X402.Facilitator.Auth` module, or a `{module, opts}` tuple. See " <>
          "`X402.Facilitator.Auth.CDP` for the Coinbase Developer Platform " <>
          "facilitator. Available since v0.5.0."
    ]
  ]

  @typedoc "Facilitator server identifier accepted by `GenServer.call/3`."
  @type server :: GenServer.server()

  @typedoc "Facilitator response payload, including values recovered or transformed by hooks."
  @type operation_result :: map()

  @type response :: {:ok, operation_result()} | {:error, Error.t() | Hooks.hook_error() | term()}

  @typedoc "One supported payment kind advertised by `GET /supported`."
  @type supported_kind :: %{
          x402_version: integer(),
          scheme: String.t(),
          network: String.t(),
          extra: map() | nil
        }

  @typedoc "Validated response of `supported/1`."
  @type supported_response :: %{
          kinds: [supported_kind()],
          extensions: [String.t()],
          signers: %{optional(String.t()) => [String.t()]}
        }

  @typedoc "Pagination metadata returned by `GET /discovery/resources`."
  @type discovery_pagination :: %{
          limit: non_neg_integer(),
          offset: non_neg_integer(),
          total: non_neg_integer()
        }

  @typedoc """
  Validated response of `list_resources/2`.

  Each item is the raw, string-keyed discovered-resource map from the wire.
  """
  @type discovery_resources_response :: %{
          x402_version: integer() | nil,
          items: [map()],
          pagination: discovery_pagination() | nil
        }

  @type state :: %{
          url: String.t(),
          finch: term(),
          hooks: module(),
          auth: nil | Auth.t(),
          max_retries: non_neg_integer(),
          retry_backoff_ms: non_neg_integer(),
          receive_timeout_ms: non_neg_integer()
        }

  @doc """
  Starts the facilitator client.

  When an `otp_app` is given, options are merged over the `config :app, <name>`
  configuration entry, with the explicit options taking precedence. This
  enables configuring the facilitator at runtime without hardcoding secrets:

      # config/runtime.exs
      config :my_app, MyX402,
        url: X402.Facilitator.Auth.CDP.facilitator_url(),
        finch: MyFinch,
        auth: {X402.Facilitator.Auth.CDP,
               api_key_id: System.fetch_env!("CDP_API_KEY_ID"),
               api_key_secret: System.fetch_env!("CDP_API_KEY_SECRET")}

      # application.ex
      children = [{X402.Facilitator, otp_app: :my_app, name: MyX402}]

  ## Options

  #{NimbleOptions.docs(@start_link_options_schema)}
  """
  @doc since: "0.1.0"
  @spec start_link(keyword()) ::
          GenServer.on_start() | {:error, NimbleOptions.ValidationError.t()}
  def start_link(opts) when is_list(opts) do
    with {:ok, validated_opts} <- validated_opts(opts),
         {:ok, auth} <- Auth.new(Keyword.get(validated_opts, :auth)) do
      name = Keyword.fetch!(validated_opts, :name)
      GenServer.start_link(__MODULE__, Keyword.put(validated_opts, :auth, auth), name: name)
    else
      {:error, %NimbleOptions.ValidationError{} = error} -> {:error, error}
      {:error, reason} -> {:error, {:invalid_auth, reason}}
    end
  end

  @doc """
  Returns a child specification for `X402.Facilitator`.
  """
  @doc since: "0.1.0"
  @spec child_spec(keyword()) :: Supervisor.child_spec()
  def child_spec(opts) when is_list(opts) do
    validated_opts = validated_opts!(opts)

    %{
      id: Keyword.fetch!(validated_opts, :name),
      start: {__MODULE__, :start_link, [validated_opts]},
      type: :worker,
      restart: :permanent,
      shutdown: 5_000
    }
  end

  defp validated_opts(opts) do
    opts
    |> merge_config()
    |> NimbleOptions.validate(@start_link_options_schema)
  end

  defp validated_opts!(opts) do
    opts
    |> merge_config()
    |> NimbleOptions.validate!(@start_link_options_schema)
  end

  defp merge_config(opts) do
    case Keyword.fetch(opts, :otp_app) do
      :error ->
        opts

      {:ok, app} ->
        name = Keyword.get(opts, :name, @default_name)
        Keyword.merge(Application.get_env(app, name, []), opts)
    end
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

  The HTTP request (including retries, hooks, and telemetry) executes in the
  calling process; the facilitator process is only consulted for its
  configuration.
  """
  @doc group: :verification
  @doc since: "0.1.0"
  @spec verify(server(), map(), map()) :: response()
  def verify(server, payment_payload, requirements)
      when is_map(payment_payload) and is_map(requirements) do
    config = fetch_config(server)
    request_with_telemetry(config, :verify, payment_payload, requirements, config.hooks)
  end

  @doc """
  Verifies a payment using the given facilitator process and hook module.

  This overrides the hook module configured when the facilitator process
  started. Hook callbacks run in the calling process.
  """
  @doc group: :verification
  @doc since: "0.1.0"
  @spec verify(server(), map(), map(), module()) :: response()
  def verify(server, payment_payload, requirements, hooks_module)
      when is_map(payment_payload) and is_map(requirements) and is_atom(hooks_module) do
    config = fetch_config(server)
    request_with_telemetry(config, :verify, payment_payload, requirements, hooks_module)
  end

  @doc """
  Settles a payment using the default facilitator process name.
  """
  @doc group: :settlement
  @doc since: "0.1.0"
  @spec settle(map(), map()) :: response()
  def settle(payment_payload, requirements)
      when is_map(payment_payload) and is_map(requirements) do
    settle(@default_name, payment_payload, requirements)
  end

  @doc """
  Settles a payment using the given facilitator process.

  The HTTP request (including retries, hooks, and telemetry) executes in the
  calling process; the facilitator process is only consulted for its
  configuration.
  """
  @doc group: :settlement
  @doc since: "0.1.0"
  @spec settle(server(), map(), map()) :: response()
  def settle(server, payment_payload, requirements)
      when is_map(payment_payload) and is_map(requirements) do
    config = fetch_config(server)
    request_with_telemetry(config, :settle, payment_payload, requirements, config.hooks)
  end

  @doc """
  Settles a payment using the given facilitator process and hook module.

  This overrides the hook module configured when the facilitator process
  started. Hook callbacks run in the calling process.
  """
  @doc group: :settlement
  @doc since: "0.1.0"
  @spec settle(server(), map(), map(), module()) :: response()
  def settle(server, payment_payload, requirements, hooks_module)
      when is_map(payment_payload) and is_map(requirements) and is_atom(hooks_module) do
    config = fetch_config(server)
    request_with_telemetry(config, :settle, payment_payload, requirements, hooks_module)
  end

  @list_resources_params_schema [
    type: [
      type: :string,
      doc: "Filter by resource type (for example `\"http\"` or `\"mcp\"`)."
    ],
    pay_to: [
      type: :string,
      doc: "Filter by payment recipient address (sent as `payTo`)."
    ],
    scheme: [
      type: :string,
      doc: "Filter by payment scheme (for example `\"exact\"`)."
    ],
    network: [
      type: :string,
      doc: "Filter by CAIP-2 payment network (for example `\"eip155:8453\"`)."
    ],
    extensions: [
      type: :string,
      doc: "Filter by extension key present on each discovered resource."
    ],
    limit: [
      type: {:in, 1..100},
      doc: "Maximum number of results to return (1–100; server default 20)."
    ],
    offset: [
      type: :non_neg_integer,
      doc: "Number of results to skip for pagination."
    ]
  ]

  @doc """
  Fetches the payment kinds, extensions, and signers a facilitator supports.

  Performs `GET /supported` in the calling process and validates the response
  fail-closed: a malformed body returns
  `{:error, %X402.Facilitator.Error{type: :malformed_facilitator_response}}`
  rather than partial data. Missing `extensions` and `signers` fields default
  to `[]` and `%{}` (matching the reference TypeScript client); a missing or
  malformed `kinds` field is an error.

  `X402.Hooks` callbacks do not apply to this read-only operation.

  ## Examples

      {:ok, %{kinds: kinds, extensions: _, signers: signers}} =
        X402.Facilitator.supported(MyFacilitator)

      Enum.any?(kinds, &(&1.scheme == "exact" and &1.network == "eip155:8453"))
  """
  @doc group: :discovery
  @doc since: "0.6.0"
  @spec supported(server()) :: {:ok, supported_response()} | {:error, Error.t()}
  def supported(server \\ @default_name) do
    config = fetch_config(server)
    get_with_telemetry(config, :supported, "/supported", [], &parse_supported/1)
  end

  @doc """
  Lists discoverable x402 resources from the facilitator's bazaar.

  Performs `GET /discovery/resources` in the calling process. Filter and
  pagination parameters are validated with `NimbleOptions` and encoded as
  query string parameters. The response is validated fail-closed: a malformed
  body returns
  `{:error, %X402.Facilitator.Error{type: :malformed_facilitator_response}}`.

  Items are returned as raw, string-keyed maps exactly as sent by the
  facilitator. `X402.Hooks` callbacks do not apply to this read-only
  operation.

  When called with just a keyword list — `list_resources(limit: 20)` — the
  parameters apply to the default facilitator process name.

  ## Parameters

  #{NimbleOptions.docs(@list_resources_params_schema)}

  ## Examples

      {:ok, %{items: items, pagination: pagination}} =
        X402.Facilitator.list_resources(MyFacilitator,
          network: "eip155:8453",
          limit: 20
        )
  """
  @doc group: :discovery
  @doc since: "0.6.0"
  @spec list_resources(server() | keyword(), keyword()) ::
          {:ok, discovery_resources_response()}
          | {:error, Error.t() | NimbleOptions.ValidationError.t()}
  def list_resources(server_or_params \\ @default_name, params \\ [])

  def list_resources(params, []) when is_list(params) do
    list_resources(@default_name, params)
  end

  def list_resources(server, params) when is_list(params) do
    case NimbleOptions.validate(params, @list_resources_params_schema) do
      {:ok, validated_params} ->
        config = fetch_config(server)
        query = discovery_query(validated_params)

        get_with_telemetry(
          config,
          :list_resources,
          "/discovery/resources",
          query,
          &parse_discovery_resources/1
        )

      {:error, %NimbleOptions.ValidationError{} = error} ->
        {:error, error}
    end
  end

  @doc false
  @spec validate_auth(nil | module() | {module(), keyword()}) ::
          {:ok, nil | module() | {module(), keyword()}} | {:error, String.t()}
  def validate_auth(nil), do: {:ok, nil}

  def validate_auth({module, opts}) when is_atom(module) and is_list(opts) do
    validate_auth_module(module, {module, opts})
  end

  def validate_auth(module) when is_atom(module), do: validate_auth_module(module, module)

  def validate_auth(_invalid),
    do: {:error, "must be nil, an auth module, or a {module, opts} tuple"}

  defp validate_auth_module(module, value) do
    if X402.Behaviour.implements?(module, new: 1, headers: 2) do
      {:ok, value}
    else
      {:error, "expected a module implementing X402.Facilitator.Auth"}
    end
  end

  @impl true
  @spec init(keyword()) :: {:ok, state()} | {:stop, term()}
  def init(opts) do
    case normalize_auth(Keyword.get(opts, :auth)) do
      {:ok, auth} ->
        state = %{
          url: Keyword.fetch!(opts, :url),
          finch: Keyword.fetch!(opts, :finch),
          hooks: Keyword.fetch!(opts, :hooks),
          auth: auth,
          max_retries: Keyword.fetch!(opts, :max_retries),
          retry_backoff_ms: Keyword.fetch!(opts, :retry_backoff_ms),
          receive_timeout_ms: Keyword.fetch!(opts, :receive_timeout_ms)
        }

        {:ok, state}

      {:error, reason} ->
        {:stop, {:invalid_auth, reason}}
    end
  end

  defp normalize_auth(nil), do: {:ok, nil}
  defp normalize_auth(%struct{} = auth) when is_atom(struct), do: {:ok, auth}
  defp normalize_auth(other), do: Auth.new(other)

  @impl true
  @spec handle_call(:config, GenServer.from(), state()) :: {:reply, state(), state()}
  def handle_call(:config, _from, state) do
    {:reply, state, state}
  end

  # Fetching the configuration is the only work performed inside the
  # facilitator process; everything else (HTTP, retries, hooks, telemetry)
  # runs in the caller so operations never serialize behind this GenServer.
  defp fetch_config(server), do: GenServer.call(server, :config)

  defp request_with_telemetry(state, operation, payment_payload, requirements, hooks_module) do
    endpoint = operation_endpoint(operation)

    :telemetry.span(
      [:x402, :facilitator, operation],
      %{operation: operation, endpoint: endpoint},
      fn ->
        result =
          request_with_hooks(
            state,
            operation,
            payment_payload,
            requirements,
            hooks_module,
            endpoint
          )

        log_failure(result, operation, endpoint)

        {result, telemetry_result_metadata(result)}
      end
    )
  end

  defp request_with_hooks(state, operation, payment_payload, requirements, hooks_module, endpoint) do
    metadata = %{operation: operation, endpoint: endpoint, hook_module: hooks_module}
    context = Context.new(payment_payload, requirements)

    case run_before_hook(hooks_module, operation, context, metadata) do
      {:cont, %Context{} = before_context} ->
        result =
          with :ok <-
                 validate_scheme_payment(
                   operation,
                   before_context.payload,
                   before_context.requirements
                 ),
               {:ok, headers} <- auth_headers(state, endpoint, :post) do
            HTTP.request(
              state.finch,
              state.url,
              endpoint,
              %{
                # x402 v2 facilitator wire format (§7.1 / §7.2)
                "x402Version" => 2,
                "paymentPayload" => before_context.payload,
                "paymentRequirements" => before_context.requirements
              },
              max_retries: state.max_retries,
              retry_backoff_ms: state.retry_backoff_ms,
              receive_timeout_ms: state.receive_timeout_ms,
              headers: headers
            )
          end

        handle_operation_result(hooks_module, operation, before_context, result, metadata)

      {:halt, reason} ->
        {:error, reason}
    end
  end

  defp auth_headers(state, endpoint, method) do
    request_info = %{
      method: method,
      host: request_host(state.url),
      path: request_path(state.url) <> endpoint
    }

    case Auth.headers(state.auth, request_info) do
      {:ok, headers} ->
        {:ok, headers}

      {:error, reason} ->
        {:error, %Error{type: :auth_failed, reason: reason, retryable: false, attempt: nil}}
    end
  end

  defp request_host(url) do
    case URI.parse(url) do
      %URI{host: host} = uri when is_binary(host) and host != "" -> host_with_port(host, uri)
      _other -> ""
    end
  end

  # Matches JavaScript `URL.host` semantics (used by the CDP SDK): the port is
  # included only when it differs from the scheme's default.
  defp host_with_port(host, %URI{port: port, scheme: scheme})
       when is_integer(port) and is_binary(scheme) do
    if URI.default_port(scheme) == port, do: host, else: "#{host}:#{port}"
  end

  defp host_with_port(host, %URI{port: port}) when is_integer(port), do: "#{host}:#{port}"
  defp host_with_port(host, _uri), do: host

  defp request_path(url) do
    case URI.parse(url) do
      %URI{path: path} when is_binary(path) and path != "" -> String.trim_trailing(path, "/")
      _other -> ""
    end
  end

  defp handle_operation_result(
         hooks_module,
         operation,
         %Context{} = context,
         {:ok, result},
         metadata
       )
       when is_map(result) do
    callback = after_callback(operation)
    success_context = %{context | result: result, error: nil}

    with {:ok, %Context{} = after_context} <-
           run_after_hook(hooks_module, operation, success_context, metadata) do
      finalized_result(after_context, result, callback)
    end
  end

  defp handle_operation_result(
         hooks_module,
         operation,
         %Context{} = context,
         {:error, error},
         metadata
       ) do
    failure_context = %{context | result: nil, error: error}
    run_failure_hook(hooks_module, operation, failure_context, error, metadata)
  end

  defp run_before_hook(hooks_module, operation, context, metadata) do
    callback = before_callback(operation)

    case invoke_hook(hooks_module, callback, context, metadata) do
      {:ok, {:cont, %Context{} = next_context}} ->
        {:cont, next_context}

      {:ok, {:halt, reason}} ->
        {:halt, {:hook_halted, callback, reason}}

      {:ok, invalid_return} ->
        {:halt, {:hook_invalid_return, callback, invalid_return}}

      {:error, reason} ->
        {:halt, {:hook_callback_failed, callback, reason}}
    end
  end

  defp run_after_hook(hooks_module, operation, context, metadata) do
    callback = after_callback(operation)

    case invoke_hook(hooks_module, callback, context, metadata) do
      {:ok, {:cont, %Context{} = next_context}} ->
        {:ok, next_context}

      {:ok, invalid_return} ->
        {:error, {:hook_invalid_return, callback, invalid_return}}

      {:error, reason} ->
        {:error, {:hook_callback_failed, callback, reason}}
    end
  end

  defp run_failure_hook(hooks_module, operation, context, original_error, metadata) do
    callback = failure_callback(operation)

    case invoke_hook(hooks_module, callback, context, metadata) do
      {:ok, {:cont, %Context{} = next_context}} ->
        {:error, finalized_error(next_context.error, original_error)}

      {:ok, {:recover, result}} when is_map(result) ->
        {:ok, result}

      {:ok, {:recover, invalid_result}} ->
        {:error, {:hook_invalid_return, callback, {:invalid_recovery_result, invalid_result}}}

      {:ok, invalid_return} ->
        {:error, {:hook_invalid_return, callback, invalid_return}}

      {:error, reason} ->
        {:error, {:hook_callback_failed, callback, reason}}
    end
  end

  defp finalized_result(%Context{result: nil}, default_result, _callback),
    do: {:ok, default_result}

  defp finalized_result(%Context{result: result}, _default_result, _callback) when is_map(result),
    do: {:ok, result}

  defp finalized_result(%Context{result: invalid_result}, _default_result, callback) do
    {:error, {:hook_invalid_return, callback, {:invalid_result, invalid_result}}}
  end

  defp finalized_error(nil, fallback), do: fallback
  defp finalized_error(error, _fallback), do: error

  defp invoke_hook(hooks_module, callback, context, metadata) do
    {:ok, apply(hooks_module, callback, [context, metadata])}
  rescue
    error -> {:error, {:exception, error}}
  catch
    kind, reason -> {:error, {kind, reason}}
  end

  defp validate_scheme_payment(operation, payload, requirements) do
    case Utils.map_value(requirements, {"scheme", :scheme}) ||
           Utils.map_value(payload, {"scheme", :scheme}) do
      "upto" ->
        validate_upto_payment(operation, payload, requirements)

      _scheme ->
        :ok
    end
  end

  defp validate_upto_payment(:verify, payload, requirements) do
    with {:ok, max_price} <- extract_max_price(payload, requirements),
         {:ok, authorized_amount} <- extract_authorized_amount(payload) do
      ensure_not_exceeds(authorized_amount, max_price)
    end
  end

  defp validate_upto_payment(:settle, payload, requirements) do
    case Utils.map_value(requirements, {"amount", :amount}) do
      nil ->
        validate_upto_payment(:verify, payload, requirements)

      settlement_amount ->
        with {:ok, settlement_amount} <- parse_settlement_amount(settlement_amount),
             {:ok, authorized_amount} <- extract_authorized_amount(payload) do
          ensure_settlement_not_exceeds_authorized(settlement_amount, authorized_amount)
        end
    end
  end

  defp extract_max_price(payload, requirements) do
    value =
      Utils.first_present([
        Utils.map_value(requirements, {"amount", :amount}),
        Utils.map_value(requirements, {"maxPrice", :maxPrice}),
        Utils.map_value(requirements, {"maxAmountRequired", :maxAmountRequired}),
        Utils.nested_map_value(payload, [{"accepted", :accepted}, {"amount", :amount}]),
        Utils.map_value(payload, {"maxPrice", :maxPrice}),
        Utils.map_value(payload, {"maxAmountRequired", :maxAmountRequired})
      ])

    case value do
      nil ->
        {:error, {:invalid_upto_payment, :missing_max_price}}

      max_price ->
        case Utils.parse_decimal(max_price) do
          {:ok, parsed} -> {:ok, parsed}
          :error -> {:error, {:invalid_upto_payment, :invalid_max_price}}
        end
    end
  end

  defp extract_authorized_amount(payload) do
    value =
      Utils.first_present([
        Utils.nested_map_value(payload, [
          {"payload", :payload},
          {"permit2Authorization", :permit2Authorization},
          {"permitted", :permitted},
          {"amount", :amount}
        ]),
        Utils.nested_map_value(payload, [
          {"permit2Authorization", :permit2Authorization},
          {"permitted", :permitted},
          {"amount", :amount}
        ]),
        Utils.nested_map_value(payload, [{"payload", :payload}, {"maxAmount", :maxAmount}]),
        Utils.map_value(payload, {"maxAmount", :maxAmount}),
        Utils.map_value(payload, {"value", :value}),
        Utils.nested_map_value(payload, [{"payload", :payload}, {"value", :value}]),
        Utils.nested_map_value(payload, [
          {"payload", :payload},
          {"authorization", :authorization},
          {"value", :value}
        ]),
        Utils.nested_map_value(payload, [{"authorization", :authorization}, {"value", :value}])
      ])

    case value do
      nil ->
        {:error, {:invalid_upto_payment, :missing_payment_value}}

      payment_value ->
        case Utils.parse_decimal(payment_value) do
          {:ok, parsed} -> {:ok, parsed}
          :error -> {:error, {:invalid_upto_payment, :invalid_payment_value}}
        end
    end
  end

  defp parse_settlement_amount(value) do
    case Utils.parse_decimal(value) do
      {:ok, parsed} -> {:ok, parsed}
      :error -> {:error, {:invalid_upto_payment, :invalid_settlement_amount}}
    end
  end

  defp ensure_not_exceeds(payment_value, max_price) do
    case Utils.compare_decimal(payment_value, max_price) do
      :gt -> {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}}
      _comparison -> :ok
    end
  end

  defp ensure_settlement_not_exceeds_authorized(settlement_amount, authorized_amount) do
    case Utils.compare_decimal(settlement_amount, authorized_amount) do
      :gt ->
        {:error, {:invalid_upto_payment, :settlement_amount_exceeds_authorized_amount}}

      _comparison ->
        :ok
    end
  end

  # --- read-only GET operations (supported / discovery) ---

  defp get_with_telemetry(config, operation, endpoint, query, parser) do
    :telemetry.span(
      [:x402, :facilitator, operation],
      %{operation: operation, endpoint: endpoint},
      fn ->
        result = get_operation(config, endpoint, query, parser)
        log_failure(result, operation, endpoint)
        {result, telemetry_result_metadata(result)}
      end
    )
  end

  defp get_operation(config, endpoint, query, parser) do
    with {:ok, headers} <- auth_headers(config, endpoint, :get),
         {:ok, %{status: status, body: body}} <-
           HTTP.get(config.finch, config.url, endpoint,
             query: query,
             max_retries: config.max_retries,
             retry_backoff_ms: config.retry_backoff_ms,
             receive_timeout_ms: config.receive_timeout_ms,
             headers: headers
           ) do
      parse_body(parser, status, body)
    end
  end

  defp parse_body(parser, status, body) do
    case parser.(body) do
      {:ok, parsed} ->
        {:ok, parsed}

      {:error, reason} ->
        {:error,
         %Error{
           type: :malformed_facilitator_response,
           status: status,
           body: body,
           reason: reason,
           retryable: false,
           attempt: nil
         }}
    end
  end

  defp discovery_query(params) do
    Enum.flat_map(params, fn
      {:pay_to, value} -> [{"payTo", value}]
      {key, value} -> [{Atom.to_string(key), value}]
    end)
  end

  defp parse_supported(body) do
    with {:ok, kinds} <- parse_supported_kinds(Map.get(body, "kinds")),
         {:ok, extensions} <- parse_supported_extensions(Map.get(body, "extensions", [])),
         {:ok, signers} <- parse_supported_signers(Map.get(body, "signers", %{})) do
      {:ok, %{kinds: kinds, extensions: extensions, signers: signers}}
    end
  end

  defp parse_supported_kinds(nil), do: {:error, {:missing_field, "kinds"}}

  defp parse_supported_kinds(kinds) when is_list(kinds) do
    kinds
    |> Enum.reduce_while([], fn kind, acc ->
      case parse_supported_kind(kind) do
        {:ok, parsed} -> {:cont, [parsed | acc]}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:error, reason} -> {:error, reason}
      parsed -> {:ok, Enum.reverse(parsed)}
    end
  end

  defp parse_supported_kinds(_kinds), do: {:error, {:invalid_field, "kinds"}}

  defp parse_supported_kind(
         %{"x402Version" => x402_version, "scheme" => scheme, "network" => network} = kind
       )
       when is_integer(x402_version) and is_binary(scheme) and is_binary(network) do
    case Map.get(kind, "extra") do
      nil ->
        {:ok, %{x402_version: x402_version, scheme: scheme, network: network, extra: nil}}

      extra when is_map(extra) ->
        {:ok, %{x402_version: x402_version, scheme: scheme, network: network, extra: extra}}

      _invalid ->
        {:error, {:invalid_kind, kind}}
    end
  end

  defp parse_supported_kind(kind), do: {:error, {:invalid_kind, kind}}

  defp parse_supported_extensions(extensions) when is_list(extensions) do
    if Enum.all?(extensions, &is_binary/1) do
      {:ok, extensions}
    else
      {:error, {:invalid_field, "extensions"}}
    end
  end

  defp parse_supported_extensions(_extensions), do: {:error, {:invalid_field, "extensions"}}

  defp parse_supported_signers(signers) when is_map(signers) do
    valid? =
      Enum.all?(signers, fn
        {pattern, addresses} when is_binary(pattern) and is_list(addresses) ->
          Enum.all?(addresses, &is_binary/1)

        _entry ->
          false
      end)

    if valid?, do: {:ok, signers}, else: {:error, {:invalid_field, "signers"}}
  end

  defp parse_supported_signers(_signers), do: {:error, {:invalid_field, "signers"}}

  defp parse_discovery_resources(body) do
    with {:ok, items} <- parse_discovery_items(Map.get(body, "items")),
         {:ok, pagination} <- parse_discovery_pagination(Map.get(body, "pagination")),
         {:ok, x402_version} <- parse_discovery_version(Map.get(body, "x402Version")) do
      {:ok, %{x402_version: x402_version, items: items, pagination: pagination}}
    end
  end

  defp parse_discovery_items(nil), do: {:error, {:missing_field, "items"}}

  defp parse_discovery_items(items) when is_list(items) do
    if Enum.all?(items, &is_map/1) do
      {:ok, items}
    else
      {:error, {:invalid_field, "items"}}
    end
  end

  defp parse_discovery_items(_items), do: {:error, {:invalid_field, "items"}}

  defp parse_discovery_pagination(nil), do: {:ok, nil}

  defp parse_discovery_pagination(%{"limit" => limit, "offset" => offset, "total" => total})
       when is_integer(limit) and is_integer(offset) and is_integer(total) do
    {:ok, %{limit: limit, offset: offset, total: total}}
  end

  defp parse_discovery_pagination(_pagination), do: {:error, {:invalid_field, "pagination"}}

  defp parse_discovery_version(nil), do: {:ok, nil}
  defp parse_discovery_version(version) when is_integer(version), do: {:ok, version}
  defp parse_discovery_version(_version), do: {:error, {:invalid_field, "x402Version"}}

  defp before_callback(:verify), do: :before_verify
  defp before_callback(:settle), do: :before_settle

  defp after_callback(:verify), do: :after_verify
  defp after_callback(:settle), do: :after_settle

  defp failure_callback(:verify), do: :on_verify_failure
  defp failure_callback(:settle), do: :on_settle_failure

  defp operation_endpoint(:verify), do: "/verify"
  defp operation_endpoint(:settle), do: "/settle"

  defp log_failure({:ok, _result}, _operation, _endpoint), do: :ok

  defp log_failure({:error, %Error{} = error}, operation, endpoint) do
    Logger.warning(
      "[X402.Facilitator] #{operation} failed at #{endpoint}: #{Exception.message(error)}"
    )
  end

  defp log_failure({:error, reason}, operation, endpoint) do
    Logger.warning("[X402.Facilitator] #{operation} failed at #{endpoint}: #{inspect(reason)}")
  end

  defp telemetry_result_metadata({:ok, %{status: status}}),
    do: %{status: status, success: true}

  defp telemetry_result_metadata({:ok, _result}), do: %{success: true}

  defp telemetry_result_metadata({:error, %Error{} = error}) do
    %{
      status: error.status,
      success: false,
      error_type: error.type,
      retryable: error.retryable,
      attempt: error.attempt
    }
  end

  defp telemetry_result_metadata({:error, reason}) do
    %{
      success: false,
      error: reason
    }
  end
end
