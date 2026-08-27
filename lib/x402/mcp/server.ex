defmodule X402.MCP.Server do
  @moduledoc """
  Server half of the x402 MCP transport: gates a tool handler behind payment.

  `call/3` inspects an MCP tool-call request for a payment in
  `_meta["x402/payment"]` and drives the full verify → execute → settle flow
  against an `X402.Facilitator`:

  1. No payment → the payment-required tool result (`isError: true` with the
     `PaymentRequired` object in `structuredContent` and `content[0].text`).
  2. Invalid payment (wrong version, `accepted` not matching the advertised
     requirements, extension echo mismatch, failed verification) → the same
     payment-required result with the rejection reason.
  3. Valid payment → the wrapped handler runs; on success the payment is
     settled and the receipt is attached to result
     `_meta["x402/payment-response"]`. When settlement fails after execution,
     only the payment error is returned — never the tool's content.

  The module is MCP-library agnostic: requests and results are plain maps in
  the shapes MCP libraries already use, so the wrapper drops into any tool
  dispatch function. See the [MCP guide](mcp.html) for integration snippets.

  ## Example

      config =
        X402.MCP.Server.init(
          tool: "premium_search",
          accepts: [
            %{
              price: "10000",
              network: "eip155:84532",
              asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
              pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
              extra: %{"name" => "USDC", "version" => "2"}
            }
          ],
          facilitator: MyApp.Facilitator
        )

      X402.MCP.Server.call(request, config, fn _request ->
        %{"content" => [%{"type" => "text", "text" => "results..."}]}
      end)

  ## Replay protection

  Pass `payment_identifier_cache:` (an
  `X402.Extensions.PaymentIdentifier.ETSCache` server, the same option
  `X402.Plug.PaymentGate` takes) to atomically claim each payment proof before
  settlement, rejecting concurrent or repeated submissions of the same signed
  payment. The claim is released when the handler fails or settlement fails,
  so the client may retry with the same payment.
  """

  alias X402.Extensions.PaymentIdentifier.Cache
  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.Facilitator
  alias X402.Facilitator.Error
  alias X402.Hooks
  alias X402.Hooks.Default
  alias X402.MCP
  alias X402.PaymentRequirements
  alias X402.PaymentSignature
  alias X402.Utils

  require Logger

  @schemes ["exact", "upto"]
  @x402_version 2
  @supported_payment_flow "authorization"
  @default_max_timeout_seconds 60
  @default_mime_type "application/json"

  @accept_option_schema [
    scheme: [
      type: {:in, @schemes},
      default: "exact",
      doc: "Payment scheme (`exact` or `upto`)."
    ],
    price: [
      type: {:custom, __MODULE__, :validate_atomic_amount, []},
      required: true,
      doc: "Payment amount in atomic token units (PaymentRequirements `amount`)."
    ],
    network: [
      type: :string,
      required: true,
      doc: "Blockchain network in CAIP-2 format (for example `eip155:84532`)."
    ],
    asset: [
      type: :string,
      required: true,
      doc: "Token contract address or asset identifier."
    ],
    pay_to: [
      type: :string,
      required: true,
      doc: "Recipient wallet address (`payTo` in the PaymentRequirements schema)."
    ],
    max_timeout_seconds: [
      type: :pos_integer,
      default: @default_max_timeout_seconds,
      doc: "Maximum time allowed for payment completion."
    ],
    extra: [
      type: {:custom, __MODULE__, :validate_extra_map, []},
      default: %{},
      doc: "Scheme-specific extra fields (string or atom keys)."
    ]
  ]

  @options_schema [
    tool: [
      type: :string,
      required: true,
      doc: "Tool name; used for the default `mcp://tool/{tool}` resource URL."
    ],
    accepts: [
      type: {:list, {:map, @accept_option_schema}},
      required: true,
      doc: "Payment options advertised in `PaymentRequired.accepts` (at least one)."
    ],
    facilitator: [
      type: :any,
      default: Facilitator,
      doc: "Facilitator server pid/name used for verification and settlement."
    ],
    hooks: [
      type: {:custom, Hooks, :validate_module, []},
      default: Default,
      doc: "Lifecycle hook module implementing `X402.Hooks`."
    ],
    payment_identifier_cache: [
      type: {:custom, __MODULE__, :validate_payment_identifier_cache, []},
      default: nil,
      doc: """
      Optional idempotency cache: an `ETSCache` server pid/name (the default
      adapter), or a `{module, cache}` adapter tuple implementing
      `X402.Extensions.PaymentIdentifier.Cache`. When set, the wrapper
      performs an atomic claim (via `put_new`) on a hash of the signed scheme
      payload before settling, preventing concurrent requests from
      double-settling the same payment.
      """
    ],
    resource_url: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: "Custom ResourceInfo.url (defaults to `mcp://tool/{tool}`)."
    ],
    description: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: "ResourceInfo.description (defaults to `Tool: {tool}`)."
    ],
    mime_type: [
      type: :string,
      default: @default_mime_type,
      doc: "ResourceInfo.mimeType."
    ],
    service_name: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: "ResourceInfo.serviceName (printable ASCII, max 32 characters recommended)."
    ],
    tags: [
      type: {:list, :string},
      default: [],
      doc: "ResourceInfo.tags (max 5 recommended)."
    ],
    icon_url: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: "ResourceInfo.iconUrl (absolute http(s) URL)."
    ],
    extensions: [
      type: {:custom, __MODULE__, :validate_extra_map, []},
      default: %{},
      doc: "Protocol extensions advertised in PaymentRequired.extensions."
    ]
  ]

  @typedoc "Configuration map produced by `init/1`."
  @type options :: %{
          tool: String.t(),
          facilitator: Facilitator.server(),
          hooks: module(),
          payment_identifier_cache: ETSCache.server() | nil,
          accepts: [map()],
          resource: map(),
          extensions: map()
        }

  @typedoc "An MCP tool-call handler: request params in, tool result map out."
  @type handler :: (map() -> map())

  # Reasons caused by facilitator infrastructure failures rather than by the
  # client's payment; these produce an opaque internal error result instead of
  # re-advertising the payment requirements.
  defguardp is_infrastructure_reason(reason)
            when is_struct(reason, Error) or
                   reason == :cache_full or
                   (is_tuple(reason) and
                      elem(reason, 0) in [
                        :unexpected_facilitator_status,
                        :malformed_facilitator_response,
                        :claim_failed
                      ])

  @doc false
  @spec validate_extra_map(term()) :: {:ok, map()} | {:error, String.t()}
  def validate_extra_map(value) when is_map(value), do: {:ok, value}
  def validate_extra_map(_value), do: {:error, "expected a map"}

  @doc false
  @spec validate_atomic_amount(term()) :: {:ok, String.t()} | {:error, String.t()}
  def validate_atomic_amount(value) when is_binary(value) do
    case Regex.match?(~r/^\d+$/, value) do
      true -> {:ok, value}
      false -> {:error, "expected a digit-only atomic-unit amount"}
    end
  end

  def validate_atomic_amount(_value), do: {:error, "expected a digit-only atomic-unit amount"}

  @doc since: "0.6.0"
  @doc """
  Validates and compiles paid-tool options.

  Raises `NimbleOptions.ValidationError` for invalid options and
  `ArgumentError` when `:accepts` is empty, an accept's `extra.paymentFlow`
  is not `"authorization"`, or the advertised data cannot be encoded as JSON.

  ## Options

  #{NimbleOptions.docs(@options_schema)}

  ### Accept option fields (inside `:accepts`)

  #{NimbleOptions.docs(@accept_option_schema)}
  """
  @spec init(keyword()) :: options()
  def init(opts) when is_list(opts) do
    validated = NimbleOptions.validate!(opts, @options_schema)

    tool = Keyword.fetch!(validated, :tool)
    accepts = compile_accepts(Keyword.fetch!(validated, :accepts))
    resource = compile_resource(tool, validated)
    extensions = stringify_keys(Keyword.fetch!(validated, :extensions))

    ensure_json_encodable!(%{
      "accepts" => accepts,
      "resource" => resource,
      "extensions" => extensions
    })

    %{
      tool: tool,
      facilitator: Keyword.fetch!(validated, :facilitator),
      hooks: Keyword.fetch!(validated, :hooks),
      payment_identifier_cache: Keyword.get(validated, :payment_identifier_cache),
      accepts: accepts,
      resource: resource,
      extensions: extensions
    }
  end

  @doc since: "0.6.0"
  @doc """
  Gates an MCP tool-call request behind x402 payment verification.

  `request` is the tool-call params map (typically with `"name"`,
  `"arguments"`, and `"_meta"` keys). `handler` receives the request and must
  return a tool result map (with a `"content"` list and optional
  `"isError"`); it only runs after the payment has been verified.

  Always returns a tool result map:

  - the payment-required result when payment is missing, invalid, rejected
    by the facilitator, or already settled (replay)
  - the handler's result with the settlement receipt attached to
    `_meta["x402/payment-response"]` on success
  - the handler's error result unchanged (no settlement) when the handler
    sets `"isError" => true`
  - the settlement-failure result (payment-required format, without the
    tool's content) when settlement fails after execution
  - an opaque internal error result when the facilitator transport fails

  If the handler raises, the replay claim is released and the exception is
  re-raised for the MCP library to surface.
  """
  @spec call(map(), options(), handler()) :: map()
  def call(request, config, handler)
      when is_map(request) and is_map(config) and is_function(handler, 1) do
    if is_nil(config.payment_identifier_cache), do: warn_no_idempotency_cache_once()

    case MCP.fetch_payment(request) do
      :error ->
        emit(:payment_required, %{tool: config.tool})
        payment_required_result(config, "Payment required to access this tool")

      {:ok, payment_payload} ->
        verify_and_execute(request, config, handler, payment_payload)
    end
  end

  @doc since: "0.6.0"
  @doc """
  Builds the payment-required tool result advertised by this configuration.

  Useful for advertising the price of a paid tool outside `call/3` (for
  example in a `tools/list` response or documentation).
  """
  @spec payment_required_result(options(), String.t()) :: map()
  def payment_required_result(config, error_message \\ "Payment required to access this tool")
      when is_map(config) and is_binary(error_message) do
    payment_required = %{
      "x402Version" => @x402_version,
      "error" => error_message,
      "resource" => config.resource,
      "accepts" => config.accepts,
      "extensions" => config.extensions
    }

    case MCP.payment_required_result(payment_required) do
      {:ok, result} -> result
      # init/1 guarantees encodability; this is a defensive fallback.
      {:error, _reason} -> internal_error_result()
    end
  end

  # -- Verification -----------------------------------------------------------

  @spec verify_and_execute(map(), options(), handler(), map()) :: map()
  defp verify_and_execute(request, config, handler, payment_payload) do
    with {:ok, requirements} <- validate_payment(payment_payload, config),
         {:ok, payment_id} <- payment_id(payment_payload),
         {:ok, verify_response} <- facilitator_verify(config, payment_payload, requirements),
         :ok <- ensure_verify_success(verify_response),
         :ok <- claim_or_fail(config.payment_identifier_cache, payment_id) do
      execute_and_settle(request, config, handler, payment_payload, requirements, payment_id)
    else
      {:error, reason} ->
        emit(:payment_rejected, %{tool: config.tool, reason: reason})
        rejection_result(config, reason)
    end
  end

  @spec validate_payment(map(), options()) :: {:ok, map()} | {:error, term()}
  defp validate_payment(payment_payload, config) do
    with :ok <- ensure_v2_payload(payment_payload),
         {:ok, payment_payload} <- PaymentSignature.validate(payment_payload),
         {:ok, matched} <- find_matching_requirements(config.accepts, payment_payload),
         :ok <- validate_extensions(payment_payload, config.extensions) do
      {:ok, matched}
    end
  end

  @spec ensure_v2_payload(map()) :: :ok | {:error, :invalid_x402_version}
  defp ensure_v2_payload(payload) do
    case Utils.map_value(payload, {"x402Version", :x402Version}) do
      @x402_version -> :ok
      _version -> {:error, :invalid_x402_version}
    end
  end

  @spec find_matching_requirements([map()], map()) ::
          {:ok, map()} | {:error, :no_matching_requirements}
  defp find_matching_requirements(accepts, payment_payload) do
    accepted = Utils.map_value(payment_payload, {"accepted", :accepted})

    with true <- is_map(accepted),
         %{} = matched <- Enum.find(accepts, &PaymentRequirements.match?(&1, accepted)) do
      {:ok, matched}
    else
      _other -> {:error, :no_matching_requirements}
    end
  end

  @spec validate_extensions(map(), map()) :: :ok | {:error, :extension_echo_mismatch}
  defp validate_extensions(payload, advertised_extensions) do
    client_extensions = Utils.map_value(payload, {"extensions", :extensions})

    case PaymentRequirements.extensions_match?(advertised_extensions, client_extensions) do
      true -> :ok
      false -> {:error, :extension_echo_mismatch}
    end
  end

  # The claim key must be derived from the SIGNED material only, encoded
  # deterministically: hashing a plain Jason encoding of the whole envelope
  # lets extra envelope fields or a different key order mint a fresh id for
  # the same signed authorization, so a mutated replay would claim a new slot
  # and run the paid handler again. The scheme payload (signature +
  # authorization) cannot be altered without failing facilitator
  # verification, which precedes the claim.
  @spec payment_id(map()) :: {:ok, String.t()} | {:error, :invalid_payload}
  defp payment_id(payment_payload) do
    case Utils.map_value(payment_payload, {"payload", :payload}) do
      scheme_payload when is_map(scheme_payload) ->
        canonical = :erlang.term_to_binary(scheme_payload, [:deterministic])
        {:ok, :crypto.hash(:sha256, canonical) |> Base.encode16(case: :lower)}

      _other ->
        {:error, :invalid_payload}
    end
  end

  # -- Execution and settlement -----------------------------------------------

  @spec execute_and_settle(map(), options(), handler(), map(), map(), String.t()) :: map()
  defp execute_and_settle(request, config, handler, payment_payload, requirements, payment_id) do
    result = run_handler(config, handler, request, payment_id)

    case error_result?(result) do
      true ->
        # The tool itself failed: return its error unchanged, do not settle,
        # and release the claim so the client may retry with the same payment.
        release_claim(config.payment_identifier_cache, payment_id)
        result

      false ->
        settle_result(config, payment_payload, requirements, payment_id, result)
    end
  end

  @spec run_handler(options(), handler(), map(), String.t()) :: map()
  defp run_handler(config, handler, request, payment_id) do
    result =
      try do
        handler.(request)
      rescue
        exception ->
          release_claim(config.payment_identifier_cache, payment_id)
          reraise exception, __STACKTRACE__
      catch
        kind, reason ->
          release_claim(config.payment_identifier_cache, payment_id)
          :erlang.raise(kind, reason, __STACKTRACE__)
      end

    case result do
      %{} = result_map ->
        result_map

      other ->
        release_claim(config.payment_identifier_cache, payment_id)

        raise ArgumentError,
              "expected the wrapped MCP tool handler to return a tool result map, " <>
                "got: #{inspect(other)}"
    end
  end

  @spec settle_result(options(), map(), map(), String.t(), map()) :: map()
  defp settle_result(config, payment_payload, requirements, payment_id, result) do
    with {:ok, settle_response} <- facilitator_settle(config, payment_payload, requirements),
         :ok <- ensure_settle_success(settle_response) do
      emit(:payment_verified, %{tool: config.tool})
      MCP.put_payment_response(result, settle_response.body)
    else
      {:error, reason} ->
        release_claim(config.payment_identifier_cache, payment_id)
        emit(:payment_rejected, %{tool: config.tool, reason: reason})
        settlement_failed_result(config, reason)
    end
  end

  # Per the spec, settlement failure after execution follows the payment
  # required format and must not include the tool's content.
  @spec settlement_failed_result(options(), term()) :: map()
  defp settlement_failed_result(_config, reason) when is_infrastructure_reason(reason) do
    internal_error_result()
  end

  defp settlement_failed_result(config, reason) do
    payment_required_result(config, "Payment settlement failed: #{rejection_message(reason)}")
  end

  @spec rejection_result(options(), term()) :: map()
  defp rejection_result(_config, reason) when is_infrastructure_reason(reason) do
    internal_error_result()
  end

  defp rejection_result(config, reason) do
    payment_required_result(config, rejection_message(reason))
  end

  @spec internal_error_result() :: map()
  defp internal_error_result do
    %{
      "isError" => true,
      "content" => [%{"type" => "text", "text" => "Internal server error"}]
    }
  end

  @spec rejection_message(term()) :: String.t()
  defp rejection_message(:invalid_x402_version), do: "invalid_x402_version"
  defp rejection_message(:invalid_payload), do: "invalid_payload"
  defp rejection_message(:no_matching_requirements), do: "No matching payment requirements"
  defp rejection_message(:extension_echo_mismatch), do: "invalid_payload"
  defp rejection_message(:already_exists), do: "payment already processed"
  defp rejection_message({:missing_fields, _fields}), do: "invalid_payload"
  defp rejection_message({:invalid_fields, _fields}), do: "invalid_payload"
  defp rejection_message({:invalid_format, _fields}), do: "invalid_payload"
  defp rejection_message({:invalid_upto_payment, _reason}), do: "invalid_payload"
  defp rejection_message(:invalid_payment_requirements), do: "invalid_payload"

  defp rejection_message({:verification_failed, reason}) when is_binary(reason), do: reason

  defp rejection_message({:verification_failed, _reason}),
    do: "facilitator rejected payment"

  defp rejection_message({:settlement_failed, reason}) when is_binary(reason), do: reason
  defp rejection_message({:settlement_failed, _reason}), do: "facilitator rejected payment"
  defp rejection_message(_reason), do: "payment processing failed"

  @spec error_result?(map()) :: boolean()
  defp error_result?(result), do: Utils.map_value(result, {"isError", :isError}) == true

  # -- Facilitator ------------------------------------------------------------

  @spec facilitator_verify(options(), map(), map()) :: Facilitator.response()
  defp facilitator_verify(%{hooks: Default} = config, payment_payload, requirements) do
    Facilitator.verify(config.facilitator, payment_payload, requirements)
  end

  defp facilitator_verify(config, payment_payload, requirements) do
    Facilitator.verify(config.facilitator, payment_payload, requirements, config.hooks)
  end

  @spec facilitator_settle(options(), map(), map()) :: Facilitator.response()
  defp facilitator_settle(%{hooks: Default} = config, payment_payload, requirements) do
    Facilitator.settle(config.facilitator, payment_payload, requirements)
  end

  defp facilitator_settle(config, payment_payload, requirements) do
    Facilitator.settle(config.facilitator, payment_payload, requirements, config.hooks)
  end

  @spec ensure_verify_success(map()) :: :ok | {:error, term()}
  defp ensure_verify_success(%{status: status, body: body})
       when status in 200..299 and is_map(body) do
    case Utils.map_value(body, {"isValid", :isValid}) do
      true ->
        :ok

      false ->
        {:error, {:verification_failed, Utils.map_value(body, {"invalidReason", :invalidReason})}}

      _missing_or_invalid ->
        {:error, {:malformed_facilitator_response, :verify}}
    end
  end

  defp ensure_verify_success(%{status: status}) when status in 200..299,
    do: {:error, {:malformed_facilitator_response, :verify}}

  defp ensure_verify_success(%{status: status}) when is_integer(status),
    do: {:error, {:unexpected_facilitator_status, status}}

  defp ensure_verify_success(%{}),
    do: {:error, {:malformed_facilitator_response, :verify}}

  @spec ensure_settle_success(map()) :: :ok | {:error, term()}
  defp ensure_settle_success(%{status: status, body: body})
       when status in 200..299 and is_map(body) do
    case Utils.map_value(body, {"success", :success}) do
      true ->
        validate_settle_response_fields(body)

      false ->
        with :ok <- validate_settle_response_fields(body) do
          {:error, {:settlement_failed, Utils.map_value(body, {"errorReason", :errorReason})}}
        end

      _missing_or_invalid ->
        {:error, {:malformed_facilitator_response, :settle}}
    end
  end

  defp ensure_settle_success(%{status: status}) when status in 200..299,
    do: {:error, {:malformed_facilitator_response, :settle}}

  defp ensure_settle_success(%{status: status}) when is_integer(status),
    do: {:error, {:unexpected_facilitator_status, status}}

  defp ensure_settle_success(%{}),
    do: {:error, {:malformed_facilitator_response, :settle}}

  @spec validate_settle_response_fields(map()) ::
          :ok | {:error, {:malformed_facilitator_response, :settle}}
  defp validate_settle_response_fields(body) do
    transaction = Utils.map_value(body, {"transaction", :transaction})
    network = Utils.map_value(body, {"network", :network})

    case is_binary(transaction) and is_binary(network) and network != "" do
      true -> :ok
      false -> {:error, {:malformed_facilitator_response, :settle}}
    end
  end

  # -- Replay claims ----------------------------------------------------------

  @spec claim_payment(Cache.adapter() | nil, String.t()) :: Cache.put_new_result()
  defp claim_payment(nil, _payment_id), do: :ok
  defp claim_payment(adapter, payment_id), do: Cache.put_new(adapter, payment_id, :verified)

  # Duplicates are payment rejections; any other claim failure is cache
  # infrastructure trouble and must fail closed as an internal error rather
  # than re-advertise PaymentRequired after a successful verify (mirrors the
  # Plug gate's 500 mapping).
  @spec claim_or_fail(Cache.adapter() | nil, String.t()) ::
          :ok | {:error, :already_exists | {:claim_failed, term()}}
  defp claim_or_fail(cache, payment_id) do
    case claim_payment(cache, payment_id) do
      :ok -> :ok
      {:error, :already_exists} = duplicate -> duplicate
      {:error, reason} -> {:error, {:claim_failed, reason}}
    end
  end

  @spec release_claim(Cache.adapter() | nil, String.t()) :: Cache.write_result()
  defp release_claim(nil, _payment_id), do: :ok
  defp release_claim(adapter, payment_id), do: Cache.delete(adapter, payment_id)

  @doc false
  @spec validate_payment_identifier_cache(term()) ::
          {:ok, Cache.adapter() | nil} | {:error, String.t()}
  def validate_payment_identifier_cache(nil), do: {:ok, nil}

  # {:global, name} and {:via, registry, term} are unambiguous GenServer
  # names, never adapter tuples — route them to the default ETSCache adapter.
  def validate_payment_identifier_cache({:global, _name} = server),
    do: {:ok, {ETSCache, server}}

  def validate_payment_identifier_cache({:via, registry, _term} = server)
      when is_atom(registry),
      do: {:ok, {ETSCache, server}}

  def validate_payment_identifier_cache({module, _cache} = adapter) when is_atom(module) do
    case Cache.validate_adapter(adapter) do
      :ok ->
        {:ok, adapter}

      {:error, message} ->
        {:error,
         message <>
           "; to address a remote ETSCache as {name, node}, wrap it explicitly: " <>
           "{X402.Extensions.PaymentIdentifier.ETSCache, {name, node}}"}
    end
  end

  def validate_payment_identifier_cache(server), do: {:ok, {ETSCache, server}}

  defp warn_no_idempotency_cache_once do
    key = {__MODULE__, :no_idempotency_cache_warned}

    unless :persistent_term.get(key, false) do
      :persistent_term.put(key, true)

      Logger.warning(
        "[X402.MCP.Server] payment_identifier_cache is not configured. " <>
          "Duplicate payment proofs will NOT be detected — your deployment is " <>
          "vulnerable to double-settlement of concurrent identical requests. " <>
          "Pass `payment_identifier_cache: pid_or_name` to enable idempotency."
      )
    end
  end

  # -- Config compilation -----------------------------------------------------

  @spec compile_accepts([map()]) :: [map()]
  defp compile_accepts([]) do
    raise ArgumentError, ":accepts must contain at least one payment option"
  end

  defp compile_accepts(accepts) do
    Enum.map(accepts, fn accept ->
      extra = stringify_keys(Map.get(accept, :extra, %{}))
      ensure_supported_payment_flow!(extra)

      %{
        "scheme" => Map.get(accept, :scheme, "exact"),
        "network" => Map.fetch!(accept, :network),
        "amount" => Map.fetch!(accept, :price),
        "asset" => Map.fetch!(accept, :asset),
        "payTo" => Map.fetch!(accept, :pay_to),
        "maxTimeoutSeconds" =>
          Map.get(accept, :max_timeout_seconds, @default_max_timeout_seconds),
        "extra" => extra
      }
    end)
  end

  @spec ensure_supported_payment_flow!(map()) :: :ok
  defp ensure_supported_payment_flow!(extra) do
    case Utils.map_value(extra, {"paymentFlow", :paymentFlow}) do
      nil -> :ok
      @supported_payment_flow -> :ok
      flow -> raise ArgumentError, "unsupported payment flow: #{inspect(flow)}"
    end
  end

  @spec compile_resource(String.t(), keyword()) :: map()
  defp compile_resource(tool, validated) do
    %{
      "url" => Keyword.get(validated, :resource_url) || "mcp://tool/#{tool}",
      "description" => Keyword.get(validated, :description) || "Tool: #{tool}",
      "mimeType" => Keyword.fetch!(validated, :mime_type)
    }
    |> maybe_put("serviceName", Keyword.get(validated, :service_name))
    |> maybe_put_tags(Keyword.fetch!(validated, :tags))
    |> maybe_put("iconUrl", Keyword.get(validated, :icon_url))
  end

  @spec ensure_json_encodable!(map()) :: :ok
  defp ensure_json_encodable!(advertised) do
    case Jason.encode(advertised) do
      {:ok, _json} ->
        :ok

      {:error, reason} ->
        raise ArgumentError,
              "accepts/resource/extensions must be JSON-encodable, got: #{inspect(reason)}"
    end
  end

  @spec maybe_put(map(), String.t(), term()) :: map()
  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, _key, ""), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  @spec maybe_put_tags(map(), [String.t()]) :: map()
  defp maybe_put_tags(map, tags) when tags != [], do: Map.put(map, "tags", tags)
  defp maybe_put_tags(map, _tags), do: map

  @spec stringify_keys(map()) :: map()
  defp stringify_keys(map) do
    Map.new(map, fn
      {key, value} when is_atom(key) -> {Atom.to_string(key), value}
      {key, value} -> {key, value}
    end)
  end

  @spec emit(:payment_required | :payment_verified | :payment_rejected, map()) :: :ok
  defp emit(event, metadata) do
    :telemetry.execute([:x402, :mcp, event], %{count: 1}, metadata)
  end
end
