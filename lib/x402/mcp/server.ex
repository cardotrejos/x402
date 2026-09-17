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

  ## Payment identifier

  Advertise the
  [`payment-identifier` extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/payment_identifier.md)
  with `extensions: %{"payment-identifier" => X402.Extensions.PaymentIdentifier.extension(required: true)}`.
  The id echoed under `extensions["payment-identifier"]["info"]["id"]` must
  be 16–128 characters of `[A-Za-z0-9_-]` (otherwise the payment-required
  result carries `invalid_payload`); with `required: true` a missing id
  yields `payment_identifier_required`. When a cache is configured, the id
  is bound to a fingerprint of the matched requirements and the tool name
  (`X402.Extensions.PaymentIdentifier.fingerprint/2`) under a `"pid:"` key:
  reusing it for a different request yields `payment_identifier_conflict`,
  the same request proceeds normally. The pre-0.7.0 `"paymentIdentifier"`
  format is still accepted but deprecated (removed in 1.0.0) and emits
  `[:x402, :payment_identifier, :legacy]`.

  ## Builder code

  A payment echoing the
  [`builder-code` extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/builder_code.md)
  — whether or not `extensions` advertises it with
  `X402.Extensions.BuilderCode.extension/2` — is checked with
  `X402.Extensions.BuilderCode.validate_echo/2`: malformed codes or more
  than ten service codes yield `invalid_payload`, and an app code that
  differs from the advertised one is an extension echo mismatch. The codes
  travel to the facilitator inside the payload.

  ## Lifecycle hooks

  The `:hooks` module may define the optional resource-server callbacks of
  `X402.Hooks`. `c:X402.Hooks.on_protected_request/2` runs on every call
  with an `X402.Hooks.RequestContext` (`transport: :mcp`, the request, the
  tool name, and the advertised requirements and extensions) before the
  payment is inspected: it may continue with replaced requirements or
  extensions, halt with `{:halt, {status, body}}` (answered as an
  `isError` result carrying `body` in `structuredContent`), or halt with
  `{:halt, :skip_payment}` to run the handler unpaid (emitting
  `[:x402, :mcp, :pass_through]` with `reason: :hook_skipped`).
  `c:X402.Hooks.on_verified_payment_canceled/2` runs when a verified
  payment is not settled: the handler returned an error result
  (`reason: :handler_failed`), the handler raised or threw
  (`reason: :handler_raised`, with `:error`), or settlement failed
  (`reason: :settlement_failed`, with `:error`).
  """

  alias X402.Extensions.BuilderCode
  alias X402.Extensions.PaymentIdentifier
  alias X402.Extensions.PaymentIdentifier.Cache
  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.Facilitator
  alias X402.Facilitator.Error
  alias X402.Hooks
  alias X402.Hooks.Default
  alias X402.Hooks.RequestContext
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
  @payment_id_binding_prefix "pid:"

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

  @typedoc false
  @type claims :: %{payment_id: String.t(), binding: String.t() | nil}

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

    context =
      RequestContext.new(
        transport: :mcp,
        request: request,
        route: config,
        tool: config.tool,
        requirements: config.accepts,
        extensions: config.extensions
      )

    case Hooks.run_protected_request(config.hooks, context, %{tool: config.tool}) do
      {:cont, context} ->
        config = %{config | accepts: context.requirements, extensions: context.extensions}
        gate_call(request, config, context, handler)

      {:halt, :skip_payment} ->
        emit(:pass_through, %{tool: config.tool, reason: :hook_skipped})
        handler.(request)

      {:halt, {status, body}} ->
        emit(:payment_rejected, %{tool: config.tool, reason: {:hook_halted, status}})
        hook_halt_result(body)

      {:error, reason} ->
        emit(:payment_rejected, %{tool: config.tool, reason: reason})
        internal_error_result()
    end
  end

  @spec gate_call(map(), options(), RequestContext.t(), handler()) :: map()
  defp gate_call(request, config, context, handler) do
    case MCP.fetch_payment(request) do
      :error ->
        emit(:payment_required, %{tool: config.tool})
        payment_required_result(config, "Payment required to access this tool")

      {:ok, payment_payload} ->
        verify_and_execute(request, config, context, handler, payment_payload)
    end
  end

  # MCP has no status line; the halt body becomes the error result's text
  # (its "error" field when present) and travels whole as structuredContent.
  @spec hook_halt_result(map()) :: map()
  defp hook_halt_result(body) do
    text =
      case Utils.map_value(body, {"error", :error}) do
        message when is_binary(message) -> message
        _other -> "request rejected"
      end

    %{
      "isError" => true,
      "content" => [%{"type" => "text", "text" => text}],
      "structuredContent" => body
    }
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

  @spec verify_and_execute(map(), options(), RequestContext.t(), handler(), map()) :: map()
  defp verify_and_execute(request, config, context, handler, payment_payload) do
    with {:ok, requirements} <- validate_payment(payment_payload, config),
         {:ok, client_payment_id} <- client_payment_id(payment_payload, config),
         {:ok, payment_id} <- payment_id(payment_payload),
         {:ok, binding} <- bind_payment_id(config, client_payment_id, requirements),
         claims = %{payment_id: payment_id, binding: binding},
         :ok <- verify_and_claim(config, payment_payload, requirements, claims) do
      context = %{context | payload: payment_payload, matched_requirements: requirements}
      execute_and_settle(request, config, context, handler, payment_payload, requirements, claims)
    else
      {:error, reason} ->
        emit(:payment_rejected, %{tool: config.tool, reason: reason})
        rejection_result(config, reason)
    end
  end

  # A binding this call created is released when verification or the replay
  # claim fails, so a rejected attempt never strands the client's id.
  @spec verify_and_claim(options(), map(), map(), claims()) :: :ok | {:error, term()}
  defp verify_and_claim(config, payment_payload, requirements, claims) do
    with {:ok, verify_response} <- facilitator_verify(config, payment_payload, requirements),
         :ok <- ensure_verify_success(verify_response),
         :ok <- claim_or_fail(config.payment_identifier_cache, claims.payment_id) do
      :ok
    else
      {:error, reason} ->
        release_binding(config.payment_identifier_cache, claims.binding)
        {:error, reason}
    end
  end

  @spec client_payment_id(map(), options()) ::
          {:ok, String.t() | nil}
          | {:error,
             :invalid_payment_identifier
             | :payment_identifier_required
             | {:invalid_payment_identifier, term()}}
  defp client_payment_id(payment_payload, config) do
    payment_payload
    |> Utils.map_value({"extensions", :extensions})
    |> PaymentIdentifier.extract_id()
    |> case do
      {:ok, {:spec, payment_id}} ->
        {:ok, payment_id}

      {:ok, {:legacy, payment_id}} ->
        PaymentIdentifier.legacy_notice(:mcp)
        {:ok, payment_id}

      {:ok, nil} ->
        case PaymentIdentifier.required?(config.extensions) do
          true -> {:error, :payment_identifier_required}
          false -> {:ok, nil}
        end

      {:error, :invalid_payment_id} ->
        {:error, :invalid_payment_identifier}

      {:error, {:legacy, reason}} ->
        {:error, {:invalid_payment_identifier, reason}}
    end
  end

  @spec validate_payment(map(), options()) :: {:ok, map()} | {:error, term()}
  defp validate_payment(payment_payload, config) do
    with :ok <- ensure_v2_payload(payment_payload),
         {:ok, payment_payload} <- PaymentSignature.validate(payment_payload),
         {:ok, matched} <- find_matching_requirements(config.accepts, payment_payload),
         :ok <- validate_extensions(payment_payload, config.extensions),
         :ok <- validate_builder_code(payment_payload, config.extensions) do
      {:ok, matched}
    end
  end

  # The generic echo check only compares advertised keys; the builder-code
  # rules also apply when the client volunteers the extension unprompted.
  @spec validate_builder_code(map(), map()) ::
          :ok | {:error, :extension_echo_mismatch | {:invalid_builder_code, term()}}
  defp validate_builder_code(payload, advertised_extensions) do
    key = BuilderCode.extension_key()

    echoed =
      case Utils.map_value(payload, {"extensions", :extensions}) do
        %{} = extensions -> Utils.map_value(extensions, {key, :"builder-code"})
        _absent -> nil
      end

    case BuilderCode.validate_echo(echoed, Map.get(advertised_extensions, key)) do
      :ok -> :ok
      {:error, :builder_code_mismatch} -> {:error, :extension_echo_mismatch}
      {:error, reason} -> {:error, {:invalid_builder_code, reason}}
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

  @spec execute_and_settle(
          map(),
          options(),
          RequestContext.t(),
          handler(),
          map(),
          map(),
          claims()
        ) :: map()
  defp execute_and_settle(
         request,
         config,
         context,
         handler,
         payment_payload,
         requirements,
         claims
       ) do
    result = run_handler(config, context, handler, request, claims)

    case error_result?(result) do
      true ->
        # The tool itself failed: return its error unchanged, do not settle,
        # and release the claim so the client may retry with the same payment.
        release_claims(config, claims)
        notify_payment_canceled(config, context, %{reason: :handler_failed})
        result

      false ->
        settle_result(config, context, payment_payload, requirements, claims, result)
    end
  end

  @spec run_handler(options(), RequestContext.t(), handler(), map(), claims()) :: map()
  defp run_handler(config, context, handler, request, claims) do
    result =
      try do
        handler.(request)
      rescue
        exception ->
          release_claims(config, claims)
          notify_payment_canceled(config, context, %{reason: :handler_raised, error: exception})
          reraise exception, __STACKTRACE__
      catch
        kind, reason ->
          release_claims(config, claims)

          notify_payment_canceled(config, context, %{
            reason: :handler_raised,
            error: {kind, reason}
          })

          :erlang.raise(kind, reason, __STACKTRACE__)
      end

    case result do
      %{} = result_map ->
        result_map

      other ->
        release_claims(config, claims)

        raise ArgumentError,
              "expected the wrapped MCP tool handler to return a tool result map, " <>
                "got: #{inspect(other)}"
    end
  end

  @spec settle_result(options(), RequestContext.t(), map(), map(), claims(), map()) :: map()
  defp settle_result(config, context, payment_payload, requirements, claims, result) do
    with {:ok, settle_response} <- facilitator_settle(config, payment_payload, requirements),
         :ok <- ensure_settle_success(settle_response) do
      emit(:payment_verified, %{tool: config.tool})
      MCP.put_payment_response(result, settle_response.body)
    else
      {:error, reason} ->
        release_claims(config, claims)
        emit(:payment_rejected, %{tool: config.tool, reason: reason})
        notify_payment_canceled(config, context, %{reason: :settlement_failed, error: reason})
        settlement_failed_result(config, reason)
    end
  end

  @spec notify_payment_canceled(options(), RequestContext.t(), map()) :: :ok
  defp notify_payment_canceled(config, context, metadata) do
    Hooks.run_verified_payment_canceled(
      config.hooks,
      context,
      Map.put(metadata, :tool, config.tool)
    )
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
  defp rejection_message({:invalid_builder_code, _reason}), do: "invalid_payload"
  defp rejection_message(:invalid_payment_identifier), do: "invalid_payload"
  defp rejection_message(:payment_identifier_required), do: "payment_identifier_required"
  defp rejection_message(:payment_identifier_conflict), do: "payment_identifier_conflict"

  defp rejection_message({:invalid_payment_identifier, _reason}),
    do: "invalid payment identifier extension"

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

  @spec release_claims(options(), claims()) :: :ok
  defp release_claims(config, claims) do
    release_claim(config.payment_identifier_cache, claims.payment_id)
    release_binding(config.payment_identifier_cache, claims.binding)
    :ok
  end

  @spec release_claim(Cache.adapter() | nil, String.t()) :: Cache.write_result()
  defp release_claim(nil, _payment_id), do: :ok
  defp release_claim(adapter, payment_id), do: Cache.delete(adapter, payment_id)

  # Binds the client's payment id to the fingerprint of the matched
  # requirements plus the tool name. Returns the binding key when this call
  # created it (and owns its release); nil when there is no id, no cache, or
  # an identical binding already exists. Adapter failures other than a
  # duplicate are infrastructure trouble and fail closed.
  @spec bind_payment_id(options(), String.t() | nil, map()) ::
          {:ok, String.t() | nil}
          | {:error, :payment_identifier_conflict | {:claim_failed, term()}}
  defp bind_payment_id(%{payment_identifier_cache: nil}, _client_payment_id, _requirements),
    do: {:ok, nil}

  defp bind_payment_id(_config, nil, _requirements), do: {:ok, nil}

  defp bind_payment_id(config, client_payment_id, requirements) do
    key = @payment_id_binding_prefix <> client_payment_id
    fingerprint = PaymentIdentifier.fingerprint(requirements, %{tool: config.tool})

    case Cache.put_new(config.payment_identifier_cache, key, {:bound, fingerprint}) do
      :ok -> {:ok, key}
      {:error, :already_exists} -> compare_binding(config, key, fingerprint)
      {:error, reason} -> {:error, {:claim_failed, reason}}
    end
  end

  @spec compare_binding(options(), String.t(), String.t()) ::
          {:ok, nil} | {:error, :payment_identifier_conflict | {:claim_failed, term()}}
  defp compare_binding(config, key, fingerprint) do
    case Cache.get(config.payment_identifier_cache, key) do
      {:hit, {:bound, ^fingerprint}} -> {:ok, nil}
      {:hit, _other} -> {:error, :payment_identifier_conflict}
      :miss -> {:ok, nil}
      {:error, reason} -> {:error, {:claim_failed, reason}}
    end
  end

  @spec release_binding(Cache.adapter() | nil, String.t() | nil) :: Cache.write_result()
  defp release_binding(_adapter, nil), do: :ok
  defp release_binding(adapter, key), do: Cache.delete(adapter, key)

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

  @spec emit(:pass_through | :payment_required | :payment_verified | :payment_rejected, map()) ::
          :ok
  defp emit(event, metadata) do
    :telemetry.execute([:x402, :mcp, event], %{count: 1}, metadata)
  end
end
