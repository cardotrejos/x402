if Code.ensure_loaded?(Plug) and Code.ensure_loaded?(Plug.Conn) do
  defmodule X402.Plug.PaymentGate do
    @moduledoc """
    Plug middleware that gates configured routes behind x402 v2 payment verification.

    For matching routes:

    1. Requests without a `PAYMENT-SIGNATURE` header receive **402** with a
       Base64-encoded `PAYMENT-REQUIRED` header (`PaymentRequired` v2 schema).
    2. Requests with `PAYMENT-SIGNATURE` are decoded as `PaymentPayload` v2.
    3. `PaymentPayload.accepted` and echoed extensions are matched against the
       complete requirements advertised by the route.
    4. Cheap local pre-checks run on the EIP-3009-style authorization object
       (payTo binding, exact amount equality, validity window) so certain
       mismatches answer 402 without a facilitator round-trip — see the
       `:local_prechecks` option.
    5. Matched requirements are verified before the protected handler runs.
    6. Successful handler responses are settled immediately before they are
       sent. Successful settlements attach a `PAYMENT-RESPONSE` header and assign
       `:x402_payment_payload` / `:x402_payment_requirements` on the conn.

    HTTP status mapping (HTTP transport v2):

    - **402** — payment required, no matching requirements, or payment failed
    - **400** — malformed / invalid payment payload (including wrong `x402Version`)
    - **500** — facilitator transport failures or malformed facilitator responses

    See the official
    [x402 v2 specification](https://github.com/x402-foundation/x402/blob/main/specs/x402-specification-v2.md)
    and
    [HTTP transport](https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/http.md).

    ## Browser paywall

    With `paywall: X402.Paywall.Default` (or any `X402.Paywall`
    implementation), pre-handler 402 responses to browser page loads —
    `Accept` containing `text/html` and `User-Agent` containing `Mozilla`,
    the heuristic shared by the reference x402 middlewares — carry a
    human-usable HTML page instead of the `{}` JSON body. The
    `PAYMENT-REQUIRED` header is identical on both forms and all other
    responses are unchanged. See the "Browser Paywall" guide.

    ## Replay protection

    When `:payment_identifier_cache` is configured, the gate claims the SHA-256
    hash of the raw `PAYMENT-SIGNATURE` header through the
    `X402.Extensions.PaymentIdentifier.Cache` behaviour before settling.
    Duplicate proofs are rejected with **402** and the claim is released when
    the protected handler responds with a status >= 400 or settlement fails,
    so clients may retry a payment whose resource was never delivered.

    The `:claim_order` option controls when the claim is taken relative to
    facilitator verification:

    * `:after_verify` (default) — the claim is taken only after the
      facilitator has verified the proof. A replayed proof can never strand a
      claim through verification, but **every** replayed request pays a full
      facilitator verify round-trip before it is rejected, so a replay storm
      translates directly into facilitator load.
    * `:before_verify` — the claim is taken before contacting the
      facilitator and released again if verification fails for any reason.
      Duplicates are rejected locally without any facilitator call, which
      sheds replay-storm load. The trade-off: a node that crashes between
      claiming and releasing (now including the verify round-trip window)
      strands the claim until the cache TTL expires, so a legitimate retry of
      that same payment is rejected with 402 until then.

    Both orderings keep the existing release semantics: the claim is released
    when the handler responds with a status >= 400 or settlement fails, and a
    duplicate claim is rejected with the same 402 duplicate-payment error.

    > #### Clustered deployments can serve one payment twice {: .warning}
    >
    > The default `X402.Extensions.PaymentIdentifier.ETSCache` adapter is
    > **per-node**: every node in a cluster keeps its own claim table, so a
    > replayed proof load-balanced onto two nodes runs the protected handler on
    > each of them even though only one settlement can ultimately succeed. If
    > you deploy more than one node, configure a shared-store adapter instead —
    > see the "Writing a distributed adapter" section in
    > `X402.Extensions.PaymentIdentifier.Cache` for a Redis sketch.
    """

    @behaviour Plug

    alias X402.Extensions.PaymentIdentifier.Cache
    alias X402.Extensions.PaymentIdentifier.ETSCache
    alias X402.Facilitator
    alias X402.Facilitator.Error
    alias X402.Hooks
    alias X402.Hooks.Default
    alias X402.PaymentRequired
    alias X402.PaymentRequirements
    alias X402.PaymentResponse
    alias X402.PaymentSignature
    alias X402.Paywall
    alias X402.Utils

    require Logger

    import Plug.Conn,
      only: [
        assign: 3,
        delete_resp_header: 2,
        get_req_header: 2,
        halt: 1,
        put_resp_content_type: 2,
        put_resp_header: 3,
        register_before_send: 2,
        resp: 3,
        send_resp: 1
      ]

    @http_methods [:any, :delete, :get, :head, :options, :patch, :post, :put, :trace]
    @route_schemes ["exact", "upto"]
    @x402_version 2
    @supported_payment_flow "authorization"
    @settlement_amount_private :x402_settlement_amount
    @default_max_timeout_seconds 60
    # Mirrors the 6-second buffer the reference facilitators apply to
    # validBefore so a payment does not expire mid-settlement.
    @precheck_time_buffer_seconds 6
    @default_description "Payment required"
    @default_mime_type "application/json"

    # Reasons that map to HTTP 400 Invalid Request (HTTP transport v2).
    @invalid_request_reasons [
      :invalid_payment_header,
      :invalid_base64,
      :invalid_json,
      :payload_too_large,
      :invalid_payload,
      :invalid_x402_version
    ]

    @accept_option_schema [
      scheme: [
        type: {:in, @route_schemes},
        default: "exact",
        doc: "Payment scheme (`exact` or `upto`)."
      ],
      price: [
        type: {:custom, __MODULE__, :validate_atomic_amount, []},
        required: true,
        doc: """
        Payment amount in atomic token units (PaymentRequirements `amount`).
        For `exact` this is the required amount; for `upto` it is the maximum
        authorized amount.
        """
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

    @route_schema [
      method: [
        type: {:in, @http_methods},
        required: true,
        doc: "HTTP method for the route (`:any` matches all methods)."
      ],
      path: [
        type: :string,
        required: true,
        doc: "Route path, supporting exact matches and `*` globs (for example `/api/*`)."
      ],
      accepts: [
        type: {:list, {:map, @accept_option_schema}},
        default: [],
        doc: """
        Payment options advertised in `PAYMENT-REQUIRED.accepts`. When empty,
        a single option is built from the top-level `:scheme`, `:price`,
        `:network`, `:asset`, and `:pay_to` fields.
        """
      ],
      scheme: [
        type: {:in, @route_schemes},
        default: "exact",
        doc: "Single-option scheme (used when `:accepts` is empty)."
      ],
      price: [
        type: {:custom, __MODULE__, :validate_atomic_amount, []},
        doc: "Single-option amount (required when `:accepts` is empty)."
      ],
      network: [
        type: :string,
        doc: "Single-option CAIP-2 network (required when `:accepts` is empty)."
      ],
      asset: [
        type: :string,
        doc: "Single-option asset (required when `:accepts` is empty)."
      ],
      pay_to: [
        type: :string,
        doc: "Single-option payTo (required when `:accepts` is empty)."
      ],
      description: [
        type: :string,
        default: @default_description,
        doc: "ResourceInfo.description."
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
      max_timeout_seconds: [
        type: :pos_integer,
        default: @default_max_timeout_seconds,
        doc: "Default maxTimeoutSeconds for single-option routes."
      ],
      extra: [
        type: {:custom, __MODULE__, :validate_extra_map, []},
        default: %{},
        doc: "Default extra map for single-option routes."
      ],
      extensions: [
        type: {:custom, __MODULE__, :validate_extra_map, []},
        default: %{},
        doc: "Protocol extensions advertised in PaymentRequired.extensions."
      ]
    ]

    @options_schema [
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
        Optional idempotency cache used for replay protection. Accepts either
        an `ETSCache` server pid/name (the default adapter), or a
        `{module, cache}` adapter tuple where `module` implements
        `X402.Extensions.PaymentIdentifier.Cache` and `cache` is passed to its
        callbacks (for example `{MyApp.RedisPaymentCache, MyApp.Redis}`).
        When set, the plug performs an atomic claim (via the adapter's
        `put_new/3`) on the payment proof hash before settling, preventing
        concurrent requests from double-settling the same payment. The default
        ETS adapter is per-node — see the "Replay protection" section above
        for the clustering hazard.
        """
      ],
      claim_order: [
        type: {:in, [:after_verify, :before_verify]},
        default: :after_verify,
        doc: """
        When the replay claim is taken relative to facilitator verification.
        `:after_verify` (default) never strands a claim on verification but
        pays a facilitator verify round-trip per replayed request;
        `:before_verify` rejects duplicates before contacting the facilitator
        (shedding replay-storm load) and releases the claim if verification
        fails, at the cost that a node crash during verification strands the
        claim until the cache TTL expires. Only meaningful when
        `:payment_identifier_cache` is configured.
        """
      ],
      routes: [
        type: {:list, {:custom, __MODULE__, :validate_route, []}},
        required: true,
        doc: "Route gate definitions (see route options below)."
      ],
      local_prechecks: [
        type: :boolean,
        default: true,
        doc: """
        Run cheap local checks on the EIP-3009-style `payload.authorization`
        object before calling the facilitator: `to` must equal the route's
        `pay_to`, `value` must equal the advertised amount for `"exact"`
        routes, and the `validAfter`/`validBefore` window must cover now (with
        a #{@precheck_time_buffer_seconds}s settlement buffer). Fields absent
        from the payload are skipped, so schemes with other payload shapes
        pass through untouched. Failures answer 402 without a facilitator
        round-trip.
        """
      ],
      paywall: [
        type: {:or, [nil, {:custom, Paywall, :validate_module, []}]},
        default: nil,
        doc: """
        Optional browser paywall renderer implementing `X402.Paywall`
        (`X402.Paywall.Default` ships a self-contained wallet-enabled page).
        When set, pre-handler 402 responses to requests that look like a
        browser page load — `Accept` header containing `text/html` **and**
        `User-Agent` containing `Mozilla`, mirroring the reference x402
        middlewares — carry the rendered HTML body instead of the default
        `{}` JSON body. The `PAYMENT-REQUIRED` header is identical on both
        forms, and every other response (API clients, absent `Accept`
        headers, 400/500 statuses, post-handler settlement failures) is
        byte-identical to running without `:paywall`.
        """
      ]
    ]

    @typedoc "Claim ordering relative to facilitator verification."
    @type claim_order :: :after_verify | :before_verify

    @typedoc "Configuration map produced by `init/1`."
    @type options :: %{
            facilitator: Facilitator.server(),
            hooks: module(),
            payment_identifier_cache: Cache.adapter() | nil,
            claim_order: claim_order(),
            routes: [compiled_route()],
            local_prechecks: boolean(),
            paywall: module() | nil
          }

    @typedoc false
    @type payment_accept :: %{
            scheme: String.t(),
            price: String.t(),
            network: String.t(),
            asset: String.t(),
            pay_to: String.t(),
            max_timeout_seconds: pos_integer(),
            extra: map()
          }

    @typedoc false
    @type compiled_route :: %{
            method: atom(),
            matcher: :exact | :glob,
            path: String.t(),
            glob_regex: Regex.t() | nil,
            accepts: [payment_accept()],
            description: String.t(),
            mime_type: String.t(),
            service_name: String.t() | nil,
            tags: [String.t()],
            icon_url: String.t() | nil,
            extensions: map()
          }

    @typedoc false
    @type settlement_context :: %{
            facilitator: Facilitator.server(),
            hooks: module(),
            payment_identifier_cache: Cache.adapter() | nil,
            payment_id: String.t(),
            payment_payload: map(),
            requirements: map(),
            route: compiled_route(),
            request_method: atom(),
            request_path: String.t()
          }

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

    @doc false
    @spec validate_payment_identifier_cache(term()) ::
            {:ok, Cache.adapter() | nil} | {:error, String.t()}
    def validate_payment_identifier_cache(nil), do: {:ok, nil}

    # {:global, name} and {:via, registry, term} are unambiguous GenServer
    # names, never adapter tuples — route them to the default ETSCache adapter
    # like a bare pid/name.
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

    @doc false
    @spec validate_route(term()) :: {:ok, map()} | {:error, String.t()}
    def validate_route(route) when is_map(route) do
      with {:ok, keyword_route} <- map_to_keyword(route),
           {:ok, validated} <- validate_route_options(keyword_route),
           validated_map = Map.new(validated),
           :ok <- ensure_accepts_source(validated_map),
           :ok <- ensure_supported_payment_flow(validated_map) do
        {:ok, validated_map}
      end
    end

    def validate_route(_route), do: {:error, "expected a route map"}

    @doc since: "0.1.0"
    @doc """
    Validates and compiles `X402.Plug.PaymentGate` options.

    ## Options

    #{NimbleOptions.docs(@options_schema)}

    ### Route options

    #{NimbleOptions.docs(@route_schema)}

    ### Accept option fields (inside `:accepts`)

    #{NimbleOptions.docs(@accept_option_schema)}
    """
    @spec init(keyword()) :: options()
    def init(opts) when is_list(opts) do
      validated_opts = NimbleOptions.validate!(opts, @options_schema)

      cache = Keyword.get(validated_opts, :payment_identifier_cache)

      if is_nil(cache) do
        IO.warn(
          "[X402.Plug.PaymentGate] payment_identifier_cache is not configured. " <>
            "Duplicate payment proofs will NOT be detected — your deployment is " <>
            "vulnerable to double-settlement of concurrent identical requests. " <>
            "Pass `payment_identifier_cache: pid_or_name` to enable idempotency.",
          __ENV__
        )
      end

      %{
        facilitator: Keyword.fetch!(validated_opts, :facilitator),
        hooks: Keyword.fetch!(validated_opts, :hooks),
        payment_identifier_cache: cache,
        claim_order: Keyword.fetch!(validated_opts, :claim_order),
        routes:
          validated_opts
          |> Keyword.fetch!(:routes)
          |> Enum.map(&compile_route/1),
        local_prechecks: Keyword.fetch!(validated_opts, :local_prechecks),
        paywall: Keyword.fetch!(validated_opts, :paywall)
      }
    end

    @doc since: "0.4.0"
    @doc """
    Stores the actual atomic amount to settle for an `"upto"` route.

    Call this from the protected handler after resource consumption is known.
    When omitted, the route's advertised maximum is settled.

    ## Examples

        iex> conn = Plug.Test.conn(:get, "/paid")
        iex> {:ok, conn} = X402.Plug.PaymentGate.put_settlement_amount(conn, "7500")
        iex> conn.private[:x402_settlement_amount]
        "7500"

        iex> X402.Plug.PaymentGate.put_settlement_amount(Plug.Test.conn(:get, "/paid"), "1.5")
        {:error, :invalid_settlement_amount}
    """
    @spec put_settlement_amount(Plug.Conn.t(), String.t() | non_neg_integer()) ::
            {:ok, Plug.Conn.t()} | {:error, :invalid_settlement_amount}
    def put_settlement_amount(%Plug.Conn{} = conn, amount) do
      case normalize_atomic_amount(amount) do
        {:ok, normalized} ->
          {:ok, Plug.Conn.put_private(conn, @settlement_amount_private, normalized)}

        :error ->
          {:error, :invalid_settlement_amount}
      end
    end

    @doc since: "0.1.0"
    @doc """
    Gates matching requests behind x402 v2 payment verification.
    """
    @spec call(Plug.Conn.t(), options()) :: Plug.Conn.t()
    def call(%Plug.Conn{} = conn, %{routes: routes} = opts) do
      if is_nil(opts.payment_identifier_cache), do: warn_no_idempotency_cache_once()

      request_path = decoded_request_path(conn)
      request_method = normalize_method(conn.method)

      case match_route(routes, request_method, request_path) do
        nil ->
          emit(:pass_through, %{method: request_method, path: request_path})
          conn

        route ->
          handle_payment_gate(conn, opts, route, request_method, request_path)
      end
    end

    @spec handle_payment_gate(Plug.Conn.t(), options(), compiled_route(), atom(), String.t()) ::
            Plug.Conn.t()
    defp handle_payment_gate(conn, opts, route, request_method, request_path) do
      case payment_header(conn) do
        :missing ->
          emit(:payment_required, %{method: request_method, path: request_path, route: route.path})

          payment_error_response(
            conn,
            route,
            request_path,
            "PAYMENT-SIGNATURE header is required",
            status: 402,
            paywall: opts.paywall
          )

        {:ok, header} ->
          verify_and_prepare_settlement(conn, opts, route, request_method, request_path, header)

        {:error, reason} ->
          emit(:payment_rejected, %{
            method: request_method,
            path: request_path,
            route: route.path,
            reason: reason
          })

          payment_error_response(
            conn,
            route,
            request_path,
            rejection_error(reason),
            status: status_for_reason(reason),
            reason: reason,
            paywall: opts.paywall
          )
      end
    end

    @spec verify_and_prepare_settlement(
            Plug.Conn.t(),
            options(),
            compiled_route(),
            atom(),
            String.t(),
            String.t()
          ) :: Plug.Conn.t()
    defp verify_and_prepare_settlement(conn, opts, route, request_method, request_path, header) do
      accepts = route_accepts(route)
      payment_id = :crypto.hash(:sha256, header) |> Base.encode16(case: :lower)

      with {:ok, payment_payload, requirements} <-
             decode_and_validate_payment(header, accepts, route.extensions),
           :ok <- run_local_prechecks(opts.local_prechecks, payment_payload, requirements),
           :ok <- claim_and_verify(opts, payment_id, payment_payload, requirements) do
        settlement_context = %{
          facilitator: opts.facilitator,
          hooks: opts.hooks,
          payment_identifier_cache: opts.payment_identifier_cache,
          payment_id: payment_id,
          payment_payload: payment_payload,
          requirements: requirements,
          route: route,
          request_method: request_method,
          request_path: request_path
        }

        conn
        |> assign(:x402_payment_payload, payment_payload)
        |> assign(:x402_payment_requirements, requirements)
        |> register_before_send(fn response_conn ->
          settle_after_resource(response_conn, settlement_context)
        end)
      else
        {:error, reason} ->
          emit(:payment_rejected, %{
            method: request_method,
            path: request_path,
            route: route.path,
            reason: reason
          })

          payment_error_response(
            conn,
            route,
            request_path,
            rejection_error(reason),
            status: status_for_reason(reason),
            reason: reason,
            paywall: opts.paywall
          )
      end
    end

    @spec settle_after_resource(Plug.Conn.t(), settlement_context()) :: Plug.Conn.t()
    defp settle_after_resource(conn, settlement_context) do
      case successful_resource_response?(conn) do
        true ->
          settle_successful_resource(conn, settlement_context)

        false ->
          release_claim(
            settlement_context.payment_identifier_cache,
            settlement_context.payment_id
          )

          conn
      end
    end

    @spec successful_resource_response?(Plug.Conn.t()) :: boolean()
    defp successful_resource_response?(%Plug.Conn{status: status}) when is_integer(status),
      do: status < 400

    defp successful_resource_response?(_conn), do: false

    @spec settle_successful_resource(Plug.Conn.t(), settlement_context()) :: Plug.Conn.t()
    defp settle_successful_resource(conn, settlement_context) do
      case settlement_requirements(conn, settlement_context.requirements) do
        {:ok, requirements} ->
          perform_settlement(conn, settlement_context, requirements)

        {:error, reason} ->
          fail_settlement(conn, settlement_context, reason, reason)
      end
    end

    @spec perform_settlement(Plug.Conn.t(), settlement_context(), map()) :: Plug.Conn.t()
    defp perform_settlement(conn, settlement_context, requirements) do
      result =
        settle_with_hooks(
          settlement_context.facilitator,
          settlement_context.payment_payload,
          requirements,
          settlement_context.hooks
        )

      case result do
        {:ok, settle_response} ->
          complete_successful_settlement(
            conn,
            settle_response,
            settlement_context.route,
            settlement_context.request_method,
            settlement_context.request_path
          )

        {:error, reason, settle_body} ->
          fail_settlement(conn, settlement_context, reason, settle_body || reason)
      end
    end

    @spec fail_settlement(Plug.Conn.t(), settlement_context(), term(), term()) :: Plug.Conn.t()
    defp fail_settlement(conn, settlement_context, reason, response_reason) do
      release_claim(
        settlement_context.payment_identifier_cache,
        settlement_context.payment_id
      )

      reject_settlement(
        conn,
        settlement_context.route,
        settlement_context.request_method,
        settlement_context.request_path,
        reason,
        response_reason
      )
    end

    @spec complete_successful_settlement(
            Plug.Conn.t(),
            map(),
            compiled_route(),
            atom(),
            String.t()
          ) :: Plug.Conn.t()
    defp complete_successful_settlement(
           conn,
           settle_response,
           route,
           request_method,
           request_path
         ) do
      case put_payment_response_header(conn, settle_response.body) do
        {:ok, response_conn} ->
          emit(:payment_verified, %{
            method: request_method,
            path: request_path,
            route: route.path
          })

          response_conn

        {:error, reason} ->
          emit(:payment_rejected, %{
            method: request_method,
            path: request_path,
            route: route.path,
            reason: reason
          })

          internal_error_conn(conn)
      end
    end

    @spec reject_settlement(
            Plug.Conn.t(),
            compiled_route(),
            atom(),
            String.t(),
            term(),
            term()
          ) :: Plug.Conn.t()
    defp reject_settlement(
           conn,
           route,
           request_method,
           request_path,
           reason,
           response_reason
         ) do
      emit(:payment_rejected, %{
        method: request_method,
        path: request_path,
        route: route.path,
        reason: reason
      })

      payment_error_conn(
        conn,
        route,
        request_path,
        rejection_error(reason),
        status: status_for_reason(reason),
        reason: response_reason
      )
    end

    @spec settlement_requirements(Plug.Conn.t(), map()) ::
            {:ok, map()} | {:error, {:invalid_settlement_amount, atom()}}
    defp settlement_requirements(conn, requirements) do
      case Utils.map_value(requirements, {"scheme", :scheme}) do
        "upto" -> upto_settlement_requirements(conn, requirements)
        _scheme -> {:ok, requirements}
      end
    end

    @spec upto_settlement_requirements(Plug.Conn.t(), map()) ::
            {:ok, map()} | {:error, {:invalid_settlement_amount, atom()}}
    defp upto_settlement_requirements(conn, requirements) do
      authorized_amount = Utils.map_value(requirements, {"amount", :amount})
      requested_amount = Map.get(conn.private, @settlement_amount_private, authorized_amount)

      with {:ok, normalized_authorized} <- normalize_settlement_amount(authorized_amount),
           {:ok, normalized_requested} <- normalize_settlement_amount(requested_amount),
           :ok <-
             ensure_settlement_not_above_authorized(normalized_requested, normalized_authorized) do
        {:ok, Utils.map_put(requirements, {"amount", :amount}, normalized_requested)}
      end
    end

    @spec normalize_settlement_amount(term()) ::
            {:ok, String.t()} | {:error, {:invalid_settlement_amount, :invalid_format}}
    defp normalize_settlement_amount(amount) do
      case normalize_atomic_amount(amount) do
        {:ok, normalized} -> {:ok, normalized}
        :error -> {:error, {:invalid_settlement_amount, :invalid_format}}
      end
    end

    @spec normalize_atomic_amount(term()) :: {:ok, String.t()} | :error
    defp normalize_atomic_amount(amount) when is_integer(amount) and amount >= 0,
      do: {:ok, Integer.to_string(amount)}

    defp normalize_atomic_amount(amount) when is_binary(amount) do
      case Regex.match?(~r/^\d+$/, amount) do
        true -> {:ok, amount}
        false -> :error
      end
    end

    defp normalize_atomic_amount(_amount), do: :error

    @spec ensure_settlement_not_above_authorized(String.t(), String.t()) ::
            :ok | {:error, {:invalid_settlement_amount, :exceeds_authorized_amount}}
    defp ensure_settlement_not_above_authorized(requested_amount, authorized_amount) do
      requested = canonical_atomic_amount(requested_amount)
      authorized = canonical_atomic_amount(authorized_amount)

      case byte_size(requested) < byte_size(authorized) or
             (byte_size(requested) == byte_size(authorized) and requested <= authorized) do
        true -> :ok
        false -> {:error, {:invalid_settlement_amount, :exceeds_authorized_amount}}
      end
    end

    @spec canonical_atomic_amount(String.t()) :: String.t()
    defp canonical_atomic_amount(amount) do
      case String.trim_leading(amount, "0") do
        "" -> "0"
        canonical -> canonical
      end
    end

    @spec settle_with_hooks(
            Facilitator.server(),
            map(),
            map(),
            module()
          ) ::
            {:ok, map()}
            | {:error, term(), term()}
    defp settle_with_hooks(facilitator, payment_payload, requirements, hooks) do
      case facilitator_settle(facilitator, payment_payload, requirements, hooks) do
        {:ok, settle_response} when is_map(settle_response) ->
          case ensure_settle_success(settle_response) do
            :ok -> {:ok, settle_response}
            {:error, reason} -> {:error, reason, Map.get(settle_response, :body)}
          end

        {:error, reason} ->
          {:error, reason, nil}
      end
    end

    # Orders the replay claim relative to facilitator verification.
    #
    # :after_verify — verify first, then claim. Verification failures never
    # touch the cache, but replayed requests pay a verify round-trip each.
    #
    # :before_verify — claim first, rejecting duplicates without contacting
    # the facilitator; release the claim when verification fails for any
    # reason so the payer can retry.
    @spec claim_and_verify(options(), String.t(), map(), map()) :: :ok | {:error, term()}
    defp claim_and_verify(%{claim_order: :after_verify} = opts, payment_id, payload, requirements) do
      with :ok <- verify_payment(opts, payload, requirements) do
        claim_payment(opts.payment_identifier_cache, payment_id)
      end
    end

    defp claim_and_verify(
           %{claim_order: :before_verify} = opts,
           payment_id,
           payload,
           requirements
         ) do
      with :ok <- claim_payment(opts.payment_identifier_cache, payment_id) do
        verify_with_claim_release(opts, payment_id, payload, requirements)
      end
    end

    # A slow or unreachable facilitator EXITS the caller (GenServer.call
    # timeout / :noproc) rather than returning an error tuple. Under
    # :before_verify the claim is already taken at that point — release it
    # before letting the exit propagate, or the payer's legitimate retry is
    # rejected as a duplicate until the cache TTL expires.
    @spec verify_with_claim_release(options(), String.t(), map(), map()) ::
            :ok | {:error, term()}
    defp verify_with_claim_release(opts, payment_id, payload, requirements) do
      case verify_payment(opts, payload, requirements) do
        :ok ->
          :ok

        {:error, reason} ->
          release_claim(opts.payment_identifier_cache, payment_id)
          {:error, reason}
      end
    catch
      :exit, reason ->
        release_claim(opts.payment_identifier_cache, payment_id)
        exit(reason)
    end

    @spec verify_payment(options(), map(), map()) :: :ok | {:error, term()}
    defp verify_payment(opts, payment_payload, requirements) do
      with {:ok, verify_response} <-
             facilitator_verify(opts.facilitator, payment_payload, requirements, opts.hooks) do
        ensure_verify_success(verify_response)
      end
    end

    @spec claim_payment(Cache.adapter() | nil, String.t()) :: Cache.put_new_result()
    defp claim_payment(nil, _payment_id), do: :ok

    defp claim_payment(adapter, payment_id) do
      Cache.put_new(adapter, payment_id, :verified)
    end

    @spec release_claim(Cache.adapter() | nil, String.t()) :: Cache.write_result()
    defp release_claim(nil, _payment_id), do: :ok
    defp release_claim(adapter, payment_id), do: Cache.delete(adapter, payment_id)

    @spec facilitator_verify(Facilitator.server(), map(), map(), module()) ::
            Facilitator.response()
    defp facilitator_verify(facilitator, payment_payload, requirements, Default) do
      Facilitator.verify(facilitator, payment_payload, requirements)
    end

    defp facilitator_verify(facilitator, payment_payload, requirements, hooks) do
      Facilitator.verify(facilitator, payment_payload, requirements, hooks)
    end

    @spec facilitator_settle(Facilitator.server(), map(), map(), module()) ::
            Facilitator.response()
    defp facilitator_settle(facilitator, payment_payload, requirements, Default) do
      Facilitator.settle(facilitator, payment_payload, requirements)
    end

    defp facilitator_settle(facilitator, payment_payload, requirements, hooks) do
      Facilitator.settle(facilitator, payment_payload, requirements, hooks)
    end

    @spec ensure_accepts_source(map()) :: :ok | {:error, String.t()}
    defp ensure_accepts_source(%{accepts: accepts}) when is_list(accepts) and accepts != [] do
      :ok
    end

    defp ensure_accepts_source(route) do
      missing =
        Enum.reject([:price, :network, :asset, :pay_to], fn key ->
          value = Map.get(route, key)
          is_binary(value) and value != ""
        end)

      case missing do
        [] ->
          :ok

        keys ->
          {:error,
           "route requires either non-empty :accepts or top-level fields #{inspect(keys)}"}
      end
    end

    @spec validate_route_options(keyword()) :: {:ok, keyword()} | {:error, String.t()}
    defp validate_route_options(route) do
      case NimbleOptions.validate(route, @route_schema) do
        {:ok, validated} -> {:ok, validated}
        {:error, error} -> {:error, Exception.message(error)}
      end
    end

    @spec ensure_supported_payment_flow(map()) :: :ok | {:error, String.t()}
    defp ensure_supported_payment_flow(%{accepts: accepts})
         when is_list(accepts) and accepts != [] do
      Enum.reduce_while(accepts, :ok, fn accept, :ok ->
        case ensure_authorization_flow(Map.get(accept, :extra, %{})) do
          :ok -> {:cont, :ok}
          {:error, reason} -> {:halt, {:error, reason}}
        end
      end)
    end

    defp ensure_supported_payment_flow(route) do
      ensure_authorization_flow(Map.get(route, :extra, %{}))
    end

    @spec ensure_authorization_flow(map()) :: :ok | {:error, String.t()}
    defp ensure_authorization_flow(extra) do
      case Utils.map_value(extra, {"paymentFlow", :paymentFlow}) do
        nil -> :ok
        @supported_payment_flow -> :ok
        flow -> {:error, "unsupported payment flow: #{inspect(flow)}"}
      end
    end

    @spec compile_route(map()) :: compiled_route()
    defp compile_route(%{} = route) do
      normalized_path = normalize_path(Map.fetch!(route, :path))
      matcher = path_matcher(normalized_path)

      accepts =
        case Map.get(route, :accepts, []) do
          list when is_list(list) and list != [] ->
            Enum.map(list, &compile_accept/1)

          _empty ->
            [
              compile_accept(%{
                scheme: Map.get(route, :scheme, "exact"),
                price: Map.fetch!(route, :price),
                network: Map.fetch!(route, :network),
                asset: Map.fetch!(route, :asset),
                pay_to: Map.fetch!(route, :pay_to),
                max_timeout_seconds:
                  Map.get(route, :max_timeout_seconds, @default_max_timeout_seconds),
                extra: Map.get(route, :extra, %{})
              })
            ]
        end

      %{
        method: Map.fetch!(route, :method),
        matcher: matcher,
        path: normalized_path,
        glob_regex: glob_regex(matcher, normalized_path),
        accepts: accepts,
        description: Map.get(route, :description, @default_description),
        mime_type: Map.get(route, :mime_type, @default_mime_type),
        service_name: Map.get(route, :service_name),
        tags: Map.get(route, :tags, []),
        icon_url: Map.get(route, :icon_url),
        extensions: stringify_keys(Map.get(route, :extensions, %{}))
      }
    end

    @spec compile_accept(map()) :: payment_accept()
    defp compile_accept(accept) do
      %{
        scheme: Map.get(accept, :scheme, "exact"),
        price: Map.fetch!(accept, :price),
        network: Map.fetch!(accept, :network),
        asset: Map.fetch!(accept, :asset),
        pay_to: Map.fetch!(accept, :pay_to),
        max_timeout_seconds: Map.get(accept, :max_timeout_seconds, @default_max_timeout_seconds),
        extra: Map.get(accept, :extra, %{})
      }
    end

    @spec path_matcher(String.t()) :: :exact | :glob
    defp path_matcher(path) do
      case String.contains?(path, "*") do
        true -> :glob
        false -> :exact
      end
    end

    @spec glob_regex(:exact | :glob, String.t()) :: Regex.t() | nil
    defp glob_regex(:exact, _path), do: nil

    defp glob_regex(:glob, path) do
      ("^" <> (path |> Regex.escape() |> String.replace("\\*", ".*")) <> "$")
      |> Regex.compile!()
    end

    @spec match_route([compiled_route()], atom(), String.t()) :: compiled_route() | nil
    defp match_route(routes, request_method, request_path) do
      Enum.find(routes, fn route ->
        method_matches?(route.method, request_method) and path_matches?(route, request_path)
      end)
    end

    @spec method_matches?(atom(), atom()) :: boolean()
    defp method_matches?(:any, _request_method), do: true
    defp method_matches?(method, request_method), do: method == request_method

    @spec path_matches?(compiled_route(), String.t()) :: boolean()
    defp path_matches?(%{matcher: :exact, path: path}, request_path), do: path == request_path

    defp path_matches?(%{matcher: :glob, glob_regex: regex}, request_path),
      do: Regex.match?(regex, request_path)

    @spec payment_header(Plug.Conn.t()) ::
            :missing | {:ok, String.t()} | {:error, :invalid_payment_header}
    defp payment_header(conn) do
      case get_req_header(conn, "payment-signature") do
        [] -> :missing
        [header | _] when is_binary(header) and header != "" -> {:ok, header}
        _ -> {:error, :invalid_payment_header}
      end
    end

    @spec decode_and_validate_payment(String.t(), [map()], map()) ::
            {:ok, map(), map()} | {:error, term()}
    defp decode_and_validate_payment(header, accepts, advertised_extensions)
         when is_list(accepts) and is_map(advertised_extensions) do
      with {:ok, payload} <- PaymentSignature.decode(header),
           :ok <- ensure_v2_payload(payload),
           {:ok, payload} <- PaymentSignature.validate(payload),
           {:ok, matched} <- find_matching_requirements(accepts, payload),
           :ok <- validate_extensions(payload, advertised_extensions) do
        {:ok, payload, matched}
      end
    end

    @spec ensure_v2_payload(map()) :: :ok | {:error, :invalid_x402_version}
    defp ensure_v2_payload(payload) do
      case Utils.map_value(payload, {"x402Version", :x402Version}) do
        2 -> :ok
        _version -> {:error, :invalid_x402_version}
      end
    end

    @spec find_matching_requirements([map()], map()) ::
            {:ok, map()} | {:error, :no_matching_requirements}
    defp find_matching_requirements(accepts, payment_payload) when is_list(accepts) do
      accepted = Utils.map_value(payment_payload, {"accepted", :accepted})

      if is_map(accepted) do
        case Enum.find(accepts, &requirements_match?(&1, accepted)) do
          nil -> {:error, :no_matching_requirements}
          matched -> {:ok, matched}
        end
      else
        {:error, :no_matching_requirements}
      end
    end

    @spec requirements_match?(map(), map()) :: boolean()
    defp requirements_match?(requirement, accepted),
      do: PaymentRequirements.match?(requirement, accepted)

    @spec validate_extensions(map(), map()) :: :ok | {:error, :extension_echo_mismatch}
    defp validate_extensions(payload, advertised_extensions) do
      client_extensions = Utils.map_value(payload, {"extensions", :extensions})

      case PaymentRequirements.extensions_match?(advertised_extensions, client_extensions) do
        true -> :ok
        false -> {:error, :extension_echo_mismatch}
      end
    end

    # Cheap local checks on the EIP-3009-style authorization object, run before
    # the facilitator round-trip. They mirror the first checks every reference
    # facilitator performs (payTo equality, exact amount equality, time
    # window), so junk traffic is rejected without paying a verify call.
    # Payloads without a `payload.authorization` map — other schemes, Permit2 —
    # are skipped entirely, as is any individual absent field: the facilitator
    # remains the authority, these checks only fail fast on certain mismatch.
    @type precheck_failure ::
            :pay_to_mismatch
            | :amount_mismatch
            | :invalid_authorization_value
            | :authorization_not_yet_valid
            | :authorization_expired
            | :invalid_authorization_timing

    @spec run_local_prechecks(boolean(), map(), map()) ::
            :ok | {:error, {:precheck_failed, precheck_failure()}}
    defp run_local_prechecks(false, _payload, _requirements), do: :ok

    defp run_local_prechecks(true, payload, requirements) do
      case eip3009_authorization(payload) do
        nil ->
          :ok

        authorization ->
          with :ok <- precheck_pay_to(authorization, requirements),
               :ok <- precheck_exact_amount(authorization, requirements) do
            precheck_timing(authorization)
          end
      end
    end

    @spec eip3009_authorization(map()) :: map() | nil
    defp eip3009_authorization(payload) do
      case Utils.nested_map_value(payload, [
             {"payload", :payload},
             {"authorization", :authorization}
           ]) do
        authorization when is_map(authorization) -> authorization
        _other -> nil
      end
    end

    @spec precheck_pay_to(map(), map()) ::
            :ok | {:error, {:precheck_failed, :pay_to_mismatch}}
    defp precheck_pay_to(authorization, requirements) do
      to = Utils.map_value(authorization, {"to", :to})
      pay_to = Utils.map_value(requirements, {"payTo", :payTo})

      case is_binary(to) and is_binary(pay_to) do
        true ->
          case same_address?(to, pay_to) do
            true -> :ok
            false -> {:error, {:precheck_failed, :pay_to_mismatch}}
          end

        false ->
          :ok
      end
    end

    @spec same_address?(String.t(), String.t()) :: boolean()
    defp same_address?(left, right) do
      case hex_address?(left) and hex_address?(right) do
        true -> String.downcase(left) == String.downcase(right)
        false -> left == right
      end
    end

    @spec hex_address?(String.t()) :: boolean()
    defp hex_address?(<<"0x", rest::binary>>) when rest != "",
      do: Regex.match?(~r/^[0-9a-fA-F]+$/, rest)

    defp hex_address?(_address), do: false

    @spec precheck_exact_amount(map(), map()) ::
            :ok | {:error, {:precheck_failed, :amount_mismatch | :invalid_authorization_value}}
    defp precheck_exact_amount(authorization, requirements) do
      scheme = Utils.map_value(requirements, {"scheme", :scheme})
      value = Utils.map_value(authorization, {"value", :value})
      amount = Utils.map_value(requirements, {"amount", :amount})

      case scheme == "exact" and not is_nil(value) and not is_nil(amount) do
        true -> compare_exact_amount(value, amount)
        false -> :ok
      end
    end

    @spec compare_exact_amount(term(), term()) ::
            :ok | {:error, {:precheck_failed, :amount_mismatch | :invalid_authorization_value}}
    defp compare_exact_amount(value, amount) do
      with {:ok, parsed_value} <- parse_precheck_amount(value),
           {:ok, parsed_amount} <- parse_precheck_amount(amount) do
        case Utils.compare_decimal(parsed_value, parsed_amount) do
          :eq -> :ok
          _other -> {:error, {:precheck_failed, :amount_mismatch}}
        end
      end
    end

    @spec parse_precheck_amount(term()) ::
            {:ok, {non_neg_integer(), non_neg_integer()}}
            | {:error, {:precheck_failed, :invalid_authorization_value}}
    defp parse_precheck_amount(value) do
      case Utils.parse_decimal(value) do
        {:ok, parsed} -> {:ok, parsed}
        :error -> {:error, {:precheck_failed, :invalid_authorization_value}}
      end
    end

    @spec precheck_timing(map()) ::
            :ok
            | {:error,
               {:precheck_failed,
                :authorization_not_yet_valid
                | :authorization_expired
                | :invalid_authorization_timing}}
    defp precheck_timing(authorization) do
      now = System.system_time(:second)

      with {:ok, valid_after} <-
             optional_unix_time(Utils.map_value(authorization, {"validAfter", :validAfter})),
           {:ok, valid_before} <-
             optional_unix_time(Utils.map_value(authorization, {"validBefore", :validBefore})) do
        cond do
          is_integer(valid_after) and valid_after > now ->
            {:error, {:precheck_failed, :authorization_not_yet_valid}}

          is_integer(valid_before) and valid_before < now + @precheck_time_buffer_seconds ->
            {:error, {:precheck_failed, :authorization_expired}}

          true ->
            :ok
        end
      end
    end

    @spec optional_unix_time(term()) ::
            {:ok, integer() | nil} | {:error, {:precheck_failed, :invalid_authorization_timing}}
    defp optional_unix_time(nil), do: {:ok, nil}
    defp optional_unix_time(value) when is_integer(value), do: {:ok, value}

    defp optional_unix_time(value) when is_binary(value) do
      case Integer.parse(value) do
        {parsed, ""} -> {:ok, parsed}
        _other -> {:error, {:precheck_failed, :invalid_authorization_timing}}
      end
    end

    defp optional_unix_time(_value),
      do: {:error, {:precheck_failed, :invalid_authorization_timing}}

    @spec ensure_verify_success(map()) ::
            :ok
            | {:error,
               {:unexpected_facilitator_status, integer()}
               | {:verification_failed, term()}
               | {:malformed_facilitator_response, :verify}}
    defp ensure_verify_success(%{status: status, body: body})
         when status in 200..299 and is_map(body) do
      case Utils.map_value(body, {"isValid", :isValid}) do
        true ->
          :ok

        false ->
          {:error,
           {:verification_failed, Utils.map_value(body, {"invalidReason", :invalidReason})}}

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

    @spec ensure_settle_success(map()) ::
            :ok
            | {:error,
               {:unexpected_facilitator_status, integer()}
               | {:settlement_failed, term()}
               | {:malformed_facilitator_response, :settle}}
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

    defp warn_no_idempotency_cache_once do
      key = {__MODULE__, :no_idempotency_cache_warned}

      unless :persistent_term.get(key, false) do
        :persistent_term.put(key, true)

        Logger.warning(
          "[X402.Plug.PaymentGate] payment_identifier_cache is not configured. " <>
            "Duplicate payment proofs will NOT be detected — your deployment is " <>
            "vulnerable to double-settlement of concurrent identical requests. " <>
            "Pass `payment_identifier_cache: pid_or_name` to enable idempotency."
        )
      end
    end

    @spec route_accepts(compiled_route()) :: [map()]
    defp route_accepts(%{accepts: accepts}) do
      Enum.map(accepts, &payment_requirements_from_accept/1)
    end

    @spec payment_requirements_from_accept(payment_accept()) :: map()
    defp payment_requirements_from_accept(accept) do
      %{
        "scheme" => accept.scheme,
        "network" => accept.network,
        "amount" => accept.price,
        "asset" => accept.asset,
        "payTo" => accept.pay_to,
        "maxTimeoutSeconds" => accept.max_timeout_seconds,
        "extra" => stringify_keys(accept.extra)
      }
    end

    @spec stringify_keys(map()) :: map()
    defp stringify_keys(map) when is_map(map) do
      Map.new(map, fn
        {key, value} when is_atom(key) -> {Atom.to_string(key), value}
        {key, value} -> {key, value}
      end)
    end

    @spec resource_info(Plug.Conn.t(), compiled_route(), String.t()) :: map()
    defp resource_info(conn, route, request_path) do
      base = %{
        "url" => resource_url(conn, request_path),
        "description" => route.description,
        "mimeType" => route.mime_type
      }

      base
      |> maybe_put("serviceName", route.service_name)
      |> maybe_put_tags(route.tags)
      |> maybe_put("iconUrl", route.icon_url)
    end

    @spec maybe_put(map(), String.t(), term()) :: map()
    defp maybe_put(map, _key, nil), do: map
    defp maybe_put(map, _key, ""), do: map
    defp maybe_put(map, key, value), do: Map.put(map, key, value)

    @spec maybe_put_tags(map(), [String.t()]) :: map()
    defp maybe_put_tags(map, tags) when is_list(tags) and tags != [],
      do: Map.put(map, "tags", tags)

    defp maybe_put_tags(map, _tags), do: map

    @spec resource_url(Plug.Conn.t(), String.t()) :: String.t()
    defp resource_url(conn, _request_path), do: Plug.Conn.request_url(conn)

    @spec payment_error_response(
            Plug.Conn.t(),
            compiled_route(),
            String.t(),
            String.t(),
            keyword()
          ) :: Plug.Conn.t()
    defp payment_error_response(conn, route, request_path, error_message, opts) do
      conn
      |> payment_error_conn(route, request_path, error_message, opts)
      |> send_resp()
      |> halt()
    end

    @spec payment_error_conn(
            Plug.Conn.t(),
            compiled_route(),
            String.t(),
            String.t(),
            keyword()
          ) :: Plug.Conn.t()
    defp payment_error_conn(conn, route, request_path, error_message, opts) do
      status = Keyword.get(opts, :status, 402)
      reason = Keyword.get(opts, :reason)
      paywall = Keyword.get(opts, :paywall)
      required_payload = payment_required_payload(conn, route, request_path, error_message)

      with {:ok, encoded_required} <- PaymentRequired.encode(required_payload),
           {:ok, response_conn} <- maybe_put_payment_response_header(conn, reason) do
        response_conn
        |> put_resp_header("payment-required", encoded_required)
        |> delete_resp_header("content-length")
        |> put_payment_error_body(status, required_payload, request_path, paywall)
      else
        {:error, _reason} -> internal_error_conn(conn)
      end
    end

    # The HTML paywall applies only to 402 responses to requests that look
    # like a browser page load. Every other combination — no :paywall
    # configured, non-402 statuses, API clients — keeps the empty JSON body,
    # byte-identical to running without the option.
    @spec put_payment_error_body(
            Plug.Conn.t(),
            integer(),
            map(),
            String.t(),
            module() | nil
          ) :: Plug.Conn.t()
    defp put_payment_error_body(conn, 402, required_payload, request_path, paywall)
         when not is_nil(paywall) do
      case browser_request?(conn) do
        true -> paywall_response(conn, required_payload, request_path, paywall)
        false -> json_error_body(conn, 402)
      end
    end

    defp put_payment_error_body(conn, status, _required_payload, _request_path, _paywall) do
      json_error_body(conn, status)
    end

    @spec json_error_body(Plug.Conn.t(), integer()) :: Plug.Conn.t()
    defp json_error_body(conn, status) do
      conn
      |> put_resp_content_type("application/json")
      |> resp(status, "{}")
    end

    @spec paywall_response(Plug.Conn.t(), map(), String.t(), module()) :: Plug.Conn.t()
    defp paywall_response(conn, required_payload, request_path, paywall) do
      conn_info = %{method: conn.method, request_path: request_path, status: 402}

      case paywall.render(required_payload, conn_info) do
        {:ok, html} ->
          # The paywall exposes a one-click wallet-signature flow; deny
          # framing so a third-party page cannot overlay it and clickjack an
          # EIP-3009 authorization.
          conn
          |> put_resp_content_type("text/html")
          |> put_resp_header("x-frame-options", "DENY")
          |> put_resp_header("content-security-policy", "frame-ancestors 'none'")
          |> resp(402, html)

        {:error, reason} ->
          Logger.warning(
            "[X402.Plug.PaymentGate] paywall renderer #{inspect(paywall)} failed " <>
              "(#{inspect(reason)}); falling back to the JSON 402 body"
          )

          json_error_body(conn, 402)
      end
    end

    # Mirrors the browser heuristic of the reference x402 middlewares (Go and
    # TypeScript): a request is a browser page load when its Accept header
    # contains "text/html" AND its User-Agent contains "Mozilla". Absent
    # headers never match, so API clients keep the JSON body.
    @spec browser_request?(Plug.Conn.t()) :: boolean()
    defp browser_request?(conn) do
      String.contains?(first_req_header(conn, "accept"), "text/html") and
        String.contains?(first_req_header(conn, "user-agent"), "Mozilla")
    end

    @spec first_req_header(Plug.Conn.t(), String.t()) :: String.t()
    defp first_req_header(conn, name) do
      case get_req_header(conn, name) do
        [value | _rest] when is_binary(value) -> value
        _missing -> ""
      end
    end

    @spec payment_required_payload(Plug.Conn.t(), compiled_route(), String.t(), String.t()) ::
            map()
    defp payment_required_payload(conn, route, request_path, error_message) do
      %{
        "x402Version" => @x402_version,
        "error" => error_message,
        "resource" => resource_info(conn, route, request_path),
        "accepts" => route_accepts(route),
        "extensions" => route.extensions
      }
    end

    @spec put_payment_response_header(Plug.Conn.t(), map()) ::
            {:ok, Plug.Conn.t()} | {:error, {:payment_response_encoding_failed, term()}}
    defp put_payment_response_header(conn, body) when is_map(body) do
      case PaymentResponse.encode(body) do
        {:ok, encoded} -> {:ok, put_resp_header(conn, "payment-response", encoded)}
        {:error, reason} -> {:error, {:payment_response_encoding_failed, reason}}
      end
    end

    @spec maybe_put_payment_response_header(Plug.Conn.t(), term()) ::
            {:ok, Plug.Conn.t()} | {:error, {:payment_response_encoding_failed, term()}}
    defp maybe_put_payment_response_header(conn, reason) do
      case payment_response_from_reason(reason) do
        nil -> {:ok, conn}
        settle_body -> put_payment_response_header(conn, settle_body)
      end
    end

    @spec internal_error_conn(Plug.Conn.t()) :: Plug.Conn.t()
    defp internal_error_conn(conn) do
      conn
      |> delete_resp_header("content-length")
      |> delete_resp_header("payment-required")
      |> delete_resp_header("payment-response")
      |> put_resp_content_type("application/json")
      |> resp(500, "{}")
    end

    @spec payment_response_from_reason(term()) :: map() | nil
    defp payment_response_from_reason(%_struct{}), do: nil
    defp payment_response_from_reason(body) when is_map(body), do: body

    defp payment_response_from_reason({:settlement_failed, reason}) when is_binary(reason) do
      %{
        "success" => false,
        "errorReason" => reason,
        "transaction" => "",
        "network" => ""
      }
    end

    defp payment_response_from_reason({:settlement_failed, reason}) when not is_nil(reason) do
      %{
        "success" => false,
        "errorReason" => to_string(reason),
        "transaction" => "",
        "network" => ""
      }
    end

    defp payment_response_from_reason(_reason), do: nil

    @spec status_for_reason(term()) :: 400 | 402 | 500
    defp status_for_reason(reason) when reason in @invalid_request_reasons, do: 400
    defp status_for_reason({:unsupported_x402_version, _version}), do: 400
    defp status_for_reason({:missing_fields, _fields}), do: 400
    defp status_for_reason({:precheck_failed, _reason}), do: 402
    defp status_for_reason({:invalid_upto_payment, _reason}), do: 400
    defp status_for_reason({:invalid_fields, _fields}), do: 400
    defp status_for_reason(:invalid_payment_requirements), do: 400
    defp status_for_reason(:extension_echo_mismatch), do: 400
    defp status_for_reason(:no_matching_requirements), do: 402
    defp status_for_reason(:already_exists), do: 402
    defp status_for_reason({:verification_failed, _reason}), do: 402
    defp status_for_reason({:settlement_failed, _reason}), do: 402
    defp status_for_reason(%Error{}), do: 500
    defp status_for_reason({:unexpected_facilitator_status, _status}), do: 500
    defp status_for_reason({:malformed_facilitator_response, _operation}), do: 500
    defp status_for_reason({:invalid_settlement_amount, _reason}), do: 500
    defp status_for_reason({:payment_response_encoding_failed, _reason}), do: 500
    defp status_for_reason(_reason), do: 500

    @spec normalize_method(String.t()) :: atom()
    defp normalize_method("DELETE"), do: :delete
    defp normalize_method("GET"), do: :get
    defp normalize_method("HEAD"), do: :head
    defp normalize_method("OPTIONS"), do: :options
    defp normalize_method("PATCH"), do: :patch
    defp normalize_method("POST"), do: :post
    defp normalize_method("PUT"), do: :put
    defp normalize_method("TRACE"), do: :trace
    defp normalize_method(_method), do: :any

    @spec normalize_path(String.t()) :: String.t()
    defp normalize_path("/"), do: "/"
    defp normalize_path(path), do: String.trim_trailing(path, "/")

    # Matching MUST use conn.script_name ++ conn.path_info, not the raw
    # conn.request_path: adapters drop empty segments when building path_info,
    # so "//premium" reaches the router as ["premium"] while its request_path
    # stays "//premium" — a raw string comparison passes the alias through
    # unguarded even though the router serves the protected resource (the
    # GHSA-3j63-5h8p-gf7c bug class). script_name must be included because
    # Plug/Phoenix `forward` pops matched prefix segments from path_info into
    # script_name — matching on path_info alone would fail open for gates
    # mounted behind a forwarded prefix whose routes are configured as full
    # paths. Segments are additionally percent-decoded so the gate also covers
    # routers that decode; when the router does not, a decoded match merely
    # 402s a request the router would 404 — over-matching is the fail-safe
    # direction for a paywall. Malformed percent sequences are matched
    # verbatim.
    @spec decoded_request_path(Plug.Conn.t()) :: String.t()
    defp decoded_request_path(%Plug.Conn{script_name: script_name, path_info: path_info}) do
      case script_name ++ path_info do
        [] -> "/"
        segments -> "/" <> Enum.map_join(segments, "/", &decode_segment/1)
      end
    end

    @spec decode_segment(String.t()) :: String.t()
    defp decode_segment(segment) do
      URI.decode(segment)
    rescue
      ArgumentError -> segment
    end

    @spec map_to_keyword(map()) :: {:ok, keyword()} | {:error, String.t()}
    defp map_to_keyword(map) do
      Enum.reduce_while(map, {:ok, []}, fn
        {key, value}, {:ok, options} when is_atom(key) ->
          {:cont, {:ok, [{key, value} | options]}}

        {key, value}, {:ok, options} when is_binary(key) ->
          try do
            {:cont, {:ok, [{String.to_existing_atom(key), value} | options]}}
          rescue
            ArgumentError -> {:halt, {:error, "unknown route option: #{inspect(key)}"}}
          end

        {key, _value}, {:ok, _options} ->
          {:halt, {:error, "invalid route option key: #{inspect(key)}"}}
      end)
      |> case do
        {:ok, options} -> {:ok, Enum.reverse(options)}
        {:error, reason} -> {:error, reason}
      end
    end

    @spec rejection_error(term()) :: String.t()
    defp rejection_error(:invalid_payment_header), do: "invalid payment header"
    defp rejection_error(:invalid_base64), do: "invalid payment header"
    defp rejection_error(:invalid_json), do: "invalid payment header"
    defp rejection_error(:payload_too_large), do: "invalid payment header"
    defp rejection_error(:invalid_payload), do: "invalid_payload"
    defp rejection_error(:invalid_x402_version), do: "invalid_x402_version"
    defp rejection_error(:no_matching_requirements), do: "No matching payment requirements"
    defp rejection_error(:already_exists), do: "payment already processed"
    defp rejection_error({:unsupported_x402_version, _version}), do: "unsupported x402 version"
    defp rejection_error({:missing_fields, _fields}), do: "invalid_payload"

    defp rejection_error({:precheck_failed, _reason}),
      do: "payment authorization does not satisfy the payment requirements"

    defp rejection_error({:invalid_upto_payment, _reason}), do: "invalid_payload"
    defp rejection_error({:invalid_fields, _fields}), do: "invalid_payload"
    defp rejection_error(:invalid_payment_requirements), do: "invalid_payload"
    defp rejection_error(:extension_echo_mismatch), do: "invalid_payload"
    defp rejection_error({:verification_failed, _reason}), do: "facilitator rejected payment"
    defp rejection_error({:settlement_failed, _reason}), do: "facilitator rejected payment"

    defp rejection_error({:unexpected_facilitator_status, _status}),
      do: "payment processing failed"

    defp rejection_error({:malformed_facilitator_response, _operation}),
      do: "payment processing failed"

    defp rejection_error(%Error{}), do: "payment processing failed"
    defp rejection_error({:invalid_settlement_amount, _reason}), do: "payment processing failed"

    defp rejection_error({:payment_response_encoding_failed, _reason}),
      do: "payment processing failed"

    defp rejection_error(_reason), do: "payment processing failed"

    @spec emit(:pass_through | :payment_required | :payment_verified | :payment_rejected, map()) ::
            :ok
    defp emit(event, metadata) do
      :telemetry.execute([:x402, :plug, event], %{count: 1}, metadata)
    end
  end
else
  defmodule X402.Plug.PaymentGate do
    @moduledoc """
    Plug middleware that gates configured routes behind x402 payment verification.

    This module requires the optional `:plug` dependency. Add `{:plug, "~> 1.14"}`
    to your project dependencies before using it.
    """

    @doc since: "0.1.0"
    @doc """
    Raises because Plug is not available.
    """
    @spec init(keyword()) :: no_return()
    def init(_opts) do
      raise ArgumentError, "X402.Plug.PaymentGate requires the optional :plug dependency"
    end

    @doc since: "0.1.0"
    @doc """
    Raises because Plug is not available.
    """
    @spec call(term(), map()) :: no_return()
    def call(_conn, _opts) do
      raise ArgumentError, "X402.Plug.PaymentGate requires the optional :plug dependency"
    end

    @doc since: "0.4.0"
    @doc """
    Raises because Plug is not available.
    """
    @spec put_settlement_amount(term(), term()) :: no_return()
    def put_settlement_amount(_conn, _amount) do
      raise ArgumentError, "X402.Plug.PaymentGate requires the optional :plug dependency"
    end
  end
end
