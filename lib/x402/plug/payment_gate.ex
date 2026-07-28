if Code.ensure_loaded?(Plug) and Code.ensure_loaded?(Plug.Conn) do
  defmodule X402.Plug.PaymentGate do
    @moduledoc """
    Plug middleware that gates configured routes behind x402 v2 payment verification.

    For matching routes:

    1. Requests without a `PAYMENT-SIGNATURE` header receive **402** with a
       Base64-encoded `PAYMENT-REQUIRED` header (`PaymentRequired` v2 schema).
    2. Requests with `PAYMENT-SIGNATURE` are decoded as `PaymentPayload` v2.
    3. `PaymentPayload.accepted` is matched against the route's advertised
       `accepts` (`scheme`, `network`, `amount`, `asset`, `payTo`).
    4. Matched requirements are verified and settled via the facilitator.
    5. Successful settlements attach a `PAYMENT-RESPONSE` header and assign
       `:x402_payment_payload` / `:x402_payment_requirements` on the conn.

    HTTP status mapping (HTTP transport v2):

    - **402** — payment required, no matching requirements, or payment failed
    - **400** — malformed / invalid payment payload (including wrong `x402Version`)

    See `docs/x402-specification-v2.md` and the
    [HTTP transport](https://github.com/x402-foundation/x402/blob/main/specs/transports-v2/http.md).
    """

    @behaviour Plug

    alias X402.Extensions.PaymentIdentifier.ETSCache
    alias X402.Facilitator
    alias X402.Hooks
    alias X402.Hooks.Default
    alias X402.PaymentRequired
    alias X402.PaymentResponse
    alias X402.PaymentSignature
    alias X402.Utils

    require Logger

    import Plug.Conn,
      only: [
        assign: 3,
        get_req_header: 2,
        halt: 1,
        put_resp_content_type: 2,
        put_resp_header: 3,
        send_resp: 3
      ]

    @http_methods [:any, :delete, :get, :head, :options, :patch, :post, :put, :trace]
    # TODO Implement batch-settlement scheme
    @route_schemes ["exact", "upto"]
    @x402_version 2
    @default_max_timeout_seconds 60
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
        type: :string,
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
        type: :string,
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
        type: {:or, [:atom, :pid, :any]},
        default: nil,
        doc: """
        Optional `ETSCache` server pid/name used for idempotency. When set,
        the plug performs an atomic claim (via `put_new`) on the payment proof
        hash before settling, preventing concurrent requests from double-settling
        the same payment.
        """
      ],
      routes: [
        type: {:list, {:custom, __MODULE__, :validate_route, []}},
        required: true,
        doc: "Route gate definitions (see route options below)."
      ]
    ]

    @typedoc "Configuration map produced by `init/1`."
    @type options :: %{
            facilitator: Facilitator.server(),
            hooks: module(),
            payment_identifier_cache: ETSCache.server() | nil,
            routes: [compiled_route()]
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

    @doc false
    @spec validate_extra_map(term()) :: {:ok, map()} | {:error, String.t()}
    def validate_extra_map(value) when is_map(value), do: {:ok, value}
    def validate_extra_map(_value), do: {:error, "expected a map"}

    @doc false
    @spec validate_route(term()) :: {:ok, map()} | {:error, String.t()}
    def validate_route(route) when is_map(route) do
      keyword_route = map_to_keyword(route)

      case NimbleOptions.validate(keyword_route, @route_schema) do
        {:ok, validated} ->
          validated_map = Map.new(validated)

          case ensure_accepts_source(validated_map) do
            :ok -> {:ok, validated_map}
            {:error, message} -> {:error, message}
          end

        {:error, %NimbleOptions.ValidationError{} = error} ->
          {:error, Exception.message(error)}
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
        routes:
          validated_opts
          |> Keyword.fetch!(:routes)
          |> Enum.map(&compile_route/1)
      }
    end

    @doc since: "0.1.0"
    @doc """
    Gates matching requests behind x402 v2 payment verification.
    """
    @spec call(Plug.Conn.t(), options()) :: Plug.Conn.t()
    def call(%Plug.Conn{} = conn, %{
          facilitator: facilitator,
          hooks: hooks,
          payment_identifier_cache: payment_identifier_cache,
          routes: routes
        }) do
      if is_nil(payment_identifier_cache), do: warn_no_idempotency_cache_once()

      request_path = normalize_path(conn.request_path)
      request_method = normalize_method(conn.method)

      case match_route(routes, request_method, request_path) do
        nil ->
          emit(:pass_through, %{method: request_method, path: request_path})
          conn

        route ->
          handle_payment_gate(
            conn,
            facilitator,
            hooks,
            payment_identifier_cache,
            route,
            request_method,
            request_path
          )
      end
    end

    @spec handle_payment_gate(
            Plug.Conn.t(),
            Facilitator.server(),
            module(),
            ETSCache.server() | nil,
            compiled_route(),
            atom(),
            String.t()
          ) :: Plug.Conn.t()
    defp handle_payment_gate(
           conn,
           facilitator,
           hooks,
           payment_identifier_cache,
           route,
           request_method,
           request_path
         ) do
      case payment_header(conn) do
        :missing ->
          emit(:payment_required, %{method: request_method, path: request_path, route: route.path})

          payment_error_response(
            conn,
            route,
            request_path,
            "PAYMENT-SIGNATURE header is required",
            status: 402
          )

        {:ok, header} ->
          verify_and_settle(
            conn,
            facilitator,
            hooks,
            payment_identifier_cache,
            route,
            request_method,
            request_path,
            header
          )

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
            reason: reason
          )
      end
    end

    @spec verify_and_settle(
            Plug.Conn.t(),
            Facilitator.server(),
            module(),
            ETSCache.server() | nil,
            compiled_route(),
            atom(),
            String.t(),
            String.t()
          ) :: Plug.Conn.t()
    defp verify_and_settle(
           conn,
           facilitator,
           hooks,
           payment_identifier_cache,
           route,
           request_method,
           request_path,
           header
         ) do
      accepts = route_accepts(route)
      payment_id = :crypto.hash(:sha256, header) |> Base.encode16(case: :lower)

      with {:ok, payment_payload, requirements} <-
             decode_and_validate_payment(header, accepts),
           {:ok, verify_response} <-
             facilitator_verify(facilitator, payment_payload, requirements, hooks),
           :ok <- ensure_verify_success(verify_response),
           :ok <- claim_payment(payment_identifier_cache, payment_id) do
        settle_result = settle_with_hooks(facilitator, payment_payload, requirements, hooks)

        case settle_result do
          {:ok, settle_response} ->
            emit(:payment_verified, %{
              method: request_method,
              path: request_path,
              route: route.path
            })

            conn
            |> assign(:x402_payment_payload, payment_payload)
            |> assign(:x402_payment_requirements, requirements)
            |> put_payment_response_header(settle_response.body)

          {:error, reason, settle_body} ->
            release_claim(payment_identifier_cache, payment_id)

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
              reason: settle_body || reason
            )
        end
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
            reason: reason
          )
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
        {:ok, settle_response} ->
          case ensure_settle_success(settle_response) do
            :ok -> {:ok, settle_response}
            {:error, reason} -> {:error, reason, settle_response.body}
          end

        {:error, reason} ->
          {:error, reason, nil}
      end
    end

    @spec claim_payment(ETSCache.server() | nil, String.t()) ::
            :ok | {:error, :already_exists}
    defp claim_payment(nil, _payment_id), do: :ok

    defp claim_payment(cache, payment_id) do
      ETSCache.put_new(cache, payment_id, :verified)
    end

    @spec release_claim(ETSCache.server() | nil, String.t()) :: :ok | {:error, term()}
    defp release_claim(nil, _payment_id), do: :ok
    defp release_claim(cache, payment_id), do: ETSCache.delete(cache, payment_id)

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

    @spec decode_and_validate_payment(String.t(), [map()]) ::
            {:ok, map(), map()} | {:error, term()}
    defp decode_and_validate_payment(header, accepts) when is_list(accepts) do
      with {:ok, payload} <- PaymentSignature.decode(header),
           :ok <- validate_v2_payload_structure(payload),
           {:ok, matched} <- find_matching_requirements(accepts, payload),
           :ok <- validate_upto_amount(payload, matched) do
        {:ok, payload, matched}
      end
    end

    @spec validate_v2_payload_structure(map()) :: :ok | {:error, term()}
    defp validate_v2_payload_structure(payload) when is_map(payload) do
      accepted = Utils.map_value(payload, {"accepted", :accepted})
      scheme_payload = Utils.map_value(payload, {"payload", :payload})
      version = Utils.map_value(payload, {"x402Version", :x402Version})

      cond do
        version != @x402_version ->
          {:error, :invalid_x402_version}

        not is_map(accepted) ->
          {:error, :invalid_payload}

        not is_map(scheme_payload) ->
          {:error, :invalid_payload}

        true ->
          :ok
      end
    end

    # Equality on scheme, network, amount, asset, payTo — matches Go
    # FindMatchingRequirements.
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
    defp requirements_match?(requirement, accepted) do
      requirement_field(requirement, "scheme") == requirement_field(accepted, "scheme") and
        requirement_field(requirement, "network") == requirement_field(accepted, "network") and
        requirement_field(requirement, "amount") == requirement_field(accepted, "amount") and
        requirement_field(requirement, "asset") == requirement_field(accepted, "asset") and
        requirement_field(requirement, "payTo") == requirement_field(accepted, "payTo")
    end

    @spec requirement_field(map(), String.t()) :: term()
    defp requirement_field(map, "scheme"), do: Utils.map_value(map, {"scheme", :scheme})
    defp requirement_field(map, "network"), do: Utils.map_value(map, {"network", :network})
    defp requirement_field(map, "amount"), do: Utils.map_value(map, {"amount", :amount})
    defp requirement_field(map, "asset"), do: Utils.map_value(map, {"asset", :asset})
    defp requirement_field(map, "payTo"), do: Utils.map_value(map, {"payTo", :payTo})

    @spec validate_upto_amount(map(), map()) :: :ok | {:error, term()}
    defp validate_upto_amount(payload, requirements) do
      case Utils.map_value(requirements, {"scheme", :scheme}) do
        "upto" -> validate_upto_max(payload, requirements)
        _scheme -> :ok
      end
    end

    @spec validate_upto_max(map(), map()) :: :ok | {:error, term()}
    defp validate_upto_max(payload, requirements) do
      with {:ok, max_amount} <- extract_max_amount(requirements),
           {:ok, payment_value} <- extract_payment_value(payload) do
        case Utils.compare_decimal(payment_value, max_amount) do
          :gt -> {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}}
          _comparison -> :ok
        end
      end
    end

    @spec extract_max_amount(map()) ::
            {:ok, {non_neg_integer(), non_neg_integer()}}
            | {:error, {:invalid_upto_payment, atom()}}
    defp extract_max_amount(requirements) do
      value =
        Utils.first_present([
          Utils.map_value(requirements, {"amount", :amount}),
          Utils.map_value(requirements, {"maxPrice", :maxPrice}),
          Utils.map_value(requirements, {"maxAmountRequired", :maxAmountRequired})
        ])

      case value do
        nil ->
          {:error, {:invalid_upto_payment, :missing_max_price}}

        max_amount ->
          case Utils.parse_decimal(max_amount) do
            {:ok, parsed} -> {:ok, parsed}
            :error -> {:error, {:invalid_upto_payment, :invalid_max_price}}
          end
      end
    end

    @spec extract_payment_value(map()) ::
            {:ok, {non_neg_integer(), non_neg_integer()}}
            | {:error, {:invalid_upto_payment, atom()}}
    defp extract_payment_value(payload) do
      value =
        Utils.first_present([
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

    @spec ensure_verify_success(%{status: non_neg_integer(), body: map()}) ::
            :ok
            | {:error,
               {:unexpected_facilitator_status, non_neg_integer()}
               | {:verification_failed, term()}}
    defp ensure_verify_success(%{status: status, body: body}) when status in 200..299 do
      case Map.get(body, "isValid", Map.get(body, :isValid, true)) do
        true -> :ok
        _invalid -> {:error, {:verification_failed, Map.get(body, "invalidReason")}}
      end
    end

    defp ensure_verify_success(%{status: status}),
      do: {:error, {:unexpected_facilitator_status, status}}

    @spec ensure_settle_success(%{status: non_neg_integer(), body: map()}) ::
            :ok
            | {:error,
               {:unexpected_facilitator_status, non_neg_integer()}
               | {:settlement_failed, term()}}
    defp ensure_settle_success(%{status: status, body: body}) when status in 200..299 do
      case Map.get(body, "success", Map.get(body, :success, true)) do
        true -> :ok
        _failed -> {:error, {:settlement_failed, Map.get(body, "errorReason")}}
      end
    end

    defp ensure_settle_success(%{status: status}),
      do: {:error, {:unexpected_facilitator_status, status}}

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
    defp resource_url(conn, request_path) do
      scheme = conn.scheme |> to_string()
      host = conn.host || "localhost"
      port = conn.port

      authority =
        cond do
          scheme == "https" and port in [443, nil] -> host
          scheme == "http" and port in [80, nil] -> host
          is_integer(port) -> "#{host}:#{port}"
          true -> host
        end

      "#{scheme}://#{authority}#{request_path}"
    end

    @spec payment_error_response(
            Plug.Conn.t(),
            compiled_route(),
            String.t(),
            String.t(),
            keyword()
          ) :: Plug.Conn.t()
    defp payment_error_response(conn, route, request_path, error_message, opts) do
      status = Keyword.get(opts, :status, 402)
      reason = Keyword.get(opts, :reason)
      required_payload = payment_required_payload(conn, route, request_path, error_message)

      conn =
        case PaymentRequired.encode(required_payload) do
          {:ok, encoded} ->
            put_resp_header(conn, "payment-required", encoded)

          {:error, _reason} ->
            conn
        end

      conn =
        case payment_response_from_reason(reason) do
          nil -> conn
          settle_body -> put_payment_response_header(conn, settle_body)
        end

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(status, "{}")
      |> halt()
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

    @spec put_payment_response_header(Plug.Conn.t(), map()) :: Plug.Conn.t()
    defp put_payment_response_header(conn, body) when is_map(body) do
      case PaymentResponse.encode(body) do
        {:ok, encoded} -> put_resp_header(conn, "payment-response", encoded)
        {:error, _reason} -> conn
      end
    end

    @spec payment_response_from_reason(term()) :: map() | nil
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

    @spec status_for_reason(term()) :: 400 | 402
    defp status_for_reason(reason) when reason in @invalid_request_reasons, do: 400
    defp status_for_reason({:missing_fields, _fields}), do: 400
    defp status_for_reason({:invalid_upto_payment, _reason}), do: 400
    defp status_for_reason({:invalid_format, _fields}), do: 400
    defp status_for_reason(_reason), do: 402

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

    @spec map_to_keyword(map()) :: keyword()
    defp map_to_keyword(map) do
      Enum.map(map, fn
        {key, value} when is_atom(key) -> {key, value}
        {key, value} when is_binary(key) -> {String.to_existing_atom(key), value}
      end)
    rescue
      ArgumentError ->
        Enum.map(map, fn
          {key, value} when is_atom(key) -> {key, value}
          {key, value} when is_binary(key) -> {String.to_atom(key), value}
        end)
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
    defp rejection_error({:missing_fields, _fields}), do: "invalid_payload"
    defp rejection_error({:invalid_upto_payment, _reason}), do: "invalid_payload"
    defp rejection_error({:invalid_format, _fields}), do: "invalid_payload"
    defp rejection_error({:verification_failed, _reason}), do: "facilitator rejected payment"
    defp rejection_error({:settlement_failed, _reason}), do: "facilitator rejected payment"

    defp rejection_error({:unexpected_facilitator_status, _status}),
      do: "facilitator rejected payment"

    defp rejection_error(_reason), do: "payment verification failed"

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
  end
end
