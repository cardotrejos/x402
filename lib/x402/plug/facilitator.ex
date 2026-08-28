if Code.ensure_loaded?(Plug) and Code.ensure_loaded?(Plug.Conn) do
  defmodule X402.Plug.Facilitator do
    @moduledoc """
    Plug scaffold exposing one or more facilitator engines as the
    facilitator HTTP API.

    Serves the x402 v2 facilitator endpoints over any Plug-compatible server
    (Bandit, Cowboy, or mounted inside a Phoenix endpoint):

    | Endpoint                   | Behaviour                                          |
    | -------------------------- | -------------------------------------------------- |
    | `POST /verify`             | the matching engine's `verify/3`                   |
    | `POST /settle`             | the matching engine's `settle/3`                   |
    | `GET /supported`           | the engines' `supported/1`, merged                 |
    | `GET /discovery/resources` | `404` — bazaar discovery serving is not included   |

    ## Usage

        {:ok, engine} =
          X402.Facilitator.Engine.new(
            rpc: rpc,
            signer: signer,
            networks: ["eip155:84532"]
          )

        children = [
          {Finch, name: MyApp.Finch},
          {Bandit, plug: {X402.Plug.Facilitator, engine: engine}, port: 4022}
        ]

    Mount the plug at the root of its listener (or behind a `forward` that
    strips the prefix): it answers `404` for paths it does not serve.

    ## Multiple engines

    A facilitator serving several chain families passes `:engines` instead
    of `:engine` — for example an EVM `X402.Facilitator.Engine` next to an
    SVM `X402.Facilitator.SVMEngine`:

        {X402.Plug.Facilitator, engines: [evm_engine, svm_engine]}

    Exactly one of `:engine` and `:engines` must be given. `POST /verify`
    and `POST /settle` dispatch to the first engine whose `supported/1`
    kinds contain the request's `paymentRequirements` `(scheme, network)`
    pair; when none matches, the request is answered with a `200`
    protocol rejection (`unsupported_scheme`, or `invalid_network` when
    some engine serves the scheme on other networks). `GET /supported`
    merges the engines' responses — kinds concatenated, extensions
    unioned, signer families merged. Any struct whose module exports
    `verify/3`, `settle/3`, and `supported/1` with the engine wire
    contract can be listed.

    ## Request/response contract

    `POST /verify` and `POST /settle` require exactly the v2 facilitator
    wire object — `{"x402Version": 2, "paymentPayload": {...},
    "paymentRequirements": {...}}` — and reject anything else with `400`.
    Following the facilitator API convention, protocol-level rejections are
    **200** responses (`{"isValid": false, ...}` / `{"success": false,
    ...}`); non-2xx statuses are reserved for transport-level problems:

    | Status | Meaning                                                        |
    | ------ | -------------------------------------------------------------- |
    | `200`  | Engine verdict (including invalid / failed payments)           |
    | `400`  | Malformed body: bad JSON or not the v2 wire object             |
    | `401`  | Missing/wrong bearer token (when `:auth_token` is configured)  |
    | `404`  | Unknown path (including `/discovery/resources`)                |
    | `405`  | Known path, wrong method                                       |
    | `413`  | Body larger than `:max_body_bytes`                             |
    | `500`  | Engine infrastructure error — opaque body, details are logged  |

    ## Authentication

    The optional `:auth_token` enables a minimal bearer-token check
    (constant-time comparison) on every endpoint. It is a convenience for
    private deployments — put real authentication, TLS termination, and
    rate limiting in front of a production facilitator.
    """

    @behaviour Plug

    alias X402.Facilitator.Engine

    require Logger

    import Plug.Conn,
      only: [
        get_req_header: 2,
        put_resp_content_type: 2,
        read_body: 2,
        send_resp: 3
      ]

    @options_schema [
      engine: [
        type: {:custom, Engine, :validate_config, []},
        doc: """
        A single `X402.Facilitator.Engine` configuration built with
        `Engine.new/1`. Exactly one of `:engine` or `:engines` must be
        given.
        """
      ],
      engines: [
        type: {:custom, __MODULE__, :validate_engines, []},
        doc: """
        A non-empty list of engine structs (`X402.Facilitator.Engine`,
        `X402.Facilitator.SVMEngine`, or any struct whose module exports
        `verify/3`, `settle/3`, and `supported/1`), dispatched by the
        request's `(scheme, network)`. Exactly one of `:engine` or
        `:engines` must be given.
        """
      ],
      auth_token: [
        type: {:or, [:string, nil]},
        default: nil,
        doc: """
        Optional bearer token required on every request (compared in
        constant time). `nil` disables authentication — front a production
        deployment with real auth instead.
        """
      ],
      max_body_bytes: [
        type: :pos_integer,
        default: 8_192,
        doc: """
        Maximum accepted request body size, consistent with the SDK's 8KB
        encoded-header caps. Larger bodies answer `413`.
        """
      ]
    ]

    @typedoc "Validated plug options."
    @type options :: %{
            engines: [struct()],
            auth_token: String.t() | nil,
            max_body_bytes: pos_integer()
          }

    @engine_callbacks [verify: 3, settle: 3, supported: 1]

    @doc since: "0.6.0"
    @doc """
    Validates the plug options.

    Exactly one of `:engine` and `:engines` must be given; both are
    normalized to a list of engines internally.

    ## Options

    #{NimbleOptions.docs(@options_schema)}
    """
    @impl Plug
    @spec init(keyword()) :: options()
    def init(opts) do
      options =
        opts
        |> NimbleOptions.validate!(@options_schema)
        |> Map.new()

      engines = resolve_engines(options)

      if is_nil(options.auth_token) do
        IO.warn(
          "[X402.Plug.Facilitator] auth_token is not configured. The verify " <>
            "and settle endpoints are UNAUTHENTICATED — anyone reaching this " <>
            "facilitator can make its fee payer broadcast (gas-capped) " <>
            "settlement transactions. Set auth_token: or put real " <>
            "authentication in front before exposing it.",
          __ENV__
        )
      end

      options
      |> Map.delete(:engine)
      |> Map.put(:engines, engines)
    end

    @doc false
    @spec validate_engines(term()) :: {:ok, [struct()]} | {:error, String.t()}
    def validate_engines([_head | _tail] = engines) do
      case Enum.all?(engines, &engine_struct?/1) do
        true -> {:ok, engines}
        false -> {:error, invalid_engines_message()}
      end
    end

    def validate_engines(_other), do: {:error, invalid_engines_message()}

    @spec engine_struct?(term()) :: boolean()
    defp engine_struct?(%module{}), do: X402.Behaviour.implements?(module, @engine_callbacks)
    defp engine_struct?(_other), do: false

    @spec invalid_engines_message() :: String.t()
    defp invalid_engines_message do
      "expected a non-empty list of engine structs whose modules export " <>
        "verify/3, settle/3, and supported/1 (e.g. X402.Facilitator.Engine, " <>
        "X402.Facilitator.SVMEngine)"
    end

    # NimbleOptions cannot express "exactly one of" across keys, so the
    # mutual exclusion is enforced here with the same exception type.
    @spec resolve_engines(map()) :: [struct()]
    defp resolve_engines(options) do
      case {Map.get(options, :engine), Map.get(options, :engines)} do
        {nil, nil} ->
          raise %NimbleOptions.ValidationError{
            key: :engine,
            message: "exactly one of :engine or :engines must be given"
          }

        {engine, nil} when engine != nil ->
          [engine]

        {nil, engines} ->
          engines

        {_engine, _engines} ->
          raise %NimbleOptions.ValidationError{
            key: :engines,
            message: ":engine and :engines are mutually exclusive — pass exactly one"
          }
      end
    end

    @doc since: "0.6.0"
    @doc """
    Dispatches a facilitator API request — see the module documentation for
    the endpoint and status contract.
    """
    @impl Plug
    @spec call(Plug.Conn.t(), options()) :: Plug.Conn.t()
    def call(%Plug.Conn{} = conn, options) do
      case authorized?(conn, options) do
        true -> dispatch(conn, options)
        false -> send_json(conn, 401, %{"error" => "unauthorized"})
      end
    end

    # -- Routing ----------------------------------------------------------------

    @spec dispatch(Plug.Conn.t(), options()) :: Plug.Conn.t()
    defp dispatch(%Plug.Conn{method: "POST", path_info: ["verify"]} = conn, options),
      do: handle_operation(conn, options, :verify)

    defp dispatch(%Plug.Conn{method: "POST", path_info: ["settle"]} = conn, options),
      do: handle_operation(conn, options, :settle)

    defp dispatch(%Plug.Conn{method: "GET", path_info: ["supported"]} = conn, options),
      do: send_json(conn, 200, merged_supported(options.engines))

    defp dispatch(%Plug.Conn{path_info: path} = conn, _options)
         when path in [["verify"], ["settle"], ["supported"]],
         do: send_json(conn, 405, %{"error" => "method_not_allowed"})

    # Bazaar discovery serving is intentionally out of scope for the
    # scaffold; the endpoint is optional in the facilitator API.
    defp dispatch(%Plug.Conn{path_info: ["discovery", "resources"]} = conn, _options),
      do: send_json(conn, 404, %{"error" => "discovery_not_supported"})

    defp dispatch(conn, _options), do: send_json(conn, 404, %{"error" => "not_found"})

    # -- Operations -------------------------------------------------------------

    @spec handle_operation(Plug.Conn.t(), options(), :verify | :settle) :: Plug.Conn.t()
    defp handle_operation(conn, options, operation) do
      case read_wire_object(conn, options) do
        {:ok, payment_payload, payment_requirements, conn} ->
          run_engine(conn, options, operation, payment_payload, payment_requirements)

        {:reject, status, body, conn} ->
          send_json(conn, status, body)
      end
    end

    @spec run_engine(Plug.Conn.t(), options(), :verify | :settle, map(), map()) :: Plug.Conn.t()
    defp run_engine(conn, options, operation, payment_payload, payment_requirements) do
      scheme = payment_requirements["scheme"]
      network = payment_requirements["network"]

      case select_engine(options.engines, scheme, network) do
        {:ok, %module{} = engine} ->
          case apply(module, operation, [engine, payment_payload, payment_requirements]) do
            {:ok, response} ->
              send_json(conn, 200, response)

            {:error, reason} ->
              # Opaque on the wire; the operator sees the real reason here.
              Logger.error("x402 facilitator #{operation} failed: #{inspect(reason)}")
              send_json(conn, 500, %{"error" => "internal_server_error"})
          end

        {:unsupported, reason} ->
          # Facilitator convention: no matching engine is a protocol-level
          # rejection, not a transport error.
          send_json(conn, 200, unsupported_response(operation, reason, network))
      end
    end

    # -- Engine selection ---------------------------------------------------------

    @spec select_engine([struct()], term(), term()) ::
            {:ok, struct()} | {:unsupported, String.t()}
    defp select_engine(engines, scheme, network) do
      case Enum.find(engines, &engine_supports?(&1, scheme, network)) do
        nil -> {:unsupported, no_engine_reason(engines, scheme)}
        engine -> {:ok, engine}
      end
    end

    @spec engine_supports?(struct(), term(), term()) :: boolean()
    defp engine_supports?(engine, scheme, network) do
      engine
      |> engine_kinds()
      |> Enum.any?(fn kind -> kind["scheme"] == scheme and kind["network"] == network end)
    end

    @spec engine_kinds(struct()) :: [map()]
    defp engine_kinds(%module{} = engine) do
      case module.supported(engine) do
        %{"kinds" => kinds} when is_list(kinds) -> kinds
        _other -> []
      end
    end

    # A scheme some engine serves (on other networks) rejects with the
    # narrower invalid_network; a scheme no engine serves at all with
    # unsupported_scheme.
    @spec no_engine_reason([struct()], term()) :: String.t()
    defp no_engine_reason(engines, scheme) do
      scheme_known? =
        Enum.any?(engines, fn engine ->
          Enum.any?(engine_kinds(engine), &(&1["scheme"] == scheme))
        end)

      case scheme_known? do
        true -> "invalid_network"
        false -> "unsupported_scheme"
      end
    end

    @spec unsupported_response(:verify | :settle, String.t(), term()) :: map()
    defp unsupported_response(:verify, reason, _network),
      do: %{"isValid" => false, "invalidReason" => reason}

    defp unsupported_response(:settle, reason, network) do
      %{
        "success" => false,
        "errorReason" => reason,
        "transaction" => "",
        "network" => network_or_empty(network)
      }
    end

    @spec network_or_empty(term()) :: String.t()
    defp network_or_empty(network) when is_binary(network), do: network
    defp network_or_empty(_network), do: ""

    # -- GET /supported merging ---------------------------------------------------

    @spec merged_supported([struct()]) :: map()
    defp merged_supported(engines) do
      responses = Enum.map(engines, fn %module{} = engine -> module.supported(engine) end)

      %{
        "kinds" => merge_lists(responses, "kinds"),
        "extensions" => merge_lists(responses, "extensions"),
        "signers" => merge_signers(responses)
      }
    end

    @spec merge_lists([map()], String.t()) :: [term()]
    defp merge_lists(responses, key) do
      responses
      |> Enum.flat_map(&List.wrap(Map.get(&1, key)))
      |> Enum.uniq()
    end

    @spec merge_signers([map()]) :: %{optional(String.t()) => [String.t()]}
    defp merge_signers(responses) do
      responses
      |> Enum.flat_map(fn response ->
        case Map.get(response, "signers") do
          %{} = signers -> Map.to_list(signers)
          _other -> []
        end
      end)
      |> Enum.reduce(%{}, fn {family, addresses}, acc ->
        Map.update(acc, family, Enum.uniq(List.wrap(addresses)), fn existing ->
          Enum.uniq(existing ++ List.wrap(addresses))
        end)
      end)
    end

    # -- Body parsing -----------------------------------------------------------

    @spec read_wire_object(Plug.Conn.t(), options()) ::
            {:ok, map(), map(), Plug.Conn.t()}
            | {:reject, non_neg_integer(), map(), Plug.Conn.t()}
    defp read_wire_object(conn, options) do
      # Behind Plug.Parsers (a Phoenix endpoint, `forward`), the raw body has
      # already been consumed and lives in body_params — a second read_body
      # would return empty and 400 every request. Use the parsed map when
      # present; read the raw body only when it is still unfetched.
      case conn.body_params do
        %Plug.Conn.Unfetched{} -> read_raw_wire_object(conn, options)
        %{} = params -> validate_wire_map(params, conn)
      end
    end

    @spec read_raw_wire_object(Plug.Conn.t(), options()) ::
            {:ok, map(), map(), Plug.Conn.t()}
            | {:reject, non_neg_integer(), map(), Plug.Conn.t()}
    defp read_raw_wire_object(conn, options) do
      case read_body(conn, length: options.max_body_bytes, read_length: options.max_body_bytes) do
        {:ok, body, conn} ->
          parse_wire_object(body, conn)

        {:more, _partial, conn} ->
          {:reject, 413, %{"error" => "payload_too_large"}, conn}

        {:error, _reason} ->
          {:reject, 400, %{"error" => "invalid_request", "reason" => "unreadable_body"}, conn}
      end
    end

    # Strict v2 wire object: exactly x402Version/paymentPayload/
    # paymentRequirements, nothing else.
    @spec parse_wire_object(binary(), Plug.Conn.t()) ::
            {:ok, map(), map(), Plug.Conn.t()}
            | {:reject, non_neg_integer(), map(), Plug.Conn.t()}
    defp parse_wire_object(body, conn) do
      case Jason.decode(body) do
        {:ok, %{} = wire} ->
          validate_wire_map(wire, conn)

        {:ok, _other} ->
          {:reject, 400, %{"error" => "invalid_request", "reason" => "invalid_wire_object"}, conn}

        {:error, _reason} ->
          {:reject, 400, %{"error" => "invalid_request", "reason" => "invalid_json"}, conn}
      end
    end

    @spec validate_wire_map(map(), Plug.Conn.t()) ::
            {:ok, map(), map(), Plug.Conn.t()}
            | {:reject, non_neg_integer(), map(), Plug.Conn.t()}
    defp validate_wire_map(wire, conn) do
      case wire do
        %{
          "x402Version" => 2,
          "paymentPayload" => %{} = payment_payload,
          "paymentRequirements" => %{} = payment_requirements
        }
        when map_size(wire) == 3 ->
          {:ok, payment_payload, payment_requirements, conn}

        %{"x402Version" => version} when version != 2 ->
          {:reject, 400, %{"error" => "invalid_request", "reason" => "invalid_x402_version"},
           conn}

        _other ->
          {:reject, 400, %{"error" => "invalid_request", "reason" => "invalid_wire_object"}, conn}
      end
    end

    # -- Auth -------------------------------------------------------------------

    @spec authorized?(Plug.Conn.t(), options()) :: boolean()
    defp authorized?(_conn, %{auth_token: nil}), do: true

    defp authorized?(conn, %{auth_token: auth_token}) do
      case get_req_header(conn, "authorization") do
        ["Bearer " <> presented] -> Plug.Crypto.secure_compare(presented, auth_token)
        _other -> false
      end
    end

    # -- Responses --------------------------------------------------------------

    @spec send_json(Plug.Conn.t(), non_neg_integer(), map()) :: Plug.Conn.t()
    defp send_json(conn, status, body) do
      conn
      |> put_resp_content_type("application/json")
      |> send_resp(status, Jason.encode!(body))
    end
  end
end
