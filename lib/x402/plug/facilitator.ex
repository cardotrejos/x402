if Code.ensure_loaded?(Plug) and Code.ensure_loaded?(Plug.Conn) do
  defmodule X402.Plug.Facilitator do
    @moduledoc """
    Plug scaffold exposing an `X402.Facilitator.Engine` as the facilitator
    HTTP API.

    Serves the x402 v2 facilitator endpoints over any Plug-compatible server
    (Bandit, Cowboy, or mounted inside a Phoenix endpoint):

    | Endpoint                   | Behaviour                                          |
    | -------------------------- | -------------------------------------------------- |
    | `POST /verify`             | `X402.Facilitator.Engine.verify/3`                 |
    | `POST /settle`             | `X402.Facilitator.Engine.settle/3`                 |
    | `GET /supported`           | `X402.Facilitator.Engine.supported/1`              |
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
        required: true,
        doc: "The `X402.Facilitator.Engine` configuration built with `Engine.new/1`."
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
            engine: Engine.t(),
            auth_token: String.t() | nil,
            max_body_bytes: pos_integer()
          }

    @doc since: "0.6.0"
    @doc """
    Validates the plug options.

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
      do: send_json(conn, 200, Engine.supported(options.engine))

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
      case apply(Engine, operation, [options.engine, payment_payload, payment_requirements]) do
        {:ok, response} ->
          send_json(conn, 200, response)

        {:error, reason} ->
          # Opaque on the wire; the operator sees the real reason here.
          Logger.error("x402 facilitator #{operation} failed: #{inspect(reason)}")
          send_json(conn, 500, %{"error" => "internal_server_error"})
      end
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
