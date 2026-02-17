if Code.ensure_loaded?(Plug) and Code.ensure_loaded?(Plug.Conn) do
  defmodule X402.Plug.PaymentGate do
    @moduledoc """
    Plug middleware that gates configured routes behind x402 payment verification.

    For matching routes, requests without an `x-payment` header receive a `402`
    response with x402 payment requirements. Requests with `x-payment` are
    decoded, verified, and settled with the configured facilitator before the
    request is allowed to continue through the plug pipeline.

    Route definitions support both x402 schemes:

    - `:exact` (default) where `price` maps to `"maxAmountRequired"`
    - `:upto` where `price` maps to `"maxPrice"`
    """

    @behaviour Plug

    alias X402.Facilitator
    alias X402.Facilitator.Error
    alias X402.PaymentSignature

    import Plug.Conn, only: [get_req_header: 2, halt: 1, put_resp_content_type: 2, send_resp: 3]

    @http_methods [:any, :delete, :get, :head, :options, :patch, :post, :put, :trace]

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
      price: [
        type: :string,
        required: true,
        doc: "Price for this route (`maxAmountRequired` for `:exact`, `maxPrice` for `:upto`)."
      ],
      scheme: [
        type: {:in, [:exact, :upto]},
        default: :exact,
        doc: "x402 scheme for this route."
      ],
      network: [
        type: :string,
        required: true,
        doc: "x402 network identifier (for example `base-sepolia`)."
      ],
      asset: [
        type: :string,
        required: true,
        doc: "Asset symbol (for example `USDC`)."
      ],
      receiver: [
        type: :string,
        required: true,
        doc: "Receiver wallet address."
      ]
    ]

    @options_schema [
      facilitator: [
        type: :any,
        default: Facilitator,
        doc: "Facilitator server pid/name used for verification and settlement."
      ],
      routes: [
        type: {:list, {:map, @route_schema}},
        required: true,
        doc: "Route gate definitions."
      ]
    ]

    @typedoc "Configuration map produced by `init/1`."
    @type options :: %{
            facilitator: Facilitator.server(),
            routes: [compiled_route()]
          }

    @typedoc false
    @type compiled_route :: %{
            method: atom(),
            matcher: :exact | :glob,
            path: String.t(),
            glob_regex: Regex.t() | nil,
            scheme: :exact | :upto,
            price: String.t(),
            network: String.t(),
            asset: String.t(),
            receiver: String.t()
          }

    @doc since: "0.1.0"
    @doc """
    Validates and compiles `X402.Plug.PaymentGate` options.

    ## Options

    #{NimbleOptions.docs(@options_schema)}
    """
    @spec init(keyword()) :: options()
    def init(opts) when is_list(opts) do
      validated_opts = NimbleOptions.validate!(opts, @options_schema)

      %{
        facilitator: Keyword.fetch!(validated_opts, :facilitator),
        routes:
          validated_opts
          |> Keyword.fetch!(:routes)
          |> Enum.map(&compile_route/1)
      }
    end

    @doc since: "0.1.0"
    @doc """
    Gates matching requests behind x402 payment verification.
    """
    @spec call(Plug.Conn.t(), options()) :: Plug.Conn.t()
    def call(%Plug.Conn{} = conn, %{facilitator: facilitator, routes: routes}) do
      request_path = normalize_path(conn.request_path)
      request_method = normalize_method(conn.method)

      case match_route(routes, request_method, request_path) do
        nil ->
          emit(:pass_through, %{method: request_method, path: request_path})
          conn

        route ->
          handle_payment_gate(conn, facilitator, route, request_method, request_path)
      end
    end

    @spec handle_payment_gate(
            Plug.Conn.t(),
            Facilitator.server(),
            compiled_route(),
            atom(),
            String.t()
          ) :: Plug.Conn.t()
    defp handle_payment_gate(conn, facilitator, route, request_method, request_path) do
      case payment_header(conn) do
        :missing ->
          emit(:payment_required, %{method: request_method, path: request_path, route: route.path})

          payment_required_response(conn, route, request_path, "")

        {:ok, header} ->
          verify_and_settle(conn, facilitator, route, request_method, request_path, header)

        {:error, reason} ->
          emit(:payment_rejected, %{
            method: request_method,
            path: request_path,
            route: route.path,
            reason: reason
          })

          payment_required_response(conn, route, request_path, rejection_error(reason))
      end
    end

    @spec verify_and_settle(
            Plug.Conn.t(),
            Facilitator.server(),
            compiled_route(),
            atom(),
            String.t(),
            String.t()
          ) :: Plug.Conn.t()
    defp verify_and_settle(conn, facilitator, route, request_method, request_path, header) do
      requirements = facilitator_requirements(route, request_path)

      with {:ok, payment_payload} <- PaymentSignature.decode_and_validate(header, requirements),
           {:ok, verify_response} <-
             Facilitator.verify(facilitator, payment_payload, requirements),
           :ok <- ensure_success_status(verify_response),
           {:ok, settle_response} <-
             Facilitator.settle(facilitator, payment_payload, requirements),
           :ok <- ensure_success_status(settle_response) do
        emit(:payment_verified, %{method: request_method, path: request_path, route: route.path})
        conn
      else
        {:error, reason} ->
          emit(:payment_rejected, %{
            method: request_method,
            path: request_path,
            route: route.path,
            reason: reason
          })

          payment_required_response(conn, route, request_path, rejection_error(reason))
      end
    end

    @spec compile_route(map()) :: compiled_route()
    defp compile_route(%{} = route) do
      normalized_path = normalize_path(Map.fetch!(route, :path))
      matcher = path_matcher(normalized_path)

      %{
        method: Map.fetch!(route, :method),
        matcher: matcher,
        path: normalized_path,
        glob_regex: glob_regex(matcher, normalized_path),
        scheme: Map.get(route, :scheme, :exact),
        price: Map.fetch!(route, :price),
        network: Map.fetch!(route, :network),
        asset: Map.fetch!(route, :asset),
        receiver: Map.fetch!(route, :receiver)
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
      case get_req_header(conn, "x-payment") do
        [] -> :missing
        [header | _] when is_binary(header) and header != "" -> {:ok, header}
        _ -> {:error, :invalid_payment_header}
      end
    end

    @spec ensure_success_status(%{status: non_neg_integer(), body: map()}) ::
            :ok | {:error, {:unexpected_facilitator_status, non_neg_integer()}}
    defp ensure_success_status(%{status: status}) when status in 200..299, do: :ok

    defp ensure_success_status(%{status: status}),
      do: {:error, {:unexpected_facilitator_status, status}}

    @spec facilitator_requirements(compiled_route(), String.t()) :: map()
    defp facilitator_requirements(route, request_path) do
      route
      |> requirement_base(request_path)
      |> put_requirement_amount(route)
    end

    @spec payment_required_response(Plug.Conn.t(), compiled_route(), String.t(), String.t()) ::
            Plug.Conn.t()
    defp payment_required_response(conn, route, request_path, error_message) do
      body = payment_required_body(route, request_path, error_message)

      conn
      |> put_resp_content_type("application/json")
      |> send_resp(402, body)
      |> halt()
    end

    @spec payment_required_body(compiled_route(), String.t(), String.t()) :: String.t()
    defp payment_required_body(route, request_path, error_message) do
      Jason.encode!(%{
        "x402Version" => 1,
        "accepts" => [accept_entry(route, request_path)],
        "error" => error_message
      })
    end

    @spec accept_entry(compiled_route(), String.t()) :: map()
    defp accept_entry(route, request_path) do
      route
      |> requirement_base(request_path)
      |> put_requirement_amount(route)
    end

    @spec requirement_base(compiled_route(), String.t()) :: map()
    defp requirement_base(route, request_path) do
      %{
        "scheme" => scheme_string(route.scheme),
        "network" => route.network,
        "asset" => route.asset,
        "resource" => request_path,
        "description" => "Payment required",
        "mimeType" => "application/json",
        "payTo" => route.receiver,
        "maxTimeoutSeconds" => 60,
        "extra" => %{}
      }
    end

    @spec put_requirement_amount(map(), compiled_route()) :: map()
    defp put_requirement_amount(requirement, route) do
      case route.scheme do
        :upto -> Map.put(requirement, "maxPrice", route.price)
        :exact -> Map.put(requirement, "maxAmountRequired", route.price)
      end
    end

    @spec scheme_string(:exact | :upto) :: String.t()
    defp scheme_string(:exact), do: "exact"
    defp scheme_string(:upto), do: "upto"

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

    @spec rejection_error(
            :invalid_payment_header
            | PaymentSignature.decode_and_validate_error()
            | {:unexpected_facilitator_status, non_neg_integer()}
            | Error.t()
            | term()
          ) :: String.t()
    defp rejection_error(:invalid_payment_header), do: "invalid payment header"
    defp rejection_error(:invalid_base64), do: "invalid payment header"
    defp rejection_error(:invalid_json), do: "invalid payment header"
    defp rejection_error(:invalid_payload), do: "invalid payment payload"
    defp rejection_error({:missing_fields, _fields}), do: "invalid payment payload"

    defp rejection_error({:value_exceeds_max_price, _value, _max_price}),
      do: "invalid payment payload"

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
