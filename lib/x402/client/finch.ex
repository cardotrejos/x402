defmodule X402.Client.Finch do
  @moduledoc """
  Finch-backed payer client with an automatic 402 → sign → retry flow.

  `request/3` performs an HTTP request; when the server answers `402` with a
  `PAYMENT-REQUIRED` header, it decodes the payment requirements, builds and
  signs a payment via `X402.Client.build_payment/3`, and retries the request
  once with the `PAYMENT-SIGNATURE` header. A request is **never paid twice**:
  at most one payment retry is made, and requests that already carry a
  `payment-signature` header are refused.

  Requires the optional `finch` dependency; without it every call returns
  `{:error, :missing_dependency}`. Start your own Finch pool (with TLS peer
  verification — see `X402.Facilitator.HTTP.secure_pool_opts/0`) and pass its
  name.

  ## Example

      {:ok, signer} = X402.Signer.LocalKey.new(System.fetch_env!("PAYER_KEY"))

      {:ok, %{status: 200, body: body, payment_response: receipt}} =
        X402.Client.Finch.request(MyApp.Finch, "https://api.example.com/paid",
          signer: signer,
          max_amount: "10000",
          on_payment_required: fn payment_required ->
            IO.inspect(payment_required["accepts"], label: "about to pay")
            :ok
          end
        )

  ## Security

  Like the facilitator client, URLs must use `https://` — payment
  authorizations must never travel in plaintext. Loopback hosts
  (`localhost`, `127.0.0.1`, `::1`) are exempt for local development.
  """

  alias X402.Client
  alias X402.PaymentRequired
  alias X402.PaymentResponse
  alias X402.Telemetry

  @loopback_hosts ["localhost", "127.0.0.1", "::1"]

  @request_opts_schema [
    signer: [
      type: {:custom, __MODULE__, :validate_signer, []},
      required: true,
      doc: "A struct implementing `X402.Signer`, used to sign the payment."
    ],
    method: [
      type: {:in, [:get, :post, :put, :patch, :delete, :head, :options]},
      default: :get,
      doc: "HTTP request method."
    ],
    headers: [
      type: {:custom, __MODULE__, :validate_headers, []},
      default: [],
      doc: "Additional `{name, value}` request headers."
    ],
    body: [
      type: {:or, [:string, nil]},
      default: nil,
      doc: "Request body."
    ],
    receive_timeout_ms: [
      type: :non_neg_integer,
      default: 5_000,
      doc: "Finch receive timeout per attempt, in milliseconds."
    ],
    network: [
      type: :string,
      doc: "Payment selection filter — see `X402.Client.select_requirements/2`."
    ],
    scheme: [
      type: :string,
      doc: "Payment selection filter — see `X402.Client.select_requirements/2`."
    ],
    asset: [
      type: :string,
      doc: "Payment selection filter — see `X402.Client.select_requirements/2`."
    ],
    max_amount: [
      type: {:or, [:string, :non_neg_integer]},
      doc: """
      Maximum `amount` (atomic units) this client will pay — the budget guard
      for automated payers. Requirements above it are never selected.
      """
    ],
    valid_after_buffer: [
      type: :non_neg_integer,
      default: 60,
      doc: "Clock-skew buffer for the authorization's `validAfter`, in seconds."
    ],
    extensions: [
      type: {:list, {:fun, 2}},
      default: [],
      doc: """
      Client extension enrichers forwarded to
      `X402.Client.build_payment/3` — see its `:extensions` option.
      """
    ],
    schemes: [
      type: {:list, {:custom, X402.Scheme, :validate_module, []}},
      default: [],
      doc: """
      Additional `X402.Scheme` modules forwarded to
      `X402.Client.build_payment/3` — see its `:schemes` option.
      """
    ],
    on_payment_required: [
      type: {:or, [{:fun, 1}, nil]},
      default: nil,
      doc: """
      Budget/consent hook invoked with the decoded `PaymentRequired` map
      before any payment is signed. Return `:cancel` to abort with
      `{:error, :payment_cancelled}`; any other return value continues.
      """
    ]
  ]

  @typedoc "A Finch pool name or pid."
  @type finch_name :: atom() | pid() | {:via, module(), term()}

  @typedoc """
  A completed HTTP response.

  `:payment_response` holds the decoded `PAYMENT-RESPONSE` header (the
  settlement receipt) when the server sent a valid one, otherwise `nil`.
  """
  @type response :: %{
          status: non_neg_integer(),
          headers: [{String.t(), String.t()}],
          body: binary(),
          payment_response: map() | nil
        }

  @type request_error ::
          :missing_dependency
          | :insecure_url
          | :payment_cancelled
          | :payment_already_attempted
          | {:transport_error, term()}
          | {:invalid_payment_required, term()}
          | Client.build_error()

  @doc since: "0.6.0"
  @doc """
  Performs an HTTP request, paying for the resource if it requires payment.

  Flow:

  1. Perform the request. Anything other than a `402` with a
     `PAYMENT-REQUIRED` header is returned as-is.
  2. Decode the `PAYMENT-REQUIRED` header (`X402.PaymentRequired.decode/1`).
  3. Invoke the `:on_payment_required` hook, which may cancel.
  4. Build and sign a payment (`X402.Client.build_payment/3`) and retry the
     request once with the `PAYMENT-SIGNATURE` header.
  5. Return the retried response with the decoded `PAYMENT-RESPONSE`
     settlement receipt, when present. A second `402` is returned as-is —
     the payment is never re-signed or re-sent.

  ## Options

  #{NimbleOptions.docs(@request_opts_schema)}
  """
  @spec request(finch_name(), String.t(), keyword()) ::
          {:ok, response()} | {:error, request_error()}
  def request(finch_name, url, opts) when is_binary(url) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @request_opts_schema)

    result =
      with {:ok, finch_module} <- ensure_finch_module(),
           :ok <- validate_url_scheme(url) do
        ctx = %{
          finch_module: finch_module,
          finch_name: finch_name,
          url: url,
          opts: opts
        }

        with {:ok, response} <- perform(ctx, Keyword.fetch!(opts, :headers)) do
          maybe_pay(ctx, response)
        end
      end

    emit_request_telemetry(result)
    result
  end

  @doc false
  @spec validate_signer(term()) :: {:ok, struct()} | {:error, String.t()}
  def validate_signer(%module{} = signer) do
    case X402.Behaviour.implements?(module, address: 1, sign_eip712: 3) do
      true -> {:ok, signer}
      false -> {:error, "expected a struct implementing X402.Signer"}
    end
  end

  def validate_signer(_signer), do: {:error, "expected a struct implementing X402.Signer"}

  @doc false
  @spec validate_headers(term()) :: {:ok, [{String.t(), String.t()}]} | {:error, String.t()}
  def validate_headers(headers) when is_list(headers) do
    case Enum.all?(headers, &valid_header?/1) do
      true -> {:ok, headers}
      false -> {:error, "expected a list of {name, value} binary tuples"}
    end
  end

  def validate_headers(_headers), do: {:error, "expected a list of {name, value} binary tuples"}

  # -- Request flow -----------------------------------------------------------

  @spec perform(map(), [{String.t(), String.t()}]) ::
          {:ok, %{status: non_neg_integer(), headers: list(), body: binary()}}
          | {:error, {:transport_error, term()}}
  defp perform(ctx, headers) do
    opts = ctx.opts

    request =
      ctx.finch_module.build(
        Keyword.fetch!(opts, :method),
        ctx.url,
        headers,
        Keyword.fetch!(opts, :body)
      )

    finch_opts = [receive_timeout: Keyword.fetch!(opts, :receive_timeout_ms)]

    response =
      try do
        ctx.finch_module.request(request, ctx.finch_name, finch_opts)
      catch
        :exit, reason -> {:error, reason}
      end

    case response do
      {:ok, %{status: status, headers: response_headers, body: body}} ->
        {:ok, %{status: status, headers: response_headers, body: body}}

      {:error, reason} ->
        {:error, {:transport_error, reason}}
    end
  end

  @spec maybe_pay(map(), map()) :: {:ok, response()} | {:error, request_error()}
  defp maybe_pay(ctx, %{status: 402} = response) do
    case fetch_header(response.headers, "payment-required") do
      nil -> {:ok, finalize(response)}
      header_value -> pay_and_retry(ctx, header_value)
    end
  end

  defp maybe_pay(_ctx, response), do: {:ok, finalize(response)}

  @spec pay_and_retry(map(), String.t()) :: {:ok, response()} | {:error, request_error()}
  defp pay_and_retry(ctx, header_value) do
    headers = Keyword.fetch!(ctx.opts, :headers)

    with :ok <- ensure_not_already_paid(headers),
         {:ok, payment_required} <- decode_payment_required(header_value),
         :ok <- consent(ctx.opts, payment_required),
         {:ok, payload} <-
           Client.build_payment(payment_required, ctx.opts[:signer], build_opts(ctx.opts)),
         {:ok, payment_header} <- Client.encode_payment(payload),
         {:ok, response} <- perform(ctx, headers ++ [{"payment-signature", payment_header}]) do
      {:ok, finalize(response)}
    end
  end

  @spec ensure_not_already_paid([{String.t(), String.t()}]) ::
          :ok | {:error, :payment_already_attempted}
  defp ensure_not_already_paid(headers) do
    case fetch_header(headers, "payment-signature") do
      nil -> :ok
      _value -> {:error, :payment_already_attempted}
    end
  end

  @spec decode_payment_required(String.t()) ::
          {:ok, map()} | {:error, {:invalid_payment_required, term()}}
  defp decode_payment_required(header_value) do
    case PaymentRequired.decode(header_value) do
      {:ok, payment_required} -> {:ok, payment_required}
      {:error, reason} -> {:error, {:invalid_payment_required, reason}}
    end
  end

  @spec consent(keyword(), map()) :: :ok | {:error, :payment_cancelled}
  defp consent(opts, payment_required) do
    case Keyword.fetch!(opts, :on_payment_required) do
      nil ->
        :ok

      hook when is_function(hook, 1) ->
        case hook.(payment_required) do
          :cancel -> {:error, :payment_cancelled}
          _other -> :ok
        end
    end
  end

  @spec build_opts(keyword()) :: keyword()
  defp build_opts(opts),
    do:
      Keyword.take(opts, [
        :network,
        :scheme,
        :asset,
        :max_amount,
        :valid_after_buffer,
        :extensions,
        :schemes
      ])

  @spec finalize(map()) :: response()
  defp finalize(response) do
    payment_response =
      case fetch_header(response.headers, "payment-response") do
        nil -> nil
        header_value -> decode_payment_response(header_value)
      end

    %{
      status: response.status,
      headers: response.headers,
      body: response.body,
      payment_response: payment_response
    }
  end

  @spec decode_payment_response(String.t()) :: map() | nil
  defp decode_payment_response(header_value) do
    case PaymentResponse.decode(header_value) do
      {:ok, decoded} -> decoded
      {:error, _reason} -> nil
    end
  end

  @spec fetch_header([{String.t(), String.t()}], String.t()) :: String.t() | nil
  defp fetch_header(headers, name) do
    Enum.find_value(headers, fn
      {header_name, value} when is_binary(header_name) and is_binary(value) ->
        String.downcase(header_name) == name && value

      _header ->
        nil
    end)
  end

  @spec emit_request_telemetry({:ok, response()} | {:error, term()}) :: :ok
  defp emit_request_telemetry({:ok, response}),
    do: Telemetry.emit(:client, :request, :ok, %{status: response.status})

  defp emit_request_telemetry({:error, reason}),
    do: Telemetry.emit(:client, :request, :error, %{reason: reason})

  @spec valid_header?(term()) :: boolean()
  defp valid_header?({name, value}) when is_binary(name) and is_binary(value), do: true
  defp valid_header?(_header), do: false

  # Enforces HTTPS on resource URLs: the PAYMENT-SIGNATURE header carries a
  # signed, settleable payment authorization and must never travel in
  # plaintext. Loopback is exempt for local development (mirrors
  # X402.Facilitator.HTTP).
  @spec validate_url_scheme(String.t()) :: :ok | {:error, :insecure_url}
  defp validate_url_scheme(url) do
    case URI.parse(url) do
      %URI{scheme: "https"} -> :ok
      %URI{scheme: "http", host: host} when host in @loopback_hosts -> :ok
      _uri -> {:error, :insecure_url}
    end
  end

  # Resolved at runtime via Module.concat so the library compiles without the
  # optional Finch dependency (same pattern as X402.Facilitator.HTTP).
  @spec ensure_finch_module() :: {:ok, module()} | {:error, :missing_dependency}
  defp ensure_finch_module do
    finch_module = Module.concat(["Finch"])

    case Code.ensure_loaded?(finch_module) and function_exported?(finch_module, :request, 3) and
           function_exported?(finch_module, :build, 4) do
      true -> {:ok, finch_module}
      false -> {:error, :missing_dependency}
    end
  end
end
