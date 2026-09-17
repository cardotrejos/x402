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

  ## Spend controls

  Cap what an automated payer signs with `:max_amount` (per payment),
  `:policies` (`X402.Client.Policy` filters on network, asset, scheme, or
  anything else), and `:budget` (an `X402.Client.Budget` shared across
  requests). With none of them configured a warning is logged once.

  ## Sign-In-With-X

  With `siwx: [chain_id: :auto]` the client answers a server's
  `sign-in-with-x` challenge before paying: a returning payer whose address
  the server remembers gets the resource without a new payment
  (`siwx_authenticated: true` in the response); otherwise the payment flow
  runs as usual, with the proof attached to the paid request too.

  ## Security

  Like the facilitator client, URLs must use `https://` — payment
  authorizations must never travel in plaintext. Loopback hosts
  (`localhost`, `127.0.0.1`, `::1`) are exempt for local development.
  """

  alias X402.Client
  alias X402.Client.Budget
  alias X402.Client.Hooks
  alias X402.Client.SIWX, as: ClientSIWX
  alias X402.Extensions.SIWX
  alias X402.PaymentRequired
  alias X402.PaymentResponse
  alias X402.Telemetry
  alias X402.Utils

  @loopback_hosts ["localhost", "127.0.0.1", "::1"]
  @siwx_header String.downcase(SIWX.header_name())

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
    policies: [
      type: {:list, {:fun, 2}},
      default: [],
      doc: """
      Selection policies forwarded to `X402.Client.select_requirements/2` —
      see `X402.Client.Policy`.
      """
    ],
    budget: [
      type: {:or, [nil, {:custom, Budget, :validate_ref, []}]},
      default: nil,
      doc: """
      An `X402.Client.Budget` the selected amount is reserved against
      before the paid retry is sent. See `X402.Client.Budget` for what
      counts as spent.
      """
    ],
    hooks: [
      type: {:custom, Hooks, :validate_module, []},
      default: Hooks.Default,
      doc: """
      `X402.Client.Hooks` module forwarded to `X402.Client.build_payment/3`.
      """
    ],
    siwx: [
      type: {:custom, ClientSIWX, :validate_opts, []},
      default: nil,
      doc: """
      Automatic Sign-In-With-X: a keyword list of `X402.Client.SIWX`
      options (`chain_id:` required, or `:auto`). `nil`/`false` disables
      it.
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
  `:siwx_authenticated` is `true` when the server accepted a Sign-In-With-X
  proof instead of a payment (see the `:siwx` option).
  """
  @type response :: %{
          status: non_neg_integer(),
          headers: [{String.t(), String.t()}],
          body: binary(),
          payment_response: map() | nil,
          siwx_authenticated: boolean()
        }

  @type request_error ::
          :missing_dependency
          | :insecure_url
          | :payment_cancelled
          | :payment_already_attempted
          | {:transport_error, term()}
          | {:invalid_payment_required, term()}
          | {:siwx, ClientSIWX.reason()}
          | Budget.reserve_error()
          | Client.build_error()

  @doc since: "0.6.0"
  @doc """
  Performs an HTTP request, paying for the resource if it requires payment.

  Flow:

  1. Perform the request. Anything other than a `402` with a
     `PAYMENT-REQUIRED` header is returned as-is.
  2. Decode the `PAYMENT-REQUIRED` header (`X402.PaymentRequired.decode/1`).
  3. With `:siwx` configured and a `sign-in-with-x` challenge advertised,
     sign it (`X402.Client.SIWX.authenticate/4`) and retry the request with
     the `SIGN-IN-WITH-X` header and no payment. Anything other than a
     `402` with a `PAYMENT-REQUIRED` header is returned as-is, with
     `siwx_authenticated: true` for a 2xx. On a second `402` the flow
     continues with the new payment requirements; the paid request carries a
     proof for the new challenge (when advertised) so the server can record
     the payer.
  4. Invoke the `:on_payment_required` hook, which may cancel.
  5. Build and sign a payment (`X402.Client.build_payment/3`), reserve its
     amount against `:budget` (when given), and retry the request once with
     the `PAYMENT-SIGNATURE` header.
  6. Return the retried response with the decoded `PAYMENT-RESPONSE`
     settlement receipt, when present. A second `402` is returned as-is —
     the payment is never re-signed or re-sent — and the budget
     reservation is released unless the response is 2xx or carries a
     successful receipt.

  When neither `:max_amount`, `:policies`, nor `:budget` is given a warning
  is logged once per VM: the client will then sign any amount a server asks
  for.

  ## Options

  #{NimbleOptions.docs(@request_opts_schema)}
  """
  @spec request(finch_name(), String.t(), keyword()) ::
          {:ok, response()} | {:error, request_error()}
  def request(finch_name, url, opts) when is_binary(url) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @request_opts_schema)
    maybe_warn_no_spend_limit(opts)

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
    case X402.Behaviour.implements?(module, address: 1, sign_eip712: 3) or
           X402.Behaviour.implements?(module, address: 1, sign_ed25519: 2) do
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
         {:ok, outcome} <- try_siwx(ctx, payment_required) do
      case outcome do
        {:done, response} -> {:ok, response}
        {:pay, payment_required, siwx_headers} -> pay(ctx, payment_required, siwx_headers)
      end
    end
  end

  @spec pay(map(), map(), [{String.t(), String.t()}]) ::
          {:ok, response()} | {:error, request_error()}
  defp pay(ctx, payment_required, siwx_headers) do
    headers = Keyword.fetch!(ctx.opts, :headers) ++ siwx_headers

    with :ok <- consent(ctx.opts, payment_required),
         {:ok, payload} <-
           Client.build_payment(payment_required, ctx.opts[:signer], build_opts(ctx.opts)),
         {:ok, payment_header} <- Client.encode_payment(payload),
         :ok <- reserve_budget(ctx.opts, payload),
         {:ok, response} <-
           ctx
           |> perform(headers ++ [{"payment-signature", payment_header}])
           |> settle_budget(ctx.opts, payload) do
      {:ok, finalize(response)}
    end
  end

  # -- Sign-In-With-X ---------------------------------------------------------

  # Outcome of the SIWX attempt: `{:done, response}` when the server answered
  # the proof with anything but a fresh payment challenge, or
  # `{:pay, payment_required, siwx_headers}` with the challenge to pay for and
  # the proof headers to send along with the payment.
  @spec try_siwx(map(), map()) ::
          {:ok, {:done, response()} | {:pay, map(), [{String.t(), String.t()}]}}
          | {:error, request_error()}
  defp try_siwx(%{opts: opts} = ctx, payment_required) do
    case Keyword.fetch!(opts, :siwx) do
      nil ->
        {:ok, {:pay, payment_required, []}}

      siwx_opts ->
        case sign_siwx(ctx, payment_required, siwx_opts) do
          {:ok, []} -> {:ok, {:pay, payment_required, []}}
          {:ok, siwx_headers} -> authenticate_siwx(ctx, siwx_headers, siwx_opts)
          {:error, _reason} = error -> error
        end
    end
  end

  @spec sign_siwx(map(), map(), keyword()) ::
          {:ok, [{String.t(), String.t()}]} | {:error, {:siwx, ClientSIWX.reason()}}
  defp sign_siwx(ctx, payment_required, siwx_opts) do
    case ClientSIWX.authenticate(payment_required, ctx.opts[:signer], siwx_opts,
           resource_url: ctx.url
         ) do
      {:ok, proof} -> {:ok, [{@siwx_header, proof.header}]}
      :none -> {:ok, []}
      {:error, _reason} = error -> error
    end
  end

  @spec authenticate_siwx(map(), [{String.t(), String.t()}], keyword()) ::
          {:ok, {:done, response()} | {:pay, map(), [{String.t(), String.t()}]}}
          | {:error, request_error()}
  defp authenticate_siwx(ctx, siwx_headers, siwx_opts) do
    headers = Keyword.fetch!(ctx.opts, :headers) ++ siwx_headers

    with {:ok, response} <- perform(ctx, headers) do
      case {response.status, fetch_header(response.headers, "payment-required")} do
        {402, header_value} when is_binary(header_value) ->
          emit_siwx(:payment_required)
          pay_with_fresh_proof(ctx, header_value, siwx_opts)

        {status, _header} when status in 200..299 ->
          emit_siwx(:authenticated)
          {:ok, {:done, finalize(response, true)}}

        {_status, _header} ->
          {:ok, {:done, finalize(response, false)}}
      end
    end
  end

  @spec pay_with_fresh_proof(map(), String.t(), keyword()) ::
          {:ok, {:pay, map(), [{String.t(), String.t()}]}} | {:error, request_error()}
  defp pay_with_fresh_proof(ctx, header_value, siwx_opts) do
    with {:ok, payment_required} <- decode_payment_required(header_value),
         {:ok, siwx_headers} <- sign_siwx(ctx, payment_required, siwx_opts) do
      {:ok, {:pay, payment_required, siwx_headers}}
    end
  end

  @spec emit_siwx(:authenticated | :payment_required) :: :ok
  defp emit_siwx(outcome),
    do: Telemetry.emit(:client, :siwx, :ok, %{transport: :http, outcome: outcome})

  # -- Budget -----------------------------------------------------------------

  @spec reserve_budget(keyword(), map()) :: :ok | {:error, Budget.reserve_error()}
  defp reserve_budget(opts, payload) do
    case Keyword.fetch!(opts, :budget) do
      nil -> :ok
      budget -> Budget.reserve(budget, accepted_asset(payload), accepted_amount(payload))
    end
  end

  # The reservation stands once the server answered 2xx or attached a
  # successful settlement receipt; any other outcome means the payment was
  # not accepted and the amount is given back.
  @spec settle_budget({:ok, map()} | {:error, term()}, keyword(), map()) ::
          {:ok, map()} | {:error, term()}
  defp settle_budget(result, opts, payload) do
    case Keyword.fetch!(opts, :budget) do
      nil -> result
      budget -> settle_budget(result, budget, payload, accepted?(result))
    end
  end

  @spec settle_budget({:ok, map()} | {:error, term()}, Budget.budget(), map(), boolean()) ::
          {:ok, map()} | {:error, term()}
  defp settle_budget(result, _budget, _payload, true), do: result

  defp settle_budget(result, budget, payload, false) do
    Budget.release(budget, accepted_asset(payload), accepted_amount(payload))
    result
  end

  @spec accepted?({:ok, map()} | {:error, term()}) :: boolean()
  defp accepted?({:ok, %{status: status} = response}) do
    status in 200..299 or
      match?(%{"success" => true}, decode_payment_response_header(response.headers))
  end

  defp accepted?({:error, _reason}), do: false

  @spec accepted_asset(map()) :: String.t()
  defp accepted_asset(payload), do: accepted_field(payload, {"asset", :asset}) || ""

  @spec accepted_amount(map()) :: term()
  defp accepted_amount(payload), do: accepted_field(payload, {"amount", :amount})

  @spec accepted_field(map(), {String.t(), atom()}) :: term()
  defp accepted_field(payload, keys) do
    case Utils.map_value(payload, {"accepted", :accepted}) do
      %{} = accepted -> Utils.map_value(accepted, keys)
      _other -> nil
    end
  end

  @spec maybe_warn_no_spend_limit(keyword()) :: :ok
  defp maybe_warn_no_spend_limit(opts) do
    case {opts[:max_amount], Keyword.fetch!(opts, :policies), Keyword.fetch!(opts, :budget)} do
      {nil, [], nil} -> Client.warn_no_spend_limit_once(__MODULE__)
      _limited -> :ok
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
        :policies,
        :hooks,
        :valid_after_buffer,
        :extensions,
        :schemes
      ])

  @spec finalize(map(), boolean()) :: response()
  defp finalize(response, siwx_authenticated \\ false) do
    %{
      status: response.status,
      headers: response.headers,
      body: response.body,
      payment_response: decode_payment_response_header(response.headers),
      siwx_authenticated: siwx_authenticated
    }
  end

  @spec decode_payment_response_header([{String.t(), String.t()}]) :: map() | nil
  defp decode_payment_response_header(headers) do
    with header_value when is_binary(header_value) <- fetch_header(headers, "payment-response"),
         {:ok, decoded} <- PaymentResponse.decode(header_value) do
      decoded
    else
      _absent_or_invalid -> nil
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
