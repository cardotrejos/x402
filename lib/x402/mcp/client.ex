defmodule X402.MCP.Client do
  @moduledoc """
  Client half of the x402 MCP transport: pay for tool calls automatically.

  `call/3` drives an arbitrary tool-call function (any MCP client library, or
  a plain function in tests) through the x402 detect → sign → retry-once loop:

  1. Perform the tool call. A result that is not payment-required is returned
     as-is.
  2. Extract the `PaymentRequired` object from the payment-required tool
     result (or from a `402`/`-32042` JSON-RPC error).
  3. With `:siwx` configured and a `sign-in-with-x` challenge advertised,
     sign it and retry the call with the proof in
     `_meta["x402/sign-in-with-x"]` and no payment; a result that is not
     payment-required is returned as-is.
  4. Invoke the `:on_payment_required` hook, which may cancel.
  5. Build and sign a payment via `X402.Client.build_payment/3`, reserve
     its amount against `:budget` (when given), and retry the tool call once
     with the payload in request `_meta["x402/payment"]`.
  6. Return the retried result with the decoded settlement receipt from
     result `_meta["x402/payment-response"]`, when present.

  A tool call is **never paid twice**: at most one payment retry is made, a
  second payment-required result is returned as-is, and requests that already
  carry `_meta["x402/payment"]` are refused.

  ## Example

      {:ok, signer} = X402.Signer.LocalKey.new(System.fetch_env!("PAYER_KEY"))

      request = %{"name" => "premium_search", "arguments" => %{"query" => "x402"}}

      {:ok, %{result: result, payment_response: receipt, paid: true}} =
        X402.MCP.Client.call(request, &MyMCP.call_tool/1,
          signer: signer,
          max_amount: "10000",
          on_payment_required: fn payment_required ->
            IO.inspect(payment_required["accepts"], label: "about to pay")
            :ok
          end
        )

  The tool-call function receives the (possibly payment-carrying) request map
  and may return the tool result map directly, `{:ok, result}`, or
  `{:error, reason}`.

  ## Spend controls

  Cap what an automated payer signs with `:max_amount` (per payment),
  `:policies` (`X402.Client.Policy` filters), and `:budget` (an
  `X402.Client.Budget` shared across calls; the reservation is released
  when the paid retry comes back as another payment-required result
  without a successful receipt). With none of them configured a warning is
  logged once.

  ## Sign-In-With-X

  With `siwx: [chain_id: :auto, domain: "mcp.example.com"]` the client
  answers a `sign-in-with-x` challenge advertised in the payment-required
  result before paying: the tool call is retried with the proof in
  `_meta["x402/sign-in-with-x"]` (see `X402.MCP.put_siwx/2`) and no
  payment. A result that is not payment-required is returned with
  `siwx_authenticated: true`; another payment-required result continues
  with the payment flow, the paid call carrying a proof for the new
  challenge. MCP resources have no HTTP origin, so pass `:domain` to pin
  the challenge to the server you expect.
  """

  alias X402.Client
  alias X402.Client.Budget
  alias X402.Client.Hooks
  alias X402.Client.SIWX, as: ClientSIWX
  alias X402.MCP
  alias X402.Signer
  alias X402.Telemetry
  alias X402.Utils

  @call_opts_schema [
    signer: [
      type: {:custom, __MODULE__, :validate_signer, []},
      required: true,
      doc: "A struct implementing `X402.Signer`, used to sign the payment."
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
      before the paid retry is made. See `X402.Client.Budget` for what
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
      options (`chain_id:` required, or `:auto`; `domain:` recommended).
      `nil`/`false` disables it.
      """
    ],
    valid_after_buffer: [
      type: :non_neg_integer,
      default: 60,
      doc: "Clock-skew buffer for the authorization's `validAfter`, in seconds."
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

  @typedoc """
  A completed tool call.

  `:result` is the final tool result map; `:payment_response` holds the
  decoded settlement receipt from `_meta["x402/payment-response"]` when the
  server sent one, otherwise `nil`; `:paid` tells whether a payment was
  signed and submitted; `:siwx_authenticated` tells whether the server
  accepted a Sign-In-With-X proof instead of a payment.
  """
  @type response :: %{
          result: map(),
          payment_response: map() | nil,
          paid: boolean(),
          siwx_authenticated: boolean()
        }

  @typedoc "A tool-call function driven by `call/3`."
  @type call_fun :: (map() -> map() | {:ok, map()} | {:error, term()})

  @type call_error ::
          :payment_already_attempted
          | :payment_cancelled
          | :invalid_tool_result
          | {:transport_error, term()}
          | {:siwx, ClientSIWX.reason()}
          | Budget.reserve_error()
          | Client.build_error()

  @doc since: "0.6.0"
  @doc """
  Performs a tool call, paying for the tool if it requires payment.

  See the module documentation for the full flow. Returns `{:ok, response()}`
  with the final tool result, or `{:error, reason}` when the payment was
  cancelled, could not be built, or the tool-call function failed.

  ## Options

  #{NimbleOptions.docs(@call_opts_schema)}
  """
  @spec call(map(), call_fun(), keyword()) :: {:ok, response()} | {:error, call_error()}
  def call(request, call_fun, opts)
      when is_map(request) and is_function(call_fun, 1) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @call_opts_schema)
    maybe_warn_no_spend_limit(opts)

    result = drive(request, call_fun, opts)
    emit_call_telemetry(result)
    result
  end

  @doc since: "0.6.0"
  @doc """
  Builds the request `_meta` map paying for a payment-required response.

  Accepts either a decoded `PaymentRequired` map or the payment-required tool
  result that carries one, selects and signs a payment option via
  `X402.Client.build_payment/3`, and returns the `_meta` entries to merge into
  the retried tool-call request. Options are forwarded to
  `X402.Client.build_payment/3`.

  Use this instead of `call/3` when your MCP library exposes request `_meta`
  but you want to drive the retry yourself.
  """
  @spec build_payment_meta(map(), Signer.t(), keyword()) ::
          {:ok, %{String.t() => map()}} | {:error, Client.build_error()}
  def build_payment_meta(payment_required_or_result, signer, opts \\ [])
      when is_map(payment_required_or_result) and is_list(opts) do
    payment_required =
      case MCP.fetch_payment_required(payment_required_or_result) do
        {:ok, payment_required} -> payment_required
        :error -> payment_required_or_result
      end

    with {:ok, payload} <- Client.build_payment(payment_required, signer, opts) do
      {:ok, %{MCP.payment_meta_key() => payload}}
    end
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

  # -- Payment flow -----------------------------------------------------------

  @spec drive(map(), call_fun(), keyword()) :: {:ok, response()} | {:error, call_error()}
  defp drive(request, call_fun, opts) do
    case attempt(call_fun, request) do
      {:ok, tool_result} -> maybe_pay(request, call_fun, opts, tool_result)
      {:error, :invalid_tool_result} = error -> error
      {:error, reason} -> maybe_pay_from_error(request, call_fun, opts, reason)
    end
  end

  @spec maybe_pay(map(), call_fun(), keyword(), map()) ::
          {:ok, response()} | {:error, call_error()}
  defp maybe_pay(request, call_fun, opts, tool_result) do
    case MCP.fetch_payment_required(tool_result) do
      {:ok, payment_required} -> pay_and_retry(request, call_fun, opts, payment_required)
      :error -> {:ok, finalize(tool_result, false)}
    end
  end

  @spec maybe_pay_from_error(map(), call_fun(), keyword(), term()) ::
          {:ok, response()} | {:error, call_error()}
  defp maybe_pay_from_error(request, call_fun, opts, reason) do
    case MCP.fetch_payment_required_from_error(reason) do
      {:ok, payment_required} -> pay_and_retry(request, call_fun, opts, payment_required)
      :error -> {:error, {:transport_error, reason}}
    end
  end

  @spec pay_and_retry(map(), call_fun(), keyword(), map()) ::
          {:ok, response()} | {:error, call_error()}
  defp pay_and_retry(request, call_fun, opts, payment_required) do
    with :ok <- ensure_not_already_paid(request),
         {:ok, outcome} <- try_siwx(request, call_fun, opts, payment_required) do
      case outcome do
        {:done, response} -> {:ok, response}
        {:pay, payment_required, request} -> pay(request, call_fun, opts, payment_required)
      end
    end
  end

  @spec pay(map(), call_fun(), keyword(), map()) :: {:ok, response()} | {:error, call_error()}
  defp pay(request, call_fun, opts, payment_required) do
    with :ok <- consent(opts, payment_required),
         {:ok, payload} <-
           Client.build_payment(payment_required, opts[:signer], build_opts(opts)),
         :ok <- reserve_budget(opts, payload),
         {:ok, retry_result} <-
           call_fun
           |> retry(MCP.put_payment(request, payload))
           |> settle_budget(opts, payload) do
      # A second payment-required result is returned as-is — the payment is
      # never re-signed or re-sent.
      {:ok, finalize(retry_result, true)}
    end
  end

  # -- Sign-In-With-X ---------------------------------------------------------

  # Outcome of the SIWX attempt: `{:done, response}` when the server answered
  # the proof with anything but a fresh payment challenge, or
  # `{:pay, payment_required, request}` with the challenge to pay for and the
  # request (carrying the proof for it) to attach the payment to.
  @spec try_siwx(map(), call_fun(), keyword(), map()) ::
          {:ok, {:done, response()} | {:pay, map(), map()}} | {:error, call_error()}
  defp try_siwx(request, call_fun, opts, payment_required) do
    case Keyword.fetch!(opts, :siwx) do
      nil ->
        {:ok, {:pay, payment_required, request}}

      siwx_opts ->
        case sign_siwx(request, opts, payment_required, siwx_opts) do
          :none -> {:ok, {:pay, payment_required, request}}
          {:ok, proving} -> authenticate_siwx(request, proving, call_fun, opts, siwx_opts)
          {:error, _reason} = error -> error
        end
    end
  end

  # Returns the request carrying a proof for the advertised challenge, or
  # `:none` when the server advertised no challenge.
  @spec sign_siwx(map(), keyword(), map(), keyword()) ::
          {:ok, map()} | :none | {:error, {:siwx, ClientSIWX.reason()}}
  defp sign_siwx(request, opts, payment_required, siwx_opts) do
    case ClientSIWX.authenticate(payment_required, opts[:signer], siwx_opts) do
      {:ok, proof} -> {:ok, MCP.put_siwx(request, proof.header)}
      :none -> :none
      {:error, _reason} = error -> error
    end
  end

  # A second challenge gets a fresh proof (its nonce differs from the one
  # just used); without one the paid call goes out with no proof at all
  # rather than a stale one.
  @spec authenticate_siwx(map(), map(), call_fun(), keyword(), keyword()) ::
          {:ok, {:done, response()} | {:pay, map(), map()}} | {:error, call_error()}
  defp authenticate_siwx(request, proving, call_fun, opts, siwx_opts) do
    with {:ok, result} <- retry(call_fun, proving) do
      case MCP.fetch_payment_required(result) do
        {:ok, payment_required} ->
          emit_siwx(:payment_required)
          pay_with_fresh_proof(request, opts, payment_required, siwx_opts)

        :error ->
          emit_siwx(:authenticated)
          {:ok, {:done, finalize(result, false, true)}}
      end
    end
  end

  @spec pay_with_fresh_proof(map(), keyword(), map(), keyword()) ::
          {:ok, {:pay, map(), map()}} | {:error, {:siwx, ClientSIWX.reason()}}
  defp pay_with_fresh_proof(request, opts, payment_required, siwx_opts) do
    case sign_siwx(request, opts, payment_required, siwx_opts) do
      {:ok, proving} -> {:ok, {:pay, payment_required, proving}}
      :none -> {:ok, {:pay, payment_required, request}}
      {:error, _reason} = error -> error
    end
  end

  @spec emit_siwx(:authenticated | :payment_required) :: :ok
  defp emit_siwx(outcome),
    do: Telemetry.emit(:client, :siwx, :ok, %{transport: :mcp, outcome: outcome})

  # -- Budget -----------------------------------------------------------------

  @spec reserve_budget(keyword(), map()) :: :ok | {:error, Budget.reserve_error()}
  defp reserve_budget(opts, payload) do
    case Keyword.fetch!(opts, :budget) do
      nil -> :ok
      budget -> Budget.reserve(budget, accepted_asset(payload), accepted_amount(payload))
    end
  end

  # The reservation stands unless the paid retry failed outright or came
  # back as another payment challenge without a successful receipt.
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
  defp accepted?({:ok, result}) do
    match?({:ok, %{"success" => true}}, MCP.fetch_payment_response(result)) or
      MCP.fetch_payment_required(result) == :error
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

  @spec ensure_not_already_paid(map()) :: :ok | {:error, :payment_already_attempted}
  defp ensure_not_already_paid(request) do
    case MCP.fetch_payment(request) do
      :error -> :ok
      {:ok, _payment} -> {:error, :payment_already_attempted}
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
        :valid_after_buffer
      ])

  @spec attempt(call_fun(), map()) :: {:ok, map()} | {:error, term()}
  defp attempt(call_fun, request) do
    case call_fun.(request) do
      {:ok, %{} = tool_result} -> {:ok, tool_result}
      {:error, reason} -> {:error, reason}
      %{} = tool_result -> {:ok, tool_result}
      _other -> {:error, :invalid_tool_result}
    end
  end

  @spec retry(call_fun(), map()) :: {:ok, map()} | {:error, call_error()}
  defp retry(call_fun, request) do
    case attempt(call_fun, request) do
      {:ok, tool_result} -> {:ok, tool_result}
      {:error, :invalid_tool_result} = error -> error
      {:error, reason} -> classify_retry_error(reason)
    end
  end

  # A rejected paid retry may come back as a JSON-RPC payment error instead of
  # a payment-required tool result. Normalize it to the tool-result form so
  # both shapes are returned as-is (the payment is never re-signed) rather
  # than surfacing as a transport error.
  @spec classify_retry_error(term()) :: {:ok, map()} | {:error, call_error()}
  defp classify_retry_error(reason) do
    with {:ok, payment_required} <- MCP.fetch_payment_required_from_error(reason),
         {:ok, tool_result} <- MCP.payment_required_result(payment_required) do
      {:ok, tool_result}
    else
      _other -> {:error, {:transport_error, reason}}
    end
  end

  @spec finalize(map(), boolean(), boolean()) :: response()
  defp finalize(tool_result, paid, siwx_authenticated \\ false) do
    payment_response =
      case MCP.fetch_payment_response(tool_result) do
        {:ok, receipt} -> receipt
        :error -> nil
      end

    %{
      result: tool_result,
      payment_response: payment_response,
      paid: paid,
      siwx_authenticated: siwx_authenticated
    }
  end

  @spec emit_call_telemetry({:ok, response()} | {:error, term()}) :: :ok
  defp emit_call_telemetry({:ok, response}) do
    :telemetry.execute([:x402, :mcp, :call], %{count: 1}, %{status: :ok, paid: response.paid})
  end

  defp emit_call_telemetry({:error, reason}) do
    :telemetry.execute([:x402, :mcp, :call], %{count: 1}, %{status: :error, reason: reason})
  end
end
