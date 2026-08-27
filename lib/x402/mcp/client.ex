defmodule X402.MCP.Client do
  @moduledoc """
  Client half of the x402 MCP transport: pay for tool calls automatically.

  `call/3` drives an arbitrary tool-call function (any MCP client library, or
  a plain function in tests) through the x402 detect → sign → retry-once loop:

  1. Perform the tool call. A result that is not payment-required is returned
     as-is.
  2. Extract the `PaymentRequired` object from the payment-required tool
     result (or from a `402`/`-32042` JSON-RPC error).
  3. Invoke the `:on_payment_required` hook, which may cancel.
  4. Build and sign a payment via `X402.Client.build_payment/3` and retry the
     tool call once with the payload in request `_meta["x402/payment"]`.
  5. Return the retried result with the decoded settlement receipt from
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
  """

  alias X402.Client
  alias X402.MCP
  alias X402.Signer

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
  signed and submitted.
  """
  @type response :: %{
          result: map(),
          payment_response: map() | nil,
          paid: boolean()
        }

  @typedoc "A tool-call function driven by `call/3`."
  @type call_fun :: (map() -> map() | {:ok, map()} | {:error, term()})

  @type call_error ::
          :payment_already_attempted
          | :payment_cancelled
          | :invalid_tool_result
          | {:transport_error, term()}
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
    case X402.Behaviour.implements?(module, address: 1, sign_eip712: 3) do
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
         :ok <- consent(opts, payment_required),
         {:ok, payload} <-
           Client.build_payment(payment_required, opts[:signer], build_opts(opts)),
         {:ok, retry_result} <- retry(call_fun, MCP.put_payment(request, payload)) do
      # A second payment-required result is returned as-is — the payment is
      # never re-signed or re-sent.
      {:ok, finalize(retry_result, true)}
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
    do: Keyword.take(opts, [:network, :scheme, :asset, :max_amount, :valid_after_buffer])

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

  @spec finalize(map(), boolean()) :: response()
  defp finalize(tool_result, paid) do
    payment_response =
      case MCP.fetch_payment_response(tool_result) do
        {:ok, receipt} -> receipt
        :error -> nil
      end

    %{result: tool_result, payment_response: payment_response, paid: paid}
  end

  @spec emit_call_telemetry({:ok, response()} | {:error, term()}) :: :ok
  defp emit_call_telemetry({:ok, response}) do
    :telemetry.execute([:x402, :mcp, :call], %{count: 1}, %{status: :ok, paid: response.paid})
  end

  defp emit_call_telemetry({:error, reason}) do
    :telemetry.execute([:x402, :mcp, :call], %{count: 1}, %{status: :error, reason: reason})
  end
end
