defmodule X402.Client.Hooks do
  @moduledoc """
  Behaviour for lifecycle hooks around client payment creation.

  `X402.Client.build_payment/3` runs the callbacks in this order:

  1. `before_payment/2` — after a requirements entry has been selected and
     before anything is signed. Continue with `{:cont, context}` (the
     context's `:requirements` may be replaced, for example to pin a
     different `accepts` entry) or abort with `{:halt, reason}`, which
     surfaces as `{:error, {:hook_halted, :before_payment, reason}}`.
  2. `after_payment/2` — once the `PaymentPayload` has been signed,
     assembled and enriched. Continue with `{:cont, context}`; the context's
     `:payload` may be replaced and becomes the returned payload.
  3. `on_payment_failure/2` — when signing or enrichment fails after
     `before_payment/2` has run. Continue with `{:cont, context}` (the
     context's `:error` may be replaced) or recover with
     `{:recover, payload}`, which returns `{:ok, payload}` instead.

  These mirror the `onBeforePaymentCreation`, `onAfterPaymentCreation`, and
  `onPaymentCreationFailure` hooks of the reference TypeScript client.
  Selection failures (`:no_acceptable_requirements`) happen before any hook
  runs and never reach `on_payment_failure/2`.

  A callback that raises or exits yields
  `{:error, {:hook_callback_failed, callback, reason}}`; one that returns
  anything outside its contract yields
  `{:error, {:hook_invalid_return, callback, value}}`.

  Hooks are invoked in the process that calls `X402.Client.build_payment/3`
  (through `X402.Client.Finch.request/3` or `X402.MCP.Client.call/3`, the
  request process). `X402.Client.Hooks.Default` is the no-op implementation
  used when no `:hooks` option is given.

  ## Example

      defmodule MyApp.PaymentHooks do
        @behaviour X402.Client.Hooks

        @impl true
        def before_payment(context, _metadata) do
          case context.requirements["amount"] do
            amount when amount > "1000000" -> {:halt, :too_expensive}
            _amount -> {:cont, context}
          end
        end

        @impl true
        def after_payment(context, _metadata) do
          Logger.info("paying \#{context.requirements["amount"]}")
          {:cont, context}
        end

        @impl true
        def on_payment_failure(context, _metadata), do: {:cont, context}
      end
  """

  alias X402.Client.Hooks.Context

  @typedoc "Lifecycle callback metadata passed to hooks."
  @type metadata :: %{
          required(:operation) => :build_payment,
          required(:hook_module) => module(),
          required(:scheme) => String.t() | nil,
          required(:network) => String.t() | nil
        }

  @typedoc "Hook callback identifier."
  @type callback_name :: :before_payment | :after_payment | :on_payment_failure

  @typedoc "Return type for `before_payment/2`."
  @type before_result :: {:cont, Context.t()} | {:halt, term()}

  @typedoc "Return type for `after_payment/2`."
  @type after_result :: {:cont, Context.t()}

  @typedoc "Return type for `on_payment_failure/2`."
  @type on_failure_result :: {:cont, Context.t()} | {:recover, map()}

  @typedoc "Hook execution errors returned by `X402.Client.build_payment/3`."
  @type hook_error ::
          {:hook_halted, callback_name(), term()}
          | {:hook_callback_failed, callback_name(), term()}
          | {:hook_invalid_return, callback_name(), term()}

  @doc """
  Runs after requirements selection and before the payment is signed.
  """
  @callback before_payment(Context.t(), metadata()) :: before_result()

  @doc """
  Runs after the payment payload has been built.
  """
  @callback after_payment(Context.t(), metadata()) :: after_result()

  @doc """
  Runs when building the payment payload fails.
  """
  @callback on_payment_failure(Context.t(), metadata()) :: on_failure_result()

  @required_callbacks [before_payment: 2, after_payment: 2, on_payment_failure: 2]

  @doc since: "0.8.0"
  @doc """
  Validates that a value is a module implementing `X402.Client.Hooks`.

  Designed for `NimbleOptions` custom validation.

  ## Examples

      iex> X402.Client.Hooks.validate_module(X402.Client.Hooks.Default)
      {:ok, X402.Client.Hooks.Default}

      iex> X402.Client.Hooks.validate_module(Enum)
      {:error, "expected a module implementing X402.Client.Hooks"}
  """
  @spec validate_module(term()) :: {:ok, module()} | {:error, String.t()}
  def validate_module(module) when is_atom(module) do
    case X402.Behaviour.implements?(module, @required_callbacks) do
      true -> {:ok, module}
      false -> {:error, "expected a module implementing X402.Client.Hooks"}
    end
  end

  def validate_module(_invalid), do: {:error, "expected a module implementing X402.Client.Hooks"}
end
