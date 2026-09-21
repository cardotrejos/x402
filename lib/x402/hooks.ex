defmodule X402.Hooks do
  @moduledoc """
  Behaviour for lifecycle hooks around facilitator verify and settle operations.

  Hooks run around each operation in this order:

  1. `before_verify/2` or `before_settle/2`
  2. `after_verify/2` or `after_settle/2` on success
  3. `on_verify_failure/2` or `on_settle_failure/2` on failure

  `before_*` callbacks can continue with `{:cont, context}` or abort with
  `{:halt, reason}`.

  `on_*_failure` callbacks can continue failure handling with `{:cont, context}`
  or recover the operation with `{:recover, result}`.

  Hook callbacks are invoked in the process that calls
  `X402.Facilitator.verify/2` or `X402.Facilitator.settle/2` (for example a
  Plug request process), not in the facilitator process. Hooks that touch
  process-bound state should account for running concurrently across callers.

  ## Resource-server hooks

  Two further callbacks are **optional** and are only invoked by the
  resource-server transports (`X402.Plug.PaymentGate` and `X402.MCP.Server`)
  when the hook module defines them. They mirror the reference resource
  server's `onProtectedRequest` and `onVerifiedPaymentCanceled` hooks:

  * `c:on_protected_request/2` runs for every request that matches a gated
    route (or paid tool) before any payment processing, with an
    `X402.Hooks.RequestContext`. It may continue with `{:cont, context}` —
    optionally replacing `context.requirements` or `context.extensions` for
    this request, for example to apply a per-caller discount — answer the
    request directly with `{:halt, {status, body}}`, or let the protected
    handler run unpaid with `{:halt, :skip_payment}` (an allowlisted API
    key, for instance). An exception or an unexpected return value fails
    closed: the transport answers with an internal error.
  * `c:on_verified_payment_canceled/2` runs when a payment the facilitator
    already verified is **not** settled: the protected handler answered with
    a status of 400 or above (or, for MCP, returned an error result or
    raised), or settlement failed before a transaction was broadcast. Its
    return value is ignored and exceptions are caught and logged, so it is
    the place for compensating side effects (undo a quota increment, log a
    refundable authorization).

  `X402.Hooks.Default` implements neither, so existing hook modules keep
  working unchanged.
  """

  alias X402.Hooks.Context
  alias X402.Hooks.RequestContext

  require Logger

  @typedoc "Lifecycle callback metadata passed to hooks."
  @type metadata :: %{
          required(:operation) => :verify | :settle,
          required(:endpoint) => String.t(),
          required(:hook_module) => module()
        }

  @typedoc "Hook callback identifier."
  @type callback_name ::
          :before_verify
          | :after_verify
          | :on_verify_failure
          | :before_settle
          | :after_settle
          | :on_settle_failure
          | :on_protected_request
          | :on_verified_payment_canceled

  @typedoc "Return type for `before_*` callbacks."
  @type before_result :: {:cont, Context.t()} | {:halt, term()}

  @typedoc "Return type for `after_*` callbacks."
  @type after_result :: {:cont, Context.t()}

  @typedoc "Return type for `on_*_failure` callbacks."
  @type on_failure_result :: {:cont, Context.t()} | {:recover, map()}

  @typedoc """
  Hook execution error tuple returned by `X402.Facilitator`.
  """
  @type hook_error ::
          {:hook_halted, callback_name(), term()}
          | {:hook_callback_failed, callback_name(), term()}
          | {:hook_invalid_return, callback_name(), term()}

  @doc """
  Runs before a verify request is sent.
  """
  @callback before_verify(Context.t(), metadata()) :: before_result()

  @doc """
  Runs after a successful verify request.
  """
  @callback after_verify(Context.t(), metadata()) :: after_result()

  @doc """
  Runs after a failed verify request.
  """
  @callback on_verify_failure(Context.t(), metadata()) :: on_failure_result()

  @doc """
  Runs before a settle request is sent.
  """
  @callback before_settle(Context.t(), metadata()) :: before_result()

  @doc """
  Runs after a successful settle request.
  """
  @callback after_settle(Context.t(), metadata()) :: after_result()

  @doc """
  Runs after a failed settle request.
  """
  @callback on_settle_failure(Context.t(), metadata()) :: on_failure_result()

  @typedoc "Metadata passed to the resource-server request hooks."
  @type request_metadata :: %{
          required(:transport) => RequestContext.transport(),
          required(:hook_module) => module(),
          optional(:method) => atom(),
          optional(:path) => String.t(),
          optional(:route) => String.t(),
          optional(:tool) => String.t()
        }

  @typedoc """
  Why a verified payment was not settled.

  * `:handler_failed` — the protected handler answered with a status of 400
    or above (HTTP) or returned an `isError` result (MCP); `:response_status`
    carries the HTTP status.
  * `:handler_raised` — the MCP handler raised, threw, or exited; `:error`
    carries `{kind, reason}`.
  * `:settlement_failed` — settlement failed before a transaction was
    broadcast; `:error` carries the failure reason.
  """
  @type cancellation_reason :: :handler_failed | :handler_raised | :settlement_failed

  @typedoc "Metadata passed to `c:on_verified_payment_canceled/2`."
  @type cancel_metadata :: %{
          required(:transport) => RequestContext.transport(),
          required(:hook_module) => module(),
          required(:reason) => cancellation_reason(),
          optional(:error) => term(),
          optional(:response_status) => pos_integer(),
          optional(:method) => atom(),
          optional(:path) => String.t(),
          optional(:route) => String.t(),
          optional(:tool) => String.t()
        }

  @typedoc "Return type for `c:on_protected_request/2`."
  @type protected_request_result ::
          {:cont, RequestContext.t()}
          | {:halt, {pos_integer(), map()}}
          | {:halt, :skip_payment}

  @doc """
  Runs before any payment processing for a request that matches a gated
  route or paid tool. Optional.
  """
  @callback on_protected_request(RequestContext.t(), request_metadata()) ::
              protected_request_result()

  @doc """
  Runs when a verified payment is not settled. Optional; the return value
  is ignored.
  """
  @callback on_verified_payment_canceled(RequestContext.t(), cancel_metadata()) :: term()

  @optional_callbacks on_protected_request: 2, on_verified_payment_canceled: 2

  @required_callbacks [
    before_verify: 2,
    after_verify: 2,
    on_verify_failure: 2,
    before_settle: 2,
    after_settle: 2,
    on_settle_failure: 2
  ]

  @doc since: "0.1.0"
  @doc """
  Validates that a value is a module implementing `X402.Hooks`.

  This function is designed for `NimbleOptions` custom validation.
  """
  @spec validate_module(term()) :: {:ok, term()} | {:error, String.t()}
  def validate_module(module) when is_atom(module) do
    case implementation?(module) do
      true -> {:ok, module}
      false -> {:error, "expected a module implementing X402.Hooks"}
    end
  end

  def validate_module(_invalid), do: {:error, "expected a module implementing X402.Hooks"}

  @doc since: "0.8.0"
  @doc """
  Invokes the optional `c:on_protected_request/2` callback of a hook module.

  Returns `{:cont, context}` untouched when the module does not define the
  callback. A callback that raises, or returns anything other than a
  `t:protected_request_result/0` with a valid replacement context (see
  `X402.Hooks.RequestContext.valid?/1`), yields a `t:hook_error/0` so the
  transport can fail closed. The `:transport` and `:hook_module` metadata
  keys are filled in from the context and the module.

  ## Examples

      iex> context = X402.Hooks.RequestContext.new(requirements: [%{"scheme" => "exact"}])
      iex> X402.Hooks.run_protected_request(X402.Hooks.Default, context, %{path: "/api"})
      {:cont, context}
  """
  @spec run_protected_request(module(), RequestContext.t(), map()) ::
          protected_request_result() | {:error, hook_error()}
  def run_protected_request(hooks_module, %RequestContext{} = context, metadata)
      when is_atom(hooks_module) and is_map(metadata) do
    case function_exported?(hooks_module, :on_protected_request, 2) do
      true ->
        invoke_protected_request(
          hooks_module,
          context,
          hook_metadata(hooks_module, context, metadata)
        )

      false ->
        {:cont, context}
    end
  end

  @spec hook_metadata(module(), RequestContext.t(), map()) :: map()
  defp hook_metadata(hooks_module, context, metadata) do
    Map.merge(metadata, %{transport: context.transport, hook_module: hooks_module})
  end

  @spec invoke_protected_request(module(), RequestContext.t(), request_metadata()) ::
          protected_request_result() | {:error, hook_error()}
  defp invoke_protected_request(hooks_module, context, metadata) do
    normalize_protected_result(hooks_module.on_protected_request(context, metadata))
  rescue
    exception ->
      {:error, {:hook_callback_failed, :on_protected_request, exception}}
  catch
    kind, reason ->
      {:error, {:hook_callback_failed, :on_protected_request, {kind, reason}}}
  end

  @spec normalize_protected_result(term()) :: protected_request_result() | {:error, hook_error()}
  defp normalize_protected_result({:cont, %RequestContext{} = updated} = result) do
    case RequestContext.valid?(updated) do
      true -> result
      false -> {:error, {:hook_invalid_return, :on_protected_request, result}}
    end
  end

  defp normalize_protected_result({:halt, {status, body}} = result)
       when is_integer(status) and status >= 100 and status <= 599 and is_map(body),
       do: result

  defp normalize_protected_result({:halt, :skip_payment} = result), do: result

  defp normalize_protected_result(invalid),
    do: {:error, {:hook_invalid_return, :on_protected_request, invalid}}

  @doc since: "0.8.0"
  @doc """
  Invokes the optional `c:on_verified_payment_canceled/2` callback of a hook
  module.

  A no-op when the module does not define the callback. The return value is
  discarded; exceptions are caught and logged so a failing hook never masks
  the response already being sent. The `:transport` and `:hook_module`
  metadata keys are filled in from the context and the module; the caller
  supplies `:reason` (a `t:cancellation_reason/0`) and its details.

  ## Examples

      iex> context = X402.Hooks.RequestContext.new(transport: :mcp, tool: "search")
      iex> metadata = %{reason: :handler_failed, tool: "search"}
      iex> X402.Hooks.run_verified_payment_canceled(X402.Hooks.Default, context, metadata)
      :ok
  """
  @spec run_verified_payment_canceled(module(), RequestContext.t(), map()) :: :ok
  def run_verified_payment_canceled(hooks_module, %RequestContext{} = context, metadata)
      when is_atom(hooks_module) and is_map(metadata) do
    if function_exported?(hooks_module, :on_verified_payment_canceled, 2) do
      try do
        _ignored =
          hooks_module.on_verified_payment_canceled(
            context,
            hook_metadata(hooks_module, context, metadata)
          )

        :ok
      rescue
        exception -> log_canceled_hook_failure(hooks_module, exception)
      catch
        kind, reason -> log_canceled_hook_failure(hooks_module, {kind, reason})
      end
    else
      :ok
    end
  end

  @spec log_canceled_hook_failure(module(), term()) :: :ok
  defp log_canceled_hook_failure(hooks_module, failure) do
    Logger.warning(
      "[X402.Hooks] #{inspect(hooks_module)}.on_verified_payment_canceled/2 failed: " <>
        inspect(failure)
    )
  end

  @spec implementation?(module()) :: boolean()
  defp implementation?(module), do: X402.Behaviour.implements?(module, @required_callbacks)
end
