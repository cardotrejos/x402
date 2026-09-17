defmodule X402.Extension do
  @moduledoc """
  Behaviour for resource-server extension adapters run by `X402.Plug.PaymentGate`.

  An adapter packages one protocol extension's server-side lifecycle so the
  gate can run it from a single option instead of the user wiring each step
  by hand:

      plug X402.Plug.PaymentGate,
        routes: [...],
        extensions: [
          {X402.Extensions.PaymentIdentifier.Adapter, required: true},
          {X402.Extensions.BuilderCode.Adapter, app_code: "my_app"}
        ]

  Every callback but `c:key/0` is optional:

  * `c:init/1` validates the adapter's options once, when the gate's own
    options are validated; the returned options are what the remaining
    callbacks receive.
  * `c:advertise/2` returns the value to advertise under the extension key
    in every `PaymentRequired.extensions` (merged over the route's static
    `extensions` map), or `nil` to advertise nothing for this request.
  * `c:validate/3` runs after the generic extension echo check on every
    payment, with the value the client echoed (or `nil`) and the value that
    was advertised (or `nil`). An error rejects the payment with **400**
    `invalid_payload` and a `{:extension_invalid, key, reason}` telemetry
    reason.
  * `c:after_verify/4` and `c:after_settle/4` are notified with the
    facilitator's result once verification succeeded and once settlement
    succeeded. Their return values are ignored and exceptions are logged.

  `c:advertise/2` and `c:validate/3` are part of the request's control flow,
  so an exception there propagates like any other programmer error.

  The `sign-in-with-x` extension keeps its dedicated `:siwx` gate option:
  its challenge is regenerated per response and it changes the request flow
  (a proof can skip payment entirely), which the generic advertise/validate
  shape does not express. Bazaar discovery metadata likewise has its own
  `:bazaar` route option because it depends on the matched route pattern.
  """

  alias X402.Hooks.RequestContext

  require Logger

  @typedoc "An adapter entry as accepted by the gate's `:extensions` option."
  @type spec :: module() | {module(), keyword()}

  @typedoc "A normalized adapter entry."
  @type entry :: {module(), keyword()}

  @doc "Returns the extension key on the wire (for example `\"payment-identifier\"`)."
  @callback key() :: String.t()

  @doc "Validates the adapter options at gate initialization."
  @callback init(keyword()) :: {:ok, keyword()} | {:error, String.t()}

  @doc "Builds the value advertised under the extension key, or `nil`."
  @callback advertise(keyword(), RequestContext.t()) :: map() | nil

  @doc "Validates the client's echoed value against the advertised one."
  @callback validate(echoed :: term(), advertised :: term(), keyword()) :: :ok | {:error, term()}

  @doc "Notified after a successful facilitator verification."
  @callback after_verify(payload :: map(), requirements :: map(), result :: map(), keyword()) ::
              term()

  @doc "Notified after a successful facilitator settlement."
  @callback after_settle(payload :: map(), requirements :: map(), result :: map(), keyword()) ::
              term()

  @optional_callbacks init: 1, advertise: 2, validate: 3, after_verify: 4, after_settle: 4

  @doc since: "0.8.0"
  @doc """
  Validates one `:extensions` entry and normalizes it to `{module, opts}`.

  Designed for `NimbleOptions` custom validation. The module must define
  `key/0`; when it defines `init/1` the options are passed through it.

  ## Examples

      iex> X402.Extension.validate_spec(X402.Extensions.PaymentIdentifier.Adapter)
      {:ok, {X402.Extensions.PaymentIdentifier.Adapter, [required: false]}}

      iex> X402.Extension.validate_spec({X402.Extensions.PaymentIdentifier.Adapter, required: true})
      {:ok, {X402.Extensions.PaymentIdentifier.Adapter, [required: true]}}

      iex> X402.Extension.validate_spec(:not_an_adapter)
      {:error, "expected a module implementing X402.Extension (key/0), got: :not_an_adapter"}
  """
  @spec validate_spec(term()) :: {:ok, entry()} | {:error, String.t()}
  def validate_spec(module) when is_atom(module), do: validate_spec({module, []})

  def validate_spec({module, opts}) when is_atom(module) and is_list(opts) do
    case Code.ensure_loaded?(module) and function_exported?(module, :key, 0) do
      true -> init_entry(module, opts)
      false -> {:error, invalid_spec_message(module)}
    end
  end

  def validate_spec(other), do: {:error, invalid_spec_message(other)}

  @spec init_entry(module(), keyword()) :: {:ok, entry()} | {:error, String.t()}
  defp init_entry(module, opts) do
    if function_exported?(module, :init, 1) do
      case module.init(opts) do
        {:ok, validated} when is_list(validated) -> {:ok, {module, validated}}
        {:error, message} when is_binary(message) -> {:error, "#{inspect(module)}: #{message}"}
      end
    else
      {:ok, {module, opts}}
    end
  end

  @spec invalid_spec_message(term()) :: String.t()
  defp invalid_spec_message(value) do
    "expected a module implementing X402.Extension (key/0), got: #{inspect(value)}"
  end

  @doc since: "0.8.0"
  @doc """
  Merges every adapter's advertisement over a base extensions map.

  Adapters without `c:advertise/2`, and those returning `nil`, leave the
  map untouched.

  ## Examples

      iex> context = X402.Hooks.RequestContext.new(requirements: [%{"scheme" => "exact"}])
      iex> entries = [{X402.Extensions.PaymentIdentifier.Adapter, required: true}]
      iex> advertised = X402.Extension.advertise_all(entries, context, %{"other" => %{}})
      iex> {Map.keys(advertised) |> Enum.sort(), advertised["payment-identifier"]["info"]}
      {["other", "payment-identifier"], %{"required" => true}}
  """
  @spec advertise_all([entry()], RequestContext.t(), map()) :: map()
  def advertise_all(entries, %RequestContext{} = context, base) when is_map(base) do
    Enum.reduce(entries, base, fn {module, opts}, acc ->
      case advertise(module, opts, context) do
        nil -> acc
        value -> Map.put(acc, module.key(), value)
      end
    end)
  end

  @spec advertise(module(), keyword(), RequestContext.t()) :: map() | nil
  defp advertise(module, opts, context) do
    case function_exported?(module, :advertise, 2) do
      true -> module.advertise(opts, context)
      false -> nil
    end
  end

  @doc since: "0.8.0"
  @doc """
  Runs every adapter's `c:validate/3` over the echoed and advertised maps.

  Stops at the first error, tagging it with the adapter's key.

  ## Examples

      iex> entries = [{X402.Extensions.BuilderCode.Adapter, app_code: "my_app"}]
      iex> advertised = %{"builder-code" => X402.Extensions.BuilderCode.extension("my_app")}
      iex> X402.Extension.validate_all(entries, %{"builder-code" => %{"a" => "my_app"}}, advertised)
      :ok

      iex> entries = [{X402.Extensions.BuilderCode.Adapter, app_code: "my_app"}]
      iex> advertised = %{"builder-code" => X402.Extensions.BuilderCode.extension("my_app")}
      iex> X402.Extension.validate_all(entries, %{"builder-code" => %{"a" => "other"}}, advertised)
      {:error, {:extension_invalid, "builder-code", :builder_code_mismatch}}
  """
  @spec validate_all([entry()], term(), map()) ::
          :ok | {:error, {:extension_invalid, String.t(), term()}}
  def validate_all(entries, echoed, advertised) when is_map(advertised) do
    Enum.reduce_while(entries, :ok, fn {module, opts}, :ok ->
      key = module.key()

      case validate(module, opts, extension_value(echoed, key), extension_value(advertised, key)) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, {:extension_invalid, key, reason}}}
      end
    end)
  end

  @spec validate(module(), keyword(), term(), term()) :: :ok | {:error, term()}
  defp validate(module, opts, echoed_value, advertised_value) do
    case function_exported?(module, :validate, 3) do
      true -> module.validate(echoed_value, advertised_value, opts)
      false -> :ok
    end
  end

  # Route configs may use atom keys; the wire is string-keyed. Atom keys are
  # compared by their string form rather than minted from the key.
  @spec extension_value(term(), String.t()) :: term()
  defp extension_value(extensions, key) when is_map(extensions) do
    extensions
    |> Enum.find_value(fn {entry_key, value} ->
      if string_key(entry_key) == key, do: {:found, value}
    end)
    |> case do
      {:found, value} -> value
      nil -> nil
    end
  end

  defp extension_value(_extensions, _key), do: nil

  @spec string_key(term()) :: term()
  defp string_key(key) when is_atom(key), do: Atom.to_string(key)
  defp string_key(key), do: key

  @doc since: "0.8.0"
  @doc """
  Notifies every adapter defining `c:after_verify/4`.

  Return values are ignored; an exception is logged and the remaining
  adapters still run.
  """
  @spec after_verify_all([entry()], map(), map(), map()) :: :ok
  def after_verify_all(entries, payload, requirements, result) do
    notify_all(entries, :after_verify, [payload, requirements, result])
  end

  @doc since: "0.8.0"
  @doc """
  Notifies every adapter defining `c:after_settle/4`.

  Return values are ignored; an exception is logged and the remaining
  adapters still run.
  """
  @spec after_settle_all([entry()], map(), map(), map()) :: :ok
  def after_settle_all(entries, payload, requirements, result) do
    notify_all(entries, :after_settle, [payload, requirements, result])
  end

  @spec notify_all([entry()], :after_verify | :after_settle, [term()]) :: :ok
  defp notify_all(entries, callback, args) do
    Enum.each(entries, fn {module, opts} ->
      if function_exported?(module, callback, 4) do
        notify(module, callback, args ++ [opts])
      end
    end)
  end

  @spec notify(module(), atom(), [term()]) :: :ok
  defp notify(module, callback, args) do
    _ignored = apply(module, callback, args)
    :ok
  rescue
    exception -> log_notify_failure(module, callback, exception)
  catch
    kind, reason -> log_notify_failure(module, callback, {kind, reason})
  end

  @spec log_notify_failure(module(), atom(), term()) :: :ok
  defp log_notify_failure(module, callback, failure) do
    Logger.warning(
      "[X402.Extension] #{inspect(module)}.#{callback}/4 failed: #{inspect(failure)}"
    )
  end
end
