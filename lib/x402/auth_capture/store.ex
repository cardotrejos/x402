defmodule X402.AuthCapture.Store do
  @moduledoc """
  Atomic storage contract for auth-capture execution and recovery.

  Applications must supply a shared, durable implementation in production.
  A successful `transact_many/3` must be serializable across all selected keys
  and durable before returning. The mutation receives a map containing every
  selected key, with `nil` for absent values. Commit maps may update only
  selected keys. `{:keep, reply}` returns a successful, atomic read without
  writing; it must still validate the snapshot when using compare-and-swap.
  It must be pure: adapters may evaluate it more than once while retrying a
  compare-and-swap. Never sign, broadcast, or execute a handler in a mutation.

  Neither unresolved work nor completed replay records may expire or be
  evicted. Read errors are not missing records. A timeout is ambiguous: the
  mutation may have committed, so callers must reconcile rather than assume
  ownership or repeat an external effect. Use a dedicated gas account unless
  every writer participates in an external global coordinator. Sharing a
  backend does not coordinate this journal with other schemes, the existing
  per-node nonce manager, or transactions submitted outside this SDK.

  `X402.AuthCapture.ETSStore` is a volatile development implementation, not a
  production durability adapter. Store records contain signed payment and
  transaction data; restrict access and do not log their contents.
  """

  alias X402.Behaviour

  @type t :: {module(), term()}
  @type value :: map() | nil
  @type mutation :: (value() -> {:commit, map(), term()} | {:keep, term()} | {:abort, term()})
  @type multi_mutation :: (map() -> {:commit, map(), term()} | {:keep, term()} | {:abort, term()})

  @callback fetch(term(), term()) :: {:ok, value()} | {:error, term()}
  @callback transact_many(term(), [term()], multi_mutation()) :: {:ok, term()} | {:error, term()}

  @doc since: "0.9.0"
  @doc """
  Validates an adapter for use with `NimbleOptions`.

  This checks callbacks, not the implementation's durability.

  ## Examples

      iex> X402.AuthCapture.Store.validate(nil)
      {:error, "expected {adapter, context} implementing the auth-capture store"}
  """
  @spec validate(term()) :: {:ok, t()} | {:error, String.t()}
  def validate({module, _context} = store) when is_atom(module) do
    if Behaviour.implements?(module, fetch: 2, transact_many: 3),
      do: {:ok, store},
      else: invalid_adapter()
  end

  def validate(_store), do: invalid_adapter()

  @doc since: "0.9.0"
  @doc "Reads a record without converting adapter errors into cache misses."
  @spec fetch(t(), term()) :: {:ok, value()} | {:error, term()}
  def fetch(store, key) do
    case invoke(store, :fetch, [key]) do
      {:ok, value} when is_map(value) or is_nil(value) -> {:ok, value}
      {:error, reason} -> {:error, reason}
      _other -> {:error, :invalid_store_response}
    end
  end

  @doc since: "0.9.0"
  @doc "Applies a pure, atomic mutation and returns its reply only after persistence."
  @spec transact(t(), term(), mutation()) :: {:ok, term()} | {:error, term()}
  def transact(store, key, mutation) when is_function(mutation, 1) do
    transact_many(store, [key], fn values ->
      case mutation.(Map.fetch!(values, key)) do
        {:commit, value, reply} -> {:commit, %{key => value}, reply}
        other -> other
      end
    end)
  end

  @doc since: "0.9.0"
  @doc "Atomically reads and updates selected keys without scanning other records."
  @spec transact_many(t(), [term()], multi_mutation()) :: {:ok, term()} | {:error, term()}
  def transact_many(store, keys, mutation) when is_list(keys) and is_function(mutation, 1) do
    case invoke(store, :transact_many, [Enum.uniq(keys), mutation]) do
      {:ok, reply} -> {:ok, reply}
      {:error, reason} -> {:error, reason}
      _other -> {:error, :invalid_store_response}
    end
  end

  @spec invoke(t(), atom(), list()) :: term()
  defp invoke({module, context}, function, arguments) do
    apply(module, function, [context | arguments])
  catch
    _kind, _reason -> {:error, :store_unavailable}
  end

  @spec invalid_adapter() :: {:error, String.t()}
  defp invalid_adapter,
    do: {:error, "expected {adapter, context} implementing the auth-capture store"}
end
