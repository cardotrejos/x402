defmodule X402.AuthCapture.Journal do
  @moduledoc """
  Durable signer-scope fencing for auth-capture transactions.

  Each scope has at most one active transaction. Its immutable intent is
  reserved before signing; raw bytes and their locally computed hash are
  persisted before dispatch. `dispatch/3` grants permission to send exactly
  once. A timeout or crash after that marker requires receipt reconciliation,
  never another send, even if the first caller may not have reached the node.

  Confirmed or reverted receipts retain the scope until the application has
  durably applied their local effects and calls `acknowledge/3`. Completed
  records remain as replay tombstones. The configurable history limit fails
  closed instead of evicting them. Migration or compaction requires an
  application-owned replay archive, not deleting live journal records.
  Each history entry has its own key. The small scope record and the selected
  entry are changed in one atomic multi-key transaction; unrelated history is
  neither fetched nor rewritten. Existing-operation lookups use read-only
  snapshots.

  Only a preparation with no frozen transaction may be cancelled. Reserving
  that cancelled intent again issues a fresh owner token. There are no leases
  or timeout takeovers; abandoned preparations require explicit application
  recovery. This module coordinates trusted execution code, not untrusted
  HTTP clients: do not expose owner tokens or accept caller-supplied receipts.

  A multi-transaction lifecycle uses one journal record per leg and a separate
  durable payment record. Releasing the signer scope does not release that
  payment's admission or authorize repeating a handler.

  This namespace does not coordinate other schemes or the existing nonce
  manager. Use a dedicated gas account or an external coordinator covering
  every writer. Structural record checks fail closed on detectable corruption;
  they cannot recover deleted data or authenticate a malicious storage adapter.
  """

  alias X402.AuthCapture.EVM
  alias X402.AuthCapture.Store
  alias X402.EIP712

  @enforce_keys [:store, :scope, :history_limit]
  defstruct [:store, :scope, :history_limit]

  @type t :: %__MODULE__{store: Store.t(), scope: tuple(), history_limit: pos_integer()}
  @type entry :: %{
          id: binary(),
          owner: binary(),
          intent: map(),
          phase:
            :preparing
            | :prepared
            | :dispatched
            | :confirmed
            | :reverted
            | :succeeded
            | :failed
            | :cancelled,
          transaction: %{raw: binary(), hash: String.t()} | nil,
          receipt: map() | nil
        }

  @options [
    store: [type: {:custom, Store, :validate, []}, required: true],
    network: [type: :string, required: true],
    signer: [type: :string, required: true],
    history_limit: [type: :pos_integer, default: 10_000]
  ]
  @max_raw_bytes 262_144
  @active_phases [:preparing, :prepared, :dispatched, :confirmed, :reverted]
  @terminal_phases [:succeeded, :failed, :cancelled]

  @doc since: "0.9.0"
  @doc """
  Builds a journal bound to a concrete EVM network and gas-account address.

  #{NimbleOptions.docs(@options)}
  """
  @spec new(keyword()) :: {:ok, t()} | {:error, term()}
  def new(opts) do
    with {:ok, validated} <- NimbleOptions.validate(opts, @options),
         :ok <- validate_scope(validated[:network], validated[:signer]) do
      {:ok,
       %__MODULE__{
         store: validated[:store],
         scope: {:auth_capture_signer, validated[:network], String.downcase(validated[:signer])},
         history_limit: validated[:history_limit]
       }}
    end
  end

  @doc since: "0.9.0"
  @doc """
  Reserves an immutable intent or returns its existing record.

  Only `{:reserved, entry}` grants a new ownership token. An existing record
  must be reconciled, not executed again. IDs are nonempty binaries of at most
  128 bytes; the caller must derive them from the canonical payment operation.
  """
  @spec reserve(t(), binary(), map()) ::
          {:ok, {:reserved | :existing, entry()}} | {:error, term()}
  def reserve(journal, id, intent)
      when is_binary(id) and byte_size(id) in 1..128 and is_map(intent) do
    owner = :crypto.strong_rand_bytes(32)

    update(journal, id, fn row, entry ->
      reserve_entry(row, entry, id, intent, owner, journal.history_limit)
    end)
  end

  def reserve(_journal, _id, _intent), do: {:error, :invalid_intent}

  @doc since: "0.9.0"
  @doc "Freezes raw transaction bytes and their local keccak-256 hash before any send."
  @spec prepare(t(), binary(), binary(), binary()) :: {:ok, entry()} | {:error, term()}
  def prepare(journal, id, owner, raw)
      when is_binary(raw) and byte_size(raw) > 0 and byte_size(raw) <= @max_raw_bytes do
    with {:ok, keccak} <- EIP712.keccak_module() do
      transaction = %{raw: raw, hash: "0x" <> Base.encode16(keccak.hash_256(raw), case: :lower)}

      transition(journal, id, owner, [:preparing], fn entry ->
        %{entry | phase: :prepared, transaction: transaction}
      end)
    end
  end

  def prepare(_journal, _id, _owner, _raw), do: {:error, :invalid_transaction}

  @doc since: "0.9.0"
  @doc "Durably grants the sole permission to send the frozen transaction."
  @spec dispatch(t(), binary(), binary()) :: {:ok, entry()} | {:error, term()}
  def dispatch(journal, id, owner),
    do: transition(journal, id, owner, [:prepared], &%{&1 | phase: :dispatched})

  @doc since: "0.9.0"
  @doc """
  Records a trusted, verified receipt without releasing the signer scope.

  The execution layer must establish transaction identity, finality, success
  or revert status, and expected events before calling this function.
  """
  @spec finish(t(), binary(), binary(), :confirmed | :reverted, map()) ::
          {:ok, entry()} | {:error, term()}
  def finish(journal, id, owner, phase, receipt)
      when phase in [:confirmed, :reverted] and is_map(receipt) do
    transition(journal, id, owner, [:dispatched], &%{&1 | phase: phase, receipt: receipt})
  end

  def finish(_journal, _id, _owner, _phase, _receipt), do: {:error, :invalid_outcome}

  @doc since: "0.9.0"
  @doc "Releases a completed scope only after its local effects are durably applied."
  @spec acknowledge(t(), binary(), binary()) :: {:ok, entry()} | {:error, term()}
  def acknowledge(journal, id, owner) do
    transition(
      journal,
      id,
      owner,
      [:confirmed, :reverted],
      fn entry ->
        %{entry | phase: if(entry.phase == :confirmed, do: :succeeded, else: :failed)}
      end,
      true
    )
  end

  @doc since: "0.9.0"
  @doc "Cancels only unprepared work. Frozen or dispatched work cannot be cancelled."
  @spec cancel_preparation(t(), binary(), binary()) :: {:ok, entry()} | {:error, term()}
  def cancel_preparation(journal, id, owner),
    do: transition(journal, id, owner, [:preparing], &%{&1 | phase: :cancelled}, true)

  @doc since: "0.9.0"
  @doc """
  Reads the active record, including finished work awaiting effect acknowledgement.

  Returns `:journal_changed` if ownership changes between selecting the key and
  reading the atomic snapshot. That is a safe read retry, not a new reservation.
  """
  @spec active(t()) :: {:ok, entry() | nil} | {:error, term()}
  def active(journal) do
    with {:ok, value} <- Store.fetch(journal.store, journal.scope),
         {:ok, row} <- row(value) do
      active_entry(journal, row.active)
    end
  end

  @doc since: "0.9.0"
  @doc "Reads a retained operation without treating a store failure as absence."
  @spec fetch(t(), binary()) :: {:ok, entry() | nil} | {:error, term()}
  def fetch(journal, id) do
    update(journal, id, fn _row, entry -> {:keep, entry} end)
  end

  @spec active_entry(t(), binary() | nil) :: {:ok, entry() | nil} | {:error, term()}
  defp active_entry(_journal, nil), do: {:ok, nil}

  defp active_entry(journal, id) do
    update(journal, id, fn row, entry ->
      if row.active == id, do: {:keep, entry}, else: {:abort, :journal_changed}
    end)
  end

  @spec reserve_entry(map(), entry() | nil, binary(), map(), binary(), pos_integer()) :: tuple()
  defp reserve_entry(row, entry, id, intent, owner, limit) do
    case entry do
      %{intent: ^intent, phase: :cancelled} ->
        insert_entry(row, id, intent, owner, 0)

      %{intent: ^intent} ->
        {:keep, {:existing, entry}}

      nil when row.count >= limit ->
        {:abort, :journal_full}

      nil ->
        insert_entry(row, id, intent, owner, 1)

      _different ->
        {:abort, :intent_mismatch}
    end
  end

  @spec insert_entry(map(), binary(), map(), binary(), 0 | 1) :: tuple()
  defp insert_entry(%{active: nil} = row, id, intent, owner, increment) do
    entry = %{
      id: id,
      owner: owner,
      intent: intent,
      phase: :preparing,
      transaction: nil,
      receipt: nil
    }

    {:commit, %{row | active: id, owner: owner, count: row.count + increment}, entry,
     {:reserved, entry}}
  end

  defp insert_entry(_row, _id, _intent, _owner, _increment), do: {:abort, :signer_busy}

  @spec transition(t(), binary(), binary(), [atom()], (entry() -> entry()), boolean()) ::
          {:ok, entry()} | {:error, term()}
  defp transition(journal, id, owner, phases, fun, release \\ false) do
    update(journal, id, fn row, entry ->
      case entry do
        %{owner: ^owner, phase: phase} = entry when row.active == id ->
          advance(row, entry, phase in phases, fun, release)

        nil ->
          {:abort, :unknown_operation}

        _other ->
          {:abort, :ownership_lost}
      end
    end)
  end

  @spec advance(map(), entry(), boolean(), (entry() -> entry()), boolean()) :: tuple()
  defp advance(row, entry, true, fun, release) do
    next = fun.(entry)
    {:commit, if(release, do: %{row | active: nil, owner: nil}, else: row), next, next}
  end

  defp advance(_row, _entry, false, _fun, _release), do: {:abort, :invalid_phase}

  @spec update(t(), binary(), (map(), entry() | nil -> tuple())) ::
          {:ok, term()} | {:error, term()}
  defp update(journal, id, fun) do
    key = {journal.scope, :operation, id}

    Store.transact_many(journal.store, [journal.scope, key], fn values ->
      with {:ok, row} <- row(Map.fetch!(values, journal.scope)),
           {:ok, entry} <- entry(Map.fetch!(values, key), id, row) do
        write_result(fun.(row, entry), row, journal.scope, key)
      else
        {:error, reason} -> {:abort, reason}
      end
    end)
  end

  @spec write_result(tuple(), map(), tuple(), tuple()) :: tuple()
  defp write_result({:commit, next_row, next_entry, reply}, row, scope, key) do
    changes = %{key => next_entry}
    changes = if next_row == row, do: changes, else: Map.put(changes, scope, next_row)
    {:commit, changes, reply}
  end

  defp write_result(result, _row, _scope, _key), do: result

  @spec row(Store.value()) :: {:ok, map()} | {:error, atom()}
  defp row(nil), do: {:ok, %{version: 1, active: nil, owner: nil, count: 0}}

  defp row(%{version: 1, active: nil, owner: nil, count: count} = row)
       when is_integer(count) and count >= 0, do: {:ok, row}

  defp row(%{version: 1, active: id, owner: owner, count: count} = row)
       when is_binary(id) and byte_size(id) in 1..128 and is_binary(owner) and
              byte_size(owner) == 32 and is_integer(count) and count > 0,
       do: {:ok, row}

  defp row(_value), do: {:error, :invalid_journal}

  @spec entry(Store.value(), binary(), map()) :: {:ok, entry() | nil} | {:error, atom()}
  defp entry(nil, id, %{active: active}) when id != active, do: {:ok, nil}

  defp entry(
         %{
           id: id,
           owner: owner,
           intent: intent,
           phase: phase,
           transaction: transaction,
           receipt: receipt
         } = entry,
         id,
         row
       )
       when is_binary(owner) and byte_size(owner) == 32 and is_map(intent) do
    if ownership_valid?(phase, row, id, owner) and record_valid?(phase, transaction, receipt),
      do: {:ok, entry},
      else: {:error, :invalid_journal}
  end

  defp entry(_entry, _id, _row), do: {:error, :invalid_journal}

  @spec ownership_valid?(atom(), map(), binary(), binary()) :: boolean()
  defp ownership_valid?(phase, row, id, owner) when phase in @active_phases,
    do: row.active == id and row.owner == owner

  defp ownership_valid?(phase, row, id, _owner) when phase in @terminal_phases,
    do: row.active != id and row.count > 0

  defp ownership_valid?(_phase, _row, _id, _owner), do: false

  @spec record_valid?(atom(), term(), term()) :: boolean()
  defp record_valid?(phase, nil, nil) when phase in [:preparing, :cancelled], do: true

  defp record_valid?(phase, transaction, receipt)
       when phase in [:prepared, :dispatched] and is_nil(receipt),
       do: transaction_valid?(transaction)

  defp record_valid?(phase, transaction, receipt)
       when phase in [:confirmed, :reverted, :succeeded, :failed] and is_map(receipt),
       do: transaction_valid?(transaction)

  defp record_valid?(_phase, _transaction, _receipt), do: false

  @spec transaction_valid?(term()) :: boolean()
  defp transaction_valid?(%{raw: raw, hash: "0x" <> hash})
       when is_binary(raw) and byte_size(raw) in 1..@max_raw_bytes and byte_size(hash) == 64,
       do: match?({:ok, _}, Base.decode16(hash, case: :mixed))

  defp transaction_valid?(_transaction), do: false

  @spec validate_scope(String.t(), String.t()) :: :ok | {:error, :invalid_scope}
  defp validate_scope("eip155:" <> chain, signer) do
    with {:ok, chain_id} when chain_id > 0 <- EVM.parse_uint256(chain),
         true <- chain == Integer.to_string(chain_id),
         true <- EVM.nonzero_address?(signer) do
      :ok
    else
      _invalid -> {:error, :invalid_scope}
    end
  end

  defp validate_scope(_network, _signer), do: {:error, :invalid_scope}
end
