defmodule X402.ETSTable do
  @moduledoc false

  # Named public ETS tables created on first use and owned by a dedicated,
  # unsupervised holder process, so callers need neither a GenServer in
  # their supervision tree nor to worry about the creating process exiting.

  @owner_key :"$x402_owner"

  @spec ensure(atom(), [term()]) :: atom()
  def ensure(name, opts) when is_atom(name) and is_list(opts) do
    case :ets.whereis(name) do
      :undefined ->
        start_owner(name, opts)
        ensure(name, opts)

      _tid ->
        name
    end
  end

  @spec delete(atom()) :: :ok
  def delete(name) when is_atom(name) do
    case :ets.whereis(name) do
      :undefined ->
        :ok

      _tid ->
        case :ets.lookup(name, @owner_key) do
          [{@owner_key, owner}] -> stop_owner(owner)
          [] -> :ok
        end
    end
  end

  # Concurrent first callers race to create the table; the loser's
  # `:ets.new/2` raises inside its holder process, which then exits, and
  # the caller re-checks `:ets.whereis/1`.
  defp start_owner(name, opts) do
    parent = self()
    ref = make_ref()

    spawn(fn ->
      created? =
        try do
          :ets.new(name, [:named_table, :public | opts])
          :ets.insert(name, {@owner_key, self()})
          true
        rescue
          ArgumentError -> false
        end

      send(parent, {ref, created?})

      if created? do
        receive do
          :delete -> :ets.delete(name)
        end
      end
    end)

    receive do
      {^ref, _created?} -> :ok
    end
  end

  defp stop_owner(owner) do
    monitor = Process.monitor(owner)
    send(owner, :delete)

    receive do
      {:DOWN, ^monitor, :process, ^owner, _reason} -> :ok
    after
      5_000 -> :ok
    end
  end
end
