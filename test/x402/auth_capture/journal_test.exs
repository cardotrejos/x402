defmodule X402.AuthCapture.JournalTest do
  use ExUnit.Case, async: true

  doctest X402.AuthCapture.Journal

  alias X402.AuthCapture.ETSStore
  alias X402.AuthCapture.Journal
  alias X402.AuthCapture.Store

  @signer "0xabcdef0123456789abcdef0123456789abcdef01"
  @intent %{payment: "payment-id", operation: :authorize, calldata: <<1, 2>>}

  defmodule CommitThenTimeout do
    @moduledoc false
    @behaviour Store

    @impl Store
    def fetch({server, _fault}, key), do: ETSStore.fetch(server, key)

    @impl Store
    def transact_many({server, fault}, keys, mutation) do
      result = ETSStore.transact_many(server, keys, mutation)
      if Agent.get_and_update(fault, &{&1, false}), do: {:error, :timeout}, else: result
    end
  end

  defmodule CountingStore do
    @moduledoc false
    @behaviour Store

    @impl Store
    def fetch(server, key), do: Agent.get(server, &{:ok, Map.get(&1.rows, key)})

    @impl Store
    def transact_many(server, keys, mutation) do
      Agent.get_and_update(server, fn state ->
        snapshot = Map.new(keys, &{&1, Map.get(state.rows, &1)})
        state = %{state | keys: keys}

        case mutation.(snapshot) do
          {:commit, changes, reply} ->
            {{:ok, reply},
             %{state | rows: Map.merge(state.rows, changes), commits: state.commits + 1}}

          {:keep, reply} ->
            {{:ok, reply}, state}

          {:abort, reason} ->
            {{:error, reason}, state}
        end
      end)
    end
  end

  defmodule ChangeAfterRead do
    @moduledoc false
    @behaviour Store

    @impl Store
    def fetch({server, action}, key) do
      result = ETSStore.fetch(server, key)
      action.()
      result
    end

    @impl Store
    def transact_many({server, _action}, keys, mutation),
      do: ETSStore.transact_many(server, keys, mutation)
  end

  setup do
    server = start_supervised!(ETSStore)
    opts = [store: {ETSStore, server}, network: "eip155:8453", signer: @signer]
    {:ok, journal} = Journal.new(opts)
    %{journal: journal, opts: opts, server: server}
  end

  test "validates and canonicalizes concrete signer scopes", %{opts: opts, journal: journal} do
    upper = "0x" <> String.upcase(String.slice(@signer, 2..-1//1))
    assert {:ok, same} = Journal.new(Keyword.put(opts, :signer, upper))
    assert same.scope == journal.scope

    for network <- [
          "solana:any",
          "eip155:0",
          "eip155:08453",
          "eip155:+8453",
          "eip155:" <> String.duplicate("9", 79)
        ] do
      assert Journal.new(Keyword.put(opts, :network, network)) == {:error, :invalid_scope}
    end

    for signer <- ["bad", "0x" <> String.duplicate("0", 40), @signer <> "\n"] do
      assert Journal.new(Keyword.put(opts, :signer, signer)) == {:error, :invalid_scope}
    end

    assert {:error, _} = Journal.new(Keyword.put(opts, :history_limit, 0))
    assert {:error, _} = Journal.new(Keyword.put(opts, :ttl, 1))
  end

  test "one concurrent reservation owns a signer scope", %{journal: journal} do
    assert Journal.active(journal) == {:ok, nil}
    assert Journal.fetch(journal, "op") == {:ok, nil}

    results =
      1..32
      |> Task.async_stream(fn _ -> Journal.reserve(journal, "op", @intent) end,
        max_concurrency: 32
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert [{:ok, {:reserved, entry}}] = Enum.filter(results, &match?({:ok, {:reserved, _}}, &1))
    assert length(Enum.filter(results, &match?({:ok, {:existing, _}}, &1))) == 31
    assert byte_size(entry.owner) == 32
    assert Journal.active(journal) == {:ok, entry}
    assert Journal.reserve(journal, "other", @intent) == {:error, :signer_busy}
    assert Journal.reserve(journal, "op", %{operation: :void}) == {:error, :intent_mismatch}
    assert Journal.reserve(journal, "", @intent) == {:error, :invalid_intent}

    assert Journal.reserve(journal, String.duplicate("x", 129), @intent) ==
             {:error, :invalid_intent}

    assert Journal.reserve(journal, "bad", nil) == {:error, :invalid_intent}
  end

  test "persists raw identity and grants dispatch exactly once", %{journal: journal} do
    {:ok, {:reserved, entry}} = Journal.reserve(journal, "op", @intent)
    assert Journal.dispatch(journal, "op", entry.owner) == {:error, :invalid_phase}
    assert Journal.prepare(journal, "op", <<0::256>>, "raw") == {:error, :ownership_lost}
    assert Journal.prepare(journal, "missing", entry.owner, "raw") == {:error, :unknown_operation}
    assert Journal.prepare(journal, "op", entry.owner, "") == {:error, :invalid_transaction}

    assert Journal.prepare(journal, "op", entry.owner, :binary.copy(<<1>>, 262_145)) ==
             {:error, :invalid_transaction}

    assert {:ok, prepared} = Journal.prepare(journal, "op", entry.owner, "raw")
    assert prepared.phase == :prepared
    assert prepared.transaction.raw == "raw"

    assert prepared.transaction.hash ==
             "0x" <> Base.encode16(ExKeccak.hash_256("raw"), case: :lower)

    assert Journal.prepare(journal, "op", entry.owner, "replacement") == {:error, :invalid_phase}
    assert Journal.cancel_preparation(journal, "op", entry.owner) == {:error, :invalid_phase}

    results =
      1..32
      |> Task.async_stream(fn _ -> Journal.dispatch(journal, "op", entry.owner) end,
        max_concurrency: 32
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert length(Enum.filter(results, &match?({:ok, %{phase: :dispatched}}, &1))) == 1
    assert length(Enum.filter(results, &(&1 == {:error, :invalid_phase}))) == 31
    assert {:ok, %{transaction: transaction}} = Journal.active(journal)
    assert transaction == prepared.transaction
  end

  test "receipt effects must be acknowledged before releasing the signer", %{journal: journal} do
    for {id, phase, terminal} <- [
          {"success", :confirmed, :succeeded},
          {"revert", :reverted, :failed}
        ] do
      {:ok, {:reserved, entry}} = Journal.reserve(journal, id, @intent)
      {:ok, _} = Journal.prepare(journal, id, entry.owner, "raw")
      assert Journal.finish(journal, id, entry.owner, phase, %{}) == {:error, :invalid_phase}
      {:ok, sent} = Journal.dispatch(journal, id, entry.owner)
      receipt = %{"transactionHash" => sent.transaction.hash}
      assert {:ok, completed} = Journal.finish(journal, id, entry.owner, phase, receipt)
      assert completed.receipt == receipt
      assert Journal.reserve(journal, "blocked", @intent) == {:error, :signer_busy}
      assert Journal.finish(journal, id, entry.owner, phase, receipt) == {:error, :invalid_phase}
      assert {:ok, final} = Journal.acknowledge(journal, id, entry.owner)
      assert final.phase == terminal
      assert Journal.active(journal) == {:ok, nil}
      assert Journal.reserve(journal, id, @intent) == {:ok, {:existing, final}}
      assert Journal.dispatch(journal, id, entry.owner) == {:error, :ownership_lost}
    end

    assert Journal.finish(journal, "bad", "owner", :other, %{}) == {:error, :invalid_outcome}
  end

  test "cancelled preparations require a new owner and retain immutable intent", %{
    journal: journal
  } do
    {:ok, {:reserved, old}} = Journal.reserve(journal, "op", @intent)
    assert {:ok, %{phase: :cancelled}} = Journal.cancel_preparation(journal, "op", old.owner)
    assert Journal.reserve(journal, "op", %{}) == {:error, :intent_mismatch}
    {:ok, {:reserved, other}} = Journal.reserve(journal, "other", @intent)
    assert Journal.reserve(journal, "op", @intent) == {:error, :signer_busy}
    {:ok, _} = Journal.cancel_preparation(journal, "other", other.owner)
    assert {:ok, {:reserved, fresh}} = Journal.reserve(journal, "op", @intent)
    refute fresh.owner == old.owner
    assert Journal.prepare(journal, "op", old.owner, "raw") == {:error, :ownership_lost}
    assert {:ok, _} = Journal.prepare(journal, "op", fresh.owner, "raw")
  end

  test "history cap refuses eviction, including cancelled records", %{opts: opts} do
    {:ok, journal} = Journal.new(Keyword.put(opts, :history_limit, 1))
    {:ok, {:reserved, entry}} = Journal.reserve(journal, "op", @intent)
    {:ok, _} = Journal.cancel_preparation(journal, "op", entry.owner)
    assert Journal.reserve(journal, "other", @intent) == {:error, :journal_full}
    assert {:ok, {:reserved, _}} = Journal.reserve(journal, "op", @intent)
  end

  test "committed timeout cannot grant a second dispatch", %{opts: opts, server: server} do
    fault = start_supervised!({Agent, fn -> false end})
    {:ok, journal} = Journal.new(Keyword.put(opts, :store, {CommitThenTimeout, {server, fault}}))
    {:ok, {:reserved, entry}} = Journal.reserve(journal, "op", @intent)
    {:ok, _} = Journal.prepare(journal, "op", entry.owner, "raw")
    Agent.update(fault, fn _ -> true end)
    assert Journal.dispatch(journal, "op", entry.owner) == {:error, :timeout}
    assert {:ok, %{phase: :dispatched}} = Journal.active(journal)
    assert Journal.dispatch(journal, "op", entry.owner) == {:error, :invalid_phase}
    assert Journal.reserve(journal, "new", @intent) == {:error, :signer_busy}
  end

  test "store failures and corrupted roots are not fresh journals", %{
    journal: journal,
    server: server
  } do
    for value <- [
          %{},
          %{version: 2, active: nil, records: %{}},
          %{version: 1, active: "missing", records: %{}}
        ] do
      {:ok, :saved} =
        ETSStore.transact(server, journal.scope, fn _ -> {:commit, value, :saved} end)

      assert Journal.active(journal) == {:error, :invalid_journal}
      assert Journal.fetch(journal, "op") == {:error, :invalid_journal}
      assert Journal.reserve(journal, "op", @intent) == {:error, :invalid_journal}
    end

    GenServer.stop(server)
    assert Journal.active(journal) == {:error, :store_unavailable}
    assert Journal.reserve(journal, "op", @intent) == {:error, :store_unavailable}
  end

  test "corrupted IDs, phases and owner links cannot grant dispatch", %{
    journal: journal,
    server: server
  } do
    {:ok, {:reserved, reservation}} = Journal.reserve(journal, "op", @intent)
    {:ok, prepared} = Journal.prepare(journal, "op", reservation.owner, "raw")
    key = {journal.scope, :operation, "op"}

    for corrupted <- [
          %{prepared | id: "other"},
          %{prepared | owner: <<0::256>>},
          %{prepared | phase: :unknown},
          %{prepared | transaction: nil},
          %{prepared | transaction: %{raw: "raw", hash: "0xzz"}},
          %{prepared | receipt: %{}}
        ] do
      {:ok, :saved} = ETSStore.transact(server, key, fn _ -> {:commit, corrupted, :saved} end)
      assert Journal.dispatch(journal, "op", prepared.owner) == {:error, :invalid_journal}
      assert Journal.dispatch(journal, "op", prepared.owner) == {:error, :invalid_journal}
      assert Journal.fetch(journal, "op") == {:error, :invalid_journal}
    end

    {:ok, :saved} = ETSStore.transact(server, key, fn _ -> {:commit, prepared, :saved} end)
    {:ok, _} = Journal.dispatch(journal, "op", prepared.owner)

    {:ok, :saved} =
      ETSStore.transact(server, journal.scope, fn row ->
        {:commit, %{row | active: nil}, :saved}
      end)

    assert Journal.reserve(journal, "new", @intent) == {:error, :invalid_journal}
    assert Journal.active(journal) == {:error, :invalid_journal}
  end

  test "duplicates and reads use no-change snapshots and touch only selected history", %{
    opts: opts
  } do
    server = start_supervised!({Agent, fn -> %{rows: %{}, commits: 0, keys: []} end})
    {:ok, journal} = Journal.new(Keyword.put(opts, :store, {CountingStore, server}))
    {:ok, {:reserved, entry}} = Journal.reserve(journal, "op", @intent)

    for _ <- 1..32 do
      assert Journal.reserve(journal, "op", @intent) == {:ok, {:existing, entry}}
      assert Journal.fetch(journal, "op") == {:ok, entry}
      assert Journal.active(journal) == {:ok, entry}
    end

    stats = Agent.get(server, & &1)
    assert stats.commits == 1
    assert stats.keys == [journal.scope, {journal.scope, :operation, "op"}]
    refute Map.has_key?(stats.rows[journal.scope], :records)
    assert map_size(stats.rows) == 2

    Agent.update(server, fn state ->
      history =
        Map.new(1..1000, fn index ->
          {{journal.scope, :operation, "historical-#{index}"},
           %{retained: :binary.copy(<<1>>, 1024)}}
        end)

      %{state | rows: Map.merge(state.rows, history)}
    end)

    assert Journal.active(journal) == {:ok, entry}
    stats = Agent.get(server, & &1)
    assert stats.keys == [journal.scope, {journal.scope, :operation, "op"}]
    assert stats.commits == 1
    assert map_size(stats.rows) == 1002
  end

  test "active selection changing before its snapshot requires a read retry", %{
    journal: journal,
    opts: opts,
    server: server
  } do
    {:ok, {:reserved, entry}} = Journal.reserve(journal, "op", @intent)
    action = fn -> Journal.cancel_preparation(journal, "op", entry.owner) end
    {:ok, reader} = Journal.new(Keyword.put(opts, :store, {ChangeAfterRead, {server, action}}))
    assert Journal.active(reader) == {:error, :journal_changed}
    assert Journal.active(journal) == {:ok, nil}
  end

  test "missing active entry and inconsistent inactive ownership fail closed", %{
    journal: journal,
    server: server
  } do
    {:ok, {:reserved, entry}} = Journal.reserve(journal, "op", @intent)
    {:ok, _} = Journal.prepare(journal, "op", entry.owner, "raw")
    {:ok, scope} = ETSStore.fetch(server, journal.scope)

    {:ok, :saved} =
      ETSStore.transact(server, journal.scope, fn _ ->
        {:commit, %{scope | active: "missing"}, :saved}
      end)

    assert Journal.active(journal) == {:error, :invalid_journal}
    assert Journal.dispatch(journal, "op", entry.owner) == {:error, :invalid_journal}

    {:ok, :saved} =
      ETSStore.transact(server, journal.scope, fn _ ->
        {:commit, %{scope | active: nil, owner: nil}, :saved}
      end)

    assert Journal.dispatch(journal, "op", entry.owner) == {:error, :invalid_journal}
  end
end
