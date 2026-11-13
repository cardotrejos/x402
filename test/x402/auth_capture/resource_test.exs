defmodule X402.AuthCapture.ResourceTest do
  use ExUnit.Case, async: true

  alias X402.AuthCapture.Engine
  alias X402.AuthCapture.Journal
  alias X402.AuthCapture.Resource
  alias X402.AuthCapture.Store
  alias X402.Scheme.AuthCaptureEVM, as: Scheme
  alias X402.Signer.LocalKey
  alias X402.TestAuthCapture, as: Fixture
  alias X402.TestAuthCaptureNode, as: Node

  defmodule WrongConsentSigner do
    @moduledoc false
    @behaviour X402.Signer
    defstruct [:address, :inner]
    @impl true
    def address(signer), do: {:ok, signer.address}
    @impl true
    def sign_eip712(signer, digest, typed_data),
      do: LocalKey.sign_eip712(signer.inner, digest, typed_data)
  end

  defmodule HookSigner do
    @moduledoc false
    @behaviour X402.Signer
    defstruct [:address, :inner, :hook]
    @impl true
    def address(signer), do: {:ok, signer.address}
    @impl true
    def sign_eip712(signer, digest, typed_data) do
      signer.hook.()
      LocalKey.sign_eip712(signer.inner, digest, typed_data)
    end
  end

  defmodule UnavailableStore do
    @moduledoc false
    @behaviour X402.AuthCapture.Store
    @impl true
    def fetch(_context, _key), do: {:error, :disk_unavailable}
    @impl true
    def transact_many(_context, _keys, _mutation), do: {:error, :disk_unavailable}
  end

  setup context do
    mode = Map.get(context, :mode, :sync)
    ctx = Node.setup(__MODULE__, mode)
    Agent.update(ctx.node, &%{&1 | advance_state: true})
    {:ok, resource} = Resource.new(engine: ctx.engine, authorizer: ctx.authorizer, mode: mode)
    Map.put(ctx, :resource, resource)
  end

  test "confirms a hold before handler and withholds output until capture and void", ctx do
    handler = fn ->
      assert Agent.get(ctx.node, & &1.sends) == 1
      assert {:ok, %{phase: :executing}} = read_entry(ctx)
      {:ok, %{"content" => "paid"}, 750_000}
    end

    assert {:ok, %{"content" => "paid"}, receipt} =
             Resource.run(ctx.resource, ctx.envelope, ctx.requirements, handler)

    assert receipt.charged_amount == 750_000
    assert receipt.status == :settled
    assert Agent.get(ctx.node, & &1.sends) == 3
    assert Agent.get(ctx.node, & &1.payment_state) == <<1::256, 0::256, 750_000::256>>
    assert Journal.active(ctx.engine.journal) == {:ok, nil}
    assert {:ok, %{phase: :complete}} = read_entry(ctx)
  end

  test "full capture avoids an unnecessary void", ctx do
    assert {:ok, "paid", receipt} =
             Resource.run(ctx.resource, ctx.envelope, ctx.requirements, fn ->
               {:ok, "paid", 1_000_000}
             end)

    assert Agent.get(ctx.node, & &1.sends) == 2

    assert Resource.resume(ctx.resource, ctx.payment_info_hash) ==
             {:ok, "paid", receipt}

    assert Agent.get(ctx.node, & &1.sends) == 2
  end

  test "explicit handler failure voids the whole hold without capture", ctx do
    assert Resource.run(ctx.resource, ctx.envelope, ctx.requirements, fn ->
             {:error, :unavailable}
           end) == {:error, :handler_failed}

    assert Agent.get(ctx.node, & &1.sends) == 2
    assert Agent.get(ctx.node, & &1.payment_state) == <<1::256, 0::256, 0::256>>
    assert Resource.resume(ctx.resource, ctx.payment_info_hash) == {:error, :handler_failed}
  end

  test "zero charge returns content only after confirmed void", ctx do
    assert {:ok, "free", %{charged_amount: 0, status: :settled}} =
             Resource.run(ctx.resource, ctx.envelope, ctx.requirements, fn -> {:ok, "free", 0} end)

    assert Agent.get(ctx.node, & &1.sends) == 2
  end

  test "uncertain handlers and invalid metering never run again", ctx do
    assert Resource.run(ctx.resource, ctx.envelope, ctx.requirements, fn ->
             raise "private failure"
           end) == {:error, :execution_uncertain}

    assert {:ok, %{phase: :executing}} = read_entry(ctx)
    test = self()

    assert Resource.resume(ctx.resource, ctx.payment_info_hash, fn ->
             send(test, :rerun)
             {:ok, "wrong", 1}
           end) == {:error, :execution_uncertain}

    refute_received :rerun
    assert Agent.get(ctx.node, & &1.sends) == 1
  end

  test "overcharging and unpersistable output withhold content", ctx do
    assert Resource.run(ctx.resource, ctx.envelope, ctx.requirements, fn ->
             {:ok, "never returned", 1_000_001}
           end) == {:error, :invalid_handler_result}

    assert Resource.resume(ctx.resource, ctx.payment_info_hash) == {:error, :execution_uncertain}
  end

  test "funding uncertainty is resumable without a duplicate handler", ctx do
    Agent.update(ctx.node, &%{&1 | receipt_mode: :pending})
    test = self()

    handler = fn ->
      send(test, :handled)
      {:ok, "paid", 750_000}
    end

    assert Resource.run(ctx.resource, ctx.envelope, ctx.requirements, handler) ==
             {:pending, ctx.payment_info_hash}

    refute_received :handled
    Agent.update(ctx.node, &%{&1 | receipt_mode: :confirmed})
    assert {:pending, _} = Resource.resume(ctx.resource, ctx.payment_info_hash)
    assert {:ok, %{phase: :funded}} = read_entry(ctx)

    results =
      1..32
      |> Task.async_stream(
        fn _ ->
          Resource.resume(ctx.resource, ctx.payment_info_hash, handler)
        end,
        max_concurrency: 32
      )
      |> Enum.to_list()

    assert Enum.any?(results, &match?({:ok, {:ok, "paid", _}}, &1))
    assert_received :handled
    refute_received :handled
    assert Agent.get(ctx.node, & &1.sends) == 3
  end

  @tag mode: :deferred
  test "deferred content has durable metering and application-driven settlement", ctx do
    assert {:ok, "paid", %{status: :deferred}} =
             Resource.run(ctx.resource, ctx.envelope, ctx.requirements, fn ->
               {:ok, "paid", 750_000}
             end)

    assert Agent.get(ctx.node, & &1.sends) == 1
    assert {:ok, %{phase: :metered, charged: 750_000}} = read_entry(ctx)

    assert {:ok, "paid", %{status: :settled}} =
             Resource.resume(ctx.resource, ctx.payment_info_hash)

    assert Agent.get(ctx.node, & &1.sends) == 3
  end

  test "unsupported routes and absent recovery records fail without execution", ctx do
    requirements = put_in(ctx.requirements, ["extra", "captureMode"], "deferred")

    assert Resource.run(ctx.resource, ctx.envelope, requirements, fn -> flunk("not admitted") end) ==
             {:error, :unsupported_resource_flow}

    assert Resource.resume(ctx.resource, "missing") == {:error, :unknown_payment}
    assert {:error, _} = Resource.new(engine: nil, authorizer: ctx.authorizer)
    assert {:error, _} = Resource.new(engine: ctx.engine, authorizer: nil)
  end

  test "recovery checks present hold and expiry before a never-started handler", ctx do
    Agent.update(ctx.node, &%{&1 | receipt_mode: :pending})

    assert {:pending, _} =
             Resource.run(ctx.resource, ctx.envelope, ctx.requirements, fn ->
               flunk("funding pending")
             end)

    Agent.update(
      ctx.node,
      &%{&1 | receipt_mode: :confirmed, payment_state: <<1::256, 0::256, 0::256>>}
    )

    assert {:error, _} =
             Resource.resume(ctx.resource, ctx.payment_info_hash, fn ->
               flunk("reclaimed hold")
             end)

    assert {:ok, %{phase: :funded}} = read_entry(ctx)
    Agent.update(ctx.node, &%{&1 | payment_state: <<1::256, 1_000_000::256, 0::256>>})

    {:ok, expired_engine} =
      Engine.new(
        Keyword.put(ctx.opts, :clock, fn -> ctx.requirements["extra"]["captureDeadline"] + 1 end)
      )

    assert {:error, _} =
             Resource.resume(
               %{ctx.resource | engine: expired_engine},
               ctx.payment_info_hash,
               fn -> flunk("expired hold") end
             )

    assert {:ok, %{phase: :funded}} = read_entry(ctx)
  end

  test "bad retained void is refused before funding or admission", ctx do
    {:ok, wrong_key} = LocalKey.new(<<4::256>>)
    signer = %WrongConsentSigner{address: ctx.authorizer.address, inner: wrong_key}
    {:ok, resource} = Resource.new(engine: ctx.engine, authorizer: signer)

    assert Resource.run(resource, ctx.envelope, ctx.requirements, fn -> flunk("bad consent") end) ==
             {:error, {:invalid, :authorizer_signature}}

    assert read_entry(ctx) == {:ok, nil}
    assert Agent.get(ctx.node, & &1.sends) == 0
  end

  test "aggregate size limit precedes any RPC, consent or durable admission", ctx do
    oversized = Map.put(ctx.envelope, "ignored", String.duplicate("x", 262_145))

    assert Resource.run(ctx.resource, oversized, ctx.requirements, fn -> flunk("oversized") end) ==
             {:error, :request_too_large}

    refute_received {:auth_rpc, _, _}
    assert read_entry(ctx) == {:ok, nil}
  end

  test "deployed receiver consent is checked through ERC-1271 before funding", ctx do
    authorizer = String.downcase(ctx.authorizer.address)
    Agent.update(ctx.node, &%{&1 | accounts: List.delete(&1.accounts, authorizer)})

    assert {:ok, "paid", _} =
             Resource.run(ctx.resource, ctx.envelope, ctx.requirements, fn -> {:ok, "paid", 0} end)

    assert_received {:auth_rpc, "eth_call",
                     [
                       %{"to" => ^authorizer, "data" => "0x1626ba7e" <> _},
                       %{"requireCanonical" => true}
                     ]}

    assert Agent.get(ctx.node, & &1.sends) == 2
  end

  test "capacity bounds funding backlog without evicting recovery records", ctx do
    {:ok, resource} = Resource.new(engine: ctx.engine, authorizer: ctx.authorizer, max_records: 1)
    Agent.update(ctx.node, &%{&1 | receipt_mode: :pending})

    assert {:pending, _} =
             Resource.run(resource, ctx.envelope, ctx.requirements, fn -> flunk("pending") end)

    drain_rpc()

    resource = %{
      resource
      | authorizer: %WrongConsentSigner{address: ctx.authorizer.address, inner: nil}
    }

    {:ok, payer} = LocalKey.new(<<1::256>>)

    for index <- 1..3 do
      {:ok, payload} =
        Scheme.sign(ctx.requirements, payer,
          now: Fixture.fixture()["now"],
          salt_nonce: Fixture.hex(<<index::256>>)
        )

      envelope = %{ctx.envelope | "payload" => payload}

      assert Resource.run(resource, envelope, ctx.requirements, fn -> flunk("full") end) ==
               {:error, :resource_capacity_exhausted}
    end

    assert {:ok, %{phase: :funding}} = read_entry(ctx)
    assert Agent.get(ctx.node, & &1.sends) == 1
    refute_received {:auth_rpc, _, _}
  end

  test "existing admission is rejected without RPC or another receiver signature", ctx do
    Agent.update(ctx.node, &%{&1 | receipt_mode: :pending})

    assert {:pending, _} =
             Resource.run(ctx.resource, ctx.envelope, ctx.requirements, fn -> flunk("pending") end)

    drain_rpc()

    resource = %{
      ctx.resource
      | authorizer: %WrongConsentSigner{address: ctx.authorizer.address, inner: nil}
    }

    assert Resource.run(resource, ctx.envelope, ctx.requirements, fn -> flunk("duplicate") end) ==
             {:error, :payment_already_admitted}

    refute_received {:auth_rpc, _, _}
  end

  @spec drain_rpc() :: :ok
  defp drain_rpc do
    receive do
      {:auth_rpc, _, _} -> drain_rpc()
    after
      0 -> :ok
    end
  end

  test "output is immutable and separate from settlement metadata", ctx do
    assert {:ok, "paid", _} =
             Resource.run(ctx.resource, ctx.envelope, ctx.requirements, fn ->
               {:ok, "paid", 750_000}
             end)

    assert {:ok, entry} = read_entry(ctx)
    refute Map.has_key?(entry, :value)
    key = {:auth_capture_resource, ctx.engine.network, ctx.payment_info_hash}
    assert Store.fetch(ctx.engine.journal.store, {key, :output}) == {:ok, %{json: "\"paid\""}}
  end

  @spec read_entry(map()) :: {:ok, map() | nil} | {:error, term()}
  defp read_entry(ctx),
    do:
      Store.fetch(
        ctx.engine.journal.store,
        {:auth_capture_resource, ctx.engine.network, ctx.payment_info_hash}
      )

  test "an authorizer without a usable address is refused", ctx do
    zero = "0x0000000000000000000000000000000000000000"
    signer = %WrongConsentSigner{address: zero, inner: nil}

    assert Resource.new(engine: ctx.engine, authorizer: signer) == {:error, :invalid_authorizer}
  end

  test "a signer that raises during consent preparation never reaches admission", ctx do
    hook = fn -> raise "private signer failure" end
    signer = %HookSigner{address: ctx.authorizer.address, inner: ctx.authorizer, hook: hook}
    {:ok, resource} = Resource.new(engine: ctx.engine, authorizer: signer)

    assert Resource.run(resource, ctx.envelope, ctx.requirements, fn -> flunk("not admitted") end) ==
             {:error, :consent_preparation_failed}

    assert read_entry(ctx) == {:ok, nil}
    assert Agent.get(ctx.node, & &1.sends) == 0
  end

  test "an unreadable store is reported instead of an unknown payment", ctx do
    {:ok, engine} = Engine.new(Keyword.put(ctx.opts, :store, {UnavailableStore, nil}))
    {:ok, resource} = Resource.new(engine: engine, authorizer: ctx.authorizer)

    assert Resource.resume(resource, ctx.payment_info_hash) == {:error, :disk_unavailable}

    assert Resource.run(resource, ctx.envelope, ctx.requirements, fn -> flunk("no store") end) ==
             {:error, :disk_unavailable}

    assert Agent.get(ctx.node, & &1.sends) == 0
  end

  test "a payment admitted while consent was being prepared is not admitted twice", ctx do
    Agent.update(ctx.node, &%{&1 | receipt_mode: :pending})
    test = self()

    hook = fn ->
      send(test, {:racing, Resource.run(ctx.resource, ctx.envelope, ctx.requirements, &flunk/0)})
    end

    signer = %HookSigner{address: ctx.authorizer.address, inner: ctx.authorizer, hook: hook}
    {:ok, resource} = Resource.new(engine: ctx.engine, authorizer: signer)

    assert Resource.run(resource, ctx.envelope, ctx.requirements, fn -> flunk("duplicate") end) ==
             {:error, :payment_already_admitted}

    assert_received {:racing, {:pending, hash}}
    assert hash == ctx.payment_info_hash
    assert {:ok, %{phase: :funding}} = read_entry(ctx)
    assert Agent.get(ctx.node, & &1.sends) == 1
  end

  test "capacity taken while consent was being prepared aborts the later admission", ctx do
    Agent.update(ctx.node, &%{&1 | receipt_mode: :pending})
    {:ok, payer} = LocalKey.new(<<1::256>>)

    {:ok, payload} =
      Scheme.sign(ctx.requirements, payer,
        now: Fixture.fixture()["now"],
        salt_nonce: Fixture.hex(<<7::256>>)
      )

    other = %{ctx.envelope | "payload" => payload}
    {:ok, limited} = Resource.new(engine: ctx.engine, authorizer: ctx.authorizer, max_records: 1)
    test = self()

    hook = fn ->
      send(test, {:racing, Resource.run(limited, other, ctx.requirements, &flunk/0)})
    end

    signer = %HookSigner{address: ctx.authorizer.address, inner: ctx.authorizer, hook: hook}
    {:ok, resource} = Resource.new(engine: ctx.engine, authorizer: signer, max_records: 1)

    assert Resource.run(resource, ctx.envelope, ctx.requirements, fn -> flunk("full") end) ==
             {:error, :resource_capacity_exhausted}

    assert_received {:racing, {:pending, other_hash}}
    assert other_hash != ctx.payment_info_hash
    assert read_entry(ctx) == {:ok, nil}
    assert Agent.get(ctx.node, & &1.sends) == 1
  end

  test "a reverted funding transaction never runs the handler and is acknowledged", ctx do
    Agent.update(ctx.node, &%{&1 | receipt_mode: :reverted})

    assert Resource.run(ctx.resource, ctx.envelope, ctx.requirements, fn ->
             flunk("reverted hold")
           end) == {:error, :funding_reverted}

    assert {:ok, %{phase: :funding_failed, funding: %{status: :reverted}}} = read_entry(ctx)
    assert Journal.active(ctx.engine.journal) == {:ok, nil}
    assert Agent.get(ctx.node, & &1.sends) == 1

    assert Resource.resume(ctx.resource, ctx.payment_info_hash, fn -> flunk("again") end) ==
             {:error, :funding_reverted}

    assert Agent.get(ctx.node, & &1.sends) == 1
  end

  test "a funding transaction that cannot be built stays recoverable", ctx do
    Agent.update(ctx.node, &%{&1 | gas: "0xffffff"})

    assert Resource.run(ctx.resource, ctx.envelope, ctx.requirements, fn ->
             flunk("no hold yet")
           end) == {:error, :gas_limit_exceeded}

    assert {:ok, %{phase: :funding}} = read_entry(ctx)
    assert Agent.get(ctx.node, & &1.sends) == 0
    Agent.update(ctx.node, &%{&1 | gas: "0x10000"})

    assert {:ok, "paid", %{status: :settled, charged_amount: 1_000_000}} =
             Resource.resume(ctx.resource, ctx.payment_info_hash, fn ->
               {:ok, "paid", 1_000_000}
             end)

    assert Agent.get(ctx.node, & &1.sends) == 2
  end

  test "a reverted settlement withholds content and stays acknowledged", ctx do
    handler = fn ->
      Agent.update(ctx.node, &%{&1 | receipt_mode: :reverted})
      {:ok, "paid", 750_000}
    end

    assert Resource.run(ctx.resource, ctx.envelope, ctx.requirements, handler) ==
             {:error, :settlement_reverted}

    assert {:ok, %{phase: :settlement_failed, settlement: %{status: :reverted}}} =
             read_entry(ctx)

    assert Journal.active(ctx.engine.journal) == {:ok, nil}
    assert Agent.get(ctx.node, & &1.sends) == 2

    assert Resource.resume(ctx.resource, ctx.payment_info_hash) == {:error, :settlement_reverted}
    assert Agent.get(ctx.node, & &1.sends) == 2
  end

  test "a settlement transaction that cannot be built is retried by recovery", ctx do
    handler = fn ->
      Agent.update(ctx.node, &%{&1 | gas: "0xffffff"})
      {:ok, "paid", 750_000}
    end

    assert Resource.run(ctx.resource, ctx.envelope, ctx.requirements, handler) ==
             {:error, :gas_limit_exceeded}

    assert {:ok, %{phase: :capturing, charged: 750_000}} = read_entry(ctx)
    assert Agent.get(ctx.node, & &1.sends) == 1
    Agent.update(ctx.node, &%{&1 | gas: "0x10000"})

    assert {:ok, "paid", %{status: :settled, charged_amount: 750_000}} =
             Resource.resume(ctx.resource, ctx.payment_info_hash)

    assert Agent.get(ctx.node, & &1.sends) == 3
    assert Agent.get(ctx.node, & &1.payment_state) == <<1::256, 0::256, 750_000::256>>
  end
end
