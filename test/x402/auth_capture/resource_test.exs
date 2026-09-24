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
end
