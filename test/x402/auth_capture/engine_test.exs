defmodule X402.AuthCapture.EngineTest do
  use ExUnit.Case, async: true

  alias X402.AuthCapture
  alias X402.AuthCapture.Engine
  alias X402.AuthCapture.Journal
  alias X402.AuthCapture.Receipt
  alias X402.Signer.LocalKey
  alias X402.TestAuthCapture, as: Fixture
  alias X402.TestAuthCaptureNode, as: Node
  alias X402.Verify.AuthCaptureEVM, as: Verify

  setup do: Node.setup(__MODULE__)

  test "freeze, one-send and effect acknowledgement survive an exact retry", ctx do
    assert {:ok, result} = Engine.execute(ctx.engine, ctx.envelope, ctx.requirements)
    assert result.status == :confirmed
    assert result.operation == :authorize
    assert result.amount == 1_000_000
    assert_received {:persisted_before_send, :dispatched, true}
    assert Agent.get(ctx.node, & &1.sends) == 1
    assert {:ok, %{phase: :confirmed}} = Journal.active(ctx.engine.journal)
    assert Engine.execute(ctx.engine, ctx.envelope, ctx.requirements) == {:ok, result}
    assert {:ok, ^result} = Engine.acknowledge(ctx.engine, result.id)
    assert Journal.active(ctx.engine.journal) == {:ok, nil}
    assert Engine.acknowledge(ctx.engine, result.id) == {:ok, result}
    assert Engine.execute(ctx.engine, ctx.envelope, ctx.requirements) == {:ok, result}
    assert Agent.get(ctx.node, & &1.sends) == 1
  end

  test "pending reconciliation never rebroadcasts and does not reverify spent authorization",
       ctx do
    Agent.update(ctx.node, &%{&1 | receipt_mode: :pending})

    assert {:ok, %{status: :pending} = pending} =
             Engine.execute(ctx.engine, ctx.envelope, ctx.requirements)

    assert Engine.reconcile(ctx.engine) == {:ok, pending}

    Agent.update(
      ctx.node,
      &%{&1 | receipt_mode: :confirmed, payment_state: <<1::256, 1_000_000::256, 0::256>>}
    )

    assert {:ok, %{status: :confirmed, transaction: hash}} = Engine.reconcile(ctx.engine)
    assert hash == pending.transaction
    assert Agent.get(ctx.node, & &1.sends) == 1
  end

  test "canonical depth and event identity are required", ctx do
    Agent.update(ctx.node, &%{&1 | head: "0x10"})
    assert {:ok, %{status: :pending}} = Engine.execute(ctx.engine, ctx.envelope, ctx.requirements)
    Agent.update(ctx.node, &%{&1 | head: "0x11", canonical: false})
    assert {:ok, %{status: :pending}} = Engine.reconcile(ctx.engine)
    Agent.update(ctx.node, &%{&1 | canonical: true, receipt_mode: :wrong_transaction})
    assert Engine.reconcile(ctx.engine) == {:error, :invalid_receipt}
    assert {:ok, %{phase: :dispatched}} = Journal.active(ctx.engine.journal)
    Agent.update(ctx.node, &%{&1 | receipt_mode: :confirmed})
    assert {:ok, %{status: :confirmed}} = Engine.reconcile(ctx.engine)
    assert Agent.get(ctx.node, & &1.sends) == 1
  end

  test "confirmed reverts remain replay tombstones after acknowledgement", ctx do
    Agent.update(ctx.node, &%{&1 | receipt_mode: :reverted})

    assert {:ok, %{status: :reverted} = result} =
             Engine.execute(ctx.engine, ctx.envelope, ctx.requirements)

    assert Engine.acknowledge(ctx.engine, result.id) == {:ok, result}
    assert Engine.execute(ctx.engine, ctx.envelope, ctx.requirements) == {:ok, result}
    assert Agent.get(ctx.node, & &1.sends) == 1
  end

  test "wrong networks, clocks and gas policy fail before broadcast", ctx do
    assert Engine.execute(
             ctx.engine,
             ctx.envelope,
             Map.put(ctx.requirements, "network", "eip155:1")
           ) ==
             {:error, :network_mismatch}

    Agent.update(ctx.node, &%{&1 | chain_id: "0x1"})

    assert Engine.execute(ctx.engine, ctx.envelope, ctx.requirements) ==
             {:error, {:chain_id_mismatch, 8453, 1}}

    Agent.update(ctx.node, &%{&1 | chain_id: "0x2105", gas: "0xffffff"})

    assert Engine.execute(ctx.engine, ctx.envelope, ctx.requirements) ==
             {:error, :gas_limit_exceeded}

    assert Journal.active(ctx.engine.journal) == {:ok, nil}
    {:ok, invalid_clock} = Engine.new(Keyword.put(ctx.opts, :clock, fn -> :bad end))

    assert Engine.execute(invalid_clock, ctx.envelope, ctx.requirements) ==
             {:error, :invalid_clock}

    assert Engine.new(Keyword.put(ctx.opts, :max_fee_per_gas, 1)) == {:error, :invalid_gas_policy}
    assert Agent.get(ctx.node, & &1.sends) == 0
    assert Engine.acknowledge(ctx.engine, "missing") == {:error, :unknown_operation}
  end

  test "idle reconciliation needs no RPC and typed-data-only signers are refused", ctx do
    assert Engine.reconcile(ctx.engine) == {:ok, nil}
    refute_received {:auth_rpc, _, _}
    assert {:error, _} = Engine.new(Keyword.put(ctx.opts, :signer, nil))
    assert Engine.validate_signer(%URI{}) == {:error, "expected an EVM transaction signer"}
  end

  test "concurrent identical requests send at most once", ctx do
    results =
      1..32
      |> Task.async_stream(
        fn _ ->
          Engine.execute(ctx.engine, ctx.envelope, ctx.requirements)
        end,
        max_concurrency: 32
      )
      |> Enum.to_list()

    assert Enum.any?(results, &match?({:ok, {:ok, %{status: :confirmed}}}, &1))
    assert Agent.get(ctx.node, & &1.sends) == 1
    assert {:ok, %{phase: :confirmed}} = Journal.active(ctx.engine.journal)
  end

  for operation <- [:charge, :capture, :void, :refund] do
    @operation operation
    test "executes explicitly consented #{@operation}", ctx do
      operation = @operation
      {envelope, state} = lifecycle(ctx, operation)
      requirements = envelope["accepted"]

      {:ok, proof} =
        Verify.verify(envelope, requirements,
          now: Fixture.fixture()["now"],
          level: :signature,
          refund_funding: true
        )

      {:ok, event} = Receipt.expected_event(%{proof | level: :full, payment_state: state})

      Agent.update(
        ctx.node,
        &%{
          &1
          | event: event,
            payment_state: <<1::256, state.capturable_amount::256, state.refundable_amount::256>>
        }
      )

      test = self()

      callback = fn verified, request, req ->
        send(test, {:funding, verified.payment_info_hash, verified.amount, request, req})
        :ok
      end

      {:ok, engine} = Engine.new(Keyword.put(ctx.opts, :refund_authorize, callback))

      assert {:ok, result} = Engine.execute(engine, envelope, requirements)
      assert result.status == :confirmed
      assert result.operation == operation

      assert Agent.get(ctx.node, & &1.sends) == 1

      if result.operation == :refund do
        assert_received {:funding, _, 250_000, ^envelope, ^requirements}
      else
        refute_received {:funding, _, _, _, _}
      end
    end
  end

  test "refund funding is separate from a valid receiver consent", ctx do
    {envelope, _state} = lifecycle(ctx, :refund)

    assert Engine.execute(ctx.engine, envelope, envelope["accepted"]) ==
             {:error, :refund_funding_not_authorized}

    for callback <- [fn _, _, _ -> :denied end, fn _, _, _ -> raise "private reason" end] do
      {:ok, engine} = Engine.new(Keyword.put(ctx.opts, :refund_authorize, callback))

      assert Engine.execute(engine, envelope, envelope["accepted"]) ==
               {:error, :refund_funding_not_authorized}
    end

    assert Agent.get(ctx.node, & &1.sends) == 0
  end

  test "ERC-1271 refund consent reaches the funding policy without EOA recovery", ctx do
    {envelope, state} = lifecycle(ctx, :refund)
    envelope = put_in(envelope, ["payload", "authorizerSignature"], "0x1234")
    requirements = envelope["accepted"]
    authorizer = String.downcase(ctx.authorizer.address)

    Agent.update(ctx.node, fn node ->
      %{
        node
        | accounts: List.delete(node.accounts, authorizer),
          payment_state: <<1::256, state.capturable_amount::256, state.refundable_amount::256>>
      }
    end)

    test = self()

    callback = fn proof, request, req ->
      assert proof.level == :signature
      assert proof.operation == :refund
      assert request == envelope
      assert req == requirements
      send(test, :authorized_contract_refund)
      :ok
    end

    {:ok, engine} = Engine.new(Keyword.put(ctx.opts, :refund_authorize, callback))

    assert {:ok, %{status: :confirmed, amount: 250_000}} =
             Engine.execute(engine, envelope, requirements)

    assert_received :authorized_contract_refund

    assert_received {:auth_rpc, "eth_call",
                     [
                       %{"to" => ^authorizer, "data" => "0x1626ba7e" <> _},
                       %{"requireCanonical" => true}
                     ]}

    assert Agent.get(ctx.node, & &1.sends) == 1
  end

  test "terminal retries and acknowledgements do not depend on available RPC", ctx do
    assert {:ok, result} = Engine.execute(ctx.engine, ctx.envelope, ctx.requirements)
    drain_rpc()
    Agent.update(ctx.node, &%{&1 | chain_id: "0x1"})
    assert Engine.execute(ctx.engine, ctx.envelope, ctx.requirements) == {:ok, result}
    assert Engine.reconcile(ctx.engine) == {:ok, result}
    assert Engine.acknowledge(ctx.engine, result.id) == {:ok, result}
    assert Engine.execute(ctx.engine, ctx.envelope, ctx.requirements) == {:ok, result}
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

  @spec lifecycle(map(), atom()) :: {map(), map()}
  defp lifecycle(ctx, operation) do
    {:ok, authorizer} = LocalKey.new(<<2::256>>)

    {:ok, proof} =
      Verify.verify(ctx.envelope, ctx.requirements,
        now: Fixture.fixture()["now"],
        level: :signature
      )

    opts = [authorizer: authorizer, salt_nonce: ctx.envelope["payload"]["saltNonce"]]

    state =
      case operation do
        :refund -> %{collected?: true, capturable_amount: 250_000, refundable_amount: 750_000}
        _operation -> %{collected?: true, capturable_amount: 1_000_000, refundable_amount: 0}
      end

    {:ok, envelope} =
      case operation do
        :charge ->
          requirements =
            ctx.requirements
            |> put_in(["extra", "paymentFlow"], "authorization")
            |> update_in(["extra"], &Map.delete(&1, "captureMode"))

          AuthCapture.complete_charge(%{ctx.envelope | "accepted" => requirements},
            authorizer: authorizer,
            amount: 750_000
          )

        :capture ->
          AuthCapture.capture_payload(
            ctx.requirements,
            proof.payment_info,
            opts ++
              [
                amount: 750_000,
                expected_capturable_amount: 1_000_000,
                expected_refundable_amount: 0
              ]
          )

        :void ->
          AuthCapture.void_payload(ctx.requirements, proof.payment_info, opts)

        :refund ->
          AuthCapture.refund_payload(
            ctx.requirements,
            proof.payment_info,
            opts ++
              [
                amount: 250_000,
                expected_capturable_amount: 250_000,
                expected_refundable_amount: 750_000
              ]
          )
      end

    {envelope, state}
  end
end
