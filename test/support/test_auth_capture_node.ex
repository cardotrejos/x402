defmodule X402.TestAuthCaptureNode do
  @moduledoc false

  import ExUnit.Callbacks, only: [start_supervised!: 1]

  alias X402.AuthCapture.Engine
  alias X402.AuthCapture.ETSStore
  alias X402.AuthCapture.Journal
  alias X402.AuthCapture.Receipt
  alias X402.RPC
  alias X402.Scheme.AuthCaptureEVM, as: Scheme
  alias X402.Signer.LocalKey
  alias X402.TestAuthCapture, as: Fixture
  alias X402.Verify.AuthCaptureEVM, as: Verify

  @block "0x" <> String.duplicate("ab", 32)

  @spec setup(atom(), :sync | :deferred) :: map()
  def setup(name, mode \\ :sync) do
    start_supervised!({Finch, name: name})
    bypass = Bypass.open()
    {:ok, payer} = LocalKey.new(<<1::256>>)
    {:ok, operator} = LocalKey.new(<<3::256>>)
    {:ok, authorizer} = LocalKey.new(<<2::256>>)
    vector = Fixture.vector()
    now = Fixture.fixture()["now"]

    requirements =
      vector["requirements"]
      |> put_in(["extra", "captureAuthorizer"], operator.address)
      |> put_in(["extra", "captureMode"], Atom.to_string(mode))

    {:ok, payload} = Scheme.sign(requirements, payer, now: now, salt_nonce: vector["salt_nonce"])
    envelope = %{"x402Version" => 2, "accepted" => requirements, "payload" => payload}
    {:ok, proof} = Verify.verify(envelope, requirements, now: now, level: :signature)
    {:ok, event} = Receipt.expected_event(%{proof | level: :full})

    node =
      start_supervised!(
        {__MODULE__,
         %{
           owner: self(),
           accounts: [payer.address, operator.address, authorizer.address],
           from: operator.address,
           to: proof.target,
           event: event
         }}
      )

    Bypass.stub(bypass, "POST", "/", &handle(&1, node))
    {:ok, rpc} = RPC.new(rpc_url: "http://localhost:#{bypass.port}", finch: name)
    store = start_supervised!(ETSStore)

    opts = [
      rpc: rpc,
      signer: operator,
      network: requirements["network"],
      store: {ETSStore, store},
      max_fee_per_gas: 3_000_000_000,
      max_priority_fee_per_gas: 1_000_000_000,
      clock: fn -> now end
    ]

    {:ok, engine} = Engine.new(opts)
    Agent.update(node, &%{&1 | journal: engine.journal})

    %{
      engine: engine,
      opts: opts,
      envelope: envelope,
      requirements: requirements,
      node: node,
      authorizer: authorizer,
      payment_info_hash: proof.payment_info_hash
    }
  end

  @spec start_link(map()) :: Agent.on_start()
  def start_link(opts) do
    Agent.start_link(fn ->
      Map.merge(
        %{
          chain_id: "0x2105",
          head: "0x11",
          gas: "0x10000",
          receipt_mode: :confirmed,
          canonical: true,
          sends: 0,
          transaction: nil,
          advance_state: false,
          payment_state: <<0::256, 0::256, 0::256>>,
          journal: nil
        },
        opts
      )
    end)
  end

  @spec child_spec(map()) :: Supervisor.child_spec()
  def child_spec(opts), do: %{id: __MODULE__, start: {__MODULE__, :start_link, [opts]}}

  @spec handle(Plug.Conn.t(), pid()) :: Plug.Conn.t()
  def handle(conn, server) do
    {:ok, body, conn} = Plug.Conn.read_body(conn)
    request = Jason.decode!(body)
    method = request["method"]
    params = request["params"]
    state = Agent.get(server, & &1)
    send(state.owner, {:auth_rpc, method, params})
    response = response(server, method, params, state)

    Plug.Conn.resp(
      conn,
      200,
      Jason.encode!(Map.merge(response, %{"jsonrpc" => "2.0", "id" => request["id"]}))
    )
  end

  @spec response(pid(), String.t(), list(), map()) :: map()
  defp response(server, "eth_sendRawTransaction", [raw], state) do
    {:ok, entry} = Journal.active(state.journal)

    send(
      state.owner,
      {:persisted_before_send, entry.phase, entry.transaction.raw == Fixture.bytes(raw)}
    )

    hash = Fixture.hex(ExKeccak.hash_256(Fixture.bytes(raw)))

    Agent.update(server, fn current ->
      current = %{
        current
        | sends: current.sends + 1,
          transaction: hash,
          event: entry.intent.event
      }

      if current.advance_state, do: apply_operation(current, entry.intent.proof), else: current
    end)

    %{"result" => hash}
  end

  defp response(_server, "eth_chainId", _, state), do: %{"result" => state.chain_id}
  defp response(_server, "eth_blockNumber", _, state), do: %{"result" => state.head}
  defp response(_server, "eth_estimateGas", _, state), do: %{"result" => state.gas}

  defp response(_server, "eth_getTransactionCount", _, state),
    do: %{"result" => "0x" <> Integer.to_string(state.sends, 16)}

  defp response(_server, "eth_getBlockByNumber", [tag, _], state) do
    hash = if tag == "latest" or state.canonical, do: @block, else: Fixture.hex(<<0::256>>)
    %{"result" => %{"hash" => hash, "number" => "0x10"}}
  end

  defp response(_server, "eth_getCode", [address, _], state) do
    %{"result" => if(String.downcase(address) in state.accounts, do: "0x", else: "0x6000")}
  end

  defp response(_server, "eth_call", [%{"data" => "0x70a08231" <> _} | _], _state),
    do: %{"result" => Fixture.hex(<<1_000_000::256>>)}

  defp response(_server, "eth_call", [%{"data" => "0x34b778ed" <> _} | _], state),
    do: %{"result" => Fixture.hex(state.payment_state)}

  defp response(_server, "eth_call", [%{"data" => "0x1626ba7e" <> _} | _], _state),
    do: %{"result" => "0x1626ba7e" <> String.duplicate("00", 28)}

  defp response(_server, "eth_call", _, _state), do: %{"result" => "0x"}

  defp response(_server, "eth_getTransactionReceipt", [hash], state),
    do: %{"result" => receipt(hash, state)}

  @spec apply_operation(map(), map()) :: map()
  defp apply_operation(state, proof) do
    <<_collected::256, capturable::256, refundable::256>> = state.payment_state

    amounts =
      case proof.operation do
        :authorize -> {proof.amount, 0}
        :capture -> {capturable - proof.amount, refundable + proof.amount}
        :charge -> {0, proof.amount}
        :void -> {0, refundable}
        :refund -> {capturable, refundable - proof.amount}
      end

    {capturable, refundable} = amounts
    %{state | payment_state: <<1::256, capturable::256, refundable::256>>}
  end

  @spec receipt(String.t(), map()) :: map() | nil
  defp receipt(_hash, %{receipt_mode: :pending}), do: nil

  defp receipt(hash, state) do
    event = state.event
    hash = if state.receipt_mode == :wrong_transaction, do: @block, else: hash

    log = %{
      "address" => event.address,
      "topics" => event.topics,
      "data" => event.data,
      "transactionHash" => hash,
      "blockHash" => @block,
      "blockNumber" => "0x10",
      "transactionIndex" => "0x0",
      "logIndex" => "0x0",
      "removed" => false
    }

    %{
      "transactionHash" => hash,
      "from" => state.from,
      "to" => state.to,
      "blockHash" => @block,
      "blockNumber" => "0x10",
      "transactionIndex" => "0x0",
      "status" => if(state.receipt_mode == :reverted, do: "0x0", else: "0x1"),
      "logs" => if(state.receipt_mode == :reverted, do: [], else: [log])
    }
  end
end
