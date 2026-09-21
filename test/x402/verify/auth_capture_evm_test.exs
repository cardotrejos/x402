defmodule X402.Verify.AuthCaptureEVMTest do
  use ExUnit.Case, async: true

  doctest X402.Verify.AuthCaptureEVM

  alias X402.ERC6492
  alias X402.RPC
  alias X402.TestAuthCapture, as: Fixture
  alias X402.Verify.AuthCaptureEVM, as: Verify

  @block_hash "0x" <> String.duplicate("ab", 32)

  setup do
    start_supervised!({Finch, name: __MODULE__})
    %{bypass: Bypass.open()}
  end

  test "full verification requires an RPC and malformed payloads fail closed" do
    assert {:error, :rpc_not_configured} = Verify.verify(%{}, %{})
    assert {:error, {:invalid, _reason}} = Verify.verify(%{}, %{}, level: :structural)
    assert {:error, {:invalid, _reason}} = Verify.validate_shape(%{}, %{})
  end

  test "invalid verification levels never downgrade" do
    assert {:error, {:invalid_options, _message}} = Verify.verify(%{}, %{}, level: :unsupported)
  end

  test "full verification pins every state read and simulation to one block", context do
    rpc = stub_rpc(context)
    vector = Fixture.vector()

    assert {:ok, result} =
             Verify.verify(Fixture.envelope(vector), vector["requirements"], full_opts(rpc))

    assert result.signature_type == :eoa
    assert_received {:rpc, "eth_chainId", []}
    assert_received {:rpc, "eth_getBlockByNumber", ["latest", false]}

    assert_received {:rpc, "eth_getCode",
                     [_, %{"blockHash" => @block_hash, "requireCanonical" => true}]}

    assert_received {:rpc, "eth_call",
                     [_, %{"blockHash" => @block_hash, "requireCanonical" => true}]}

    refute_received {:rpc, "eth_call", [_, "latest"]}
  end

  test "wrong chain is rejected before any account or signature RPC", context do
    rpc = stub_rpc(context, chain_id: "0x1", code: "0x6000")
    payload = Fixture.lifecycle(Fixture.vector(), "capture")
    payload = put_in(payload, ["payload", "authorizerSignature"], "0x1234")

    assert Verify.verify(payload, payload["accepted"], full_opts(rpc)) ==
             {:error, {:chain_id_mismatch, 8453, 1}}

    refute_received {:rpc, "eth_getCode", _}
    refute_received {:rpc, "eth_call", _}
  end

  test "deployed payer always requires ERC1271 even for a matching ECDSA signature", context do
    rpc = stub_rpc(context, code: "0x00", magic: "0xffffffff" <> String.duplicate("00", 28))
    vector = Fixture.vector()

    assert Verify.verify(Fixture.envelope(vector), vector["requirements"], full_opts(rpc)) ==
             {:error, {:invalid, :signature}}

    assert_received {:rpc, "eth_call", [%{"data" => "0x1626ba7e" <> _}, _]}
  end

  test "deployed receiver authorizer cannot bypass ERC1271 through ECDSA recovery", context do
    rpc = stub_rpc(context, code: "0x00", magic: "0xffffffff" <> String.duplicate("00", 28))
    payload = Fixture.lifecycle(Fixture.vector(), "capture")

    assert Verify.verify(payload, payload["accepted"], full_opts(rpc)) ==
             {:error, {:invalid, :authorizer_signature}}
  end

  for magic <- [
        "0x1626ba7e",
        "0x1626ba7e" <> String.duplicate("00", 29),
        "0x1626ba7e" <> String.duplicate("00", 27) <> "01"
      ] do
    @magic magic
    test "ERC1271 rejects noncanonical response #{magic}", context do
      rpc = stub_rpc(context, code: "0x6000", magic: @magic)
      vector = Fixture.vector()
      envelope = put_in(Fixture.envelope(vector), ["payload", "signature"], "0x1234")

      assert Verify.verify(envelope, vector["requirements"], full_opts(rpc)) ==
               {:error, {:invalid, :signature}}
    end
  end

  test "malformed code is an RPC error, never an EOA classification", context do
    rpc = stub_rpc(context, code: "0x0")
    vector = Fixture.vector()

    assert {:error, {:rpc_error, {:invalid_response, "0x0"}}} =
             Verify.verify(Fixture.envelope(vector), vector["requirements"], full_opts(rpc))
  end

  test "counterfactual verification requires simulation and preserves the wrapper", context do
    vector = Fixture.vector("v1_1_bound_permit2")
    factory = "0x7777777777777777777777777777777777777777"
    {:ok, wrapped} = ERC6492.wrap(factory, <<1, 2>>, <<3, 4>>)
    envelope = put_in(Fixture.envelope(vector), ["payload", "signature"], Fixture.hex(wrapped))
    rpc = stub_rpc(context)
    opts = full_opts(rpc) ++ [simulate: false, eip6492_allowed_factories: [factory]]

    assert {:ok, result} = Verify.verify(envelope, vector["requirements"], opts)
    assert result.signature_type == :erc6492_counterfactual
    assert :binary.match(result.calldata, wrapped) != :nomatch
    assert_received {:rpc, "eth_call", [%{"from" => _, "data" => _}, _]}
  end

  test "counterfactual wrapper without preparation target fails closed" do
    vector = Fixture.vector()
    {:ok, wrapped} = ERC6492.wrap("0x" <> String.duplicate("00", 20), <<>>, <<1>>)
    envelope = put_in(Fixture.envelope(vector), ["payload", "signature"], Fixture.hex(wrapped))

    assert Verify.verify(envelope, vector["requirements"],
             level: :signature,
             now: Fixture.fixture()["now"]
           ) ==
             {:error, {:invalid, :erc6492_factory_not_allowed}}
  end

  test "authorization selection rejects an explicitly present null alternative" do
    vector = Fixture.vector()

    for key <- ["permit2Authorization", :permit2Authorization] do
      envelope = update_in(Fixture.envelope(vector), ["payload"], &Map.put(&1, key, nil))

      assert Verify.verify(envelope, vector["requirements"],
               level: :structural,
               now: Fixture.fixture()["now"]
             ) ==
               {:error, {:invalid, :payload_format}}
    end
  end

  test "lifecycle shape guard accepts signed capture and rejects mixed fee fields" do
    payload = Fixture.lifecycle(Fixture.vector(), "capture")
    assert Verify.validate_shape(payload, payload["accepted"]) == :ok
    mixed = put_in(payload, ["payload", "feeBps"], "100")

    assert Verify.validate_shape(mixed, payload["accepted"]) ==
             {:error, {:invalid, :payload_format}}
  end

  test "completed charge matches independent consent for both methods and deployments" do
    for id <- [
          "v1_1_bound_eip3009",
          "v1_0_bound_eip3009",
          "v1_1_bound_permit2",
          "v1_0_bound_permit2"
        ] do
      vector = Fixture.vector(id)
      payload = Fixture.charge(vector)

      assert {:ok, verified} =
               Verify.verify(payload, payload["accepted"],
                 level: :signature,
                 now: Fixture.fixture()["now"],
                 settlement: true
               )

      assert Fixture.hex(verified.calldata) == vector["calldata"]["charge"]
    end
  end

  test "collect-only routes must explicitly defer lifecycle" do
    vector = Fixture.vector("v1_1_unbound_eip3009")
    requirements = update_in(vector["requirements"], ["extra"], &Map.delete(&1, "captureMode"))

    assert Verify.verify(
             Fixture.envelope(%{vector | "requirements" => requirements}),
             requirements,
             level: :structural,
             now: Fixture.fixture()["now"]
           ) ==
             {:error, {:invalid, :extra}}
  end

  test "a missing deployment cannot prove a counterfactual signature", context do
    vector = Fixture.vector()
    factory = "0x7777777777777777777777777777777777777777"
    {:ok, wrapped} = ERC6492.wrap(factory, <<1>>, <<2, 3>>)
    envelope = put_in(Fixture.envelope(vector), ["payload", "signature"], Fixture.hex(wrapped))
    rpc = stub_rpc(context, contract_code: "0x")

    assert Verify.verify(
             envelope,
             vector["requirements"],
             full_opts(rpc) ++ [eip6492_allowed_factories: [factory]]
           ) ==
             {:error, {:invalid, :simulation_failed}}

    refute_received {:rpc, "eth_call", [%{"from" => _}, _]}
  end

  test "shape requires all fields and a zero EIP3009 validAfter" do
    vector = Fixture.vector()

    for key <- ["from", "to", "value", "validAfter", "validBefore", "nonce"] do
      envelope =
        update_in(Fixture.envelope(vector), ["payload", "authorization"], &Map.delete(&1, key))

      assert Verify.validate_shape(envelope, vector["requirements"]) ==
               {:error, {:invalid, :payload_format}}
    end

    nonzero = put_in(Fixture.envelope(vector), ["payload", "authorization", "validAfter"], "1")

    assert Verify.validate_shape(nonzero, vector["requirements"]) ==
             {:error, {:invalid, :payload_format}}

    permit = Fixture.vector("v1_1_bound_permit2")

    for key <- ["from", "spender", "permitted", "nonce", "deadline"] do
      envelope =
        update_in(
          Fixture.envelope(permit),
          ["payload", "permit2Authorization"],
          &Map.delete(&1, key)
        )

      assert Verify.validate_shape(envelope, permit["requirements"]) ==
               {:error, {:invalid, :payload_format}}
    end
  end

  test "capture-and-void uses one stateful simulation and one authorizer lookup", context do
    vector = Fixture.vector()

    envelope =
      put_in(
        Fixture.lifecycle(vector, "capture"),
        ["payload", "voidAuthorizerSignature"],
        vector["consents"]["void"]["signature"]
      )

    rpc = stub_rpc(context)
    assert {:ok, _result} = Verify.verify(envelope, envelope["accepted"], full_opts(rpc))
    authorizer = Fixture.fixture()["authorizer"]
    assert_received {:rpc, "eth_getCode", [^authorizer, _]}
    refute_received {:rpc, "eth_getCode", [^authorizer, _]}
    assert_received {:rpc, "eth_simulateV1", [simulation, block]}
    assert block == @block_hash
    assert [%{"calls" => [capture, void]}] = simulation["blockStateCalls"]
    assert capture["data"] == vector["calldata"]["capture"]
    assert void["data"] == vector["calldata"]["void"]
    refute_received {:rpc, "eth_call", [%{"from" => _}, _]}
  end

  test "failed or malformed second simulation leg never falls back to independent calls",
       context do
    vector = Fixture.vector()

    envelope =
      put_in(
        Fixture.lifecycle(vector, "capture"),
        ["payload", "voidAuthorizerSignature"],
        vector["consents"]["void"]["signature"]
      )

    for result <- [nil, [], [%{"calls" => [%{"status" => "0x1"}, %{"status" => "0x0"}]}]] do
      rpc = stub_rpc(context, simulation: result)

      assert Verify.verify(envelope, envelope["accepted"], full_opts(rpc)) ==
               {:error, {:invalid, :simulation_failed}}

      refute_received {:rpc, "eth_call", [%{"from" => _}, _]}
    end
  end

  test "direct callers cannot bypass bounded decimal and signature inputs" do
    vector = Fixture.vector()

    for value <- [" " <> "1000000", "+1000000", String.duplicate("9", 100_000)] do
      envelope = put_in(Fixture.envelope(vector), ["payload", "authorization", "value"], value)

      assert Verify.validate_shape(envelope, vector["requirements"]) ==
               {:error, {:invalid, :payload_format}}
    end

    large =
      put_in(
        Fixture.envelope(vector),
        ["payload", "signature"],
        "0x" <> String.duplicate("01", 65_537)
      )

    assert Verify.validate_shape(large, vector["requirements"]) ==
             {:error, {:invalid, :payload_format}}
  end

  test "stateful simulation requires the pinned parent and RPC capability", context do
    vector = Fixture.vector()

    envelope =
      put_in(
        Fixture.lifecycle(vector, "capture"),
        ["payload", "voidAuthorizerSignature"],
        vector["consents"]["void"]["signature"]
      )

    wrong_parent = [
      %{
        "parentHash" => "0x" <> String.duplicate("cd", 32),
        "calls" => [
          %{"status" => "0x1", "returnData" => "0x"},
          %{"status" => "0x1", "returnData" => "0x"}
        ]
      }
    ]

    rpc = stub_rpc(context, simulation: wrong_parent)

    assert Verify.verify(envelope, envelope["accepted"], full_opts(rpc)) ==
             {:error, {:invalid, :simulation_failed}}

    rpc = stub_rpc(context, fail_method: "eth_simulateV1")

    assert Verify.verify(envelope, envelope["accepted"], full_opts(rpc)) ==
             {:error, {:invalid, :simulation_failed}}

    refute_received {:rpc, "eth_call", [%{"from" => _}, _]}
  end

  test "custom full verification is refused without outcome assertions", context do
    vector = Fixture.vector()

    requirements =
      vector["requirements"]
      |> put_in(["extra", "operatorType"], "custom")
      |> put_in(["extra", "captureMode"], "deferred")

    vector = %{vector | "requirements" => requirements}
    rpc = stub_rpc(context)

    opts =
      full_opts(rpc) ++
        [
          operators: [
            %{address: requirements["extra"]["captureAuthorizer"], operator_type: :custom}
          ]
        ]

    assert Verify.verify(Fixture.envelope(vector), requirements, opts) ==
             {:error, {:invalid, :unsupported_operator_type}}

    refute_received {:rpc, "eth_call", [%{"from" => _}, _]}
  end

  @spec full_opts(RPC.t()) :: keyword()
  defp full_opts(rpc), do: [rpc: rpc, now: Fixture.fixture()["now"]]

  @spec stub_rpc(map(), keyword()) :: RPC.t()
  defp stub_rpc(context, overrides \\ []) do
    config = Map.new(overrides)
    test = self()

    Bypass.stub(context.bypass, "POST", "/", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      %{"method" => method, "params" => params, "id" => id} = Jason.decode!(body)
      send(test, {:rpc, method, params})

      response =
        if Map.get(config, :fail_method) == method do
          %{"error" => %{"code" => -32_601, "message" => "method not supported"}}
        else
          %{"result" => node_result(method, params, config)}
        end

      Plug.Conn.resp(
        conn,
        200,
        Jason.encode!(Map.merge(response, %{"jsonrpc" => "2.0", "id" => id}))
      )
    end)

    {:ok, rpc} = RPC.new(rpc_url: "http://localhost:#{context.bypass.port}", finch: __MODULE__)
    rpc
  end

  @spec node_result(String.t(), list(), map()) :: term()
  defp node_result("eth_chainId", [], config), do: Map.get(config, :chain_id, "0x2105")

  defp node_result("eth_getBlockByNumber", _, _config),
    do: %{"hash" => @block_hash, "number" => "0x10"}

  defp node_result("eth_getCode", [address, _], config) do
    if address in [Fixture.fixture()["payer"], Fixture.fixture()["authorizer"]] do
      Map.get(config, :code, "0x")
    else
      Map.get(config, :contract_code, "0x6000")
    end
  end

  defp node_result("eth_simulateV1", _, config),
    do:
      Map.get(config, :simulation, [
        %{
          "parentHash" => @block_hash,
          "calls" => [
            %{"status" => "0x1", "returnData" => "0x"},
            %{"status" => "0x1", "returnData" => "0x"}
          ]
        }
      ])

  defp node_result("eth_call", [%{"data" => "0x1626ba7e" <> _} | _], config),
    do: Map.get(config, :magic, "0x1626ba7e" <> String.duplicate("00", 28))

  defp node_result("eth_call", [%{"data" => "0x70a08231" <> _} | _], _config),
    do: Fixture.hex(<<1_000_000::256>>)

  defp node_result("eth_call", [%{"data" => "0x34b778ed" <> _} | _], _config),
    do: Fixture.hex(<<1::256, 1_000_000::256, 0::256>>)

  defp node_result("eth_call", _, _config), do: "0x"
end
