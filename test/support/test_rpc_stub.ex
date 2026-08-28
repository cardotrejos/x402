defmodule X402.TestRPCStub do
  @moduledoc false

  # Scripted JSON-RPC node backed by Bypass, shared by the facilitator engine
  # and Plug scaffold tests. Every request is echoed to the test process as
  # `{:rpc, method, params}` so tests can assert exactly which calls were
  # (not) made. Behaviour is driven by a config map — see `defaults/0`.

  alias X402.RPC

  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @payer "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
  @pay_to "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"

  # keccak256("Transfer(address,address,uint256)")
  @transfer_topic "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

  def defaults do
    %{
      chain_id: 84_532,
      code: %{String.downcase(@asset) => "0x6001"},
      balance: 1_000_000,
      simulate: :ok,
      multicall: [{true, <<>>}, {true, <<>>}],
      estimate_gas: {:ok, 60_000},
      max_priority_fee: {:ok, 1_000_000},
      fee_history: {:ok, [100, 120]},
      gas_price: 2_000_000,
      nonce: 5,
      send_raw: {:ok, "0x" <> String.duplicate("cd", 32)},
      receipts: [%{"status" => "0x1"}],
      asset: @asset,
      payer: @payer,
      pay_to: @pay_to,
      value: 10_000
    }
  end

  # The matching ERC-20 Transfer log for the stub's configured payment —
  # override asset/payer/pay_to/value to script a mismatching log.
  def transfer_log(overrides \\ %{}) do
    defaults()
    |> Map.merge(Map.new(overrides))
    |> transfer_log_from()
  end

  def stub_rpc(bypass, finch, overrides \\ %{}) do
    config = Map.merge(defaults(), Map.new(overrides))
    config = Map.put_new_lazy(config, :receipt_queue, fn -> start_queue(config.receipts) end)
    {:ok, code_agent} = Agent.start_link(fn -> config.code end)
    config = Map.put(config, :code_agent, code_agent)
    test_pid = self()

    Bypass.stub(bypass, "POST", "/", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      respond(conn, Jason.decode!(body), config, test_pid)
    end)

    {:ok, rpc} = RPC.new(rpc_url: "http://localhost:#{bypass.port}", finch: finch)
    rpc
  end

  # Pass your own agent as :receipt_queue to feed receipts mid-test.
  def start_queue(receipts) do
    {:ok, receipt_queue} = Agent.start_link(fn -> receipts end)
    receipt_queue
  end

  # send_raw: :http_error simulates a transport-level broadcast failure
  # (the node may or may not have accepted the transaction).
  defp respond(
         conn,
         %{"method" => "eth_sendRawTransaction"} = request,
         %{send_raw: :http_error},
         test_pid
       ) do
    send(test_pid, {:rpc, "eth_sendRawTransaction", request["params"]})
    Plug.Conn.resp(conn, 500, "boom")
  end

  defp respond(conn, decoded, config, test_pid) do
    response =
      case decoded do
        requests when is_list(requests) -> Enum.map(requests, &handle_rpc(&1, config, test_pid))
        request -> handle_rpc(request, config, test_pid)
      end

    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.resp(200, Jason.encode!(response))
  end

  defp handle_rpc(%{"id" => id, "method" => method, "params" => params}, config, test_pid) do
    send(test_pid, {:rpc, method, params})

    case rpc_result(method, params, config) do
      {:ok, result} -> %{"jsonrpc" => "2.0", "id" => id, "result" => result}
      {:error, error} -> %{"jsonrpc" => "2.0", "id" => id, "error" => error}
    end
  end

  defp rpc_result("eth_chainId", [], config),
    do: {:ok, "0x" <> Integer.to_string(config.chain_id, 16)}

  # A per-address list serves one entry per call (the last entry sticks) so
  # tests can script code appearing between verification and settlement.
  defp rpc_result("eth_getCode", [address, _block], config) do
    key = String.downcase(address)

    code =
      Agent.get_and_update(config.code_agent, fn codes ->
        case Map.get(codes, key, "0x") do
          [code] -> {code, codes}
          [code | rest] -> {code, Map.put(codes, key, rest)}
          code -> {code, codes}
        end
      end)

    {:ok, code}
  end

  defp rpc_result("eth_call", [%{"data" => "0x" <> data_hex} | _rest], config),
    do: dispatch_call(Base.decode16!(data_hex, case: :mixed), config)

  defp rpc_result("eth_estimateGas", [_call], config) do
    case config.estimate_gas do
      {:ok, gas} -> {:ok, quantity_hex(gas)}
      {:error, error} -> {:error, error}
    end
  end

  defp rpc_result("eth_maxPriorityFeePerGas", [], config) do
    case config.max_priority_fee do
      {:ok, fee} -> {:ok, quantity_hex(fee)}
      :error -> {:error, %{"code" => -32_601, "message" => "method not found"}}
    end
  end

  defp rpc_result("eth_feeHistory", [_blocks, _newest, _percentiles], config) do
    case config.fee_history do
      {:ok, base_fees} -> {:ok, %{"baseFeePerGas" => Enum.map(base_fees, &quantity_hex/1)}}
      :error -> {:error, %{"code" => -32_601, "message" => "method not found"}}
    end
  end

  defp rpc_result("eth_gasPrice", [], config), do: {:ok, quantity_hex(config.gas_price)}

  defp rpc_result("eth_getTransactionCount", [_address, "pending"], config),
    do: {:ok, quantity_hex(config.nonce)}

  defp rpc_result("eth_sendRawTransaction", [_raw], config), do: config.send_raw

  defp rpc_result("eth_getTransactionReceipt", [_hash], config) do
    receipt =
      Agent.get_and_update(config.receipt_queue, fn
        [] -> {nil, []}
        [head | tail] -> {head, tail}
      end)

    {:ok, decorate_receipt(receipt, config)}
  end

  # A confirmed receipt without explicit logs gains the matching Transfer
  # log derived from the stub config, mirroring a real node; script "logs"
  # explicitly for mismatch/absent/malformed scenarios.
  defp decorate_receipt(%{"status" => "0x1"} = receipt, config)
       when not is_map_key(receipt, "logs"),
       do: Map.put(receipt, "logs", [transfer_log_from(config)])

  defp decorate_receipt(receipt, _config), do: receipt

  defp transfer_log_from(config) do
    %{
      "address" => config.asset,
      "topics" => [
        @transfer_topic,
        address_topic(config.payer),
        address_topic(config.pay_to)
      ],
      "data" => quantity_word(config.value)
    }
  end

  defp address_topic("0x" <> hex_address),
    do: "0x" <> String.duplicate("0", 24) <> String.downcase(hex_address)

  # balanceOf(address)
  defp dispatch_call(<<0x70, 0xA0, 0x82, 0x31, _rest::binary>>, config),
    do: {:ok, quantity_word(config.balance)}

  # transferWithAuthorization — (v,r,s) and bytes variants
  defp dispatch_call(<<0xE3, 0xEE, 0x16, 0x0E, _rest::binary>>, config),
    do: simulate_result(config)

  defp dispatch_call(<<0xCF, 0x09, 0x29, 0x95, _rest::binary>>, config),
    do: simulate_result(config)

  # aggregate3((address,bool,bytes)[]) — the atomic ERC-6492 counterfactual
  # deploy-and-transfer simulation.
  defp dispatch_call(<<0x82, 0xAD, 0x56, 0xCB, _rest::binary>>, config),
    do: {:ok, aggregate3_hex(config.multicall)}

  # Diagnosis probes after a failed simulation: authorizationState (unused),
  # name(), version().
  defp dispatch_call(<<0xE9, 0x4A, 0x01, 0x02, _rest::binary>>, _config),
    do: {:ok, quantity_word(0)}

  defp dispatch_call(<<0x06, 0xFD, 0xDE, 0x03>>, _config), do: {:ok, string_word("USDC")}
  defp dispatch_call(<<0x54, 0xFD, 0x4D, 0x50>>, _config), do: {:ok, string_word("2")}

  defp simulate_result(%{simulate: :ok}), do: {:ok, "0x"}

  defp simulate_result(%{simulate: {:revert, message}}),
    do: {:error, %{"code" => 3, "message" => "execution reverted: #{message}"}}

  defp quantity_hex(value), do: "0x" <> Integer.to_string(value, 16)

  defp quantity_word(value),
    do: "0x" <> Base.encode16(<<value::unsigned-big-integer-size(256)>>, case: :lower)

  defp string_word(string) do
    padded = string <> :binary.copy(<<0>>, rem(32 - rem(byte_size(string), 32), 32))

    "0x" <>
      Base.encode16(
        <<32::unsigned-big-integer-size(256), byte_size(string)::unsigned-big-integer-size(256)>> <>
          padded,
        case: :lower
      )
  end

  defp aggregate3_hex(results) do
    tuples =
      Enum.map(results, fn {success, data} ->
        flag = if success, do: 1, else: 0
        padded = data <> :binary.copy(<<0>>, rem(32 - rem(byte_size(data), 32), 32))

        <<flag::unsigned-big-integer-size(256), 64::unsigned-big-integer-size(256),
          byte_size(data)::unsigned-big-integer-size(256)>> <> padded
      end)

    {offsets, _end} =
      Enum.map_reduce(tuples, 32 * length(tuples), fn tuple, position ->
        {position, position + byte_size(tuple)}
      end)

    array =
      <<length(tuples)::unsigned-big-integer-size(256)>> <>
        Enum.map_join(offsets, &<<&1::unsigned-big-integer-size(256)>>) <> Enum.join(tuples)

    "0x" <> Base.encode16(<<32::unsigned-big-integer-size(256)>> <> array, case: :lower)
  end
end
