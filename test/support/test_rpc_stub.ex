defmodule X402.TestRPCStub do
  @moduledoc false

  # Scripted JSON-RPC node backed by Bypass, shared by the facilitator engine
  # and Plug scaffold tests. Every request is echoed to the test process as
  # `{:rpc, method, params}` so tests can assert exactly which calls were
  # (not) made. Behaviour is driven by a config map — see `defaults/0`.

  alias X402.RPC

  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

  def defaults do
    %{
      chain_id: 84_532,
      code: %{String.downcase(@asset) => "0x6001"},
      balance: 1_000_000,
      simulate: :ok,
      estimate_gas: {:ok, 60_000},
      max_priority_fee: {:ok, 1_000_000},
      fee_history: {:ok, [100, 120]},
      gas_price: 2_000_000,
      nonce: 5,
      send_raw: {:ok, "0x" <> String.duplicate("cd", 32)},
      receipts: [%{"status" => "0x1"}]
    }
  end

  def stub_rpc(bypass, finch, overrides \\ %{}) do
    config = Map.merge(defaults(), Map.new(overrides))
    {:ok, receipt_queue} = Agent.start_link(fn -> config.receipts end)
    config = Map.put(config, :receipt_queue, receipt_queue)
    test_pid = self()

    Bypass.stub(bypass, "POST", "/", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)

      response =
        case Jason.decode!(body) do
          requests when is_list(requests) -> Enum.map(requests, &handle_rpc(&1, config, test_pid))
          request -> handle_rpc(request, config, test_pid)
        end

      conn
      |> Plug.Conn.put_resp_content_type("application/json")
      |> Plug.Conn.resp(200, Jason.encode!(response))
    end)

    {:ok, rpc} = RPC.new(rpc_url: "http://localhost:#{bypass.port}", finch: finch)
    rpc
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

  defp rpc_result("eth_getCode", [address, _block], config),
    do: {:ok, Map.get(config.code, String.downcase(address), "0x")}

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

    {:ok, receipt}
  end

  # balanceOf(address)
  defp dispatch_call(<<0x70, 0xA0, 0x82, 0x31, _rest::binary>>, config),
    do: {:ok, quantity_word(config.balance)}

  # transferWithAuthorization — (v,r,s) and bytes variants
  defp dispatch_call(<<0xE3, 0xEE, 0x16, 0x0E, _rest::binary>>, config),
    do: simulate_result(config)

  defp dispatch_call(<<0xCF, 0x09, 0x29, 0x95, _rest::binary>>, config),
    do: simulate_result(config)

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
end
