defmodule X402.TestSolanaRPCStub do
  @moduledoc false

  # Scripted Solana JSON-RPC node backed by Bypass, shared by the SVM
  # facilitator engine and Plug scaffold tests. Every request is echoed to
  # the test process as `{:solana_rpc, method, params}` so tests can assert
  # exactly which calls were (not) made. Behaviour is driven by a config
  # map — see `defaults/0`.

  alias X402.Base58
  alias X402.RPC
  alias X402.Solana.Transaction

  def defaults do
    %{
      blockhash: "EZ3rST5dvHmbanh75jc4PuLfV96vp9fEYBVeNk4FfM1k",
      last_valid_block_height: 1_000,
      simulate: {:ok, nil},
      send: :echo_signature,
      # One entry per getSignatureStatuses call; each entry is the "value"
      # list. An exhausted queue answers [nil] (perpetually pending) — the
      # lever for timeout scenarios.
      statuses: [[%{"confirmationStatus" => "confirmed", "err" => nil}]]
    }
  end

  def stub_rpc(bypass, finch, overrides \\ %{}) do
    config = Map.merge(defaults(), Map.new(overrides))
    {:ok, status_queue} = Agent.start_link(fn -> config.statuses end)
    config = Map.put(config, :status_queue, status_queue)
    test_pid = self()

    Bypass.stub(bypass, "POST", "/", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      respond(conn, Jason.decode!(body), config, test_pid)
    end)

    {:ok, rpc} = RPC.new(rpc_url: "http://localhost:#{bypass.port}", finch: finch)
    rpc
  end

  # send: :http_error simulates a transport-level broadcast failure (the
  # node may or may not have accepted the transaction).
  defp respond(conn, %{"method" => "sendTransaction"} = request, %{send: :http_error}, test_pid) do
    send(test_pid, {:solana_rpc, "sendTransaction", request["params"]})
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
    send(test_pid, {:solana_rpc, method, params})

    case rpc_result(method, params, config) do
      {:ok, result} -> %{"jsonrpc" => "2.0", "id" => id, "result" => result}
      {:error, error} -> %{"jsonrpc" => "2.0", "id" => id, "error" => error}
    end
  end

  defp rpc_result("getLatestBlockhash", _params, config) do
    {:ok,
     value_envelope(%{
       "blockhash" => config.blockhash,
       "lastValidBlockHeight" => config.last_valid_block_height
     })}
  end

  defp rpc_result("simulateTransaction", _params, config) do
    case config.simulate do
      {:ok, err} -> {:ok, value_envelope(%{"err" => err, "logs" => []})}
      {:error, error} -> {:error, error}
    end
  end

  defp rpc_result("sendTransaction", [transaction_base64, _config], config) do
    case config.send do
      # The transaction id is the slot-0 (fee payer) signature of the
      # submitted wire bytes, exactly what a real node acknowledges.
      :echo_signature ->
        {:ok, decoded} = transaction_base64 |> Base.decode64!() |> Transaction.decode()
        {:ok, Base58.encode(hd(decoded.signatures))}

      {:ok, signature} ->
        {:ok, signature}

      {:error, error} ->
        {:error, error}
    end
  end

  defp rpc_result("getSignatureStatuses", _params, config) do
    value =
      Agent.get_and_update(config.status_queue, fn
        [] -> {[nil], []}
        [head | tail] -> {head, tail}
      end)

    {:ok, value_envelope(value)}
  end

  defp value_envelope(value), do: %{"context" => %{"slot" => 1}, "value" => value}
end
