defmodule X402.RPCTest do
  use ExUnit.Case, async: false

  alias X402.RPC

  import X402.TestHelpers

  doctest X402.RPC

  setup :setup_bypass
  setup :setup_finch

  defp rpc(%{bypass: bypass, finch: finch}, opts \\ []) do
    {:ok, rpc} =
      RPC.new(Keyword.merge([rpc_url: "http://localhost:#{bypass.port}", finch: finch], opts))

    rpc
  end

  defp respond(conn, payload) do
    conn
    |> Plug.Conn.put_resp_content_type("application/json")
    |> Plug.Conn.resp(200, Jason.encode!(payload))
  end

  describe "new/1" do
    test "builds a config with defaults", %{finch: finch} do
      assert {:ok, %RPC{timeout: 5_000}} =
               RPC.new(rpc_url: "https://sepolia.base.org", finch: finch)
    end

    test "accepts pid and via-tuple finch names" do
      assert {:ok, %RPC{}} = RPC.new(rpc_url: "https://example.com", finch: self())

      assert {:ok, %RPC{}} =
               RPC.new(rpc_url: "https://example.com", finch: {:via, Registry, {Reg, :key}})
    end

    test "rejects plain http for non-loopback hosts" do
      assert RPC.new(rpc_url: "http://rpc.example.com", finch: MyFinch) ==
               {:error, :insecure_rpc_url}

      assert RPC.new(rpc_url: "ftp://rpc.example.com", finch: MyFinch) ==
               {:error, :insecure_rpc_url}

      assert RPC.new(rpc_url: "rpc.example.com", finch: MyFinch) == {:error, :insecure_rpc_url}
    end

    test "allows http for loopback hosts" do
      assert {:ok, %RPC{}} = RPC.new(rpc_url: "http://localhost:8545", finch: MyFinch)
      assert {:ok, %RPC{}} = RPC.new(rpc_url: "http://127.0.0.1:8545", finch: MyFinch)
    end

    test "raises on invalid options" do
      assert_raise NimbleOptions.ValidationError, fn ->
        RPC.new(rpc_url: "https://example.com", finch: "not a finch name")
      end

      assert_raise NimbleOptions.ValidationError, fn ->
        RPC.new(finch: MyFinch)
      end

      assert_raise NimbleOptions.ValidationError, fn ->
        RPC.new(rpc_url: "https://example.com", finch: MyFinch, timeout: 0)
      end
    end
  end

  describe "request/3" do
    test "returns the decoded result", context do
      Bypass.expect_once(context.bypass, "POST", "/", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)

        assert %{
                 "jsonrpc" => "2.0",
                 "id" => 1,
                 "method" => "eth_blockNumber",
                 "params" => []
               } = Jason.decode!(body)

        respond(conn, %{"jsonrpc" => "2.0", "id" => 1, "result" => "0x10"})
      end)

      assert RPC.request(rpc(context), "eth_blockNumber", []) == {:ok, "0x10"}
    end

    test "maps node-side errors to jsonrpc_error", context do
      Bypass.expect_once(context.bypass, "POST", "/", fn conn ->
        respond(conn, %{
          "jsonrpc" => "2.0",
          "id" => 1,
          "error" => %{"code" => 3, "message" => "execution reverted", "data" => "0x"}
        })
      end)

      assert RPC.request(rpc(context), "eth_call", []) ==
               {:error, {:jsonrpc_error, %{code: 3, message: "execution reverted", data: "0x"}}}
    end

    test "normalizes malformed error objects", context do
      Bypass.expect_once(context.bypass, "POST", "/", fn conn ->
        respond(conn, %{"jsonrpc" => "2.0", "id" => 1, "error" => %{"code" => "3"}})
      end)

      assert RPC.request(rpc(context), "eth_call", []) ==
               {:error, {:jsonrpc_error, %{code: nil, message: nil, data: nil}}}
    end

    test "returns http_error for non-2xx statuses", context do
      Bypass.expect_once(context.bypass, "POST", "/", fn conn ->
        Plug.Conn.resp(conn, 502, "bad gateway")
      end)

      assert RPC.request(rpc(context), "eth_chainId", []) == {:error, {:http_error, 502}}
    end

    test "returns invalid_response for non-JSON bodies", context do
      Bypass.expect_once(context.bypass, "POST", "/", fn conn ->
        Plug.Conn.resp(conn, 200, "not json")
      end)

      assert {:error, {:invalid_response, %Jason.DecodeError{}}} =
               RPC.request(rpc(context), "eth_chainId", [])
    end

    test "returns invalid_response for JSON without result or error", context do
      Bypass.expect_once(context.bypass, "POST", "/", fn conn ->
        respond(conn, %{"jsonrpc" => "2.0", "id" => 1})
      end)

      assert {:error, {:invalid_response, _body}} = RPC.request(rpc(context), "eth_chainId", [])
    end

    test "returns transport_error when the endpoint is down", context do
      Bypass.down(context.bypass)

      assert {:error, {:transport_error, _reason}} =
               RPC.request(rpc(context), "eth_chainId", [])
    end

    test "emits telemetry on success and error", context do
      ref = make_ref()
      test_pid = self()

      :telemetry.attach(
        "rpc-test-#{inspect(ref)}",
        [:x402, :rpc, :request],
        fn _event, _measurements, metadata, _config -> send(test_pid, {:telemetry, metadata}) end,
        nil
      )

      on_exit(fn -> :telemetry.detach("rpc-test-#{inspect(ref)}") end)

      Bypass.expect_once(context.bypass, "POST", "/", fn conn ->
        respond(conn, %{"jsonrpc" => "2.0", "id" => 1, "result" => "0x1"})
      end)

      assert {:ok, "0x1"} = RPC.request(rpc(context), "eth_chainId", [])
      assert_received {:telemetry, %{status: :ok, method: "eth_chainId"}}

      Bypass.down(context.bypass)
      assert {:error, _reason} = RPC.request(rpc(context), "eth_chainId", [])
      assert_received {:telemetry, %{status: :error, method: "eth_chainId"}}
    end
  end

  describe "batch/2" do
    test "returns results in request order even when responses are shuffled", context do
      Bypass.expect_once(context.bypass, "POST", "/", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        requests = Jason.decode!(body)
        assert Enum.map(requests, & &1["id"]) == [1, 2, 3]

        respond(conn, [
          %{"jsonrpc" => "2.0", "id" => 3, "result" => "0x3"},
          %{"jsonrpc" => "2.0", "id" => 1, "result" => "0x1"},
          %{"jsonrpc" => "2.0", "id" => 2, "error" => %{"code" => -32_000, "message" => "boom"}}
        ])
      end)

      requests = [
        {"eth_chainId", []},
        {"eth_getCode", ["0xabc", "latest"]},
        {"eth_blockNumber", []}
      ]

      assert RPC.batch(rpc(context), requests) ==
               {:ok,
                [
                  {:ok, "0x1"},
                  {:error, {:jsonrpc_error, %{code: -32_000, message: "boom", data: nil}}},
                  {:ok, "0x3"}
                ]}
    end

    test "returns {:ok, []} for an empty batch without an HTTP call", context do
      assert RPC.batch(rpc(context), []) == {:ok, []}
    end

    test "fails the whole batch when a response id is missing", context do
      Bypass.expect_once(context.bypass, "POST", "/", fn conn ->
        respond(conn, [%{"jsonrpc" => "2.0", "id" => 1, "result" => "0x1"}])
      end)

      assert {:error, {:invalid_response, {:missing_response, 2}}} =
               RPC.batch(rpc(context), [{"eth_chainId", []}, {"eth_blockNumber", []}])
    end

    test "ignores batch responses without an id", context do
      Bypass.expect_once(context.bypass, "POST", "/", fn conn ->
        respond(conn, [%{"jsonrpc" => "2.0", "result" => "0x1"}])
      end)

      assert {:error, {:invalid_response, {:missing_response, 1}}} =
               RPC.batch(rpc(context), [{"eth_chainId", []}])
    end

    test "fails when the response is not a list", context do
      Bypass.expect_once(context.bypass, "POST", "/", fn conn ->
        respond(conn, %{"jsonrpc" => "2.0", "id" => 1, "result" => "0x1"})
      end)

      assert {:error, {:invalid_response, _body}} =
               RPC.batch(rpc(context), [{"eth_chainId", []}])
    end

    test "propagates transport errors", context do
      Bypass.down(context.bypass)

      assert {:error, {:transport_error, _reason}} =
               RPC.batch(rpc(context), [{"eth_chainId", []}])
    end
  end

  describe "eth helpers" do
    test "call/3 normalizes the call object and defaults to latest", context do
      Bypass.expect_once(context.bypass, "POST", "/", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)

        assert %{
                 "method" => "eth_call",
                 "params" => [%{"to" => "0xto", "data" => "0xdata", "from" => "0xfrom"}, "latest"]
               } = Jason.decode!(body)

        respond(conn, %{"jsonrpc" => "2.0", "id" => 1, "result" => "0x"})
      end)

      assert RPC.call(rpc(context), %{to: "0xto", data: "0xdata", from: "0xfrom"}) == {:ok, "0x"}
    end

    test "get_code/2 requests eth_getCode", context do
      Bypass.expect_once(context.bypass, "POST", "/", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        assert %{"method" => "eth_getCode", "params" => ["0xabc", "latest"]} = Jason.decode!(body)
        respond(conn, %{"jsonrpc" => "2.0", "id" => 1, "result" => "0x"})
      end)

      assert RPC.get_code(rpc(context), "0xabc") == {:ok, "0x"}
    end

    test "chain_id/1 requests eth_chainId", context do
      Bypass.expect_once(context.bypass, "POST", "/", fn conn ->
        {:ok, body, conn} = Plug.Conn.read_body(conn)
        assert %{"method" => "eth_chainId", "params" => []} = Jason.decode!(body)
        respond(conn, %{"jsonrpc" => "2.0", "id" => 1, "result" => "0x14a34"})
      end)

      assert RPC.chain_id(rpc(context)) == {:ok, "0x14a34"}
    end
  end

  describe "validate_config/1" do
    test "accepts an %X402.RPC{} struct", context do
      assert {:ok, %RPC{}} = RPC.validate_config(rpc(context))
    end

    test "rejects other values" do
      assert {:error, message} = RPC.validate_config(%{rpc_url: "https://example.com"})
      assert message =~ "X402.RPC"
    end
  end
end
