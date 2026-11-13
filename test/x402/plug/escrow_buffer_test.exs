defmodule X402.Plug.EscrowBufferTest do
  use ExUnit.Case, async: true
  alias X402.Plug.EscrowBuffer

  defmodule UnreadableBody do
    @moduledoc false
    @spec read_req_body(term(), keyword()) :: {:error, :timeout}
    def read_req_body(_payload, _opts), do: {:error, :timeout}
  end

  test "bounds shared iodata before flattening or any real send" do
    conn = Plug.Test.conn(:get, "/")
    shared = String.duplicate("x", 1024)
    body = List.duplicate(shared, 1_048_576)
    assert :erlang.iolist_size(body) == 1_073_741_824

    assert_raise ArgumentError, ~r/size limit/, fn ->
      EscrowBuffer.run(conn, &Plug.Conn.send_resp(&1, 200, body))
    end

    assert_raise RuntimeError, ~r/no sent response/, fn -> Plug.Test.sent_resp(conn) end
  end

  test "buffers callbacks and cookies once without notifying the HTTP owner" do
    conn = Plug.Test.conn(:get, "/")

    result =
      EscrowBuffer.run(conn, fn buffered ->
        buffered
        |> Plug.Conn.register_before_send(fn ready ->
          send(self(), :callback)
          Plug.Conn.put_resp_cookie(ready, "paid", "yes")
        end)
        |> Plug.Conn.send_resp(201, ["paid", " result"])
      end)

    assert result.state == :set
    assert result.resp_body == "paid result"
    assert_received :callback
    refute_received {:plug_conn, :sent}
    result = Plug.Conn.send_resp(result)
    assert {201, headers, "paid result"} = Plug.Test.sent_resp(result)
    assert Enum.count(headers, &(elem(&1, 0) == "set-cookie")) == 1
    refute_received :callback
  end

  test "body reads and metadata preserve the adapter context" do
    conn = Plug.Test.conn(:post, "/", "request")

    response =
      EscrowBuffer.run(conn, fn buffered ->
        assert Plug.Conn.get_peer_data(buffered) == Plug.Conn.get_peer_data(conn)
        assert Plug.Conn.get_http_protocol(buffered) == Plug.Conn.get_http_protocol(conn)
        assert Plug.Conn.get_sock_data(buffered) == Plug.Conn.get_sock_data(conn)
        assert Plug.Conn.get_ssl_data(buffered) == Plug.Conn.get_ssl_data(conn)
        assert {:ok, "request", buffered} = Plug.Conn.read_body(buffered)
        Plug.Conn.resp(buffered, 200, "done")
      end)

    assert response.owner == conn.owner
    assert {:ok, "", _} = Plug.Conn.read_body(response)
  end

  test "rejects alternate output paths and foreign connections" do
    conn = Plug.Test.conn(:get, "/")

    for handler <- [
          &Plug.Conn.send_file(&1, 200, __ENV__.file),
          &Plug.Conn.send_chunked(&1, 200),
          &Plug.Conn.inform(&1, 103, []),
          &Plug.Conn.upgrade_adapter(&1, :websocket, []),
          & &1,
          fn _ -> :invalid end,
          fn _ -> Plug.Conn.resp(conn, 200, "foreign") end
        ] do
      assert_raise ArgumentError, fn -> EscrowBuffer.run(conn, handler) end
    end

    assert_raise ArgumentError, fn -> EscrowBuffer.chunk(nil, "private") end
    assert_raise ArgumentError, fn -> EscrowBuffer.push(nil, "/private", []) end
  end

  test "body read failures reach the handler without being observed as reads" do
    test = self()
    conn = %{Plug.Test.conn(:post, "/", "request") | adapter: {UnreadableBody, %{}}}

    response =
      EscrowBuffer.run(
        conn,
        fn buffered ->
          assert Plug.Conn.read_body(buffered) == {:error, :timeout}
          Plug.Conn.resp(buffered, 200, "unread")
        end,
        fn adapter -> send(test, {:observed, adapter}) end
      )

    assert response.resp_body == "unread"
    assert response.adapter == {UnreadableBody, %{}}
    refute_received {:observed, _}
  end

  test "the adapter owner exits when the calling process dies mid-handler" do
    test = self()

    {caller, caller_ref} =
      spawn_monitor(fn ->
        EscrowBuffer.run(Plug.Test.conn(:get, "/"), fn buffered ->
          send(test, {:owner, buffered.owner})

          receive do
            :proceed -> Process.exit(self(), :kill)
          end
        end)
      end)

    assert_receive {:owner, owner}, 1_000
    owner_ref = Process.monitor(owner)
    send(caller, :proceed)

    assert_receive {:DOWN, ^caller_ref, :process, ^caller, :killed}, 1_000
    assert_receive {:DOWN, ^owner_ref, :process, ^owner, :normal}, 1_000
  end

  test "the adapter owner exits once the handler returns" do
    test = self()

    result =
      EscrowBuffer.run(Plug.Test.conn(:get, "/"), fn buffered ->
        send(test, {:owner, buffered.owner})
        Plug.Conn.resp(buffered, 200, "done")
      end)

    assert result.state == :set
    assert_receive {:owner, owner}, 1_000
    ref = Process.monitor(owner)
    assert_receive {:DOWN, ^ref, :process, ^owner, reason}, 1_000
    assert reason in [:normal, :noproc]
  end
end
