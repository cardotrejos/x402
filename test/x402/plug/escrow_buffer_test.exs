defmodule X402.Plug.EscrowBufferTest do
  use ExUnit.Case, async: true
  alias X402.Plug.EscrowBuffer

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
    assert length(Enum.filter(headers, &(elem(&1, 0) == "set-cookie"))) == 1
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
end
