defmodule X402.Facilitator.HTTPTest do
  use ExUnit.Case, async: false

  alias X402.Facilitator.Error
  alias X402.Facilitator.HTTP

  import X402.TestHelpers

  setup :setup_bypass
  setup :setup_finch

  test "request/5 returns status and decoded body on success", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"ok" => true}))
    end)

    assert {:ok, %{status: 200, body: %{"ok" => true}}} =
             HTTP.request(finch, facilitator_url, "/verify", %{"payload" => %{}}, [])
  end

  test "request/5 returns non-retryable error for 400", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 400, Jason.encode!(%{"error" => "bad request"}))
    end)

    assert {:error,
            %Error{
              type: :http_error,
              status: 400,
              body: %{"error" => "bad request"},
              retryable: false
            }} =
             HTTP.request(finch, facilitator_url, "/verify", %{}, max_retries: 2)
  end

  test "request/5 returns non-retryable error for 401", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 401, Jason.encode!(%{"error" => "unauthorized"}))
    end)

    assert {:error,
            %Error{
              type: :http_error,
              status: 401,
              body: %{"error" => "unauthorized"},
              retryable: false
            }} = HTTP.request(finch, facilitator_url, "/verify", %{}, max_retries: 2)
  end

  test "request/5 retries transient errors and eventually succeeds", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    {:ok, attempts} = Agent.start_link(fn -> 0 end)

    Bypass.stub(bypass, "POST", "/verify", fn conn ->
      current_attempt = Agent.get_and_update(attempts, &{&1 + 1, &1 + 1})

      case current_attempt do
        attempt when attempt < 3 ->
          Plug.Conn.resp(conn, 503, Jason.encode!(%{"error" => "busy"}))

        _attempt ->
          Plug.Conn.resp(conn, 200, Jason.encode!(%{"ok" => true}))
      end
    end)

    assert {:ok, %{status: 200, body: %{"ok" => true}}} =
             HTTP.request(finch, facilitator_url, "/verify", %{},
               max_retries: 2,
               retry_backoff_ms: 1
             )

    assert Agent.get(attempts, & &1) == 3
  end

  test "request/5 returns retryable error for 500 after retries exhausted", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.stub(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 500, Jason.encode!(%{"error" => "server"}))
    end)

    assert {:error, %Error{type: :http_error, status: 500, retryable: true, attempt: 3}} =
             HTTP.request(finch, facilitator_url, "/verify", %{},
               max_retries: 2,
               retry_backoff_ms: 1
             )
  end

  test "request/5 handles receive timeout", %{finch: finch} do
    assert {:error, %Error{type: :timeout, retryable: true}} =
             HTTP.request(finch, "http://10.255.255.1:81", "/verify", %{},
               max_retries: 0,
               receive_timeout_ms: 10
             )
  end

  test "request/5 handles invalid JSON in successful response", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 200, "not-json")
    end)

    assert {:error, %Error{type: :invalid_json, status: 200, retryable: false}} =
             HTTP.request(finch, facilitator_url, "/verify", %{}, [])
  end

  test "request/5 validates options" do
    assert {:error, %Error{type: :invalid_option, reason: {:max_retries, -1}}} =
             HTTP.request(:finch, "https://example.com", "/verify", %{}, max_retries: -1)
  end
end
