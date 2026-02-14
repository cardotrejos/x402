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

  test "request/5 validates retry_backoff_ms option" do
    assert {:error, %Error{type: :invalid_option, reason: {:retry_backoff_ms, "bad"}}} =
             HTTP.request(:finch, "https://example.com", "/verify", %{}, retry_backoff_ms: "bad")
  end

  test "request/5 validates receive_timeout_ms option" do
    assert {:error, %Error{type: :invalid_option, reason: {:receive_timeout_ms, -5}}} =
             HTTP.request(:finch, "https://example.com", "/verify", %{}, receive_timeout_ms: -5)
  end

  test "request/5 handles empty body in successful response", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 200, "")
    end)

    assert {:ok, %{status: 200, body: %{}}} =
             HTTP.request(finch, facilitator_url, "/verify", %{}, [])
  end

  test "request/5 handles nil body in error response (transient status)", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.stub(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 503, "")
    end)

    assert {:error, %Error{type: :http_error, status: 503, body: %{}, retryable: true}} =
             HTTP.request(finch, facilitator_url, "/verify", %{}, max_retries: 0)
  end

  test "request/5 handles non-JSON error body", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 400, "plain text error")
    end)

    assert {:error,
            %Error{type: :http_error, status: 400, body: %{"raw_body" => "plain text error"}}} =
             HTTP.request(finch, facilitator_url, "/verify", %{}, [])
  end

  test "request/5 handles JSON array response as invalid json", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 200, "[1, 2, 3]")
    end)

    assert {:error, %Error{type: :invalid_json, status: 200, retryable: false}} =
             HTTP.request(finch, facilitator_url, "/verify", %{}, [])
  end

  test "request/5 handles transport error (connection refused)", %{finch: finch} do
    # Use a port that's definitely not listening
    assert {:error, %Error{type: :transport_error, retryable: true}} =
             HTTP.request(finch, "http://127.0.0.1:1", "/verify", %{},
               max_retries: 0,
               receive_timeout_ms: 100
             )
  end

  test "request/5 handles timeout with %{reason: :timeout} format", %{finch: finch} do
    assert {:error, %Error{retryable: true}} =
             HTTP.request(finch, "http://10.255.255.1:81", "/verify", %{},
               max_retries: 0,
               receive_timeout_ms: 10
             )
  end

  test "request/5 handles all transient status codes", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    for status <- [408, 429, 502, 504] do
      Bypass.stub(bypass, "POST", "/verify", fn conn ->
        Plug.Conn.resp(conn, status, Jason.encode!(%{"error" => "transient"}))
      end)

      assert {:error, %Error{type: :http_error, status: ^status, retryable: true}} =
               HTTP.request(finch, facilitator_url, "/verify", %{},
                 max_retries: 0,
                 retry_backoff_ms: 1
               )
    end
  end

  test "request/5 normalizes URL trailing slashes", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"ok" => true}))
    end)

    assert {:ok, %{status: 200}} =
             HTTP.request(finch, facilitator_url <> "/", "/verify", %{}, [])
  end
end
