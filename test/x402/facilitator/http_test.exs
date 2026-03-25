defmodule X402.Facilitator.HTTPTest do
  use ExUnit.Case, async: false

  alias X402.Facilitator.Error
  alias X402.Facilitator.HTTP

  test "request/5 returns status and decoded body on success" do
    with_stubbed_finch(fn ->
      Process.put(
        :http_test_finch_response,
        {:ok, %{status: 200, body: Jason.encode!(%{"ok" => true})}}
      )

      assert {:ok, %{status: 200, body: %{"ok" => true}}} =
               HTTP.request(:stub, "https://facilitator.test", "/verify", %{"payload" => %{}}, [])
    end)
  end

  test "request/4 applies default opts" do
    with_stubbed_finch(fn ->
      Process.put(
        :http_test_finch_response,
        {:ok, %{status: 200, body: Jason.encode!(%{"ok" => true})}}
      )

      assert {:ok, %{status: 200, body: %{"ok" => true}}} =
               HTTP.request(:stub, "https://facilitator.test", "/verify", %{"payload" => %{}})
    end)
  end

  test "request/5 returns non-retryable error for 400" do
    with_stubbed_finch(fn ->
      Process.put(
        :http_test_finch_response,
        {:ok, %{status: 400, body: Jason.encode!(%{"error" => "bad request"})}}
      )

      assert {:error,
              %Error{
                type: :http_error,
                status: 400,
                body: %{"error" => "bad request"},
                retryable: false
              }} = HTTP.request(:stub, "https://facilitator.test", "/verify", %{}, max_retries: 2)
    end)
  end

  test "request/5 returns non-retryable error for 401" do
    with_stubbed_finch(fn ->
      Process.put(
        :http_test_finch_response,
        {:ok, %{status: 401, body: Jason.encode!(%{"error" => "unauthorized"})}}
      )

      assert {:error,
              %Error{
                type: :http_error,
                status: 401,
                body: %{"error" => "unauthorized"},
                retryable: false
              }} = HTTP.request(:stub, "https://facilitator.test", "/verify", %{}, max_retries: 2)
    end)
  end

  test "request/5 retries transient errors and eventually succeeds" do
    with_stubbed_finch(fn ->
      {:ok, attempts} = Agent.start_link(fn -> 0 end)

      Process.put(
        :http_test_finch_response,
        {:fun,
         fn _req, _name, _opts ->
           current_attempt = Agent.get_and_update(attempts, &{&1 + 1, &1 + 1})

           case current_attempt do
             1 -> {:ok, %{status: 429, body: Jason.encode!(%{"error" => "rate limited"})}}
             2 -> {:ok, %{status: 503, body: Jason.encode!(%{"error" => "busy"})}}
             _ -> {:ok, %{status: 200, body: Jason.encode!(%{"ok" => true})}}
           end
         end}
      )

      assert {:ok, %{status: 200, body: %{"ok" => true}}} =
               HTTP.request(:stub, "https://facilitator.test", "/verify", %{},
                 max_retries: 2,
                 retry_backoff_ms: 1
               )

      assert Agent.get(attempts, & &1) == 3
    end)
  end

  test "request/5 returns retryable error for 500 after retries exhausted" do
    with_stubbed_finch(fn ->
      Process.put(
        :http_test_finch_response,
        {:ok, %{status: 500, body: Jason.encode!(%{"error" => "server"})}}
      )

      assert {:error, %Error{type: :http_error, status: 500, retryable: true, attempt: 3}} =
               HTTP.request(:stub, "https://facilitator.test", "/verify", %{},
                 max_retries: 2,
                 retry_backoff_ms: 1
               )
    end)
  end

  test "request/5 wraps non-Error setup failures from payload encoding" do
    assert {:error, %Error{type: :request_setup_failed, retryable: false, attempt: 1}} =
             HTTP.request(:finch, "https://example.com", "/verify", %{
               "unencodable" => fn -> :not_json end
             })
  end

  test "request/5 handles invalid JSON in successful response" do
    with_stubbed_finch(fn ->
      Process.put(:http_test_finch_response, {:ok, %{status: 200, body: "not-json"}})

      assert {:error, %Error{type: :invalid_json, status: 200, retryable: false}} =
               HTTP.request(:stub, "https://facilitator.test", "/verify", %{}, [])
    end)
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

  test "request/5 handles empty body in successful response" do
    with_stubbed_finch(fn ->
      Process.put(:http_test_finch_response, {:ok, %{status: 200, body: ""}})

      assert {:ok, %{status: 200, body: %{}}} =
               HTTP.request(:stub, "https://facilitator.test", "/verify", %{}, [])
    end)
  end

  test "request/5 handles nil body in error response (transient status)" do
    with_stubbed_finch(fn ->
      Process.put(:http_test_finch_response, {:ok, %{status: 503, body: ""}})

      assert {:error, %Error{type: :http_error, status: 503, body: %{}, retryable: true}} =
               HTTP.request(:stub, "https://facilitator.test", "/verify", %{}, max_retries: 0)
    end)
  end

  test "request/5 handles non-JSON error body" do
    with_stubbed_finch(fn ->
      Process.put(:http_test_finch_response, {:ok, %{status: 400, body: "plain text error"}})

      assert {:error,
              %Error{type: :http_error, status: 400, body: %{"raw_body" => "plain text error"}}} =
               HTTP.request(:stub, "https://facilitator.test", "/verify", %{}, [])
    end)
  end

  test "request/5 handles JSON array response as invalid json" do
    with_stubbed_finch(fn ->
      Process.put(:http_test_finch_response, {:ok, %{status: 200, body: "[1, 2, 3]"}})

      assert {:error, %Error{type: :invalid_json, status: 200, retryable: false}} =
               HTTP.request(:stub, "https://facilitator.test", "/verify", %{}, [])
    end)
  end

  test "request/5 handles all transient status codes" do
    for status <- [408, 429, 502, 504] do
      with_stubbed_finch(fn ->
        Process.put(
          :http_test_finch_response,
          {:ok, %{status: status, body: Jason.encode!(%{"error" => "transient"})}}
        )

        assert {:error, %Error{type: :http_error, status: ^status, retryable: true}} =
                 HTTP.request(:stub, "https://facilitator.test", "/verify", %{},
                   max_retries: 0,
                   retry_backoff_ms: 1
                 )
      end)
    end
  end

  test "request/5 normalizes URL trailing slashes" do
    with_stubbed_finch(fn ->
      Process.put(
        :http_test_finch_response,
        {:ok, %{status: 200, body: Jason.encode!(%{"ok" => true})}}
      )

      assert {:ok, %{status: 200}} =
               HTTP.request(:stub, "https://facilitator.test/", "/verify", %{}, [])
    end)
  end

  test "request/5 handles finch edge responses without external network" do
    with_stubbed_finch(fn ->
      Process.put(:http_test_finch_response, {:ok, %{status: 200, body: nil}})

      assert {:ok, %{status: 200, body: %{}}} =
               HTTP.request(:stub, "https://example.com", "/verify", %{}, max_retries: 0)

      non_binary_body = %{unexpected: true}
      Process.put(:http_test_finch_response, {:ok, %{status: 200, body: non_binary_body}})

      assert {:error,
              %Error{
                type: :invalid_json,
                status: 200,
                reason: {:invalid_body_type, ^non_binary_body},
                body: %{"raw_body" => "%{unexpected: true}"},
                retryable: false
              }} = HTTP.request(:stub, "https://example.com", "/verify", %{}, max_retries: 0)

      Process.put(:http_test_finch_response, {:ok, %{status: 503, body: nil}})

      assert {:error, %Error{type: :http_error, status: 503, body: %{}, retryable: true}} =
               HTTP.request(:stub, "https://example.com", "/verify", %{}, max_retries: 0)

      unexpected = %{foo: :bar}
      Process.put(:http_test_finch_response, {:ok, unexpected})

      assert {:error, %Error{type: :unexpected_response, reason: ^unexpected, retryable: false}} =
               HTTP.request(:stub, "https://example.com", "/verify", %{}, max_retries: 0)

      Process.put(:http_test_finch_response, {:error, :timeout})

      assert {:error, %Error{type: :timeout, reason: :timeout, retryable: true}} =
               HTTP.request(:stub, "https://example.com", "/verify", %{}, max_retries: 0)

      nested_timeout = %{reason: {:timeout, :read}}
      Process.put(:http_test_finch_response, {:error, nested_timeout})

      assert {:error, %Error{type: :timeout, reason: ^nested_timeout, retryable: true}} =
               HTTP.request(:stub, "https://example.com", "/verify", %{}, max_retries: 0)

      Process.put(:http_test_finch_response, {:exit, :simulated_exit})

      assert {:error, %Error{type: :transport_error, reason: :simulated_exit, retryable: true}} =
               HTTP.request(:stub, "https://example.com", "/verify", %{}, max_retries: 0)
    end)
  end

  test "request/5 rejects http:// base_url with insecure_scheme error" do
    assert {:error, %Error{type: :insecure_scheme}} =
             HTTP.request(:finch, "http://example.com", "/verify", %{})
  end

  test "request/5 rejects base_url with no scheme" do
    assert {:error, %Error{type: :insecure_scheme}} =
             HTTP.request(:finch, "example.com", "/verify", %{})
  end

  test "request/5 rejects ftp:// base_url with insecure_scheme error" do
    assert {:error, %Error{type: :insecure_scheme}} =
             HTTP.request(:finch, "ftp://example.com", "/verify", %{})
  end

  test "request/5 accepts https:// base_url (scheme validation passes, Finch may still fail)" do
    with_stubbed_finch(fn ->
      Process.put(:http_test_finch_response, {:error, :connection_refused})

      result = HTTP.request(:stub, "https://example.com", "/verify", %{})
      assert {:error, %Error{type: type}} = result
      refute type == :insecure_scheme
    end)
  end

  test "request/5 allows http://localhost (loopback exemption — no MitM risk)" do
    with_stubbed_finch(fn ->
      Process.put(:http_test_finch_response, {:error, :connection_refused})

      result = HTTP.request(:stub, "http://localhost:4000", "/verify", %{})
      assert {:error, %Error{type: type}} = result
      refute type == :insecure_scheme
    end)
  end

  test "request/5 allows http://127.0.0.1 (loopback exemption — no MitM risk)" do
    with_stubbed_finch(fn ->
      Process.put(:http_test_finch_response, {:error, :connection_refused})

      result = HTTP.request(:stub, "http://127.0.0.1:4000", "/verify", %{})
      assert {:error, %Error{type: type}} = result
      refute type == :insecure_scheme
    end)
  end

  test "request/5 allows http://[::1] (IPv6 loopback exemption — no MitM risk)" do
    with_stubbed_finch(fn ->
      Process.put(:http_test_finch_response, {:error, :connection_refused})

      result = HTTP.request(:stub, "http://[::1]:4000", "/verify", %{})
      assert {:error, %Error{type: type}} = result
      refute type == :insecure_scheme
    end)
  end

  test "request/5 returns finch_unavailable when Finch callbacks are missing" do
    with_redefined_finch(
      """
      defmodule Finch do
        def build(_method, _url, _headers, _body), do: :stubbed_request
      end
      """,
      fn ->
        assert {:error,
                %Error{
                  type: :finch_unavailable,
                  reason: :missing_dependency,
                  retryable: false
                }} = HTTP.request(:stub, "https://example.com", "/verify", %{})
      end
    )
  end

  test "secure_pool_opts/0 returns default TLS configuration" do
    assert [
             conn_opts: [
               transport_opts: [
                 verify: :verify_peer,
                 cacerts: cacerts
               ]
             ]
           ] = HTTP.secure_pool_opts()

    assert is_list(cacerts) and cacerts != []
  end

  defp with_stubbed_finch(fun) when is_function(fun, 0) do
    with_redefined_finch(
      """
      defmodule Finch do
        def build(method, url, headers, body), do: %{method: method, url: url, headers: headers, body: body}

        def request(request, finch_name, opts) do
          case Process.get(:http_test_finch_response) do
            {:exit, reason} -> exit(reason)
            {:fun, response_fun} when is_function(response_fun, 3) -> response_fun.(request, finch_name, opts)
            response -> response
          end
        end
      end
      """,
      fn ->
        try do
          fun.()
        after
          Process.delete(:http_test_finch_response)
        end
      end
    )
  end

  defp with_redefined_finch(module_source, fun)
       when is_binary(module_source) and is_function(fun, 0) do
    {Finch, original_binary, original_path} = :code.get_object_code(Finch)
    original_conflict_setting = Code.get_compiler_option(:ignore_module_conflict)

    Code.put_compiler_option(:ignore_module_conflict, true)

    try do
      Code.compile_string(module_source)
      fun.()
    after
      :code.load_binary(Finch, original_path, original_binary)
      Code.put_compiler_option(:ignore_module_conflict, original_conflict_setting)
    end
  end
end
