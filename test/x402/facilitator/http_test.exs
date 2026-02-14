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

  test "request/5 handles empty error response body", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 503, "")
    end)

    assert {:error,
            %Error{type: :http_error, status: 503, body: %{}, retryable: true, attempt: 1}} =
             HTTP.request(finch, facilitator_url, "/verify", %{},
               max_retries: 0,
               receive_timeout_ms: 50
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

  test "request/5 handles non-JSON transient response body", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 503, "service temporarily unavailable")
    end)

    assert {:error,
            %Error{
              type: :http_error,
              status: 503,
              body: %{"raw_body" => "service temporarily unavailable"},
              retryable: true,
              attempt: 1
            }} =
             HTTP.request(finch, facilitator_url, "/verify", %{}, max_retries: 0)
  end

  test "request/5 handles JSON that is not an object", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 200, Jason.encode!([1, 2, 3]))
    end)

    assert {:error,
            %Error{
              type: :invalid_json,
              status: 200,
              reason: {:invalid_json_object, [1, 2, 3]},
              retryable: false,
              attempt: 1
            }} = HTTP.request(finch, facilitator_url, "/verify", %{}, [])
  end

  test "request/5 wraps payload encoding errors as setup failures", %{
    finch: finch,
    facilitator_url: facilitator_url
  } do
    assert {:error,
            %Error{
              type: :request_setup_failed,
              reason: %Protocol.UndefinedError{},
              retryable: false,
              attempt: 1
            }} =
             HTTP.request(finch, facilitator_url, "/verify", %{"bad" => self()}, [])
  end

  test "request/5 validates options" do
    assert {:error, %Error{type: :invalid_option, reason: {:max_retries, -1}}} =
             HTTP.request(:finch, "https://example.com", "/verify", %{}, max_retries: -1)

    assert {:error, %Error{type: :invalid_option, reason: {:max_retries, "two"}}} =
             HTTP.request(:finch, "https://example.com", "/verify", %{}, max_retries: "two")
  end
end

defmodule X402.Facilitator.HTTPFinchShimTest do
  use ExUnit.Case, async: false

  alias X402.Facilitator.Error
  alias X402.Facilitator.HTTP

  test "request/5 handles unexpected Finch responses" do
    with_stubbed_finch(
      quote do
        def build(method, url, headers, body), do: {method, url, headers, body}
        def request(_request, _name, _opts), do: {:ok, :unexpected}
      end,
      fn ->
        assert {:error,
                %Error{
                  type: :unexpected_response,
                  reason: :unexpected,
                  retryable: false,
                  attempt: 1
                }} = HTTP.request(:unused, "http://unused", "/verify", %{}, [])
      end
    )
  end

  test "request/5 decodes nil and empty successful response bodies as empty maps" do
    with_stubbed_finch(
      quote do
        def build(method, url, headers, body), do: {method, url, headers, body}
        def request(_request, :nil_body, _opts), do: {:ok, %{status: 200, body: nil}}
        def request(_request, :empty_body, _opts), do: {:ok, %{status: 200, body: ""}}
      end,
      fn ->
        assert {:ok, %{status: 200, body: %{}}} =
                 HTTP.request(:nil_body, "http://unused", "/verify", %{}, [])

        assert {:ok, %{status: 200, body: %{}}} =
                 HTTP.request(:empty_body, "http://unused", "/verify", %{}, [])
      end
    )
  end

  test "request/5 reports invalid body types with inspected raw body" do
    with_stubbed_finch(
      quote do
        def build(method, url, headers, body), do: {method, url, headers, body}
        def request(_request, _name, _opts), do: {:ok, %{status: 200, body: %{oops: true}}}
      end,
      fn ->
        assert {:error,
                %Error{
                  type: :invalid_json,
                  status: 200,
                  body: %{"raw_body" => "%{oops: true}"},
                  reason: {:invalid_body_type, %{oops: true}},
                  retryable: false,
                  attempt: 1
                }} = HTTP.request(:unused, "http://unused", "/verify", %{}, [])
      end
    )
  end

  test "request/5 classifies timeout reasons from atom and tuple formats" do
    with_stubbed_finch(
      quote do
        def build(method, url, headers, body), do: {method, url, headers, body}
        def request(_request, :atom_timeout, _opts), do: {:error, :timeout}
        def request(_request, :tuple_timeout, _opts), do: {:error, %{reason: {:timeout, :read}}}
      end,
      fn ->
        assert {:error, %Error{type: :timeout, reason: :timeout, retryable: true, attempt: 1}} =
                 HTTP.request(:atom_timeout, "http://unused", "/verify", %{}, max_retries: 0)

        assert {:error,
                %Error{
                  type: :timeout,
                  reason: %{reason: {:timeout, :read}},
                  retryable: true,
                  attempt: 1
                }} = HTTP.request(:tuple_timeout, "http://unused", "/verify", %{}, max_retries: 0)
      end
    )
  end

  test "request/5 converts exited Finch requests into transport errors" do
    with_stubbed_finch(
      quote do
        def build(method, url, headers, body), do: {method, url, headers, body}
        def request(_request, _name, _opts), do: exit(:noproc)
      end,
      fn ->
        assert {:error,
                %Error{type: :transport_error, reason: :noproc, retryable: true, attempt: 1}} =
                 HTTP.request(:missing_finch, "http://unused", "/verify", %{}, max_retries: 0)
      end
    )
  end

  test "request/5 returns finch_unavailable when Finch dependency contract is missing" do
    with_stubbed_finch(
      quote do
        def build(_method, _url, _headers, _body), do: :built_request
      end,
      fn ->
        assert {:error,
                %Error{
                  type: :finch_unavailable,
                  reason: :missing_dependency,
                  retryable: false
                }} = HTTP.request(:unused, "http://unused", "/verify", %{}, [])
      end
    )
  end

  defp with_stubbed_finch(stub_ast, test_fun) do
    true = Code.ensure_loaded?(Finch)
    {Finch, original_binary, original_path} = :code.get_object_code(Finch)
    original_compiler_options = Code.compiler_options()

    :code.purge(Finch)
    :code.delete(Finch)
    Code.compiler_options(ignore_module_conflict: true)

    Code.compile_quoted(
      quote do
        defmodule Finch do
          unquote(stub_ast)
        end
      end
    )

    try do
      test_fun.()
    after
      :code.purge(Finch)
      :code.delete(Finch)
      :code.load_binary(Finch, original_path, original_binary)
      Code.compiler_options(original_compiler_options)
    end
  end
end
