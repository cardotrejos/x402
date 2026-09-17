defmodule X402.Plug.PaymentGateRateLimitTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Plug.Conn
  import Plug.Test

  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.Facilitator
  alias X402.PaymentRequired
  alias X402.Plug.PaymentGate
  alias X402.RateLimiter

  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @receiver "0x1111111111111111111111111111111111111111"
  @payer "0x2222222222222222222222222222222222222222"
  @network "eip155:84532"
  @amount "10000"

  @route %{
    method: :get,
    path: "/api/resource",
    price: @amount,
    network: @network,
    asset: @asset,
    pay_to: @receiver
  }

  defmodule DenyingStore do
    @moduledoc false
    @behaviour X402.RateLimiter

    @impl true
    def hit(_ref, _key, _limit, _window_ms), do: {:deny, 2_500}
  end

  defmodule FailingStore do
    @moduledoc false
    @behaviour X402.RateLimiter

    @impl true
    def hit(_ref, _key, _limit, _window_ms), do: {:error, :redis_down}
  end

  defmodule RecordingStore do
    @moduledoc false
    @behaviour X402.RateLimiter

    @impl true
    def hit(owner, key, limit, window_ms) do
      send(owner, {:hit, key, limit, window_ms})
      {:allow, limit - 1}
    end
  end

  setup do
    :ok = RateLimiter.ETS.reset()
    :ok
  end

  describe "option validation" do
    test "rejects an incomplete rate_limit option" do
      assert_raise NimbleOptions.ValidationError, ~r/window_ms/, fn ->
        PaymentGate.init(routes: [@route], rate_limit: [limit: 10])
      end
    end

    test "rejects a store that does not implement the behaviour" do
      assert_raise NimbleOptions.ValidationError, ~r/X402.RateLimiter/, fn ->
        PaymentGate.init(routes: [@route], rate_limit: [limit: 1, window_ms: 1, store: Enum])
      end
    end

    test "compiles a full configuration" do
      opts =
        PaymentGate.init(
          routes: [@route],
          rate_limit: [limit: 5, window_ms: 1_000, key: :ip, store: {RecordingStore, self()}]
        )

      assert %{limit: 5, window_ms: 1_000, key: :ip, store: {RecordingStore, _pid}} =
               opts.rate_limit
    end

    test "defaults to no rate limit" do
      assert PaymentGate.init(routes: [@route]).rate_limit == nil
    end
  end

  describe "per-payer limiting" do
    test "allows requests within the limit and assigns :x402_rate_limit" do
      facilitator = start_mock_facilitator()
      table = unique_table()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        rate_limit: [limit: 2, window_ms: 60_000, store: {RateLimiter.ETS, table}]
      ]

      first = run_request(paid_conn(), opts)
      assert first.status == 200

      assert %{key: {:payer, @payer}, remaining: 1, limit: 2, window_ms: 60_000} =
               first.assigns.x402_rate_limit

      second = run_request(paid_conn(), opts)
      assert second.status == 200
      assert second.assigns.x402_rate_limit.remaining == 0
    end

    test "answers 429 with Retry-After once the limit is exhausted" do
      facilitator = start_mock_facilitator()
      table = unique_table()
      handler = attach_rate_limited_handler()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        rate_limit: [limit: 1, window_ms: 60_000, store: {RateLimiter.ETS, table}]
      ]

      assert run_request(paid_conn(), opts).status == 200
      assert_receive {:verify_called, _payload, _requirements}
      assert_receive {:settle_called, _payload, _requirements}

      conn = run_request(paid_conn(), opts)

      assert conn.status == 429
      assert conn.halted
      assert get_resp_header(conn, "retry-after") == ["60"]
      assert get_resp_header(conn, "content-type") == ["application/json; charset=utf-8"]
      assert conn.resp_body == "{}"
      assert decode_payment_required!(conn)["error"] == "rate_limited"

      # The payer is only trusted once the facilitator vouched for it, so the
      # denied request still paid a verify round-trip — but it never settles.
      assert_receive {:verify_called, _payload, _requirements}
      refute_receive {:settle_called, _payload, _requirements}

      assert_receive {:rate_limited, metadata}

      assert %{
               method: :get,
               path: "/api/resource",
               route: "/api/resource",
               payer: @payer,
               key: {:payer, @payer},
               limit: 1,
               window_ms: 60_000,
               retry_after_ms: retry_after_ms
             } = metadata

      assert retry_after_ms in 1..60_000
      refute_received {:payment_rejected, _metadata}

      :telemetry.detach(handler)
    end

    test "only verified payments count against the payer" do
      facilitator = start_mock_facilitator()
      table = unique_table()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        rate_limit: [limit: 1, window_ms: 60_000, store: {RateLimiter.ETS, table}]
      ]

      bad_amount =
        paid_conn(fn payload -> put_in(payload, ["payload", "authorization", "value"], "1") end)

      assert run_request(bad_amount, opts).status == 402
      refute_receive {:verify_called, _payload, _requirements}

      rejected = paid_conn(&Map.put(&1, "reject", true))
      assert run_request(rejected, opts).status == 402
      assert_receive {:verify_called, _payload, _requirements}

      assert run_request(paid_conn(), opts).status == 200
      assert run_request(paid_conn(), opts).status == 429
    end

    test "a forged payer cannot exhaust a victim's allowance" do
      facilitator = start_mock_facilitator()
      table = unique_table()
      handler = attach_rate_limited_handler()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        rate_limit: [limit: 1, window_ms: 60_000, store: {RateLimiter.ETS, table}]
      ]

      # The attacker names the victim as `from` but cannot produce the
      # victim's signature, so the facilitator rejects every attempt.
      forged = paid_conn(&Map.put(&1, "reject", true))

      for _attempt <- 1..3 do
        conn = run_request(forged, opts)
        assert conn.status == 402
        assert decode_payment_required!(conn)["error"] == "facilitator rejected payment"
        refute Map.has_key?(conn.assigns, :x402_rate_limit)
      end

      refute_received {:rate_limited, _metadata}
      assert RateLimiter.ETS.hit(table, {:payer, @payer}, 1, 60_000) == {:allow, 0}
      :ok = RateLimiter.ETS.reset(table)

      victim = run_request(paid_conn(), opts)
      assert victim.status == 200
      assert victim.assigns.x402_rate_limit.remaining == 0

      :telemetry.detach(handler)
    end

    test "a denied payment releases its replay claim for a later retry" do
      facilitator = start_mock_facilitator()
      table = unique_table()
      cache = start_supervised!({ETSCache, name: unique_table()})

      opts = [
        routes: [@route],
        facilitator: facilitator,
        payment_identifier_cache: cache,
        rate_limit: [limit: 1, window_ms: 40, store: {RateLimiter.ETS, table}]
      ]

      other_nonce = "0x" <> String.duplicate("ef", 32)

      second_proof = fn ->
        paid_conn(&put_in(&1, ["payload", "authorization", "nonce"], other_nonce))
      end

      assert run_request(paid_conn(), opts).status == 200
      assert_receive {:settle_called, _payload, _requirements}

      assert run_request(second_proof.(), opts).status == 429
      refute_receive {:settle_called, _payload, _requirements}

      Process.sleep(50)

      # A claim still held from the denied attempt would answer 402 here; the
      # released one lets the same proof through once its window rolled over.
      assert run_request(second_proof.(), opts).status == 200

      assert_receive {:settle_called,
                      %{"payload" => %{"authorization" => %{"nonce" => ^other_nonce}}},
                      _requirements}
    end

    test "limits payers independently" do
      facilitator = start_mock_facilitator()
      table = unique_table()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        rate_limit: [limit: 1, window_ms: 60_000, store: {RateLimiter.ETS, table}]
      ]

      other_payer = "0x3333333333333333333333333333333333333333"

      assert run_request(paid_conn(), opts).status == 200
      assert run_request(paid_conn(&put_payer(&1, other_payer)), opts).status == 200
      assert run_request(paid_conn(), opts).status == 429
      assert run_request(paid_conn(&put_payer(&1, other_payer)), opts).status == 429
    end

    test "treats EVM payer addresses case-insensitively" do
      facilitator = start_mock_facilitator()
      table = unique_table()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        rate_limit: [limit: 1, window_ms: 60_000, store: {RateLimiter.ETS, table}]
      ]

      assert run_request(paid_conn(), opts).status == 200

      upper = "0x" <> String.upcase(String.trim_leading(@payer, "0x"))
      assert run_request(paid_conn(&put_payer(&1, upper)), opts).status == 429
    end

    test "opens a new window after window_ms" do
      facilitator = start_mock_facilitator()
      table = unique_table()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        rate_limit: [limit: 1, window_ms: 40, store: {RateLimiter.ETS, table}]
      ]

      assert run_request(paid_conn(), opts).status == 200
      denied = run_request(paid_conn(), opts)
      assert denied.status == 429
      assert get_resp_header(denied, "retry-after") == ["1"]

      Process.sleep(50)
      assert run_request(paid_conn(), opts).status == 200
    end

    test "does not touch the store without a payment header" do
      facilitator = start_mock_facilitator()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        rate_limit: [limit: 1, window_ms: 60_000, store: {RecordingStore, self()}]
      ]

      assert run_request(conn(:get, "/api/resource"), opts).status == 402
      refute_receive {:hit, _key, _limit, _window_ms}
    end
  end

  describe "keys" do
    test ":ip keys on the remote address" do
      facilitator = start_mock_facilitator()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        rate_limit: [limit: 3, window_ms: 1_000, key: :ip, store: {RecordingStore, self()}]
      ]

      conn = run_request(%{paid_conn() | remote_ip: {10, 1, 2, 3}}, opts)

      assert conn.status == 200
      assert_receive {:hit, {:ip, {10, 1, 2, 3}}, 3, 1_000}
      assert conn.assigns.x402_rate_limit.key == {:ip, {10, 1, 2, 3}}
    end

    test ":payer prefers the payer the facilitator reports" do
      reported = "0x4444444444444444444444444444444444444444"
      facilitator = start_mock_facilitator(payer: reported)

      opts = [
        routes: [@route],
        facilitator: facilitator,
        rate_limit: [limit: 3, window_ms: 1_000, store: {RecordingStore, self()}]
      ]

      conn = run_request(paid_conn(), opts)

      assert conn.status == 200
      assert_receive {:hit, {:payer, ^reported}, 3, 1_000}
    end

    test ":payer falls back to the remote address when nobody names a payer" do
      facilitator = start_mock_facilitator(payer: nil)

      opts = [
        routes: [@route],
        facilitator: facilitator,
        local_prechecks: false,
        rate_limit: [limit: 3, window_ms: 1_000, store: {RecordingStore, self()}]
      ]

      conn =
        paid_conn(fn payload ->
          update_in(payload, ["payload", "authorization"], &Map.delete(&1, "from"))
        end)

      assert run_request(%{conn | remote_ip: {10, 9, 9, 9}}, opts).status == 200
      assert_receive {:hit, {:ip, {10, 9, 9, 9}}, 3, 1_000}
    end

    test "a key function receives the request context" do
      facilitator = start_mock_facilitator()
      owner = self()

      key_fun = fn context ->
        send(owner, {:context, context})
        {:tenant, context.conn.request_path, context.payer}
      end

      opts = [
        routes: [@route],
        facilitator: facilitator,
        rate_limit: [limit: 3, window_ms: 1_000, key: key_fun, store: {RecordingStore, self()}]
      ]

      assert run_request(paid_conn(), opts).status == 200

      assert_receive {:context,
                      %{
                        conn: %Plug.Conn{},
                        payer: @payer,
                        payment_payload: %{},
                        requirements: %{}
                      }}

      assert_receive {:hit, {:tenant, "/api/resource", @payer}, 3, 1_000}
    end

    test "a key function returning nil exempts the request" do
      facilitator = start_mock_facilitator()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        rate_limit: [
          limit: 3,
          window_ms: 1_000,
          key: fn _context -> nil end,
          store: {RecordingStore, self()}
        ]
      ]

      conn = run_request(paid_conn(), opts)

      assert conn.status == 200
      refute_receive {:hit, _key, _limit, _window_ms}
      refute Map.has_key?(conn.assigns, :x402_rate_limit)
    end
  end

  describe "stores" do
    test "a denying store answers 429 with the store's retry delay rounded up" do
      facilitator = start_mock_facilitator()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        rate_limit: [limit: 3, window_ms: 1_000, store: DenyingStore]
      ]

      conn = run_request(paid_conn(), opts)

      assert conn.status == 429
      assert get_resp_header(conn, "retry-after") == ["3"]
      assert_receive {:verify_called, _payload, _requirements}
      refute_receive {:settle_called, _payload, _requirements}
    end

    test "a failing store allows the request by default and logs" do
      facilitator = start_mock_facilitator()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        rate_limit: [limit: 3, window_ms: 1_000, store: FailingStore]
      ]

      log =
        capture_log(fn ->
          conn = run_request(paid_conn(), opts)
          assert conn.status == 200
          assert conn.assigns.x402_rate_limit.remaining == 3
        end)

      assert log =~ "FailingStore"
      assert log =~ ":redis_down"
      assert log =~ "allowing the request"
    end

    test "a failing store denies when on_error is :deny" do
      facilitator = start_mock_facilitator()

      opts = [
        routes: [@route],
        facilitator: facilitator,
        rate_limit: [limit: 3, window_ms: 1_000, store: FailingStore, on_error: :deny]
      ]

      log =
        capture_log(fn ->
          conn = run_request(paid_conn(), opts)
          assert conn.status == 429
          assert get_resp_header(conn, "retry-after") == ["1"]
        end)

      assert log =~ "denying the request"
      refute_receive {:settle_called, _payload, _requirements}
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp run_request(conn, opts) do
    conn = PaymentGate.call(conn, PaymentGate.init(opts))
    if conn.halted, do: conn, else: send_resp(conn, 200, "ok")
  end

  defp paid_conn(transform \\ &Function.identity/1) do
    header = transform.(payment_payload()) |> Jason.encode!() |> Base.encode64()

    conn(:get, "/api/resource")
    |> put_req_header("payment-signature", header)
  end

  defp put_payer(payload, payer),
    do: put_in(payload, ["payload", "authorization", "from"], payer)

  defp payment_payload do
    %{
      "x402Version" => 2,
      "resource" => %{
        "url" => "http://www.example.com/api/resource",
        "description" => "Payment required",
        "mimeType" => "application/json"
      },
      "accepted" => %{
        "scheme" => "exact",
        "network" => @network,
        "amount" => @amount,
        "asset" => @asset,
        "payTo" => @receiver,
        "maxTimeoutSeconds" => 60,
        "extra" => %{}
      },
      "payload" => %{
        "signature" =>
          "0x2d6a7588d6acca505cbf0d9a4a227e0c52c6c34008c8e8986a1283259764173608a2ce6496642e377d6da8dbbf5836e9bd15092f9ecab05ded3d6293af148b571c",
        "authorization" => %{
          "from" => @payer,
          "to" => @receiver,
          "value" => @amount,
          "validAfter" => Integer.to_string(System.system_time(:second) - 60),
          "validBefore" => Integer.to_string(System.system_time(:second) + 300),
          "nonce" => "0xf3746613c2d920b5fdabc0856f2aeb2d4f88ee6037b8cc5d04a71a4462f13480"
        }
      },
      "extensions" => %{}
    }
  end

  defp decode_payment_required!(conn) do
    [header] = get_resp_header(conn, "payment-required")
    assert {:ok, payload} = PaymentRequired.decode(header)
    payload
  end

  defp maybe_put_payer(response, nil), do: response
  defp maybe_put_payer(response, payer), do: Map.put(response, "payer", payer)

  defp unique_table do
    String.to_atom("rate_limit_gate_#{System.unique_integer([:positive, :monotonic])}")
  end

  defp attach_rate_limited_handler do
    owner = self()
    handler = "rate-limit-gate-#{System.unique_integer([:positive])}"

    :ok =
      :telemetry.attach_many(
        handler,
        [[:x402, :plug, :rate_limited], [:x402, :plug, :payment_rejected]],
        fn [:x402, :plug, event], _measurements, metadata, _config ->
          send(owner, {event, metadata})
        end,
        nil
      )

    handler
  end

  # The mock facilitator vouches for the payer named in the payload unless
  # the payload carries `"reject" => true` (a stand-in for a bad signature),
  # and reports `payer:` in its verify response when given (`nil` omits it;
  # the default echoes the payload's `from`).
  defp start_mock_facilitator(mock_opts \\ []) do
    owner = self()
    bypass = Bypass.open()

    Bypass.stub(bypass, "POST", "/verify", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      decoded = Jason.decode!(body)
      payload = decoded["paymentPayload"]
      send(owner, {:verify_called, payload, decoded["paymentRequirements"]})

      response =
        case payload["reject"] do
          true ->
            %{"isValid" => false, "invalidReason" => "invalid_signature"}

          _valid ->
            payer = Keyword.get(mock_opts, :payer, payload["payload"]["authorization"]["from"])
            %{"isValid" => true} |> maybe_put_payer(payer)
        end

      Plug.Conn.resp(conn, 200, Jason.encode!(response))
    end)

    Bypass.stub(bypass, "POST", "/settle", fn conn ->
      {:ok, body, conn} = Plug.Conn.read_body(conn)
      decoded = Jason.decode!(body)
      send(owner, {:settle_called, decoded["paymentPayload"], decoded["paymentRequirements"]})

      Plug.Conn.resp(
        conn,
        200,
        Jason.encode!(%{
          "success" => true,
          "transaction" => "0x" <> String.duplicate("ab", 32),
          "network" => @network,
          "payer" => @payer
        })
      )
    end)

    suffix = System.unique_integer([:positive, :monotonic])
    finch = String.to_atom("rate_limit_finch_#{suffix}")
    name = String.to_atom("rate_limit_facilitator_#{suffix}")

    start_supervised!(Supervisor.child_spec({Finch, name: finch}, id: finch))

    start_supervised!(
      {Facilitator,
       name: name,
       finch: finch,
       max_retries: 0,
       receive_timeout_ms: 1_000,
       url: "http://localhost:#{bypass.port}"}
    )
  end
end
