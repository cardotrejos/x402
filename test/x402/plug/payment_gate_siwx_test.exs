defmodule X402.Plug.PaymentGateSIWXTest do
  @moduledoc """
  Sign-In-With-X integration of `X402.Plug.PaymentGate`: challenge
  advertisement, header authentication, and payer recording after
  settlement.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog
  import Plug.Conn
  import Plug.Test

  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.Extensions.SIWX
  alias X402.Extensions.SIWX.ETSStorage
  alias X402.Facilitator
  alias X402.PaymentRequired
  alias X402.Plug.PaymentGate
  alias X402.Signer.LocalKey

  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @receiver "0x1111111111111111111111111111111111111111"
  @network "eip155:84532"
  @amount "10000"

  @private_key "0x" <> String.duplicate("11", 32)
  @address "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
  @evm_chain "eip155:8453"
  @resource "http://www.example.com/api/resource"
  @access_resource "GET " <> @resource

  @route %{
    method: :get,
    path: "/api/resource",
    price: @amount,
    network: @network,
    asset: @asset,
    pay_to: @receiver
  }

  @siwx [
    domain: "www.example.com",
    uri: "http://www.example.com",
    supported_chains: [%{chain_id: @evm_chain}]
  ]

  @default_verify {:ok, %{status: 200, body: %{"isValid" => true, "payer" => @address}}}

  @default_settle {
    :ok,
    %{
      status: 200,
      body: %{
        "success" => true,
        "transaction" => "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        "network" => @network,
        "payer" => @address
      }
    }
  }

  defmodule FailingCache do
    @behaviour X402.Extensions.PaymentIdentifier.Cache

    @impl true
    def get(_cache, _key), do: :miss
    @impl true
    def put(_cache, _key, _value), do: {:error, :down}
    @impl true
    def put_new(_cache, _key, _value), do: {:error, :down}
    @impl true
    def delete(_cache, _key), do: :ok
  end

  defmodule FailingStorage do
    @behaviour X402.Extensions.SIWX.Storage

    @impl true
    def get(_address, _resource), do: {:error, :not_found}
    @impl true
    def put(_address, _resource, _proof, _ttl_ms), do: {:error, :storage_full}
    @impl true
    def delete(_address, _resource), do: :ok
  end

  setup do
    storage = start_storage()
    cache = start_cache()
    {:ok, storage: storage, cache: cache, siwx: siwx_opts(storage, cache)}
  end

  describe "challenge advertisement" do
    test "every 402 carries a fresh challenge whose nonce is recorded", %{
      siwx: siwx,
      cache: cache
    } do
      first = conn(:get, "/api/resource") |> run_request(gate_opts(siwx: siwx))
      second = conn(:get, "/api/resource") |> run_request(gate_opts(siwx: siwx))

      assert first.status == 402
      assert %{"info" => info, "supportedChains" => chains} = challenge_of(first)
      assert info["domain"] == "www.example.com"
      assert info["uri"] == "http://www.example.com"
      assert chains == [%{"chainId" => @evm_chain, "type" => "eip191"}]
      assert info["nonce"] != challenge_of(second)["info"]["nonce"]

      assert {:hit, {:siwx_nonce, :issued}} = ETSCache.get(cache, "siwx:issued:" <> info["nonce"])
    end

    test "is absent without :siwx and on 400 responses", %{siwx: siwx} do
      plain = conn(:get, "/api/resource") |> run_request(gate_opts())
      refute Map.has_key?(decode_payment_required!(plain)["extensions"], "sign-in-with-x")

      bad =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", "%%")
        |> run_request(gate_opts(siwx: siwx))

      assert bad.status == 400
      refute Map.has_key?(decode_payment_required!(bad)["extensions"], "sign-in-with-x")
    end

    test "keeps route extensions and is omitted when the nonce cannot be recorded", %{
      storage: storage
    } do
      route = Map.put(@route, :extensions, %{"custom" => %{"info" => %{"a" => 1}}})
      siwx = siwx_opts(storage, {FailingCache, :ref})

      log =
        capture_log(fn ->
          conn =
            conn(:get, "/api/resource") |> run_request(gate_opts(routes: [route], siwx: siwx))

          extensions = decode_payment_required!(conn)["extensions"]

          assert extensions == %{"custom" => %{"info" => %{"a" => 1}}}
        end)

      assert log =~ "omitting the challenge"
    end

    test "rejects invalid :siwx options at init" do
      assert_raise NimbleOptions.ValidationError, fn ->
        PaymentGate.init(gate_opts(siwx: [domain: "x"]))
      end
    end
  end

  describe "SIGN-IN-WITH-X authentication" do
    test "serves a recorded payer without payment", %{siwx: siwx, storage: storage} do
      facilitator = start_mock_facilitator()
      opts = gate_opts(siwx: siwx, facilitator: facilitator)
      :ok = ETSStorage.put(storage, @address, @access_resource, :paid, 60_000)
      attach_telemetry([:x402, :plug, :siwx_authenticated])

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("sign-in-with-x", proof(opts))
        |> run_request(opts)

      assert conn.status == 200
      assert conn.resp_body == "ok"
      assert conn.assigns[:x402_siwx_address] == @address
      assert conn.assigns[:x402_siwx_chain_id] == @evm_chain
      assert get_resp_header(conn, "payment-required") == []
      refute_receive {:verify_called, _payload, _requirements}

      assert_receive {:telemetry, [:x402, :plug, :siwx_authenticated],
                      %{address: @address, chain_id: @evm_chain, route: "/api/resource"}}
    end

    test "answers 402 with a fresh challenge when the address has no record", %{siwx: siwx} do
      opts = gate_opts(siwx: siwx)
      attach_telemetry([:x402, :plug, :payment_required])

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("sign-in-with-x", proof(opts))
        |> run_request(opts)

      assert conn.status == 402
      required = decode_payment_required!(conn)
      assert required["error"] =~ "no payment recorded"
      assert %{"info" => %{"nonce" => _nonce}} = required["extensions"]["sign-in-with-x"]
      assert_receive {:telemetry, [:x402, :plug, :payment_required], %{siwx: :not_authorized}}
    end

    test "a proof authenticates once with a nonce cache", %{siwx: siwx, storage: storage} do
      opts = gate_opts(siwx: siwx)
      :ok = ETSStorage.put(storage, @address, @access_resource, :paid, 60_000)
      header = proof(opts)

      first =
        conn(:get, "/api/resource")
        |> put_req_header("sign-in-with-x", header)
        |> run_request(opts)

      assert first.status == 200

      replay =
        conn(:get, "/api/resource")
        |> put_req_header("sign-in-with-x", header)
        |> run_request(opts)

      assert replay.status == 402
      assert decode_payment_required!(replay)["error"] == "invalid_siwx_nonce"
    end

    test "answers 402 with the spec error code for proofs that fail verification", %{
      siwx: siwx,
      storage: storage
    } do
      opts = gate_opts(siwx: siwx)
      :ok = ETSStorage.put(storage, @address, @access_resource, :paid, 60_000)
      attach_telemetry([:x402, :plug, :payment_rejected])

      challenge = fetch_challenge(opts)
      {:ok, signer} = LocalKey.new(@private_key)

      {:ok, signed} =
        SIWX.sign(put_in(challenge, ["info", "domain"], "evil.example.com"), signer,
          chain_id: @evm_chain
        )

      {:ok, header} = SIWX.encode_signed(signed)

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("sign-in-with-x", header)
        |> run_request(opts)

      assert conn.status == 402
      assert decode_payment_required!(conn)["error"] == "invalid_siwx_domain_mismatch"
      assert Map.has_key?(decode_payment_required!(conn)["extensions"], "sign-in-with-x")

      assert_receive {:telemetry, [:x402, :plug, :payment_rejected],
                      %{reason: {:siwx, :invalid_siwx_domain_mismatch}}}
    end

    test "answers 400 for headers that cannot be decoded", %{siwx: siwx} do
      opts = gate_opts(siwx: siwx)
      attach_telemetry([:x402, :plug, :payment_rejected])

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("sign-in-with-x", Base.encode64(~s({"domain":"x"})))
        |> run_request(opts)

      assert conn.status == 400
      assert decode_payment_required!(conn)["error"] == "invalid_siwx_header"

      assert_receive {:telemetry, [:x402, :plug, :payment_rejected],
                      %{reason: {:siwx_header, :invalid_payload}}}
    end

    test "an empty header is treated as absent", %{siwx: siwx} do
      conn =
        conn(:get, "/api/resource")
        |> put_req_header("sign-in-with-x", "")
        |> run_request(gate_opts(siwx: siwx))

      assert conn.status == 402
      assert decode_payment_required!(conn)["error"] == "PAYMENT-SIGNATURE header is required"
    end

    test "accepts the deprecated header format and emits the legacy event", %{
      siwx: siwx,
      storage: storage
    } do
      opts = gate_opts(siwx: siwx)
      :ok = ETSStorage.put(storage, @address, @access_resource, :paid, 60_000)
      attach_telemetry([:x402, :siwx, :legacy])
      challenge = fetch_challenge(opts)

      {:ok, message} =
        SIWX.encode(%{
          domain: "www.example.com",
          address: @address,
          statement: "Sign in",
          uri: "http://www.example.com",
          version: "1",
          chain_id: @evm_chain,
          nonce: challenge["info"]["nonce"],
          issued_at: challenge["info"]["issuedAt"],
          expiration_time: challenge["info"]["expirationTime"]
        })

      {:ok, signer} = LocalKey.new(@private_key)
      {:ok, signature} = LocalKey.sign_message(signer, message)
      header = Base.encode64(Jason.encode!(%{"message" => message, "signature" => signature}))

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("sign-in-with-x", header)
        |> run_request(opts)

      assert conn.status == 200
      assert conn.assigns[:x402_siwx_address] == @address
      assert_receive {:telemetry, [:x402, :siwx, :legacy], %{source: :gate, status: :ok}}
    end
  end

  describe "payer recording" do
    test "checksummed settlement payers authenticate with lowercase proofs", %{siwx: siwx} do
      {:ok, response} = @default_settle
      mixed = "0x19E7E376E7C213B7E7e7e46cc70A5dD086DAfF2A"
      settle = {:ok, %{response | body: Map.put(response.body, "payer", mixed)}}
      facilitator = start_mock_facilitator(settle: settle)
      opts = gate_opts(siwx: siwx, facilitator: facilitator)

      paid =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(opts)

      assert paid.status == 200

      authenticated =
        conn(:get, "/api/resource")
        |> put_req_header("sign-in-with-x", proof(opts))
        |> run_request(opts)

      assert authenticated.status == 200
      assert authenticated.assigns.x402_siwx_address == @address
    end

    test "a GET payment cannot authorize a differently priced POST", %{siwx: siwx} do
      facilitator = start_mock_facilitator()
      post_route = %{@route | method: :post, price: "50000"}
      opts = gate_opts(siwx: siwx, facilitator: facilitator, routes: [@route, post_route])

      paid =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(opts)

      assert paid.status == 200

      rejected =
        conn(:post, "/api/resource")
        |> put_req_header("sign-in-with-x", proof(opts))
        |> run_request(opts)

      assert rejected.status == 402
      assert hd(decode_payment_required!(rejected)["accepts"])["amount"] == "50000"

      allowed =
        conn(:get, "/api/resource")
        |> put_req_header("sign-in-with-x", proof(opts))
        |> run_request(opts)

      assert allowed.status == 200
    end

    test "any-method routes still scope grants by the actual request method",
         %{siwx: siwx, storage: storage} do
      facilitator = start_mock_facilitator()
      opts = gate_opts(siwx: siwx, facilitator: facilitator, routes: [%{@route | method: :any}])

      paid =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(opts)

      assert paid.status == 200
      assert {:ok, _record} = ETSStorage.get(storage, @address, @access_resource)
      assert {:error, :not_found} = ETSStorage.get(storage, @address, "POST " <> @resource)

      for method <- [:post, :delete, :head] do
        rejected =
          conn(method, "/api/resource")
          |> put_req_header("sign-in-with-x", proof(opts))
          |> run_request(opts)

        assert rejected.status == 402
      end
    end

    test "grants retain origin, port, query and raw-path boundaries", %{siwx: siwx} do
      facilitator = start_mock_facilitator()
      opts = gate_opts(siwx: siwx, facilitator: facilitator)

      paid =
        conn(:get, "/api/resource?item=1")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(opts)

      assert paid.status == 200

      for url <- [
            @resource,
            @resource <> "?item=2",
            "http://other.example.com/api/resource?item=1",
            "http://www.example.com:8080/api/resource?item=1",
            "https://www.example.com/api/resource?item=1",
            "http://www.example.com/api/%72esource?item=1"
          ] do
        rejected =
          conn(:get, url)
          |> put_req_header("sign-in-with-x", proof(opts))
          |> run_request(opts)

        assert rejected.status == 402
      end

      allowed =
        conn(:get, @resource <> "?item=1")
        |> put_req_header("sign-in-with-x", proof(opts))
        |> run_request(opts)

      assert allowed.status == 200
    end

    test "legacy URL-only grants cannot bypass method scoping", %{siwx: siwx, storage: storage} do
      :ok = ETSStorage.put(storage, @address, @resource, :legacy, 60_000)
      opts = gate_opts(siwx: siwx)

      rejected =
        conn(:get, "/api/resource")
        |> put_req_header("sign-in-with-x", proof(opts))
        |> run_request(opts)

      assert rejected.status == 402
    end

    test "handler rewrites cannot change the resource recorded after settlement",
         %{siwx: siwx, storage: storage} do
      opts = gate_opts(siwx: siwx, facilitator: start_mock_facilitator())

      prepared =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> PaymentGate.call(PaymentGate.init(opts))

      assert send_resp(%{prepared | method: "POST", query_string: "item=other"}, 200, "ok").status ==
               200

      assert {:ok, _record} = ETSStorage.get(storage, @address, @access_resource)

      assert {:error, :not_found} =
               ETSStorage.get(storage, @address, "POST " <> @resource <> "?item=other")
    end

    test "records the settle response payer so later proofs skip payment", %{
      siwx: siwx,
      storage: storage
    } do
      facilitator = start_mock_facilitator()
      opts = gate_opts(siwx: siwx, facilitator: facilitator)

      paid =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(opts)

      assert paid.status == 200
      assert_receive {:settle_called, _payload, _requirements}

      assert {:ok, %{payment_proof: %{"success" => true}}} =
               ETSStorage.get(storage, @address, @access_resource)

      authenticated =
        conn(:get, "/api/resource")
        |> put_req_header("sign-in-with-x", proof(opts))
        |> run_request(opts)

      assert authenticated.status == 200
      assert authenticated.assigns[:x402_siwx_address] == @address
    end

    test "falls back to the authorization's from when the settle response has no payer", %{
      siwx: siwx,
      storage: storage
    } do
      {:ok, %{body: body}} = @default_settle
      settle = {:ok, %{status: 200, body: Map.delete(body, "payer")}}
      facilitator = start_mock_facilitator(settle: settle)

      paid =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(gate_opts(siwx: siwx, facilitator: facilitator))

      assert paid.status == 200
      assert {:ok, _record} = ETSStorage.get(storage, @receiver, @access_resource)
      assert ETSStorage.get(storage, @address, @access_resource) == {:error, :not_found}
    end

    test "records nothing when neither the response nor the payload names a payer", %{
      siwx: siwx,
      storage: storage
    } do
      {:ok, %{body: body}} = @default_settle
      settle = {:ok, %{status: 200, body: Map.delete(body, "payer")}}
      facilitator = start_mock_facilitator(settle: settle)

      payload =
        update_in(valid_payment_payload(), ["payload", "authorization"], &Map.delete(&1, "from"))

      paid =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", encode_header(payload))
        |> run_request(gate_opts(siwx: siwx, facilitator: facilitator))

      assert paid.status == 200
      assert ETSStorage.get(storage, @receiver, @access_resource) == {:error, :not_found}
    end

    test "logs and still serves the response when storage rejects the record", %{cache: cache} do
      facilitator = start_mock_facilitator()
      siwx = @siwx ++ [storage: FailingStorage, nonce_cache: cache]

      log =
        capture_log(fn ->
          paid =
            conn(:get, "/api/resource")
            |> put_req_header("payment-signature", valid_payment_header())
            |> run_request(gate_opts(siwx: siwx, facilitator: facilitator))

          assert paid.status == 200
        end)

      assert log =~ "could not record sign-in-with-x payer"
    end

    test "a proof without a record falls through to payment when one is supplied", %{
      siwx: siwx,
      storage: storage
    } do
      facilitator = start_mock_facilitator()
      opts = gate_opts(siwx: siwx, facilitator: facilitator)

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("sign-in-with-x", proof(opts))
        |> put_req_header("payment-signature", valid_payment_header())
        |> run_request(opts)

      assert conn.status == 200
      assert_receive {:verify_called, _payload, _requirements}
      assert {:ok, _record} = ETSStorage.get(storage, @address, @access_resource)
    end
  end

  describe "extension echo" do
    test "a sign-in-with-x value in the route extensions is exempt from the echo check", %{
      siwx: siwx
    } do
      facilitator = start_mock_facilitator()

      route =
        Map.put(@route, :extensions, %{
          "sign-in-with-x" => %{"info" => %{"domain" => "stale.example.com"}}
        })

      payload =
        Map.put(valid_payment_payload(), "extensions", %{
          "sign-in-with-x" => %{"info" => %{"domain" => "other.example.com"}}
        })

      conn =
        conn(:get, "/api/resource")
        |> put_req_header("payment-signature", encode_header(payload))
        |> run_request(gate_opts(routes: [route], siwx: siwx, facilitator: facilitator))

      assert conn.status == 200
    end
  end

  # ---------------------------------------------------------------------------
  # Helpers
  # ---------------------------------------------------------------------------

  defp gate_opts(overrides \\ []) do
    Keyword.merge([routes: [@route], facilitator: self()], overrides)
  end

  defp siwx_opts(storage, cache) do
    @siwx ++ [storage: {ETSStorage, storage}, nonce_cache: cache]
  end

  defp run_request(conn, opts) do
    conn = PaymentGate.call(conn, PaymentGate.init(opts))

    case conn.halted do
      true -> conn
      false -> Plug.Conn.send_resp(conn, 200, "ok")
    end
  end

  defp decode_payment_required!(conn) do
    [header] = get_resp_header(conn, "payment-required")
    assert {:ok, payload} = PaymentRequired.decode(header)
    payload
  end

  defp challenge_of(conn), do: decode_payment_required!(conn)["extensions"]["sign-in-with-x"]

  defp fetch_challenge(opts) do
    conn(:get, "/api/resource") |> run_request(opts) |> challenge_of()
  end

  # Runs the real client flow: fetch a 402, sign the advertised challenge.
  defp proof(opts) do
    {:ok, signer} = LocalKey.new(@private_key)
    {:ok, signed} = SIWX.sign(fetch_challenge(opts), signer, chain_id: @evm_chain)
    {:ok, header} = SIWX.encode_signed(signed)
    header
  end

  defp attach_telemetry(event) do
    handler_id = {__MODULE__, event, System.unique_integer()}
    test_pid = self()

    :telemetry.attach(
      handler_id,
      event,
      fn name, _measurements, metadata, _config ->
        send(test_pid, {:telemetry, name, metadata})
      end,
      nil
    )

    on_exit(fn -> :telemetry.detach(handler_id) end)
  end

  defp start_cache do
    name = String.to_atom("gate_siwx_cache_#{System.unique_integer([:positive, :monotonic])}")
    start_supervised!({ETSCache, name: name, ttl_ms: 60_000})
    name
  end

  defp start_storage do
    suffix = System.unique_integer([:positive, :monotonic])
    name = String.to_atom("gate_siwx_storage_#{suffix}")
    table = String.to_atom("gate_siwx_storage_table_#{suffix}")
    start_supervised!({ETSStorage, name: name, table: table})
    name
  end

  defp valid_payment_payload do
    %{
      "x402Version" => 2,
      "resource" => %{
        "url" => @resource,
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
          "from" => @receiver,
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

  defp valid_payment_header, do: encode_header(valid_payment_payload())

  defp encode_header(payload) when is_map(payload) do
    payload |> Jason.encode!() |> Base.encode64()
  end

  defp start_mock_facilitator(opts \\ []) do
    owner = self()
    verify = Keyword.get(opts, :verify, @default_verify)
    settle = Keyword.get(opts, :settle, @default_settle)

    bypass = Bypass.open()
    stub_facilitator_endpoint(bypass, owner, "/verify", :verify_called, verify)
    stub_facilitator_endpoint(bypass, owner, "/settle", :settle_called, settle)

    start_facilitator(url: "http://localhost:#{bypass.port}")
  end

  defp stub_facilitator_endpoint(bypass, owner, path, tag, {:ok, %{status: status, body: body}}) do
    Bypass.stub(bypass, "POST", path, fn conn ->
      {:ok, request_body, conn} = Plug.Conn.read_body(conn)
      decoded = Jason.decode!(request_body)
      send(owner, {tag, decoded["paymentPayload"], decoded["paymentRequirements"]})
      Plug.Conn.resp(conn, status, Jason.encode!(body))
    end)
  end

  defp start_facilitator(opts) do
    suffix = System.unique_integer([:positive, :monotonic])
    finch = String.to_atom("gate_siwx_finch_#{suffix}")
    name = String.to_atom("gate_siwx_facilitator_#{suffix}")

    start_supervised!(Supervisor.child_spec({Finch, name: finch}, id: finch))

    start_supervised!(
      {Facilitator,
       Keyword.merge([name: name, finch: finch, max_retries: 0, receive_timeout_ms: 1_000], opts)}
    )

    name
  end
end
