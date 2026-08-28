defmodule X402.Plug.FacilitatorTest do
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias X402.EIP3009
  alias X402.Facilitator.Engine
  alias X402.Facilitator.SVMEngine
  alias X402.Plug.Facilitator, as: FacilitatorPlug
  alias X402.Scheme.ExactSVM
  alias X402.Signer.LocalKey
  alias X402.Signer.SolanaKey

  import X402.TestHelpers

  @payer_key "0x" <> String.duplicate("11", 32)
  @payer "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
  @facilitator_key "0x" <> String.duplicate("22", 32)
  @facilitator_address "0x1563915e194d8cfba1943570603f7606a3115508"
  @pay_to "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @network "eip155:84532"
  @tx_hash "0x" <> String.duplicate("cd", 32)

  # SVM golden fixture keys (see test/x402/scheme/exact_svm_test.exs).
  @svm_client_seed :binary.copy(<<1>>, 32)
  @svm_client "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"
  @svm_fee_payer_seed :binary.copy(<<2>>, 32)
  @svm_fee_payer "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu"
  @svm_pay_to "GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse"
  @svm_usdc "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
  @svm_blockhash "EZ3rST5dvHmbanh75jc4PuLfV96vp9fEYBVeNk4FfM1k"
  @svm_network "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

  setup [:setup_bypass, :setup_finch]

  # -- Fixtures ---------------------------------------------------------------

  defp requirements(overrides \\ %{}) do
    Map.merge(
      %{
        "scheme" => "exact",
        "network" => @network,
        "amount" => "10000",
        "asset" => @asset,
        "payTo" => @pay_to,
        "maxTimeoutSeconds" => 600,
        "extra" => %{"name" => "USDC", "version" => "2"}
      },
      overrides
    )
  end

  defp signed_payload(requirements) do
    {:ok, payer_signer} = LocalKey.new(@payer_key)
    {:ok, scheme_payload} = EIP3009.sign(requirements, payer_signer)
    %{"x402Version" => 2, "accepted" => requirements, "payload" => scheme_payload}
  end

  defp plug_options(context, overrides \\ []) do
    rpc =
      X402.TestRPCStub.stub_rpc(
        context.bypass,
        context.finch,
        Keyword.get(overrides, :stub, %{})
      )

    {:ok, signer} = LocalKey.new(@facilitator_key)

    {:ok, engine} =
      Engine.new(
        rpc: rpc,
        signer: signer,
        networks: [@network],
        receipt_timeout_ms: 500,
        receipt_interval_ms: 10
      )

    FacilitatorPlug.init([engine: engine] ++ Keyword.delete(overrides, :stub))
  end

  defp wire_body(payload, requirements) do
    Jason.encode!(%{
      "x402Version" => 2,
      "paymentPayload" => payload,
      "paymentRequirements" => requirements
    })
  end

  defp post_json(options, path, body) do
    :post
    |> conn(path, body)
    |> put_req_header("content-type", "application/json")
    |> FacilitatorPlug.call(options)
  end

  defp json_response(conn) do
    assert conn.state == :sent
    assert {"content-type", "application/json; charset=utf-8"} in conn.resp_headers
    Jason.decode!(conn.resp_body)
  end

  # SVM fixtures for the multi-engine tests.

  defp svm_requirements(overrides \\ %{}) do
    Map.merge(
      %{
        "scheme" => "exact",
        "network" => @svm_network,
        "amount" => "1000",
        "asset" => @svm_usdc,
        "payTo" => @svm_pay_to,
        "maxTimeoutSeconds" => 60,
        "extra" => %{
          "feePayer" => @svm_fee_payer,
          "memo" => "pi_3abc123def456",
          "recentBlockhash" => @svm_blockhash
        }
      },
      overrides
    )
  end

  defp svm_signed_payload(requirements) do
    {:ok, client_signer} = SolanaKey.new(@svm_client_seed)
    {:ok, scheme_payload} = ExactSVM.sign(requirements, client_signer, [])
    %{"x402Version" => 2, "accepted" => requirements, "payload" => scheme_payload}
  end

  defp svm_engine(finch) do
    svm_bypass = Bypass.open()
    rpc = X402.TestSolanaRPCStub.stub_rpc(svm_bypass, finch)
    {:ok, signer} = SolanaKey.new(@svm_fee_payer_seed)

    {:ok, engine} =
      SVMEngine.new(
        rpc: rpc,
        signer: signer,
        networks: [@svm_network],
        confirm_timeout_ms: 500,
        confirm_interval_ms: 10
      )

    engine
  end

  defp multi_engine_options(context) do
    single = plug_options(context)
    [evm_engine] = single.engines
    FacilitatorPlug.init(engines: [evm_engine, svm_engine(context.finch)])
  end

  # -- init/1 -----------------------------------------------------------------

  describe "init/1" do
    test "requires a built engine" do
      assert_raise NimbleOptions.ValidationError, fn ->
        FacilitatorPlug.init([])
      end

      assert_raise NimbleOptions.ValidationError, fn ->
        FacilitatorPlug.init(engine: :nope)
      end
    end

    test "validates the engines list" do
      assert_raise NimbleOptions.ValidationError, fn ->
        FacilitatorPlug.init(engines: [])
      end

      assert_raise NimbleOptions.ValidationError, fn ->
        FacilitatorPlug.init(engines: [:nope])
      end

      # Struct without the engine contract.
      assert_raise NimbleOptions.ValidationError, fn ->
        FacilitatorPlug.init(engines: [%URI{}])
      end
    end

    test "engine and engines are mutually exclusive", context do
      single = plug_options(context)
      [engine] = single.engines

      assert_raise NimbleOptions.ValidationError, fn ->
        FacilitatorPlug.init(engine: engine, engines: [engine])
      end
    end

    test "normalizes a single engine to the engines list", context do
      assert %{engines: [%Engine{}]} = plug_options(context)
    end
  end

  # -- GET /supported ---------------------------------------------------------

  describe "GET /supported" do
    test "returns the engine's supported response", context do
      conn = :get |> conn("/supported") |> FacilitatorPlug.call(plug_options(context))

      assert conn.status == 200

      assert json_response(conn) == %{
               "kinds" => [
                 %{"x402Version" => 2, "scheme" => "exact", "network" => @network}
               ],
               "extensions" => [],
               "signers" => %{"eip155:*" => [@facilitator_address]}
             }
    end
  end

  # -- POST /verify -----------------------------------------------------------

  describe "POST /verify" do
    test "answers 200 with the verify response for a valid payment", context do
      options = plug_options(context)
      requirements = requirements()

      conn = post_json(options, "/verify", wire_body(signed_payload(requirements), requirements))

      assert conn.status == 200
      assert json_response(conn) == %{"isValid" => true, "payer" => @payer}
    end

    test "accepts a body already parsed by Plug.Parsers", context do
      # Behind a Phoenix endpoint or `forward`, Plug.Parsers has consumed the
      # raw body — the wire object arrives in body_params and a second
      # read_body would be empty.
      options = plug_options(context)
      requirements = requirements()

      wire = %{
        "x402Version" => 2,
        "paymentPayload" => signed_payload(requirements),
        "paymentRequirements" => requirements
      }

      conn =
        :post
        |> conn("/verify", "")
        |> Map.put(:body_params, wire)
        |> put_req_header("content-type", "application/json")
        |> FacilitatorPlug.call(options)

      assert conn.status == 200
      assert json_response(conn) == %{"isValid" => true, "payer" => @payer}
    end

    test "rejects a parsed body that is not the strict wire object", context do
      options = plug_options(context)

      conn =
        :post
        |> conn("/verify", "")
        |> Map.put(:body_params, %{"x402Version" => 2, "extra" => true})
        |> put_req_header("content-type", "application/json")
        |> FacilitatorPlug.call(options)

      assert conn.status == 400
      assert json_response(conn)["reason"] == "invalid_wire_object"
    end

    test "answers 200 with isValid false for a rejected payment", context do
      options = plug_options(context)
      requirements = requirements()
      payload = signed_payload(requirements)
      tampered = requirements(%{"amount" => "20000"})

      conn = post_json(options, "/verify", wire_body(payload, tampered))

      assert conn.status == 200

      assert json_response(conn) == %{
               "isValid" => false,
               "invalidReason" => "invalid_exact_evm_payload_authorization_value_mismatch",
               "payer" => @payer
             }
    end

    test "answers 500 with an opaque body on infrastructure errors", context do
      options = plug_options(context)
      requirements = requirements()
      body = wire_body(signed_payload(requirements), requirements)
      Bypass.down(context.bypass)

      conn = post_json(options, "/verify", body)

      assert conn.status == 500
      assert json_response(conn) == %{"error" => "internal_server_error"}
    end
  end

  # -- POST /settle -----------------------------------------------------------

  describe "POST /settle" do
    test "answers 200 with the settle response", context do
      options = plug_options(context)
      requirements = requirements()

      conn = post_json(options, "/settle", wire_body(signed_payload(requirements), requirements))

      assert conn.status == 200

      assert json_response(conn) == %{
               "success" => true,
               "transaction" => @tx_hash,
               "network" => @network,
               "payer" => @payer
             }
    end

    test "answers 200 with success false for a rejected settlement", context do
      options = plug_options(context)
      requirements = requirements()
      payload = signed_payload(requirements)
      tampered = requirements(%{"amount" => "20000"})

      conn = post_json(options, "/settle", wire_body(payload, tampered))

      assert conn.status == 200
      assert %{"success" => false, "transaction" => ""} = json_response(conn)
    end
  end

  # -- Body validation --------------------------------------------------------

  describe "body validation" do
    test "rejects invalid JSON with 400", context do
      conn = post_json(plug_options(context), "/verify", "{not json")

      assert conn.status == 400
      assert json_response(conn) == %{"error" => "invalid_request", "reason" => "invalid_json"}
    end

    test "rejects a wrong x402Version with 400", context do
      body =
        Jason.encode!(%{
          "x402Version" => 1,
          "paymentPayload" => %{},
          "paymentRequirements" => %{}
        })

      conn = post_json(plug_options(context), "/verify", body)

      assert conn.status == 400

      assert json_response(conn) == %{
               "error" => "invalid_request",
               "reason" => "invalid_x402_version"
             }
    end

    test "rejects missing keys, extra keys, and non-map sections with 400", context do
      options = plug_options(context)

      missing = Jason.encode!(%{"x402Version" => 2, "paymentPayload" => %{}})

      extra =
        Jason.encode!(%{
          "x402Version" => 2,
          "paymentPayload" => %{},
          "paymentRequirements" => %{},
          "sneaky" => true
        })

      non_map =
        Jason.encode!(%{
          "x402Version" => 2,
          "paymentPayload" => "nope",
          "paymentRequirements" => %{}
        })

      for body <- [missing, extra, non_map, "[]", "42"] do
        conn = post_json(options, "/settle", body)
        assert conn.status == 400

        assert json_response(conn) == %{
                 "error" => "invalid_request",
                 "reason" => "invalid_wire_object"
               }
      end
    end

    test "rejects bodies over the cap with 413", context do
      options = plug_options(context, max_body_bytes: 64)
      body = Jason.encode!(%{"padding" => String.duplicate("a", 200)})

      conn = post_json(options, "/verify", body)

      assert conn.status == 413
      assert json_response(conn) == %{"error" => "payload_too_large"}
    end
  end

  # -- Authentication ---------------------------------------------------------

  describe "authentication" do
    test "requires the bearer token on every endpoint when configured", context do
      options = plug_options(context, auth_token: "secret")

      unauthorized = :get |> conn("/supported") |> FacilitatorPlug.call(options)
      assert unauthorized.status == 401
      assert json_response(unauthorized) == %{"error" => "unauthorized"}

      wrong =
        :get
        |> conn("/supported")
        |> put_req_header("authorization", "Bearer wrong")
        |> FacilitatorPlug.call(options)

      assert wrong.status == 401

      authorized =
        :get
        |> conn("/supported")
        |> put_req_header("authorization", "Bearer secret")
        |> FacilitatorPlug.call(options)

      assert authorized.status == 200
    end
  end

  # -- Routing ----------------------------------------------------------------

  describe "routing" do
    test "unknown paths answer 404", context do
      conn = :get |> conn("/nope") |> FacilitatorPlug.call(plug_options(context))

      assert conn.status == 404
      assert json_response(conn) == %{"error" => "not_found"}
    end

    test "discovery resources answers 404 with a documented reason", context do
      conn =
        :get
        |> conn("/discovery/resources")
        |> FacilitatorPlug.call(plug_options(context))

      assert conn.status == 404
      assert json_response(conn) == %{"error" => "discovery_not_supported"}
    end

    test "known paths with the wrong method answer 405", context do
      options = plug_options(context)

      for {method, path} <- [{:get, "/verify"}, {:get, "/settle"}, {:post, "/supported"}] do
        conn = method |> conn(path) |> FacilitatorPlug.call(options)
        assert conn.status == 405
        assert json_response(conn) == %{"error" => "method_not_allowed"}
      end
    end
  end

  # -- Multiple engines ---------------------------------------------------------

  describe "multiple engines" do
    test "routes verify by the requirements' network", context do
      options = multi_engine_options(context)

      evm_requirements = requirements()

      evm_conn =
        post_json(
          options,
          "/verify",
          wire_body(signed_payload(evm_requirements), evm_requirements)
        )

      assert evm_conn.status == 200
      assert json_response(evm_conn) == %{"isValid" => true, "payer" => @payer}

      svm_requirements = svm_requirements()

      svm_conn =
        post_json(
          options,
          "/verify",
          wire_body(svm_signed_payload(svm_requirements), svm_requirements)
        )

      assert svm_conn.status == 200
      assert json_response(svm_conn) == %{"isValid" => true, "payer" => @svm_client}
    end

    test "routes settle to the SVM engine", context do
      options = multi_engine_options(context)
      svm_requirements = svm_requirements()

      conn =
        post_json(
          options,
          "/settle",
          wire_body(svm_signed_payload(svm_requirements), svm_requirements)
        )

      assert conn.status == 200

      assert %{
               "success" => true,
               "transaction" => signature,
               "network" => @svm_network,
               "payer" => @svm_client
             } = json_response(conn)

      assert signature != ""
      assert_received {:solana_rpc, "sendTransaction", _params}
    end

    test "answers 200 protocol rejections when no engine matches", context do
      options = multi_engine_options(context)
      payload = signed_payload(requirements())

      # A scheme some engine serves, on a network none does.
      wrong_network = requirements(%{"network" => "eip155:1"})
      conn = post_json(options, "/verify", wire_body(payload, wrong_network))
      assert conn.status == 200
      assert json_response(conn) == %{"isValid" => false, "invalidReason" => "invalid_network"}

      # A scheme no engine serves.
      wrong_scheme = requirements(%{"scheme" => "upto"})
      conn = post_json(options, "/verify", wire_body(payload, wrong_scheme))
      assert conn.status == 200

      assert json_response(conn) == %{
               "isValid" => false,
               "invalidReason" => "unsupported_scheme"
             }

      conn = post_json(options, "/settle", wire_body(payload, wrong_network))
      assert conn.status == 200

      assert json_response(conn) == %{
               "success" => false,
               "errorReason" => "invalid_network",
               "transaction" => "",
               "network" => "eip155:1"
             }
    end

    test "GET /supported merges kinds, extensions, and signers", context do
      options = multi_engine_options(context)

      conn = :get |> conn("/supported") |> FacilitatorPlug.call(options)

      assert conn.status == 200

      assert json_response(conn) == %{
               "kinds" => [
                 %{"x402Version" => 2, "scheme" => "exact", "network" => @network},
                 %{
                   "x402Version" => 2,
                   "scheme" => "exact",
                   "network" => @svm_network,
                   "extra" => %{"feePayer" => @svm_fee_payer}
                 }
               ],
               "extensions" => [],
               "signers" => %{
                 "eip155:*" => [@facilitator_address],
                 "solana:*" => [@svm_fee_payer]
               }
             }
    end
  end
end
