defmodule X402.Client.FinchTest do
  use ExUnit.Case, async: false

  alias Plug.Conn
  alias X402.Client
  alias X402.Client.Finch, as: FinchClient
  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.PaymentRequired
  alias X402.PaymentResponse
  alias X402.PaymentSignature
  alias X402.Plug.PaymentGate
  alias X402.Signer.LocalKey

  import X402.TestHelpers

  @receiver "0x2222222222222222222222222222222222222222"
  @contract "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

  @requirements %{
    "scheme" => "exact",
    "network" => "eip155:84532",
    "amount" => "10000",
    "asset" => @contract,
    "payTo" => @receiver,
    "maxTimeoutSeconds" => 300,
    "extra" => %{"name" => "USDC", "version" => "2"}
  }

  @payment_required %{
    "x402Version" => 2,
    "error" => "PAYMENT-SIGNATURE header is required",
    "resource" => %{"url" => "https://api.example.com/paid", "mimeType" => "application/json"},
    "accepts" => [@requirements],
    "extensions" => %{}
  }

  @settlement %{
    "success" => true,
    "transaction" => "0x" <> String.duplicate("ab", 32),
    "network" => "eip155:84532",
    "payer" => "0x1111111111111111111111111111111111111111"
  }

  setup :setup_bypass
  setup :setup_finch

  setup do
    {:ok, signer} = LocalKey.new(:crypto.strong_rand_bytes(32))
    {:ok, signer: signer}
  end

  defp url(bypass, path), do: "http://localhost:#{bypass.port}#{path}"

  defp respond_402(conn) do
    {:ok, header} = PaymentRequired.encode(@payment_required)

    conn
    |> Conn.put_resp_header("payment-required", header)
    |> Conn.resp(402, "{}")
  end

  describe "request/3 payment flow" do
    test "pays a 402 and returns the settled response", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      test_pid = self()

      Bypass.expect(bypass, "GET", "/paid", fn conn ->
        case Conn.get_req_header(conn, "payment-signature") do
          [] ->
            respond_402(conn)

          [header] ->
            send(test_pid, {:payment_header, header})
            {:ok, response_header} = PaymentResponse.encode(@settlement)

            conn
            |> Conn.put_resp_header("payment-response", response_header)
            |> Conn.resp(200, ~s({"data":42}))
        end
      end)

      assert {:ok, response} =
               FinchClient.request(finch, url(bypass, "/paid"), signer: signer)

      assert response.status == 200
      assert response.body == ~s({"data":42})
      assert response.payment_response == @settlement

      # The wire header we sent validates against the advertised requirements.
      assert_received {:payment_header, header}
      assert {:ok, payload} = PaymentSignature.decode_and_validate(header, @requirements)
      assert payload["accepted"] == @requirements
      assert payload["payload"]["authorization"]["to"] == @receiver
    end

    test "forwards :extensions enrichers to build_payment", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      alias X402.Extensions.EIP2612GasSponsoring

      test_pid = self()

      payment_required =
        Map.put(@payment_required, "extensions", %{
          "eip2612GasSponsoring" => EIP2612GasSponsoring.build_extension()
        })

      Bypass.expect(bypass, "GET", "/sponsored", fn conn ->
        case Conn.get_req_header(conn, "payment-signature") do
          [] ->
            {:ok, header} = PaymentRequired.encode(payment_required)

            conn
            |> Conn.put_resp_header("payment-required", header)
            |> Conn.resp(402, "{}")

          [header] ->
            send(test_pid, {:payment_header, header})
            {:ok, response_header} = PaymentResponse.encode(@settlement)

            conn
            |> Conn.put_resp_header("payment-response", response_header)
            |> Conn.resp(200, "{}")
        end
      end)

      assert {:ok, %{status: 200}} =
               FinchClient.request(finch, url(bypass, "/sponsored"),
                 signer: signer,
                 extensions: [EIP2612GasSponsoring.enricher(signer, nonce: "0")]
               )

      assert_received {:payment_header, header}
      assert {:ok, payload} = PaymentSignature.decode(header)
      assert {:ok, info} = EIP2612GasSponsoring.extract_info(payload)
      assert EIP2612GasSponsoring.validate_info(info) == :ok
      assert info["from"] == signer.address
    end

    test "returns non-402 responses untouched, without paying", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      Bypass.expect_once(bypass, "GET", "/free", fn conn ->
        Conn.resp(conn, 200, "free")
      end)

      assert {:ok, %{status: 200, body: "free", payment_response: nil}} =
               FinchClient.request(finch, url(bypass, "/free"), signer: signer)
    end

    test "returns a 402 without a PAYMENT-REQUIRED header as-is", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      Bypass.expect_once(bypass, "GET", "/not-x402", fn conn ->
        Conn.resp(conn, 402, "nope")
      end)

      assert {:ok, %{status: 402, body: "nope", payment_response: nil}} =
               FinchClient.request(finch, url(bypass, "/not-x402"), signer: signer)
    end

    test "never pays twice: a second 402 is returned without another attempt", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      counter = :counters.new(1, [])

      Bypass.expect(bypass, "GET", "/always-402", fn conn ->
        :counters.add(counter, 1, 1)
        respond_402(conn)
      end)

      assert {:ok, %{status: 402}} =
               FinchClient.request(finch, url(bypass, "/always-402"), signer: signer)

      assert :counters.get(counter, 1) == 2
    end

    test "refuses to pay when the request already carries a payment", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      Bypass.expect_once(bypass, "GET", "/paid", fn conn -> respond_402(conn) end)

      assert FinchClient.request(finch, url(bypass, "/paid"),
               signer: signer,
               headers: [{"PAYMENT-SIGNATURE", "stale"}]
             ) == {:error, :payment_already_attempted}
    end

    test "the on_payment_required hook sees the offer and can cancel", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      test_pid = self()
      Bypass.expect_once(bypass, "GET", "/paid", fn conn -> respond_402(conn) end)

      assert FinchClient.request(finch, url(bypass, "/paid"),
               signer: signer,
               on_payment_required: fn payment_required ->
                 send(test_pid, {:offer, payment_required})
                 :cancel
               end
             ) == {:error, :payment_cancelled}

      assert_received {:offer, offer}
      assert offer["accepts"] == [@requirements]
    end

    test "selection options narrow what the client will pay", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      Bypass.expect_once(bypass, "GET", "/paid", fn conn -> respond_402(conn) end)

      assert FinchClient.request(finch, url(bypass, "/paid"),
               signer: signer,
               max_amount: "100"
             ) == {:error, :no_acceptable_requirements}
    end

    test "returns a structured error for an invalid PAYMENT-REQUIRED header", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      Bypass.expect_once(bypass, "GET", "/paid", fn conn ->
        conn
        |> Conn.put_resp_header("payment-required", "%%%not-base64%%%")
        |> Conn.resp(402, "{}")
      end)

      assert FinchClient.request(finch, url(bypass, "/paid"), signer: signer) ==
               {:error, {:invalid_payment_required, :invalid_base64}}
    end

    test "returns transport errors", %{bypass: bypass, finch: finch, signer: signer} do
      Bypass.down(bypass)

      assert {:error, {:transport_error, _reason}} =
               FinchClient.request(finch, url(bypass, "/paid"), signer: signer)
    end

    test "a hook returning anything but :cancel continues the payment", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      Bypass.expect(bypass, "GET", "/paid", fn conn ->
        case Conn.get_req_header(conn, "payment-signature") do
          [] -> respond_402(conn)
          [_header] -> Conn.resp(conn, 200, "paid")
        end
      end)

      assert {:ok, %{status: 200, body: "paid"}} =
               FinchClient.request(finch, url(bypass, "/paid"),
                 signer: signer,
                 on_payment_required: fn _payment_required -> :ok end
               )
    end

    test "an unparseable PAYMENT-RESPONSE header yields payment_response: nil", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      Bypass.expect_once(bypass, "GET", "/paid", fn conn ->
        conn
        |> Conn.put_resp_header("payment-response", "%%%")
        |> Conn.resp(200, "ok")
      end)

      assert {:ok, %{status: 200, payment_response: nil}} =
               FinchClient.request(finch, url(bypass, "/paid"), signer: signer)
    end

    test "rejects plaintext non-loopback URLs", %{finch: finch, signer: signer} do
      assert FinchClient.request(finch, "http://example.com/paid", signer: signer) ==
               {:error, :insecure_url}
    end

    test "accepts https URLs", %{finch: finch, signer: signer} do
      # TLS to a closed local port: passes URL validation, fails at transport.
      assert {:error, {:transport_error, _reason}} =
               FinchClient.request(finch, "https://localhost:1", signer: signer)
    end

    test "validates options", %{finch: finch} do
      assert_raise NimbleOptions.ValidationError, fn ->
        FinchClient.request(finch, "https://example.com", [])
      end

      assert_raise NimbleOptions.ValidationError, fn ->
        FinchClient.request(finch, "https://example.com", signer: :nope)
      end

      assert_raise NimbleOptions.ValidationError, fn ->
        FinchClient.request(finch, "https://example.com", signer: %URI{})
      end

      {:ok, signer} = LocalKey.new(:crypto.strong_rand_bytes(32))

      assert_raise NimbleOptions.ValidationError, fn ->
        FinchClient.request(finch, "https://example.com",
          signer: signer,
          headers: [{"name", 1}]
        )
      end

      assert_raise NimbleOptions.ValidationError, fn ->
        FinchClient.request(finch, "https://example.com",
          signer: signer,
          headers: "nope"
        )
      end
    end
  end

  describe "end-to-end against X402.Plug.PaymentGate" do
    test "full 402 → sign → verify → settle loop through this SDK's own gate", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      facilitator = start_bypass_facilitator(self())
      cache = start_supervised!({ETSCache, []})

      gate_opts =
        PaymentGate.init(
          facilitator: facilitator,
          payment_identifier_cache: cache,
          routes: [
            %{
              method: :get,
              path: "/premium",
              price: "10000",
              network: "eip155:84532",
              asset: @contract,
              pay_to: @receiver,
              max_timeout_seconds: 300,
              extra: %{"name" => "USDC", "version" => "2"}
            }
          ]
        )

      Bypass.expect(bypass, "GET", "/premium", fn conn ->
        conn = PaymentGate.call(conn, gate_opts)

        case conn.halted do
          true -> conn
          false -> Conn.send_resp(conn, 200, ~s({"premium":true}))
        end
      end)

      assert {:ok, response} =
               FinchClient.request(finch, url(bypass, "/premium"), signer: signer)

      assert response.status == 200
      assert response.body == ~s({"premium":true})

      assert %{"success" => true, "transaction" => "0x" <> _tx, "network" => "eip155:84532"} =
               response.payment_response

      # The gate verified and settled the exact payload we signed.
      assert_received {:facilitator_verify, verify_payload, verify_requirements}
      assert verify_payload["payload"]["authorization"]["from"] == signer.address
      assert verify_requirements["payTo"] == @receiver

      assert_received {:facilitator_settle, settle_payload, _settle_requirements}
      assert settle_payload["payload"]["authorization"]["value"] == "10000"
    end
  end

  describe "without the Finch dependency" do
    test "build_payment and encode_payment stay usable with any HTTP client", %{signer: signer} do
      # The transport-agnostic core drives the same flow without Finch:
      {:ok, payload} = Client.build_payment(@payment_required, signer)
      {:ok, header} = Client.encode_payment(payload)

      assert {:ok, _decoded} = PaymentSignature.decode_and_validate(header, @requirements)
    end
  end

  # A real caller-side X402.Facilitator over a Bypass HTTP stub, so the gate is
  # exercised end-to-end exactly as in production (the facilitator client
  # executes verify/settle in the calling process over HTTP).
  defp start_bypass_facilitator(owner) do
    bypass = Bypass.open()

    Bypass.stub(bypass, "POST", "/verify", fn conn ->
      {:ok, body, conn} = Conn.read_body(conn)
      decoded = Jason.decode!(body)

      send(
        owner,
        {:facilitator_verify, decoded["paymentPayload"], decoded["paymentRequirements"]}
      )

      response = %{
        "isValid" => true,
        "payer" => decoded["paymentPayload"]["payload"]["authorization"]["from"]
      }

      Conn.resp(conn, 200, Jason.encode!(response))
    end)

    Bypass.stub(bypass, "POST", "/settle", fn conn ->
      {:ok, body, conn} = Conn.read_body(conn)
      decoded = Jason.decode!(body)

      send(
        owner,
        {:facilitator_settle, decoded["paymentPayload"], decoded["paymentRequirements"]}
      )

      response = %{
        "success" => true,
        "transaction" => "0x" <> String.duplicate("cd", 32),
        "network" => decoded["paymentRequirements"]["network"],
        "payer" => decoded["paymentPayload"]["payload"]["authorization"]["from"]
      }

      Conn.resp(conn, 200, Jason.encode!(response))
    end)

    suffix = System.unique_integer([:positive, :monotonic])
    facilitator_finch = String.to_atom("finch_client_facilitator_finch_#{suffix}")
    name = String.to_atom("finch_client_facilitator_#{suffix}")

    start_supervised!(
      Supervisor.child_spec({Finch, name: facilitator_finch}, id: facilitator_finch)
    )

    start_supervised!(
      {X402.Facilitator,
       name: name,
       finch: facilitator_finch,
       url: "http://localhost:#{bypass.port}",
       max_retries: 0,
       receive_timeout_ms: 2_000}
    )
  end
end
