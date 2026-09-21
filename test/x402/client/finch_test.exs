defmodule X402.Client.FinchTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Plug.Conn
  alias X402.Client
  alias X402.Client.Budget
  alias X402.Client.Finch, as: FinchClient
  alias X402.Client.Policy
  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.Extensions.SIWX
  alias X402.Extensions.SIWX.ETSStorage
  alias X402.PaymentRequired
  alias X402.PaymentResponse
  alias X402.PaymentSignature
  alias X402.Plug.PaymentGate
  alias X402.Signer.LocalKey
  alias X402.Signer.SolanaKey
  alias X402.Solana.Transaction

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
    test "accepts a SolanaKey and signs an SVM payment before retrying", %{
      bypass: bypass,
      finch: finch
    } do
      {:ok, signer} = SolanaKey.new(:binary.copy(<<1>>, 32))

      requirements = %{
        "scheme" => "exact",
        "network" => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        "amount" => "1000",
        "asset" => "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
        "payTo" => "GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse",
        "maxTimeoutSeconds" => 60,
        "extra" => %{
          "feePayer" => "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu",
          "recentBlockhash" => "EZ3rST5dvHmbanh75jc4PuLfV96vp9fEYBVeNk4FfM1k"
        }
      }

      payment_required = %{@payment_required | "accepts" => [requirements]}
      test_pid = self()

      Bypass.expect_once(bypass, "GET", "/solana", fn conn ->
        assert Conn.get_req_header(conn, "payment-signature") == []
        {:ok, header} = PaymentRequired.encode(payment_required)

        Bypass.expect_once(bypass, "GET", "/solana", fn retry ->
          [payment_header] = Conn.get_req_header(retry, "payment-signature")
          send(test_pid, {:payment_header, payment_header})
          Conn.resp(retry, 200, "paid")
        end)

        conn
        |> Conn.put_resp_header("payment-required", header)
        |> Conn.resp(402, "{}")
      end)

      assert {:ok, %{status: 200, body: "paid"}} =
               FinchClient.request(finch, url(bypass, "/solana"), signer: signer)

      assert_received {:payment_header, header}
      assert {:ok, payload} = PaymentSignature.decode_and_validate(header, requirements)
      assert payload["accepted"] == requirements
      assert {:ok, transaction} = Base.decode64(payload["payload"]["transaction"])
      assert {:ok, decoded} = Transaction.decode(transaction)
      assert [<<0::512>>, signature] = decoded.signatures
      {:ok, public_key} = X402.Solana.decode_address(signer.address)

      assert :crypto.verify(:eddsa, :none, decoded.message_bytes, signature, [
               public_key,
               :ed25519
             ])
    end

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

  describe "spend controls" do
    @no_spend_limit_key {X402.Client, :no_spend_limit_warned}

    test "warns once per VM when no spend limit is configured", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      :persistent_term.erase(@no_spend_limit_key)
      Bypass.stub(bypass, "GET", "/free", fn conn -> Conn.resp(conn, 200, "free") end)

      first =
        capture_log(fn ->
          assert {:ok, %{status: 200}} =
                   FinchClient.request(finch, url(bypass, "/free"), signer: signer)
        end)

      assert first =~ "[X402.Client.Finch] no spend limit is configured"
      assert first =~ "max_amount:"

      second =
        capture_log(fn ->
          assert {:ok, %{status: 200}} =
                   FinchClient.request(finch, url(bypass, "/free"), signer: signer)
        end)

      refute second =~ "no spend limit"

      :persistent_term.erase(@no_spend_limit_key)

      limited =
        capture_log(fn ->
          for opts <- [
                [max_amount: "1"],
                [policies: [Policy.max_amount("1")]],
                [budget: start_supervised!({Budget, limit: 1}, id: :warn_budget)]
              ] do
            assert {:ok, %{status: 200}} =
                     FinchClient.request(finch, url(bypass, "/free"), [signer: signer] ++ opts)
          end
        end)

      refute limited =~ "no spend limit"
    end

    test "policies narrow what the client will pay", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      Bypass.expect_once(bypass, "GET", "/paid", fn conn -> respond_402(conn) end)

      assert FinchClient.request(finch, url(bypass, "/paid"),
               signer: signer,
               policies: [Policy.networks(["solana:*"])]
             ) == {:error, :no_acceptable_requirements}

      Bypass.expect_once(bypass, "GET", "/paid", fn conn -> respond_402(conn) end)

      assert FinchClient.request(finch, url(bypass, "/paid"),
               signer: signer,
               policies: [fn _requirements, _payment_required -> {:error, :nope} end]
             ) == {:error, :nope}
    end

    test "reserves the amount against the budget and keeps it once the server answers 2xx", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      budget = start_supervised!({Budget, limit: "15000"})
      counter = :counters.new(1, [])

      Bypass.expect(bypass, "GET", "/paid", fn conn ->
        case Conn.get_req_header(conn, "payment-signature") do
          [] ->
            respond_402(conn)

          [_header] ->
            :counters.add(counter, 1, 1)
            Conn.resp(conn, 200, "paid")
        end
      end)

      assert {:ok, %{status: 200}} =
               FinchClient.request(finch, url(bypass, "/paid"), signer: signer, budget: budget)

      assert Budget.spent(budget) == %{
               total: 10_000,
               per_asset: %{String.downcase(@contract) => 10_000}
             }

      # The second payment would exceed the budget: nothing is signed or sent.
      assert {:error, {:budget_exceeded, details}} =
               FinchClient.request(finch, url(bypass, "/paid"), signer: signer, budget: budget)

      assert details == %{
               scope: :total,
               asset: @contract,
               amount: 10_000,
               limit: 15_000,
               spent: 10_000
             }

      assert :counters.get(counter, 1) == 1
      assert Budget.spent(budget).total == 10_000
    end

    test "releases the reservation when the paid retry is not accepted", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      budget = start_supervised!({Budget, limit: 10_000})

      # Rejected payment: a second 402.
      Bypass.expect(bypass, "GET", "/always-402", fn conn -> respond_402(conn) end)

      assert {:ok, %{status: 402}} =
               FinchClient.request(finch, url(bypass, "/always-402"),
                 signer: signer,
                 budget: budget
               )

      assert Budget.spent(budget).total == 0

      # Server error without a receipt.
      Bypass.expect(bypass, "GET", "/flaky", fn conn ->
        case Conn.get_req_header(conn, "payment-signature") do
          [] -> respond_402(conn)
          [_header] -> Conn.resp(conn, 500, "oops")
        end
      end)

      assert {:ok, %{status: 500}} =
               FinchClient.request(finch, url(bypass, "/flaky"), signer: signer, budget: budget)

      assert Budget.spent(budget).total == 0

      # Transport error on the paid retry.
      Bypass.expect(bypass, "GET", "/slow", fn conn ->
        case Conn.get_req_header(conn, "payment-signature") do
          [] ->
            respond_402(conn)

          [_header] ->
            Process.sleep(300)
            Conn.resp(conn, 200, "late")
        end
      end)

      assert {:error, {:transport_error, _reason}} =
               FinchClient.request(finch, url(bypass, "/slow"),
                 signer: signer,
                 budget: budget,
                 receive_timeout_ms: 100
               )

      assert Budget.spent(budget).total == 0
      Bypass.pass(bypass)
    end

    test "a successful receipt counts as spent even on a non-2xx status", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      budget = start_supervised!({Budget, limit: 10_000})

      Bypass.expect(bypass, "GET", "/settled-anyway", fn conn ->
        case Conn.get_req_header(conn, "payment-signature") do
          [] ->
            respond_402(conn)

          [_header] ->
            {:ok, response_header} = PaymentResponse.encode(@settlement)

            conn
            |> Conn.put_resp_header("payment-response", response_header)
            |> Conn.resp(503, "settled but failed")
        end
      end)

      assert {:ok, %{status: 503, payment_response: @settlement}} =
               FinchClient.request(finch, url(bypass, "/settled-anyway"),
                 signer: signer,
                 budget: budget
               )

      assert Budget.spent(budget).total == 10_000
    end

    test "validates budget, policies, and hooks options", %{finch: finch, signer: signer} do
      assert_raise NimbleOptions.ValidationError, ~r/budget/, fn ->
        FinchClient.request(finch, "https://example.com", signer: signer, budget: "budget")
      end

      assert_raise NimbleOptions.ValidationError, ~r/policies/, fn ->
        FinchClient.request(finch, "https://example.com", signer: signer, policies: [& &1])
      end

      assert_raise NimbleOptions.ValidationError, ~r/hooks/, fn ->
        FinchClient.request(finch, "https://example.com", signer: signer, hooks: Enum)
      end
    end
  end

  describe "sign-in-with-x" do
    @evm_chain "eip155:8453"
    @solana_chain "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"

    setup do
      owner = self()
      handler_id = "finch-siwx-#{System.unique_integer([:positive])}"

      :telemetry.attach(
        handler_id,
        [:x402, :client, :siwx],
        fn _event, _measurements, metadata, _config ->
          if self() == owner, do: send(owner, {:siwx, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)
      :ok
    end

    defp siwx_server_opts(bypass, chains \\ [@evm_chain]) do
      [
        domain: "localhost",
        uri: "http://localhost:#{bypass.port}",
        supported_chains: Enum.map(chains, &%{chain_id: &1})
      ]
    end

    defp respond_402_with_challenge(conn, bypass, chains \\ [@evm_chain]) do
      challenge = SIWX.challenge(siwx_server_opts(bypass, chains))

      payment_required =
        Map.put(@payment_required, "extensions", %{"sign-in-with-x" => challenge})

      {:ok, header} = PaymentRequired.encode(payment_required)

      conn
      |> Conn.put_resp_header("payment-required", header)
      |> Conn.resp(402, "{}")
    end

    defp verify_proof(conn, bypass, chains \\ [@evm_chain]) do
      [header] = Conn.get_req_header(conn, "sign-in-with-x")
      SIWX.verify(header, siwx_server_opts(bypass, chains))
    end

    test "authenticates a remembered payer without paying", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      test_pid = self()

      Bypass.expect(bypass, "GET", "/premium", fn conn ->
        assert Conn.get_req_header(conn, "payment-signature") == []

        case Conn.get_req_header(conn, "sign-in-with-x") do
          [] ->
            respond_402_with_challenge(conn, bypass)

          [_header] ->
            assert {:ok, identity} = verify_proof(conn, bypass)
            send(test_pid, {:authenticated, identity})
            Conn.resp(conn, 200, "welcome back")
        end
      end)

      assert {:ok, response} =
               FinchClient.request(finch, url(bypass, "/premium"),
                 signer: signer,
                 max_amount: "10000",
                 siwx: [chain_id: @evm_chain]
               )

      assert %{status: 200, body: "welcome back", siwx_authenticated: true, payment_response: nil} =
               response

      assert_received {:authenticated, %{address: address, chain_id: @evm_chain}}
      assert address == signer.address

      assert_received {:siwx,
                       %{
                         status: :ok,
                         transport: :http,
                         chain_id: @evm_chain,
                         outcome: :authenticated
                       }}

      refute_received {:siwx, _metadata}
    end

    test "falls back to payment with a fresh proof when the address is unknown", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      test_pid = self()

      Bypass.expect(bypass, "GET", "/premium", fn conn ->
        siwx = Conn.get_req_header(conn, "sign-in-with-x")
        payment = Conn.get_req_header(conn, "payment-signature")

        case {siwx, payment} do
          {[], []} ->
            respond_402_with_challenge(conn, bypass)

          {[_proof], []} ->
            assert {:ok, identity} = verify_proof(conn, bypass)
            send(test_pid, {:proof_without_payment, identity.fields["nonce"]})
            respond_402_with_challenge(conn, bypass)

          {[_proof], [payment_header]} ->
            assert {:ok, identity} = verify_proof(conn, bypass)
            send(test_pid, {:proof_with_payment, identity.fields["nonce"], payment_header})
            {:ok, response_header} = PaymentResponse.encode(@settlement)

            conn
            |> Conn.put_resp_header("payment-response", response_header)
            |> Conn.resp(200, "paid")
        end
      end)

      assert {:ok, response} =
               FinchClient.request(finch, url(bypass, "/premium"),
                 signer: signer,
                 max_amount: "10000",
                 siwx: [chain_id: :auto],
                 on_payment_required: fn payment_required ->
                   send(test_pid, {:consent, payment_required})
                   :ok
                 end
               )

      assert %{status: 200, body: "paid", siwx_authenticated: false} = response
      assert response.payment_response == @settlement

      assert_received {:proof_without_payment, first_nonce}
      assert_received {:proof_with_payment, second_nonce, payment_header}
      assert first_nonce != second_nonce
      assert {:ok, payload} = PaymentSignature.decode_and_validate(payment_header, @requirements)
      assert payload["payload"]["authorization"]["from"] == signer.address

      # Consent was asked once, for the challenge that was actually paid.
      assert_received {:consent, %{"extensions" => %{"sign-in-with-x" => %{"info" => info}}}}
      assert info["nonce"] == second_nonce
      refute_received {:consent, _payment_required}

      assert_received {:siwx,
                       %{
                         status: :ok,
                         transport: :http,
                         chain_id: @evm_chain,
                         outcome: :payment_required
                       }}

      refute_received {:siwx, _metadata}
    end

    test "chain_id: :auto follows the signer family", %{bypass: bypass, finch: finch} do
      {:ok, signer} = SolanaKey.new(:binary.copy(<<1>>, 32))
      chains = [@evm_chain, @solana_chain]
      test_pid = self()

      Bypass.expect(bypass, "GET", "/premium", fn conn ->
        case Conn.get_req_header(conn, "sign-in-with-x") do
          [] ->
            respond_402_with_challenge(conn, bypass, chains)

          [_header] ->
            assert {:ok, identity} = verify_proof(conn, bypass, chains)
            send(test_pid, {:authenticated, identity.chain_id})
            Conn.resp(conn, 200, "welcome back")
        end
      end)

      assert {:ok, %{status: 200, siwx_authenticated: true}} =
               FinchClient.request(finch, url(bypass, "/premium"),
                 signer: signer,
                 max_amount: "10000",
                 siwx: [chain_id: :auto]
               )

      assert_received {:authenticated, @solana_chain}

      assert_received {:siwx,
                       %{
                         status: :ok,
                         transport: :http,
                         chain_id: @solana_chain,
                         outcome: :authenticated
                       }}

      refute_received {:siwx, _metadata}
    end

    test "pays without a proof when the second 402 carries no challenge", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      test_pid = self()

      Bypass.expect(bypass, "GET", "/premium", fn conn ->
        siwx = Conn.get_req_header(conn, "sign-in-with-x")
        payment = Conn.get_req_header(conn, "payment-signature")

        case {siwx, payment} do
          {[], []} ->
            respond_402_with_challenge(conn, bypass)

          {[_proof], []} ->
            respond_402(conn)

          {[], [_payment]} ->
            send(test_pid, :paid_without_proof)
            Conn.resp(conn, 200, "paid")
        end
      end)

      assert {:ok, %{status: 200, siwx_authenticated: false}} =
               FinchClient.request(finch, url(bypass, "/premium"),
                 signer: signer,
                 max_amount: "10000",
                 siwx: [chain_id: @evm_chain]
               )

      assert_received :paid_without_proof
    end

    test "returns a rejected proof's response as-is", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      Bypass.expect(bypass, "GET", "/premium", fn conn ->
        case Conn.get_req_header(conn, "sign-in-with-x") do
          [] -> respond_402_with_challenge(conn, bypass)
          [_header] -> Conn.resp(conn, 401, "invalid_siwx_signature")
        end
      end)

      assert {:ok, %{status: 401, body: "invalid_siwx_signature", siwx_authenticated: false}} =
               FinchClient.request(finch, url(bypass, "/premium"),
                 signer: signer,
                 max_amount: "10000",
                 siwx: [chain_id: @evm_chain]
               )
    end

    test "surfaces unsupported chains and origin mismatches as {:siwx, reason}", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      Bypass.expect_once(bypass, "GET", "/premium", fn conn ->
        respond_402_with_challenge(conn, bypass)
      end)

      assert FinchClient.request(finch, url(bypass, "/premium"),
               signer: signer,
               max_amount: "10000",
               siwx: [chain_id: "eip155:1"]
             ) == {:error, {:siwx, :unsupported_chain}}

      assert_received {:siwx,
                       %{
                         status: :error,
                         transport: :http,
                         chain_id: "eip155:1",
                         reason: :unsupported_chain
                       }}

      Bypass.expect_once(bypass, "GET", "/premium", fn conn ->
        challenge =
          SIWX.challenge(
            domain: "api.example.com",
            uri: "https://api.example.com",
            supported_chains: [%{chain_id: @evm_chain}]
          )

        payment_required =
          Map.put(@payment_required, "extensions", %{"sign-in-with-x" => challenge})

        {:ok, header} = PaymentRequired.encode(payment_required)

        conn
        |> Conn.put_resp_header("payment-required", header)
        |> Conn.resp(402, "{}")
      end)

      assert FinchClient.request(finch, url(bypass, "/premium"),
               signer: signer,
               max_amount: "10000",
               siwx: [chain_id: @evm_chain]
             ) == {:error, {:siwx, :domain_mismatch}}

      assert_received {:siwx,
                       %{
                         status: :error,
                         transport: :http,
                         chain_id: nil,
                         reason: :domain_mismatch
                       }}

      Bypass.expect_once(bypass, "GET", "/premium", fn conn ->
        respond_402_with_challenge(conn, bypass)
      end)

      {:ok, solana} = SolanaKey.new(:binary.copy(<<1>>, 32))

      assert FinchClient.request(finch, url(bypass, "/premium"),
               signer: solana,
               max_amount: "10000",
               siwx: [chain_id: :auto]
             ) == {:error, {:siwx, :unsupported_chain}}

      assert_received {:siwx,
                       %{
                         status: :error,
                         transport: :http,
                         chain_id: nil,
                         reason: :unsupported_chain
                       }}

      refute_received {:siwx, _metadata}
    end

    test "siwx: false and no challenge keep the plain payment flow", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      counter = :counters.new(1, [])

      Bypass.expect(bypass, "GET", "/premium", fn conn ->
        :counters.add(counter, 1, 1)
        assert Conn.get_req_header(conn, "sign-in-with-x") == []

        case Conn.get_req_header(conn, "payment-signature") do
          [] -> respond_402_with_challenge(conn, bypass)
          [_header] -> Conn.resp(conn, 200, "paid")
        end
      end)

      assert {:ok, %{status: 200, siwx_authenticated: false}} =
               FinchClient.request(finch, url(bypass, "/premium"),
                 signer: signer,
                 max_amount: "10000",
                 siwx: false
               )

      assert :counters.get(counter, 1) == 2

      Bypass.expect(bypass, "GET", "/plain", fn conn ->
        assert Conn.get_req_header(conn, "sign-in-with-x") == []

        case Conn.get_req_header(conn, "payment-signature") do
          [] -> respond_402(conn)
          [_header] -> Conn.resp(conn, 200, "paid")
        end
      end)

      assert {:ok, %{status: 200, siwx_authenticated: false}} =
               FinchClient.request(finch, url(bypass, "/plain"),
                 signer: signer,
                 max_amount: "10000",
                 siwx: [chain_id: @evm_chain]
               )

      refute_received {:siwx, _metadata}
    end

    test "validates siwx options", %{finch: finch, signer: signer} do
      assert_raise NimbleOptions.ValidationError, ~r/chain_id/, fn ->
        FinchClient.request(finch, "https://example.com", signer: signer, siwx: [address: "0x1"])
      end

      assert_raise NimbleOptions.ValidationError, ~r/siwx/, fn ->
        FinchClient.request(finch, "https://example.com", signer: signer, siwx: true)
      end
    end

    test "end to end: pay once with a proof, then sign in through the gate", %{
      bypass: bypass,
      finch: finch,
      signer: signer
    } do
      facilitator = start_bypass_facilitator(self())
      cache = start_supervised!({ETSCache, []})
      suffix = System.unique_integer([:positive, :monotonic])
      storage = :"finch_siwx_storage_#{suffix}"

      start_supervised!({ETSStorage, name: storage, table: :"finch_siwx_storage_table_#{suffix}"})

      nonce_cache =
        start_supervised!({ETSCache, name: :"finch_siwx_nonces_#{suffix}"}, id: :siwx_nonces)

      gate_opts =
        PaymentGate.init(
          facilitator: facilitator,
          payment_identifier_cache: cache,
          siwx:
            siwx_server_opts(bypass) ++
              [storage: {ETSStorage, storage}, nonce_cache: nonce_cache],
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

      client_opts = [signer: signer, max_amount: "10000", siwx: [chain_id: :auto]]

      # First visit: the proof is unknown, so the client pays (with the proof
      # attached) and the gate records the payer at settlement.
      assert {:ok, first} = FinchClient.request(finch, url(bypass, "/premium"), client_opts)

      assert %{status: 200, siwx_authenticated: false, payment_response: %{"success" => true}} =
               first

      assert_received {:facilitator_settle, _payload, _requirements}

      # Second visit: the proof alone opens the door.
      assert {:ok, second} = FinchClient.request(finch, url(bypass, "/premium"), client_opts)
      assert %{status: 200, siwx_authenticated: true, payment_response: nil} = second
      assert second.body == ~s({"premium":true})
      refute_received {:facilitator_settle, _payload, _requirements}
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
