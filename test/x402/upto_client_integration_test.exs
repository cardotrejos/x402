defmodule X402.UptoClientIntegrationTest do
  @moduledoc """
  End-to-end test of the built-in `upto` scheme's client half: the gate
  advertises a metered upto route (with the facilitator address in
  `extra`), `X402.Client.build_payment/3` selects and signs it via
  Permit2, the signature recovers to the payer over the EIP-712 digest,
  and `X402.Plug.PaymentGate` validates, verifies, and settles the
  metered amount against a Bypass-backed facilitator.
  """

  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias X402.Client
  alias X402.EIP3009
  alias X402.Facilitator
  alias X402.PaymentRequired
  alias X402.PaymentSignature
  alias X402.Permit2
  alias X402.Plug.PaymentGate
  alias X402.Signer
  alias X402.Signer.LocalKey

  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @pay_to "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
  @facilitator_address "0x3333333333333333333333333333333333333333"
  @max_amount "20000"

  @upto_route %{
    method: :get,
    path: "/metered/resource",
    scheme: "upto",
    price: @max_amount,
    network: "eip155:84532",
    asset: @asset,
    pay_to: @pay_to,
    extra: %{
      "name" => "USDC",
      "version" => "2",
      "facilitatorAddress" => @facilitator_address
    }
  }

  @default_verify {:ok, %{status: 200, body: %{"isValid" => true, "payer" => "0xpayer"}}}

  @default_settle {
    :ok,
    %{
      status: 200,
      body: %{
        "success" => true,
        "transaction" => "0x" <> String.duplicate("ab", 32),
        "network" => "eip155:84532",
        "payer" => "0xpayer"
      }
    }
  }

  defp signer do
    {:ok, signer} = LocalKey.new(:crypto.strong_rand_bytes(32))
    signer
  end

  defp gate_opts(facilitator), do: [routes: [@upto_route], facilitator: facilitator]

  defp run_request(conn, facilitator) do
    conn = PaymentGate.call(conn, PaymentGate.init(gate_opts(facilitator)))

    case conn.halted do
      true -> conn
      false -> Plug.Conn.send_resp(conn, 200, "metered response")
    end
  end

  defp decode_payment_required!(conn) do
    [header] = get_resp_header(conn, "payment-required")
    assert {:ok, payload} = PaymentRequired.decode(header)
    payload
  end

  defp advertised_requirements(facilitator) do
    unpaid = run_request(conn(:get, "/metered/resource"), facilitator)
    assert unpaid.status == 402

    assert [accept] = decode_payment_required!(unpaid)["accepts"]
    {decode_payment_required!(unpaid), accept}
  end

  test "the client signs an advertised upto requirement and the gate settles the metered amount" do
    facilitator = start_mock_facilitator()

    # 1. Unpaid request: the gate advertises the upto route with the
    #    facilitator address the witness must bind.
    {payment_required, accept} = advertised_requirements(facilitator)

    assert accept["scheme"] == "upto"
    assert accept["amount"] == @max_amount
    assert accept["extra"]["facilitatorAddress"] == @facilitator_address

    # 2. The payer client selects and signs the upto requirement.
    signer = signer()
    {:ok, payer} = Signer.address(signer)

    assert {:ok, payload} = Client.build_payment(payment_required, signer)
    assert payload["accepted"] == accept

    assert %{"signature" => signature, "permit2Authorization" => authorization} =
             payload["payload"]

    assert authorization["from"] == payer
    assert authorization["permitted"] == %{"token" => @asset, "amount" => @max_amount}
    assert authorization["spender"] == Permit2.upto_proxy_address()

    assert authorization["witness"] == %{
             "to" => @pay_to,
             "facilitator" => @facilitator_address,
             "validAfter" => "0"
           }

    # 3. The signature recovers to the payer over the Permit2 EIP-712
    #    digest — domain and type encoding round-trip.
    {:ok, domain} = Permit2.upto_domain(accept)
    {:ok, digest} = Permit2.upto_digest(domain, authorization)
    assert EIP3009.recover_signer(digest, signature) == {:ok, payer}

    # 4. The encoded header round-trips through decode_and_validate
    #    against the advertised requirements.
    assert {:ok, header} = Client.encode_payment(payload)
    assert PaymentSignature.decode_and_validate(header, accept) == {:ok, payload}

    # 5. The paid request passes the gate: validation, pre-checks, the
    #    facilitator verify (against the maximum), and settle.
    paid =
      conn(:get, "/metered/resource")
      |> put_req_header("payment-signature", header)
      |> run_request(facilitator)

    assert paid.status == 200
    assert paid.resp_body == "metered response"

    assert_receive {:verify_called, verified_payload, verified_requirements}
    assert verified_payload["payload"]["permit2Authorization"] == authorization
    assert verified_requirements["amount"] == @max_amount

    assert_receive {:settle_called, _payload, %{"amount" => @max_amount}}
    assert [_response] = get_resp_header(paid, "payment-response")
  end

  test "put_settlement_amount/2 meters the settled amount below the signed maximum" do
    facilitator = start_mock_facilitator()
    {payment_required, _accept} = advertised_requirements(facilitator)

    {:ok, payload} = Client.build_payment(payment_required, signer())
    {:ok, header} = Client.encode_payment(payload)

    gated =
      conn(:get, "/metered/resource")
      |> put_req_header("payment-signature", header)
      |> PaymentGate.call(PaymentGate.init(gate_opts(facilitator)))

    refute gated.halted

    # The handler measured 1858 atomic units of usage.
    assert {:ok, gated} = PaymentGate.put_settlement_amount(gated, "1858")
    response = Plug.Conn.send_resp(gated, 200, "usage complete")

    assert response.status == 200
    assert_receive {:verify_called, _payload, %{"amount" => @max_amount}}
    assert_receive {:settle_called, settled_payload, %{"amount" => "1858"}}

    # The client-signed ceiling is untouched; only the settlement
    # requirements carry the metered amount.
    assert settled_payload["payload"]["permit2Authorization"]["permitted"]["amount"] ==
             @max_amount
  end

  test "the client cannot sign the route when extra lacks the facilitator address" do
    facilitator = start_mock_facilitator()
    {payment_required, accept} = advertised_requirements(facilitator)

    without_facilitator =
      put_in(payment_required["accepts"], [
        Map.put(accept, "extra", %{"name" => "USDC", "version" => "2"})
      ])

    assert Client.build_payment(without_facilitator, signer()) ==
             {:error, :no_acceptable_requirements}
  end

  # Bypass-backed facilitator harness, mirroring
  # test/x402/scheme_integration_test.exs.
  defp start_mock_facilitator do
    owner = self()

    bypass = Bypass.open()
    stub_facilitator_endpoint(bypass, owner, "/verify", :verify_called, @default_verify)
    stub_facilitator_endpoint(bypass, owner, "/settle", :settle_called, @default_settle)

    suffix = System.unique_integer([:positive, :monotonic])
    finch = String.to_atom("upto_integration_finch_#{suffix}")
    name = String.to_atom("upto_integration_facilitator_#{suffix}")

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

  defp stub_facilitator_endpoint(bypass, owner, path, tag, {:ok, %{status: status, body: body}}) do
    Bypass.stub(bypass, "POST", path, fn conn ->
      {:ok, request_body, conn} = Plug.Conn.read_body(conn)
      decoded = Jason.decode!(request_body)
      send(owner, {tag, decoded["paymentPayload"], decoded["paymentRequirements"]})
      Plug.Conn.resp(conn, status, Jason.encode!(body))
    end)
  end
end
