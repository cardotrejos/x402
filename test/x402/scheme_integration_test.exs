defmodule X402.SchemeIntegrationTest do
  @moduledoc """
  End-to-end test of a custom `X402.Scheme` registered via the `:schemes`
  option: a toy "cash" scheme drives the full loop — the gate advertises a
  cash route in `PAYMENT-REQUIRED`, `X402.Client.build_payment/3` selects
  and signs it, and `X402.Plug.PaymentGate` validates, pre-checks,
  verifies, and settles it against a Bypass-backed facilitator.
  """

  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias X402.Client
  alias X402.Facilitator
  alias X402.PaymentRequired
  alias X402.PaymentSignature
  alias X402.Plug.PaymentGate
  alias X402.Signer.LocalKey

  defmodule CashScheme do
    @moduledoc false
    @behaviour X402.Scheme

    @impl X402.Scheme
    def scheme, do: "cash"

    @impl X402.Scheme
    def networks, do: ["local:*"]

    @impl X402.Scheme
    def sign(requirements, _signer, _opts) do
      {:ok, %{"note" => "IOU " <> Map.fetch!(requirements, "amount")}}
    end

    @impl X402.Scheme
    def validate_payload(payload, requirements, _opts) do
      expected = "IOU " <> Map.fetch!(requirements, "amount")

      case get_in(payload, ["payload", "note"]) do
        ^expected -> :ok
        _other -> {:error, {:invalid_scheme_payment, :missing_note}}
      end
    end

    @impl X402.Scheme
    def precheck(payload, _requirements, _opts) do
      case get_in(payload, ["payload", "counterfeit"]) do
        true -> {:error, {:precheck_failed, :counterfeit_note}}
        _other -> :ok
      end
    end
  end

  @cash_route %{
    method: :get,
    path: "/cash/resource",
    scheme: "cash",
    price: "5000",
    network: "local:test",
    asset: "note",
    pay_to: "till"
  }

  @default_verify {:ok, %{status: 200, body: %{"isValid" => true, "payer" => "payer-1"}}}

  @default_settle {
    :ok,
    %{
      status: 200,
      body: %{
        "success" => true,
        "transaction" => "cash-receipt-1",
        "network" => "local:test",
        "payer" => "payer-1"
      }
    }
  }

  defp signer do
    {:ok, signer} = LocalKey.new(:crypto.strong_rand_bytes(32))
    signer
  end

  defp gate_opts(facilitator) do
    [
      routes: [@cash_route],
      schemes: [CashScheme],
      facilitator: facilitator
    ]
  end

  defp run_request(conn, facilitator) do
    conn = PaymentGate.call(conn, PaymentGate.init(gate_opts(facilitator)))

    case conn.halted do
      true -> conn
      false -> Plug.Conn.send_resp(conn, 200, "cash accepted")
    end
  end

  defp decode_payment_required!(conn) do
    [header] = get_resp_header(conn, "payment-required")
    assert {:ok, payload} = PaymentRequired.decode(header)
    payload
  end

  test "a custom cash scheme drives the full client → gate → facilitator loop" do
    facilitator = start_mock_facilitator()

    # 1. Unpaid request: the gate advertises the cash route.
    unpaid = run_request(conn(:get, "/cash/resource"), facilitator)

    assert unpaid.status == 402
    payment_required = decode_payment_required!(unpaid)

    assert [accept] = payment_required["accepts"]
    assert accept["scheme"] == "cash"
    assert accept["network"] == "local:test"
    assert accept["amount"] == "5000"

    # 2. The payer client selects and signs the cash requirement.
    assert {:ok, payload} =
             Client.build_payment(payment_required, signer(), schemes: [CashScheme])

    assert payload["accepted"] == accept
    assert payload["payload"] == %{"note" => "IOU 5000"}
    assert {:ok, header} = Client.encode_payment(payload)

    # 3. The paid request passes validation, pre-checks, verify, and settle.
    paid =
      conn(:get, "/cash/resource")
      |> put_req_header("payment-signature", header)
      |> run_request(facilitator)

    assert paid.status == 200
    assert paid.resp_body == "cash accepted"

    assert_receive {:verify_called, verified_payload, verified_requirements}
    assert verified_payload["payload"] == %{"note" => "IOU 5000"}
    assert verified_requirements["scheme"] == "cash"

    assert_receive {:settle_called, _settled_payload, settled_requirements}
    assert settled_requirements["scheme"] == "cash"

    assert [_response] = get_resp_header(paid, "payment-response")
  end

  test "the client cannot select cash requirements without the scheme" do
    facilitator = start_mock_facilitator()
    unpaid = run_request(conn(:get, "/cash/resource"), facilitator)
    payment_required = decode_payment_required!(unpaid)

    assert Client.build_payment(payment_required, signer()) ==
             {:error, :no_acceptable_requirements}
  end

  test "the scheme's validate_payload rejects tampered payloads before the facilitator" do
    facilitator = start_mock_facilitator()
    unpaid = run_request(conn(:get, "/cash/resource"), facilitator)
    payment_required = decode_payment_required!(unpaid)

    {:ok, payload} = Client.build_payment(payment_required, signer(), schemes: [CashScheme])
    tampered = put_in(payload, ["payload", "note"], "IOU 1")
    {:ok, header} = Client.encode_payment(tampered)

    rejected =
      conn(:get, "/cash/resource")
      |> put_req_header("payment-signature", header)
      |> run_request(facilitator)

    # {:invalid_scheme_payment, _} maps to 400 Invalid Request.
    assert rejected.status == 400
    refute_receive {:verify_called, _payload, _requirements}
  end

  test "the scheme's precheck rejects counterfeit payloads before the facilitator" do
    facilitator = start_mock_facilitator()
    unpaid = run_request(conn(:get, "/cash/resource"), facilitator)
    payment_required = decode_payment_required!(unpaid)

    {:ok, payload} = Client.build_payment(payment_required, signer(), schemes: [CashScheme])
    counterfeit = put_in(payload, ["payload", "counterfeit"], true)
    {:ok, header} = Client.encode_payment(counterfeit)

    rejected =
      conn(:get, "/cash/resource")
      |> put_req_header("payment-signature", header)
      |> run_request(facilitator)

    assert rejected.status == 402
    refute_receive {:verify_called, _payload, _requirements}
  end

  test "cash routes require the scheme to be registered on the gate" do
    assert_raise NimbleOptions.ValidationError, ~r/scheme/, fn ->
      PaymentGate.init(routes: [@cash_route])
    end
  end

  test "PaymentSignature.validate/3 consults the registered scheme" do
    accepted = %{
      "scheme" => "cash",
      "network" => "local:test",
      "amount" => "5000",
      "asset" => "note",
      "payTo" => "till",
      "maxTimeoutSeconds" => 60,
      "extra" => %{}
    }

    payload = %{
      "x402Version" => 2,
      "accepted" => accepted,
      "payload" => %{"note" => "IOU 5000"}
    }

    assert PaymentSignature.validate(payload, %{}, schemes: [CashScheme]) == {:ok, payload}

    tampered = put_in(payload, ["payload", "note"], "IOU 1")

    assert PaymentSignature.validate(tampered, %{}, schemes: [CashScheme]) ==
             {:error, {:invalid_scheme_payment, :missing_note}}

    # Without the scheme registered, the kind is unknown and passes through.
    assert PaymentSignature.validate(tampered) == {:ok, tampered}
  end

  # Bypass-backed facilitator harness, mirroring
  # test/x402/plug/payment_gate_test.exs.
  defp start_mock_facilitator do
    owner = self()

    bypass = Bypass.open()
    stub_facilitator_endpoint(bypass, owner, "/verify", :verify_called, @default_verify)
    stub_facilitator_endpoint(bypass, owner, "/settle", :settle_called, @default_settle)

    suffix = System.unique_integer([:positive, :monotonic])
    finch = String.to_atom("scheme_integration_finch_#{suffix}")
    name = String.to_atom("scheme_integration_facilitator_#{suffix}")

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
