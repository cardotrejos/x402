defmodule X402.Client.AuthCaptureTest do
  use ExUnit.Case, async: true

  alias X402.Client
  alias X402.Client.Budget
  alias X402.Client.Finch, as: FinchClient
  alias X402.MCP
  alias X402.MCP.Client, as: MCPClient
  alias X402.PaymentRequired
  alias X402.PaymentSignature
  alias X402.Signer.LocalKey
  alias X402.TestAuthCapture, as: Fixture

  defmodule DelegatingScheme do
    @moduledoc false
    @behaviour X402.Scheme
    defdelegate scheme(), to: X402.Scheme.AuthCaptureEVM
    defdelegate networks(), to: X402.Scheme.AuthCaptureEVM
    defdelegate signable?(requirements), to: X402.Scheme.AuthCaptureEVM
    defdelegate validate_payload(payload, requirements, opts), to: X402.Scheme.AuthCaptureEVM
    defdelegate sign(requirements, signer, opts), to: X402.Scheme.AuthCaptureEVM
  end

  setup do
    {:ok, signer} = LocalKey.new(<<1::256>>)
    vector = Fixture.vector()

    payment_required = %{
      "x402Version" => 2,
      "accepts" => [vector["requirements"]],
      "resource" => %{"url" => "https://example.com/paid"}
    }

    %{
      signer: signer,
      vector: vector,
      payment_required: payment_required,
      opts: [auth_capture: [now: Fixture.fixture()["now"], salt_nonce: vector["salt_nonce"]]]
    }
  end

  test "built-in selection and signing retain the independent envelope", ctx do
    assert Client.select_requirements(ctx.payment_required) == {:ok, ctx.vector["requirements"]}
    assert {:ok, envelope} = Client.build_payment(ctx.payment_required, ctx.signer, ctx.opts)
    assert envelope["payload"] == ctx.vector["payload"]
    assert PaymentSignature.validate(envelope) == {:ok, envelope}

    for flow <- ["upfront", "unknown"] do
      requirements = put_in(ctx.vector["requirements"], ["extra", "paymentFlow"], flow)
      assert {:error, _} = Client.build_payment(requirements, ctx.signer, ctx.opts)
    end

    assert_raise NimbleOptions.ValidationError, fn ->
      Client.build_payment(ctx.payment_required, ctx.signer, auth_capture: [wrong: true])
    end
  end

  test "HTTP error after dispatch retains the full escrow reservation", ctx do
    bypass = Bypass.open()
    start_supervised!({Finch, name: __MODULE__})
    budget = start_supervised!({Budget, limit: 1_000_000})
    {:ok, header} = PaymentRequired.encode(ctx.payment_required)
    parent = self()

    Bypass.stub(bypass, "GET", "/paid", fn conn ->
      case Plug.Conn.get_req_header(conn, "payment-signature") do
        [] ->
          conn |> Plug.Conn.put_resp_header("payment-required", header) |> Plug.Conn.resp(402, "")

        [payment] ->
          {:ok, payload} = PaymentSignature.decode(payment)
          send(parent, {:signed, payload})
          Plug.Conn.resp(conn, 500, "execution failed after funding")
      end
    end)

    opts = ctx.opts ++ [signer: ctx.signer, budget: budget]

    assert {:ok, %{status: 500}} =
             FinchClient.request(__MODULE__, "http://localhost:#{bypass.port}/paid", opts)

    assert_received {:signed, %{"payload" => payload}}
    assert payload == ctx.vector["payload"]
    assert Budget.spent(budget).total == 1_000_000
  end

  test "a custom scheme can delegate the complete client option contract", ctx do
    assert {:ok, envelope} =
             Client.build_payment(
               ctx.payment_required,
               ctx.signer,
               ctx.opts ++ [schemes: [DelegatingScheme]]
             )

    assert envelope["payload"] == ctx.vector["payload"]
  end

  test "MCP failures and repeated challenges retain dispatched exposure", ctx do
    budget = start_supervised!({Budget, limit: 2_000_000})
    parent = self()
    {:ok, challenge} = MCP.payment_required_result(ctx.payment_required)

    for outcome <- [{:error, :timeout}, {:ok, challenge}] do
      call = fn request ->
        case MCP.fetch_payment(request) do
          {:ok, payload} ->
            send(parent, {:mcp_payment, payload})
            outcome

          _absent ->
            {:ok, challenge}
        end
      end

      MCPClient.call(
        %{"name" => "paid", "arguments" => %{}},
        call,
        ctx.opts ++ [signer: ctx.signer, budget: budget]
      )

      assert_received {:mcp_payment, %{"payload" => payload}}
      assert payload == ctx.vector["payload"]
    end

    assert Budget.spent(budget).total == 2_000_000
  end
end
