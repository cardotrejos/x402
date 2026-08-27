defmodule E2eServerSmokeTest do
  @moduledoc """
  Local smoke test for the e2e harness server contract.

  Boots the real server supervision tree against a stub facilitator that
  approves structurally well-formed payments, then exercises the wire
  contract the harness expects:

  1. `GET /exact/evm/eip3009` without payment → 402 + `PAYMENT-REQUIRED`
  2. same request with a well-formed `PAYMENT-SIGNATURE` → 200 + body +
     `PAYMENT-RESPONSE` (verify + settle hit the facilitator)
  3. `GET /health` → healthy, `POST /close` → graceful-shutdown body
  4. malformed payment header → 400; mismatched `accepted` → 402
  """

  use ExUnit.Case

  alias E2eServer.Config
  alias E2eServer.StubFacilitator

  @client E2eServerSmokeTest.Finch
  @pay_to "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
  @route_path "/exact/evm/eip3009"

  setup_all do
    facilitator_port = free_port()
    server_port = free_port()

    start_supervised!({Finch, name: @client})

    start_supervised!({Bandit, plug: StubFacilitator, port: facilitator_port, ip: {127, 0, 0, 1}})

    env = fn
      "PORT" -> Integer.to_string(server_port)
      "FACILITATOR_URL" -> "http://localhost:#{facilitator_port}"
      "SERVER_EVM_ADDRESS" -> @pay_to
      _other -> nil
    end

    stopper = fn ->
      send(:persistent_term.get({__MODULE__, :listener}), :server_stopped)
    end

    {:ok, config} = Config.load(env, stopper: stopper)

    start_supervised!(%{
      id: E2eServer.Supervisor,
      start: {E2eServer.Supervisor, :start_link, [config]},
      type: :supervisor
    })

    E2eServer.Supervisor.print_banner(config)

    {:ok, base_url: "http://localhost:#{server_port}", config: config}
  end

  setup do
    StubFacilitator.listen(self())
    :persistent_term.put({__MODULE__, :listener}, self())
    :ok
  end

  test "unpaid request answers 402 with a decodable PAYMENT-REQUIRED header", %{
    base_url: base_url
  } do
    {status, headers, _body} = request(:get, base_url <> @route_path)

    assert status == 402

    assert {:ok, required} = X402.PaymentRequired.decode(header(headers, "payment-required"))
    assert required["x402Version"] == 2
    assert [accept] = required["accepts"]

    assert accept["scheme"] == "exact"
    assert accept["network"] == "eip155:84532"
    assert accept["amount"] == "1000"
    assert accept["asset"] == "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
    assert accept["payTo"] == @pay_to
    assert accept["extra"] == %{"name" => "USDC", "version" => "2"}
    assert is_map(required["resource"])
    assert required["resource"]["url"] =~ @route_path
  end

  test "well-formed PAYMENT-SIGNATURE is verified, served, and settled", %{base_url: base_url} do
    {402, headers, _body} = request(:get, base_url <> @route_path)
    {:ok, required} = X402.PaymentRequired.decode(header(headers, "payment-required"))
    [accept] = required["accepts"]

    {status, headers, body} =
      request(:get, base_url <> @route_path, [{"payment-signature", signature_header(accept)}])

    assert status == 200

    assert %{"message" => "Protected endpoint accessed successfully", "timestamp" => _ts} =
             Jason.decode!(body)

    assert {:ok, settled} = X402.PaymentResponse.decode(header(headers, "payment-response"))
    assert settled["success"] == true
    assert settled["network"] == "eip155:84532"
    assert is_binary(settled["transaction"])

    assert_receive {:facilitator, :verify, verify_body}
    assert verify_body["x402Version"] == 2
    assert verify_body["paymentRequirements"]["payTo"] == @pay_to

    assert_receive {:facilitator, :settle, settle_body}
    assert settle_body["paymentPayload"]["accepted"]["amount"] == "1000"
  end

  test "malformed PAYMENT-SIGNATURE answers 400", %{base_url: base_url} do
    {status, _headers, _body} =
      request(:get, base_url <> @route_path, [{"payment-signature", "not-base64!!"}])

    assert status == 400
    refute_receive {:facilitator, _op, _body}
  end

  test "payment for mismatched requirements answers 402", %{base_url: base_url} do
    {402, headers, _body} = request(:get, base_url <> @route_path)
    {:ok, required} = X402.PaymentRequired.decode(header(headers, "payment-required"))
    [accept] = required["accepts"]

    tampered = Map.put(accept, "amount", "1")

    {status, _headers, _body} =
      request(:get, base_url <> @route_path, [{"payment-signature", signature_header(tampered)}])

    assert status == 402
    refute_receive {:facilitator, _op, _body}
  end

  test "GET /health reports the served networks", %{base_url: base_url} do
    {status, _headers, body} = request(:get, base_url <> "/health")

    assert status == 200
    assert %{"status" => "healthy", "networks" => networks} = Jason.decode!(body)
    assert networks["evm"] == %{"network" => "eip155:84532", "payee" => @pay_to}
  end

  test "POST /close answers the shutdown body and invokes the stopper", %{base_url: base_url} do
    {status, _headers, body} = request(:post, base_url <> "/close")

    assert status == 200
    assert %{"message" => "Server shutting down gracefully"} = Jason.decode!(body)
    assert_receive :server_stopped, 2_000
  end

  test "unknown paths answer 404", %{base_url: base_url} do
    {status, _headers, _body} = request(:get, base_url <> "/does-not-exist")
    assert status == 404
  end

  # -- Helpers -----------------------------------------------------------------

  defp signature_header(accept) do
    %{
      "x402Version" => 2,
      "accepted" => accept,
      "payload" => %{"signature" => "0x" <> String.duplicate("ab", 65)}
    }
    |> Jason.encode!()
    |> Base.encode64()
  end

  defp request(method, url, headers \\ []) do
    {:ok, response} =
      method
      |> Finch.build(url, headers)
      |> Finch.request(@client)

    {response.status, response.headers, response.body}
  end

  defp header(headers, name) do
    Enum.find_value(headers, fn
      {^name, value} -> value
      _other -> nil
    end)
  end

  defp free_port do
    {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(socket)
    :ok = :gen_tcp.close(socket)
    port
  end
end
