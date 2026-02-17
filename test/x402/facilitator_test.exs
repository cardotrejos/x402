defmodule X402.FacilitatorTest do
  use ExUnit.Case, async: false

  alias X402.Facilitator
  alias X402.Facilitator.Error

  import X402.TestHelpers

  setup :setup_bypass
  setup :setup_finch

  test "verify/3 posts payload and requirements to /verify", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    payment_payload = %{"signature" => "abc"}
    requirements = %{"scheme" => "exact"}

    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      assert {:ok, body, conn} = Plug.Conn.read_body(conn)

      assert %{"payload" => ^payment_payload, "requirements" => ^requirements} =
               Jason.decode!(body)

      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    assert {:ok, %{status: 200, body: %{"verified" => true}}} =
             Facilitator.verify(facilitator, payment_payload, requirements)
  end

  test "settle/3 posts payload and requirements to /settle", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    payment_payload = %{"tx" => "0xdeadbeef"}
    requirements = %{"network" => "eip155:8453"}

    Bypass.expect(bypass, "POST", "/settle", fn conn ->
      assert {:ok, body, conn} = Plug.Conn.read_body(conn)

      assert %{"payload" => ^payment_payload, "requirements" => ^requirements} =
               Jason.decode!(body)

      Plug.Conn.resp(conn, 200, Jason.encode!(%{"settled" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    assert {:ok, %{status: 200, body: %{"settled" => true}}} =
             Facilitator.settle(facilitator, payment_payload, requirements)
  end

  test "verify/3 normalizes upto scheme requirements", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    payment_payload = %{"scheme" => "upto", "signature" => "abc"}
    requirements = %{scheme: :upto, price: "0.03", network: "eip155:8453"}

    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      assert {:ok, body, conn} = Plug.Conn.read_body(conn)
      decoded = Jason.decode!(body)

      assert decoded["payload"] == payment_payload
      assert decoded["requirements"]["scheme"] == "upto"
      assert decoded["requirements"]["maxPrice"] == "0.03"
      refute Map.has_key?(decoded["requirements"], "price")

      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    assert {:ok, %{status: 200, body: %{"verified" => true}}} =
             Facilitator.verify(facilitator, payment_payload, requirements)
  end

  test "settle/3 normalizes exact scheme requirements from price", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    payment_payload = %{"scheme" => "exact", "tx" => "0xdeadbeef"}
    requirements = %{scheme: :exact, price: "0.05", network: "eip155:8453"}

    Bypass.expect(bypass, "POST", "/settle", fn conn ->
      assert {:ok, body, conn} = Plug.Conn.read_body(conn)
      decoded = Jason.decode!(body)

      assert decoded["payload"] == payment_payload
      assert decoded["requirements"]["scheme"] == "exact"
      assert decoded["requirements"]["maxAmountRequired"] == "0.05"
      refute Map.has_key?(decoded["requirements"], "price")

      Plug.Conn.resp(conn, 200, Jason.encode!(%{"settled" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    assert {:ok, %{status: 200, body: %{"settled" => true}}} =
             Facilitator.settle(facilitator, payment_payload, requirements)
  end

  test "verify/2 and settle/2 use default registered name", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    Bypass.expect(bypass, "POST", "/settle", fn conn ->
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"settled" => true}))
    end)

    start_supervised!({Facilitator, finch: finch, url: facilitator_url})

    assert {:ok, %{status: 200, body: %{"verified" => true}}} =
             Facilitator.verify(%{"p" => 1}, %{"r" => 1})

    assert {:ok, %{status: 200, body: %{"settled" => true}}} =
             Facilitator.settle(%{"p" => 2}, %{"r" => 2})
  end

  test "returns structured errors from transport", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 400, Jason.encode!(%{"error" => "bad request"}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    assert {:error, %Error{type: :http_error, status: 400, retryable: false}} =
             Facilitator.verify(facilitator, %{}, %{})
  end

  test "emits telemetry span events", %{
    bypass: bypass,
    finch: finch,
    facilitator_url: facilitator_url
  } do
    parent = self()
    handler_id = "facilitator-span-#{System.unique_integer([:positive, :monotonic])}"

    :ok =
      :telemetry.attach_many(
        handler_id,
        [[:x402, :facilitator, :verify, :start], [:x402, :facilitator, :verify, :stop]],
        fn event, measurements, metadata, _config ->
          send(parent, {:telemetry, event, measurements, metadata})
        end,
        nil
      )

    on_exit(fn -> :telemetry.detach(handler_id) end)

    Bypass.expect(bypass, "POST", "/verify", fn conn ->
      Plug.Conn.resp(conn, 200, Jason.encode!(%{"verified" => true}))
    end)

    facilitator =
      start_supervised!(
        {Facilitator, name: unique_name("facilitator"), finch: finch, url: facilitator_url}
      )

    assert {:ok, %{status: 200, body: %{"verified" => true}}} =
             Facilitator.verify(facilitator, %{}, %{})

    assert_receive {:telemetry, [:x402, :facilitator, :verify, :start], _measurements,
                    %{operation: :verify, endpoint: "/verify"}}

    assert_receive {:telemetry, [:x402, :facilitator, :verify, :stop], measurements,
                    %{success: true, status: 200}}

    assert %{duration: duration} = measurements
    assert is_integer(duration)
  end

  test "start_link validates required options" do
    assert {:error, %NimbleOptions.ValidationError{}} = Facilitator.start_link([])

    assert {:error, %NimbleOptions.ValidationError{}} =
             Facilitator.start_link(finch: :finch, max_retries: -1)
  end

  defp unique_name(prefix) do
    String.to_atom("#{prefix}_#{System.unique_integer([:positive, :monotonic])}")
  end
end
