defmodule X402Test do
  use ExUnit.Case, async: true

  doctest X402

  describe "OTP application dependencies" do
    test "declares every required runtime application" do
      applications = Application.spec(:x402, :applications)

      assert :telemetry in applications
      assert :public_key in applications
    end
  end

  describe "convenience delegates" do
    test "delegates payment-required encode/decode" do
      payload = %{"scheme" => "exact"}
      assert {:ok, encoded} = X402.encode_payment_required(payload)
      assert {:ok, ^payload} = X402.decode_payment_required(encoded)
    end

    test "delegates payment-signature decode and validate" do
      payload = %{
        "x402Version" => 2,
        "accepted" => %{
          "scheme" => "exact",
          "network" => "eip155:8453",
          "amount" => "10000",
          "asset" => "0xasset",
          "payTo" => "0xreceiver",
          "maxTimeoutSeconds" => 60,
          "extra" => %{}
        },
        "payload" => %{"signature" => "0xsignature"}
      }

      encoded = payload |> Jason.encode!() |> Base.encode64()

      assert {:ok, ^payload} = X402.decode_payment_signature(encoded)
      assert {:ok, ^payload} = X402.validate_payment_signature(payload)
      assert {:ok, ^payload} = X402.decode_and_validate_payment_signature(encoded)
    end

    test "delegates payment-response encode/decode" do
      payload = %{"settled" => true}
      assert {:ok, encoded} = X402.encode_payment_response(payload)
      assert {:ok, ^payload} = X402.decode_payment_response(encoded)
    end

    test "delegates wallet helpers" do
      assert X402.valid_wallet?("0x1111111111111111111111111111111111111111")
      assert X402.wallet_type("0x1111111111111111111111111111111111111111") == :evm
      refute X402.valid_wallet?("bad-wallet")
      assert X402.wallet_type("bad-wallet") == :unknown
    end
  end
end
