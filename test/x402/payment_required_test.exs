defmodule X402.PaymentRequiredTest do
  use ExUnit.Case, async: true

  doctest X402.PaymentRequired

  alias X402.PaymentRequired

  describe "header_name/0" do
    test "returns PAYMENT-REQUIRED" do
      assert PaymentRequired.header_name() == "PAYMENT-REQUIRED"
    end
  end

  describe "encode/1" do
    test "encodes a map payload" do
      payload = %{"scheme" => "exact", "maxAmountRequired" => "100"}

      assert {:ok, encoded} = PaymentRequired.encode(payload)
      assert {:ok, ^payload} = PaymentRequired.decode(encoded)
    end

    test "returns invalid_payload for non-map payloads" do
      assert PaymentRequired.encode(nil) == {:error, :invalid_payload}
      assert PaymentRequired.encode("") == {:error, :invalid_payload}
    end

    test "returns invalid_json for non-encodable map values" do
      assert PaymentRequired.encode(%{"bad" => self()}) == {:error, :invalid_json}
    end
  end

  describe "decode/1" do
    test "returns invalid_base64 for nil and malformed base64" do
      assert PaymentRequired.decode(nil) == {:error, :invalid_base64}
      assert PaymentRequired.decode("%%%") == {:error, :invalid_base64}
      assert PaymentRequired.decode("") == {:error, :invalid_base64}
    end

    test "returns invalid_json for invalid json" do
      invalid_json = Base.encode64("{")
      assert PaymentRequired.decode(invalid_json) == {:error, :invalid_json}
    end

    test "returns invalid_json for json that is not a map" do
      not_map = Base.encode64("[]")
      assert PaymentRequired.decode(not_map) == {:error, :invalid_json}
    end
  end
end
