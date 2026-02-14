defmodule X402.PaymentResponseTest do
  use ExUnit.Case, async: true

  doctest X402.PaymentResponse

  alias X402.PaymentResponse

  describe "header_name/0" do
    test "returns PAYMENT-RESPONSE" do
      assert PaymentResponse.header_name() == "PAYMENT-RESPONSE"
    end
  end

  describe "encode/1" do
    test "encodes map payloads" do
      payload = %{"settled" => true, "transactionHash" => "0xabc"}

      assert {:ok, encoded} = PaymentResponse.encode(payload)
      assert PaymentResponse.decode(encoded) == {:ok, payload}
    end

    test "returns invalid_payload for non-map payloads" do
      assert PaymentResponse.encode(nil) == {:error, :invalid_payload}
      assert PaymentResponse.encode("") == {:error, :invalid_payload}
    end

    test "returns invalid_json when payload cannot be encoded" do
      assert PaymentResponse.encode(%{"bad" => self()}) == {:error, :invalid_json}
    end
  end

  describe "decode/1" do
    test "returns invalid_base64 for malformed values" do
      assert PaymentResponse.decode(nil) == {:error, :invalid_base64}
      assert PaymentResponse.decode("") == {:error, :invalid_base64}
      assert PaymentResponse.decode("%%%") == {:error, :invalid_base64}
    end

    test "returns invalid_json for invalid json and non-map json" do
      assert PaymentResponse.decode(Base.encode64("{")) == {:error, :invalid_json}
      assert PaymentResponse.decode(Base.encode64("\"ok\"")) == {:error, :invalid_json}
    end
  end
end
