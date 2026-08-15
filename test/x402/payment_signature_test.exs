defmodule X402.PaymentSignatureTest do
  use ExUnit.Case, async: true

  doctest X402.PaymentSignature

  alias X402.PaymentSignature

  @v2_requirements %{
    "scheme" => "upto",
    "network" => "eip155:84532",
    "amount" => "10000",
    "asset" => "0xasset",
    "payTo" => "0xreceiver",
    "maxTimeoutSeconds" => 60,
    "extra" => %{}
  }

  describe "header_name/0" do
    test "returns PAYMENT-SIGNATURE" do
      assert PaymentSignature.header_name() == "PAYMENT-SIGNATURE"
    end
  end

  describe "decode/1" do
    test "decodes a valid base64 json payload" do
      payload = %{
        "transactionHash" => "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "network" => "eip155:8453",
        "scheme" => "exact",
        "payerWallet" => "0x1111111111111111111111111111111111111111"
      }

      encoded = payload |> Jason.encode!() |> Base.encode64()

      assert PaymentSignature.decode(encoded) == {:ok, payload}
    end

    test "returns invalid_base64 for nil, empty, or malformed values" do
      assert PaymentSignature.decode(nil) == {:error, :invalid_base64}
      assert PaymentSignature.decode("") == {:error, :invalid_base64}
      assert PaymentSignature.decode("%%%") == {:error, :invalid_base64}
    end

    test "returns invalid_json for invalid json payloads" do
      invalid_json = Base.encode64("{")
      assert PaymentSignature.decode(invalid_json) == {:error, :invalid_json}
    end

    test "accepts headers at exactly the size limit" do
      # @max_header_bytes is 8_192 — check is on raw input byte_size
      at_limit = String.duplicate("A", 8_192)
      # Should NOT return :payload_too_large (will fail for other reasons)
      refute PaymentSignature.decode(at_limit) == {:error, :payload_too_large}
    end

    test "returns payload_too_large for headers exceeding size limit" do
      # @max_header_bytes is 8_192 — one byte over triggers rejection
      oversized = String.duplicate("A", 8_193)
      assert PaymentSignature.decode(oversized) == {:error, :payload_too_large}
    end

    test "returns invalid_json when decoded json is not a map" do
      encoded_array = Base.encode64("[1,2,3]")
      assert PaymentSignature.decode(encoded_array) == {:error, :invalid_json}
    end
  end

  describe "validate/1" do
    test "returns ok for complete payload" do
      payload = %{
        "transactionHash" => "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "network" => "eip155:8453",
        "scheme" => "exact",
        "payerWallet" => "0x1111111111111111111111111111111111111111"
      }

      assert PaymentSignature.validate(payload) == {:ok, payload}
    end

    test "returns invalid_payload for non-map payload" do
      assert PaymentSignature.validate(nil) == {:error, :invalid_payload}
    end

    test "returns missing_fields for absent values" do
      payload = %{"network" => "eip155:8453"}

      assert PaymentSignature.validate(payload) ==
               {:error, {:missing_fields, ["payerWallet", "scheme", "transactionHash"]}}
    end

    test "treats empty strings as missing" do
      payload = %{
        "transactionHash" => "",
        "network" => "eip155:8453",
        "scheme" => "",
        "payerWallet" => "0x1111111111111111111111111111111111111111"
      }

      assert PaymentSignature.validate(payload) ==
               {:error, {:missing_fields, ["scheme", "transactionHash"]}}
    end

    test "validates upto payments when value is within maxPrice from payload" do
      payload = %{
        "transactionHash" => "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "network" => "eip155:8453",
        "scheme" => "upto",
        "payerWallet" => "0x1111111111111111111111111111111111111111",
        "value" => "0.009",
        "maxPrice" => "0.01"
      }

      assert PaymentSignature.validate(payload) == {:ok, payload}
    end

    test "validates v2 payloads through the public API" do
      payload = v2_payload("9000")

      assert PaymentSignature.validate(payload) == {:ok, payload}
    end

    test "rejects unsupported explicit protocol versions" do
      assert PaymentSignature.validate(%{"x402Version" => 3}) ==
               {:error, :invalid_x402_version}
    end

    test "validates v2 accepted fields and optional object types" do
      assert PaymentSignature.validate(put_in(v2_payload("9000"), ["accepted", "amount"], 9_000)) ==
               {:error, {:invalid_fields, ["amount"]}}

      assert PaymentSignature.validate(Map.put(v2_payload("9000"), "extensions", [])) ==
               {:error, :invalid_payload}
    end
  end

  describe "validate/2" do
    test "validates upto payments when value is within requirements maxPrice" do
      payload = %{
        "transactionHash" => "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "network" => "eip155:8453",
        "scheme" => "upto",
        "payerWallet" => "0x1111111111111111111111111111111111111111",
        "value" => "0.009"
      }

      requirements = %{"scheme" => "upto", "maxPrice" => "0.01"}

      assert PaymentSignature.validate(payload, requirements) == {:ok, payload}
    end

    test "rejects upto payments when value exceeds maxPrice" do
      payload = %{
        "transactionHash" => "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "network" => "eip155:8453",
        "scheme" => "upto",
        "payerWallet" => "0x1111111111111111111111111111111111111111",
        "value" => "0.02"
      }

      requirements = %{"scheme" => "upto", "maxPrice" => "0.01"}

      assert PaymentSignature.validate(payload, requirements) ==
               {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}}
    end

    test "rejects upto payments when value is missing" do
      payload = %{
        "transactionHash" => "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "network" => "eip155:8453",
        "scheme" => "upto",
        "payerWallet" => "0x1111111111111111111111111111111111111111"
      }

      requirements = %{"scheme" => "upto", "maxPrice" => "0.01"}

      assert PaymentSignature.validate(payload, requirements) ==
               {:error, {:invalid_upto_payment, :missing_payment_value}}
    end

    test "returns invalid_payload for non-map requirements" do
      payload = %{
        "transactionHash" => "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "network" => "eip155:8453",
        "scheme" => "upto",
        "payerWallet" => "0x1111111111111111111111111111111111111111",
        "value" => "0.01"
      }

      assert PaymentSignature.validate(payload, :bad) == {:error, :invalid_payload}
    end

    test "matches the complete v2 requirements object" do
      payload = v2_payload("9000")

      assert PaymentSignature.validate(payload, @v2_requirements) == {:ok, payload}

      changed_timeout = put_in(payload, ["accepted", "maxTimeoutSeconds"], 30)

      assert PaymentSignature.validate(changed_timeout, @v2_requirements) ==
               {:error, :no_matching_requirements}
    end

    test "validates v2 upto value against accepted amount" do
      assert PaymentSignature.validate(v2_payload("10001")) ==
               {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}}
    end

    test "reads the authorized maximum from the v2 Permit2 payload" do
      payload =
        v2_payload("ignored")
        |> put_in(
          ["payload"],
          %{
            "signature" => "0xsignature",
            "permit2Authorization" => %{
              "permitted" => %{"token" => "0xasset", "amount" => "10000"}
            }
          }
        )

      assert PaymentSignature.validate(payload, @v2_requirements) == {:ok, payload}

      oversized =
        put_in(payload, ["payload", "permit2Authorization", "permitted", "amount"], "10001")

      assert PaymentSignature.validate(oversized, @v2_requirements) ==
               {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}}
    end
  end

  describe "decode_and_validate/1" do
    test "returns ok for valid encoded payload" do
      payload = %{
        "transactionHash" => "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "network" => "eip155:8453",
        "scheme" => "exact",
        "payerWallet" => "0x1111111111111111111111111111111111111111"
      }

      encoded = payload |> Jason.encode!() |> Base.encode64()

      assert PaymentSignature.decode_and_validate(encoded) == {:ok, payload}
    end

    test "returns decode errors first" do
      assert PaymentSignature.decode_and_validate("%%%") == {:error, :invalid_base64}
    end

    test "returns validation errors for missing fields" do
      payload = %{"network" => "eip155:8453"}
      encoded = payload |> Jason.encode!() |> Base.encode64()

      assert PaymentSignature.decode_and_validate(encoded) ==
               {:error, {:missing_fields, ["payerWallet", "scheme", "transactionHash"]}}
    end
  end

  describe "decode_and_validate/2" do
    test "validates upto scheme against requirements" do
      payload = %{
        "transactionHash" => "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "network" => "eip155:8453",
        "scheme" => "upto",
        "payerWallet" => "0x1111111111111111111111111111111111111111",
        "value" => "0.02"
      }

      requirements = %{"scheme" => "upto", "maxPrice" => "0.01"}
      encoded = payload |> Jason.encode!() |> Base.encode64()

      assert PaymentSignature.decode_and_validate(encoded, requirements) ==
               {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}}
    end

    test "returns invalid_payload for non-map requirements" do
      encoded = "payload"
      assert PaymentSignature.decode_and_validate(encoded, :invalid) == {:error, :invalid_payload}
    end
  end

  defp v2_payload(value) do
    %{
      "x402Version" => 2,
      "accepted" => @v2_requirements,
      "payload" => %{
        "signature" => "0xsignature",
        "authorization" => %{"value" => value}
      },
      "extensions" => %{}
    }
  end
end
