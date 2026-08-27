defmodule X402.Scheme.UptoEVMTest do
  use ExUnit.Case, async: true

  doctest X402.Scheme.UptoEVM

  alias X402.Scheme.UptoEVM

  @requirements %{
    "scheme" => "upto",
    "network" => "eip155:84532",
    "amount" => "10000",
    "asset" => "0xasset",
    "payTo" => "0xreceiver",
    "maxTimeoutSeconds" => 60,
    "extra" => %{}
  }

  describe "metadata" do
    test "declares upto on every EVM network" do
      assert UptoEVM.scheme() == "upto"
      assert UptoEVM.networks() == ["eip155:*"]
    end

    test "does not implement the client sign callback" do
      refute function_exported?(UptoEVM, :sign, 3)
    end
  end

  describe "validate_payload/3" do
    test "accepts payments within the ceiling" do
      payload = %{"payload" => %{"authorization" => %{"value" => "9000"}}}

      assert UptoEVM.validate_payload(payload, @requirements, []) == :ok
    end

    test "rejects payments above the ceiling" do
      payload = %{"payload" => %{"authorization" => %{"value" => "10001"}}}

      assert UptoEVM.validate_payload(payload, @requirements, []) ==
               {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}}
    end

    test "reads the Permit2 payload shape" do
      payload = %{
        "payload" => %{
          "permit2Authorization" => %{"permitted" => %{"token" => "0xasset", "amount" => "10000"}}
        }
      }

      assert UptoEVM.validate_payload(payload, @requirements, []) == :ok

      oversized =
        put_in(payload, ["payload", "permit2Authorization", "permitted", "amount"], "10001")

      assert UptoEVM.validate_payload(oversized, @requirements, []) ==
               {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}}
    end

    test "falls back to maxPrice and maxAmountRequired ceilings" do
      payload = %{"payload" => %{"value" => "15"}}

      assert UptoEVM.validate_payload(payload, %{"maxPrice" => "10"}, []) ==
               {:error, {:invalid_upto_payment, :payment_value_exceeds_max_price}}

      assert UptoEVM.validate_payload(payload, %{"maxAmountRequired" => "20"}, []) == :ok
    end

    test "rejects payments with no discernible value" do
      payload = %{"payload" => %{"signature" => "0xsig"}}

      assert UptoEVM.validate_payload(payload, @requirements, []) ==
               {:error, {:invalid_upto_payment, :missing_payment_value}}
    end

    test "rejects payments with no discernible ceiling" do
      payload = %{"payload" => %{"value" => "10"}}

      assert UptoEVM.validate_payload(payload, %{}, []) ==
               {:error, {:invalid_upto_payment, :missing_max_price}}
    end

    test "rejects unparsable values" do
      payload = %{"payload" => %{"value" => "lots"}}

      assert UptoEVM.validate_payload(payload, @requirements, []) ==
               {:error, {:invalid_upto_payment, :invalid_payment_value}}

      assert UptoEVM.validate_payload(%{"payload" => %{"value" => "10"}}, %{"amount" => "??"}, []) ==
               {:error, {:invalid_upto_payment, :invalid_max_price}}
    end
  end

  describe "precheck/3" do
    test "checks payTo binding but not amount equality" do
      now = System.system_time(:second)

      payload = %{
        "payload" => %{
          "authorization" => %{
            "to" => "0xreceiver",
            "value" => "500",
            "validAfter" => Integer.to_string(now - 60),
            "validBefore" => Integer.to_string(now + 600)
          }
        }
      }

      # value != amount is fine for upto — the signed value is a ceiling.
      assert UptoEVM.precheck(payload, @requirements, []) == :ok

      mismatched = put_in(payload, ["payload", "authorization", "to"], "0xother")

      assert UptoEVM.precheck(mismatched, @requirements, []) ==
               {:error, {:precheck_failed, :pay_to_mismatch}}
    end
  end
end
