defmodule X402.Scheme.ExactEVMTest do
  use ExUnit.Case, async: true

  doctest X402.Scheme.ExactEVM

  alias X402.Scheme.ExactEVM
  alias X402.Signer.LocalKey

  @requirements %{
    "scheme" => "exact",
    "network" => "eip155:84532",
    "amount" => "10000",
    "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "payTo" => "0x2222222222222222222222222222222222222222",
    "maxTimeoutSeconds" => 300,
    "extra" => %{"name" => "USDC", "version" => "2"}
  }

  defp signer do
    {:ok, signer} = LocalKey.new(:crypto.strong_rand_bytes(32))
    signer
  end

  describe "metadata" do
    test "declares exact on every EVM network" do
      assert ExactEVM.scheme() == "exact"
      assert ExactEVM.networks() == ["eip155:*"]
    end
  end

  describe "signable?/1" do
    test "requires a derivable EIP-712 domain" do
      assert ExactEVM.signable?(@requirements)
      refute ExactEVM.signable?(Map.put(@requirements, "extra", %{}))
      refute ExactEVM.signable?(nil)
    end
  end

  describe "sign/3" do
    test "produces the EIP-3009 scheme payload" do
      assert {:ok, %{"signature" => "0x" <> _sig, "authorization" => authorization}} =
               ExactEVM.sign(@requirements, signer(), valid_after_buffer: 60)

      assert authorization["to"] == @requirements["payTo"]
      assert authorization["value"] == @requirements["amount"]
    end

    test "ignores unrelated client build options" do
      assert {:ok, _payload} =
               ExactEVM.sign(@requirements, signer(), schemes: [], extensions: [])
    end

    test "propagates EIP-3009 errors" do
      missing_domain = Map.put(@requirements, "extra", %{})

      assert ExactEVM.sign(missing_domain, signer(), []) == {:error, {:missing_extra, "name"}}
    end
  end

  describe "validate_payload/3" do
    test "always passes" do
      assert ExactEVM.validate_payload(%{"payload" => %{}}, @requirements, []) == :ok
    end
  end

  describe "precheck/3" do
    test "enforces exact amount equality" do
      now = System.system_time(:second)

      payload = %{
        "payload" => %{
          "authorization" => %{
            "to" => @requirements["payTo"],
            "value" => "9999",
            "validAfter" => Integer.to_string(now - 60),
            "validBefore" => Integer.to_string(now + 600)
          }
        }
      }

      assert ExactEVM.precheck(payload, @requirements, []) ==
               {:error, {:precheck_failed, :amount_mismatch}}

      matching = put_in(payload, ["payload", "authorization", "value"], "10000")
      assert ExactEVM.precheck(matching, @requirements, []) == :ok
    end
  end
end
