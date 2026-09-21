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

  # -- Permit2 transfer method ------------------------------------------------

  @permit2_requirements Map.put(@requirements, "extra", %{
                          "assetTransferMethod" => "permit2",
                          "name" => "USDC",
                          "version" => "2"
                        })

  @exact_proxy "0x402085c248EeA27D92E8b30b2C58ed07f9E20001"

  describe "transfer_method/1" do
    test "defaults to eip3009 and honours atom keys" do
      assert ExactEVM.transfer_method(@requirements) == {:ok, :eip3009}

      assert ExactEVM.transfer_method(%{extra: %{assetTransferMethod: "permit2"}}) ==
               {:ok, :permit2}

      assert ExactEVM.transfer_method(%{"extra" => "nope"}) == {:ok, :eip3009}
    end
  end

  describe "signable?/1 with Permit2" do
    test "needs only an EVM network, not a token domain" do
      assert ExactEVM.signable?(@permit2_requirements)

      assert ExactEVM.signable?(%{
               "network" => "eip155:1",
               "extra" => %{"assetTransferMethod" => "permit2"}
             })

      refute ExactEVM.signable?(Map.put(@permit2_requirements, "network", "solana:mainnet"))
    end
  end

  describe "sign/3 with Permit2" do
    test "produces the Permit2 scheme payload bound to the exact proxy" do
      assert {:ok, %{"signature" => "0x" <> _sig, "permit2Authorization" => authorization}} =
               ExactEVM.sign(@permit2_requirements, signer(), valid_after_buffer: 60)

      assert authorization["spender"] == @exact_proxy
      assert authorization["permitted"]["amount"] == @requirements["amount"]
      assert authorization["witness"]["to"] == @requirements["payTo"]
      refute Map.has_key?(authorization, "authorization")
    end

    test "rejects unsupported transfer methods" do
      requirements = put_in(@permit2_requirements, ["extra", "assetTransferMethod"], "erc7710")

      assert ExactEVM.sign(requirements, signer(), []) ==
               {:error, {:unsupported_transfer_method, "erc7710"}}
    end
  end

  describe "precheck/3 with Permit2" do
    setup do
      now = System.system_time(:second)

      payload = %{
        "payload" => %{
          "permit2Authorization" => %{
            "permitted" => %{"token" => @requirements["asset"], "amount" => "10000"},
            "spender" => String.downcase(@exact_proxy),
            "deadline" => Integer.to_string(now + 600),
            "witness" => %{"to" => @requirements["payTo"], "validAfter" => "0"}
          }
        }
      }

      %{payload: payload}
    end

    test "passes a matching authorization", %{payload: payload} do
      assert ExactEVM.precheck(payload, @permit2_requirements, []) == :ok
    end

    test "enforces exact amount, token, spender, recipient, and window", %{payload: payload} do
      path = ["payload", "permit2Authorization"]

      assert ExactEVM.precheck(
               put_in(payload, path ++ ["permitted", "amount"], "9999"),
               @permit2_requirements,
               []
             ) == {:error, {:precheck_failed, :amount_mismatch}}

      assert ExactEVM.precheck(
               put_in(
                 payload,
                 path ++ ["permitted", "token"],
                 "0x1111111111111111111111111111111111111111"
               ),
               @permit2_requirements,
               []
             ) == {:error, {:precheck_failed, :token_mismatch}}

      assert ExactEVM.precheck(
               put_in(payload, path ++ ["spender"], "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002"),
               @permit2_requirements,
               []
             ) == {:error, {:precheck_failed, :spender_mismatch}}

      assert ExactEVM.precheck(
               put_in(
                 payload,
                 path ++ ["witness", "to"],
                 "0x3333333333333333333333333333333333333333"
               ),
               @permit2_requirements,
               []
             ) == {:error, {:precheck_failed, :pay_to_mismatch}}

      assert ExactEVM.precheck(
               put_in(payload, path ++ ["deadline"], "1"),
               @permit2_requirements,
               []
             ) == {:error, {:precheck_failed, :authorization_expired}}

      assert ExactEVM.precheck(
               put_in(payload, path ++ ["witness", "validAfter"], "99999999999"),
               @permit2_requirements,
               []
             ) == {:error, {:precheck_failed, :authorization_not_yet_valid}}
    end
  end
end
