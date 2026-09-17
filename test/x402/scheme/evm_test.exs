defmodule X402.Scheme.EVMTest do
  use ExUnit.Case, async: true

  doctest X402.Scheme.EVM

  alias X402.Scheme.EVM

  @receiver "0x1111111111111111111111111111111111111111"

  defp payload(authorization) do
    %{"payload" => %{"signature" => "0xsig", "authorization" => authorization}}
  end

  defp valid_authorization(overrides \\ %{}) do
    now = System.system_time(:second)

    Map.merge(
      %{
        "from" => "0x2222222222222222222222222222222222222222",
        "to" => @receiver,
        "value" => "10000",
        "validAfter" => Integer.to_string(now - 60),
        "validBefore" => Integer.to_string(now + 600),
        "nonce" => "0xnonce"
      },
      overrides
    )
  end

  defp requirements do
    %{"scheme" => "exact", "payTo" => @receiver, "amount" => "10000"}
  end

  describe "authorization_precheck/3" do
    test "passes a valid authorization" do
      assert EVM.authorization_precheck(payload(valid_authorization()), requirements(),
               enforce_exact_amount: true
             ) == :ok
    end

    test "skips payloads without an authorization map" do
      assert EVM.authorization_precheck(%{"payload" => %{"transaction" => "tx"}}, requirements()) ==
               :ok

      assert EVM.authorization_precheck(%{}, requirements()) == :ok
    end

    test "compares payTo case-insensitively for hex addresses" do
      authorization = valid_authorization(%{"to" => "0xAbCdEf1234567890aBcDeF1234567890AbCdEf12"})

      requirements = %{
        "scheme" => "exact",
        "payTo" => "0xabcdef1234567890abcdef1234567890abcdef12",
        "amount" => "10000"
      }

      assert EVM.authorization_precheck(payload(authorization), requirements) == :ok
    end

    test "rejects payTo mismatches" do
      authorization =
        valid_authorization(%{"to" => "0x9999999999999999999999999999999999999999"})

      assert EVM.authorization_precheck(payload(authorization), requirements()) ==
               {:error, {:precheck_failed, :pay_to_mismatch}}
    end

    test "compares non-hex recipients exactly" do
      authorization = valid_authorization(%{"to" => "till"})

      assert EVM.authorization_precheck(payload(authorization), %{"payTo" => "till"}) == :ok

      assert EVM.authorization_precheck(payload(authorization), %{"payTo" => "TILL"}) ==
               {:error, {:precheck_failed, :pay_to_mismatch}}
    end

    test "enforces exact amount equality only when requested" do
      authorization = valid_authorization(%{"value" => "9999"})

      assert EVM.authorization_precheck(payload(authorization), requirements(),
               enforce_exact_amount: true
             ) == {:error, {:precheck_failed, :amount_mismatch}}

      assert EVM.authorization_precheck(payload(authorization), requirements()) == :ok
    end

    test "rejects unparsable authorization values when enforcing amounts" do
      authorization = valid_authorization(%{"value" => "not-a-number"})

      assert EVM.authorization_precheck(payload(authorization), requirements(),
               enforce_exact_amount: true
             ) == {:error, {:precheck_failed, :invalid_authorization_value}}
    end

    test "skips the amount check when either side is absent" do
      authorization = Map.delete(valid_authorization(), "value")

      assert EVM.authorization_precheck(payload(authorization), requirements(),
               enforce_exact_amount: true
             ) == :ok

      assert EVM.authorization_precheck(
               payload(valid_authorization()),
               Map.delete(requirements(), "amount"),
               enforce_exact_amount: true
             ) == :ok
    end

    test "rejects authorizations that are not yet valid" do
      future = System.system_time(:second) + 600
      authorization = valid_authorization(%{"validAfter" => Integer.to_string(future)})

      assert EVM.authorization_precheck(payload(authorization), requirements()) ==
               {:error, {:precheck_failed, :authorization_not_yet_valid}}
    end

    test "rejects authorizations expiring within the settlement buffer" do
      soon = System.system_time(:second) + 2
      authorization = valid_authorization(%{"validBefore" => Integer.to_string(soon)})

      assert EVM.authorization_precheck(payload(authorization), requirements()) ==
               {:error, {:precheck_failed, :authorization_expired}}
    end

    test "rejects malformed timing values" do
      authorization = valid_authorization(%{"validBefore" => "soon"})

      assert EVM.authorization_precheck(payload(authorization), requirements()) ==
               {:error, {:precheck_failed, :invalid_authorization_timing}}
    end

    test "skips absent timing fields" do
      authorization =
        valid_authorization()
        |> Map.delete("validAfter")
        |> Map.delete("validBefore")

      assert EVM.authorization_precheck(payload(authorization), requirements()) == :ok
    end

    test "skips the payTo check when either side is not a string" do
      non_binary_to = valid_authorization(%{"to" => 42})
      assert EVM.authorization_precheck(payload(non_binary_to), requirements()) == :ok

      missing_pay_to = Map.delete(requirements(), "payTo")

      assert EVM.authorization_precheck(payload(valid_authorization()), missing_pay_to) ==
               :ok
    end

    test "accepts integer timing values" do
      now = System.system_time(:second)

      authorization =
        valid_authorization(%{"validAfter" => now - 60, "validBefore" => now + 600})

      assert EVM.authorization_precheck(payload(authorization), requirements()) == :ok

      expired = valid_authorization(%{"validBefore" => now + 2})

      assert EVM.authorization_precheck(payload(expired), requirements()) ==
               {:error, {:precheck_failed, :authorization_expired}}
    end

    test "rejects timing values that are neither integers nor strings" do
      authorization = valid_authorization(%{"validAfter" => 1.5})

      assert EVM.authorization_precheck(payload(authorization), requirements()) ==
               {:error, {:precheck_failed, :invalid_authorization_timing}}
    end
  end

  # -- permit2_precheck/3 -----------------------------------------------------

  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @proxy "0x402085c248EeA27D92E8b30b2C58ed07f9E20001"

  defp permit2_payload(authorization) do
    %{"payload" => %{"signature" => "0xsig", "permit2Authorization" => authorization}}
  end

  defp valid_permit2_authorization(overrides \\ %{}) do
    now = System.system_time(:second)

    Map.merge(
      %{
        "from" => "0x2222222222222222222222222222222222222222",
        "permitted" => %{"token" => @asset, "amount" => "10000"},
        "spender" => @proxy,
        "nonce" => "1",
        "deadline" => Integer.to_string(now + 600),
        "witness" => %{"to" => @receiver, "validAfter" => Integer.to_string(now - 60)}
      },
      overrides
    )
  end

  defp permit2_requirements do
    %{"scheme" => "exact", "payTo" => @receiver, "amount" => "10000", "asset" => @asset}
  end

  describe "permit2_precheck/3" do
    test "passes a valid authorization with every option" do
      assert EVM.permit2_precheck(
               permit2_payload(valid_permit2_authorization()),
               permit2_requirements(),
               enforce_exact_amount: true,
               spender: @proxy
             ) == :ok
    end

    test "skips payloads without a permit2Authorization map" do
      assert EVM.permit2_precheck(payload(valid_authorization()), permit2_requirements()) == :ok
      assert EVM.permit2_precheck(%{"payload" => %{"permit2Authorization" => "x"}}, %{}) == :ok
    end

    test "tolerates malformed witness and permitted objects" do
      authorization = valid_permit2_authorization(%{"witness" => "nope", "permitted" => 1})

      assert EVM.permit2_precheck(permit2_payload(authorization), permit2_requirements(),
               enforce_exact_amount: true
             ) == :ok
    end

    test "rejects witness recipients that differ from payTo" do
      authorization =
        valid_permit2_authorization(%{
          "witness" => %{
            "to" => "0x9999999999999999999999999999999999999999",
            "validAfter" => "0"
          }
        })

      assert EVM.permit2_precheck(permit2_payload(authorization), permit2_requirements()) ==
               {:error, {:precheck_failed, :pay_to_mismatch}}
    end

    test "enforces the permitted amount only when requested" do
      authorization =
        valid_permit2_authorization(%{"permitted" => %{"token" => @asset, "amount" => "9999"}})

      assert EVM.permit2_precheck(permit2_payload(authorization), permit2_requirements(),
               enforce_exact_amount: true
             ) == {:error, {:precheck_failed, :amount_mismatch}}

      assert EVM.permit2_precheck(permit2_payload(authorization), permit2_requirements()) == :ok
    end

    test "rejects tokens that differ from the asset, case-insensitively" do
      lowercase =
        valid_permit2_authorization(%{"permitted" => %{"token" => String.downcase(@asset)}})

      assert EVM.permit2_precheck(permit2_payload(lowercase), permit2_requirements()) == :ok

      other = valid_permit2_authorization(%{"permitted" => %{"token" => @receiver}})

      assert EVM.permit2_precheck(permit2_payload(other), permit2_requirements()) ==
               {:error, {:precheck_failed, :token_mismatch}}
    end

    test "checks the spender only when one is expected" do
      authorization =
        valid_permit2_authorization(%{"spender" => "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002"})

      assert EVM.permit2_precheck(permit2_payload(authorization), permit2_requirements()) == :ok

      assert EVM.permit2_precheck(permit2_payload(authorization), permit2_requirements(),
               spender: @proxy
             ) == {:error, {:precheck_failed, :spender_mismatch}}

      assert EVM.permit2_precheck(permit2_payload(authorization), permit2_requirements(),
               spender: "0x4020a4f3b7b90cca423b9fabcc0ce57c6c240002"
             ) == :ok
    end

    test "applies the settlement window to deadline and validAfter" do
      now = System.system_time(:second)

      expiring = valid_permit2_authorization(%{"deadline" => Integer.to_string(now + 2)})

      assert EVM.permit2_precheck(permit2_payload(expiring), permit2_requirements()) ==
               {:error, {:precheck_failed, :authorization_expired}}

      future =
        valid_permit2_authorization(%{
          "witness" => %{"to" => @receiver, "validAfter" => Integer.to_string(now + 600)}
        })

      assert EVM.permit2_precheck(permit2_payload(future), permit2_requirements()) ==
               {:error, {:precheck_failed, :authorization_not_yet_valid}}

      malformed = valid_permit2_authorization(%{"deadline" => "soon"})

      assert EVM.permit2_precheck(permit2_payload(malformed), permit2_requirements()) ==
               {:error, {:precheck_failed, :invalid_authorization_timing}}
    end
  end
end
