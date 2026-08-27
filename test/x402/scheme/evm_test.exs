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
  end
end
