defmodule X402.PaymentRequirementsTest do
  use ExUnit.Case, async: true

  doctest X402.PaymentRequirements

  alias X402.PaymentRequirements

  @requirements %{
    "scheme" => "exact",
    "network" => "eip155:84532",
    "amount" => "10000",
    "asset" => "0xasset",
    "payTo" => "0xreceiver",
    "maxTimeoutSeconds" => 60,
    "extra" => %{"name" => "USDC", "nested" => %{"version" => "2"}}
  }

  test "validates field types" do
    assert {:error, {:invalid_fields, ["amount"]}} =
             PaymentRequirements.validate(%{@requirements | "amount" => 10_000})

    assert {:error, {:invalid_fields, ["amount"]}} =
             PaymentRequirements.validate(%{@requirements | "amount" => "0.01"})

    assert {:error, {:invalid_fields, ["maxTimeoutSeconds"]}} =
             PaymentRequirements.validate(%{@requirements | "maxTimeoutSeconds" => 0})

    assert {:error, {:invalid_fields, ["extra"]}} =
             PaymentRequirements.validate(%{@requirements | "extra" => []})

    assert {:error, :invalid_payment_requirements} = PaymentRequirements.validate([])
  end

  test "matches every core field and accepts additive extra metadata" do
    accepted =
      put_in(@requirements, ["extra", "clientNonce"], "nonce")

    assert PaymentRequirements.match?(@requirements, accepted)

    refute PaymentRequirements.match?(
             @requirements,
             Map.put(accepted, "maxTimeoutSeconds", 30)
           )

    refute PaymentRequirements.match?(
             @requirements,
             put_in(accepted, ["extra", "nested", "version"], "1")
           )

    refute PaymentRequirements.match?(@requirements, Map.put(accepted, "unknown", true))
    refute PaymentRequirements.match?(@requirements, Map.delete(accepted, "extra"))
  end

  test "normalizes atom keys without creating atoms" do
    atom_requirements = %{
      scheme: "exact",
      network: "eip155:84532",
      amount: "10000",
      asset: "0xasset",
      payTo: "0xreceiver",
      maxTimeoutSeconds: 60,
      extra: %{name: "USDC"}
    }

    assert PaymentRequirements.match?(atom_requirements, %{
             @requirements
             | "extra" => %{"name" => "USDC"}
           })
  end

  test "treats a required object without extra as preserved" do
    assert PaymentRequirements.match?(%{"scheme" => "exact"}, %{"scheme" => "exact"})

    assert PaymentRequirements.match?(
             %{"scheme" => "exact"},
             %{"scheme" => "exact", "extra" => %{"name" => "USDC"}}
           )
  end

  test "match?/2 returns false for non-map arguments" do
    refute PaymentRequirements.match?(nil, %{"scheme" => "exact"})
    refute PaymentRequirements.match?(%{"scheme" => "exact"}, "exact")
  end

  test "extensions_match?/2 returns false for non-map advertised extensions" do
    refute PaymentRequirements.extensions_match?(nil, %{})
    refute PaymentRequirements.extensions_match?("extensions", %{})
  end

  test "matches echoed extensions without an info wrapper as a subset" do
    advertised = %{"plain" => %{"required" => true}}

    assert PaymentRequirements.extensions_match?(advertised, %{
             "plain" => %{"required" => true, "client" => "value"}
           })

    refute PaymentRequirements.extensions_match?(advertised, %{"plain" => %{}})
  end

  test "matches scalar extension values by equality" do
    assert PaymentRequirements.extensions_match?(%{"flag" => "v1"}, %{"flag" => "v1"})
    refute PaymentRequirements.extensions_match?(%{"flag" => "v1"}, %{"flag" => "v2"})
  end

  test "validates echoed extensions and ignores unadvertised client extensions" do
    advertised = %{
      "one" => %{"info" => %{"required" => true}, "schema" => %{"type" => "object"}}
    }

    assert PaymentRequirements.extensions_match?(advertised, nil)

    assert PaymentRequirements.extensions_match?(advertised, %{
             "one" => %{
               "info" => %{"required" => true, "client" => "value"},
               "schema" => %{"type" => "object"}
             },
             "client-only" => %{"info" => %{}}
           })

    assert PaymentRequirements.extensions_match?(advertised, %{
             "one" => %{"info" => %{"required" => true}}
           })

    refute PaymentRequirements.extensions_match?(advertised, %{
             "one" => %{"info" => %{"required" => false}}
           })

    refute PaymentRequirements.extensions_match?(advertised, [])
  end
end
