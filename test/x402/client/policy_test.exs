defmodule X402.Client.PolicyTest do
  use ExUnit.Case, async: true

  doctest X402.Client.Policy

  alias X402.Client.Policy

  describe "max_amount/1" do
    test "compares decimal amounts and skips missing ones" do
      policy = Policy.max_amount("1.5")

      assert policy.(%{"amount" => "1.50"}, nil)
      assert policy.(%{amount: "0.75"}, nil)
      refute policy.(%{"amount" => "1.51"}, nil)
      refute policy.(%{"scheme" => "exact"}, nil)
      assert policy.(%{"amount" => 1}, %{"accepts" => []})
      refute policy.(%{"amount" => 2}, %{"accepts" => []})
    end

    test "rejects negative limits" do
      assert_raise FunctionClauseError, fn -> Policy.max_amount(-1) end
    end
  end

  describe "networks/1" do
    test "matches exact ids and wildcard prefixes, skipping non-binary networks" do
      policy = Policy.networks(["eip155:8453", "solana:*"])

      assert policy.(%{network: "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1"}, nil)
      refute policy.(%{"network" => "eip155:84532"}, nil)
      refute policy.(%{"network" => 8453}, nil)
      refute Policy.networks([]).(%{"network" => "eip155:8453"}, nil)
    end
  end

  describe "assets/1" do
    test "compares case-insensitively and skips non-binary assets" do
      policy = Policy.assets(["EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"])

      assert policy.(%{asset: "epjfwdd5aufqssqem2qn1xzybapc8g4weggkzwytdt1v"}, nil)
      refute policy.(%{"asset" => nil}, nil)
    end
  end

  describe "schemes/1" do
    test "accepts listed schemes only" do
      policy = Policy.schemes(["exact", "upto"])

      assert policy.(%{scheme: "upto"}, nil)
      refute policy.(%{"scheme" => "deferred"}, nil)
      refute policy.(%{}, nil)
    end
  end
end
