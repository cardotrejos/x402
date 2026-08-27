defmodule X402.Scheme.RegistryTest do
  use ExUnit.Case, async: true

  doctest X402.Scheme.Registry

  alias X402.Scheme.Registry

  defmodule WildcardEVM do
    @moduledoc false
    @behaviour X402.Scheme

    @impl X402.Scheme
    def scheme, do: "exact"

    @impl X402.Scheme
    def networks, do: ["eip155:*"]
  end

  defmodule BaseSepoliaOnly do
    @moduledoc false
    @behaviour X402.Scheme

    @impl X402.Scheme
    def scheme, do: "exact"

    @impl X402.Scheme
    def networks, do: ["eip155:84532"]
  end

  defmodule SolanaExact do
    @moduledoc false
    @behaviour X402.Scheme

    @impl X402.Scheme
    def scheme, do: "exact"

    @impl X402.Scheme
    def networks, do: ["solana:*"]
  end

  defmodule CatchAll do
    @moduledoc false
    @behaviour X402.Scheme

    @impl X402.Scheme
    def scheme, do: "exact"

    @impl X402.Scheme
    def networks, do: ["*"]
  end

  describe "builtins/0" do
    test "seeds exact on EVM and SVM plus upto on EVM" do
      assert Registry.builtins() == [
               X402.Scheme.ExactEVM,
               X402.Scheme.ExactSVM,
               X402.Scheme.UptoEVM
             ]
    end
  end

  describe "resolve/3 with the built-ins" do
    test "resolves exact and upto on any eip155 network" do
      assert Registry.resolve("exact", "eip155:1") == {:ok, X402.Scheme.ExactEVM}
      assert Registry.resolve("exact", "eip155:84532") == {:ok, X402.Scheme.ExactEVM}
      assert Registry.resolve("upto", "eip155:8453") == {:ok, X402.Scheme.UptoEVM}
    end

    test "resolves exact on any solana network" do
      assert Registry.resolve("exact", "solana:mainnet") == {:ok, X402.Scheme.ExactSVM}

      assert Registry.resolve("exact", "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1") ==
               {:ok, X402.Scheme.ExactSVM}
    end

    test "does not resolve unregistered kinds" do
      assert Registry.resolve("cash", "eip155:1") == :error
      assert Registry.resolve("upto", "solana:mainnet") == :error
      assert Registry.resolve("exact", "bip122:000000000019d6689c085ae165831e93") == :error
    end

    test "does not resolve non-binary scheme or network" do
      assert Registry.resolve([], nil, "eip155:1") == :error
      assert Registry.resolve([], "exact", nil) == :error
      assert Registry.resolve([], :exact, "eip155:1") == :error
    end
  end

  describe "resolve/3 with extra schemes" do
    test "extends resolution to new kinds" do
      assert Registry.resolve([SolanaExact], "exact", "solana:mainnet") == {:ok, SolanaExact}
      assert Registry.resolve([SolanaExact], "exact", "eip155:1") == {:ok, X402.Scheme.ExactEVM}
    end

    test "an exact network match beats any wildcard" do
      # BaseSepoliaOnly is listed after the wildcard module but matches the
      # network exactly, so it wins.
      assert Registry.resolve([WildcardEVM, BaseSepoliaOnly], "exact", "eip155:84532") ==
               {:ok, BaseSepoliaOnly}

      # For other networks, the wildcard applies.
      assert Registry.resolve([WildcardEVM, BaseSepoliaOnly], "exact", "eip155:1") ==
               {:ok, WildcardEVM}
    end

    test "an extra exact match beats the built-in wildcard" do
      assert Registry.resolve([BaseSepoliaOnly], "exact", "eip155:84532") ==
               {:ok, BaseSepoliaOnly}
    end

    test "the longest wildcard prefix wins" do
      # CatchAll ("*") is listed first, but the built-in "eip155:*" is more
      # specific.
      assert Registry.resolve([CatchAll], "exact", "eip155:1") == {:ok, X402.Scheme.ExactEVM}

      # For networks no other pattern covers, the catch-all applies.
      assert Registry.resolve([CatchAll], "exact", "tezos:mainnet") == {:ok, CatchAll}
    end

    test "equally specific wildcards go to the earlier module" do
      # WildcardEVM's "eip155:*" ties with the built-in's; extra schemes are
      # consulted first, so the user module overrides the built-in.
      assert Registry.resolve([WildcardEVM], "exact", "eip155:1") == {:ok, WildcardEVM}
    end

    test "duplicate modules are ignored" do
      assert Registry.resolve(
               [X402.Scheme.ExactEVM, X402.Scheme.ExactEVM],
               "exact",
               "eip155:1"
             ) == {:ok, X402.Scheme.ExactEVM}
    end
  end

  describe "network_matches?/2" do
    test "wildcard patterns match by prefix" do
      assert Registry.network_matches?("eip155:*", "eip155:84532")
      refute Registry.network_matches?("eip155:*", "solana:mainnet")
      assert Registry.network_matches?("*", "anything:at-all")
    end

    test "plain patterns match exactly" do
      assert Registry.network_matches?("eip155:1", "eip155:1")
      refute Registry.network_matches?("eip155:1", "eip155:10")
    end

    test "non-binary input never matches" do
      refute Registry.network_matches?(nil, "eip155:1")
      refute Registry.network_matches?("eip155:*", nil)
    end
  end
end
