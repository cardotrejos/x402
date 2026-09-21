defmodule X402.Extensions.SIWX.MessageTest do
  use ExUnit.Case, async: true

  doctest X402.Extensions.SIWX.Message

  alias X402.Extensions.SIWX.Message

  @evm_fields %{
    "domain" => "api.example.com",
    "address" => "0x857b06519E91e3A54538791bDbb0E22373e36b66",
    "uri" => "https://api.example.com",
    "version" => "1",
    "chainId" => "eip155:8453",
    "nonce" => "a1b2c3d4e5f67890a1b2c3d4e5f67890",
    "issuedAt" => "2024-01-15T10:30:00.000Z"
  }

  @solana_fields %{
    @evm_fields
    | "address" => "BSmWDgE9ex6dZYbiTsJGcwMEgFp8q4aWh92hdErQPeVW",
      "chainId" => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
  }

  describe "build/1" do
    test "renders an EIP-4361 message without a statement (two blank lines)" do
      assert {:ok, text} = Message.build(@evm_fields)

      assert text ==
               """
               api.example.com wants you to sign in with your Ethereum account:
               0x857b06519E91e3A54538791bDbb0E22373e36b66


               URI: https://api.example.com
               Version: 1
               Chain ID: 8453
               Nonce: a1b2c3d4e5f67890a1b2c3d4e5f67890
               Issued At: 2024-01-15T10:30:00.000Z\
               """
    end

    test "renders a Sign-In With Solana message without a statement (one blank line)" do
      assert {:ok, text} = Message.build(@solana_fields)

      assert text ==
               """
               api.example.com wants you to sign in with your Solana account:
               BSmWDgE9ex6dZYbiTsJGcwMEgFp8q4aWh92hdErQPeVW

               URI: https://api.example.com
               Version: 1
               Chain ID: 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp
               Nonce: a1b2c3d4e5f67890a1b2c3d4e5f67890
               Issued At: 2024-01-15T10:30:00.000Z\
               """
    end

    test "renders every optional field in spec order" do
      fields =
        Map.merge(@solana_fields, %{
          "statement" => "Sign in to access premium data",
          "expirationTime" => "2024-01-15T10:35:00.000Z",
          "notBefore" => "2024-01-15T10:31:00.000Z",
          "requestId" => "req-123",
          "resources" => ["https://api.example.com/a", "https://api.example.com/b"]
        })

      assert {:ok, text} = Message.build(fields)

      assert text ==
               """
               api.example.com wants you to sign in with your Solana account:
               BSmWDgE9ex6dZYbiTsJGcwMEgFp8q4aWh92hdErQPeVW

               Sign in to access premium data

               URI: https://api.example.com
               Version: 1
               Chain ID: 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp
               Nonce: a1b2c3d4e5f67890a1b2c3d4e5f67890
               Issued At: 2024-01-15T10:30:00.000Z
               Expiration Time: 2024-01-15T10:35:00.000Z
               Not Before: 2024-01-15T10:31:00.000Z
               Request ID: req-123
               Resources:
               - https://api.example.com/a
               - https://api.example.com/b\
               """
    end

    test "omits empty resources, empty optional strings, and non-string resource entries" do
      fields =
        Map.merge(@evm_fields, %{
          "statement" => "",
          "resources" => [],
          "requestId" => nil
        })

      assert {:ok, text} = Message.build(fields)
      refute text =~ "Resources:"
      refute text =~ "Request ID:"

      assert {:ok, text} = Message.build(Map.put(@evm_fields, "resources", [1, "https://x"]))
      assert text =~ "Resources:\n- https://x"
    end

    test "reads snake_case atom keys" do
      fields = %{
        domain: "api.example.com",
        address: "0x857b06519E91e3A54538791bDbb0E22373e36b66",
        uri: "https://api.example.com",
        version: "1",
        chain_id: "eip155:1",
        nonce: "a1b2c3d4e5f67890a1b2c3d4e5f67890",
        issued_at: "2024-01-15T10:30:00.000Z",
        expiration_time: "2024-01-15T10:35:00.000Z"
      }

      assert {:ok, text} = Message.build(fields)
      assert text =~ "Chain ID: 1\n"
      assert text =~ "Expiration Time: 2024-01-15T10:35:00.000Z"
    end

    test "returns errors for missing fields and unsupported chains" do
      assert Message.build(Map.delete(@evm_fields, "nonce")) == {:error, :invalid_fields}
      assert Message.build(Map.put(@evm_fields, "domain", "")) == {:error, :invalid_fields}

      assert Message.build(Map.put(@evm_fields, "chainId", "eip155:0")) ==
               {:error, :invalid_chain_id}

      assert Message.build(Map.put(@evm_fields, "chainId", "solana:0")) ==
               {:error, :invalid_chain_id}

      assert Message.build(Map.put(@evm_fields, "chainId", "cosmos:hub")) ==
               {:error, :unsupported_chain}

      assert Message.build("nope") == {:error, :invalid_fields}
    end
  end

  describe "family/1" do
    test "classifies chain ids" do
      assert Message.family("eip155:1") == {:ok, :eip155}
      assert Message.family("eip155:01") == {:error, :invalid_chain_id}
      assert Message.family("solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1") == {:ok, :solana}
      assert Message.family("solana:0OIl") == {:error, :invalid_chain_id}
      assert Message.family(nil) == {:error, :unsupported_chain}
    end
  end

  describe "chain_reference/1" do
    test "returns the reference or the whole id when there is no namespace" do
      assert Message.chain_reference("eip155:1") == "1"
      assert Message.chain_reference("mainnet") == "mainnet"
    end
  end
end
