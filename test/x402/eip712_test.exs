defmodule X402.EIP712Test do
  use ExUnit.Case, async: true

  doctest X402.EIP712

  alias X402.EIP712
  alias X402.TestPayments

  @contract "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

  @domain %{
    name: "USDC",
    version: "2",
    chain_id: 84_532,
    verifying_contract: @contract
  }

  @requirements %{
    "scheme" => "exact",
    "network" => "eip155:84532",
    "amount" => "10000",
    "asset" => @contract,
    "payTo" => "0x2222222222222222222222222222222222222222",
    "maxTimeoutSeconds" => 300,
    "extra" => %{"name" => "USDC", "version" => "2"}
  }

  describe "domain/1" do
    test "derives the domain from requirements" do
      assert EIP712.domain(@requirements) == {:ok, @domain}
    end

    test "does not restrict the assetTransferMethod" do
      for method <- ["eip3009", "permit2"] do
        requirements = put_in(@requirements, ["extra", "assetTransferMethod"], method)
        assert EIP712.domain(requirements) == {:ok, @domain}
      end
    end

    test "requires extra.name and extra.version" do
      assert EIP712.domain(Map.put(@requirements, "extra", %{"version" => "2"})) ==
               {:error, {:missing_extra, "name"}}

      assert EIP712.domain(Map.put(@requirements, "extra", %{"name" => "USDC"})) ==
               {:error, {:missing_extra, "version"}}
    end

    test "rejects non-EVM networks and malformed requirements" do
      solana = Map.put(@requirements, "network", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
      assert EIP712.domain(solana) == {:error, :unsupported_network}

      assert EIP712.domain("not a map") == {:error, :invalid_requirements}

      assert EIP712.domain(Map.put(@requirements, "extra", "nope")) ==
               {:error, :invalid_requirements}

      assert EIP712.domain(Map.delete(@requirements, "asset")) == {:error, :invalid_requirements}
    end
  end

  describe "domain_separator/1" do
    test "accepts wire-style and internal keys" do
      wire_domain = %{
        "name" => "USDC",
        "version" => "2",
        "chainId" => 84_532,
        "verifyingContract" => @contract
      }

      assert {:ok, separator} = EIP712.domain_separator(@domain)
      assert byte_size(separator) == 32
      assert EIP712.domain_separator(wire_domain) == {:ok, separator}
    end

    test "returns structured errors for missing or malformed fields" do
      assert EIP712.domain_separator(Map.delete(@domain, :chain_id)) ==
               {:error, {:missing_field, "chainId"}}

      assert EIP712.domain_separator(%{@domain | verifying_contract: "0xnope"}) ==
               {:error, :invalid_address}
    end

    test "hashes the three-field EIP712Domain type for version-less domains" do
      domain = %{name: "Permit2", chain_id: 84_532, verifying_contract: @contract}

      "0x" <> contract_hex = @contract
      contract_word = <<0::96, Base.decode16!(contract_hex, case: :mixed)::binary>>

      expected =
        ExKeccak.hash_256(
          ExKeccak.hash_256("EIP712Domain(string name,uint256 chainId,address verifyingContract)") <>
            ExKeccak.hash_256("Permit2") <> <<84_532::256>> <> contract_word
        )

      assert EIP712.domain_separator(domain) == {:ok, expected}

      # A versioned domain hashes differently.
      assert {:ok, versioned} = EIP712.domain_separator(Map.put(domain, :version, "1"))
      refute versioned == expected
    end
  end

  describe "hash_struct/2 and digest/2" do
    test "reproduce the EIP-3009 digest for the same vectors" do
      authorization = %{
        from: "0x1111111111111111111111111111111111111111",
        to: "0x2222222222222222222222222222222222222222",
        value: "1",
        valid_after: "0",
        valid_before: "9999999999",
        nonce: "0x" <> String.duplicate("ab", 32)
      }

      type =
        "TransferWithAuthorization(address from,address to,uint256 value," <>
          "uint256 validAfter,uint256 validBefore,bytes32 nonce)"

      {:ok, from_word} = EIP712.encode_address(authorization.from)
      {:ok, to_word} = EIP712.encode_address(authorization.to)
      {:ok, value_word} = EIP712.encode_uint256(authorization.value)
      {:ok, valid_after_word} = EIP712.encode_uint256(authorization.valid_after)
      {:ok, valid_before_word} = EIP712.encode_uint256(authorization.valid_before)
      {:ok, nonce_word} = EIP712.encode_bytes32(authorization.nonce)

      {:ok, struct_hash} =
        EIP712.hash_struct(type, [
          from_word,
          to_word,
          value_word,
          valid_after_word,
          valid_before_word,
          nonce_word
        ])

      assert {:ok, digest} = EIP712.digest(@domain, struct_hash)
      assert digest == TestPayments.eip712_digest(@domain, authorization)
    end

    test "hash_struct/2 rejects words that are not 32 bytes" do
      assert EIP712.hash_struct("Permit()", [<<1, 2, 3>>]) == {:error, :invalid_word}
      assert EIP712.hash_struct("Permit()", [:not_a_word]) == {:error, :invalid_word}
    end

    test "digest/2 propagates domain errors" do
      assert EIP712.digest(%{}, <<0::256>>) == {:error, {:missing_field, "name"}}
    end
  end
end
