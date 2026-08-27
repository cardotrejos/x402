defmodule X402.EIP3009Test do
  use ExUnit.Case, async: true

  doctest X402.EIP3009

  alias X402.EIP3009
  alias X402.Signer.LocalKey
  alias X402.TestPayments

  @receiver "0x2222222222222222222222222222222222222222"
  @contract "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

  @requirements %{
    "scheme" => "exact",
    "network" => "eip155:84532",
    "amount" => "10000",
    "asset" => @contract,
    "payTo" => @receiver,
    "maxTimeoutSeconds" => 300,
    "extra" => %{"name" => "USDC", "version" => "2"}
  }

  @domain %{
    name: "USDC",
    version: "2",
    chain_id: 84_532,
    verifying_contract: @contract
  }

  defp signer(key \\ :crypto.strong_rand_bytes(32)) do
    {:ok, signer} = LocalKey.new(key)
    signer
  end

  describe "domain/1" do
    test "derives the EIP-712 domain from requirements" do
      assert EIP3009.domain(@requirements) ==
               {:ok,
                %{
                  name: "USDC",
                  version: "2",
                  chain_id: 84_532,
                  verifying_contract: @contract
                }}
    end

    test "accepts an explicit eip3009 assetTransferMethod" do
      requirements =
        put_in(@requirements, ["extra", "assetTransferMethod"], "eip3009")

      assert {:ok, _domain} = EIP3009.domain(requirements)
    end

    test "rejects non-default transfer methods" do
      requirements = put_in(@requirements, ["extra", "assetTransferMethod"], "permit2")

      assert EIP3009.domain(requirements) == {:error, {:unsupported_transfer_method, "permit2"}}
    end

    test "requires extra.name and extra.version" do
      assert EIP3009.domain(Map.put(@requirements, "extra", %{"version" => "2"})) ==
               {:error, {:missing_extra, "name"}}

      assert EIP3009.domain(Map.put(@requirements, "extra", %{"name" => "USDC"})) ==
               {:error, {:missing_extra, "version"}}

      assert EIP3009.domain(Map.delete(@requirements, "extra")) ==
               {:error, {:missing_extra, "name"}}
    end

    test "rejects non-EVM networks and malformed chain ids" do
      solana = Map.put(@requirements, "network", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")
      assert EIP3009.domain(solana) == {:error, :unsupported_network}

      assert EIP3009.domain(Map.put(@requirements, "network", "eip155:")) ==
               {:error, :unsupported_network}

      assert EIP3009.domain(Map.put(@requirements, "network", "eip155:abc")) ==
               {:error, :unsupported_network}
    end

    test "rejects malformed requirements" do
      assert EIP3009.domain("not a map") == {:error, :invalid_requirements}

      assert EIP3009.domain(Map.put(@requirements, "extra", "nope")) ==
               {:error, :invalid_requirements}

      assert EIP3009.domain(Map.delete(@requirements, "asset")) == {:error, :invalid_requirements}
    end
  end

  describe "build_authorization/3" do
    test "builds a wire-shape authorization from requirements" do
      from = "0x1111111111111111111111111111111111111111"
      now = System.os_time(:second)

      assert {:ok, authorization} = EIP3009.build_authorization(@requirements, from)

      assert authorization["from"] == from
      assert authorization["to"] == @receiver
      assert authorization["value"] == "10000"
      assert String.match?(authorization["nonce"], ~r/^0x[0-9a-f]{64}$/)

      valid_after = String.to_integer(authorization["validAfter"])
      valid_before = String.to_integer(authorization["validBefore"])
      assert_in_delta valid_after, now - 60, 2
      assert_in_delta valid_before, now + 300, 2
    end

    test "honors the valid_after_buffer option" do
      from = "0x1111111111111111111111111111111111111111"
      now = System.os_time(:second)

      assert {:ok, authorization} =
               EIP3009.build_authorization(@requirements, from, valid_after_buffer: 0)

      assert_in_delta String.to_integer(authorization["validAfter"]), now, 2
    end

    test "generates a fresh nonce per authorization" do
      from = "0x1111111111111111111111111111111111111111"
      {:ok, first} = EIP3009.build_authorization(@requirements, from)
      {:ok, second} = EIP3009.build_authorization(@requirements, from)

      assert first["nonce"] != second["nonce"]
    end

    test "rejects requirements missing amount, payTo, or maxTimeoutSeconds" do
      from = "0x1111111111111111111111111111111111111111"

      for missing <- ["amount", "payTo", "maxTimeoutSeconds"] do
        assert EIP3009.build_authorization(Map.delete(@requirements, missing), from) ==
                 {:error, :invalid_requirements}
      end
    end
  end

  describe "eip712_digest/2" do
    test "matches the battle-tested test-support digest for the same vectors" do
      authorization = %{
        from: "0x1111111111111111111111111111111111111111",
        to: @receiver,
        value: "1",
        valid_after: "0",
        valid_before: "9999999999",
        nonce: "0x" <> String.duplicate("ab", 32)
      }

      assert {:ok, digest} = EIP3009.eip712_digest(@domain, authorization)
      assert byte_size(digest) == 32
      assert digest == TestPayments.eip712_digest(@domain, authorization)
    end

    test "wire-style keys and internal keys produce the same digest" do
      wire_authorization = %{
        "from" => "0x1111111111111111111111111111111111111111",
        "to" => @receiver,
        "value" => "1",
        "validAfter" => "0",
        "validBefore" => "9999999999",
        "nonce" => "0x" <> String.duplicate("ab", 32)
      }

      internal_authorization = %{
        from: "0x1111111111111111111111111111111111111111",
        to: @receiver,
        value: "1",
        valid_after: "0",
        valid_before: "9999999999",
        nonce: "0x" <> String.duplicate("ab", 32)
      }

      wire_domain = %{
        "name" => "USDC",
        "version" => "2",
        "chainId" => 84_532,
        "verifyingContract" => @contract
      }

      assert EIP3009.eip712_digest(wire_domain, wire_authorization) ==
               EIP3009.eip712_digest(@domain, internal_authorization)
    end

    test "returns structured errors for malformed fields" do
      authorization = %{
        "from" => "0x1111111111111111111111111111111111111111",
        "to" => @receiver,
        "value" => "1",
        "validAfter" => "0",
        "validBefore" => "1",
        "nonce" => "0x" <> String.duplicate("ab", 32)
      }

      assert EIP3009.eip712_digest(@domain, Map.put(authorization, "from", "0xnope")) ==
               {:error, :invalid_address}

      assert EIP3009.eip712_digest(@domain, Map.put(authorization, "value", "-1")) ==
               {:error, :invalid_amount}

      assert EIP3009.eip712_digest(@domain, Map.put(authorization, "nonce", "0xdead")) ==
               {:error, :invalid_bytes32}

      assert EIP3009.eip712_digest(@domain, Map.delete(authorization, "from")) ==
               {:error, {:missing_field, "from"}}

      assert EIP3009.eip712_digest(Map.delete(@domain, :chain_id), authorization) ==
               {:error, {:missing_field, "chainId"}}
    end
  end

  describe "sign/3" do
    test "produces the scheme payload with a recoverable signature" do
      key = :crypto.strong_rand_bytes(32)
      signer = signer(key)

      assert {:ok, %{"signature" => signature, "authorization" => authorization}} =
               EIP3009.sign(@requirements, signer)

      assert authorization["from"] == signer.address
      assert authorization["to"] == @receiver
      assert authorization["value"] == "10000"

      {:ok, digest} = EIP3009.eip712_digest(@domain, authorization)
      assert EIP3009.recover_signer(digest, signature) == {:ok, signer.address}
    end

    test "signature verifies against an independently computed digest" do
      key = :crypto.strong_rand_bytes(32)
      signer = signer(key)

      {:ok, %{"signature" => "0x" <> signature_hex, "authorization" => authorization}} =
        EIP3009.sign(@requirements, signer)

      digest = TestPayments.eip712_digest(@domain, authorization)
      <<compact::binary-size(64), v>> = Base.decode16!(signature_hex, case: :lower)
      assert v in [27, 28]

      {:ok, public_key} = ExSecp256k1.recover_compact(digest, compact, v - 27)
      assert TestPayments.public_key_to_address(public_key) == signer.address
    end

    test "propagates domain errors" do
      requirements = Map.put(@requirements, "extra", %{})

      assert EIP3009.sign(requirements, signer()) == {:error, {:missing_extra, "name"}}
    end

    test "propagates signer errors" do
      assert EIP3009.sign(@requirements, :not_a_signer) == {:error, :invalid_signer}
    end
  end

  describe "recover_signer/2" do
    test "accepts hex and raw signatures, with 0/1 or 27/28 recovery bytes" do
      key = :crypto.strong_rand_bytes(32)
      signer = signer(key)
      digest = :crypto.strong_rand_bytes(32)

      {:ok, <<compact::binary-size(64), v>> = raw} =
        LocalKey.sign_eip712(signer, digest, %{})

      hex = "0x" <> Base.encode16(raw, case: :lower)

      assert EIP3009.recover_signer(digest, raw) == {:ok, signer.address}
      assert EIP3009.recover_signer(digest, hex) == {:ok, signer.address}
      assert EIP3009.recover_signer(digest, compact <> <<v - 27>>) == {:ok, signer.address}
    end

    test "rejects malformed signatures and digests" do
      digest = :crypto.strong_rand_bytes(32)

      assert EIP3009.recover_signer(digest, "0xdead") == {:error, :invalid_signature}

      assert EIP3009.recover_signer(digest, :crypto.strong_rand_bytes(64)) ==
               {:error, :invalid_signature}

      assert EIP3009.recover_signer(<<1, 2>>, :crypto.strong_rand_bytes(65)) ==
               {:error, :invalid_signature}
    end
  end

  describe "address helpers" do
    test "derive_address/1 rejects malformed keys" do
      assert EIP3009.derive_address(<<1, 2, 3>>) == {:error, :invalid_private_key}
      assert EIP3009.derive_address(<<0::256>>) == {:error, :invalid_private_key}
    end

    test "public_key_to_address/1 handles 64- and 65-byte keys" do
      key = :crypto.strong_rand_bytes(32)
      {:ok, address} = EIP3009.derive_address(key)
      {:ok, <<4, uncompressed::binary-size(64)>>} = ExSecp256k1.create_public_key(key)

      assert EIP3009.public_key_to_address(<<4, uncompressed::binary>>) == {:ok, address}
      assert EIP3009.public_key_to_address(uncompressed) == {:ok, address}
      assert EIP3009.public_key_to_address(<<1, 2, 3>>) == {:error, :invalid_public_key}
    end
  end
end
