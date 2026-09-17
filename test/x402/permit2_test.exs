defmodule X402.Permit2Test do
  use ExUnit.Case, async: true

  doctest X402.Permit2

  alias X402.EIP3009
  alias X402.Permit2
  alias X402.Signer
  alias X402.Signer.LocalKey

  @asset "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @pay_to "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
  @facilitator "0x2222222222222222222222222222222222222222"
  @spender "0x4020A4f3b7b90ccA423B9fabCc0CE57C6C240002"
  @permit2 "0x000000000022D473030F116dDEE9F6B43aC78BA3"

  @requirements %{
    "scheme" => "upto",
    "network" => "eip155:84532",
    "amount" => "5000000",
    "asset" => @asset,
    "payTo" => @pay_to,
    "maxTimeoutSeconds" => 300,
    "extra" => %{
      "name" => "USDC",
      "version" => "2",
      "facilitatorAddress" => @facilitator
    }
  }

  # EIP-712 type strings transcribed from the reference contracts: the
  # canonical Permit2 _PERMIT_TRANSFER_FROM_WITNESS_TYPEHASH_STUB plus the
  # x402UptoPermit2Proxy WITNESS_TYPE_STRING.
  @permit_stub "PermitWitnessTransferFrom(TokenPermissions permitted,address spender," <>
                 "uint256 nonce,uint256 deadline,"
  @witness_type_string "Witness witness)TokenPermissions(address token,uint256 amount)" <>
                         "Witness(address to,address facilitator,uint256 validAfter)"

  defp signer do
    {:ok, signer} = LocalKey.new("0x" <> String.duplicate("11", 32))
    signer
  end

  defp address_word("0x" <> hex), do: <<0::96, Base.decode16!(hex, case: :mixed)::binary>>

  defp uint_word(value) when is_binary(value),
    do: <<String.to_integer(value)::unsigned-big-integer-size(256)>>

  describe "upto_domain/1" do
    test "carries no version key" do
      assert {:ok, domain} = Permit2.upto_domain(@requirements)
      refute Map.has_key?(domain, :version)
      assert domain.verifying_contract == @permit2
    end

    test "rejects malformed requirements" do
      assert Permit2.upto_domain("nope") == {:error, :invalid_requirements}
      assert Permit2.upto_domain(%{"network" => "eip155:x"}) == {:error, :unsupported_network}
    end
  end

  describe "facilitator_address/1" do
    test "accepts atom-keyed requirements" do
      assert Permit2.facilitator_address(%{extra: %{facilitatorAddress: @facilitator}}) ==
               {:ok, @facilitator}
    end

    test "rejects missing, empty, or malformed extra" do
      for requirements <- [%{}, %{"extra" => %{}}, %{"extra" => "nope"}, "nope"] do
        assert Permit2.facilitator_address(requirements) ==
                 {:error, {:missing_extra, "facilitatorAddress"}}
      end

      assert Permit2.facilitator_address(%{"extra" => %{"facilitatorAddress" => ""}}) ==
               {:error, {:missing_extra, "facilitatorAddress"}}
    end
  end

  describe "build_upto_authorization/2" do
    test "builds the wire-shape authorization" do
      before_build = System.os_time(:second)
      {:ok, from} = Signer.address(signer())

      assert {:ok, authorization} = Permit2.build_upto_authorization(@requirements, from)

      assert authorization["from"] == from
      assert authorization["permitted"] == %{"token" => @asset, "amount" => "5000000"}
      assert authorization["spender"] == @spender

      assert authorization["witness"] == %{
               "to" => @pay_to,
               "facilitator" => @facilitator,
               "validAfter" => "0"
             }

      deadline = String.to_integer(authorization["deadline"])
      assert deadline >= before_build + 300
      assert deadline <= System.os_time(:second) + 300

      assert String.match?(authorization["nonce"], ~r/^[0-9]+$/)
    end

    test "draws a fresh nonce per authorization" do
      {:ok, first} = Permit2.build_upto_authorization(@requirements, @pay_to)
      {:ok, second} = Permit2.build_upto_authorization(@requirements, @pay_to)

      refute first["nonce"] == second["nonce"]
    end

    test "requires extra.facilitatorAddress" do
      requirements = Map.put(@requirements, "extra", %{"name" => "USDC", "version" => "2"})

      assert Permit2.build_upto_authorization(requirements, @pay_to) ==
               {:error, {:missing_extra, "facilitatorAddress"}}
    end

    test "rejects structurally invalid requirements" do
      for broken <- [
            Map.delete(@requirements, "amount"),
            Map.delete(@requirements, "payTo"),
            Map.put(@requirements, "maxTimeoutSeconds", 0),
            Map.put(@requirements, "maxTimeoutSeconds", "300")
          ] do
        assert Permit2.build_upto_authorization(broken, @pay_to) ==
                 {:error, :invalid_requirements}
      end
    end
  end

  describe "upto_digest/2" do
    test "matches an independent computation from the contract type strings" do
      {:ok, domain} = Permit2.upto_domain(@requirements)

      authorization = %{
        "from" => "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a",
        "permitted" => %{"token" => @asset, "amount" => "5000000"},
        "spender" => @spender,
        "nonce" => "1234567890",
        "deadline" => "1740672154",
        "witness" => %{"to" => @pay_to, "facilitator" => @facilitator, "validAfter" => "0"}
      }

      token_hash =
        ExKeccak.hash_256(
          ExKeccak.hash_256("TokenPermissions(address token,uint256 amount)") <>
            address_word(@asset) <> uint_word("5000000")
        )

      witness_hash =
        ExKeccak.hash_256(
          ExKeccak.hash_256("Witness(address to,address facilitator,uint256 validAfter)") <>
            address_word(@pay_to) <> address_word(@facilitator) <> uint_word("0")
        )

      struct_hash =
        ExKeccak.hash_256(
          ExKeccak.hash_256(@permit_stub <> @witness_type_string) <>
            token_hash <>
            address_word(@spender) <>
            uint_word("1234567890") <> uint_word("1740672154") <> witness_hash
        )

      domain_separator =
        ExKeccak.hash_256(
          ExKeccak.hash_256("EIP712Domain(string name,uint256 chainId,address verifyingContract)") <>
            ExKeccak.hash_256("Permit2") <> <<84_532::256>> <> address_word(@permit2)
        )

      expected = ExKeccak.hash_256(<<0x19, 0x01>> <> domain_separator <> struct_hash)

      assert Permit2.upto_digest(domain, authorization) == {:ok, expected}
    end

    test "returns structured errors for missing or malformed fields" do
      {:ok, domain} = Permit2.upto_domain(@requirements)
      {:ok, authorization} = Permit2.build_upto_authorization(@requirements, @pay_to)

      assert Permit2.upto_digest(domain, Map.delete(authorization, "witness")) ==
               {:error, {:missing_field, "witness"}}

      assert Permit2.upto_digest(domain, Map.put(authorization, "permitted", "nope")) ==
               {:error, {:missing_field, "permitted"}}

      broken = put_in(authorization, ["witness", "facilitator"], "0xnope")
      assert Permit2.upto_digest(domain, broken) == {:error, :invalid_address}

      broken = put_in(authorization, ["permitted", "amount"], "not a number")
      assert Permit2.upto_digest(domain, broken) == {:error, :invalid_amount}
    end
  end

  describe "sign_upto/2" do
    test "produces a signature that recovers to the signer over the digest" do
      signer = signer()
      {:ok, from} = Signer.address(signer)

      assert {:ok, payload} = Permit2.sign_upto(@requirements, signer)
      assert %{"signature" => "0x" <> _, "permit2Authorization" => authorization} = payload
      assert authorization["from"] == from

      {:ok, domain} = Permit2.upto_domain(@requirements)
      {:ok, digest} = Permit2.upto_digest(domain, authorization)

      assert EIP3009.recover_signer(digest, payload["signature"]) == {:ok, from}
    end

    test "requires extra.facilitatorAddress" do
      requirements = Map.put(@requirements, "extra", %{"name" => "USDC", "version" => "2"})

      assert Permit2.sign_upto(requirements, signer()) ==
               {:error, {:missing_extra, "facilitatorAddress"}}
    end

    test "rejects non-EVM networks and malformed input" do
      solana = Map.put(@requirements, "network", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")

      assert Permit2.sign_upto(solana, signer()) == {:error, :unsupported_network}
      assert Permit2.sign_upto("nope", signer()) == {:error, :invalid_requirements}
      assert Permit2.sign_upto(@requirements, :not_a_signer) == {:error, :invalid_signer}
    end
  end

  # -- exact (Permit2 transfer method) ----------------------------------------

  @exact_spender "0x402085c248EeA27D92E8b30b2C58ed07f9E20001"
  @exact_witness_type_string "Witness witness)TokenPermissions(address token,uint256 amount)" <>
                               "Witness(address to,uint256 validAfter)"

  @exact_requirements %{
    "scheme" => "exact",
    "network" => "eip155:84532",
    "amount" => "10000",
    "asset" => @asset,
    "payTo" => @pay_to,
    "maxTimeoutSeconds" => 60,
    "extra" => %{"assetTransferMethod" => "permit2", "name" => "USDC", "version" => "2"}
  }

  @exact_authorization %{
    "from" => "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a",
    "permitted" => %{"token" => @asset, "amount" => "10000"},
    "spender" => @exact_spender,
    "nonce" => "1234567890",
    "deadline" => "1740672154",
    "witness" => %{"to" => @pay_to, "validAfter" => "0"}
  }

  describe "build_exact_authorization/2" do
    test "binds the exact proxy, the exact amount, and payTo" do
      before_build = System.os_time(:second)

      assert {:ok, authorization} =
               Permit2.build_exact_authorization(@exact_requirements, @pay_to)

      assert authorization["from"] == @pay_to
      assert authorization["permitted"] == %{"token" => @asset, "amount" => "10000"}
      assert authorization["spender"] == @exact_spender
      assert authorization["witness"] == %{"to" => @pay_to, "validAfter" => "0"}
      refute Map.has_key?(authorization["witness"], "facilitator")

      deadline = String.to_integer(authorization["deadline"])
      assert deadline >= before_build + 60
      assert deadline <= System.os_time(:second) + 60
    end

    test "does not need a facilitator address" do
      requirements = Map.put(@exact_requirements, "extra", %{"assetTransferMethod" => "permit2"})
      assert {:ok, _authorization} = Permit2.build_exact_authorization(requirements, @pay_to)
    end

    test "rejects structurally invalid requirements" do
      assert Permit2.build_exact_authorization(Map.delete(@exact_requirements, "asset"), @pay_to) ==
               {:error, :invalid_requirements}
    end
  end

  describe "digest/2 for the exact witness" do
    test "matches an independent computation from the x402ExactPermit2Proxy type string" do
      {:ok, domain} = Permit2.domain(@exact_requirements)

      token_hash =
        ExKeccak.hash_256(
          ExKeccak.hash_256("TokenPermissions(address token,uint256 amount)") <>
            address_word(@asset) <> uint_word("10000")
        )

      witness_hash =
        ExKeccak.hash_256(
          ExKeccak.hash_256("Witness(address to,uint256 validAfter)") <>
            address_word(@pay_to) <> uint_word("0")
        )

      struct_hash =
        ExKeccak.hash_256(
          ExKeccak.hash_256(@permit_stub <> @exact_witness_type_string) <>
            token_hash <>
            address_word(@exact_spender) <>
            uint_word("1234567890") <> uint_word("1740672154") <> witness_hash
        )

      domain_separator =
        ExKeccak.hash_256(
          ExKeccak.hash_256("EIP712Domain(string name,uint256 chainId,address verifyingContract)") <>
            ExKeccak.hash_256("Permit2") <> <<84_532::256>> <> address_word(@permit2)
        )

      expected = ExKeccak.hash_256(<<0x19, 0x01>> <> domain_separator <> struct_hash)

      assert Permit2.digest(domain, @exact_authorization) == {:ok, expected}
    end

    test "the witness shape selects the type: adding a facilitator changes the digest" do
      {:ok, domain} = Permit2.domain(@exact_requirements)
      {:ok, exact} = Permit2.digest(domain, @exact_authorization)

      upto =
        put_in(@exact_authorization, ["witness", "facilitator"], @facilitator)

      assert {:ok, upto_digest} = Permit2.digest(domain, upto)
      refute upto_digest == exact
      assert Permit2.upto_digest(domain, upto) == {:ok, upto_digest}
    end

    test "reports missing witness fields" do
      {:ok, domain} = Permit2.domain(@exact_requirements)
      broken = put_in(@exact_authorization, ["witness"], %{"to" => @pay_to})

      assert Permit2.digest(domain, broken) == {:error, {:missing_field, "validAfter"}}
    end
  end

  describe "sign_exact/2" do
    test "produces a signature that recovers to the signer over the exact digest" do
      signer = signer()
      {:ok, from} = Signer.address(signer)

      assert {:ok, payload} = Permit2.sign_exact(@exact_requirements, signer)
      assert %{"signature" => "0x" <> _, "permit2Authorization" => authorization} = payload
      assert authorization["from"] == from
      assert authorization["spender"] == @exact_spender

      {:ok, domain} = Permit2.domain(@exact_requirements)
      {:ok, digest} = Permit2.digest(domain, authorization)

      assert EIP3009.recover_signer(digest, payload["signature"]) == {:ok, from}
    end

    test "rejects non-EVM networks and malformed input" do
      solana = Map.put(@exact_requirements, "network", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp")

      assert Permit2.sign_exact(solana, signer()) == {:error, :unsupported_network}
      assert Permit2.sign_exact("nope", signer()) == {:error, :invalid_requirements}
      assert Permit2.sign_exact(@exact_requirements, :not_a_signer) == {:error, :invalid_signer}
    end
  end

  describe "exact_settle_calldata/2" do
    test "ABI-encodes settle(permit, owner, witness, signature)" do
      signature = :binary.copy(<<0xAB>>, 65)

      assert {:ok, calldata} = Permit2.exact_settle_calldata(@exact_authorization, signature)

      expected_selector =
        binary_part(
          ExKeccak.hash_256(
            "settle(((address,uint256),uint256,uint256),address,(address,uint256),bytes)"
          ),
          0,
          4
        )

      <<selector::binary-size(4), head::binary-size(7 * 32), offset::256, length::256,
        tail::binary>> = calldata

      assert selector == expected_selector

      assert head ==
               address_word(@asset) <>
                 uint_word("10000") <>
                 uint_word("1234567890") <>
                 uint_word("1740672154") <>
                 address_word("0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a") <>
                 address_word(@pay_to) <> uint_word("0")

      assert offset == 8 * 32
      assert length == 65
      assert tail == signature <> :binary.copy(<<0>>, 31)
    end

    test "rejects malformed input" do
      assert Permit2.exact_settle_calldata(@exact_authorization, "") ==
               {:error, :invalid_signature}

      assert Permit2.exact_settle_calldata(Map.delete(@exact_authorization, "from"), <<1>>) ==
               {:error, {:missing_field, "from"}}

      assert Permit2.exact_settle_calldata(
               put_in(@exact_authorization, ["witness"], "nope"),
               <<1>>
             ) == {:error, {:missing_field, "witness"}}

      assert Permit2.exact_settle_calldata(
               put_in(@exact_authorization, ["permitted", "token"], "0xnope"),
               <<1>>
             ) == {:error, :invalid_address}
    end
  end

  describe "upto_settle_calldata/3" do
    test "ABI-encodes settle(permit, amount, owner, witness, signature)" do
      signature = :binary.copy(<<0xCD>>, 65)

      authorization =
        @exact_authorization
        |> Map.put("spender", @spender)
        |> put_in(["witness", "facilitator"], @facilitator)

      assert {:ok, calldata} = Permit2.upto_settle_calldata(authorization, "9000", signature)

      expected_selector =
        binary_part(
          ExKeccak.hash_256(
            "settle(((address,uint256),uint256,uint256),uint256,address," <>
              "(address,address,uint256),bytes)"
          ),
          0,
          4
        )

      <<selector::binary-size(4), head::binary-size(9 * 32), offset::256, length::256,
        tail::binary>> = calldata

      assert selector == expected_selector

      assert head ==
               address_word(@asset) <>
                 uint_word("10000") <>
                 uint_word("1234567890") <>
                 uint_word("1740672154") <>
                 uint_word("9000") <>
                 address_word("0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a") <>
                 address_word(@pay_to) <> address_word(@facilitator) <> uint_word("0")

      assert offset == 10 * 32
      assert length == 65
      assert tail == signature <> :binary.copy(<<0>>, 31)
    end

    test "accepts integer amounts and rejects malformed ones" do
      authorization = put_in(@exact_authorization, ["witness", "facilitator"], @facilitator)

      assert {:ok, _calldata} = Permit2.upto_settle_calldata(authorization, 9000, <<1>>)

      assert Permit2.upto_settle_calldata(authorization, "nope", <<1>>) ==
               {:error, :invalid_amount}

      assert Permit2.upto_settle_calldata(@exact_authorization, "1", <<1>>) ==
               {:error, {:missing_field, "facilitator"}}
    end
  end
end
