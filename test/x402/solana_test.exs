defmodule X402.SolanaTest do
  use ExUnit.Case, async: true

  doctest X402.Solana

  alias X402.Base58
  alias X402.Solana

  # Vectors generated with @solana/kit 8.0.0 (`findAssociatedTokenPda` /
  # `getProgramDerivedAddress` / `createKeyPairSignerFromPrivateKeyBytes`)
  # against fixed Ed25519 seeds: 0x01*32 (client), 0x02*32 (fee payer),
  # 0x03*32 (payTo). See the exact SVM scheme fixture in
  # test/x402/scheme/exact_svm_test.exs for the same provenance.
  @client "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"
  @pay_to "GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse"
  @usdc "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
  @pyusd "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo"
  @source_ata "3wvJdyFnGvaMWpbq93NU91SggiVRveULUXL6iX5VZDGP"
  @dest_ata "DNDTCnZkNk358qDFZd9unHtnrc73SsXcpVWtwJJMrR4B"
  @dest_2022_ata "5AJ5PmLBPTY9JkKPSkSdNrghd1iqoWh1U55g3ByVG41y"

  describe "decode_address/1 and valid_address?/1" do
    test "decodes valid 32-byte addresses" do
      assert {:ok, pubkey} = Solana.decode_address(@usdc)
      assert byte_size(pubkey) == 32
    end

    test "rejects addresses that decode to other sizes" do
      # 31 bytes of data encodes to a shorter string.
      short = Base58.encode(:binary.copy(<<7>>, 31))
      assert Solana.decode_address(short) == {:error, :invalid_address}
      refute Solana.valid_address?(short)
    end

    test "rejects invalid base58" do
      refute Solana.valid_address?("not base58 0OIl")
      refute Solana.valid_address?(nil)
      refute Solana.valid_address?(42)
    end
  end

  describe "on_curve?/1" do
    test "Ed25519 public keys are on the curve" do
      for seed_byte <- 1..10 do
        {public, _private} =
          :crypto.generate_key(:eddsa, :ed25519, :binary.copy(<<seed_byte>>, 32))

        assert Solana.on_curve?(public)
      end
    end

    test "derived program addresses are off the curve" do
      for address <- [@source_ata, @dest_ata, @dest_2022_ata] do
        {:ok, pubkey} = Solana.decode_address(address)
        refute Solana.on_curve?(pubkey)
      end
    end

    test "points with x = 0 are on the curve only with a zero sign bit" do
      # y = 1 solves x^2 = (y^2 - 1) / (d*y^2 + 1) with x = 0; RFC 8032
      # requires the sign bit to be 0 when x = 0.
      y_one = <<1>> <> :binary.copy(<<0>>, 31)
      assert Solana.on_curve?(y_one)

      y_one_negative_sign = <<1>> <> :binary.copy(<<0>>, 30) <> <<0x80>>
      refute Solana.on_curve?(y_one_negative_sign)
    end
  end

  describe "find_program_address/2" do
    test "matches @solana/kit getProgramDerivedAddress vectors" do
      {:ok, owner} = Solana.decode_address(@pay_to)
      {:ok, token_program} = Solana.decode_address(Solana.token_program())
      {:ok, mint} = Solana.decode_address(@usdc)

      assert {:ok, {address, 255}} =
               Solana.find_program_address(
                 [owner, token_program, mint],
                 Solana.ata_program()
               )

      assert Base58.encode(address) == @dest_ata
    end

    test "rejects invalid seeds" do
      too_long = :binary.copy(<<1>>, 33)

      assert Solana.find_program_address([too_long], Solana.ata_program()) ==
               {:error, :invalid_seeds}

      too_many = List.duplicate("seed", 17)

      assert Solana.find_program_address(too_many, Solana.ata_program()) ==
               {:error, :invalid_seeds}
    end

    test "rejects an invalid program id" do
      assert Solana.find_program_address(["seed"], "bogus") == {:error, :invalid_address}
    end
  end

  describe "associated_token_address/3" do
    test "derives the SPL Token ATAs from the reference fixture" do
      assert Solana.associated_token_address(@client, @usdc, Solana.token_program()) ==
               {:ok, @source_ata}

      assert Solana.associated_token_address(@pay_to, @usdc, Solana.token_program()) ==
               {:ok, @dest_ata}
    end

    test "derives Token-2022 ATAs from the reference fixture" do
      assert Solana.associated_token_address(@pay_to, @pyusd, Solana.token_2022_program()) ==
               {:ok, @dest_2022_ata}
    end

    test "rejects invalid inputs" do
      assert Solana.associated_token_address("nope", @usdc, Solana.token_program()) ==
               {:error, :invalid_address}

      assert Solana.associated_token_address(@client, "nope", Solana.token_program()) ==
               {:error, :invalid_address}
    end
  end
end
