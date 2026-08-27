defmodule X402.Signer.SolanaKeyTest do
  use ExUnit.Case, async: true

  doctest X402.Signer.SolanaKey

  alias X402.Base58
  alias X402.Signer
  alias X402.Signer.SolanaKey

  # Seed 0x01*32 derives this address in @solana/kit 8.0.0 too.
  @seed :binary.copy(<<1>>, 32)
  @address "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"

  describe "new/1" do
    test "accepts a raw 32-byte seed" do
      assert {:ok, signer} = SolanaKey.new(@seed)
      assert signer.address == @address
    end

    test "accepts a 64-byte solana-keygen keypair" do
      {public, _private} = :crypto.generate_key(:eddsa, :ed25519, @seed)

      assert {:ok, signer} = SolanaKey.new(@seed <> public)
      assert signer.address == @address
    end

    test "rejects a keypair whose public half does not match" do
      assert SolanaKey.new(@seed <> :binary.copy(<<9>>, 32)) ==
               {:error, :invalid_private_key}
    end

    test "Base58 keys whose text is also valid Base64 decode as Base58" do
      # 44- and 88-character Base58 strings are valid Base64 lengths too; a
      # Base64-first decode yields 33/66 garbage bytes and rejects real
      # Phantom / solana-keygen imports (review finding).
      base58_seed = Base58.encode(@seed)
      assert rem(byte_size(base58_seed), 4) == 0 or byte_size(base58_seed) in [43, 44]
      assert {:ok, %{address: @address}} = SolanaKey.new(base58_seed)

      {public, _} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      base58_keypair = Base58.encode(@seed <> public)
      assert {:ok, %{address: @address}} = SolanaKey.new(base58_keypair)
    end

    test "accepts Base58 and Base64 encodings" do
      {public, _private} = :crypto.generate_key(:eddsa, :ed25519, @seed)

      assert {:ok, %{address: @address}} = SolanaKey.new(Base58.encode(@seed))
      assert {:ok, %{address: @address}} = SolanaKey.new(Base.encode64(@seed))
      assert {:ok, %{address: @address}} = SolanaKey.new(Base58.encode(@seed <> public))
    end

    test "rejects malformed keys" do
      assert SolanaKey.new("way too short") == {:error, :invalid_private_key}
      assert SolanaKey.new(:binary.copy(<<1>>, 31)) == {:error, :invalid_private_key}
      assert SolanaKey.new(nil) == {:error, :invalid_private_key}
    end
  end

  describe "sign_ed25519/2" do
    test "produces a valid deterministic Ed25519 signature" do
      {:ok, signer} = SolanaKey.new(@seed)
      {public, _private} = :crypto.generate_key(:eddsa, :ed25519, @seed)
      message = "solana message bytes"

      assert {:ok, signature} = SolanaKey.sign_ed25519(signer, message)
      assert byte_size(signature) == 64
      assert :crypto.verify(:eddsa, :none, message, signature, [public, :ed25519])

      # RFC 8032 signing is deterministic.
      assert SolanaKey.sign_ed25519(signer, message) == {:ok, signature}
    end

    test "dispatches through X402.Signer" do
      {:ok, signer} = SolanaKey.new(@seed)

      assert {:ok, signature} = Signer.sign_ed25519(signer, "message")
      assert byte_size(signature) == 64
    end

    test "EVM signing reports unsupported_signer" do
      {:ok, signer} = SolanaKey.new(@seed)

      assert Signer.sign_eip712(signer, <<0::256>>, %{}) == {:error, :unsupported_signer}
    end
  end

  describe "address/1" do
    test "returns the derived Base58 address" do
      {:ok, signer} = SolanaKey.new(@seed)
      assert SolanaKey.address(signer) == {:ok, @address}
      assert Signer.address(signer) == {:ok, @address}
    end
  end

  test "inspect redacts the private key" do
    {:ok, signer} = SolanaKey.new(@seed)
    rendered = inspect(signer)

    assert rendered =~ @address
    refute rendered =~ "seed"
    refute rendered =~ Base.encode16(@seed, case: :lower)
  end
end
