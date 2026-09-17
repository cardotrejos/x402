defmodule X402.Extensions.SIWX.Verifier.Ed25519Test do
  use ExUnit.Case, async: true

  doctest X402.Extensions.SIWX.Verifier.Ed25519

  alias X402.Base58
  alias X402.Extensions.SIWX.Verifier.Ed25519
  alias X402.Signer.SolanaKey

  @seed :binary.copy(<<1>>, 32)

  describe "verify_signature/3" do
    test "accepts a signature produced by the matching Solana key" do
      {:ok, signer} = SolanaKey.new(@seed)
      {:ok, address} = SolanaKey.address(signer)
      message = "api.example.com wants you to sign in with your Solana account:\n" <> address
      {:ok, signature} = SolanaKey.sign_ed25519(signer, message)

      assert Ed25519.verify_signature(message, Base58.encode(signature), address) == {:ok, true}
    end

    test "rejects a signature over a different message" do
      {:ok, signer} = SolanaKey.new(@seed)
      {:ok, address} = SolanaKey.address(signer)
      {:ok, signature} = SolanaKey.sign_ed25519(signer, "hello")

      assert Ed25519.verify_signature("hello!", Base58.encode(signature), address) ==
               {:ok, false}
    end

    test "rejects a signature from a different key" do
      {:ok, signer} = SolanaKey.new(@seed)
      {:ok, other} = SolanaKey.new(:binary.copy(<<2>>, 32))
      {:ok, other_address} = SolanaKey.address(other)
      {:ok, signature} = SolanaKey.sign_ed25519(signer, "hello")

      assert Ed25519.verify_signature("hello", Base58.encode(signature), other_address) ==
               {:ok, false}
    end

    test "rejects small-order public keys without consulting the signature" do
      {:ok, signer} = SolanaKey.new(@seed)
      {:ok, signature} = SolanaKey.sign_ed25519(signer, "hello")
      identity = Base58.encode(<<1, 0::248>>)

      assert Ed25519.verify_signature("hello", Base58.encode(signature), identity) ==
               {:ok, false}
    end

    test "returns malformed_signature for signatures that are not 64 bytes" do
      {:ok, signer} = SolanaKey.new(@seed)
      {:ok, address} = SolanaKey.address(signer)

      assert Ed25519.verify_signature("hello", Base58.encode(<<1, 2, 3>>), address) ==
               {:error, :malformed_signature}
    end

    test "returns invalid_address for addresses that are not 32 bytes" do
      assert Ed25519.verify_signature("hello", Base58.encode(<<0::512>>), Base58.encode(<<1>>)) ==
               {:error, :invalid_address}
    end

    test "returns invalid_arguments for non-binary inputs" do
      assert Ed25519.verify_signature(nil, "sig", "addr") == {:error, :invalid_arguments}
      assert Ed25519.verify_signature("msg", nil, "addr") == {:error, :invalid_arguments}
      assert Ed25519.verify_signature("msg", "sig", nil) == {:error, :invalid_arguments}
    end
  end
end
