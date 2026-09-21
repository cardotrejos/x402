defmodule X402.Signer.LocalKeyTest do
  use ExUnit.Case, async: true

  alias X402.Extensions.SIWX.Verifier.Default
  alias X402.Signer
  alias X402.Signer.LocalKey

  @private_key "0x" <> String.duplicate("11", 32)
  @address "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"

  describe "sign_message/2" do
    test "produces an EIP-191 personal_sign signature the default verifier accepts" do
      {:ok, signer} = LocalKey.new(@private_key)
      message = "api.example.com wants you to sign in with your Ethereum account:\n" <> @address

      assert {:ok, signature} = LocalKey.sign_message(signer, message)
      assert String.length(signature) == 132
      assert signature =~ ~r/\A0x[0-9a-f]{128}(1b|1c)\z/
      assert Default.verify_signature(message, signature, @address) == {:ok, true}
    end

    test "binds the signature to the exact message" do
      {:ok, signer} = LocalKey.new(@private_key)
      {:ok, signature} = LocalKey.sign_message(signer, "hello")

      assert Default.verify_signature("hello!", signature, @address) == {:ok, false}
    end

    test "is deterministic" do
      {:ok, signer} = LocalKey.new(@private_key)

      assert LocalKey.sign_message(signer, "hello") == LocalKey.sign_message(signer, "hello")
    end

    test "rejects non-binary messages" do
      {:ok, signer} = LocalKey.new(@private_key)

      assert LocalKey.sign_message(signer, 123) == {:error, :invalid_message}
    end
  end

  describe "X402.Signer.sign_message/2" do
    test "dispatches to the LocalKey implementation" do
      {:ok, signer} = LocalKey.new(@private_key)

      assert {:ok, signature} = Signer.sign_message(signer, "hello")
      assert Default.verify_signature("hello", signature, @address) == {:ok, true}
    end
  end
end
