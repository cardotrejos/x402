defmodule X402.Extensions.SIWX.Verifier.DefaultTest do
  use ExUnit.Case, async: true

  doctest X402.Extensions.SIWX.Verifier.Default

  alias X402.Extensions.SIWX.Verifier.Default

  @private_key Base.decode16!("4f3edf983ac636a65a842ce7c78d9aa706d3b113bce036f9f3e0f0f7d1f5f5cb",
                 case: :lower
               )

  describe "verify_signature/3" do
    test "returns true for a valid EVM signature" do
      message = "Sign in to access purchased content"
      address = private_key_to_address(@private_key)
      signature = sign_message(message, @private_key)

      assert Default.verify_signature(message, signature, address) == {:ok, true}
    end

    test "returns false when signature does not match claimed address" do
      message = "Sign in to access purchased content"
      signature = sign_message(message, @private_key)

      assert Default.verify_signature(
               message,
               signature,
               "0x2222222222222222222222222222222222222222"
             ) == {:ok, false}
    end

    test "returns invalid_signature for malformed signatures" do
      assert Default.verify_signature(
               "hello",
               "0x1234",
               "0x1111111111111111111111111111111111111111"
             ) == {:error, :invalid_signature}
    end

    test "returns false when public key recovery fails" do
      # r = 5 is not the x-coordinate of any secp256k1 point, so recovery
      # fails for any message — surfaced as a non-matching signature.
      unrecoverable = "0x" <> Base.encode16(<<5::256, 1::256, 27>>, case: :lower)

      assert Default.verify_signature(
               "hello",
               unrecoverable,
               "0x1111111111111111111111111111111111111111"
             ) == {:ok, false}
    end

    test "accepts raw 0/1 recovery ids" do
      message = "Sign in to access purchased content"
      address = private_key_to_address(@private_key)
      hash = message_hash(message)
      {:ok, {compact_signature, recovery_id}} = ExSecp256k1.sign_compact(hash, @private_key)

      raw = "0x" <> Base.encode16(compact_signature <> <<recovery_id>>, case: :lower)

      assert Default.verify_signature(message, raw, address) == {:ok, true}
    end

    test "accepts EIP-155-style recovery ids (v >= 35)" do
      message = "Sign in to access purchased content"
      address = private_key_to_address(@private_key)
      hash = message_hash(message)
      {:ok, {compact_signature, recovery_id}} = ExSecp256k1.sign_compact(hash, @private_key)

      # v = chain_id * 2 + 35 + recovery_id; chain_id 1 gives 37/38.
      eip155 = "0x" <> Base.encode16(compact_signature <> <<recovery_id + 37>>, case: :lower)

      assert Default.verify_signature(message, eip155, address) == {:ok, true}
    end

    test "rejects out-of-range recovery bytes" do
      message = "Sign in to access purchased content"
      address = private_key_to_address(@private_key)
      hash = message_hash(message)
      {:ok, {compact_signature, _recovery_id}} = ExSecp256k1.sign_compact(hash, @private_key)

      bad_v = "0x" <> Base.encode16(compact_signature <> <<29>>, case: :lower)

      assert Default.verify_signature(message, bad_v, address) == {:error, :invalid_signature}
    end

    test "returns invalid_address for malformed addresses" do
      message = "hello"
      signature = sign_message(message, @private_key)

      assert Default.verify_signature(message, signature, "bad-address") ==
               {:error, :invalid_address}
    end

    test "returns invalid_arguments for invalid argument types" do
      assert Default.verify_signature(nil, nil, nil) == {:error, :invalid_arguments}
    end
  end

  defp sign_message(message, private_key) do
    hash = message_hash(message)
    {:ok, {compact_signature, recovery_id}} = ExSecp256k1.sign_compact(hash, private_key)

    "0x" <> Base.encode16(compact_signature <> <<recovery_id + 27>>, case: :lower)
  end

  defp private_key_to_address(private_key) do
    {:ok, <<4, public_key::binary-size(64)>>} = ExSecp256k1.create_public_key(private_key)
    hash = ExKeccak.hash_256(public_key)
    address = binary_part(hash, byte_size(hash) - 20, 20)
    "0x" <> Base.encode16(address, case: :lower)
  end

  defp message_hash(message) do
    ExKeccak.hash_256("\x19Ethereum Signed Message:\n#{byte_size(message)}#{message}")
  end
end
