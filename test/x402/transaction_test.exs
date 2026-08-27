defmodule X402.TransactionTest do
  use ExUnit.Case, async: true

  alias X402.EIP3009
  alias X402.RLP
  alias X402.Signer
  alias X402.Signer.LocalKey
  alias X402.TestRLPDecoder
  alias X402.Transaction

  doctest X402.Transaction

  @to "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
  @to_bytes Base.decode16!("036CbD53842c5426634e7929541eC2318f3dCF7e", case: :mixed)
  @private_key "0x" <> String.duplicate("11", 32)

  defp transaction(overrides) do
    struct!(
      %Transaction{
        chain_id: 84_532,
        nonce: 7,
        max_priority_fee_per_gas: 1_000_000,
        max_fee_per_gas: 30_000_000,
        gas_limit: 90_000,
        to: @to,
        value: 0,
        data: <<0xE3, 0xEE, 0x16, 0x0E, 1, 2, 3>>
      },
      overrides
    )
  end

  describe "preimage/1" do
    test "encodes the nine unsigned fields in EIP-1559 order" do
      {:ok, preimage} = Transaction.preimage(transaction([]))

      assert <<0x02, rlp::binary>> = preimage
      assert {fields, <<>>} = TestRLPDecoder.decode(rlp)

      assert fields == [
               :binary.encode_unsigned(84_532),
               :binary.encode_unsigned(7),
               :binary.encode_unsigned(1_000_000),
               :binary.encode_unsigned(30_000_000),
               :binary.encode_unsigned(90_000),
               @to_bytes,
               "",
               <<0xE3, 0xEE, 0x16, 0x0E, 1, 2, 3>>,
               []
             ]
    end

    test "rejects an invalid to address" do
      assert Transaction.preimage(transaction(to: "0x1234")) == {:error, :invalid_address}
      assert Transaction.preimage(transaction(to: nil)) == {:error, :invalid_address}
    end

    test "rejects negative quantities and non-binary data" do
      assert Transaction.preimage(transaction(nonce: -1)) == {:error, :invalid_transaction}
      assert Transaction.preimage(transaction(data: :nope)) == {:error, :invalid_transaction}
    end
  end

  describe "digest/1" do
    test "is the keccak-256 hash of the preimage" do
      transaction = transaction([])
      {:ok, preimage} = Transaction.preimage(transaction)

      assert Transaction.digest(transaction) == {:ok, ExKeccak.hash_256(preimage)}
    end
  end

  describe "encode_signed/2" do
    test "appends yParity, r, and s as integers" do
      r = <<0::248, 0xAB>>
      s = <<0x0C, 0::248>>

      {:ok, raw} = Transaction.encode_signed(transaction([]), r <> s <> <<1>>)

      assert [_, _, _, _, _, _, _, _, [], y_parity, r_bytes, s_bytes] =
               TestRLPDecoder.decode_eip1559(raw)

      # yParity 1, r and s stripped to their minimal big-endian bytes.
      assert y_parity == <<1>>
      assert r_bytes == <<0xAB>>
      assert s_bytes == <<0x0C>> <> :binary.copy(<<0>>, 31)
    end

    test "normalizes a legacy 27/28 recovery id to yParity 0/1" do
      signature_v27 = :binary.copy(<<1>>, 64) <> <<27>>
      signature_v28 = :binary.copy(<<1>>, 64) <> <<28>>

      {:ok, raw_v27} = Transaction.encode_signed(transaction([]), signature_v27)
      {:ok, raw_v28} = Transaction.encode_signed(transaction([]), signature_v28)

      assert TestRLPDecoder.decode_eip1559(raw_v27) |> Enum.at(9) == ""
      assert TestRLPDecoder.decode_eip1559(raw_v28) |> Enum.at(9) == <<1>>
    end

    test "rejects malformed signatures" do
      assert Transaction.encode_signed(transaction([]), <<1, 2, 3>>) ==
               {:error, :invalid_signature_format}

      bad_v = :binary.copy(<<1>>, 64) <> <<29>>

      assert Transaction.encode_signed(transaction([]), bad_v) ==
               {:error, :invalid_signature_format}
    end
  end

  describe "signed transaction recovery proof" do
    # Proves the whole encoding pipeline: the broadcast bytes decode (with an
    # independent reference decoder) to fields whose re-encoded signing
    # preimage recovers the signer's address from the embedded signature.
    test "the sender recovered from the raw transaction is the signing key" do
      {:ok, signer} = LocalKey.new(@private_key)
      transaction = transaction([])

      {:ok, digest} = Transaction.digest(transaction)
      {:ok, signature} = Signer.sign_eip712(signer, digest, %{})
      {:ok, raw} = Transaction.encode_signed(transaction, signature)

      assert [
               chain_id,
               nonce,
               max_priority,
               max_fee,
               gas_limit,
               to,
               value,
               data,
               access_list,
               y_parity,
               r,
               s
             ] = TestRLPDecoder.decode_eip1559(raw)

      # Rebuild the signing preimage from the *decoded* fields only.
      rebuilt_preimage =
        <<0x02>> <>
          RLP.encode([
            chain_id,
            nonce,
            max_priority,
            max_fee,
            gas_limit,
            to,
            value,
            data,
            access_list
          ])

      rebuilt_digest = ExKeccak.hash_256(rebuilt_preimage)
      assert rebuilt_digest == digest

      recovery_signature =
        pad_word(r) <> pad_word(s) <> <<:binary.decode_unsigned(pad_word(y_parity)) + 27>>

      assert {:ok, recovered} = EIP3009.recover_signer(rebuilt_digest, recovery_signature)
      assert {:ok, recovered} == LocalKey.address(signer)
      assert to == @to_bytes
    end
  end

  defp pad_word(bytes) when byte_size(bytes) <= 32,
    do: :binary.copy(<<0>>, 32 - byte_size(bytes)) <> bytes
end
