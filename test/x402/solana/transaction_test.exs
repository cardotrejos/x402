defmodule X402.Solana.TransactionTest do
  use ExUnit.Case, async: true

  doctest X402.Solana.Transaction

  alias X402.Solana
  alias X402.Solana.Transaction

  # Fixed keys shared with the reference fixture (seeds 0x01/0x02/0x03,
  # addresses derived with @solana/kit 8.0.0).
  @client "AKnL4NNf3DGWZJS6cPknBuEGnVsV4A4m5tgebLHaRSZ9"
  @fee_payer "9hSR6S7WPtxmTojgo6GG3k4yDPecgJY292j7xrsUGWBu"
  @usdc "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
  @source_ata "3wvJdyFnGvaMWpbq93NU91SggiVRveULUXL6iX5VZDGP"
  @dest_ata "DNDTCnZkNk358qDFZd9unHtnrc73SsXcpVWtwJJMrR4B"
  @blockhash "EZ3rST5dvHmbanh75jc4PuLfV96vp9fEYBVeNk4FfM1k"

  defp reference_instructions do
    [
      Transaction.set_compute_unit_limit(20_000),
      Transaction.set_compute_unit_price(1),
      Transaction.transfer_checked(%{
        source: @source_ata,
        mint: @usdc,
        destination: @dest_ata,
        authority: @client,
        amount: 1000,
        decimals: 6,
        token_program: Solana.token_program()
      }),
      Transaction.memo("pi_3abc123def456")
    ]
  end

  defp compiled do
    {:ok, compiled} = Transaction.compile(@fee_payer, reference_instructions(), @blockhash)
    compiled
  end

  describe "encode_compact_u16/1 and decode_compact_u16/1" do
    test "round-trips the u16 range boundaries" do
      for value <- [0, 1, 127, 128, 255, 256, 16_383, 16_384, 65_535] do
        encoded = Transaction.encode_compact_u16(value)
        assert Transaction.decode_compact_u16(encoded <> "tail") == {:ok, value, "tail"}
      end
    end

    test "rejects truncated and oversized encodings" do
      assert Transaction.decode_compact_u16(<<0x80>>) == :error
      assert Transaction.decode_compact_u16(<<0x80, 0x80, 0x80, 0x01>>) == :error
      # 0x04 in the third group is 65_536 — beyond u16.
      assert Transaction.decode_compact_u16(<<0x80, 0x80, 0x04>>) == :error
    end
  end

  describe "compile/3" do
    test "orders static accounts like @solana/kit and builds the v0 header" do
      %{bytes: bytes, signers: signers} = compiled()

      # Fee payer first, then the read-only signer (transfer authority).
      assert signers == [@fee_payer, @client]

      assert {:ok, decoded} = Transaction.decode(Transaction.serialize(compiled(), %{}))
      assert decoded.version == 0
      assert decoded.num_required_signatures == 2
      assert decoded.num_readonly_signed == 1
      assert decoded.num_readonly_unsigned == 4

      expected_accounts = [
        @fee_payer,
        @client,
        @source_ata,
        @dest_ata,
        Solana.compute_budget_program(),
        @usdc,
        Solana.memo_program(),
        Solana.token_program()
      ]

      decoded_accounts =
        Enum.map(decoded.static_accounts, fn pubkey -> X402.Base58.encode(pubkey) end)

      assert decoded_accounts == expected_accounts

      # Message bytes start with the v0 version prefix.
      assert <<0x80, _rest::binary>> = bytes
    end

    test "rejects invalid addresses" do
      assert Transaction.compile("bogus", reference_instructions(), @blockhash) ==
               {:error, :invalid_address}

      assert Transaction.compile(@fee_payer, reference_instructions(), "bogus") ==
               {:error, :invalid_address}
    end
  end

  describe "serialize/2 and decode/1 round-trip" do
    test "re-asserts every field of the decoded transaction" do
      seed = :binary.copy(<<1>>, 32)
      {public, _private} = :crypto.generate_key(:eddsa, :ed25519, seed)
      signature = :crypto.sign(:eddsa, :none, compiled().bytes, [seed, :ed25519])

      wire = Transaction.serialize(compiled(), %{@client => signature})
      assert {:ok, decoded} = Transaction.decode(wire)

      # Signature slots: fee payer placeholder, then the client signature.
      assert decoded.signatures == [<<0::512>>, signature]

      # The signature covers the message bytes, version prefix included.
      assert decoded.message_bytes == compiled().bytes

      assert :crypto.verify(
               :eddsa,
               :none,
               decoded.message_bytes,
               Enum.at(decoded.signatures, 1),
               [public, :ed25519]
             )

      {:ok, blockhash} = Solana.decode_address(@blockhash)
      assert decoded.recent_blockhash == blockhash
      assert decoded.address_table_lookups == 0

      assert [limit_ix, price_ix, transfer_ix, memo_ix] = decoded.instructions

      # Account indices refer to the ordered account list above.
      assert %{program_index: 4, account_indices: [], data: <<2, 20_000::32-little>>} = limit_ix
      assert %{program_index: 4, account_indices: [], data: <<3, 1::64-little>>} = price_ix

      assert %{
               program_index: 7,
               account_indices: [2, 5, 3, 1],
               data: <<12, 1000::64-little, 6>>
             } = transfer_ix

      assert %{program_index: 6, account_indices: [], data: "pi_3abc123def456"} = memo_ix
    end

    test "decodes legacy (unversioned) messages" do
      # A legacy wire is the v0 wire without the version prefix and without
      # the trailing address-table-lookup section.
      %{bytes: <<0x80, body::binary>>} = compiled()
      body_size = byte_size(body) - 1
      <<legacy_message::binary-size(^body_size), 0>> = body

      wire = <<2>> <> <<0::512>> <> <<0::512>> <> legacy_message

      assert {:ok, decoded} = Transaction.decode(wire)
      assert decoded.version == :legacy
      assert decoded.address_table_lookups == 0
      assert length(decoded.instructions) == 4
    end

    test "rejects malformed wires" do
      wire = Transaction.serialize(compiled(), %{})

      assert Transaction.decode("") == {:error, :invalid_transaction}
      assert Transaction.decode(<<2, 0, 0>>) == {:error, :invalid_transaction}
      # Trailing garbage after the message.
      assert Transaction.decode(wire <> <<0>>) == {:error, :invalid_transaction}
      # Truncated signature section.
      assert Transaction.decode(binary_part(wire, 0, 40)) == {:error, :invalid_transaction}
      # Unsupported message version (v1).
      <<count, sigs::binary-size(128), 0x80, rest::binary>> = wire

      assert Transaction.decode(<<count, sigs::binary, 0x81, rest::binary>>) ==
               {:error, :invalid_transaction}
    end

    test "rejects signature count differing from the header" do
      %{bytes: bytes} = compiled()
      # One signature slot, but the header requires two.
      wire = <<1>> <> <<0::512>> <> bytes
      assert Transaction.decode(wire) == {:error, :invalid_transaction}
    end

    test "treats signatures that are not 64 bytes as missing" do
      wire = Transaction.serialize(compiled(), %{@client => "way too short"})
      assert {:ok, decoded} = Transaction.decode(wire)
      assert decoded.signatures == [<<0::512>>, <<0::512>>]
    end

    test "rejects non-binary input and truncated lookup sections" do
      assert Transaction.decode(nil) == {:error, :invalid_transaction}

      %{bytes: bytes} = compiled()
      body_size = byte_size(bytes) - 1
      <<body::binary-size(^body_size), 0>> = bytes

      # ALT count says 1 but only a single byte of the table follows.
      truncated = <<2>> <> <<0::512>> <> <<0::512>> <> body <> <<1, 7>>
      assert Transaction.decode(truncated) == {:error, :invalid_transaction}
    end

    test "rejects an empty message section" do
      # Zero signatures and nothing after them: there is no message to parse.
      assert Transaction.decode(<<0>>) == {:error, :invalid_transaction}
    end

    test "rejects a message body shorter than the three-byte header" do
      # v0 version prefix followed by a single header byte.
      assert Transaction.decode(<<0, 0x80, 1>>) == {:error, :invalid_transaction}
    end

    test "rejects an instruction section shorter than its declared count" do
      # Header claims one instruction but the section is empty.
      message =
        <<0x80, 1, 0, 0>> <>
          <<1>> <> :binary.copy(<<7>>, 32) <> :binary.copy(<<9>>, 32) <> <<1>>

      assert Transaction.decode(<<0>> <> message) == {:error, :invalid_transaction}
    end
  end

  describe "account ordering case tiebreak" do
    # Three valid 32-byte addresses whose Base58 strings differ only in
    # letter case, so the case-insensitive primary comparison ties and the
    # @solana/kit lowercase-first tiebreak decides the order — plus two
    # addresses whose binary order ("Z" before "a") is the reverse of their
    # case-insensitive order ("a" before "z").
    @fold_low "9fqXgrwWsBPkaXj1GYZLxGnBKqeNZYJ1TxR8MxZ1Wyzk"
    @fold_up_f "9FqXgrwWsBPkaXj1GYZLxGnBKqeNZYJ1TxR8MxZ1Wyzk"
    @fold_up_q "9fQXgrwWsBPkaXj1GYZLxGnBKqeNZYJ1TxR8MxZ1Wyzk"
    @lower_a "akCe1Z7oU33i21MxoQC8mHVMyEXewLrQn3WvCsEq1B6"
    @upper_z "ZA24VttNsMsrMtaz2xxzSXnK4SS1EEGD7Nz7cZ7MPNe"

    test "case-insensitively equal addresses sort lowercase-first" do
      group = [@fold_low, @fold_up_f, @fold_up_q, @lower_a, @upper_z]

      for address <- group do
        assert {:ok, pubkey} = Solana.decode_address(address)
        assert byte_size(pubkey) == 32
      end

      instruction = %{
        program: Solana.memo_program(),
        accounts:
          Enum.map(group, fn address ->
            %{address: address, signer?: false, writable?: true}
          end),
        data: "x"
      }

      {:ok, compiled} = Transaction.compile(@fee_payer, [instruction], @blockhash)
      {:ok, decoded} = Transaction.decode(Transaction.serialize(compiled, %{}))

      decoded_accounts =
        Enum.map(decoded.static_accounts, fn pubkey -> X402.Base58.encode(pubkey) end)

      # Writable non-signers sort between the fee payer and the read-only
      # program, case-insensitively ("a…" before "Z…"), with ties broken
      # lowercase-first at the earliest differing position.
      assert decoded_accounts == [
               @fee_payer,
               @fold_low,
               @fold_up_q,
               @fold_up_f,
               @lower_a,
               @upper_z,
               Solana.memo_program()
             ]
    end
  end

  describe "attach_signature/3" do
    test "splices the fee-payer signature preserving the other slots" do
      client_seed = :binary.copy(<<1>>, 32)
      fee_payer_seed = :binary.copy(<<2>>, 32)
      client_signature = :crypto.sign(:eddsa, :none, compiled().bytes, [client_seed, :ed25519])

      wire = Transaction.serialize(compiled(), %{@client => client_signature})
      {:ok, decoded} = Transaction.decode(wire)

      fee_payer_signature =
        :crypto.sign(:eddsa, :none, decoded.message_bytes, [fee_payer_seed, :ed25519])

      assert {:ok, signed_wire} = Transaction.attach_signature(decoded, 0, fee_payer_signature)

      # Round-trip: both slots filled, message bytes untouched.
      assert {:ok, signed} = Transaction.decode(signed_wire)
      assert signed.signatures == [fee_payer_signature, client_signature]
      assert signed.message_bytes == decoded.message_bytes

      {fee_payer_public, _private} = :crypto.generate_key(:eddsa, :ed25519, fee_payer_seed)

      assert :crypto.verify(
               :eddsa,
               :none,
               signed.message_bytes,
               hd(signed.signatures),
               [fee_payer_public, :ed25519]
             )
    end

    test "rejects non-64-byte signatures instead of zero-filling" do
      {:ok, decoded} = compiled() |> Transaction.serialize(%{}) |> Transaction.decode()

      assert Transaction.attach_signature(decoded, 0, <<1, 2, 3>>) ==
               {:error, :invalid_signature}

      assert Transaction.attach_signature(decoded, 0, <<0::520>>) ==
               {:error, :invalid_signature}
    end

    test "rejects out-of-range signature slots" do
      {:ok, decoded} = compiled() |> Transaction.serialize(%{}) |> Transaction.decode()

      assert Transaction.attach_signature(decoded, 2, <<1::512>>) == {:error, :invalid_slot}
    end
  end
end
