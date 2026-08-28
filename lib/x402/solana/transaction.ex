defmodule X402.Solana.Transaction do
  @moduledoc """
  Solana v0 transaction message building, serialization, and decoding.

  Implements exactly what the `exact` SVM scheme needs, with no RPC and no
  new dependencies:

  * Instruction constructors for the reference client's instruction set —
    Compute Budget `SetComputeUnitLimit`/`SetComputeUnitPrice`, SPL Token /
    Token-2022 `TransferChecked`, and SPL Memo
  * `compile/3` — compiles instructions into a serialized **version 0**
    message (the version the reference TypeScript and Python clients
    produce), including compact-u16 (shortvec) encoding, account
    deduplication, and the account ordering used by `@solana/kit`, so the
    output is byte-identical to the reference client
  * `serialize/2` — the wire transaction: compact-u16 signature count
    followed by 64-byte signature slots (missing signatures are all-zero
    placeholders, which is how a *partially signed* transaction represents
    the fee payer's pending signature) and the message bytes
  * `decode/1` — parses a wire transaction (v0 or legacy) back into its
    parts for structural validation

  ## Account ordering

  Static accounts are ordered: fee payer first, then writable signers,
  read-only signers, writable non-signers, read-only non-signers. Within a
  group, addresses sort with `@solana/kit`'s comparator (case-insensitive
  primary pass, lowercase-first tiebreak) so compiled messages are
  byte-identical to the reference client's.

  ## Signing

  Ed25519 signatures cover the *entire* serialized message returned by
  `compile/3`, including the leading `0x80` version byte.
  """

  alias X402.Solana

  # IPv6 minimum MTU (1280) minus packet headers — the Solana network's hard
  # cap on serialized transaction size.
  @max_transaction_size 1232

  @compute_unit_limit_discriminator 2
  @compute_unit_price_discriminator 3
  @transfer_checked_discriminator 12

  @typedoc "An account referenced by an instruction."
  @type account_meta :: %{address: Solana.address(), signer?: boolean(), writable?: boolean()}

  @typedoc "An instruction to compile into a message."
  @type instruction :: %{program: Solana.address(), accounts: [account_meta()], data: binary()}

  @typedoc "A compiled v0 message ready to sign."
  @type compiled :: %{bytes: binary(), signers: [Solana.address()]}

  @typedoc "A decoded wire transaction."
  @type decoded :: %{
          version: 0 | :legacy,
          num_required_signatures: non_neg_integer(),
          num_readonly_signed: non_neg_integer(),
          num_readonly_unsigned: non_neg_integer(),
          signatures: [binary()],
          static_accounts: [Solana.pubkey()],
          recent_blockhash: Solana.pubkey(),
          instructions: [
            %{program_index: byte(), account_indices: [byte()], data: binary()}
          ],
          address_table_lookups: non_neg_integer(),
          message_bytes: binary()
        }

  @doc since: "0.6.0"
  @doc """
  The Solana network's maximum serialized transaction size in bytes.

  ## Examples

      iex> X402.Solana.Transaction.max_transaction_size()
      1232
  """
  @spec max_transaction_size() :: pos_integer()
  def max_transaction_size, do: @max_transaction_size

  @doc since: "0.6.0"
  @doc """
  Encodes a non-negative integer as compact-u16 (shortvec).

  Little-endian 7-bit groups with a continuation bit, as used for all
  counts in Solana's wire format.

  ## Examples

      iex> X402.Solana.Transaction.encode_compact_u16(0)
      <<0>>

      iex> X402.Solana.Transaction.encode_compact_u16(127)
      <<0x7F>>

      iex> X402.Solana.Transaction.encode_compact_u16(128)
      <<0x80, 0x01>>

      iex> X402.Solana.Transaction.encode_compact_u16(16_383)
      <<0xFF, 0x7F>>

      iex> X402.Solana.Transaction.encode_compact_u16(16_384)
      <<0x80, 0x80, 0x01>>
  """
  @spec encode_compact_u16(non_neg_integer()) :: binary()
  def encode_compact_u16(value) when value >= 0 and value < 0x80, do: <<value>>

  def encode_compact_u16(value) when value >= 0x80 and value <= 0xFFFF do
    <<Bitwise.bor(Bitwise.band(value, 0x7F), 0x80)>> <>
      encode_compact_u16(Bitwise.bsr(value, 7))
  end

  @doc since: "0.6.0"
  @doc """
  Decodes a compact-u16 prefix, returning the value and the rest.

  ## Examples

      iex> X402.Solana.Transaction.decode_compact_u16(<<0x80, 0x01, "rest">>)
      {:ok, 128, "rest"}

      iex> X402.Solana.Transaction.decode_compact_u16(<<0xFF, 0x7F>>)
      {:ok, 16_383, ""}

      iex> X402.Solana.Transaction.decode_compact_u16(<<0x80>>)
      :error
  """
  @spec decode_compact_u16(binary()) :: {:ok, non_neg_integer(), binary()} | :error
  def decode_compact_u16(binary) when is_binary(binary), do: decode_compact_u16(binary, 0, 0)

  # -- Instruction constructors ----------------------------------------------

  @doc since: "0.6.0"
  @doc """
  The Compute Budget `SetComputeUnitLimit` instruction (discriminator 2,
  `u32` little-endian units).

  ## Examples

      iex> ix = X402.Solana.Transaction.set_compute_unit_limit(20_000)
      iex> {ix.program, ix.accounts, ix.data}
      {"ComputeBudget111111111111111111111111111111", [], <<2, 32, 78, 0, 0>>}
  """
  @spec set_compute_unit_limit(non_neg_integer()) :: instruction()
  def set_compute_unit_limit(units) when units >= 0 and units <= 0xFFFFFFFF do
    %{
      program: Solana.compute_budget_program(),
      accounts: [],
      data: <<@compute_unit_limit_discriminator, units::32-little>>
    }
  end

  @doc since: "0.6.0"
  @doc """
  The Compute Budget `SetComputeUnitPrice` instruction (discriminator 3,
  `u64` little-endian microlamports).

  ## Examples

      iex> ix = X402.Solana.Transaction.set_compute_unit_price(1)
      iex> ix.data
      <<3, 1, 0, 0, 0, 0, 0, 0, 0>>
  """
  @spec set_compute_unit_price(non_neg_integer()) :: instruction()
  def set_compute_unit_price(micro_lamports)
      when micro_lamports >= 0 and micro_lamports <= 0xFFFFFFFFFFFFFFFF do
    %{
      program: Solana.compute_budget_program(),
      accounts: [],
      data: <<@compute_unit_price_discriminator, micro_lamports::64-little>>
    }
  end

  @doc since: "0.6.0"
  @doc """
  The SPL Token / Token-2022 `TransferChecked` instruction.

  Discriminator 12, `u64` little-endian amount, `u8` decimals; accounts
  `[source (writable), mint, destination (writable), authority (signer)]` —
  the layout the facilitator's static verification path parses.
  """
  @spec transfer_checked(%{
          source: Solana.address(),
          mint: Solana.address(),
          destination: Solana.address(),
          authority: Solana.address(),
          amount: non_neg_integer(),
          decimals: byte(),
          token_program: Solana.address()
        }) :: instruction()
  def transfer_checked(%{
        source: source,
        mint: mint,
        destination: destination,
        authority: authority,
        amount: amount,
        decimals: decimals,
        token_program: token_program
      })
      when amount >= 0 and amount <= 0xFFFFFFFFFFFFFFFF and decimals in 0..255 do
    %{
      program: token_program,
      accounts: [
        %{address: source, signer?: false, writable?: true},
        %{address: mint, signer?: false, writable?: false},
        %{address: destination, signer?: false, writable?: true},
        %{address: authority, signer?: true, writable?: false}
      ],
      data: <<@transfer_checked_discriminator, amount::64-little, decimals>>
    }
  end

  @doc since: "0.6.0"
  @doc """
  An SPL Memo instruction carrying UTF-8 `data` (no accounts).

  ## Examples

      iex> ix = X402.Solana.Transaction.memo("pi_3abc123def456")
      iex> {ix.program, ix.data}
      {"MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", "pi_3abc123def456"}
  """
  @spec memo(binary()) :: instruction()
  def memo(data) when is_binary(data) do
    %{program: Solana.memo_program(), accounts: [], data: data}
  end

  # -- Compile ----------------------------------------------------------------

  @doc since: "0.6.0"
  @doc """
  Compiles instructions into a serialized v0 message.

  Returns the message bytes (starting with the `0x80` version prefix —
  these are the bytes Ed25519 signatures cover) and the required signer
  addresses in signature-slot order (the fee payer is always first).

  Returns `{:error, :invalid_address}` when any address fails Base58
  decoding.
  """
  @spec compile(Solana.address(), [instruction()], Solana.address()) ::
          {:ok, compiled()} | {:error, :invalid_address}
  def compile(fee_payer, instructions, recent_blockhash) do
    with {:ok, blockhash} <- Solana.decode_address(recent_blockhash),
         {:ok, ordered} <- ordered_accounts(fee_payer, instructions),
         {:ok, encoded_instructions} <- encode_instructions(instructions, ordered) do
      {signers, header} = header_for(ordered)

      account_section =
        encode_compact_u16(length(ordered)) <>
          IO.iodata_to_binary(Enum.map(ordered, & &1.pubkey))

      body =
        header <>
          account_section <>
          blockhash <>
          encode_compact_u16(length(instructions)) <>
          encoded_instructions <>
          encode_compact_u16(0)

      {:ok, %{bytes: <<0x80, body::binary>>, signers: signers}}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Serializes a wire transaction from message bytes and signatures.

  `signatures` maps signer addresses to 64-byte Ed25519 signatures;
  signers without an entry get a 64-byte zero placeholder — how a
  partially signed transaction leaves the fee payer's slot empty for the
  facilitator to fill at settlement.
  """
  @spec serialize(compiled(), %{Solana.address() => binary()}) :: binary()
  def serialize(%{bytes: message, signers: signers}, signatures) when is_map(signatures) do
    slots =
      Enum.map(signers, fn address ->
        case signatures do
          %{^address => <<signature::binary-size(64)>>} -> signature
          _missing -> <<0::512>>
        end
      end)

    encode_compact_u16(length(signers)) <> IO.iodata_to_binary(slots) <> message
  end

  @doc since: "0.6.0"
  @doc """
  Splices a 64-byte Ed25519 signature into a decoded transaction's slot.

  Rebuilds the wire transaction from a `decode/1` result — compact-u16
  signature count, the signature slots with `signature` at `index`, then the
  message bytes — **preserving** every other existing signature. This is how
  a facilitator fills the fee payer's empty slot 0 at settlement without
  disturbing the payer's signature.

  Unlike `serialize/2` (which zero-fills missing signatures by design, the
  partially-signed representation), a malformed signature here returns
  `{:error, :invalid_signature}`: silently broadcasting a zeroed fee-payer
  slot would only fail later on chain. An out-of-range `index` returns
  `{:error, :invalid_slot}`.

  ## Examples

      iex> decoded = %{
      ...>   num_required_signatures: 2,
      ...>   signatures: [<<0::512>>, <<1::512>>],
      ...>   message_bytes: <<0x80, 2, 1, 4>>
      ...> }
      iex> {:ok, wire} = X402.Solana.Transaction.attach_signature(decoded, 0, <<9::512>>)
      iex> wire == <<2>> <> <<9::512>> <> <<1::512>> <> <<0x80, 2, 1, 4>>
      true

      iex> X402.Solana.Transaction.attach_signature(
      ...>   %{num_required_signatures: 1, signatures: [<<0::512>>], message_bytes: <<0x80>>},
      ...>   0,
      ...>   <<1, 2, 3>>
      ...> )
      {:error, :invalid_signature}
  """
  @spec attach_signature(decoded(), non_neg_integer(), binary()) ::
          {:ok, binary()} | {:error, :invalid_signature | :invalid_slot}
  def attach_signature(
        %{num_required_signatures: count, signatures: signatures, message_bytes: message},
        index,
        <<signature::binary-size(64)>>
      )
      when is_integer(index) and index >= 0 do
    case index < count and index < length(signatures) do
      true ->
        slots = List.replace_at(signatures, index, signature)
        {:ok, encode_compact_u16(count) <> IO.iodata_to_binary(slots) <> message}

      false ->
        {:error, :invalid_slot}
    end
  end

  def attach_signature(%{signatures: _signatures}, index, signature)
      when is_integer(index) and index >= 0 and is_binary(signature),
      do: {:error, :invalid_signature}

  # -- Decode -----------------------------------------------------------------

  @doc since: "0.6.0"
  @doc """
  Decodes a wire transaction (v0 or legacy) into its parts.

  Used by the server-side structural checks in `X402.Scheme.ExactSVM`.
  Rejects trailing bytes and truncated sections with
  `{:error, :invalid_transaction}`.
  """
  @spec decode(binary()) :: {:ok, decoded()} | {:error, :invalid_transaction}
  def decode(wire) when is_binary(wire) do
    with {:ok, num_signatures, rest} <- decode_compact_u16(wire),
         {:ok, signatures, message} <- take_signatures(rest, num_signatures),
         {:ok, decoded} <- decode_message(message) do
      case length(decoded.static_accounts) >= decoded.num_required_signatures and
             num_signatures == decoded.num_required_signatures do
        true -> {:ok, Map.merge(decoded, %{signatures: signatures, message_bytes: message})}
        false -> {:error, :invalid_transaction}
      end
    else
      _error -> {:error, :invalid_transaction}
    end
  end

  def decode(_wire), do: {:error, :invalid_transaction}

  # -- Compile internals ------------------------------------------------------

  # Ordered static account entries: fee payer, writable signers, read-only
  # signers, writable non-signers, read-only non-signers; kit's address
  # comparator within each group.
  @spec ordered_accounts(Solana.address(), [instruction()]) ::
          {:ok, [map()]} | {:error, :invalid_address}
  defp ordered_accounts(fee_payer, instructions) do
    metas =
      Enum.flat_map(instructions, fn instruction ->
        program_meta = %{address: instruction.program, signer?: false, writable?: false}
        instruction.accounts ++ [program_meta]
      end)

    merged =
      Enum.reduce(metas, %{}, fn meta, acc ->
        Map.update(
          acc,
          meta.address,
          %{signer?: meta.signer?, writable?: meta.writable?},
          fn existing ->
            %{
              signer?: existing.signer? or meta.signer?,
              writable?: existing.writable? or meta.writable?
            }
          end
        )
      end)
      |> Map.put(fee_payer, %{signer?: true, writable?: true})

    entries =
      merged
      |> Enum.map(fn {address, roles} ->
        %{address: address, signer?: roles.signer?, writable?: roles.writable?}
      end)
      |> Enum.sort(fn left, right -> account_before?(left, right, fee_payer) end)

    entries
    |> Enum.reduce_while({:ok, []}, fn entry, {:ok, acc} ->
      case Solana.decode_address(entry.address) do
        {:ok, pubkey} -> {:cont, {:ok, [Map.put(entry, :pubkey, pubkey) | acc]}}
        {:error, :invalid_address} -> {:halt, {:error, :invalid_address}}
      end
    end)
    |> case do
      {:ok, reversed} -> {:ok, Enum.reverse(reversed)}
      error -> error
    end
  end

  @spec account_before?(map(), map(), Solana.address()) :: boolean()
  defp account_before?(%{address: fee_payer}, _right, fee_payer), do: true
  defp account_before?(_left, %{address: fee_payer}, fee_payer), do: false

  defp account_before?(left, right, _fee_payer) do
    cond do
      left.signer? != right.signer? -> left.signer?
      left.writable? != right.writable? -> left.writable?
      true -> address_compare(left.address, right.address) != :gt
    end
  end

  # @solana/kit orders same-role addresses with an English collator:
  # case-insensitive primary comparison, lowercase-first tiebreak.
  @spec address_compare(Solana.address(), Solana.address()) :: :lt | :eq | :gt
  defp address_compare(left, right) do
    case {String.downcase(left), String.downcase(right)} do
      {folded, folded} -> case_tiebreak(left, right)
      {left_folded, right_folded} when left_folded < right_folded -> :lt
      _greater -> :gt
    end
  end

  @spec case_tiebreak(binary(), binary()) :: :lt | :eq | :gt
  defp case_tiebreak(<<char, left::binary>>, <<char, right::binary>>),
    do: case_tiebreak(left, right)

  defp case_tiebreak(<<left_char, _::binary>>, <<right_char, _::binary>>) do
    # Same base letter, differing case: lowercase sorts first.
    case left_char > right_char do
      true -> :lt
      false -> :gt
    end
  end

  defp case_tiebreak("", ""), do: :eq

  @spec header_for([map()]) :: {[Solana.address()], binary()}
  defp header_for(ordered) do
    signers = for entry <- ordered, entry.signer?, do: entry.address
    readonly_signed = Enum.count(ordered, &(&1.signer? and not &1.writable?))
    readonly_unsigned = Enum.count(ordered, &(not &1.signer? and not &1.writable?))

    {signers, <<length(signers), readonly_signed, readonly_unsigned>>}
  end

  @spec encode_instructions([instruction()], [map()]) :: {:ok, binary()}
  defp encode_instructions(instructions, ordered) do
    index_by_address =
      ordered |> Enum.with_index() |> Map.new(fn {entry, index} -> {entry.address, index} end)

    encoded =
      Enum.map(instructions, fn instruction ->
        account_indices =
          Enum.map(instruction.accounts, &Map.fetch!(index_by_address, &1.address))

        <<Map.fetch!(index_by_address, instruction.program)>> <>
          encode_compact_u16(length(account_indices)) <>
          IO.iodata_to_binary(Enum.map(account_indices, &<<&1>>)) <>
          encode_compact_u16(byte_size(instruction.data)) <>
          instruction.data
      end)

    {:ok, IO.iodata_to_binary(encoded)}
  end

  # -- Decode internals -------------------------------------------------------

  @spec decode_compact_u16(binary(), non_neg_integer(), non_neg_integer()) ::
          {:ok, non_neg_integer(), binary()} | :error
  defp decode_compact_u16(<<byte, rest::binary>>, shift, acc) when shift <= 14 do
    value = Bitwise.bor(acc, Bitwise.bsl(Bitwise.band(byte, 0x7F), shift))

    case Bitwise.band(byte, 0x80) do
      0 -> if value <= 0xFFFF, do: {:ok, value, rest}, else: :error
      _continue -> decode_compact_u16(rest, shift + 7, value)
    end
  end

  defp decode_compact_u16(_binary, _shift, _acc), do: :error

  @spec take_signatures(binary(), non_neg_integer()) :: {:ok, [binary()], binary()} | :error
  defp take_signatures(binary, count), do: take_chunks(binary, count, 64, [])

  @spec take_chunks(binary(), non_neg_integer(), pos_integer(), [binary()]) ::
          {:ok, [binary()], binary()} | :error
  defp take_chunks(binary, 0, _size, acc), do: {:ok, Enum.reverse(acc), binary}

  defp take_chunks(binary, count, size, acc) do
    case binary do
      <<chunk::binary-size(^size), rest::binary>> ->
        take_chunks(rest, count - 1, size, [chunk | acc])

      _short ->
        :error
    end
  end

  @spec decode_message(binary()) :: {:ok, map()} | :error
  defp decode_message(<<prefix, rest::binary>> = message) do
    case Bitwise.band(prefix, 0x80) do
      0x80 ->
        case Bitwise.band(prefix, 0x7F) do
          0 -> decode_message_body(rest, 0)
          _unsupported -> :error
        end

      0 ->
        decode_message_body(message, :legacy)
    end
  end

  defp decode_message(_message), do: :error

  @spec decode_message_body(binary(), 0 | :legacy) :: {:ok, map()} | :error
  defp decode_message_body(
         <<num_required, readonly_signed, readonly_unsigned, rest::binary>>,
         version
       ) do
    with {:ok, num_accounts, rest} <- decode_compact_u16(rest),
         {:ok, accounts, rest} <- take_chunks(rest, num_accounts, 32, []),
         <<blockhash::binary-size(32), rest::binary>> <- rest,
         {:ok, num_instructions, rest} <- decode_compact_u16(rest),
         {:ok, instructions, rest} <- decode_instructions(rest, num_instructions, []),
         {:ok, lookups, rest} <- decode_lookups(rest, version),
         "" <- rest do
      {:ok,
       %{
         version: version,
         num_required_signatures: num_required,
         num_readonly_signed: readonly_signed,
         num_readonly_unsigned: readonly_unsigned,
         static_accounts: accounts,
         recent_blockhash: blockhash,
         instructions: instructions,
         address_table_lookups: lookups
       }}
    else
      _error -> :error
    end
  end

  defp decode_message_body(_binary, _version), do: :error

  @spec decode_instructions(binary(), non_neg_integer(), [map()]) ::
          {:ok, [map()], binary()} | :error
  defp decode_instructions(binary, 0, acc), do: {:ok, Enum.reverse(acc), binary}

  defp decode_instructions(<<program_index, rest::binary>>, count, acc) do
    with {:ok, num_accounts, rest} <- decode_compact_u16(rest),
         <<indices::binary-size(^num_accounts), rest::binary>> <- rest,
         {:ok, data_len, rest} <- decode_compact_u16(rest),
         <<data::binary-size(^data_len), rest::binary>> <- rest do
      instruction = %{
        program_index: program_index,
        account_indices: :binary.bin_to_list(indices),
        data: data
      }

      decode_instructions(rest, count - 1, [instruction | acc])
    else
      _error -> :error
    end
  end

  defp decode_instructions(_binary, _count, _acc), do: :error

  @spec decode_lookups(binary(), 0 | :legacy) :: {:ok, non_neg_integer(), binary()} | :error
  defp decode_lookups(binary, :legacy), do: {:ok, 0, binary}

  defp decode_lookups(binary, 0) do
    with {:ok, count, rest} <- decode_compact_u16(binary),
         {:ok, rest} <- skip_lookups(rest, count) do
      {:ok, count, rest}
    end
  end

  @spec skip_lookups(binary(), non_neg_integer()) :: {:ok, binary()} | :error
  defp skip_lookups(binary, 0), do: {:ok, binary}

  defp skip_lookups(<<_table::binary-size(32), rest::binary>>, count) do
    with {:ok, writable, rest} <- decode_compact_u16(rest),
         <<_writable::binary-size(^writable), rest::binary>> <- rest,
         {:ok, readonly, rest} <- decode_compact_u16(rest),
         <<_readonly::binary-size(^readonly), rest::binary>> <- rest do
      skip_lookups(rest, count - 1)
    else
      _error -> :error
    end
  end

  defp skip_lookups(_binary, _count), do: :error
end
