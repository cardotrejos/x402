defmodule X402.Solana do
  @moduledoc """
  Solana address primitives: program IDs, PDA and ATA derivation.

  Implements the address arithmetic the `exact` scheme on `solana:*`
  networks needs without any RPC or native dependencies:

  * Base58 address validation/decoding (32-byte Ed25519 public keys)
  * The Ed25519 on-curve check used to reject PDA candidates
    (RFC 8032 point decompression over integer arithmetic)
  * `create_program_address/2` / `find_program_address/2` — SHA-256 program
    derived addresses, as specified by the Solana runtime
  * `associated_token_address/3` — the Associated Token Account PDA for an
    (owner, mint, token program) triple, which is where the `exact` scheme
    says the payment must land (scheme spec §1.1)

  All hashing uses OTP's `:crypto`; no new dependencies.
  """

  @token_program "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
  @token_2022_program "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
  @ata_program "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
  @memo_program "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
  @compute_budget_program "ComputeBudget111111111111111111111111111111"
  @lighthouse_program "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"

  # Ed25519 field parameters (RFC 8032): p = 2^255 - 19, the twisted
  # Edwards d constant, and sqrt(-1) mod p.
  @p 57_896_044_618_658_097_711_785_492_504_343_953_926_634_992_332_820_282_019_728_792_003_956_564_819_949
  @d 37_095_705_934_669_439_343_138_083_508_754_565_189_542_113_879_843_219_016_388_785_533_085_940_283_555
  @sqrt_m1 19_681_161_376_707_505_956_807_079_304_988_542_015_446_066_515_923_890_162_744_021_073_123_829_784_752

  @pda_marker "ProgramDerivedAddress"

  @typedoc "A Base58-encoded Solana address."
  @type address :: String.t()

  @typedoc "A raw 32-byte Ed25519 public key or PDA."
  @type pubkey :: <<_::256>>

  @doc since: "0.6.0"
  @doc """
  The SPL Token program address.

  ## Examples

      iex> X402.Solana.token_program()
      "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
  """
  @spec token_program() :: address()
  def token_program, do: @token_program

  @doc since: "0.6.0"
  @doc """
  The Token-2022 program address.

  ## Examples

      iex> X402.Solana.token_2022_program()
      "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
  """
  @spec token_2022_program() :: address()
  def token_2022_program, do: @token_2022_program

  @doc since: "0.6.0"
  @doc """
  The Associated Token Account program address.

  ## Examples

      iex> X402.Solana.ata_program()
      "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL"
  """
  @spec ata_program() :: address()
  def ata_program, do: @ata_program

  @doc since: "0.6.0"
  @doc """
  The SPL Memo program address.

  ## Examples

      iex> X402.Solana.memo_program()
      "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr"
  """
  @spec memo_program() :: address()
  def memo_program, do: @memo_program

  @doc since: "0.6.0"
  @doc """
  The Compute Budget program address.

  ## Examples

      iex> X402.Solana.compute_budget_program()
      "ComputeBudget111111111111111111111111111111"
  """
  @spec compute_budget_program() :: address()
  def compute_budget_program, do: @compute_budget_program

  @doc since: "0.6.0"
  @doc """
  The Lighthouse assertion program address (wallet-injected guard
  instructions; allowed as optional instructions by the scheme spec §3.1).

  ## Examples

      iex> X402.Solana.lighthouse_program()
      "L2TExMFKdjpN9kozasaurPirfHy9P8sbXoAN1qA3S95"
  """
  @spec lighthouse_program() :: address()
  def lighthouse_program, do: @lighthouse_program

  @doc since: "0.6.0"
  @doc """
  Decodes a Base58 address into its raw 32-byte public key.

  ## Examples

      iex> X402.Solana.decode_address("11111111111111111111111111111111")
      {:ok, <<0::256>>}

      iex> X402.Solana.decode_address("tooshort")
      {:error, :invalid_address}

      iex> X402.Solana.decode_address(nil)
      {:error, :invalid_address}
  """
  @spec decode_address(term()) :: {:ok, pubkey()} | {:error, :invalid_address}
  def decode_address(address) when is_binary(address) do
    case X402.Base58.decode(address) do
      {:ok, <<pubkey::binary-size(32)>>} -> {:ok, pubkey}
      _other -> {:error, :invalid_address}
    end
  end

  def decode_address(_address), do: {:error, :invalid_address}

  @doc since: "0.6.0"
  @doc """
  Whether a term is a Base58 string decoding to 32 bytes.

  ## Examples

      iex> X402.Solana.valid_address?("EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
      true

      iex> X402.Solana.valid_address?("0x036CbD53842c5426634e7929541eC2318f3dCF7e")
      false
  """
  @spec valid_address?(term()) :: boolean()
  def valid_address?(address), do: match?({:ok, _pubkey}, decode_address(address))

  @doc since: "0.6.0"
  @doc """
  Whether 32 bytes decompress to a point on the Ed25519 curve.

  Program derived addresses must *not* be on the curve (so no private key
  can exist for them); `create_program_address/2` uses this check. The
  algorithm mirrors the reference SDKs' vendored Ed25519 decompression:
  mask the sign bit, solve `x^2 = (y^2 - 1) / (d*y^2 + 1)`, and require a
  square root to exist (with `x = 0` requiring a zero sign bit).

  ## Examples

      iex> {:ok, system_program} = X402.Solana.decode_address("11111111111111111111111111111111")
      iex> X402.Solana.on_curve?(system_program)
      true

      iex> {:ok, ata} = X402.Solana.decode_address("DNDTCnZkNk358qDFZd9unHtnrc73SsXcpVWtwJJMrR4B")
      iex> X402.Solana.on_curve?(ata)
      false
  """
  @spec on_curve?(pubkey()) :: boolean()
  def on_curve?(<<_::binary-size(31), last_byte>> = pubkey) when byte_size(pubkey) == 32 do
    y = decompress_y(pubkey)
    y2 = mod(y * y)
    u = mod(y2 - 1)
    v = mod(@d * y2 + 1)

    case uv_ratio(u, v) do
      nil -> false
      0 -> Bitwise.band(last_byte, 0x80) == 0
      _x -> true
    end
  end

  @doc since: "0.6.0"
  @doc """
  Derives a program address from seeds and a program ID (no bump search).

  Seeds are binaries of at most 32 bytes each, at most 16 seeds. Returns
  `{:error, :on_curve}` when the SHA-256 candidate lands on the Ed25519
  curve (callers should try another bump seed) and
  `{:error, :invalid_seeds}` for out-of-range seeds.
  """
  @spec create_program_address([binary()], address()) ::
          {:ok, pubkey()} | {:error, :on_curve | :invalid_seeds | :invalid_address}
  def create_program_address(seeds, program_id) when is_list(seeds) do
    with :ok <- validate_seeds(seeds),
         {:ok, program_pubkey} <- decode_address(program_id) do
      candidate = :crypto.hash(:sha256, [seeds, program_pubkey, @pda_marker])

      case on_curve?(candidate) do
        true -> {:error, :on_curve}
        false -> {:ok, candidate}
      end
    end
  end

  @doc since: "0.6.0"
  @doc """
  Finds the first off-curve program address, searching bump seeds 255 down
  to 0 — the canonical `find_program_address` from the Solana SDKs.

  Returns the raw 32-byte address and the bump seed that produced it.

  ## Examples

      iex> {:ok, {address, bump}} =
      ...>   X402.Solana.find_program_address(
      ...>     ["hello", "world"],
      ...>     "11111111111111111111111111111111"
      ...>   )
      iex> {X402.Base58.encode(address), bump}
      {"JDC4d5bNdpBPNLHfugxDcuknk6e9cp2xBis5V5v67PGh", 253}
  """
  @spec find_program_address([binary()], address()) ::
          {:ok, {pubkey(), byte()}} | {:error, :invalid_seeds | :invalid_address | :not_found}
  def find_program_address(seeds, program_id) when is_list(seeds) do
    find_with_bump(seeds, program_id, 255)
  end

  @doc since: "0.6.0"
  @doc """
  Derives the Associated Token Account address for an owner and mint.

  This is the destination the `exact` SVM scheme requires: the ATA derived
  from `payTo` and `asset` under the relevant token program (scheme spec
  §1.1–1.2). Seeds are `[owner, token_program, mint]` under the ATA
  program.

  ## Examples

      iex> X402.Solana.associated_token_address(
      ...>   "GyGKxMyg1p9SsHfm15MkNUu1u9TN2JtTspcdmrtGUdse",
      ...>   "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
      ...>   X402.Solana.token_program()
      ...> )
      {:ok, "DNDTCnZkNk358qDFZd9unHtnrc73SsXcpVWtwJJMrR4B"}

      iex> X402.Solana.associated_token_address("bogus", "also-bogus", "nope")
      {:error, :invalid_address}
  """
  @spec associated_token_address(address(), address(), address()) ::
          {:ok, address()} | {:error, :invalid_address | :not_found}
  def associated_token_address(owner, mint, token_program \\ @token_program) do
    with {:ok, owner_pubkey} <- decode_address(owner),
         {:ok, mint_pubkey} <- decode_address(mint),
         {:ok, program_pubkey} <- decode_address(token_program),
         {:ok, {address, _bump}} <-
           find_program_address([owner_pubkey, program_pubkey, mint_pubkey], @ata_program) do
      {:ok, X402.Base58.encode(address)}
    else
      {:error, :invalid_seeds} -> {:error, :invalid_address}
      {:error, reason} -> {:error, reason}
    end
  end

  # -- PDA internals ----------------------------------------------------------

  @spec find_with_bump([binary()], address(), integer()) ::
          {:ok, {pubkey(), byte()}} | {:error, :invalid_seeds | :invalid_address | :not_found}
  defp find_with_bump(_seeds, _program_id, bump) when bump < 0, do: {:error, :not_found}

  defp find_with_bump(seeds, program_id, bump) do
    case create_program_address(seeds ++ [<<bump>>], program_id) do
      {:ok, address} -> {:ok, {address, bump}}
      {:error, :on_curve} -> find_with_bump(seeds, program_id, bump - 1)
      {:error, reason} -> {:error, reason}
    end
  end

  @spec validate_seeds([term()]) :: :ok | {:error, :invalid_seeds}
  defp validate_seeds(seeds) do
    valid? =
      length(seeds) <= 16 and
        Enum.all?(seeds, &(is_binary(&1) and byte_size(&1) <= 32))

    case valid? do
      true -> :ok
      false -> {:error, :invalid_seeds}
    end
  end

  # -- Ed25519 field arithmetic ----------------------------------------------

  @spec decompress_y(pubkey()) :: non_neg_integer()
  defp decompress_y(<<head::binary-size(31), last_byte>>) do
    :binary.decode_unsigned(<<head::binary, Bitwise.band(last_byte, 0x7F)>>, :little)
  end

  # Square root of u/v via the (p-5)/8 exponent trick (RFC 8032 §5.1.3).
  # Returns nil when u/v is not a quadratic residue (candidate not on curve).
  @spec uv_ratio(non_neg_integer(), non_neg_integer()) :: non_neg_integer() | nil
  defp uv_ratio(u, v) do
    v3 = mod(v * v * v)
    v7 = mod(v3 * v3 * v)
    x = mod(u * v3 * mod_pow(mod(u * v7), div(@p - 5, 8)))
    vx2 = mod(v * x * x)

    cond do
      vx2 == u -> x
      vx2 == mod(-u) -> mod(x * @sqrt_m1)
      true -> nil
    end
  end

  @spec mod(integer()) :: non_neg_integer()
  defp mod(a) do
    case rem(a, @p) do
      r when r < 0 -> r + @p
      r -> r
    end
  end

  @spec mod_pow(non_neg_integer(), non_neg_integer()) :: non_neg_integer()
  defp mod_pow(base, exponent) do
    :binary.decode_unsigned(:crypto.mod_pow(base, exponent, @p))
  end
end
