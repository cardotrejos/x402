defmodule X402.Wallet do
  @moduledoc """
  Wallet address validation utilities for x402.

  This module supports EVM and Solana address formats and can detect the wallet
  type from a single string value.
  """

  @evm_regex ~r/^0x[0-9a-fA-F]{40}$/
  # Solana addresses are 32-byte Ed25519 public keys encoded in base58.
  # base58(32 bytes) always produces 43 or 44 characters — never shorter.
  # The original range [32,44] was too permissive; tightened to [43,44].
  #
  # Note: Solana does NOT use Bitcoin's Base58Check format (no checksum byte).
  # This regex is a structural guard only; the facilitator performs full
  # on-chain key validation.
  @solana_regex ~r/^[1-9A-HJ-NP-Za-km-z]{43,44}$/

  @doc since: "0.1.0"
  @doc """
  Returns `true` when the value is a valid EVM or Solana wallet address.

  ## Examples

      iex> X402.Wallet.valid?("0x1111111111111111111111111111111111111111")
      true

      iex> X402.Wallet.valid?("not-a-wallet")
      false
  """
  @spec valid?(term()) :: boolean()
  def valid?(wallet), do: valid_evm?(wallet) or valid_solana?(wallet)

  @doc since: "0.1.0"
  @doc """
  Returns `true` for addresses in the format `0x` + 40 hexadecimal characters.

  ## Examples

      iex> X402.Wallet.valid_evm?("0x1111111111111111111111111111111111111111")
      true

      iex> X402.Wallet.valid_evm?("0x123")
      false
  """
  @spec valid_evm?(term()) :: boolean()
  def valid_evm?(wallet) when is_binary(wallet), do: wallet =~ @evm_regex
  def valid_evm?(_wallet), do: false

  @doc since: "0.1.0"
  @doc """
  Returns `true` for Base58 strings with length 43 or 44 (the valid range for 32-byte Solana public keys).

  ## Examples

      iex> X402.Wallet.valid_solana?("9xQeWvG816bUx9EPfQmQTYnC16hHhV6bQf8kX6y4YB9")
      true

      iex> X402.Wallet.valid_solana?("invalid0base58")
      false
  """
  @spec valid_solana?(term()) :: boolean()
  def valid_solana?(wallet) when is_binary(wallet), do: wallet =~ @solana_regex
  def valid_solana?(_wallet), do: false

  @doc since: "0.1.0"
  @doc """
  Detects the wallet type.

  ## Examples

      iex> X402.Wallet.type("0x1111111111111111111111111111111111111111")
      :evm

      iex> X402.Wallet.type("9xQeWvG816bUx9EPfQmQTYnC16hHhV6bQf8kX6y4YB9")
      :solana

      iex> X402.Wallet.type("not-a-wallet")
      :unknown
  """
  @spec type(term()) :: :evm | :solana | :unknown
  def type(wallet) do
    cond do
      valid_evm?(wallet) -> :evm
      valid_solana?(wallet) -> :solana
      true -> :unknown
    end
  end
end
