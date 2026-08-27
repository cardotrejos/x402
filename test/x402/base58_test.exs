defmodule X402.Base58Test do
  use ExUnit.Case, async: true

  doctest X402.Base58

  alias X402.Base58

  # Bitcoin Core base58_encode_decode.json vectors (hex => base58),
  # cross-checked against @solana/kit's base58 codec.
  @vectors [
    {"", ""},
    {"61", "2g"},
    {"626262", "a3gV"},
    {"636363", "aPEr"},
    {"73696d706c792061206c6f6e6720737472696e67", "2cFupjhnEsSn59qHXstmK2ffpLv2"},
    {"00eb15231dfceb60925886b67d065299925915aeb172c06647", "1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L"},
    {"516b6fcd0f", "ABnLTmg"},
    {"bf4f89001e670274dd", "3SEo3LWLoPntC"},
    {"572e4794", "3EFU7m"},
    {"ecac89cad93923c02321", "EJDM8drfXA6uyA"},
    {"10c8511e", "Rt5zm"},
    {"00000000000000000000", "1111111111"}
  ]

  describe "encode/1" do
    test "matches the Bitcoin Core test vectors" do
      for {hex, expected} <- @vectors do
        assert Base58.encode(Base.decode16!(hex, case: :lower)) == expected
      end
    end

    test "encodes 32-byte Solana public keys" do
      assert Base58.encode(<<0::256>>) == "11111111111111111111111111111111"
    end
  end

  describe "decode/1" do
    test "round-trips the Bitcoin Core test vectors" do
      for {hex, encoded} <- @vectors do
        assert Base58.decode(encoded) == {:ok, Base.decode16!(hex, case: :lower)}
      end
    end

    test "round-trips random binaries" do
      for _iteration <- 1..50 do
        binary = :crypto.strong_rand_bytes(:rand.uniform(64))
        assert {:ok, decoded} = binary |> Base58.encode() |> Base58.decode()
        assert decoded == binary
      end
    end

    test "rejects characters outside the alphabet" do
      for invalid <- ["0", "O", "I", "l", "hello world", "abc!"] do
        assert Base58.decode(invalid) == :error
      end
    end

    test "rejects non-binary input" do
      assert Base58.decode(nil) == :error
      assert Base58.decode(123) == :error
    end
  end
end
