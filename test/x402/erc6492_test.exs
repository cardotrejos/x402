defmodule X402.ERC6492Test do
  use ExUnit.Case, async: true

  alias X402.ERC6492

  doctest X402.ERC6492

  @factory "0x2222222222222222222222222222222222222222"
  @zero_factory "0x0000000000000000000000000000000000000000"

  describe "parse/1" do
    test "round-trips a wrapped signature built with wrap/3" do
      inner = :crypto.strong_rand_bytes(65)
      calldata = :crypto.strong_rand_bytes(36)

      {:ok, wrapped} = ERC6492.wrap(@factory, calldata, inner)
      {:ok, parsed} = ERC6492.parse(wrapped)

      assert parsed.wrapped?
      assert parsed.factory == @factory
      assert parsed.factory_calldata == calldata
      assert parsed.inner_signature == inner
    end

    test "accepts 0x-prefixed hex input" do
      inner = :crypto.strong_rand_bytes(65)
      {:ok, wrapped} = ERC6492.wrap(@factory, <<0xAB>>, inner)
      hex = "0x" <> Base.encode16(wrapped, case: :lower)

      {:ok, parsed} = ERC6492.parse(hex)
      assert parsed.inner_signature == inner
    end

    test "handles calldata and signatures at 32-byte boundaries" do
      inner = :crypto.strong_rand_bytes(64)
      calldata = :crypto.strong_rand_bytes(32)

      {:ok, wrapped} = ERC6492.wrap(@factory, calldata, inner)
      {:ok, parsed} = ERC6492.parse(wrapped)

      assert parsed.factory_calldata == calldata
      assert parsed.inner_signature == inner
    end

    test "a zero factory address parses as no deployment info" do
      inner = :crypto.strong_rand_bytes(65)
      {:ok, wrapped} = ERC6492.wrap(@zero_factory, <<0xAB>>, inner)

      assert {:ok, parsed} = ERC6492.parse(wrapped)
      assert parsed.wrapped?
      assert parsed.factory == nil
      assert parsed.factory_calldata == nil
      assert parsed.inner_signature == inner
    end

    test "empty factory calldata parses as no deployment info" do
      inner = :crypto.strong_rand_bytes(65)
      {:ok, wrapped} = ERC6492.wrap(@factory, <<>>, inner)

      assert {:ok, parsed} = ERC6492.parse(wrapped)
      assert parsed.factory == nil
      assert parsed.inner_signature == inner
    end

    test "an unwrapped signature passes through untouched" do
      inner = :crypto.strong_rand_bytes(65)

      assert {:ok, parsed} = ERC6492.parse(inner)
      refute parsed.wrapped?
      assert parsed.factory == nil
      assert parsed.inner_signature == inner
    end

    test "rejects a magic suffix with a truncated ABI prefix" do
      malformed = <<1, 2, 3>> <> ERC6492.magic_suffix()
      assert ERC6492.parse(malformed) == {:error, :invalid_erc6492_wrapper}
    end

    test "rejects out-of-bounds calldata offsets" do
      {:ok, factory_word} = X402.EIP3009.encode_address(@factory)

      malformed =
        factory_word <>
          <<9_999::unsigned-big-integer-size(256)>> <>
          <<96::unsigned-big-integer-size(256)>> <>
          <<0::unsigned-big-integer-size(256)>> <> ERC6492.magic_suffix()

      assert ERC6492.parse(malformed) == {:error, :invalid_erc6492_wrapper}
    end

    test "rejects a declared bytes length past the end of the buffer" do
      {:ok, factory_word} = X402.EIP3009.encode_address(@factory)

      malformed =
        factory_word <>
          <<96::unsigned-big-integer-size(256)>> <>
          <<128::unsigned-big-integer-size(256)>> <>
          <<1_000_000::unsigned-big-integer-size(256)>> <>
          <<0::unsigned-big-integer-size(256)>> <> ERC6492.magic_suffix()

      assert ERC6492.parse(malformed) == {:error, :invalid_erc6492_wrapper}
    end

    test "rejects a non-zero-padded factory word" do
      malformed = <<0xFF>> <> :binary.copy(<<0>>, 95) <> ERC6492.magic_suffix()

      assert ERC6492.parse(malformed) == {:error, :invalid_erc6492_wrapper}
    end
  end

  describe "wrapped?/1" do
    test "false for short binaries and unwrapped signatures" do
      refute ERC6492.wrapped?(<<>>)
      refute ERC6492.wrapped?(:crypto.strong_rand_bytes(65))
      refute ERC6492.wrapped?("0x" <> String.duplicate("11", 65))
    end

    test "false for invalid hex strings" do
      refute ERC6492.wrapped?("0xzz")
    end

    test "true for hex-encoded wrapped signatures" do
      {:ok, wrapped} = ERC6492.wrap(@factory, <<0xAB>>, :crypto.strong_rand_bytes(65))
      assert ERC6492.wrapped?("0x" <> Base.encode16(wrapped, case: :lower))
    end
  end
end
