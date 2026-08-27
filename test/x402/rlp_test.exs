defmodule X402.RLPTest do
  use ExUnit.Case, async: true

  alias X402.RLP

  doctest X402.RLP

  # Published vectors from the Ethereum RLP specification
  # (https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/).
  describe "encode/1 specification vectors" do
    test "the empty string encodes as 0x80" do
      assert RLP.encode("") == <<0x80>>
    end

    test "a single byte below 0x80 encodes as itself" do
      assert RLP.encode(<<0x00>>) == <<0x00>>
      assert RLP.encode(<<0x0F>>) == <<0x0F>>
      assert RLP.encode(<<0x7F>>) == <<0x7F>>
    end

    test "a single byte at or above 0x80 gets a length prefix" do
      assert RLP.encode(<<0x80>>) == <<0x81, 0x80>>
      assert RLP.encode(<<0xFF>>) == <<0x81, 0xFF>>
    end

    test "the string dog encodes as 0x83 dog" do
      assert RLP.encode("dog") == <<0x83, "dog">>
    end

    test "a 55-byte string uses the short form" do
      string = :binary.copy(<<0xAA>>, 55)
      assert RLP.encode(string) == <<0x80 + 55>> <> string
    end

    test "a 56-byte string switches to the long form" do
      string = :binary.copy(<<0xAA>>, 56)
      assert RLP.encode(string) == <<0xB8, 56>> <> string
    end

    test "Lorem ipsum encodes with a one-byte length of length" do
      string = "Lorem ipsum dolor sit amet, consectetur adipisicing elit"
      assert byte_size(string) == 56
      assert RLP.encode(string) == <<0xB8, 0x38>> <> string
    end

    test "the integer 0 encodes as the empty string" do
      assert RLP.encode(0) == <<0x80>>
    end

    test "the encoded integer 15 is 0x0f" do
      assert RLP.encode(15) == <<0x0F>>
    end

    test "the encoded integer 1024 is 0x820400" do
      assert RLP.encode(1024) == <<0x82, 0x04, 0x00>>
    end

    test "the empty list encodes as 0xc0" do
      assert RLP.encode([]) == <<0xC0>>
    end

    test "the list [cat, dog] encodes as 0xc88363617483646f67" do
      assert RLP.encode(["cat", "dog"]) == <<0xC8, 0x83, "cat", 0x83, "dog">>
    end

    test "the set-theoretical representation of three encodes as 0xc7c0c1c0c3c0c1c0" do
      assert RLP.encode([[], [[]], [[], [[]]]]) ==
               <<0xC7, 0xC0, 0xC1, 0xC0, 0xC3, 0xC0, 0xC1, 0xC0>>
    end

    test "a list whose payload exceeds 55 bytes uses the long form" do
      items = List.duplicate("dog", 15)
      payload = :binary.copy(<<0x83, "dog">>, 15)
      assert byte_size(payload) == 60
      assert RLP.encode(items) == <<0xF8, 60>> <> payload
    end
  end

  describe "encode/1 round trip" do
    test "decodes back to the original structure" do
      item = [1, 1024, "dog", ["cat", [0, <<0xFF>>]], "", []]

      assert {decoded, <<>>} = X402.TestRLPDecoder.decode(RLP.encode(item))
      assert decoded == [<<1>>, <<4, 0>>, "dog", ["cat", [<<>>, <<0xFF>>]], "", []]
    end
  end
end
