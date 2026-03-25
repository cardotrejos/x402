defmodule X402.UtilsTest do
  use ExUnit.Case, async: true

  alias X402.Utils

  doctest X402.Utils

  describe "decode_base64/1" do
    test "returns error for empty string" do
      assert Utils.decode_base64("") == {:error, :invalid_base64}
    end

    test "decodes valid base64 with padding" do
      assert Utils.decode_base64("aGVsbG8=") == {:ok, "hello"}
    end

    test "decodes valid base64 without padding" do
      assert Utils.decode_base64("aGVsbG8") == {:ok, "hello"}
    end

    test "returns error for invalid base64" do
      assert Utils.decode_base64("not-valid-!!!") == {:error, :invalid_base64}
    end
  end

  describe "first_present/1" do
    test "returns nil for empty list" do
      assert Utils.first_present([]) == nil
    end

    test "returns nil when all values are nil" do
      assert Utils.first_present([nil, nil, nil]) == nil
    end

    test "returns first non-nil value" do
      assert Utils.first_present([nil, "found", "other"]) == "found"
    end

    test "returns false (non-nil falsy value)" do
      assert Utils.first_present([nil, false, "other"]) == false
    end

    test "returns first element when no nils" do
      assert Utils.first_present([1, 2, 3]) == 1
    end
  end

  describe "map_value/2" do
    test "prefers string key over atom key" do
      assert Utils.map_value(%{"key" => "string", key: "atom"}, {"key", :key}) == "string"
    end

    test "falls back to atom key when string key absent" do
      assert Utils.map_value(%{key: "atom_val"}, {"key", :key}) == "atom_val"
    end

    test "returns nil when neither key present" do
      assert Utils.map_value(%{}, {"key", :key}) == nil
    end
  end

  describe "parse_decimal/1" do
    test "parses non-negative integer" do
      assert Utils.parse_decimal(42) == {:ok, {42, 0}}
    end

    test "parses zero integer" do
      assert Utils.parse_decimal(0) == {:ok, {0, 0}}
    end

    test "rejects negative integer" do
      assert Utils.parse_decimal(-1) == :error
    end

    test "parses integer string" do
      assert Utils.parse_decimal("123") == {:ok, {123, 0}}
    end

    test "parses decimal string" do
      assert Utils.parse_decimal("12.34") == {:ok, {1234, 2}}
    end

    test "strips trailing zeros from fraction" do
      assert Utils.parse_decimal("12.50") == {:ok, {125, 1}}
    end

    test "strips all-zero fraction" do
      assert Utils.parse_decimal("12.00") == {:ok, {12, 0}}
    end

    test "parses leading-zero fraction" do
      assert Utils.parse_decimal("0.001") == {:ok, {1, 3}}
    end

    test "trims whitespace before parsing" do
      assert Utils.parse_decimal("  42  ") == {:ok, {42, 0}}
    end

    test "rejects empty string" do
      assert Utils.parse_decimal("") == :error
    end

    test "rejects leading-dot string like .5" do
      assert Utils.parse_decimal(".5") == :error
    end

    test "rejects trailing-dot string like 1." do
      assert Utils.parse_decimal("1.") == :error
    end

    test "rejects string with no digits" do
      assert Utils.parse_decimal("abc") == :error
    end

    test "rejects mixed alphanumeric" do
      assert Utils.parse_decimal("1e5") == :error
    end

    test "rejects multiple dots" do
      assert Utils.parse_decimal("1.2.3") == :error
    end

    test "rejects nil" do
      assert Utils.parse_decimal(nil) == :error
    end

    test "rejects float" do
      assert Utils.parse_decimal(1.5) == :error
    end
  end

  describe "compare_decimal/2" do
    test "equal values with same scale" do
      assert Utils.compare_decimal({10, 1}, {10, 1}) == :eq
    end

    test "equal values with different scales" do
      # 1.0 == 1.00
      assert Utils.compare_decimal({10, 1}, {100, 2}) == :eq
    end

    test "left less than right" do
      assert Utils.compare_decimal({5, 1}, {1, 0}) == :lt
    end

    test "left greater than right" do
      assert Utils.compare_decimal({15, 1}, {1, 0}) == :gt
    end

    test "integer equivalent comparison" do
      assert Utils.compare_decimal({1, 0}, {1, 0}) == :eq
      assert Utils.compare_decimal({0, 0}, {1, 0}) == :lt
      assert Utils.compare_decimal({2, 0}, {1, 0}) == :gt
    end

    test "cross-scale: 1.5 > 1.0" do
      assert Utils.compare_decimal({15, 1}, {10, 1}) == :gt
    end

    test "cross-scale: 0.5 < 1" do
      assert Utils.compare_decimal({5, 1}, {1, 0}) == :lt
    end
  end
end
