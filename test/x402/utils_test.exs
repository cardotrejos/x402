defmodule X402.UtilsTest do
  use ExUnit.Case, async: true

  alias X402.Utils

  describe "map_value/2" do
    test "returns value for string key" do
      map = %{"key" => "value", :key => "other"}
      assert Utils.map_value(map, {"key", :key}) == "value"
    end

    test "returns value for atom key if string key missing" do
      map = %{:key => "value"}
      assert Utils.map_value(map, {"key", :key}) == "value"
    end

    test "returns nil if both keys missing" do
      map = %{}
      assert Utils.map_value(map, {"key", :key}) == nil
    end
  end

  describe "nested_map_value/2" do
    test "returns value for single key" do
      map = %{"key" => "value"}
      assert Utils.nested_map_value(map, [{"key", :key}]) == "value"
    end

    test "returns value for nested keys" do
      map = %{"parent" => %{"child" => "value"}}
      assert Utils.nested_map_value(map, [{"parent", :parent}, {"child", :child}]) == "value"
    end

    test "returns nil if path broken" do
      map = %{"parent" => "not_a_map"}
      assert Utils.nested_map_value(map, [{"parent", :parent}, {"child", :child}]) == nil
    end

    test "returns nil if key missing" do
      map = %{"parent" => %{}}
      assert Utils.nested_map_value(map, [{"parent", :parent}, {"child", :child}]) == nil
    end

    test "handles mixed string/atom keys" do
      map = %{:parent => %{"child" => "value"}}
      assert Utils.nested_map_value(map, [{"parent", :parent}, {"child", :child}]) == "value"
    end
  end

  describe "first_present/1" do
    test "returns first non-nil value" do
      assert Utils.first_present([nil, "value", "other"]) == "value"
    end

    test "returns nil if all values are nil" do
      assert Utils.first_present([nil, nil]) == nil
    end

    test "returns nil for empty list" do
      assert Utils.first_present([]) == nil
    end
  end
end
