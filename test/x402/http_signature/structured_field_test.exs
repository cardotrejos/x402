defmodule X402.HTTPSignature.StructuredFieldTest do
  use ExUnit.Case, async: true

  alias X402.HTTPSignature.StructuredField, as: SF

  doctest X402.HTTPSignature.StructuredField

  describe "serialization" do
    test "dictionary members: bare keys, items, inner lists and parameters" do
      members = [
        {"flag", {true, []}},
        {"flag-p", {true, [{"x", 1}]}},
        {"str", {"a b", [{"q", {:token, "tok"}}, {"b", {:bytes, <<255>>}}]}},
        {"num", {-12, []}},
        {"dec", {3.14159, []}},
        {"off", {false, []}},
        {"list", {:inner_list, [{"@a", [{"req", true}]}, {1, []}], [{"n", 2.0}]}}
      ]

      assert {:ok, wire} = SF.serialize_dictionary(members)

      assert wire ==
               ~S|flag, flag-p;x=1, str="a b";q=tok;b=:/w==:, num=-12, dec=3.142, off=?0, list=("@a";req 1);n=2.0|

      # Decimals lose precision on the wire; everything else roundtrips.
      assert {:ok, parsed} = SF.parse_dictionary(wire)
      assert parsed == List.keyreplace(members, "dec", 0, {"dec", {3.142, []}})
    end

    test "decimals are rounded to three places and keep at least one" do
      assert {:ok, "1.0"} = SF.serialize_bare(1.0)
      assert {:ok, "-0.5"} = SF.serialize_bare(-0.5)
      assert {:ok, "2.346"} = SF.serialize_bare(2.3456)
      assert {:ok, "2.35"} = SF.serialize_bare(2.3500001)
      assert {:ok, "999999999999.0"} = SF.serialize_bare(999_999_999_999.0)
      assert {:error, :invalid_structured_field} = SF.serialize_bare(1_000_000_000_000.0)
    end

    test "integers are bounded to 15 digits" do
      assert {:ok, "999999999999999"} = SF.serialize_bare(999_999_999_999_999)
      assert {:ok, "-999999999999999"} = SF.serialize_bare(-999_999_999_999_999)
      assert {:error, :invalid_structured_field} = SF.serialize_bare(-1_000_000_000_000_000)
    end

    test "strings must be printable ASCII and tokens must match the grammar" do
      assert {:error, :invalid_structured_field} = SF.serialize_bare("tab\there")
      assert {:error, :invalid_structured_field} = SF.serialize_bare("nl\n")
      assert {:ok, ~S|""|} = SF.serialize_bare("")
      assert {:ok, "*tok/1:x"} = SF.serialize_bare({:token, "*tok/1:x"})
      assert {:error, :invalid_structured_field} = SF.serialize_bare({:token, "1abc"})
      assert {:error, :invalid_structured_field} = SF.serialize_bare({:token, ""})
      assert {:error, :invalid_structured_field} = SF.serialize_bare({:token, "a b"})
      assert {:error, :invalid_structured_field} = SF.serialize_bare(:atom)
      assert {:error, :invalid_structured_field} = SF.serialize_bare(nil)
    end

    test "invalid keys and nested values fail the whole field" do
      assert {:error, :invalid_structured_field} =
               SF.serialize_dictionary([{"ok", {1, []}}, {"1bad", {1, []}}])

      assert {:error, :invalid_structured_field} =
               SF.serialize_dictionary([{"a", {1, [{"BAD", 1}]}}])

      assert {:error, :invalid_structured_field} =
               SF.serialize_dictionary([{"a", {:inner_list, [{"x\n", []}], []}}])

      assert {:error, :invalid_structured_field} =
               SF.serialize_dictionary([{"a", {:inner_list, [], [{"p", "\t"}]}}])

      assert {:error, :invalid_structured_field} = SF.serialize_item({1, [{:atom, 1}]})
      assert {:error, :invalid_structured_field} = SF.serialize_key(:atom)
      assert {:error, :invalid_structured_field} = SF.serialize_key("")
      assert {:ok, "*"} = SF.serialize_key("*")
      assert {:ok, "a.b_c-d*9"} = SF.serialize_key("a.b_c-d*9")
    end
  end

  describe "parsing" do
    test "roundtrips every bare item type" do
      for {wire, value} <- [
            {~S|"a \"q\" \\ b"|, ~S|a "q" \ b|},
            {"0", 0},
            {"-7", -7},
            {"123456789012345", 123_456_789_012_345},
            {"1.5", 1.5},
            {"-0.125", -0.125},
            {"?1", true},
            {"?0", false},
            {"tok*", {:token, "tok*"}},
            {"*", {:token, "*"}},
            {":AQID:", {:bytes, <<1, 2, 3>>}},
            {"::", {:bytes, ""}},
            {":AQ:", {:bytes, <<1>>}}
          ] do
        assert {:ok, {^value, []}, ""} = SF.parse_item(wire), wire
      end
    end

    test "rejects malformed bare items (as a dictionary value, so trailing garbage counts)" do
      for wire <- [
            ~S|"unterminated|,
            ~S|"bad \x escape"|,
            ~S|"ctl \x01"|,
            "\"tab\there\"",
            "?2",
            "?",
            "-",
            "1234567890123456",
            "1234567890123.5",
            "1.2345",
            "1.",
            ":not base64!:",
            ":AQID",
            "%",
            "",
            "\"caf\u00e9\""
          ] do
        assert {:error, :invalid_structured_field} = SF.parse_dictionary("a=" <> wire),
               inspect(wire)
      end
    end

    test "parameters: bare keys are true, values follow =, and later ones win by default" do
      assert {:ok, {1, [{"a", true}, {"b", "x"}, {"c", 2}]}, ""} =
               SF.parse_item("1;a;b=\"x\";c=2")

      assert {:ok, {1, [{"a", 3}]}, ""} = SF.parse_item("1;a=1;a=3")
      assert {:ok, {1, [{"a", 1}]}, " rest"} = SF.parse_item("1; a=1 rest")
      assert :error = SF.parse_item("1;A=1")
      assert :error = SF.parse_item("1;a=")
      assert :error = SF.parse_item("1;")
    end

    test "dictionaries: separators, whitespace and inner lists" do
      assert {:ok, [{"a", {1, []}}, {"b", {2, []}}]} = SF.parse_dictionary("a=1 , \t b=2")
      assert {:ok, [{"a", {1, []}}, {"b", {2, []}}]} = SF.parse_dictionary("   a=1,b=2")
      assert {:ok, [{"a", {true, []}}]} = SF.parse_dictionary("a")
      assert {:ok, []} = SF.parse_dictionary("")

      assert {:ok, [{"l", {:inner_list, [], []}}]} = SF.parse_dictionary("l=()")
      assert {:ok, [{"l", {:inner_list, [], [{"p", true}]}}]} = SF.parse_dictionary("l=();p")

      assert {:ok, [{"l", {:inner_list, [{"a", []}, {{:token, "b"}, [{"x", 1}]}, {3, []}], []}}]} =
               SF.parse_dictionary(~S|l=( "a"  b;x=1   3 )|)

      for wire <- [
            "a=1,",
            ",a=1",
            "a=1,,b=2",
            "a=1 b=2",
            "a==1",
            "A=1",
            "a=(1",
            "a=(1,2)",
            "a=(\"x\"\"y\")",
            "a=1;",
            "a=1 ;x"
          ] do
        assert {:error, :invalid_structured_field} = SF.parse_dictionary(wire), inspect(wire)
      end

      assert {:error, :invalid_structured_field} = SF.parse_dictionary(nil)
    end

    test "duplicate keys overwrite in place by default and are rejected when asked" do
      assert {:ok, [{"a", {3, []}}, {"b", {2, []}}]} = SF.parse_dictionary("a=1, b=2, a=3")
      assert {:ok, [{"a", {1, [{"x", 2}]}}]} = SF.parse_dictionary("a=1;x=1;x=2")

      assert {:ok, [{"l", {:inner_list, [{1, [{"x", 2}]}], [{"y", 4}]}}]} =
               SF.parse_dictionary("l=(1;x=1;x=2);y=3;y=4")

      strict = [duplicate_keys: :error]
      assert {:error, :duplicate_key} = SF.parse_dictionary("a=1, b=2, a=3", strict)
      assert {:error, :duplicate_key} = SF.parse_dictionary("a;x;x", strict)
      assert {:error, :duplicate_key} = SF.parse_dictionary("l=(1;x=1;x=2)", strict)
      assert {:error, :duplicate_key} = SF.parse_dictionary("l=(1);y=3;y=4", strict)
      assert {:ok, [{"a", {1, []}}, {"b", {2, []}}]} = SF.parse_dictionary("a=1, b=2", strict)
      assert {:error, :duplicate_key} = SF.parse_dictionary("l=(1;x=1;x=2", strict)
      assert {:error, :invalid_structured_field} = SF.parse_dictionary("l=(1;x=1;y=2", strict)
    end

    test "serialization and parsing are inverse on signature headers" do
      wire =
        ~S|sig1=("@method" "@authority" "@query-param";name="Pet" "date";req);created=1618884473;expires=1618884773;keyid="k";alg="ed25519";nonce="n";tag="t", sig2=:AQID:|

      assert {:ok, parsed} = SF.parse_dictionary(wire)
      assert {:ok, ^wire} = SF.serialize_dictionary(parsed)
    end
  end
end
