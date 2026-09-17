defmodule X402.Extensions.BuilderCodeTest do
  use ExUnit.Case, async: true
  doctest X402.Extensions.BuilderCode

  alias X402.Extensions.BuilderCode

  describe "extension/2" do
    test "advertises the app code, optional service codes, and the schema" do
      assert %{"info" => %{"a" => "my_app"}, "schema" => schema} = BuilderCode.extension("my_app")
      assert schema == BuilderCode.schema()
      assert schema["additionalProperties"] == false
      assert schema["properties"]["w"]["pattern"] == "^[a-z0-9_]{1,32}$"

      assert BuilderCode.extension("my_app", service_codes: ["a", "b"])["info"] ==
               %{"a" => "my_app", "s" => ["a", "b"]}
    end

    test "rejects malformed codes and more than five service codes at declaration" do
      assert_raise NimbleOptions.ValidationError, ~r/invalid builder code "My App"/, fn ->
        BuilderCode.extension("My App")
      end

      assert_raise NimbleOptions.ValidationError, ~r/invalid builder code "x-y"/, fn ->
        BuilderCode.extension("my_app", service_codes: ["ok", "x-y"])
      end

      assert_raise NimbleOptions.ValidationError, ~r/too many service codes: 6/, fn ->
        BuilderCode.extension("my_app", service_codes: Enum.map(1..6, &"s#{&1}"))
      end

      assert_raise NimbleOptions.ValidationError, ~r/expected a builder code or a list/, fn ->
        BuilderCode.extension("my_app", service_codes: :nope)
      end
    end
  end

  describe "extract/1" do
    test "reads bare and info-wrapped maps with atom or string keys" do
      assert {:ok, %{app_code: "app", service_codes: ["s1"]}} =
               BuilderCode.extract(%{"a" => "app", "s" => ["s1"]})

      assert {:ok, %{app_code: "app", service_codes: []}} =
               BuilderCode.extract(%{info: %{a: "app"}, schema: %{}})

      assert {:ok, %{app_code: nil, service_codes: []}} = BuilderCode.extract(%{})
    end

    test "rejects malformed shapes" do
      assert {:error, {:invalid_builder_code, "s"}} = BuilderCode.extract(%{"s" => %{}})
      assert {:error, {:invalid_builder_code, "a"}} = BuilderCode.extract(%{"a" => 1})
      assert {:error, :invalid_builder_code_extension} = BuilderCode.extract([])
    end
  end

  describe "validate_echo/2" do
    test "accepts an echo matching an atom-keyed advertisement" do
      assert :ok = BuilderCode.validate_echo(%{"info" => %{"a" => "app"}}, %{info: %{a: "app"}})
    end

    test "requires the echoed app code to equal the advertised one" do
      advertised = BuilderCode.extension("app")
      assert :ok = BuilderCode.validate_echo(%{"a" => "app"}, advertised)
      assert :ok = BuilderCode.validate_echo(%{"s" => ["only_service"]}, advertised)

      assert {:error, :builder_code_mismatch} =
               BuilderCode.validate_echo(%{"a" => "x"}, advertised)

      assert {:error, :builder_code_mismatch} = BuilderCode.validate_echo(%{"a" => "app"}, "junk")
    end

    test "surfaces malformed echoes" do
      assert {:error, :invalid_builder_code_extension} = BuilderCode.validate_echo("app", nil)
      assert {:error, {:invalid_builder_code, "a"}} = BuilderCode.validate_echo(%{"a" => ""}, nil)
    end

    test "allows exactly ten echoed service codes" do
      ten = Enum.map(1..10, &"code_#{&1}")
      assert :ok = BuilderCode.validate_echo(%{"s" => ten}, nil)

      assert {:error, :too_many_service_codes} =
               BuilderCode.validate_echo(%{"s" => ten ++ ["x"]}, nil)
    end
  end

  describe "enricher/1" do
    test "echoes the advertised declaration and prepends the client codes without duplicates" do
      enricher = BuilderCode.enricher(service_codes: ["mine", "shared"])

      advertised = %{
        "builder-code" => BuilderCode.extension("app", service_codes: ["shared", "srv"])
      }

      payment_required = %{"extensions" => advertised}

      assert {:ok, enriched} = enricher.(%{"extensions" => advertised}, payment_required)
      declaration = enriched["extensions"]["builder-code"]
      assert declaration["info"] == %{"a" => "app", "s" => ["mine", "shared", "srv"]}
      assert declaration["schema"] == BuilderCode.schema()
    end

    test "builds the extensions map when the payload has none" do
      enricher = BuilderCode.enricher(service_codes: "mine")

      assert {:ok, %{"extensions" => %{"builder-code" => %{"info" => %{"s" => ["mine"]}}}}} =
               enricher.(%{}, nil)

      assert {:ok, %{"extensions" => %{"builder-code" => %{"info" => %{"s" => ["mine"]}}}}} =
               enricher.(%{"extensions" => "junk"}, %{"extensions" => %{"builder-code" => 1}})
    end

    test "keeps an existing echo in the payload and merges a string s" do
      enricher = BuilderCode.enricher(service_codes: "mine")

      payload = %{
        "extensions" => %{"builder-code" => %{"info" => %{"a" => "app", "s" => "theirs"}}}
      }

      assert {:ok, enriched} = enricher.(payload, nil)

      assert enriched["extensions"]["builder-code"]["info"] == %{
               "a" => "app",
               "s" => ["mine", "theirs"]
             }
    end

    test "with always: false attaches nothing unless advertised" do
      enricher = BuilderCode.enricher(service_codes: "mine", always: false)
      assert {:ok, %{}} = enricher.(%{}, %{"extensions" => %{}})

      advertised = %{"extensions" => %{"builder-code" => BuilderCode.extension("app")}}
      assert {:ok, enriched} = enricher.(%{}, advertised)
      assert enriched["extensions"]["builder-code"]["info"] == %{"a" => "app", "s" => ["mine"]}
    end

    test "validates its options" do
      assert_raise NimbleOptions.ValidationError, fn -> BuilderCode.enricher([]) end

      assert_raise NimbleOptions.ValidationError, ~r/too many service codes/, fn ->
        BuilderCode.enricher(service_codes: Enum.map(1..6, &"s#{&1}"))
      end
    end
  end
end
