defmodule X402.Extensions.BazaarTest do
  use ExUnit.Case, async: true

  doctest X402.Extensions.Bazaar

  alias X402.Extensions.Bazaar

  describe "HTTP input" do
    test "GET builds a read-only signature with queryParams" do
      ext = Bazaar.build_extension(method: :get, input: %{"city" => "San Francisco"})

      assert %{"type" => "http", "method" => "GET", "queryParams" => %{"city" => "San Francisco"}} =
               ext["info"]["input"]

      refute Map.has_key?(ext["info"]["input"], "bodyType")
      refute Map.has_key?(ext["info"]["input"], "body")

      assert %{"$schema" => "https://json-schema.org/draft/2020-12/schema"} = ext["schema"]
      assert ext["schema"]["type"] == "object"
      assert ext["schema"]["required"] == ["input"]

      input_schema = ext["schema"]["properties"]["input"]
      assert input_schema["required"] == ["type", "method"]
      assert input_schema["properties"]["method"]["enum"] == ["GET", "HEAD", "DELETE"]
      assert input_schema["properties"]["type"]["const"] == "http"
      assert input_schema["properties"]["queryParams"] == %{"type" => "object"}
      assert input_schema["additionalProperties"] == false
    end

    test "GET without input still declares queryParams in schema" do
      ext = Bazaar.build_extension(method: :get)

      refute Map.has_key?(ext["info"]["input"], "queryParams")

      assert ext["schema"]["properties"]["input"]["properties"]["queryParams"] == %{
               "type" => "object"
             }
    end

    test "HEAD and DELETE are accepted as query methods" do
      for method <- [:head, :delete] do
        ext = Bazaar.build_extension(method: method)
        assert ext["info"]["input"]["method"] == String.upcase(to_string(method))
        refute Map.has_key?(ext["info"]["input"], "bodyType")
      end
    end

    test "POST/PUT/PATCH build a signature with bodyType and body" do
      for method <- [:post, :put, :patch] do
        ext = Bazaar.build_extension(method: method, input: %{"query" => "example"})

        input = ext["info"]["input"]
        assert input["method"] == String.upcase(to_string(method))
        assert input["bodyType"] == "json"
        assert input["body"] == %{"query" => "example"}

        input_schema = ext["schema"]["properties"]["input"]
        assert input_schema["required"] == ["type", "method", "bodyType", "body"]
        assert input_schema["properties"]["method"]["enum"] == ["POST", "PUT", "PATCH"]
        assert input_schema["properties"]["bodyType"]["enum"] == ["json", "form-data", "text"]
      end
    end

    test "body method with no input defaults body to empty map" do
      ext = Bazaar.build_extension(method: :post)
      assert ext["info"]["input"]["body"] == %{}
    end

    test "custom body_type is reflected in info" do
      ext = Bazaar.build_extension(method: :post, input: %{}, body_type: "form-data")
      assert ext["info"]["input"]["bodyType"] == "form-data"
    end

    test "input_schema is merged into queryParams schema" do
      input_schema = %{"properties" => %{"city" => %{"type" => "string"}}}

      ext =
        Bazaar.build_extension(
          method: :get,
          input: %{"city" => "Paris"},
          input_schema: input_schema
        )

      assert ext["schema"]["properties"]["input"]["properties"]["queryParams"] ==
               Map.merge(%{"type" => "object"}, input_schema)
    end

    test "input_schema becomes the body schema for body methods" do
      input_schema = %{"type" => "object", "properties" => %{"q" => %{"type" => "string"}}}

      ext = Bazaar.build_extension(method: :post, input_schema: input_schema)

      assert ext["schema"]["properties"]["input"]["properties"]["body"] == input_schema
    end

    test "headers and path_params are reflected in info" do
      ext =
        Bazaar.build_extension(
          method: :get,
          headers: %{"x-api-key" => "abc"},
          path_params: %{"id" => "42"}
        )

      assert ext["info"]["input"]["headers"] == %{"x-api-key" => "abc"}
      assert ext["info"]["input"]["pathParams"] == %{"id" => "42"}
    end

    test "path_params_schema adds pathParams property" do
      ext =
        Bazaar.build_extension(
          method: :get,
          path_params: %{"id" => "42"},
          path_params_schema: %{"properties" => %{"id" => %{"type" => "string"}}}
        )

      path_params = ext["schema"]["properties"]["input"]["properties"]["pathParams"]
      assert path_params["type"] == "object"
      assert path_params["properties"] == %{"id" => %{"type" => "string"}}
    end

    test "string methods are normalized" do
      assert Bazaar.build_extension(method: "get")["info"]["input"]["method"] == "GET"
      assert Bazaar.build_extension(method: "POST")["info"]["input"]["method"] == "POST"
    end
  end

  describe "MCP input" do
    @input_schema %{
      "type" => "object",
      "properties" => %{"ticker" => %{"type" => "string"}},
      "required" => ["ticker"]
    }

    test "tool_name and input_schema build a minimal signature" do
      ext = Bazaar.build_extension(tool_name: "financial_analysis", input_schema: @input_schema)

      assert %{
               "type" => "mcp",
               "toolName" => "financial_analysis",
               "inputSchema" => @input_schema
             } = ext["info"]["input"]

      refute Map.has_key?(ext["info"]["input"], "transport")
      refute Map.has_key?(ext["info"]["input"], "description")
      refute Map.has_key?(ext["info"]["input"], "example")

      input_schema = ext["schema"]["properties"]["input"]
      assert input_schema["required"] == ["type", "toolName", "inputSchema"]
      assert input_schema["properties"]["type"]["const"] == "mcp"
      assert input_schema["properties"]["transport"]["enum"] == ["streamable-http", "sse"]
      assert input_schema["additionalProperties"] == false
    end

    test "transport, description, and example are reflected in info" do
      ext =
        Bazaar.build_extension(
          tool_name: "t",
          input_schema: @input_schema,
          transport: "sse",
          description: "Performs financial analysis",
          example: %{"ticker" => "AAPL"}
        )

      assert ext["info"]["input"]["transport"] == "sse"
      assert ext["info"]["input"]["description"] == "Performs financial analysis"
      assert ext["info"]["input"]["example"] == %{"ticker" => "AAPL"}
    end
  end

  describe "output" do
    test "is present by default with json output type" do
      ext = Bazaar.build_extension(method: :get)

      assert ext["info"]["output"] == %{"type" => "json"}

      output_schema = ext["schema"]["properties"]["output"]
      assert output_schema["required"] == ["type"]
      assert output_schema["properties"]["type"] == %{"type" => "string"}
      assert output_schema["properties"]["example"] == %{"type" => "object"}
      refute Map.has_key?(output_schema["properties"], "format")
    end

    test "reflects concrete values in info and schema" do
      ext =
        Bazaar.build_extension(
          method: :get,
          output: %{type: "Set", format: "JSON", example: %{landmarks: ""}}
        )

      assert ext["info"]["output"] == %{
               "type" => "Set",
               "format" => "JSON",
               "example" => %{landmarks: ""}
             }

      output = ext["schema"]["properties"]["output"]
      assert output["properties"]["type"] == %{"type" => "string"}
      assert output["properties"]["format"] == %{"type" => "string"}
      assert output["properties"]["example"] == %{"type" => "object"}
    end

    test "schema output example is declared as an object" do
      ext =
        Bazaar.build_extension(
          method: :get,
          output: [
            example: %{
              "count" => 3,
              "ok" => true,
              "tags" => ["a"],
              "ratio" => 1.5,
              "mixed" => [1, "a"]
            }
          ]
        )

      assert ext["schema"]["properties"]["output"]["properties"]["example"] == %{
               "type" => "object"
             }
    end

    test "accepts a keyword list with format, example, and schema" do
      ext =
        Bazaar.build_extension(
          method: :get,
          output: [
            type: "application/json",
            format: "text",
            example: %{"price" => 42},
            schema: %{"properties" => %{"price" => %{"type" => "number"}}}
          ]
        )

      assert ext["info"]["output"] == %{
               "type" => "application/json",
               "format" => "text",
               "example" => %{"price" => 42}
             }

      example_schema = ext["schema"]["properties"]["output"]["properties"]["example"]
      assert example_schema["type"] == "object"
      assert example_schema["properties"] == %{"price" => %{"type" => "number"}}
    end

    test "accepts a string-keyed map" do
      ext =
        Bazaar.build_extension(
          method: :get,
          output: %{"type" => "json", "example" => %{"ok" => true}}
        )

      assert ext["info"]["output"] == %{"type" => "json", "example" => %{"ok" => true}}
    end

    test "applies to MCP input as well" do
      ext =
        Bazaar.build_extension(tool_name: "t", input_schema: %{"type" => "object"}, output: [])

      assert ext["info"]["output"] == %{"type" => "json"}
      assert Map.has_key?(ext["schema"]["properties"], "output")
    end
  end

  describe "validation" do
    test "raises when options are not a keyword list" do
      assert_raise ArgumentError, ~r/expected options as a keyword list/, fn ->
        Bazaar.build_extension(%{method: :get})
      end

      assert_raise ArgumentError, ~r/expected options as a keyword list/, fn ->
        Bazaar.build_extension(nil)
      end
    end

    test "raises when method is missing for HTTP input" do
      assert_raise ArgumentError, ~r/expected :method option/, fn ->
        Bazaar.build_extension(input: %{})
      end

      assert_raise ArgumentError, ~r/expected :method option/, fn ->
        Bazaar.build_extension(method: nil)
      end
    end

    test "raises on invalid method" do
      for method <- [:trace, "OPTIONS", "GETS", true, 123] do
        assert_raise ArgumentError, ~r/invalid :method/, fn ->
          Bazaar.build_extension(method: method)
        end
      end
    end

    test "raises when input is not a map" do
      assert_raise NimbleOptions.ValidationError, ~r/input/, fn ->
        Bazaar.build_extension(method: :get, input: "bad")
      end
    end

    test "raises on invalid body_type" do
      assert_raise ArgumentError, ~r/invalid :body_type/, fn ->
        Bazaar.build_extension(method: :post, body_type: "xml")
      end
    end

    test "raises on invalid transport" do
      assert_raise ArgumentError, ~r/invalid :transport/, fn ->
        Bazaar.build_extension(
          tool_name: "t",
          input_schema: %{"type" => "object"},
          transport: "ws"
        )
      end
    end

    test "raises on unknown options" do
      assert_raise NimbleOptions.ValidationError, ~r/unknown options/, fn ->
        Bazaar.build_extension(method: :get, foo: :bar)
      end
    end

    test "raises when MCP tool_name is missing or not a string" do
      assert_raise ArgumentError, ~r/expected :method option/, fn ->
        Bazaar.build_extension(input_schema: %{"type" => "object"})
      end

      assert_raise NimbleOptions.ValidationError, ~r/tool_name/, fn ->
        Bazaar.build_extension(tool_name: 123, input_schema: %{"type" => "object"})
      end
    end

    test "raises when MCP input_schema is missing" do
      assert_raise NimbleOptions.ValidationError, ~r/input_schema/, fn ->
        Bazaar.build_extension(tool_name: "t")
      end
    end

    test "raises on invalid output" do
      assert_raise NimbleOptions.ValidationError, ~r/output/, fn ->
        Bazaar.build_extension(method: :get, output: "json")
      end

      assert_raise NimbleOptions.ValidationError, ~r/unknown :output option/, fn ->
        Bazaar.build_extension(method: :get, output: %{"bogus" => 1})
      end
    end
  end
end
