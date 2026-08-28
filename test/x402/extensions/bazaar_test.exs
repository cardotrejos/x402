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

      nil_ext = Bazaar.build_extension(method: :post, input: nil)
      assert nil_ext["info"]["input"]["body"] == %{}
    end

    test "text body methods accept strings and emit a matching schema" do
      ext = Bazaar.build_extension(method: :post, body_type: "text", input: "hello")

      assert ext["info"]["input"]["body"] == "hello"

      assert ext["schema"]["properties"]["input"]["properties"]["body"] == %{
               "type" => "string"
             }

      default_ext = Bazaar.build_extension(method: :post, body_type: "text")
      assert default_ext["info"]["input"]["body"] == ""

      nil_ext = Bazaar.build_extension(method: :post, body_type: "text", input: nil)
      assert nil_ext["info"]["input"]["body"] == ""
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
      assert output_schema["properties"]["example"] == %{}
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

    test "schema output example matches scalar and array JSON types" do
      examples = [
        {"ok", "string"},
        {42, "integer"},
        {1.5, "number"},
        {true, "boolean"},
        {["ok"], "array"}
      ]

      for {example, expected_type} <- examples do
        ext = Bazaar.build_extension(method: :get, output: [example: example])

        assert ext["info"]["output"]["example"] == example

        assert ext["schema"]["properties"]["output"]["properties"]["example"] == %{
                 "type" => expected_type
               }
      end
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

    test "accepts a string-keyed map with format and schema entries" do
      ext =
        Bazaar.build_extension(
          method: :get,
          output: %{
            "type" => "json",
            "format" => "iso8601",
            "example" => %{"at" => "2026-01-01"},
            "schema" => %{"properties" => %{"at" => %{"type" => "string"}}}
          }
        )

      assert ext["info"]["output"]["format"] == "iso8601"

      example_schema = ext["schema"]["properties"]["output"]["properties"]["example"]
      assert example_schema["type"] == "object"
      assert example_schema["properties"] == %{"at" => %{"type" => "string"}}
    end

    test "a custom schema without an example still declares an object" do
      ext =
        Bazaar.build_extension(
          method: :get,
          output: [schema: %{"minProperties" => 1}]
        )

      assert ext["schema"]["properties"]["output"]["properties"]["example"] == %{
               "type" => "object",
               "minProperties" => 1
             }
    end

    test "examples with no JSON equivalent leave the example schema open" do
      ext = Bazaar.build_extension(method: :get, output: [example: :pending])

      assert ext["info"]["output"]["example"] == :pending
      assert ext["schema"]["properties"]["output"]["properties"]["example"] == %{}
    end

    test "empty-string optional info fields are omitted" do
      ext =
        Bazaar.build_extension(
          tool_name: "t",
          input_schema: %{"type" => "object"},
          description: ""
        )

      refute Map.has_key?(ext["info"]["input"], "description")
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

    test "raises when query input is not a map" do
      assert_raise ArgumentError, ~r/expected query :input to be a map/, fn ->
        Bazaar.build_extension(method: :get, input: "bad")
      end
    end

    test "raises when body input does not match its body_type" do
      assert_raise ArgumentError, ~r/expected json :input to be a map/, fn ->
        Bazaar.build_extension(method: :post, body_type: "json", input: "bad")
      end

      assert_raise ArgumentError, ~r/expected text :input to be a string/, fn ->
        Bazaar.build_extension(method: :post, body_type: "text", input: %{})
      end
    end

    test "raises when body_type is provided for a query method" do
      assert_raise ArgumentError, ~r/:body_type is only supported/, fn ->
        Bazaar.build_extension(method: :get, body_type: "text")
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

    test "raises on mistyped output entries" do
      assert_raise NimbleOptions.ValidationError, ~r/output/, fn ->
        Bazaar.build_extension(method: :get, output: [type: 123])
      end
    end

    test "validate_output/1 reports the failing option" do
      assert {:error, message} = Bazaar.validate_output(type: 123)
      assert message =~ ":type"

      assert {:error, message} = Bazaar.validate_output("json")
      assert message =~ "expected a keyword list or map"
    end

    test "validate_map/1 rejects non-map values" do
      assert Bazaar.validate_map(%{"type" => "object"}) == {:ok, %{"type" => "object"}}

      assert {:error, message} = Bazaar.validate_map("not a map")
      assert message =~ "expected a map"
    end
  end

  describe "discovery client" do
    @valid_item %{
      "resource" => "https://api.example.com/premium-data",
      "type" => "http",
      "x402Version" => 2,
      "accepts" => [
        %{
          "scheme" => "exact",
          "network" => "eip155:8453",
          "amount" => "10000",
          "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
          "payTo" => "0x1111111111111111111111111111111111111111"
        }
      ],
      "lastUpdated" => 1_703_123_456,
      "description" => "Premium market data",
      "mimeType" => "application/json",
      "metadata" => %{"category" => "finance"}
    }

    test "list_resources/2 returns typed resources from the facilitator" do
      minimal_item = %{
        "resource" => "https://api.example.com/mcp-tool",
        "type" => "mcp",
        "x402Version" => 2,
        "accepts" => [%{"scheme" => "upto", "network" => "solana:mainnet"}],
        "lastUpdated" => "2026-08-26T00:00:00Z"
      }

      facilitator =
        start_discovery_facilitator(fn conn ->
          conn = Plug.Conn.fetch_query_params(conn)
          assert conn.query_params == %{"network" => "eip155:8453", "limit" => "2"}

          Plug.Conn.resp(
            conn,
            200,
            Jason.encode!(%{
              "x402Version" => 2,
              "items" => [@valid_item, minimal_item],
              "pagination" => %{"limit" => 2, "offset" => 0, "total" => 2}
            })
          )
        end)

      assert {:ok,
              %{
                x402_version: 2,
                items: [full, minimal],
                pagination: %{limit: 2, offset: 0, total: 2}
              }} = Bazaar.list_resources(facilitator, network: "eip155:8453", limit: 2)

      assert %{
               resource: "https://api.example.com/premium-data",
               type: "http",
               x402_version: 2,
               last_updated: 1_703_123_456,
               description: "Premium market data",
               mime_type: "application/json",
               metadata: %{"category" => "finance"},
               extensions: nil
             } = full

      assert [%{"scheme" => "exact", "amount" => "10000"}] = full.accepts

      assert %{
               resource: "https://api.example.com/mcp-tool",
               type: "mcp",
               last_updated: "2026-08-26T00:00:00Z",
               description: nil,
               mime_type: nil,
               metadata: nil,
               extensions: nil
             } = minimal
    end

    test "list_resources/2 fails closed on a structurally invalid entry" do
      invalid_item = Map.delete(@valid_item, "resource")

      facilitator =
        start_discovery_facilitator(fn conn ->
          Plug.Conn.resp(
            conn,
            200,
            Jason.encode!(%{"items" => [@valid_item, invalid_item]})
          )
        end)

      assert {:error,
              %X402.Facilitator.Error{
                type: :malformed_facilitator_response,
                reason: {:invalid_resource, 1, {:missing_field, "resource"}},
                retryable: false
              }} = Bazaar.list_resources(facilitator)
    end

    test "list_resources/2 propagates facilitator transport and validation errors" do
      facilitator =
        start_discovery_facilitator(fn conn ->
          Plug.Conn.resp(conn, 503, Jason.encode!(%{"error" => "unavailable"}))
        end)

      assert {:error, %X402.Facilitator.Error{type: :http_error, status: 503}} =
               Bazaar.list_resources(facilitator)

      assert {:error, %NimbleOptions.ValidationError{}} =
               Bazaar.list_resources(facilitator, limit: 0)
    end

    test "list_resources/1 applies parameters to the default facilitator name" do
      # Parameter validation happens before the default X402.Facilitator
      # process is consulted, so the delegation is observable without one.
      assert {:error, %NimbleOptions.ValidationError{}} = Bazaar.list_resources(limit: 0)
    end

    test "parse_resource/1 rejects mistyped or missing required fields" do
      assert {:error, {:invalid_field, "resource"}} =
               Bazaar.parse_resource(%{@valid_item | "resource" => 123})

      assert {:error, {:invalid_field, "x402Version"}} =
               Bazaar.parse_resource(%{@valid_item | "x402Version" => "2"})

      assert {:error, {:missing_field, "x402Version"}} =
               Bazaar.parse_resource(Map.delete(@valid_item, "x402Version"))

      assert {:error, {:missing_field, "accepts"}} =
               Bazaar.parse_resource(Map.delete(@valid_item, "accepts"))

      assert {:error, {:missing_field, "lastUpdated"}} =
               Bazaar.parse_resource(Map.delete(@valid_item, "lastUpdated"))
    end

    test "parse_resource/1 treats explicit nil optional fields as absent" do
      item =
        @valid_item
        |> Map.put("description", nil)
        |> Map.put("metadata", nil)

      assert {:ok, parsed} = Bazaar.parse_resource(item)
      assert parsed.description == nil
      assert parsed.metadata == nil
    end

    test "parse_resource/1 rejects mistyped optional fields" do
      assert {:error, {:invalid_field, "metadata"}} =
               Bazaar.parse_resource(%{@valid_item | "metadata" => "finance"})

      assert {:error, {:invalid_field, "description"}} =
               Bazaar.parse_resource(%{@valid_item | "description" => 42})

      assert {:error, {:invalid_field, "lastUpdated"}} =
               Bazaar.parse_resource(%{@valid_item | "lastUpdated" => %{}})

      assert {:error, {:invalid_resource_entry, "nope"}} = Bazaar.parse_resource("nope")
    end

    test "filter helpers match any accepted payment option" do
      multi_network = %{
        resource: "https://multi.example",
        accepts: [
          %{"scheme" => "exact", "network" => "eip155:8453", "amount" => "999999"},
          %{"scheme" => "upto", "network" => "solana:mainnet", "amount" => "100"}
        ]
      }

      legacy_amount = %{
        resource: "https://legacy.example",
        accepts: [%{"scheme" => "exact", "network" => "eip155:1", "maxAmountRequired" => "500"}]
      }

      priceless = %{
        resource: "https://priceless.example",
        accepts: [%{"scheme" => "exact", "network" => "eip155:1", "amount" => "not-a-number"}]
      }

      resources = [multi_network, legacy_amount, priceless]

      assert [^multi_network] = Bazaar.filter_by_network(resources, "solana:mainnet")
      assert [^multi_network] = Bazaar.filter_by_scheme(resources, "upto")

      assert [^multi_network, ^legacy_amount] = Bazaar.filter_by_max_price(resources, "500")
      assert [^multi_network, ^legacy_amount] = Bazaar.filter_by_max_price(resources, 500)
      assert [^multi_network] = Bazaar.filter_by_max_price(resources, 250)
      assert [] = Bazaar.filter_by_max_price(resources, "50")
    end

    test "filter_by_max_price/2 skips entries without an amount or with junk accepts" do
      amountless = %{
        resource: "https://amountless.example",
        accepts: [%{"scheme" => "exact", "network" => "eip155:1"}]
      }

      junk_accepts = %{
        resource: "https://junk.example",
        accepts: ["not-a-requirements-map"]
      }

      affordable = %{
        resource: "https://cheap.example",
        accepts: [%{"scheme" => "exact", "amount" => "100"}]
      }

      assert Bazaar.filter_by_max_price([amountless, junk_accepts, affordable], "500") ==
               [affordable]
    end

    test "filter_by_max_price/2 raises on an unparsable maximum" do
      assert_raise ArgumentError, ~r/max_price/, fn ->
        Bazaar.filter_by_max_price([], "not-a-price")
      end
    end

    defp start_discovery_facilitator(handler) do
      suffix = System.unique_integer([:positive, :monotonic])
      finch = String.to_atom("bazaar_finch_#{suffix}")
      name = String.to_atom("bazaar_facilitator_#{suffix}")

      bypass = Bypass.open()
      Bypass.stub(bypass, "GET", "/discovery/resources", handler)

      start_supervised!(Supervisor.child_spec({Finch, name: finch}, id: finch))

      start_supervised!(
        {X402.Facilitator,
         name: name, finch: finch, url: "http://localhost:#{bypass.port}", max_retries: 0}
      )
    end
  end
end
