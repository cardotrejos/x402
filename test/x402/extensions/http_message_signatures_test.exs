defmodule X402.Extensions.HTTPMessageSignaturesTest do
  use ExUnit.Case, async: true

  alias X402.Extensions.HTTPMessageSignatures, as: Extension

  doctest X402.Extensions.HTTPMessageSignatures

  # The declaration example from the extension specification.
  @spec_extension Jason.decode!(~S"""
                  {
                    "http-message-signatures": {
                      "schema": {
                        "$schema": "https://json-schema.org/draft/2020-12/schema",
                        "type": "object",
                        "properties": {
                          "registrationUrl": {
                            "type": "string",
                            "format": "uri",
                            "description": "URL to the network's setup endpoint and documentation"
                          },
                          "signatureSchemes": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            },
                            "description": "Supported cryptographic signature algorithms"
                          },
                          "tags": {
                            "type": "array",
                            "items": {
                              "type": "string"
                            },
                            "description": "Supported signature tags for validation"
                          }
                        },
                        "required": ["registrationUrl", "signatureSchemes"]
                      },
                      "info": {
                        "registrationUrl": "https://network.example.com/signature-agents",
                        "signatureSchemes": ["ed25519", "ecdsa-p256-sha256", "rsa-pss-sha512"],
                        "tags": ["web-bot-auth", "agent-browser-auth"]
                      }
                    }
                  }
                  """)

  @spec_opts [
    registration_url: "https://network.example.com/signature-agents",
    signature_schemes: ["ed25519", "ecdsa-p256-sha256", "rsa-pss-sha512"],
    tags: ["web-bot-auth", "agent-browser-auth"]
  ]

  describe "extension/1" do
    test "reproduces the specification example exactly" do
      assert Extension.extension(@spec_opts) == @spec_extension["http-message-signatures"]
    end

    test "omits the schema on request and defaults tags to an empty list" do
      extension =
        Extension.extension(
          registration_url: "https://n.example/r",
          signature_schemes: ["ed25519"],
          include_schema: false
        )

      assert extension == %{
               "info" => %{
                 "registrationUrl" => "https://n.example/r",
                 "signatureSchemes" => ["ed25519"],
                 "tags" => []
               }
             }

      refute Map.has_key?(extension, "schema")
    end

    test "rejects invalid options at configuration time" do
      assert_raise NimbleOptions.ValidationError, ~r/:registration_url/, fn ->
        Extension.extension(signature_schemes: ["ed25519"])
      end

      assert_raise NimbleOptions.ValidationError, ~r/http\(s\) URL/, fn ->
        Extension.extension(
          registration_url: "network.example.com",
          signature_schemes: ["ed25519"]
        )
      end

      assert_raise NimbleOptions.ValidationError, ~r/http\(s\) URL/, fn ->
        Extension.extension(registration_url: nil, signature_schemes: ["ed25519"])
      end

      assert_raise NimbleOptions.ValidationError, ~r/:signature_schemes/, fn ->
        Extension.extension(registration_url: "https://n.example/r")
      end

      assert_raise NimbleOptions.ValidationError, ~r/non-empty list of signature schemes/, fn ->
        Extension.extension(registration_url: "https://n.example/r", signature_schemes: [])
      end

      assert_raise NimbleOptions.ValidationError, ~r/non-empty list of signature schemes/, fn ->
        Extension.extension(registration_url: "https://n.example/r", signature_schemes: "ed25519")
      end

      assert_raise NimbleOptions.ValidationError, ~r/non-empty strings/, fn ->
        Extension.extension(
          registration_url: "https://n.example/r",
          signature_schemes: ["ed25519", ""]
        )
      end

      assert_raise NimbleOptions.ValidationError, ~r/non-empty strings/, fn ->
        Extension.extension(
          registration_url: "https://n.example/r",
          signature_schemes: ["ed25519"],
          tags: [1]
        )
      end

      assert_raise NimbleOptions.ValidationError, ~r/non-empty list of tags/, fn ->
        Extension.extension(
          registration_url: "https://n.example/r",
          signature_schemes: ["ed25519"],
          tags: "web-bot-auth"
        )
      end

      assert_raise NimbleOptions.ValidationError, ~r/:include_schema/, fn ->
        Extension.extension(
          registration_url: "https://n.example/r",
          signature_schemes: ["ed25519"],
          include_schema: "no"
        )
      end
    end
  end

  describe "validate/1" do
    test "accepts the specification example, with or without schema, or bare info" do
      expected = %{
        registration_url: "https://network.example.com/signature-agents",
        signature_schemes: ["ed25519", "ecdsa-p256-sha256", "rsa-pss-sha512"],
        tags: ["web-bot-auth", "agent-browser-auth"]
      }

      declaration = @spec_extension["http-message-signatures"]
      assert {:ok, ^expected} = Extension.validate(declaration)
      assert {:ok, ^expected} = Extension.validate(Map.delete(declaration, "schema"))
      assert {:ok, ^expected} = Extension.validate(declaration["info"])

      assert {:ok, ^expected} =
               Extension.validate(%{
                 info: %{
                   registrationUrl: expected.registration_url,
                   signatureSchemes: expected.signature_schemes,
                   tags: expected.tags
                 }
               })
    end

    test "defaults tags and reports missing or malformed fields" do
      info = %{"registrationUrl" => "https://n.example/r", "signatureSchemes" => ["ed25519"]}

      assert {:ok, %{tags: []}} = Extension.validate(%{"info" => info})

      assert {:error, {:missing_field, "registrationUrl"}} =
               Extension.validate(%{"info" => Map.delete(info, "registrationUrl")})

      assert {:error, {:missing_field, "signatureSchemes"}} =
               Extension.validate(%{"info" => Map.delete(info, "signatureSchemes")})

      assert {:error, :invalid_http_message_signatures_extension} =
               Extension.validate(%{"info" => Map.put(info, "registrationUrl", "")})

      assert {:error, :invalid_http_message_signatures_extension} =
               Extension.validate(%{"info" => Map.put(info, "registrationUrl", 1)})

      assert {:error, :invalid_http_message_signatures_extension} =
               Extension.validate(%{"info" => Map.put(info, "signatureSchemes", [1])})

      assert {:error, :invalid_http_message_signatures_extension} =
               Extension.validate(%{"info" => Map.put(info, "tags", "x")})

      assert {:error, :invalid_http_message_signatures_extension} =
               Extension.validate(%{"info" => Map.put(info, "tags", [nil])})

      assert {:error, {:missing_field, "registrationUrl"}} = Extension.validate(%{"info" => "x"})
      assert {:error, :invalid_http_message_signatures_extension} = Extension.validate([])
      assert {:error, :invalid_http_message_signatures_extension} = Extension.validate(nil)
    end
  end

  describe "decode/1" do
    test "finds the extension in a PaymentRequired map or an extensions map" do
      payment_required = %{"x402Version" => 2, "accepts" => [], "extensions" => @spec_extension}

      assert {:ok, %{registration_url: "https://network.example.com/signature-agents"}} =
               Extension.decode(payment_required)

      assert {:ok, %{tags: ["web-bot-auth", "agent-browser-auth"]}} =
               Extension.decode(@spec_extension)

      assert {:ok, %{signature_schemes: [_, _, _]}} =
               Extension.decode(%{
                 extensions: %{
                   "http-message-signatures": @spec_extension["http-message-signatures"]
                 }
               })
    end

    test "is nil when absent and an error when malformed" do
      assert {:ok, nil} = Extension.decode(%{})
      assert {:ok, nil} = Extension.decode(%{"extensions" => %{}})
      assert {:ok, nil} = Extension.decode(%{"extensions" => nil})

      assert {:error, :invalid_http_message_signatures_extension} =
               Extension.decode(%{"extensions" => %{"http-message-signatures" => 1}})

      assert {:error, {:missing_field, "signatureSchemes"}} =
               Extension.decode(%{
                 "http-message-signatures" => %{"registrationUrl" => "https://n.example/r"}
               })

      assert {:error, :invalid_http_message_signatures_extension} = Extension.decode("x")
    end
  end
end
