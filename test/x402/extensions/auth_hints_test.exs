defmodule X402.Extensions.AuthHintsTest do
  use ExUnit.Case, async: true

  alias X402.Extensions.AuthHints

  doctest X402.Extensions.AuthHints

  # The PAYMENT-REQUIRED example from the extension specification.
  @spec_payment_required Jason.decode!(~S"""
                         {
                           "x402Version": 2,
                           "error": "Payment required",
                           "resource": {
                             "url": "https://api.example.com/premium-data",
                             "description": "Access to premium market data",
                             "mimeType": "application/json"
                           },
                           "accepts": [
                             {
                               "scheme": "exact",
                               "network": "eip155:8453",
                               "amount": "10000",
                               "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                               "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
                               "maxTimeoutSeconds": 60
                             },
                             {
                               "scheme": "deferred",
                               "network": "eip155:8453",
                               "amount": "10000",
                               "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                               "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
                               "maxTimeoutSeconds": 60
                             }
                           ],
                           "extensions": {
                             "auth-hints": {
                               "info": {
                                 "authRequirements": [
                                   {
                                     "acceptIndexes": [1],
                                     "methods": [
                                       {
                                         "type": "oauth2",
                                         "tokenType": "DPoP",
                                         "authorizationServer": "https://as.example.com",
                                         "tokenEndpoint": "https://as.example.com/token",
                                         "registrationEndpoint": "https://as.example.com/register"
                                       }
                                     ]
                                   }
                                 ]
                               },
                               "schema": {
                                 "$schema": "https://json-schema.org/draft/2020-12/schema",
                                 "type": "object",
                                 "properties": {
                                   "authRequirements": {
                                     "type": "array",
                                     "items": {
                                       "type": "object",
                                       "properties": {
                                         "acceptIndexes": {
                                           "type": "array",
                                           "items": { "type": "integer" },
                                           "description": "Indexes into the accepts[] array"
                                         },
                                         "methods": {
                                           "type": "array",
                                           "items": {
                                             "type": "object",
                                             "properties": {
                                               "type": {
                                                 "type": "string",
                                                 "description": "Authentication method type"
                                               }
                                             },
                                             "required": ["type"]
                                           }
                                         }
                                       },
                                       "required": ["acceptIndexes", "methods"]
                                     }
                                   }
                                 },
                                 "required": ["authRequirements"]
                               }
                             }
                           }
                         }
                         """)

  defp spec_oauth2 do
    AuthHints.oauth2(
      token_type: "DPoP",
      authorization_server: "https://as.example.com",
      token_endpoint: "https://as.example.com/token",
      registration_endpoint: "https://as.example.com/register"
    )
  end

  describe "extension/1" do
    test "reproduces the specification example exactly" do
      extension = AuthHints.extension([[accept_indexes: [1], methods: [spec_oauth2()]]])

      assert extension == @spec_payment_required["extensions"]["auth-hints"]
      assert Jason.encode!(extension) |> Jason.decode!() == extension
    end

    test "carries several requirements and methods in order" do
      extension =
        AuthHints.extension([
          [accept_indexes: [0, 2], methods: [AuthHints.sign_in_with_x(), spec_oauth2()]],
          [accept_indexes: [1], methods: [%{"type" => "future", "hint" => 1}]]
        ])

      assert extension["info"]["authRequirements"] == [
               %{
                 "acceptIndexes" => [0, 2],
                 "methods" => [%{"type" => "sign-in-with-x"}, spec_oauth2()]
               },
               %{"acceptIndexes" => [1], "methods" => [%{"type" => "future", "hint" => 1}]}
             ]
    end

    test "rejects invalid declarations at configuration time" do
      valid = [accept_indexes: [0], methods: [AuthHints.sign_in_with_x()]]

      assert_raise NimbleOptions.ValidationError, ~r/non-empty list of auth requirements/, fn ->
        AuthHints.extension([])
      end

      assert_raise NimbleOptions.ValidationError, ~r/non-empty list of auth requirements/, fn ->
        AuthHints.extension(:nope)
      end

      assert_raise NimbleOptions.ValidationError, ~r/accept indexes/, fn ->
        AuthHints.extension([Keyword.put(valid, :accept_indexes, [])])
      end

      assert_raise NimbleOptions.ValidationError, ~r/non-negative accept indexes/, fn ->
        AuthHints.extension([Keyword.put(valid, :accept_indexes, [-1])])
      end

      assert_raise NimbleOptions.ValidationError, ~r/non-negative accept indexes/, fn ->
        AuthHints.extension([Keyword.put(valid, :accept_indexes, ["1"])])
      end

      assert_raise NimbleOptions.ValidationError, ~r/at least one authentication method/, fn ->
        AuthHints.extension([Keyword.put(valid, :methods, [])])
      end

      assert_raise NimbleOptions.ValidationError, ~r/list of authentication methods/, fn ->
        AuthHints.extension([Keyword.put(valid, :methods, "oauth2")])
      end

      assert_raise NimbleOptions.ValidationError,
                   ~r/invalid authentication method.*:invalid_method/,
                   fn ->
                     AuthHints.extension([
                       Keyword.put(valid, :methods, [%{"tokenType" => "Bearer"}])
                     ])
                   end

      assert_raise NimbleOptions.ValidationError, ~r/missing_method_field/, fn ->
        AuthHints.extension([Keyword.put(valid, :methods, [%{"type" => "oauth2"}])])
      end

      assert_raise NimbleOptions.ValidationError, ~r/:methods/, fn ->
        AuthHints.extension([[accept_indexes: [0]]])
      end

      assert_raise NimbleOptions.ValidationError, ~r/:accept_indexes/, fn ->
        AuthHints.extension([[methods: [AuthHints.sign_in_with_x()]]])
      end

      assert_raise NimbleOptions.ValidationError, ~r/:extra/, fn ->
        AuthHints.extension([Keyword.put(valid, :extra, 1)])
      end
    end
  end

  describe "oauth2/1" do
    test "rejects invalid token types and URLs" do
      valid = [
        token_type: "Bearer",
        authorization_server: "https://as.example.com",
        token_endpoint: "https://as.example.com/token"
      ]

      assert_raise NimbleOptions.ValidationError, ~r/:token_type/, fn ->
        AuthHints.oauth2(Keyword.put(valid, :token_type, "MAC"))
      end

      assert_raise NimbleOptions.ValidationError, ~r/http\(s\) URL/, fn ->
        AuthHints.oauth2(Keyword.put(valid, :authorization_server, "as.example.com"))
      end

      assert_raise NimbleOptions.ValidationError, ~r/http\(s\) URL/, fn ->
        AuthHints.oauth2(Keyword.put(valid, :token_endpoint, "ftp://as.example.com/token"))
      end

      assert_raise NimbleOptions.ValidationError, ~r/http\(s\) URL/, fn ->
        AuthHints.oauth2(Keyword.put(valid, :registration_endpoint, 42))
      end

      assert_raise NimbleOptions.ValidationError, ~r/:token_endpoint/, fn ->
        AuthHints.oauth2(Keyword.delete(valid, :token_endpoint))
      end

      assert AuthHints.oauth2(Keyword.put(valid, :authorization_server, "http://localhost:4000"))[
               "authorizationServer"
             ] == "http://localhost:4000"
    end
  end

  describe "validate_method/1" do
    test "checks oauth2 fields thoroughly" do
      oauth2 = spec_oauth2()

      assert {:ok, ^oauth2} = AuthHints.validate_method(oauth2)
      assert {:ok, _} = AuthHints.validate_method(Map.delete(oauth2, "registrationEndpoint"))
      assert {:ok, _} = AuthHints.validate_method(Map.put(oauth2, "tokenType", "Bearer"))

      assert {:error, {:missing_method_field, "tokenType"}} =
               AuthHints.validate_method(Map.delete(oauth2, "tokenType"))

      assert {:error, {:missing_method_field, "authorizationServer"}} =
               AuthHints.validate_method(Map.delete(oauth2, "authorizationServer"))

      assert {:error, :invalid_token_type} =
               AuthHints.validate_method(Map.put(oauth2, "tokenType", "bearer"))

      assert {:error, :invalid_method} =
               AuthHints.validate_method(Map.put(oauth2, "tokenType", 1))

      assert {:error, :invalid_method} =
               AuthHints.validate_method(Map.put(oauth2, "tokenEndpoint", ""))

      assert {:error, :invalid_method} =
               AuthHints.validate_method(Map.put(oauth2, "registrationEndpoint", 1))
    end

    test "accepts unknown types and rejects non-string or missing types" do
      assert {:ok, %{"type" => "custom", "x" => 1}} =
               AuthHints.validate_method(%{"type" => "custom", "x" => 1})

      assert {:error, :invalid_method} = AuthHints.validate_method(%{"type" => 1})
      assert {:error, :invalid_method} = AuthHints.validate_method(%{})
      assert {:error, :invalid_method} = AuthHints.validate_method("oauth2")
      assert {:error, :invalid_method} = AuthHints.validate_method(nil)
    end
  end

  describe "decode/1" do
    test "decodes the specification example" do
      assert {:ok, [%{accept_indexes: [1], methods: [method]}]} =
               AuthHints.decode(@spec_payment_required)

      assert method == spec_oauth2()
    end

    test "accepts the extensions map alone, atom keys and a bare info map" do
      extension = @spec_payment_required["extensions"]["auth-hints"]

      assert {:ok, [%{accept_indexes: [1]}]} = AuthHints.decode(%{"auth-hints" => extension})

      assert {:ok, [%{accept_indexes: [1]}]} =
               AuthHints.decode(%{extensions: %{"auth-hints": extension}})

      assert {:ok, [%{accept_indexes: [1]}]} =
               AuthHints.decode(%{"extensions" => %{"auth-hints" => extension["info"]}})

      assert {:ok, [%{accept_indexes: [1]}]} =
               AuthHints.decode(%{
                 accepts: [%{}, %{}],
                 extensions: %{
                   "auth-hints": %{
                     info: %{
                       authRequirements: [%{acceptIndexes: [1, 3], methods: [%{"type" => "x"}]}]
                     }
                   }
                 }
               })
    end

    test "is empty when the extension is absent" do
      assert {:ok, []} = AuthHints.decode(%{})
      assert {:ok, []} = AuthHints.decode(%{"extensions" => %{"other" => %{}}})
      assert {:ok, []} = AuthHints.decode(%{"extensions" => nil})

      assert {:ok, []} =
               AuthHints.decode(%{
                 "extensions" => %{"auth-hints" => %{"info" => %{"authRequirements" => []}}}
               })
    end

    test "silently ignores out-of-range indexes and drops emptied requirements" do
      hints = %{
        "info" => %{
          "authRequirements" => [
            %{"acceptIndexes" => [5, 0, 2, -1], "methods" => [%{"type" => "sign-in-with-x"}]},
            %{"acceptIndexes" => [9], "methods" => [%{"type" => "sign-in-with-x"}]}
          ]
        }
      }

      assert {:ok, [%{accept_indexes: [0]}]} =
               AuthHints.decode(%{
                 "accepts" => [%{}, %{}],
                 "extensions" => %{"auth-hints" => hints}
               })

      # Without accepts[] there is nothing to bound by, only negatives go.
      assert {:ok, [%{accept_indexes: [5, 0, 2]}, %{accept_indexes: [9]}]} =
               AuthHints.decode(%{"extensions" => %{"auth-hints" => hints}})

      assert {:ok, []} =
               AuthHints.decode(%{"accepts" => [], "extensions" => %{"auth-hints" => hints}})
    end

    test "rejects malformed declarations" do
      wrap = fn value -> %{"accepts" => [%{}], "extensions" => %{"auth-hints" => value}} end

      assert {:error, :invalid_auth_hints} = AuthHints.decode(wrap.("x"))
      assert {:error, :invalid_auth_hints} = AuthHints.decode(wrap.(%{"info" => "x"}))
      assert {:error, :invalid_auth_hints} = AuthHints.decode(wrap.(%{"info" => %{}}))

      assert {:error, :invalid_auth_hints} =
               AuthHints.decode(wrap.(%{"info" => %{"authRequirements" => [1]}}))

      assert {:error, :invalid_accept_indexes} =
               AuthHints.decode(wrap.(%{"info" => %{"authRequirements" => [%{"methods" => []}]}}))

      assert {:error, :invalid_accept_indexes} =
               AuthHints.decode(
                 wrap.(%{
                   "info" => %{
                     "authRequirements" => [%{"acceptIndexes" => ["0"], "methods" => []}]
                   }
                 })
               )

      assert {:error, :invalid_method} =
               AuthHints.decode(
                 wrap.(%{"info" => %{"authRequirements" => [%{"acceptIndexes" => [0]}]}})
               )

      assert {:error, :invalid_method} =
               AuthHints.decode(
                 wrap.(%{
                   "info" => %{
                     "authRequirements" => [%{"acceptIndexes" => [0], "methods" => [1]}]
                   }
                 })
               )

      assert {:error, :invalid_token_type} =
               AuthHints.decode(
                 wrap.(%{
                   "info" => %{
                     "authRequirements" => [
                       %{
                         "acceptIndexes" => [0],
                         "methods" => [Map.put(spec_oauth2(), "tokenType", "MAC")]
                       }
                     ]
                   }
                 })
               )

      assert {:error, :invalid_auth_hints} = AuthHints.decode("not a map")
    end
  end

  describe "methods_for/2 and requires_auth?/2" do
    setup do
      %{payment_required: @spec_payment_required, accepts: @spec_payment_required["accepts"]}
    end

    test "resolve by index or by requirements map", %{
      payment_required: payment_required,
      accepts: [exact, deferred]
    } do
      assert AuthHints.methods_for(payment_required, deferred) == [spec_oauth2()]
      assert AuthHints.methods_for(payment_required, 1) == [spec_oauth2()]
      assert AuthHints.methods_for(payment_required, exact) == []
      assert AuthHints.methods_for(payment_required, 0) == []
      assert AuthHints.methods_for(payment_required, 2) == []
      assert AuthHints.methods_for(payment_required, %{"scheme" => "unknown"}) == []

      assert AuthHints.requires_auth?(payment_required, deferred)
      assert AuthHints.requires_auth?(payment_required, 1)
      refute AuthHints.requires_auth?(payment_required, exact)
      refute AuthHints.requires_auth?(payment_required, 7)
    end

    test "concatenate methods from every requirement naming the entry", %{accepts: accepts} do
      extension =
        AuthHints.extension([
          [accept_indexes: [1], methods: [AuthHints.sign_in_with_x()]],
          [accept_indexes: [0, 1], methods: [spec_oauth2()]]
        ])

      payment_required = %{"accepts" => accepts, "extensions" => %{"auth-hints" => extension}}

      assert AuthHints.methods_for(payment_required, 1) == [
               AuthHints.sign_in_with_x(),
               spec_oauth2()
             ]

      assert AuthHints.methods_for(payment_required, 0) == [spec_oauth2()]
    end

    test "treat a malformed extension or missing accepts as no requirement" do
      broken = %{
        "accepts" => [%{}],
        "extensions" => %{"auth-hints" => %{"info" => %{"authRequirements" => 1}}}
      }

      assert AuthHints.methods_for(broken, 0) == []
      refute AuthHints.requires_auth?(broken, %{})

      assert AuthHints.methods_for(%{"extensions" => %{}}, %{"scheme" => "exact"}) == []
    end
  end
end
