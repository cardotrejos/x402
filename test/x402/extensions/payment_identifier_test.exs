defmodule X402.Extensions.PaymentIdentifierTest do
  use ExUnit.Case, async: true

  doctest X402.Extensions.PaymentIdentifier

  alias X402.Extensions.PaymentIdentifier

  @valid_id String.duplicate("a", 16)

  # Legacy functions are deprecated; resolving the module through the test
  # context keeps the test compile free of deprecation warnings.
  defp legacy_context(_context), do: %{legacy: PaymentIdentifier}

  describe "extension_key/0 and legacy_extension_key/0" do
    test "return the wire keys" do
      assert PaymentIdentifier.extension_key() == "payment-identifier"
      assert PaymentIdentifier.legacy_extension_key() == "paymentIdentifier"
    end
  end

  describe "extension/1 and schema/0" do
    test "advertises the spec shape" do
      assert PaymentIdentifier.extension() == %{
               "info" => %{"required" => false},
               "schema" => %{
                 "$schema" => "https://json-schema.org/draft/2020-12/schema",
                 "type" => "object",
                 "properties" => %{
                   "id" => %{
                     "type" => "string",
                     "minLength" => 16,
                     "maxLength" => 128,
                     "pattern" => "^[A-Za-z0-9_-]+$"
                   },
                   "required" => %{"type" => "boolean"}
                 }
               }
             }

      assert PaymentIdentifier.extension(required: true)["info"] == %{"required" => true}
      assert PaymentIdentifier.extension()["schema"] == PaymentIdentifier.schema()
    end

    test "rejects invalid options" do
      assert_raise NimbleOptions.ValidationError, fn ->
        PaymentIdentifier.extension(required: "yes")
      end
    end

    test "is JSON encodable" do
      assert {:ok, _json} = Jason.encode(PaymentIdentifier.extension(required: true))
    end
  end

  describe "valid_id?/1" do
    test "accepts 16..128 characters of [A-Za-z0-9_-]" do
      assert PaymentIdentifier.valid_id?(String.duplicate("a", 16))
      assert PaymentIdentifier.valid_id?(String.duplicate("Z", 128))
      assert PaymentIdentifier.valid_id?("AZaz09_-AZaz09_-")
    end

    test "rejects boundary lengths 15 and 129" do
      refute PaymentIdentifier.valid_id?(String.duplicate("a", 15))
      refute PaymentIdentifier.valid_id?(String.duplicate("a", 129))
    end

    test "rejects invalid characters and non-binaries" do
      refute PaymentIdentifier.valid_id?("abcdefghijklmno.")
      refute PaymentIdentifier.valid_id?("abcdefghijklmno ")
      refute PaymentIdentifier.valid_id?("abcdefghijklmno=")
      refute PaymentIdentifier.valid_id?("abcdefghijklmnoé")
      refute PaymentIdentifier.valid_id?("")
      refute PaymentIdentifier.valid_id?(nil)
      refute PaymentIdentifier.valid_id?(1234)
    end

    test "rejects ids with embedded or trailing newlines" do
      refute PaymentIdentifier.valid_id?("abcdefghijklmnop\nabcdefghijklmnop")
      refute PaymentIdentifier.valid_id?("abcdefghijklmnop\n")
    end
  end

  describe "generate_id/0" do
    test "produces distinct valid 32-character ids" do
      ids = for _ <- 1..50, do: PaymentIdentifier.generate_id()

      assert Enum.all?(ids, &PaymentIdentifier.valid_id?/1)
      assert Enum.all?(ids, &(String.length(&1) == 32))
      assert length(Enum.uniq(ids)) == 50
    end
  end

  describe "required?/1" do
    test "reads info.required from the advertisement" do
      required = %{"payment-identifier" => PaymentIdentifier.extension(required: true)}
      optional = %{"payment-identifier" => PaymentIdentifier.extension()}

      assert PaymentIdentifier.required?(required)
      refute PaymentIdentifier.required?(optional)
      refute PaymentIdentifier.required?(%{"payment-identifier" => %{"info" => "x"}})
      refute PaymentIdentifier.required?(%{"payment-identifier" => "x"})
      refute PaymentIdentifier.required?(%{})
      refute PaymentIdentifier.required?(nil)
    end

    test "accepts atom keys" do
      assert PaymentIdentifier.required?(%{"payment-identifier": %{info: %{required: true}}})
    end
  end

  describe "extract_id/1 spec format" do
    test "returns the spec id" do
      extensions = %{"payment-identifier" => %{"info" => %{"id" => @valid_id}}}
      assert PaymentIdentifier.extract_id(extensions) == {:ok, {:spec, @valid_id}}
    end

    test "accepts atom keys" do
      extensions = %{"payment-identifier": %{info: %{id: @valid_id}}}
      assert PaymentIdentifier.extract_id(extensions) == {:ok, {:spec, @valid_id}}
    end

    test "returns nil when the extension is echoed without an id" do
      assert PaymentIdentifier.extract_id(%{"payment-identifier" => %{"info" => %{}}}) ==
               {:ok, nil}

      assert PaymentIdentifier.extract_id(%{"payment-identifier" => %{}}) == {:ok, nil}
    end

    test "rejects invalid ids and shapes" do
      for invalid <- [
            %{"payment-identifier" => %{"info" => %{"id" => String.duplicate("a", 15)}}},
            %{"payment-identifier" => %{"info" => %{"id" => String.duplicate("a", 129)}}},
            %{"payment-identifier" => %{"info" => %{"id" => "abcdefghijklmno!"}}},
            %{"payment-identifier" => %{"info" => %{"id" => ""}}},
            %{"payment-identifier" => %{"info" => %{"id" => 42}}},
            %{"payment-identifier" => %{"info" => "not-a-map"}},
            %{"payment-identifier" => "not-a-map"}
          ] do
        assert PaymentIdentifier.extract_id(invalid) == {:error, :invalid_payment_id}
      end
    end

    test "spec key wins over the legacy key" do
      extensions = %{
        "payment-identifier" => %{"info" => %{"id" => @valid_id}},
        "paymentIdentifier" => %{"paymentId" => "legacy-1"}
      }

      assert PaymentIdentifier.extract_id(extensions) == {:ok, {:spec, @valid_id}}
    end

    test "a spec echo without an id falls through to the legacy key" do
      extensions = %{
        "payment-identifier" => %{"info" => %{"required" => false}},
        "paymentIdentifier" => %{"paymentId" => "legacy-1"}
      }

      assert PaymentIdentifier.extract_id(extensions) == {:ok, {:legacy, "legacy-1"}}
    end

    test "an invalid spec id is rejected even when a legacy id is present" do
      extensions = %{
        "payment-identifier" => %{"info" => %{"id" => "short"}},
        "paymentIdentifier" => %{"paymentId" => "legacy-1"}
      }

      assert PaymentIdentifier.extract_id(extensions) == {:error, :invalid_payment_id}
    end

    test "returns nil for absent or non-map extensions" do
      assert PaymentIdentifier.extract_id(%{}) == {:ok, nil}
      assert PaymentIdentifier.extract_id(nil) == {:ok, nil}
      assert PaymentIdentifier.extract_id("garbage") == {:ok, nil}
    end
  end

  describe "extract_id/1 legacy format" do
    setup :legacy_context

    test "accepts the Base64 string, bare map, and info-wrapped forms", %{legacy: legacy} do
      {:ok, encoded} = legacy.encode("pay-1")

      for value <- [
            encoded,
            %{"paymentId" => "pay-1"},
            %{"info" => encoded},
            %{"info" => %{"paymentId" => "pay-1"}},
            %{"schema" => "https://x402.org/ext", "info" => %{"paymentId" => "pay-1"}}
          ] do
        assert PaymentIdentifier.extract_id(%{"paymentIdentifier" => value}) ==
                 {:ok, {:legacy, "pay-1"}}
      end
    end

    test "accepts atom keys" do
      assert PaymentIdentifier.extract_id(%{paymentIdentifier: %{"paymentId" => "pay-1"}}) ==
               {:ok, {:legacy, "pay-1"}}
    end

    test "does not apply the spec length and character rules" do
      assert PaymentIdentifier.extract_id(%{"paymentIdentifier" => %{"paymentId" => "x"}}) ==
               {:ok, {:legacy, "x"}}
    end

    test "wraps legacy decode errors" do
      for {value, reason} <- [
            {"%%% not base64 %%%", :invalid_base64},
            {Base.encode64("not-json"), :invalid_json},
            {%{}, :missing_payment_id},
            {%{"paymentId" => ""}, :invalid_payment_id},
            {%{"info" => %{}}, :missing_payment_id},
            {%{"info" => 42}, :invalid_payment_id},
            {42, :invalid_payment_id}
          ] do
        assert PaymentIdentifier.extract_id(%{"paymentIdentifier" => value}) ==
                 {:error, {:legacy, reason}}
      end
    end
  end

  describe "fingerprint/2" do
    @requirements %{
      "scheme" => "exact",
      "network" => "eip155:84532",
      "asset" => "0xasset",
      "amount" => "10000",
      "payTo" => "0xreceiver"
    }

    test "is a deterministic lowercase hex SHA-256" do
      fingerprint = PaymentIdentifier.fingerprint(@requirements, %{method: :get, path: "/api"})

      assert fingerprint ==
               PaymentIdentifier.fingerprint(@requirements, %{method: :get, path: "/api"})

      assert fingerprint =~ ~r/^[0-9a-f]{64}$/

      expected =
        :crypto.hash(:sha256, "exact\neip155:84532\n0xasset\n10000\n0xreceiver\nget\n/api\n")
        |> Base.encode16(case: :lower)

      assert fingerprint == expected
    end

    test "changes with every requirement and context component" do
      base = PaymentIdentifier.fingerprint(@requirements, %{method: :get, path: "/api"})

      variants = [
        PaymentIdentifier.fingerprint(%{@requirements | "scheme" => "upto"}, %{
          method: :get,
          path: "/api"
        }),
        PaymentIdentifier.fingerprint(%{@requirements | "network" => "eip155:8453"}, %{
          method: :get,
          path: "/api"
        }),
        PaymentIdentifier.fingerprint(%{@requirements | "asset" => "0xother"}, %{
          method: :get,
          path: "/api"
        }),
        PaymentIdentifier.fingerprint(%{@requirements | "amount" => "10001"}, %{
          method: :get,
          path: "/api"
        }),
        PaymentIdentifier.fingerprint(%{@requirements | "payTo" => "0xother"}, %{
          method: :get,
          path: "/api"
        }),
        PaymentIdentifier.fingerprint(@requirements, %{method: :post, path: "/api"}),
        PaymentIdentifier.fingerprint(@requirements, %{method: :get, path: "/other"}),
        PaymentIdentifier.fingerprint(@requirements, %{tool: "search"})
      ]

      refute base in variants
      assert length(Enum.uniq(variants)) == length(variants)
    end

    test "reads atom-keyed requirements and stringifies non-binary values" do
      atom_requirements = %{
        scheme: "exact",
        network: "eip155:84532",
        asset: "0xasset",
        amount: 10_000,
        payTo: "0xreceiver"
      }

      assert PaymentIdentifier.fingerprint(atom_requirements, %{method: :get, path: "/api"}) ==
               PaymentIdentifier.fingerprint(@requirements, %{method: "get", path: "/api"})
    end

    test "treats absent components as empty strings" do
      assert PaymentIdentifier.fingerprint(%{}, %{}) ==
               PaymentIdentifier.fingerprint(
                 %{"scheme" => nil, "network" => "", "asset" => nil},
                 %{method: nil, path: "", tool: nil}
               )
    end
  end

  describe "enricher/1" do
    @advertised %{"payment-identifier" => PaymentIdentifier.extension(required: true)}
    @payment_required %{"extensions" => @advertised}

    test "echoes the advertisement and adds a generated info.id" do
      enricher = PaymentIdentifier.enricher()
      payload = %{"accepted" => %{}, "extensions" => @advertised}

      assert {:ok, enriched} = enricher.(payload, @payment_required)

      declaration = enriched["extensions"]["payment-identifier"]
      assert declaration["schema"] == PaymentIdentifier.schema()
      assert declaration["info"]["required"] == true
      assert PaymentIdentifier.valid_id?(declaration["info"]["id"])
      assert enriched["accepted"] == %{}

      assert PaymentIdentifier.extract_id(enriched["extensions"]) ==
               {:ok, {:spec, declaration["info"]["id"]}}
    end

    test "generates a fresh id per invocation" do
      enricher = PaymentIdentifier.enricher()
      payload = %{"extensions" => @advertised}

      {:ok, first} = enricher.(payload, @payment_required)
      {:ok, second} = enricher.(payload, @payment_required)

      assert first["extensions"]["payment-identifier"]["info"]["id"] !=
               second["extensions"]["payment-identifier"]["info"]["id"]
    end

    test "uses an explicit id and rejects an invalid one" do
      {:ok, enriched} =
        PaymentIdentifier.enricher(id: @valid_id).(
          %{"extensions" => @advertised},
          @payment_required
        )

      assert enriched["extensions"]["payment-identifier"]["info"]["id"] == @valid_id

      assert PaymentIdentifier.enricher(id: "short").(
               %{"extensions" => @advertised},
               @payment_required
             ) ==
               {:error, :invalid_payment_id}
    end

    test "is a no-op when the server did not advertise the extension" do
      payload = %{"extensions" => %{}}

      assert PaymentIdentifier.enricher().(payload, %{"extensions" => %{}}) == {:ok, payload}
      assert PaymentIdentifier.enricher().(payload, nil) == {:ok, payload}
      assert PaymentIdentifier.enricher().(%{}, %{}) == {:ok, %{}}
    end

    test "always: true attaches a minimal declaration without an advertisement" do
      {:ok, enriched} = PaymentIdentifier.enricher(always: true, id: @valid_id).(%{}, nil)

      assert enriched == %{
               "extensions" => %{"payment-identifier" => %{"info" => %{"id" => @valid_id}}}
             }
    end

    test "falls back to the advertisement when the payload has no echo yet" do
      {:ok, enriched} = PaymentIdentifier.enricher(id: @valid_id).(%{}, @payment_required)

      assert enriched["extensions"]["payment-identifier"]["info"] ==
               %{"required" => true, "id" => @valid_id}

      assert enriched["extensions"]["payment-identifier"]["schema"] == PaymentIdentifier.schema()
    end

    test "preserves other extensions and atom-keyed advertisements" do
      payment_required = %{extensions: %{"payment-identifier": %{info: %{required: false}}}}
      payload = %{"extensions" => %{"other" => %{"info" => %{}}}}

      {:ok, enriched} = PaymentIdentifier.enricher(id: @valid_id).(payload, payment_required)

      assert enriched["extensions"]["other"] == %{"info" => %{}}

      assert enriched["extensions"]["payment-identifier"][:info] ==
               %{"id" => @valid_id, required: false}
    end

    test "rejects invalid options" do
      assert_raise NimbleOptions.ValidationError, fn -> PaymentIdentifier.enricher(always: 1) end
      assert_raise NimbleOptions.ValidationError, fn -> PaymentIdentifier.enricher(id: 1) end
    end
  end

  describe "legacy_notice/1" do
    test "emits the legacy telemetry event with the source" do
      handler_id = "legacy-notice-#{System.unique_integer([:positive])}"
      parent = self()

      :ok =
        :telemetry.attach(
          handler_id,
          [:x402, :payment_identifier, :legacy],
          fn event, measurements, metadata, _config ->
            send(parent, {:legacy_event, event, measurements, metadata})
          end,
          nil
        )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      assert :ok = PaymentIdentifier.legacy_notice(:gate)
      assert :ok = PaymentIdentifier.legacy_notice(:mcp)

      assert_receive {:legacy_event, [:x402, :payment_identifier, :legacy], %{count: 1},
                      %{source: :gate, status: :ok}}

      assert_receive {:legacy_event, [:x402, :payment_identifier, :legacy], %{count: 1},
                      %{source: :mcp, status: :ok}}
    end
  end

  describe "legacy encode/decode (deprecated)" do
    setup :legacy_context

    test "encode/1 returns Base64 JSON payload with paymentId", %{legacy: legacy} do
      assert {:ok, encoded} = legacy.encode("payment-123")

      assert {:ok, decoded_json} = Base.decode64(encoded)
      assert %{"paymentId" => "payment-123"} = Jason.decode!(decoded_json)
    end

    test "encode/1 rejects empty and non-binary payment identifiers", %{legacy: legacy} do
      assert {:error, :invalid_payment_id} = legacy.encode("")
      assert {:error, :invalid_payment_id} = legacy.encode(nil)
      assert {:error, :invalid_payment_id} = legacy.encode(123)
    end

    test "decode/1 returns payment identifier from encoded payload", %{legacy: legacy} do
      assert {:ok, encoded} = legacy.encode("payment-abc")
      assert {:ok, "payment-abc"} = legacy.decode(encoded)
    end

    test "decode/1 handles malformed payloads", %{legacy: legacy} do
      assert {:error, :invalid_base64} = legacy.decode("not-base64")
      assert {:error, :invalid_base64} = legacy.decode("")
      assert {:error, :invalid_base64} = legacy.decode(nil)

      invalid_json = Base.encode64("not-json")
      assert {:error, :invalid_json} = legacy.decode(invalid_json)

      missing_id = Base.encode64(Jason.encode!(%{"foo" => "bar"}))
      assert {:error, :missing_payment_id} = legacy.decode(missing_id)

      invalid_id = Base.encode64(Jason.encode!(%{"paymentId" => 123}))
      assert {:error, :invalid_payment_id} = legacy.decode(invalid_id)
    end

    test "fetch_payment_id/1 validates paymentId field", %{legacy: legacy} do
      assert {:ok, "payment-1"} = legacy.fetch_payment_id(%{"paymentId" => "payment-1"})
      assert {:error, :missing_payment_id} = legacy.fetch_payment_id(%{})
      assert {:error, :invalid_payment_id} = legacy.fetch_payment_id(%{"paymentId" => ""})
      assert {:error, :invalid_payment_id} = legacy.fetch_payment_id(%{"paymentId" => 1})
      assert {:error, :invalid_payment_id} = legacy.fetch_payment_id("bad")
    end
  end
end
