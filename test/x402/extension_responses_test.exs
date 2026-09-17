defmodule X402.ExtensionResponsesTest do
  use ExUnit.Case, async: true

  alias X402.ExtensionResponses

  doctest X402.ExtensionResponses

  @bazaar %{"bazaar" => %{"status" => "success"}}

  describe "encode/1" do
    test "round-trips through decode/1" do
      assert {:ok, encoded} = ExtensionResponses.encode(@bazaar)
      assert {:ok, @bazaar} = ExtensionResponses.decode(encoded)
    end

    test "rejects non-map values" do
      assert {:error, :invalid_responses} = ExtensionResponses.encode("bazaar")
      assert {:error, :invalid_responses} = ExtensionResponses.encode([@bazaar])
      assert {:error, :invalid_responses} = ExtensionResponses.encode(nil)
    end

    test "rejects maps with non-string keys" do
      assert {:error, :invalid_responses} =
               ExtensionResponses.encode(%{bazaar: %{"status" => "success"}})
    end

    test "rejects maps whose values are not objects" do
      assert {:error, :invalid_responses} = ExtensionResponses.encode(%{"bazaar" => "success"})
    end

    test "rejects values that cannot be encoded as JSON" do
      assert {:error, :invalid_json} =
               ExtensionResponses.encode(%{"bazaar" => %{"status" => {:tuple, 1}}})
    end

    test "accepts an empty map" do
      assert {:ok, encoded} = ExtensionResponses.encode(%{})
      assert {:ok, %{}} = ExtensionResponses.decode(encoded)
    end
  end

  describe "decode/1" do
    test "rejects invalid Base64" do
      assert {:error, :invalid_base64} = ExtensionResponses.decode("not base64!")
    end

    test "rejects invalid JSON" do
      assert {:error, :invalid_json} = ExtensionResponses.decode(Base.encode64("{oops"))
    end

    test "rejects JSON that is not an object of objects" do
      assert {:error, :invalid_responses} = ExtensionResponses.decode(Base.encode64("[1,2]"))
      assert {:error, :invalid_responses} = ExtensionResponses.decode(Base.encode64("42"))

      assert {:error, :invalid_responses} =
               ExtensionResponses.decode(Base.encode64(~s({"bazaar":"success"})))
    end

    test "rejects headers above the size cap" do
      assert {:error, :payload_too_large} =
               ExtensionResponses.decode(String.duplicate("A", 8_193))
    end

    test "rejects non-binary input" do
      assert {:error, :invalid_base64} = ExtensionResponses.decode(nil)
      assert {:error, :invalid_base64} = ExtensionResponses.decode(%{})
    end
  end

  describe "from_headers/1" do
    test "returns nil when the header is absent" do
      assert {:ok, nil} = ExtensionResponses.from_headers([{"content-type", "application/json"}])
      assert {:ok, nil} = ExtensionResponses.from_headers([])
    end

    test "tolerates non-list input" do
      assert {:ok, nil} = ExtensionResponses.from_headers(nil)
    end

    test "matches the header name case-insensitively" do
      {:ok, encoded} = ExtensionResponses.encode(@bazaar)

      assert {:ok, @bazaar} = ExtensionResponses.from_headers([{"EXTENSION-RESPONSES", encoded}])
      assert {:ok, @bazaar} = ExtensionResponses.from_headers([{"Extension-Responses", encoded}])
    end

    test "uses the first occurrence of the header" do
      {:ok, first} = ExtensionResponses.encode(@bazaar)
      {:ok, second} = ExtensionResponses.encode(%{"bazaar" => %{"status" => "rejected"}})

      assert {:ok, @bazaar} =
               ExtensionResponses.from_headers([
                 {"extension-responses", first},
                 {"extension-responses", second}
               ])
    end

    test "ignores malformed header tuples" do
      assert {:ok, nil} = ExtensionResponses.from_headers([:not_a_header, {"x", 1}])
    end

    test "surfaces decode errors" do
      assert {:error, :invalid_base64} =
               ExtensionResponses.from_headers([{"extension-responses", "%%%"}])
    end
  end

  describe "from_headers_lenient/1" do
    test "returns the decoded map for a valid header" do
      {:ok, encoded} = ExtensionResponses.encode(@bazaar)

      assert ExtensionResponses.from_headers_lenient([{"extension-responses", encoded}]) ==
               @bazaar
    end

    test "returns nil when the header is absent" do
      assert ExtensionResponses.from_headers_lenient([]) == nil
    end

    test "returns nil and emits telemetry for a malformed header" do
      handler_id = "extension-responses-#{System.unique_integer([:positive, :monotonic])}"
      parent = self()

      :ok =
        :telemetry.attach(
          handler_id,
          [:x402, :extension_responses, :decode],
          fn _event, measurements, metadata, _config ->
            send(parent, {:decode_event, measurements, metadata})
          end,
          nil
        )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      assert ExtensionResponses.from_headers_lenient([{"extension-responses", "%%%"}]) == nil

      assert_receive {:decode_event, %{count: 1},
                      %{status: :error, reason: :invalid_base64, header: "EXTENSION-RESPONSES"}}
    end
  end
end
