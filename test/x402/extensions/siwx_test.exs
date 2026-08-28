defmodule X402.Extensions.SIWXTest do
  use ExUnit.Case, async: true

  doctest X402.Extensions.SIWX

  alias X402.Extensions.SIWX

  describe "header_name/0" do
    test "returns SIGN-IN-WITH-X" do
      assert SIWX.header_name() == "SIGN-IN-WITH-X"
    end
  end

  describe "encode/1 and decode/1" do
    test "roundtrips a valid SIWX payload" do
      payload = valid_payload()

      assert {:ok, message} = SIWX.encode(payload)
      assert {:ok, ^payload} = SIWX.decode(message)
    end

    test "supports integer chain_id on encode" do
      payload = Map.put(valid_payload(), :chain_id, 8453)

      assert {:ok, message} = SIWX.encode(payload)
      assert {:ok, decoded} = SIWX.decode(message)
      assert decoded.chain_id == "eip155:8453"
    end

    test "returns invalid_payload for non-map payloads" do
      assert SIWX.encode(nil) == {:error, :invalid_payload}
    end

    test "returns missing_fields when required fields are absent" do
      assert SIWX.encode(%{domain: "example.com"}) ==
               {:error,
                {:missing_fields,
                 [
                   :address,
                   :statement,
                   :uri,
                   :version,
                   :chain_id,
                   :nonce,
                   :issued_at,
                   :expiration_time
                 ]}}
    end

    test "rejects invalid payload fields" do
      invalid_address = Map.put(valid_payload(), :address, "0x123")
      assert SIWX.encode(invalid_address) == {:error, {:invalid_field, :address}}

      invalid_chain_id = Map.put(valid_payload(), :chain_id, "solana:mainnet")
      assert SIWX.encode(invalid_chain_id) == {:error, {:invalid_field, :chain_id}}

      invalid_nonce = Map.put(valid_payload(), :nonce, "short")
      assert SIWX.encode(invalid_nonce) == {:error, {:invalid_field, :nonce}}

      invalid_version = Map.put(valid_payload(), :version, "2")
      assert SIWX.encode(invalid_version) == {:error, {:invalid_field, :version}}

      invalid_expiration =
        valid_payload()
        |> Map.put(:issued_at, "2026-02-16T13:00:00Z")
        |> Map.put(:expiration_time, "2026-02-16T12:00:00Z")

      assert SIWX.encode(invalid_expiration) == {:error, {:invalid_field, :expiration_time}}
    end

    test "returns invalid_message when format is malformed" do
      assert SIWX.decode("not a siwx message") == {:error, :invalid_message}
      assert SIWX.decode(nil) == {:error, :invalid_message}
    end

    test "returns invalid field errors for malformed message fields" do
      payload = valid_payload()
      {:ok, message} = SIWX.encode(payload)

      invalid_chain_message = String.replace(message, "Chain ID: 1", "Chain ID: abc")
      assert SIWX.decode(invalid_chain_message) == {:error, {:invalid_field, :chain_id}}

      invalid_address_message =
        String.replace(message, payload.address, "0x111111111111111111111111111111111111111")

      assert SIWX.decode(invalid_address_message) == {:error, {:invalid_field, :address}}
    end

    test "rejects messages with an empty domain" do
      {:ok, message} = SIWX.encode(valid_payload())

      # The first line ends with the SIWE suffix but carries no domain.
      empty_domain_message = String.replace(message, "example.com", "")

      assert SIWX.decode(empty_domain_message) == {:error, {:invalid_field, :domain}}
    end

    test "rejects messages whose first line lacks the SIWE suffix" do
      {:ok, message} = SIWX.encode(valid_payload())

      # Dropping the leading space breaks the " wants you to sign in..." suffix.
      no_suffix_message = String.replace(message, "example.com wants", "example.com-wants")

      assert SIWX.decode(no_suffix_message) == {:error, :invalid_message}
    end

    test "rejects messages with an empty prefixed field value" do
      {:ok, message} = SIWX.encode(valid_payload())

      empty_uri_message =
        String.replace(message, "URI: https://example.com/protected", "URI: ")

      assert SIWX.decode(empty_uri_message) == {:error, {:invalid_field, :uri}}
    end

    test "rejects messages with a mislabeled field line" do
      {:ok, message} = SIWX.encode(valid_payload())

      mislabeled_message = String.replace(message, "Version: 1", "Ver: 1")

      assert SIWX.decode(mislabeled_message) == {:error, :invalid_message}
    end

    test "rejects empty or malformed field values on encode" do
      empty_address = Map.put(valid_payload(), :address, "")
      assert SIWX.encode(empty_address) == {:error, {:invalid_field, :address}}

      empty_statement = Map.put(valid_payload(), :statement, "")
      assert SIWX.encode(empty_statement) == {:error, {:invalid_field, :statement}}

      multiline_statement = Map.put(valid_payload(), :statement, "line one\nline two")
      assert SIWX.encode(multiline_statement) == {:error, {:invalid_field, :statement}}

      empty_uri = Map.put(valid_payload(), :uri, "")
      assert SIWX.encode(empty_uri) == {:error, {:invalid_field, :uri}}

      schemeless_uri = Map.put(valid_payload(), :uri, "not-a-uri")
      assert SIWX.encode(schemeless_uri) == {:error, {:invalid_field, :uri}}

      empty_nonce = Map.put(valid_payload(), :nonce, "")
      assert SIWX.encode(empty_nonce) == {:error, {:invalid_field, :nonce}}

      empty_issued_at = Map.put(valid_payload(), :issued_at, "")
      assert SIWX.encode(empty_issued_at) == {:error, {:invalid_field, :issued_at}}

      malformed_issued_at = Map.put(valid_payload(), :issued_at, "yesterday at noon")
      assert SIWX.encode(malformed_issued_at) == {:error, {:invalid_field, :issued_at}}
    end

    test "accepts decimal-string chain ids and rejects non-positive ones" do
      decimal_chain_id = Map.put(valid_payload(), :chain_id, "8453")
      assert {:ok, message} = SIWX.encode(decimal_chain_id)
      assert {:ok, decoded} = SIWX.decode(message)
      assert decoded.chain_id == "eip155:8453"

      zero_chain_id = Map.put(valid_payload(), :chain_id, 0)
      assert SIWX.encode(zero_chain_id) == {:error, {:invalid_field, :chain_id}}

      negative_chain_id = Map.put(valid_payload(), :chain_id, "-1")
      assert SIWX.encode(negative_chain_id) == {:error, {:invalid_field, :chain_id}}

      nil_chain_id = Map.put(valid_payload(), :chain_id, nil)
      assert SIWX.encode(nil_chain_id) == {:error, {:invalid_field, :chain_id}}
    end
  end

  describe "encode_header/1 and decode_header/1" do
    test "roundtrips a valid header payload" do
      payload = %{message: "sign-in message", signature: "0xabcdef"}

      assert {:ok, encoded_header} = SIWX.encode_header(payload)

      assert SIWX.decode_header(encoded_header) ==
               {:ok, %{"message" => "sign-in message", "signature" => "0xabcdef"}}
    end

    test "returns invalid payload for malformed encode payloads" do
      assert SIWX.encode_header(nil) == {:error, :invalid_payload}
      assert SIWX.encode_header(%{message: "only message"}) == {:error, :invalid_payload}
      assert SIWX.encode_header(%{message: "", signature: "0xabc"}) == {:error, :invalid_payload}
    end

    test "returns invalid_json when the payload cannot be JSON-encoded" do
      invalid_utf8 = <<0xFF, 0xFE>>

      assert SIWX.encode_header(%{message: invalid_utf8, signature: "0xabc"}) ==
               {:error, :invalid_json}
    end

    test "returns decode errors for malformed headers" do
      assert SIWX.decode_header("%%") == {:error, :invalid_base64}
      assert SIWX.decode_header("") == {:error, :invalid_base64}
      assert SIWX.decode_header(nil) == {:error, :invalid_base64}

      invalid_json = Base.encode64("{")
      assert SIWX.decode_header(invalid_json) == {:error, :invalid_json}

      not_map = Base.encode64("[]")
      assert SIWX.decode_header(not_map) == {:error, :invalid_json}

      missing_signature = Base.encode64(Jason.encode!(%{"message" => "ok"}))
      assert SIWX.decode_header(missing_signature) == {:error, :invalid_payload}
    end
  end

  defp valid_payload do
    %{
      domain: "example.com",
      address: "0x1111111111111111111111111111111111111111",
      statement: "Access purchased content",
      uri: "https://example.com/protected",
      version: "1",
      chain_id: "eip155:1",
      nonce: "abc12345",
      issued_at: "2026-02-16T12:00:00Z",
      expiration_time: "2026-02-16T13:00:00Z"
    }
  end
end
