defmodule X402.Facilitator.Auth.CDPTest do
  use ExUnit.Case, async: false

  alias X402.Facilitator.Auth
  alias X402.Facilitator.Auth.CDP

  import X402.TestAuthKeys

  doctest X402.Facilitator.Auth.CDP

  describe "facilitator_url/0" do
    test "returns the CDP x402 facilitator base URL" do
      assert CDP.facilitator_url() == "https://api.cdp.coinbase.com/platform/v2/x402"
    end
  end

  describe "new/1" do
    test "builds auth state from an Ed25519 secret" do
      assert {:ok, %CDP{api_key_id: "key-123", key_format: :ed25519}} =
               CDP.new(api_key_id: "key-123", api_key_secret: ed25519_secret())
    end

    test "builds auth state from an EC P-256 PEM secret" do
      assert {:ok, %CDP{api_key_id: "key-123", key_format: :ecdsa_p256}} =
               CDP.new(api_key_id: "key-123", api_key_secret: ec_p256_secret())
    end

    test "errors when the API key id is missing" do
      assert {:error, {:missing_credential, :api_key_id}} =
               CDP.new(api_key_id: nil, api_key_secret: ed25519_secret())
    end

    test "errors when the API key secret is missing" do
      assert {:error, {:missing_credential, :api_key_secret}} =
               CDP.new(api_key_id: "key-123", api_key_secret: nil)
    end

    test "errors on a secret that is not valid base64" do
      assert {:error, :invalid_secret_format} =
               CDP.new(api_key_id: "key-123", api_key_secret: "!!not-base64!!")
    end

    test "errors on a base64 secret of the wrong length" do
      too_short = Base.encode64(:binary.copy("x", 16))

      assert {:error, :invalid_ed25519_secret} =
               CDP.new(api_key_id: "key-123", api_key_secret: too_short)
    end

    test "errors on a malformed EC PEM secret" do
      broken_pem = "-----BEGIN EC PRIVATE KEY-----\nbm90IGEga2V5\n-----END EC PRIVATE KEY-----\n"

      assert {:error, :invalid_ec_private_key} =
               CDP.new(api_key_id: "key-123", api_key_secret: broken_pem)
    end

    test "errors on an EC PEM for a non-P-256 curve" do
      {pub, priv} = :crypto.generate_key(:ecdh, :secp384r1)

      der =
        <<48, 118, 2, 1, 1, 4, 48, priv::binary, 160, 10, 6, 8, 42, 134, 72, 206, 61, 3, 1, 8,
          161, 68, 3, 66, 0, pub::binary>>

      pem =
        "-----BEGIN EC PRIVATE KEY-----\n" <>
          Base.encode64(der, line_length: 64) <> "\n-----END EC PRIVATE KEY-----\n"

      assert {:error, :invalid_ec_private_key} =
               CDP.new(api_key_id: "key-123", api_key_secret: pem)
    end

    test "errors on an EC PEM whose private scalar is all zeros" do
      pem = ec_pem_with_scalar(<<0::size(32 * 8)>>)

      assert {:error, :invalid_ec_private_key} =
               CDP.new(api_key_id: "key-123", api_key_secret: pem)
    end

    test "errors on an EC PEM whose private scalar is wider than 32 bytes" do
      pem = ec_pem_with_scalar(<<1, 0::size(32 * 8)>>)

      assert {:error, :invalid_ec_private_key} =
               CDP.new(api_key_id: "key-123", api_key_secret: pem)
    end

    test "left-pads a short EC private scalar to 32 bytes and signs with it" do
      pem = ec_pem_with_scalar(<<0, 5>>)

      assert {:ok, %CDP{key_format: :ecdsa_p256, key_material: key_material} = auth} =
               CDP.new(api_key_id: "key-123", api_key_secret: pem)

      assert key_material == <<0::size(31 * 8), 5>>

      assert {:ok, [{"authorization", "Bearer " <> token} | _rest]} =
               Auth.headers(auth, %{method: :post, host: "h", path: "/verify"})

      [_header_part, _payload_part, signature_part] = String.split(token, ".")
      assert byte_size(Base.url_decode64!(signature_part, padding: false)) == 64
    end
  end

  describe "headers/2 with an Ed25519 key" do
    setup do
      {secret, public_key} = ed25519()
      {:ok, auth} = CDP.new(api_key_id: "key-123", api_key_secret: secret)
      {:ok, auth: auth, public_key: public_key}
    end

    test "returns authorization and correlation-context headers", %{auth: auth} do
      assert {:ok,
              [
                {"authorization", "Bearer " <> _token},
                {"correlation-context", context}
              ]} = Auth.headers(auth, %{method: :post, host: "h", path: "/verify"})

      assert String.starts_with?(context, "sdkLanguage=elixir,source=x402,sourceVersion=")
    end

    test "builds a valid JWT bound to the request method, host and path", %{auth: auth} do
      {:ok, headers} =
        Auth.headers(auth, %{
          method: :post,
          host: "api.cdp.coinbase.com",
          path: "/platform/v2/x402/verify"
        })

      {_, "Bearer " <> token} = hd(headers)

      [header_part, payload_part, signature_part] = String.split(token, ".")
      header = header_part |> Base.url_decode64!(padding: false) |> Jason.decode!()
      payload = payload_part |> Base.url_decode64!(padding: false) |> Jason.decode!()

      assert header["alg"] == "EdDSA"
      assert header["kid"] == "key-123"
      assert header["typ"] == "JWT"
      assert String.match?(header["nonce"], ~r/^[0-9a-f]{32}$/)
      assert payload["sub"] == "key-123"
      assert payload["iss"] == "cdp"
      assert payload["uris"] == ["POST api.cdp.coinbase.com/platform/v2/x402/verify"]

      now = System.os_time(:second)
      assert payload["iat"] in [now, now - 1]
      assert payload["nbf"] == payload["iat"]
      assert payload["exp"] == payload["iat"] + 120

      signature = Base.url_decode64!(signature_part, padding: false)
      assert byte_size(signature) == 64
    end

    test "signature verifies with the public key", %{auth: auth, public_key: public_key} do
      {:ok, headers} = Auth.headers(auth, %{method: :get, host: "h", path: "/supported"})
      {_, "Bearer " <> token} = hd(headers)
      [header_part, payload_part, signature_part] = String.split(token, ".")
      signing_input = header_part <> "." <> payload_part
      signature = Base.url_decode64!(signature_part, padding: false)

      assert :crypto.verify(:eddsa, :none, signing_input, signature, [public_key, :ed25519])
    end

    test "uses GET in the uris claim for get requests", %{auth: auth} do
      {:ok, headers} = Auth.headers(auth, %{method: :get, host: "h", path: "/supported"})
      {_, "Bearer " <> token} = hd(headers)
      [_header_part, payload_part, _signature_part] = String.split(token, ".")
      payload = payload_part |> Base.url_decode64!(padding: false) |> Jason.decode!()

      assert payload["uris"] == ["GET h/supported"]
    end
  end

  describe "headers/2 with an EC P-256 key" do
    setup do
      {secret, public_key} = ec_p256()
      {:ok, auth} = CDP.new(api_key_id: "key-123", api_key_secret: secret)
      {:ok, auth: auth, public_key: public_key}
    end

    test "uses the ES256 algorithm and a 64-byte raw signature", %{auth: auth} do
      {:ok, headers} = Auth.headers(auth, %{method: :post, host: "h", path: "/verify"})
      {_, "Bearer " <> token} = hd(headers)
      [header_part, _payload_part, signature_part] = String.split(token, ".")
      header = header_part |> Base.url_decode64!(padding: false) |> Jason.decode!()
      signature = Base.url_decode64!(signature_part, padding: false)

      assert header["alg"] == "ES256"
      assert byte_size(signature) == 64
    end

    test "signature verifies with the public key", %{auth: auth, public_key: public_key} do
      {:ok, headers} = Auth.headers(auth, %{method: :post, host: "h", path: "/verify"})
      {_, "Bearer " <> token} = hd(headers)
      [header_part, payload_part, signature_part] = String.split(token, ".")
      signing_input = header_part <> "." <> payload_part
      signature = Base.url_decode64!(signature_part, padding: false)

      der = X402.TestAuthKeys.es256_der(signature)

      assert :crypto.verify(:ecdsa, :sha256, signing_input, der, [public_key, :secp256r1])
    end

    test "signatures stay exactly 64 bytes across many signings", %{auth: auth} do
      # A DER signature component occasionally comes back shorter than 32
      # bytes (top byte zero, roughly 1 in 128 signatures); every such
      # component must be left-padded into the fixed 64-byte r || s form.
      # 1500 signatures make the short-component branch all but certain to
      # be exercised.
      for _index <- 1..1500 do
        {:ok, headers} = Auth.headers(auth, %{method: :post, host: "h", path: "/verify"})
        {_, "Bearer " <> token} = hd(headers)
        [_header_part, _payload_part, signature_part] = String.split(token, ".")
        assert byte_size(Base.url_decode64!(signature_part, padding: false)) == 64
      end
    end
  end

  # Builds an `EC PRIVATE KEY` PEM around an arbitrary private-scalar octet
  # string (a fresh P-256 public point keeps the structure valid), so tests
  # can exercise scalar normalization on shapes real keygens never emit.
  defp ec_pem_with_scalar(scalar) when is_binary(scalar) do
    {public_key, _private_key} = :crypto.generate_key(:ecdh, :secp256r1)

    body =
      <<2, 1, 1, 4, byte_size(scalar), scalar::binary, 160, 10, 6, 8, 42, 134, 72, 206, 61, 3, 1,
        7, 161, 68, 3, 66, 0, public_key::binary>>

    der = <<48, byte_size(body), body::binary>>

    "-----BEGIN EC PRIVATE KEY-----\n" <>
      Base.encode64(der, line_length: 64) <> "\n-----END EC PRIVATE KEY-----\n"
  end
end
