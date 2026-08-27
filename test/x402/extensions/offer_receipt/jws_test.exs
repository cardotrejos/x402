defmodule X402.Extensions.OfferReceipt.JWSTest do
  use ExUnit.Case, async: true

  alias X402.Extensions.OfferReceipt.JWS

  doctest X402.Extensions.OfferReceipt.JWS

  @kid "did:web:api.example.com#key-1"

  defp ed25519_pair, do: :crypto.generate_key(:eddsa, :ed25519)
  defp secp256k1_pair, do: :crypto.generate_key(:ecdh, :secp256k1)

  describe "canonicalize/1 (JCS, RFC 8785)" do
    test "sorts object keys and emits no whitespace" do
      assert {:ok, ~s({"a":1,"b":[2,3],"c":{"x":null}})} =
               JWS.canonicalize(%{"c" => %{"x" => nil}, "a" => 1, "b" => [2, 3]})
    end

    test "sorts keys by UTF-16 code units, not UTF-8 bytes" do
      # U+1D11E (surrogate pair D834 DD1E) sorts before U+FB04 in UTF-16,
      # but after it in UTF-8 byte order — RFC 8785 requires UTF-16 order.
      assert {:ok, ~s({"𝄞":2,"ﬄ":1})} = JWS.canonicalize(%{"ﬄ" => 1, "𝄞" => 2})
    end

    test "escapes strings minimally, per ECMAScript JSON.stringify" do
      assert {:ok, ~s({"s":"a\\"b\\\\c\\n\\t\\u0000"})} =
               JWS.canonicalize(%{"s" => "a\"b\\c\n\t" <> <<0>>})
    end

    test "serializes literals and integers" do
      assert {:ok, "[null,true,false,0,-42]"} = JWS.canonicalize([nil, true, false, 0, -42])
    end

    test "accepts atom keys and values as strings" do
      assert {:ok, ~s({"key":"value"})} = JWS.canonicalize(%{key: :value})
    end

    test "rejects floats as unsupported" do
      assert {:error, {:unsupported_json_value, 1.5}} = JWS.canonicalize(%{"x" => 1.5})
    end

    test "rejects non-JSON values" do
      assert {:error, {:unsupported_json_value, {:a, :b}}} = JWS.canonicalize(%{"x" => {:a, :b}})
    end
  end

  describe "sign/2 with EdDSA" do
    test "produces a three-part compact JWS with the spec header fields" do
      {_public, seed} = ed25519_pair()

      assert {:ok, jws} =
               JWS.sign(%{"version" => 1}, alg: "EdDSA", kid: @kid, key: seed)

      assert [header_b64, payload_b64, signature_b64] = String.split(jws, ".")

      assert {:ok, %{"alg" => "EdDSA", "kid" => @kid}} = JWS.peek_header(jws)
      assert Base.url_decode64!(header_b64, padding: false) == ~s({"alg":"EdDSA","kid":"#{@kid}"})
      assert Base.url_decode64!(payload_b64, padding: false) == ~s({"version":1})
      assert byte_size(Base.url_decode64!(signature_b64, padding: false)) == 64
    end

    test "round-trips through verify/3" do
      {public, seed} = ed25519_pair()
      payload = %{"version" => 1, "resourceUrl" => "https://api.example.com/data"}

      assert {:ok, jws} = JWS.sign(payload, alg: "EdDSA", kid: @kid, key: seed)

      assert {:ok, %{header: %{"alg" => "EdDSA", "kid" => @kid}, payload: ^payload}} =
               JWS.verify(jws, public)
    end

    test "rejects a wrong key" do
      {_public, seed} = ed25519_pair()
      {other_public, _other_seed} = ed25519_pair()

      assert {:ok, jws} = JWS.sign(%{"version" => 1}, alg: "EdDSA", kid: @kid, key: seed)
      assert {:error, :signature_mismatch} = JWS.verify(jws, other_public)
    end

    test "rejects an invalid seed size" do
      assert {:error, {:invalid_key, _message}} =
               JWS.sign(%{"version" => 1}, alg: "EdDSA", kid: @kid, key: <<1::128>>)
    end
  end

  describe "sign/2 with ES256K" do
    test "signs the JCS-canonicalized payload with a 64-byte low-S signature" do
      {public, private} = secp256k1_pair()

      assert {:ok, jws} =
               JWS.sign(%{"b" => 2, "a" => 1}, alg: "ES256K", kid: @kid, key: private)

      [_header, payload_b64, signature_b64] = String.split(jws, ".")
      assert Base.url_decode64!(payload_b64, padding: false) == ~s({"a":1,"b":2})

      # Low-S normalization: s must be in the lower half of the group order.
      n =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

      assert <<_r::unsigned-big-integer-size(256), s::unsigned-big-integer-size(256)>> =
               Base.url_decode64!(signature_b64, padding: false)

      assert s <= div(n, 2)
      assert {:ok, %{payload: %{"a" => 1, "b" => 2}}} = JWS.verify(jws, public)
    end

    test "accepts compressed and bare 64-byte public keys for verification" do
      {public, private} = secp256k1_pair()
      assert {:ok, jws} = JWS.sign(%{"version" => 1}, alg: "ES256K", kid: @kid, key: private)

      <<4, bare::binary-size(64)>> = public
      assert {:ok, _verified} = JWS.verify(jws, bare)

      compressed = compress_point(public)
      assert {:ok, _verified} = JWS.verify(jws, compressed)
    end

    test "rejects a tampered payload" do
      {public, private} = secp256k1_pair()

      assert {:ok, jws} =
               JWS.sign(%{"amount" => "10000", "version" => 1},
                 alg: "ES256K",
                 kid: @kid,
                 key: private
               )

      [header, _payload, signature] = String.split(jws, ".")
      forged_payload = Base.url_encode64(~s({"amount":"20000","version":1}), padding: false)
      forged = Enum.join([header, forged_payload, signature], ".")

      assert {:error, :signature_mismatch} = JWS.verify(forged, public)
    end

    test "rejects an invalid public key" do
      {_public, private} = secp256k1_pair()
      assert {:ok, jws} = JWS.sign(%{"version" => 1}, alg: "ES256K", kid: @kid, key: private)
      assert {:error, {:invalid_key, _message}} = JWS.verify(jws, <<1, 2, 3>>)
    end

    test "rejects an invalid private key size" do
      assert {:error, {:invalid_key, _message}} =
               JWS.sign(%{"version" => 1}, alg: "ES256K", kid: @kid, key: <<1::128>>)
    end
  end

  describe "verify/3 header requirements" do
    test "enforces the :algs allowlist" do
      {public, private} = secp256k1_pair()
      assert {:ok, jws} = JWS.sign(%{"version" => 1}, alg: "ES256K", kid: @kid, key: private)

      assert {:error, {:unsupported_algorithm, "ES256K"}} =
               JWS.verify(jws, public, algs: ["EdDSA"])
    end

    test "rejects a header without kid (§3.3)" do
      header = Base.url_encode64(~s({"alg":"EdDSA"}), padding: false)
      payload = Base.url_encode64(~s({"version":1}), padding: false)
      signature = Base.url_encode64(:crypto.strong_rand_bytes(64), padding: false)

      assert {:error, {:missing_header, "kid"}} =
               JWS.verify(Enum.join([header, payload, signature], "."), <<0::256>>)
    end

    test "rejects a header without alg" do
      header = Base.url_encode64(~s({"kid":"did:web:x"}), padding: false)
      payload = Base.url_encode64(~s({"version":1}), padding: false)
      signature = Base.url_encode64(<<0::512>>, padding: false)

      assert {:error, {:missing_header, "alg"}} =
               JWS.verify(Enum.join([header, payload, signature], "."), <<0::256>>)
    end

    test "rejects unknown algorithms in the header" do
      header = Base.url_encode64(~s({"alg":"none","kid":"did:web:x"}), padding: false)
      payload = Base.url_encode64(~s({"version":1}), padding: false)
      signature = Base.url_encode64(<<0::512>>, padding: false)

      assert {:error, {:unsupported_algorithm, "none"}} =
               JWS.verify(Enum.join([header, payload, signature], "."), <<0::256>>)
    end

    test "rejects malformed compact serializations" do
      assert {:error, :invalid_jws} = JWS.verify("only.two", <<0::256>>)
      assert {:error, :invalid_jws} = JWS.verify("a.b.c.d", <<0::256>>)
      assert {:error, :invalid_jws} = JWS.verify("!not-base64!.b.c", <<0::256>>)
    end
  end

  describe "peek_payload/1" do
    test "decodes the payload without verification" do
      {_public, seed} = ed25519_pair()
      payload = %{"version" => 1, "amount" => "10000"}

      assert {:ok, jws} = JWS.sign(payload, alg: "EdDSA", kid: @kid, key: seed)
      assert {:ok, ^payload} = JWS.peek_payload(jws)
    end

    test "rejects malformed input" do
      assert {:error, :invalid_jws} = JWS.peek_payload("nope")
      assert {:error, :invalid_jws} = JWS.peek_payload("a.!bad-base64!.c")
    end
  end

  # SEC1 point compression: prefix 02 for even Y, 03 for odd Y.
  defp compress_point(<<4, x::binary-size(32), y::unsigned-big-integer-size(256)>>) do
    prefix = if rem(y, 2) == 0, do: 2, else: 3
    <<prefix, x::binary>>
  end
end
