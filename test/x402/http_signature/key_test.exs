defmodule X402.HTTPSignature.KeyTest do
  use ExUnit.Case, async: true

  alias X402.HTTPSignature.Key
  alias X402.RFC9421Vectors, as: Vectors

  doctest X402.HTTPSignature.Key

  @algorithms %{
    "ed25519" => "test-key-ed25519",
    "ecdsa-p256-sha256" => "test-key-ecc-p256",
    "rsa-pss-sha512" => "test-key-rsa-pss"
  }

  defp decode(value), do: Base.url_decode64!(value, padding: false)

  describe "algorithms/0" do
    test "lists the supported RFC 9421 algorithms only" do
      assert Key.algorithms() == ["ed25519", "ecdsa-p256-sha256", "rsa-pss-sha512"]
    end
  end

  describe "generate/1, sign/2 and verify/3" do
    for alg <- Map.keys(@algorithms) do
      @alg alg

      test "#{alg}: fresh keys sign and verify, and reject other data or keys" do
        assert {:ok, key} = Key.generate(@alg)
        assert key.alg == @alg
        assert key.kid == Key.thumbprint(key)
        refute is_nil(key.private)

        # ECDSA r/s values start with a high bit roughly half the time; a
        # handful of signatures exercises both DER integer encodings.
        for _ <- 1..8 do
          assert {:ok, signature} = Key.sign(key, "payload")
          assert Key.verify(key, "payload", signature)
          refute Key.verify(key, "other", signature)
          refute Key.verify(key, "payload", :binary.copy(<<0>>, byte_size(signature)))
          refute Key.verify(key, "payload", "short")
        end

        assert {:ok, other} = Key.generate(@alg)
        assert {:ok, signature} = Key.sign(key, "payload")
        refute Key.verify(other, "payload", signature)
      end

      test "#{alg}: the public JWK roundtrips and carries no private material" do
        {:ok, key} = Key.generate(@alg)
        jwk = Key.to_jwk(key)

        assert jwk["alg"] == @alg
        assert jwk["use"] == "sig"
        assert jwk["kid"] == key.kid
        refute Map.has_key?(jwk, "d")

        assert {:ok, public} = Key.from_jwk(jwk)
        assert public.public == key.public
        assert public.kid == key.kid
        assert is_nil(public.private)
        assert {:error, :missing_private_key} = Key.sign(public, "x")
      end
    end

    test "raw signature sizes follow RFC 9421 §3.3" do
      {:ok, ed} = Key.generate("ed25519")
      {:ok, ec} = Key.generate("ecdsa-p256-sha256")
      {:ok, rsa} = Key.generate("rsa-pss-sha512")

      assert {:ok, <<_::binary-64>>} = Key.sign(ed, "x")
      assert {:ok, <<_::binary-64>>} = Key.sign(ec, "x")
      assert {:ok, <<_::binary-256>>} = Key.sign(rsa, "x")
    end

    test "unsupported algorithms are rejected" do
      assert {:error, {:unsupported_algorithm, "hmac-sha256"}} = Key.generate("hmac-sha256")

      assert {:error, {:unsupported_algorithm, "rsa-v1_5-sha256"}} =
               Key.new(alg: "rsa-v1_5-sha256", public_key: "x")
    end
  end

  describe "RFC 9421 Appendix B keys" do
    for {alg, name} <- @algorithms do
      @alg alg
      @name name

      test "#{name}: JWK, PEM and raw forms agree" do
        assert {:ok, from_jwk} = Key.from_jwk(Vectors.public_jwks()[@name])

        assert {:ok, from_pem} =
                 Key.new(alg: @alg, public_key: Vectors.public_pems()[@name], kid: @name)

        assert {:ok, from_raw} = Key.new(alg: @alg, public_key: from_jwk.public, kid: @name)

        assert from_jwk.alg == @alg
        assert from_jwk.kid == @name
        assert from_jwk.public == from_pem.public
        assert from_jwk.public == from_raw.public
        assert is_nil(from_jwk.private)
      end

      test "#{name}: the private JWK derives the published public key and signs" do
        assert {:ok, private} = Key.from_jwk(Vectors.private_jwks()[@name])
        assert {:ok, public} = Key.from_jwk(Vectors.public_jwks()[@name])
        assert private.public == public.public

        assert {:ok, derived} = Key.new(alg: @alg, private_key: private.private)
        assert derived.public == public.public

        assert {:ok, signature} = Key.sign(private, "data")
        assert Key.verify(public, "data", signature)
      end
    end

    test "thumbprints match an independent RFC 7638 computation" do
      for {_alg, name} <- @algorithms do
        jwk = Vectors.public_jwks()[name]
        {:ok, key} = Key.from_jwk(jwk)

        members =
          jwk
          |> Map.take(["kty", "crv", "x", "y", "n", "e"])
          |> Enum.sort()
          |> Enum.map_join(",", fn {k, v} -> ~s("#{k}":"#{v}") end)

        expected = Base.url_encode64(:crypto.hash(:sha256, "{" <> members <> "}"), padding: false)
        assert Key.thumbprint(key) == expected, name
      end
    end

    test "Ed25519 seed with appended public key is accepted" do
      seed = decode(Vectors.private_jwks()["test-key-ed25519"]["d"])
      public = decode(Vectors.public_jwks()["test-key-ed25519"]["x"])

      assert {:ok, key} = Key.new(alg: "ed25519", private_key: seed <> public)
      assert key.public == public
      assert key.private == seed
    end
  end

  describe "new/1 with Erlang key records and PEMs" do
    test "accepts :public_key records" do
      {:ok, ed} = Key.generate("ed25519")
      {:ok, ec} = Key.generate("ecdsa-p256-sha256")
      {:ok, rsa} = Key.generate("rsa-pss-sha512")
      [e, n] = rsa.public

      assert {:ok, %Key{public: public}} =
               Key.new(
                 alg: "ed25519",
                 public_key: {{:ECPoint, ed.public}, {:namedCurve, {1, 3, 101, 112}}}
               )

      assert public == ed.public

      assert {:ok, %Key{public: public}} =
               Key.new(
                 alg: "ecdsa-p256-sha256",
                 public_key: {{:ECPoint, ec.public}, {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}}
               )

      assert public == ec.public

      assert {:ok, %Key{public: [^e, ^n]}} =
               Key.new(
                 alg: "rsa-pss-sha512",
                 public_key:
                   {:RSAPublicKey, :binary.decode_unsigned(n), :binary.decode_unsigned(e)}
               )

      assert {:ok, %Key{public: [^e, ^n]}} =
               Key.new(
                 alg: "rsa-pss-sha512",
                 public_key: [:binary.decode_unsigned(e), :binary.decode_unsigned(n)]
               )
    end

    test "accepts private PEMs and derives the public key from them" do
      {:ok, ed} = Key.generate("ed25519")
      {:ok, ec} = Key.generate("ecdsa-p256-sha256")
      {:ok, rsa} = Key.generate("rsa-pss-sha512")
      [e, n, d] = rsa.private

      ed_entry =
        {:ECPrivateKey, 1, ed.private, {:namedCurve, {1, 3, 101, 112}}, ed.public, :asn1_NOVALUE}

      ec_entry =
        {:ECPrivateKey, 1, ec.private, {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}, ec.public,
         :asn1_NOVALUE}

      rsa_entry =
        {:RSAPrivateKey, :"two-prime", :binary.decode_unsigned(n), :binary.decode_unsigned(e),
         :binary.decode_unsigned(d), 3, 5, 7, 11, 13, :asn1_NOVALUE}

      for {alg, entry, expected} <- [
            {"ed25519", ed_entry, ed},
            {"ecdsa-p256-sha256", ec_entry, ec}
          ] do
        pem = :public_key.pem_encode([:public_key.pem_entry_encode(:ECPrivateKey, entry)])

        assert {:ok, key} = Key.new(alg: alg, private_key: pem), alg
        assert key.private == expected.private
        assert key.public == expected.public

        # A private PEM handed as the public key still yields the public part.
        assert {:ok, %Key{public: public, private: nil}} = Key.new(alg: alg, public_key: pem)
        assert public == expected.public
      end

      assert {:ok, key} = Key.new(alg: "rsa-pss-sha512", private_key: rsa_entry)
      assert key.private == [e, n, d]
      assert key.public == [e, n]

      assert {:ok, key} =
               Key.new(
                 alg: "rsa-pss-sha512",
                 private_key: [
                   :binary.decode_unsigned(e),
                   :binary.decode_unsigned(n),
                   :binary.decode_unsigned(d)
                 ]
               )

      assert key.private == [e, n, d]
    end

    test "accepts JWK maps as key material" do
      jwk = Vectors.private_jwks()["test-key-ecc-p256"]
      assert {:ok, key} = Key.new(alg: "ecdsa-p256-sha256", private_key: jwk, kid: "mine")
      assert key.kid == "mine"
      refute is_nil(key.private)

      assert {:ok, public} = Key.new(alg: "ecdsa-p256-sha256", public_key: Map.delete(jwk, "d"))
      assert public.public == key.public

      # The JWK must match the declared algorithm and carry the right part.
      assert {:error, :invalid_key} = Key.new(alg: "ed25519", private_key: jwk)

      assert {:error, :invalid_key} =
               Key.new(alg: "ecdsa-p256-sha256", private_key: Map.delete(jwk, "d"))

      assert {:error, :invalid_key} = Key.new(alg: "ed25519", public_key: Map.delete(jwk, "d"))
    end

    test "rejects malformed material" do
      assert {:error, :invalid_key} = Key.new(alg: "ed25519")
      assert {:error, :invalid_key} = Key.new(alg: "ed25519", public_key: "short")
      assert {:error, :invalid_key} = Key.new(alg: "ed25519", private_key: "short")

      assert {:error, :invalid_key} =
               Key.new(alg: "ecdsa-p256-sha256", public_key: :binary.copy(<<2>>, 65))

      assert {:error, :invalid_key} = Key.new(alg: "rsa-pss-sha512", public_key: ["e"])
      assert {:error, :invalid_key} = Key.new(alg: "rsa-pss-sha512", private_key: ["e", "n"])

      assert {:error, :invalid_key} =
               Key.new(alg: "ed25519", public_key: "-----BEGIN PUBLIC KEY-----\ngarbage\n")

      assert {:error, :invalid_key} = Key.new(alg: "ed25519", public_key: 42)
      assert {:error, :invalid_key} = Key.new(alg: "ed25519", public_key: {:RSAPublicKey, 1, 2})

      # A PEM of the wrong key type for the algorithm.
      assert {:error, :invalid_key} =
               Key.new(alg: "ed25519", public_key: Vectors.public_pems()["test-key-ecc-p256"])

      assert {:error, :invalid_key} = Key.new(alg: "ed25519", public_key: "x", kid: 1)
    end
  end

  describe "from_jwk/1" do
    test "rejects malformed and unsupported JWKs" do
      assert {:error, :invalid_key} =
               Key.from_jwk(%{"kty" => "OKP", "crv" => "Ed25519", "x" => "!!"})

      assert {:error, :invalid_key} =
               Key.from_jwk(%{"kty" => "OKP", "crv" => "Ed25519", "x" => "AQID"})

      assert {:error, :invalid_key} =
               Key.from_jwk(%{"kty" => "OKP", "crv" => "Ed25519", "x" => 1})

      assert {:error, :invalid_key} =
               Key.from_jwk(%{"kty" => "EC", "crv" => "P-256", "x" => "AQ", "y" => "!"})

      assert {:error, :invalid_key} =
               Key.from_jwk(%{"kty" => "RSA", "n" => "AQ", "e" => "AQAB", "d" => "!"})

      ed = Vectors.public_jwks()["test-key-ed25519"]
      assert {:error, :invalid_key} = Key.from_jwk(Map.put(ed, "d", "!!"))
      assert {:error, :invalid_key} = Key.from_jwk(Map.put(ed, "d", "AQID"))

      assert {:error, {:unsupported_algorithm, "OKP"}} =
               Key.from_jwk(%{"kty" => "OKP", "crv" => "X25519", "x" => "AQ"})

      assert {:error, {:unsupported_algorithm, "EC"}} =
               Key.from_jwk(%{"kty" => "EC", "crv" => "P-384", "x" => "AQ", "y" => "AQ"})

      assert {:error, :invalid_key} = Key.from_jwk(%{"x" => "AQ"})
      assert {:error, :invalid_key} = Key.from_jwk("not a map")
    end

    test "kid is optional and defaults to the thumbprint" do
      jwk = Map.delete(Vectors.public_jwks()["test-key-ecc-p256"], "kid")
      assert {:ok, key} = Key.from_jwk(jwk)
      assert key.kid == Key.thumbprint(key)
      assert Key.to_jwk(key)["kid"] == key.kid
    end
  end
end
