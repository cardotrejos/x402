defmodule X402.HTTPSignatureTest do
  use ExUnit.Case, async: true

  alias X402.HTTPSignature
  alias X402.HTTPSignature.Key
  alias X402.RFC9421Vectors, as: Vectors

  doctest X402.HTTPSignature

  defp public_key(name) do
    {:ok, key} = Key.from_jwk(Vectors.public_jwks()[name])
    key
  end

  defp private_key(name) do
    {:ok, key} = Key.from_jwk(Vectors.private_jwks()[name])
    key
  end

  defp signed(message, signature_input, signature) do
    Map.update!(
      message,
      :headers,
      &(&1 ++ [{"Signature-Input", signature_input}, {"Signature", signature}])
    )
  end

  defp generated(alg) do
    {:ok, key} = Key.generate(alg)
    key
  end

  defp request(overrides \\ []) do
    Map.merge(
      %{
        method: "GET",
        url: "https://api.example.com/premium?limit=10&x=1",
        headers: [{"payment-signature", "cGF5bG9hZA"}, {"x-extra", "ignored"}]
      },
      Map.new(overrides)
    )
  end

  describe "RFC 9421 Appendix B known-answer vectors" do
    for vector <- Vectors.vectors() do
      @vector_name vector.name

      test "#{vector.name}: signature base is reproduced byte for byte" do
        vector = Enum.find(Vectors.vectors(), &(&1.name == @vector_name))

        assert {:ok, base} =
                 HTTPSignature.signature_base(vector.message, vector.components, vector.params)

        assert base == vector.base
      end

      test "#{vector.name}: the RFC signature verifies with the RFC public key" do
        vector = Enum.find(Vectors.vectors(), &(&1.name == @vector_name))
        message = signed(vector.message, vector.signature_input, vector.signature)

        assert {:ok, verified} = HTTPSignature.verify(message, keys: [public_key(vector.key)])
        assert verified.label == vector.label
        assert verified.key.kid == vector.key
        assert verified.params == Map.new(vector.params)
        assert {:ok, components} = HTTPSignature.normalize_components(vector.components)
        assert verified.components == components
      end

      test "#{vector.name}: signing with the RFC private key reproduces the wire headers" do
        vector = Enum.find(Vectors.vectors(), &(&1.name == @vector_name))
        params = Map.new(vector.params)

        opts =
          [label: vector.label, components: vector.components, created: params["created"]] ++
            Enum.reject([nonce: params["nonce"], tag: params["tag"]], &is_nil(elem(&1, 1)))

        assert {:ok, headers} = HTTPSignature.sign(vector.message, private_key(vector.key), opts)
        expected_input = vector.signature_input
        assert [{"signature-input", ^expected_input}, {"signature", signature}] = headers

        # RSA-PSS and ECDSA are randomized: a fresh signature differs from
        # the RFC's but must verify with the RFC public key. Ed25519 is
        # deterministic and must match byte for byte.
        message = signed(vector.message, vector.signature_input, signature)
        assert {:ok, _verified} = HTTPSignature.verify(message, keys: [public_key(vector.key)])
        if vector.deterministic, do: assert(signature == vector.signature)
      end
    end

    test "PEM public keys verify the same vectors" do
      for vector <- Vectors.vectors() do
        pem = Vectors.public_pems()[vector.key]

        assert {:ok, key} =
                 Key.new(alg: public_key(vector.key).alg, public_key: pem, kid: vector.key)

        message = signed(vector.message, vector.signature_input, vector.signature)
        assert {:ok, _verified} = HTTPSignature.verify(message, keys: [key]), vector.name
      end
    end

    test "B.2.4 response signature cannot be verified as a request" do
      vector = Enum.find(Vectors.vectors(), &(&1.label == "sig-b24"))
      message = vector.message |> Map.delete(:status) |> Map.put(:method, "GET")
      message = signed(message, vector.signature_input, vector.signature)

      assert {:error, {:invalid_component, ~S|"@status"|}} =
               HTTPSignature.verify(message, keys: [public_key(vector.key)])
    end
  end

  describe "RFC 9421 Appendix B.4 transformations" do
    setup do
      %{key: public_key("test-key-ed25519"), transformations: Vectors.transformations()}
    end

    test "the original message verifies and matches the RFC signature base", %{
      key: key,
      transformations: transformations
    } do
      assert {:ok, base} =
               HTTPSignature.signature_base(
                 transformations.original,
                 ~w(@method @path @authority accept),
                 [{"created", 1_618_884_473}, {"keyid", "test-key-ed25519"}]
               )

      assert base == transformations.base

      assert {:ok, %{label: "transform"}} =
               HTTPSignature.verify(transformations.original, keys: [key])
    end

    test "allowed transformations keep the signature valid", %{
      key: key,
      transformations: transformations
    } do
      for {name, message} <- transformations.valid do
        assert {:ok, _verified} = HTTPSignature.verify(message, keys: [key]), name
      end
    end

    test "covered changes invalidate the signature", %{key: key, transformations: transformations} do
      for {name, message} <- transformations.invalid do
        assert {:error, :invalid_signature} = HTTPSignature.verify(message, keys: [key]), name
      end
    end
  end

  describe "sign/3 and verify/2 roundtrip" do
    for alg <- Key.algorithms() do
      @alg alg

      test "#{alg}: request with default components" do
        key = generated(@alg)
        message = request()

        assert {:ok, [{"signature-input", input}, {"signature", _}] = headers} =
                 HTTPSignature.sign(message, key)

        assert input =~ ~S|sig1=("@method" "@authority" "@path" "payment-signature");created=|
        assert input =~ ~s|;keyid="#{key.kid}"|

        signed = %{message | headers: message.headers ++ headers}
        assert {:ok, verified} = HTTPSignature.verify(signed, keys: [key])
        assert verified.key.public == key.public
        assert verified.params["keyid"] == key.kid
        assert is_integer(verified.params["created"])
      end

      test "#{alg}: response bound to its request through ;req" do
        key = generated(@alg)
        request = request()

        response = %{
          status: 402,
          headers: [{"payment-required", "eyJ4NDAyIjoyfQ"}],
          request: request
        }

        assert {:ok, headers} =
                 HTTPSignature.sign(response, key,
                   tag: "x402-response",
                   ttl: 60,
                   alg: true,
                   nonce: true
                 )

        [{"signature-input", input}, _signature] = headers

        assert input =~
                 ~S|sig1=("@status" "payment-required" "@authority";req "@path";req);created=|

        assert input =~ ~s|;alg="#{@alg}";nonce="|
        assert input =~ ~S|;tag="x402-response"|

        signed = %{response | headers: response.headers ++ headers}

        assert {:ok, verified} =
                 HTTPSignature.verify(signed,
                   keys: [key],
                   tag: "x402-response",
                   required_components: ["@status", {"@authority", req: true}],
                   required_params: ["expires", "nonce"]
                 )

        assert verified.params["expires"] == verified.params["created"] + 60

        # The same response answering a different request fails.
        other = %{signed | request: %{request | url: "https://api.example.com/other"}}
        assert {:error, :invalid_signature} = HTTPSignature.verify(other, keys: [key])
      end
    end

    test "public-only keys cannot sign" do
      key = generated("ed25519")
      assert {:error, :missing_private_key} = HTTPSignature.sign(request(), %{key | private: nil})
    end

    test "custom components, keyid override and omitted created" do
      key = generated("ed25519")

      assert {:ok, [{"signature-input", input}, _]} =
               HTTPSignature.sign(request(), key,
                 components: [
                   "@target-uri",
                   "@scheme",
                   "@request-target",
                   "@query",
                   {"@query-param", name: "limit"}
                 ],
                 created: false,
                 keyid: "custom",
                 label: "x402"
               )

      assert input ==
               ~S|x402=("@target-uri" "@scheme" "@request-target" "@query" "@query-param";name="limit");keyid="custom"|

      assert {:ok, base} =
               HTTPSignature.signature_base(
                 request(),
                 [
                   "@target-uri",
                   "@scheme",
                   "@request-target",
                   "@query",
                   {"@query-param", name: "limit"}
                 ],
                 []
               )

      assert base ==
               Enum.join(
                 [
                   ~S|"@target-uri": https://api.example.com/premium?limit=10&x=1|,
                   ~S|"@scheme": https|,
                   ~S|"@request-target": /premium?limit=10&x=1|,
                   ~S|"@query": ?limit=10&x=1|,
                   ~S|"@query-param";name="limit": 10|,
                   ~S|"@signature-params": ("@target-uri" "@scheme" "@request-target" "@query" "@query-param";name="limit")|
                 ],
                 "\n"
               )
    end

    test "keyid: false omits the parameter and a single key still verifies" do
      key = generated("ed25519")
      assert {:ok, headers} = HTTPSignature.sign(request(), key, keyid: false)
      signed = request(headers: request().headers ++ headers)

      assert {:ok, _verified} = HTTPSignature.verify(signed, keys: key)
      assert {:error, :unknown_key} = HTTPSignature.verify(signed, keys: [key])
    end

    test "sign errors surface component problems" do
      key = generated("ed25519")

      assert {:error, {:missing_component, ~S|"x-missing"|}} =
               HTTPSignature.sign(request(), key, components: ["x-missing"])

      assert {:error, {:invalid_component, ":bogus"}} =
               HTTPSignature.sign(request(), key, components: [:bogus])

      assert {:error, {:unknown_component, ~S|"@nope"|}} =
               HTTPSignature.sign(request(), key, components: ["@nope"])

      assert {:error, {:invalid_component, ~S|"@status"|}} =
               HTTPSignature.sign(request(), key, components: ["@status"])

      assert {:error, {:invalid_component, ~S|"@authority";req|}} =
               HTTPSignature.sign(request(), key, components: [{"@authority", req: true}])

      assert {:error, {:invalid_component, ~S|"@query-param"|}} =
               HTTPSignature.sign(request(), key, components: ["@query-param"])

      assert {:error, {:missing_component, ~S|"@query-param";name="nope"|}} =
               HTTPSignature.sign(request(), key, components: [{"@query-param", name: "nope"}])

      assert {:error, {:unsupported_component_parameter, "sf"}} =
               HTTPSignature.sign(request(headers: [{"date", "x"}]), key,
                 components: [{"date", sf: true}]
               )
    end

    test "response components need the request for ;req and reject request-only ones without it" do
      key = generated("ed25519")
      response = %{status: 200, headers: []}

      assert {:error, {:missing_component, ~S|"@authority";req|}} =
               HTTPSignature.sign(response, key, components: [{"@authority", req: true}])

      assert {:error, {:invalid_component, ~S|"@path"|}} =
               HTTPSignature.sign(Map.put(response, :request, request()), key,
                 components: ["@path"]
               )

      assert {:error, {:missing_component, ~S|"x-nope";req|}} =
               HTTPSignature.sign(Map.put(response, :request, request()), key,
                 components: [{"x-nope", req: true}]
               )
    end

    test "messages without method, absolute URL or status cannot derive those components" do
      key = generated("ed25519")

      assert {:error, {:missing_component, ~S|"@method"|}} =
               HTTPSignature.sign(%{headers: []}, key)

      assert {:error, {:missing_component, ~S|"@method"|}} =
               HTTPSignature.sign(%{method: "", url: "https://e.com/"}, key)

      assert {:error, {:missing_component, ~S|"@authority"|}} =
               HTTPSignature.sign(%{method: "GET", url: "/relative"}, key)

      assert {:error, {:missing_component, ~S|"@status"|}} =
               HTTPSignature.sign(%{status: "200", headers: []}, key)

      assert {:error, {:missing_component, ~S|"@status"|}} =
               HTTPSignature.sign(%{status: 999}, key)
    end

    test "header values are canonicalized: whitespace trimmed, obs-fold collapsed, instances joined" do
      message =
        request(
          headers: [
            {"X-Multi", "  first  "},
            {"x-multi", "second\r\n\tcontinued "},
            {"X-Obs", "a\n b"}
          ]
        )

      assert {:ok, base} = HTTPSignature.signature_base(message, ["x-multi", "x-obs"], [])
      assert base =~ ~S|"x-multi": first, second continued|
      assert base =~ ~S|"x-obs": a b|
    end

    test "header maps are accepted, and non-ASCII values are rejected" do
      message = request(headers: %{"Accept" => ["a", "b"], "X-One" => "1"})
      assert {:ok, base} = HTTPSignature.signature_base(message, ["accept", "x-one"], [])
      assert base =~ ~S|"accept": a, b|

      message = request(headers: [{"x-utf", "héllo"}])
      assert {:error, :non_ascii} = HTTPSignature.signature_base(message, ["x-utf"], [])

      message = request(headers: [{"x-crlf", "a\r\nb"}])

      assert {:error, {:invalid_field_value, "x-crlf"}} =
               HTTPSignature.signature_base(message, ["x-crlf"], [])
    end

    test "@authority lowercases the host and drops default ports" do
      for {url, authority} <- [
            {"HTTPS://API.Example.com:443/p", "api.example.com"},
            {"http://example.com:80/p", "example.com"},
            {"https://example.com:8443/p", "example.com:8443"},
            {"http://example.com:8080/p", "example.com:8080"}
          ] do
        assert {:ok, base} = HTTPSignature.signature_base(request(url: url), ["@authority"], [])
        assert base =~ ~s|"@authority": #{authority}\n|, url
      end
    end

    test "@path and @query handle empty and absent values" do
      assert {:ok, base} =
               HTTPSignature.signature_base(
                 request(url: "https://example.com"),
                 ["@path", "@query"],
                 []
               )

      assert base =~ ~S|"@path": /|
      assert base =~ ~S|"@query": ?|

      assert {:ok, base} =
               HTTPSignature.signature_base(
                 request(url: "https://example.com/a?"),
                 ["@query"],
                 []
               )

      assert base =~ ~S|"@query": ?|
    end

    test "@query-param decodes and re-encodes values (RFC 9421 §2.2.8)" do
      url =
        "https://example.com/path?param=value&foo=bar&baz=bat%2Dman&qux=&var=this%20is%20a%20big%0Amultiline%20value"

      assert {:ok, base} =
               HTTPSignature.signature_base(
                 request(url: url),
                 [
                   {"@query-param", name: "baz"},
                   {"@query-param", name: "qux"},
                   {"@query-param", name: "param"},
                   {"@query-param", name: "var"}
                 ],
                 []
               )

      assert base =~ ~S|"@query-param";name="baz": bat-man|
      assert base =~ ~S|"@query-param";name="qux": |
      assert base =~ ~S|"@query-param";name="param": value|
      assert base =~ ~S|"@query-param";name="var": this%20is%20a%20big%0Amultiline%20value|

      # Repeated parameters are ambiguous (§2.2.8) and refused.
      assert {:error, {:duplicate_component, ~S|"@query-param";name="a"|}} =
               HTTPSignature.signature_base(
                 request(url: "https://e.com/?a=1&a=2"),
                 [{"@query-param", name: "a"}],
                 []
               )
    end

    test "the method is upcased and atoms are accepted" do
      assert {:ok, base} = HTTPSignature.signature_base(request(method: :post), ["@method"], [])
      assert base =~ ~S|"@method": POST|
    end
  end

  describe "verify/2 policy" do
    setup do
      key = generated("ed25519")

      {:ok, headers} =
        HTTPSignature.sign(request(), key, created: 1_700_000_000, ttl: 300, tag: "web-bot-auth")

      %{key: key, message: request(headers: request().headers ++ headers)}
    end

    test "requires covered components and parameters the caller demands", %{
      key: key,
      message: message
    } do
      assert {:error, {:missing_component, ~S|"content-digest"|}} =
               HTTPSignature.verify(message,
                 keys: [key],
                 required_components: ["content-digest"],
                 now: 1_700_000_001
               )

      assert {:error, {:missing_parameter, "nonce"}} =
               HTTPSignature.verify(message,
                 keys: [key],
                 required_params: ["nonce"],
                 now: 1_700_000_001
               )

      assert {:error, {:invalid_component, ":bogus"}} =
               HTTPSignature.verify(message,
                 keys: [key],
                 required_components: [:bogus],
                 now: 1_700_000_001
               )

      assert {:ok, _verified} =
               HTTPSignature.verify(message,
                 keys: [key],
                 required_components: ["@method", "@authority", "@path", "payment-signature"],
                 required_params: ["created", "expires", "tag"],
                 now: 1_700_000_001
               )
    end

    test "enforces expires, created and max_age with clock skew", %{key: key, message: message} do
      assert {:ok, _} = HTTPSignature.verify(message, keys: [key], now: 1_700_000_300)

      assert {:error, :signature_expired} =
               HTTPSignature.verify(message, keys: [key], now: 1_700_000_301)

      assert {:ok, _} =
               HTTPSignature.verify(message, keys: [key], now: 1_700_000_301, clock_skew: 5)

      assert {:error, :signature_not_yet_valid} =
               HTTPSignature.verify(message, keys: [key], now: 1_699_999_999)

      assert {:ok, _} =
               HTTPSignature.verify(message, keys: [key], now: 1_699_999_999, clock_skew: 1)

      assert {:error, :signature_too_old} =
               HTTPSignature.verify(message, keys: [key], now: 1_700_000_061, max_age: 60)

      assert {:ok, _} =
               HTTPSignature.verify(message,
                 keys: [key],
                 now: 1_700_000_061,
                 max_age: 60,
                 clock_skew: 1
               )
    end

    test "max_age demands a created parameter", %{key: key} do
      {:ok, headers} = HTTPSignature.sign(request(), key, created: false)
      message = request(headers: request().headers ++ headers)

      assert {:ok, _} = HTTPSignature.verify(message, keys: [key])

      assert {:error, {:missing_parameter, "created"}} =
               HTTPSignature.verify(message, keys: [key], max_age: 60)
    end

    test "selects by label and tag, refusing ambiguity", %{key: key, message: message} do
      other = generated("ecdsa-p256-sha256")

      {:ok, extra} =
        HTTPSignature.sign(message, other, label: "proxy", created: 1_700_000_000, tag: "proxy")

      headers = HTTPSignature.merge_headers([message.headers, extra])
      message = request(headers: request().headers ++ headers)

      assert {:error, :ambiguous_signature} =
               HTTPSignature.verify(message, keys: [key, other], now: 1_700_000_001)

      assert {:ok, %{label: "sig1"}} =
               HTTPSignature.verify(message,
                 keys: [key, other],
                 label: "sig1",
                 now: 1_700_000_001
               )

      assert {:ok, %{label: "proxy"}} =
               HTTPSignature.verify(message, keys: [key, other], tag: "proxy", now: 1_700_000_001)

      assert {:error, :signature_not_found} =
               HTTPSignature.verify(message, keys: [key, other], tag: "other", now: 1_700_000_001)

      assert {:error, :signature_not_found} =
               HTTPSignature.verify(message,
                 keys: [key, other],
                 label: "sig1",
                 tag: "proxy",
                 now: 1_700_000_001
               )
    end

    test "the key is resolved through the caller's keys, never from the signature alone", %{
      key: key,
      message: message
    } do
      now = [now: 1_700_000_001]

      assert {:error, :unknown_key} = HTTPSignature.verify(message, [keys: []] ++ now)

      assert {:error, :unknown_key} =
               HTTPSignature.verify(message, [keys: generated("ed25519")] ++ now)

      assert {:error, :unknown_key} =
               HTTPSignature.verify(message, [keys: fn _keyid -> nil end] ++ now)

      assert {:error, :unknown_key} =
               HTTPSignature.verify(message, [keys: fn _keyid -> :error end] ++ now)

      assert {:error, :unknown_key} = HTTPSignature.verify(message, [keys: :not_keys] ++ now)

      assert {:error, :invalid_key} =
               HTTPSignature.verify(
                 message,
                 [keys: fn _keyid -> %{"kty" => "OKP", "crv" => "Ed25519", "x" => "!"} end] ++ now
               )

      lookup = fn keyid ->
        assert keyid == key.kid
        {:ok, Key.to_jwk(key)}
      end

      assert {:ok, %{key: %Key{private: nil}}} =
               HTTPSignature.verify(message, [keys: lookup] ++ now)

      assert {:ok, _} = HTTPSignature.verify(message, [keys: fn _keyid -> {:ok, key} end] ++ now)
      assert {:ok, _} = HTTPSignature.verify(message, [keys: fn _keyid -> key end] ++ now)
    end

    test "the algorithm allow-list and alg parameter are enforced", %{key: key, message: message} do
      assert {:error, {:unsupported_algorithm, "ed25519"}} =
               HTTPSignature.verify(message,
                 keys: [key],
                 algorithms: ["rsa-pss-sha512"],
                 now: 1_700_000_001
               )

      {:ok, headers} = HTTPSignature.sign(request(), key, alg: true, created: 1_700_000_000)
      [{"signature-input", input}, signature] = headers
      lying = String.replace(input, ~S|alg="ed25519"|, ~S|alg="ecdsa-p256-sha256"|)
      message = request(headers: request().headers ++ [{"signature-input", lying}, signature])

      assert {:error, :algorithm_mismatch} =
               HTTPSignature.verify(message, keys: [key], now: 1_700_000_001)
    end

    test "tampering with covered components or the signature is detected", %{
      key: key,
      message: message
    } do
      now = [now: 1_700_000_001]

      assert {:error, :invalid_signature} =
               HTTPSignature.verify(
                 %{message | url: "https://api.example.com/other"},
                 [keys: [key]] ++ now
               )

      tampered =
        List.keyreplace(message.headers, "payment-signature", 0, {"payment-signature", "b3RoZXI"})

      assert {:error, :invalid_signature} =
               HTTPSignature.verify(%{message | headers: tampered}, [keys: [key]] ++ now)

      [{"signature-input", input}, {"signature", signature}] = Enum.take(message.headers, -2)
      forged = String.replace(input, "created=1700000000", "created=1700000001")

      assert {:error, :invalid_signature} =
               HTTPSignature.verify(
                 request(
                   headers:
                     request().headers ++ [{"signature-input", forged}, {"signature", signature}]
                 ),
                 [keys: [key]] ++ now
               )

      <<prefix::binary-10, byte, rest::binary>> = signature
      flipped = <<prefix::binary, Bitwise.bxor(byte, 1), rest::binary>>

      corrupt =
        request(
          headers: request().headers ++ [{"signature-input", input}, {"signature", flipped}]
        )

      assert {:error, reason} = HTTPSignature.verify(corrupt, [keys: [key]] ++ now)
      assert reason in [:invalid_signature, :malformed_signature]
    end

    test "malformed Signature-Input and Signature headers are rejected", %{key: key} do
      cases = [
        {"not a dictionary", ~S|sig1=(|, "sig1=:AQID:", :malformed_signature_input},
        {"label mapped to an item", ~S|sig1="x"|, "sig1=:AQID:", :malformed_signature_input},
        {"non-string component", ~S|sig1=(1 2)|, "sig1=:AQID:", :malformed_signature_input},
        {"unknown component parameter", ~S|sig1=("@method";weird)|, "sig1=:AQID:",
         :malformed_signature_input},
        {"req with a value", ~S|sig1=("@method";req="x")|, "sig1=:AQID:",
         :malformed_signature_input},
        {"created not an integer", ~S|sig1=("@method");created="soon"|, "sig1=:AQID:",
         :malformed_signature_input},
        {"keyid not a string", ~S|sig1=("@method");keyid=1|, "sig1=:AQID:",
         :malformed_signature_input},
        {"duplicate label", ~S|sig1=("@method"), sig1=("@path")|, "sig1=:AQID:",
         :malformed_signature_input},
        {"duplicate parameter", ~S|sig1=("@method");created=1;created=2|, "sig1=:AQID:",
         :malformed_signature_input},
        {"signature not bytes", ~S|sig1=("@method")|, ~S|sig1="AQID"|, :malformed_signature},
        {"signature not a dictionary", ~S|sig1=("@method")|, "sig1=:AQID", :malformed_signature},
        {"signature label missing", ~S|sig1=("@method")|, "other=:AQID:", :missing_signature},
        {"sf parameter is unsupported", ~S|sig1=("date";sf)|, "sig1=:AQID:",
         {:unsupported_component_parameter, "sf"}},
        {"unknown derived component", ~S|sig1=("@nope")|, "sig1=:AQID:",
         {:unknown_component, ~S|"@nope"|}}
      ]

      for {name, input, signature, expected} <- cases do
        message =
          request(headers: [{"date", "x"}, {"signature-input", input}, {"signature", signature}])

        assert {:error, ^expected} = HTTPSignature.verify(message, keys: key), name
      end

      assert {:error, :missing_signature} =
               HTTPSignature.verify(request(headers: [{"signature-input", ~S|sig1=("@method")|}]),
                 keys: [key]
               )

      assert {:error, :missing_signature} =
               HTTPSignature.verify(request(headers: [{"signature", "sig1=:AQID:"}]), keys: [key])
    end

    test "verifies headers split across several field instances", %{key: key, message: message} do
      other = generated("ed25519")
      {:ok, extra} = HTTPSignature.sign(message, other, label: "sig2", created: 1_700_000_000)
      message = request(headers: request().headers ++ Enum.take(message.headers, -2) ++ extra)

      assert {:ok, %{label: "sig2"}} =
               HTTPSignature.verify(message, keys: [other], label: "sig2", now: 1_700_000_001)

      assert {:ok, %{label: "sig1"}} =
               HTTPSignature.verify(message, keys: [key], label: "sig1", now: 1_700_000_001)
    end
  end

  describe "directory/1" do
    test "publishes public JWKs with kid, alg and use" do
      ed = generated("ed25519")
      ec = generated("ecdsa-p256-sha256")

      assert %{"keys" => [jwk_ed, jwk_ec]} =
               HTTPSignature.directory([ed, {ec, nbf: 1_700_000_000}])

      assert jwk_ed == Key.to_jwk(ed)
      refute Map.has_key?(jwk_ed, "d")
      assert jwk_ec == Map.put(Key.to_jwk(ec), "nbf", 1_700_000_000)
      assert jwk_ec["kid"] == Key.thumbprint(ec)
    end
  end

  describe "merge_headers/1" do
    test "joins field instances per header, skipping unrelated ones" do
      assert [{"signature-input", ~S|a=(), b=()|}, {"signature", "a=:AQ==:, b=:Ag==:"}] =
               HTTPSignature.merge_headers([
                 [{"Signature-Input", "a=()"}, {"Signature", "a=:AQ==:"}, {"x-other", "1"}],
                 [{"signature-input", "b=()"}, {"signature", "b=:Ag==:"}]
               ])
    end
  end

  describe "form_encode/1" do
    test "percent-encodes everything outside unreserved and encodes space as %20" do
      assert HTTPSignature.form_encode("a b+c/d~e") == "a%20b%2Bc%2Fd%7Ee"
      assert HTTPSignature.form_encode("") == ""
    end
  end
end
