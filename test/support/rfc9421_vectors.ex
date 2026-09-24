defmodule X402.RFC9421Vectors do
  @moduledoc false
  # RFC 9421 Appendix B test keys and known-answer vectors. These are the
  # public, non-secret example keys published in the RFC for interop
  # testing; they must never be used outside tests.

  # -- B.1.2 test-key-rsa-pss (JWK form of the RFC's PEM) ------------------

  @rfc9421_rsa_pss_n "r4tmm3r20Wd_PbqvP1s2-QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct-Lh1GH45x28Rw3Ry53mm-oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHqgDsznjPFmTOtCEcN2Z1FpWgchwuYLPL-Wokqltd11nqqzi-bJ9cvSKADYdUAAN5WUtzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4aOT9v6d-nb4bnNkQVklLQ3fVAvJm-xdDOp9LCNCN48V2pnDOkFV6-U9nV5oyc6XI2w"
  @rfc9421_rsa_pss_e "AQAB"
  @rfc9421_rsa_pss_d "lAfIqfpCYomVShfAKnwf2lD9I0wKjkHsCtZCif4kAlwQqqW6N-tIL3bdOR-VWf0Q1ZBIDtpO91UrG7pansyrPERbNrRJlPiYEyPTHkCT1nD-l2isuiyGLNBNnFoKfBgA4KAbPJZQatFIV9Cn34JSHnpN5-2ehreGBYHtkwHFtlmzeF3yu5bqRcqOhx8lkYmBzDAEUFyyXjknU5-WjAT9DzuG0MpOTkcU1EnjnIjyVBZLUB5Lxm8puyq8hH8B_E5LNC-1oc8j-tDy98UvRTTiYvZvs87cGCFxg0LijNhg7CE3g9piNqB6DzMgA9MHSOwcElVtfKdYfo4H3OHZXsSmEQ"

  # -- B.1.3 test-key-ecc-p256 ---------------------------------------------

  @rfc9421_p256_x "qIVYZVLCrPZHGHjP17CTW0_-D9Lfw0EkjqF7xB4FivA"
  @rfc9421_p256_y "Mc4nN9LTDOBhfoUeg8Ye9WedFRhnZXZJA12Qp0zZ6F0"
  @rfc9421_p256_d "UpuF81l-kOxbjf7T4mNSv0r5tN67Gim7rnf6EFpcYDs"

  @rfc9421_p256_public_pem """
  -----BEGIN PUBLIC KEY-----
  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEqIVYZVLCrPZHGHjP17CTW0/+D9Lf
  w0EkjqF7xB4FivAxzic30tMM4GF+hR6Dxh71Z50VGGdldkkDXZCnTNnoXQ==
  -----END PUBLIC KEY-----
  """

  # -- B.1.4 test-key-ed25519 ----------------------------------------------

  @rfc9421_ed25519_x "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs"
  @rfc9421_ed25519_d "n4Ni-HpISpVObnQMW0wOhCKROaIKqKtW_2ZYb2p9KcU"

  @rfc9421_ed25519_public_pem """
  -----BEGIN PUBLIC KEY-----
  MCowBQYDK2VwAyEAJrQLj5P/89iXES9+vFgrIy29clF9CC/oPPsw3c5D0bs=
  -----END PUBLIC KEY-----
  """

  @rfc9421_rsa_pss_public_pem """
  -----BEGIN PUBLIC KEY-----
  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr4tmm3r20Wd/PbqvP1s2
  +QEtvpuRaV8Yq40gjUR8y2Rjxa6dpG2GXHbPfvMs8ct+Lh1GH45x28Rw3Ry53mm+
  oAXjyQ86OnDkZ5N8lYbggD4O3w6M6pAvLkhk95AndTrifbIFPNU8PPMO7OyrFAHq
  gDsznjPFmTOtCEcN2Z1FpWgchwuYLPL+Wokqltd11nqqzi+bJ9cvSKADYdUAAN5W
  Utzdpiy6LbTgSxP7ociU4Tn0g5I6aDZJ7A8Lzo0KSyZYoA485mqcO0GVAdVw9lq4
  aOT9v6d+nb4bnNkQVklLQ3fVAvJm+xdDOp9LCNCN48V2pnDOkFV6+U9nV5oyc6XI
  2wIDAQAB
  -----END PUBLIC KEY-----
  """

  @doc "Public JWKs, keyed by the RFC's key names."
  def public_jwks do
    %{
      "test-key-rsa-pss" => %{
        "kty" => "RSA",
        "kid" => "test-key-rsa-pss",
        "n" => @rfc9421_rsa_pss_n,
        "e" => @rfc9421_rsa_pss_e
      },
      "test-key-ecc-p256" => %{
        "kty" => "EC",
        "crv" => "P-256",
        "kid" => "test-key-ecc-p256",
        "x" => @rfc9421_p256_x,
        "y" => @rfc9421_p256_y
      },
      "test-key-ed25519" => %{
        "kty" => "OKP",
        "crv" => "Ed25519",
        "kid" => "test-key-ed25519",
        "x" => @rfc9421_ed25519_x
      }
    }
  end

  @doc "Private JWKs, keyed by the RFC's key names."
  def private_jwks do
    %{
      "test-key-rsa-pss" => Map.put(public_jwks()["test-key-rsa-pss"], "d", @rfc9421_rsa_pss_d),
      "test-key-ecc-p256" => Map.put(public_jwks()["test-key-ecc-p256"], "d", @rfc9421_p256_d),
      "test-key-ed25519" => Map.put(public_jwks()["test-key-ed25519"], "d", @rfc9421_ed25519_d)
    }
  end

  @doc "Public PEMs, keyed by the RFC's key names."
  def public_pems do
    %{
      "test-key-rsa-pss" => @rfc9421_rsa_pss_public_pem,
      "test-key-ecc-p256" => @rfc9421_p256_public_pem,
      "test-key-ed25519" => @rfc9421_ed25519_public_pem
    }
  end

  @doc "The Appendix B.2 test-request as a `X402.HTTPSignature` message."
  def test_request do
    %{
      method: "POST",
      url: "https://example.com/foo?param=Value&Pet=dog",
      headers: [
        {"Host", "example.com"},
        {"Date", "Tue, 20 Apr 2021 02:07:55 GMT"},
        {"Content-Type", "application/json"},
        {"Content-Digest",
         "sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:"},
        {"Content-Length", "18"}
      ]
    }
  end

  @doc "The Appendix B.2 test-response as a `X402.HTTPSignature` message."
  def test_response do
    %{
      status: 200,
      headers: [
        {"Date", "Tue, 20 Apr 2021 02:07:56 GMT"},
        {"Content-Type", "application/json"},
        {"Content-Digest",
         "sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:"},
        {"Content-Length", "23"}
      ],
      request: test_request()
    }
  end

  @doc """
  Appendix B.2 and B.3 known-answer vectors: each carries the message,
  the wire `Signature-Input`/`Signature` values, the expected signature
  base and the key name.
  """
  def vectors do
    [
      %{
        name: "B.2.1 minimal rsa-pss-sha512",
        label: "sig-b21",
        key: "test-key-rsa-pss",
        message: test_request(),
        signature_input:
          ~S|sig-b21=();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"|,
        signature:
          "sig-b21=:d2pmTvmbncD3xQm8E9ZV2828BjQWGgiwAaw5bAkgibUopemLJcWDy/lkbbHAve4cRAtx31Iq786U7it++wgGxbtRxf8Udx7zFZsckzXaJMkA7ChG52eSkFxykJeNqsrWH5S+oxNFlD4dzVuwe8DhTSja8xxbR/Z2cOGdCbzR72rgFWhzx2VjBqJzsPLMIQKhO4DGezXehhWwE56YCE+O6c0mKZsfxVrogUvA4HELjVKWmAvtl6UnCh8jYzuVG5WSb/QEVPnP5TmcAnLH1g+s++v6d4s8m0gCw1fV5/SITLq9mhho8K3+7EPYTU8IU1bLhdxO5Nyt8C8ssinQ98Xw9Q==:",
        components: [],
        params: [
          {"created", 1_618_884_473},
          {"keyid", "test-key-rsa-pss"},
          {"nonce", "b3k2pp5k7z-50gnwp.yemd"}
        ],
        base:
          ~S|"@signature-params": ();created=1618884473;keyid="test-key-rsa-pss";nonce="b3k2pp5k7z-50gnwp.yemd"|,
        deterministic: false
      },
      %{
        name: "B.2.2 selective rsa-pss-sha512",
        label: "sig-b22",
        key: "test-key-rsa-pss",
        message: test_request(),
        signature_input:
          ~S|sig-b22=("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"|,
        signature:
          "sig-b22=:LjbtqUbfmvjj5C5kr1Ugj4PmLYvx9wVjZvD9GsTT4F7GrcQEdJzgI9qHxICagShLRiLMlAJjtq6N4CDfKtjvuJyE5qH7KT8UCMkSowOB4+ECxCmT8rtAmj/0PIXxi0A0nxKyB09RNrCQibbUjsLS/2YyFYXEu4TRJQzRw1rLEuEfY17SARYhpTlaqwZVtR8NV7+4UKkjqpcAoFqWFQh62s7Cl+H2fjBSpqfZUJcsIk4N6wiKYd4je2U/lankenQ99PZfB4jY3I5rSV2DSBVkSFsURIjYErOs0tFTQosMTAoxk//0RoKUqiYY8Bh0aaUEb0rQl3/XaVe4bXTugEjHSw==:",
        components: ["@authority", "content-digest", {"@query-param", name: "Pet"}],
        params: [
          {"created", 1_618_884_473},
          {"keyid", "test-key-rsa-pss"},
          {"tag", "header-example"}
        ],
        base:
          Enum.join(
            [
              ~S|"@authority": example.com|,
              ~S|"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:|,
              ~S|"@query-param";name="Pet": dog|,
              ~S|"@signature-params": ("@authority" "content-digest" "@query-param";name="Pet");created=1618884473;keyid="test-key-rsa-pss";tag="header-example"|
            ],
            "\n"
          ),
        deterministic: false
      },
      %{
        name: "B.2.3 full coverage rsa-pss-sha512",
        label: "sig-b23",
        key: "test-key-rsa-pss",
        message: test_request(),
        signature_input:
          ~S|sig-b23=("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"|,
        signature:
          "sig-b23=:bbN8oArOxYoyylQQUU6QYwrTuaxLwjAC9fbY2F6SVWvh0yBiMIRGOnMYwZ/5MR6fb0Kh1rIRASVxFkeGt683+qRpRRU5p2voTp768ZrCUb38K0fUxN0O0iC59DzYx8DFll5GmydPxSmme9v6ULbMFkl+V5B1TP/yPViV7KsLNmvKiLJH1pFkh/aYA2HXXZzNBXmIkoQoLd7YfW91kE9o/CCoC1xMy7JA1ipwvKvfrs65ldmlu9bpG6A9BmzhuzF8Eim5f8ui9eH8LZH896+QIF61ka39VBrohr9iyMUJpvRX2Zbhl5ZJzSRxpJyoEZAFL2FUo5fTIztsDZKEgM4cUA==:",
        components:
          ~w(date @method @path @query @authority content-type content-digest content-length),
        params: [{"created", 1_618_884_473}, {"keyid", "test-key-rsa-pss"}],
        base:
          Enum.join(
            [
              ~S|"date": Tue, 20 Apr 2021 02:07:55 GMT|,
              ~S|"@method": POST|,
              ~S|"@path": /foo|,
              ~S|"@query": ?param=Value&Pet=dog|,
              ~S|"@authority": example.com|,
              ~S|"content-type": application/json|,
              ~S|"content-digest": sha-512=:WZDPaVn/7XgHaAy8pmojAkGWoRx2UFChF41A2svX+TaPm+AbwAgBWnrIiYllu7BNNyealdVLvRwEmTHWXvJwew==:|,
              ~S|"content-length": 18|,
              ~S|"@signature-params": ("date" "@method" "@path" "@query" "@authority" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-rsa-pss"|
            ],
            "\n"
          ),
        deterministic: false
      },
      %{
        name: "B.2.4 response ecdsa-p256-sha256",
        label: "sig-b24",
        key: "test-key-ecc-p256",
        message: test_response(),
        signature_input:
          ~S|sig-b24=("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"|,
        signature:
          "sig-b24=:wNmSUAhwb5LxtOtOpNa6W5xj067m5hFrj0XQ4fvpaCLx0NKocgPquLgyahnzDnDAUy5eCdlYUEkLIj+32oiasw==:",
        components: ~w(@status content-type content-digest content-length),
        params: [{"created", 1_618_884_473}, {"keyid", "test-key-ecc-p256"}],
        base:
          Enum.join(
            [
              ~S|"@status": 200|,
              ~S|"content-type": application/json|,
              ~S|"content-digest": sha-512=:mEWXIS7MaLRuGgxOBdODa3xqM1XdEvxoYhvlCFJ41QJgJc4GTsPp29l5oGX69wWdXymyU0rjJuahq4l5aGgfLQ==:|,
              ~S|"content-length": 23|,
              ~S|"@signature-params": ("@status" "content-type" "content-digest" "content-length");created=1618884473;keyid="test-key-ecc-p256"|
            ],
            "\n"
          ),
        deterministic: false
      },
      %{
        name: "B.2.6 request ed25519",
        label: "sig-b26",
        key: "test-key-ed25519",
        message: test_request(),
        signature_input:
          ~S|sig-b26=("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"|,
        signature:
          "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:",
        components: ~w(date @method @path @authority content-type content-length),
        params: [{"created", 1_618_884_473}, {"keyid", "test-key-ed25519"}],
        base:
          Enum.join(
            [
              ~S|"date": Tue, 20 Apr 2021 02:07:55 GMT|,
              ~S|"@method": POST|,
              ~S|"@path": /foo|,
              ~S|"@authority": example.com|,
              ~S|"content-type": application/json|,
              ~S|"content-length": 18|,
              ~S|"@signature-params": ("date" "@method" "@path" "@authority" "content-type" "content-length");created=1618884473;keyid="test-key-ed25519"|
            ],
            "\n"
          ),
        deterministic: true
      },
      %{
        name: "B.3 TLS-terminating proxy ecdsa-p256-sha256",
        label: "ttrp",
        key: "test-key-ecc-p256",
        message: %{
          method: "POST",
          url: "https://service.internal.example/foo?param=Value&Pet=dog",
          headers: [
            {"Host", "service.internal.example"},
            {"Date", "Tue, 20 Apr 2021 02:07:55 GMT"},
            {"Content-Type", "application/json"},
            {"Content-Length", "18"},
            {"Client-Cert", ":" <> client_cert() <> ":"}
          ]
        },
        signature_input:
          ~S|ttrp=("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256"|,
        signature:
          "ttrp=:xVMHVpawaAC/0SbHrKRs9i8I3eOs5RtTMGCWXm/9nvZzoHsIg6Mce9315T6xoklyy0yzhD9ah4JHRwMLOgmizw==:",
        components: ~w(@path @query @method @authority client-cert),
        params: [{"created", 1_618_884_473}, {"keyid", "test-key-ecc-p256"}],
        base:
          Enum.join(
            [
              ~S|"@path": /foo|,
              ~S|"@query": ?param=Value&Pet=dog|,
              ~S|"@method": POST|,
              ~S|"@authority": service.internal.example|,
              ~S|"client-cert": :| <> client_cert() <> ":",
              ~S|"@signature-params": ("@path" "@query" "@method" "@authority" "client-cert");created=1618884473;keyid="test-key-ecc-p256"|
            ],
            "\n"
          ),
        deterministic: false
      }
    ]
  end

  @doc """
  Appendix B.4: an ed25519-signed request and the transformations that
  must (`valid`) and must not (`invalid`) keep the signature valid.
  """
  def transformations do
    signature_input =
      ~S|transform=("@method" "@path" "@authority" "accept");created=1618884473;keyid="test-key-ed25519"|

    signature =
      "transform=:ZT1kooQsEHpZ0I1IjCqtQppOmIqlJPeo7DHR3SoMn0s5JZ1eRGS0A+vyYP9t/LXlh5QMFFQ6cpLt2m0pmj3NDA==:"

    signed = [{"Signature-Input", signature_input}, {"Signature", signature}]

    %{
      base:
        Enum.join(
          [
            ~S|"@method": GET|,
            ~S|"@path": /demo|,
            ~S|"@authority": example.org|,
            ~S|"accept": application/json, */*|,
            ~S|"@signature-params": ("@method" "@path" "@authority" "accept");created=1618884473;keyid="test-key-ed25519"|
          ],
          "\n"
        ),
      original: %{
        method: "GET",
        url: "https://example.org/demo?name1=Value1&Name2=value2",
        headers:
          [
            {"Host", "example.org"},
            {"Date", "Fri, 15 Jul 2022 14:24:55 GMT"},
            {"Accept", "application/json"},
            {"Accept", "*/*"}
          ] ++ signed
      },
      valid: [
        {"added header and query parameter",
         %{
           method: "GET",
           url: "https://example.org/demo?name1=Value1&Name2=value2&param=added",
           headers:
             [
               {"Host", "example.org"},
               {"Date", "Fri, 15 Jul 2022 14:24:55 GMT"},
               {"Accept", "application/json"},
               {"Accept", "*/*"},
               {"Accept-Language", "en-US,en;q=0.5"}
             ] ++ signed
         }},
        {"collapsed accept and swapped uncovered headers",
         %{
           method: "GET",
           url: "https://example.org/demo?name1=Value1&Name2=value2",
           headers:
             [
               {"Host", "example.org"},
               {"Referer", "https://developer.example.org/demo"},
               {"Accept", "application/json, */*"}
             ] ++ signed
         }},
        {"reordered fields",
         %{
           method: "GET",
           url: "https://example.org/demo?name1=Value1&Name2=value2",
           headers:
             [
               {"Accept", "application/json"},
               {"Accept", "*/*"},
               {"Date", "Fri, 15 Jul 2022 14:24:55 GMT"},
               {"Host", "example.org"}
             ] ++ signed
         }}
      ],
      invalid: [
        {"changed method and authority",
         %{
           method: "POST",
           url: "https://example.com/demo?name1=Value1&Name2=value2",
           headers:
             [
               {"Host", "example.com"},
               {"Date", "Fri, 15 Jul 2022 14:24:55 GMT"},
               {"Accept", "application/json"},
               {"Accept", "*/*"}
             ] ++ signed
         }},
        {"reordered accept values",
         %{
           method: "GET",
           url: "https://example.org/demo?name1=Value1&Name2=value2",
           headers:
             [
               {"Host", "example.org"},
               {"Date", "Fri, 15 Jul 2022 14:24:55 GMT"},
               {"Accept", "*/*"},
               {"Accept", "application/json"}
             ] ++ signed
         }}
      ]
    }
  end

  defp client_cert do
    "MIIBqDCCAU6gAwIBAgIBBzAKBggqhkjOPQQDAjA6MRswGQYDVQQKDBJMZXQncyBBdXRoZW50aWNhdGUxGzAZBgNVBAMMEkxBIEludGVybWVkaWF0ZSBDQTAeFw0yMDAxMTQyMjU1MzNaFw0yMTAxMjMyMjU1MzNaMA0xCzAJBgNVBAMMAkJDMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE8YnXXfaUgmnMtOXU/IncWalRhebrXmckC8vdgJ1p5Be5F/3YC8OthxM4+k1M6aEAEFcGzkJiNy6J84y7uzo9M6NyMHAwCQYDVR0TBAIwADAfBgNVHSMEGDAWgBRm3WjLa38lbEYCuiCPct0ZaSED2DAOBgNVHQ8BAf8EBAMCBsAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0RAQH/BBMwEYEPYmRjQGV4YW1wbGUuY29tMAoGCCqGSM49BAMCA0gAMEUCIBHda/r1vaL6G3VliL4/Di6YK0Q6bMjeSkC3dFCOOB8TAiEAx/kHSB4urmiZ0NX5r5XarmPk0wmuydBVoU4hBVZ1yhk="
  end
end
