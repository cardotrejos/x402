defmodule X402.Plug.HTTPSignatureDirectoryTest do
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias X402.HTTPSignature
  alias X402.HTTPSignature.Key
  alias X402.Plug.HTTPSignatureDirectory

  doctest X402.Plug.HTTPSignatureDirectory

  @path "/.well-known/http-message-signatures-directory"

  defp generated(alg) do
    {:ok, key} = Key.generate(alg)
    key
  end

  defp serve(conn, opts), do: HTTPSignatureDirectory.call(conn, HTTPSignatureDirectory.init(opts))

  defp response_message(conn) do
    %{
      status: conn.status,
      headers: conn.resp_headers,
      request: %{method: conn.method, url: request_url(conn), headers: conn.req_headers}
    }
  end

  describe "init/1" do
    test "requires keys with private material or a function" do
      {:ok, key} = Key.generate("ed25519")

      assert %{keys: [^key]} = HTTPSignatureDirectory.init(keys: [key])
      assert %{keys: fun} = HTTPSignatureDirectory.init(keys: fn -> [key] end)
      assert is_function(fun, 0)

      assert %{path: "/keys", sign: false, ttl: 60} =
               HTTPSignatureDirectory.init(keys: [key], path: "/keys", sign: false, ttl: 60)

      assert_raise NimbleOptions.ValidationError, ~r/:keys/, fn ->
        HTTPSignatureDirectory.init([])
      end

      assert_raise NimbleOptions.ValidationError, ~r/non-empty list of keys/, fn ->
        HTTPSignatureDirectory.init(keys: [])
      end

      assert_raise NimbleOptions.ValidationError, ~r/private material/, fn ->
        HTTPSignatureDirectory.init(keys: [%{key | private: nil}])
      end

      assert_raise NimbleOptions.ValidationError, ~r/private material/, fn ->
        HTTPSignatureDirectory.init(keys: [Key.to_jwk(key)])
      end

      assert_raise NimbleOptions.ValidationError, ~r/:ttl/, fn ->
        HTTPSignatureDirectory.init(keys: [key], ttl: 0)
      end
    end
  end

  describe "call/2" do
    test "serves the signed JWKS directory for every key" do
      keys = Enum.map(Key.algorithms(), &generated/1)
      conn = serve(conn(:get, "https://agent.example.com" <> @path), keys: keys)

      assert conn.status == 200
      assert conn.halted
      assert [content_type] = get_resp_header(conn, "content-type")
      assert content_type =~ "application/http-message-signatures-directory+json"
      assert ["max-age=3600"] = get_resp_header(conn, "cache-control")

      assert %{"keys" => jwks} = Jason.decode!(conn.resp_body)
      assert jwks == Enum.map(keys, &Key.to_jwk/1)
      refute Enum.any?(jwks, &Map.has_key?(&1, "d"))
      assert Enum.map(jwks, & &1["kid"]) == Enum.map(keys, &Key.thumbprint/1)

      # One signature per key, each verifiable with its published JWK only.
      assert [input] = get_resp_header(conn, "signature-input")
      assert input =~ ~S|sig1=("@authority";req);created=|
      assert input =~ "sig3="
      assert [_signature] = get_resp_header(conn, "signature")

      message = response_message(conn)

      for {jwk, index} <- Enum.with_index(jwks, 1) do
        {:ok, public} = Key.from_jwk(jwk)

        assert {:ok, verified} =
                 HTTPSignature.verify(message,
                   keys: [public],
                   label: "sig#{index}",
                   tag: "http-message-signatures-directory",
                   required_components: [{"@authority", req: true}],
                   required_params: ["created", "expires", "keyid", "alg", "nonce"],
                   max_age: 3600
                 )

        assert verified.params["keyid"] == jwk["kid"]
        assert verified.params["alg"] == jwk["alg"]
        assert verified.params["expires"] - verified.params["created"] == 3600
      end

      # A directory replayed from another origin does not verify.
      other = %{message | request: %{message.request | url: "https://other.example.com" <> @path}}
      {:ok, public} = Key.from_jwk(hd(jwks))

      assert {:error, :invalid_signature} =
               HTTPSignature.verify(other, keys: [public], label: "sig1")
    end

    test "resolves keys through a function and honours ttl and sign: false" do
      key = generated("ed25519")
      conn = serve(conn(:get, @path), keys: fn -> [key] end, sign: false, ttl: 60)

      assert conn.status == 200
      assert ["max-age=60"] = get_resp_header(conn, "cache-control")
      assert [] = get_resp_header(conn, "signature-input")
      assert [] = get_resp_header(conn, "signature")
      assert %{"keys" => [%{"kid" => kid}]} = Jason.decode!(conn.resp_body)
      assert kid == key.kid
    end

    test "serves a custom path and passes other requests through" do
      key = generated("ed25519")

      conn = serve(conn(:get, "/keys"), keys: [key], path: "/keys")
      assert conn.status == 200

      for conn <- [conn(:get, @path), conn(:post, "/keys"), conn(:get, "/keys/"), conn(:get, "/")] do
        conn = serve(conn, keys: [key], path: "/keys")
        refute conn.halted
        assert conn.state == :unset
      end
    end
  end
end
