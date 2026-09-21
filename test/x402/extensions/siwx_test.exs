defmodule X402.Extensions.SIWXTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  doctest X402.Extensions.SIWX

  alias X402.Base58
  alias X402.Extensions.PaymentIdentifier.ETSCache
  alias X402.Extensions.SIWX
  alias X402.Signer.LocalKey
  alias X402.Signer.SolanaKey

  @private_key "0x" <> String.duplicate("11", 32)
  @address "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
  @other_private_key "0x" <> String.duplicate("22", 32)
  @solana_seed :binary.copy(<<1>>, 32)
  @solana_chain "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"
  @evm_chain "eip155:8453"
  @domain "api.example.com"
  @uri "https://api.example.com"
  @chains [%{chain_id: @evm_chain}, %{chain_id: @solana_chain}]

  # Legacy functions are deprecated; resolving the module through the test
  # context keeps the test compile free of deprecation warnings.
  defp legacy_context(_context), do: %{legacy: SIWX}

  defmodule ErrorVerifier do
    @behaviour X402.Extensions.SIWX.Verifier

    @impl true
    def verify_signature(_message, _signature, _address), do: {:error, :rpc_unavailable}
  end

  defmodule RaisingVerifier do
    @behaviour X402.Extensions.SIWX.Verifier

    @impl true
    def verify_signature(_message, _signature, _address), do: raise("boom")
  end

  defmodule MalformedVerifier do
    @behaviour X402.Extensions.SIWX.Verifier

    @impl true
    def verify_signature(_message, _signature, _address), do: {:error, :invalid_signature}
  end

  defmodule InvalidAddressVerifier do
    @behaviour X402.Extensions.SIWX.Verifier

    @impl true
    def verify_signature(_message, _signature, _address), do: {:error, :invalid_address}
  end

  defmodule GarbageVerifier do
    @behaviour X402.Extensions.SIWX.Verifier

    @impl true
    def verify_signature(_message, _signature, _address), do: :nope
  end

  describe "extension_key/0 and header_name/0" do
    test "return the wire names" do
      assert SIWX.extension_key() == "sign-in-with-x"
      assert SIWX.header_name() == "SIGN-IN-WITH-X"
    end
  end

  describe "challenge/1" do
    test "builds the advertisement with a fresh nonce and default expiration" do
      challenge = challenge()

      assert %{"info" => info, "supportedChains" => chains, "schema" => schema} = challenge
      assert info["domain"] == @domain
      assert info["uri"] == @uri
      assert info["version"] == "1"
      assert info["nonce"] =~ ~r/\A[a-f0-9]{32}\z/
      assert {:ok, issued_at, 0} = DateTime.from_iso8601(info["issuedAt"])
      assert {:ok, expiration, 0} = DateTime.from_iso8601(info["expirationTime"])
      assert DateTime.diff(expiration, issued_at, :second) == 300
      refute Map.has_key?(info, "statement")
      refute Map.has_key?(info, "resources")

      assert chains == [
               %{"chainId" => @evm_chain, "type" => "eip191"},
               %{"chainId" => @solana_chain, "type" => "ed25519"}
             ]

      assert schema == SIWX.schema()
      assert challenge()["info"]["nonce"] != info["nonce"]
    end

    test "raises for invalid options" do
      assert_raise NimbleOptions.ValidationError, fn -> SIWX.challenge(domain: @domain) end

      assert_raise NimbleOptions.ValidationError, fn ->
        SIWX.challenge(domain: @domain, uri: @uri, supported_chains: [])
      end
    end
  end

  describe "sign/3" do
    test "signs an eip155 challenge with a LocalKey" do
      challenge = challenge(statement: "Sign in", resources: ["https://api.example.com/x"])

      assert {:ok, signed} = SIWX.sign(challenge, evm_signer(), chain_id: @evm_chain)

      assert signed["address"] == @address
      assert signed["chainId"] == @evm_chain
      assert signed["type"] == "eip191"
      assert signed["domain"] == @domain
      assert signed["uri"] == @uri
      assert signed["statement"] == "Sign in"
      assert signed["resources"] == ["https://api.example.com/x"]
      assert signed["nonce"] == challenge["info"]["nonce"]
      assert signed["issuedAt"] == challenge["info"]["issuedAt"]
      assert signed["expirationTime"] == challenge["info"]["expirationTime"]
      assert signed["signature"] =~ ~r/\A0x[0-9a-f]{130}\z/
      refute Map.has_key?(signed, "signatureScheme")

      assert {:ok, %{address: @address, chain_id: @evm_chain}} =
               SIWX.verify({:spec, signed}, verify_opts())
    end

    test "signs a solana challenge with a SolanaKey" do
      {:ok, signer} = SolanaKey.new(@solana_seed)
      {:ok, address} = SolanaKey.address(signer)

      assert {:ok, signed} = SIWX.sign(challenge(), signer, chain_id: @solana_chain)
      assert signed["address"] == address
      assert signed["type"] == "ed25519"
      assert {:ok, <<_::binary-size(64)>>} = Base58.decode(signed["signature"])

      assert {:ok, %{address: ^address, chain_id: @solana_chain}} =
               SIWX.verify({:spec, signed}, verify_opts())
    end

    test "accepts a bare info map and copies address and signatureScheme options" do
      info = challenge()["info"]

      assert {:ok, signed} =
               SIWX.sign(info, evm_signer(),
                 chain_id: @evm_chain,
                 address: "0x19E7E376E7C213B7E7E7E46CC70A5DD086DAFF2A",
                 signature_scheme: "eip191"
               )

      assert signed["address"] == "0x19E7E376E7C213B7E7E7E46CC70A5DD086DAFF2A"
      assert signed["signatureScheme"] == "eip191"
    end

    test "rejects chains the challenge does not advertise" do
      challenge = challenge(supported_chains: [%{chain_id: @evm_chain}])

      assert SIWX.sign(challenge, evm_signer(), chain_id: "eip155:1") ==
               {:error, :unsupported_chain}

      assert SIWX.sign(challenge, evm_signer(), chain_id: "cosmos:hub") ==
               {:error, :unsupported_chain}

      assert SIWX.sign(challenge, evm_signer(), chain_id: "eip155:base") ==
               {:error, :invalid_chain_id}
    end

    test "rejects challenges without the required info fields" do
      assert SIWX.sign(%{"info" => %{"domain" => @domain}}, evm_signer(), chain_id: @evm_chain) ==
               {:error, :invalid_payload}

      assert SIWX.sign(:nope, evm_signer(), chain_id: @evm_chain) == {:error, :invalid_payload}
    end

    test "returns signer errors" do
      {:ok, solana} = SolanaKey.new(@solana_seed)

      assert SIWX.sign(challenge(), solana, chain_id: @evm_chain) ==
               {:error, :unsupported_signer}

      assert SIWX.sign(challenge(), evm_signer(), chain_id: @solana_chain) ==
               {:error, :unsupported_signer}
    end

    test "raises for invalid options" do
      assert_raise NimbleOptions.ValidationError, fn ->
        SIWX.sign(challenge(), evm_signer(), [])
      end
    end
  end

  describe "encode_signed/1 and decode_signed/1" do
    test "round-trip spec proofs" do
      signed = signed_evm()

      assert {:ok, header} = SIWX.encode_signed(signed)
      assert {:ok, {:spec, decoded}} = SIWX.decode_signed(header)
      assert decoded == signed
    end

    test "accept snake_case atom keys and drop unknown keys" do
      fields = %{
        domain: @domain,
        address: @address,
        uri: @uri,
        version: "1",
        chain_id: @evm_chain,
        type: "eip191",
        nonce: String.duplicate("a", 32),
        issued_at: "2024-01-15T10:30:00.000Z",
        request_id: "req-1",
        not_before: "2024-01-15T10:30:00.000Z",
        signature: "0xabc",
        extra: "dropped"
      }

      assert {:ok, header} = SIWX.encode_signed(fields)
      assert {:ok, {:spec, decoded}} = SIWX.decode_signed(header)
      assert decoded["chainId"] == @evm_chain
      assert decoded["requestId"] == "req-1"
      assert decoded["notBefore"] == "2024-01-15T10:30:00.000Z"
      refute Map.has_key?(decoded, "extra")
    end

    test "encode_signed rejects incomplete proofs" do
      assert SIWX.encode_signed(Map.delete(signed_evm(), "signature")) ==
               {:error, :invalid_payload}

      assert SIWX.encode_signed(Map.put(signed_evm(), "signature", "")) ==
               {:error, :invalid_payload}

      assert SIWX.encode_signed(nil) == {:error, :invalid_payload}
    end

    test "encode_signed returns invalid_json for values that cannot be encoded" do
      assert SIWX.encode_signed(Map.put(signed_evm(), "statement", <<0xFF, 0xFE>>)) ==
               {:error, :invalid_json}
    end

    test "decode_signed classifies the legacy format" do
      {:ok, message} = SIWX.encode(legacy_payload())
      header = Base.encode64(Jason.encode!(%{"message" => message, "signature" => "0xabc"}))

      assert SIWX.decode_signed(header) ==
               {:ok, {:legacy, %{"message" => message, "signature" => "0xabc"}}}
    end

    test "decode_signed rejects legacy payloads with unparseable messages or empty signatures" do
      {:ok, message} = SIWX.encode(legacy_payload())

      garbage = Base.encode64(Jason.encode!(%{"message" => "hello", "signature" => "0xabc"}))
      assert SIWX.decode_signed(garbage) == {:error, :invalid_payload}

      empty = Base.encode64(Jason.encode!(%{"message" => message, "signature" => ""}))
      assert SIWX.decode_signed(empty) == {:error, :invalid_payload}
    end

    test "decode_signed rejects malformed headers" do
      assert SIWX.decode_signed("%%") == {:error, :invalid_base64}
      assert SIWX.decode_signed("") == {:error, :invalid_base64}
      assert SIWX.decode_signed(nil) == {:error, :invalid_base64}
      assert SIWX.decode_signed(Base.encode64("{")) == {:error, :invalid_json}
      assert SIWX.decode_signed(Base.encode64("[]")) == {:error, :invalid_payload}
      assert SIWX.decode_signed(Base.encode64(~s({"domain":"x"}))) == {:error, :invalid_payload}

      too_large = Base.encode64(String.duplicate("a", 8 * 1024))
      assert SIWX.decode_signed(too_large) == {:error, :payload_too_large}
    end
  end

  describe "validate_fields/1" do
    test "requires version 1 and string-typed optional fields" do
      fields = Map.delete(signed_evm(), "signature")

      assert {:ok, ^fields} = SIWX.validate_fields(fields)
      assert SIWX.validate_fields(Map.put(fields, "version", "2")) == {:error, :invalid_payload}
      assert SIWX.validate_fields(Map.put(fields, "statement", 1)) == {:error, :invalid_payload}
      assert SIWX.validate_fields(Map.put(fields, "resources", "x")) == {:error, :invalid_payload}
      assert SIWX.validate_fields(Map.put(fields, "resources", [1])) == {:error, :invalid_payload}
      assert SIWX.validate_fields(Map.put(fields, "nonce", "")) == {:error, :invalid_payload}
      assert SIWX.validate_fields([]) == {:error, :invalid_payload}
    end

    test "omits an empty resources list" do
      assert {:ok, fields} = SIWX.validate_fields(Map.put(signed_evm(), "resources", []))
      refute Map.has_key?(fields, "resources")
    end
  end

  describe "verify/2" do
    test "verifies a raw header value" do
      {:ok, header} = SIWX.encode_signed(signed_evm())

      assert {:ok, %{address: @address, chain_id: @evm_chain, fields: fields}} =
               SIWX.verify(header, verify_opts())

      assert fields["nonce"] =~ ~r/\A[a-f0-9]{32}\z/
      assert SIWX.verify("%%", verify_opts()) == {:error, :invalid_base64}
    end

    test "rejects unknown decoded shapes" do
      assert SIWX.verify({:spec, %{}}, verify_opts()) == {:error, :invalid_payload}

      assert SIWX.verify({:legacy, %{"message" => "x", "signature" => "y"}}, verify_opts()) ==
               {:error, :invalid_payload}

      assert SIWX.verify(:nope, verify_opts()) == {:error, :invalid_payload}
    end

    test "ignores a trailing slash on the configured uri" do
      assert {:ok, _identity} = SIWX.verify({:spec, signed_evm()}, verify_opts(uri: @uri <> "/"))
    end

    test "returns invalid_siwx_domain_mismatch" do
      assert SIWX.verify({:spec, signed_evm()}, verify_opts(domain: "other.example.com")) ==
               {:error, :invalid_siwx_domain_mismatch}
    end

    test "returns invalid_siwx_uri_mismatch" do
      assert SIWX.verify({:spec, signed_evm()}, verify_opts(uri: "https://other.example.com")) ==
               {:error, :invalid_siwx_uri_mismatch}
    end

    test "returns the issuedAt errors" do
      tampered = Map.put(signed_evm(), "issuedAt", "yesterday")
      assert SIWX.verify({:spec, tampered}, verify_opts()) == {:error, :invalid_siwx_issued_at}

      old =
        signed_evm(
          issued_at: DateTime.add(DateTime.utc_now(), -600, :second),
          expiration_seconds: 1_200
        )

      assert SIWX.verify({:spec, old}, verify_opts()) ==
               {:error, :invalid_siwx_issued_at_too_old}

      assert {:ok, _identity} = SIWX.verify({:spec, old}, verify_opts(max_age_seconds: 900))

      future = signed_evm(issued_at: DateTime.add(DateTime.utc_now(), 120, :second))

      assert SIWX.verify({:spec, future}, verify_opts()) ==
               {:error, :invalid_siwx_issued_at_in_future}

      assert {:ok, _identity} = SIWX.verify({:spec, future}, verify_opts(clock_skew_seconds: 180))
    end

    test "returns the expirationTime errors" do
      tampered = Map.put(signed_evm(), "expirationTime", "never")

      assert SIWX.verify({:spec, tampered}, verify_opts()) ==
               {:error, :invalid_siwx_expiration_time}

      expired =
        signed_evm(
          issued_at: DateTime.add(DateTime.utc_now(), -120, :second),
          expiration_seconds: 60
        )

      assert SIWX.verify({:spec, expired}, verify_opts()) == {:error, :invalid_siwx_expired}
    end

    test "returns the notBefore errors" do
      tampered = Map.put(signed_evm(), "notBefore", "soon")
      assert SIWX.verify({:spec, tampered}, verify_opts()) == {:error, :invalid_siwx_not_before}

      not_yet = signed_evm(not_before: DateTime.add(DateTime.utc_now(), 3600, :second))
      assert SIWX.verify({:spec, not_yet}, verify_opts()) == {:error, :invalid_siwx_not_yet_valid}

      valid = signed_evm(not_before: DateTime.add(DateTime.utc_now(), -60, :second))
      assert {:ok, _identity} = SIWX.verify({:spec, valid}, verify_opts())
    end

    test "returns invalid_siwx_nonce for malformed nonces" do
      assert SIWX.verify({:spec, signed_evm(nonce: "short")}, verify_opts()) ==
               {:error, :invalid_siwx_nonce}

      upper = signed_evm(nonce: String.upcase(String.duplicate("ab", 16)))
      assert SIWX.verify({:spec, upper}, verify_opts()) == {:error, :invalid_siwx_nonce}
    end

    test "with a nonce cache, accepts an issued nonce exactly once" do
      cache = {ETSCache, start_cache()}
      signed = signed_evm()
      opts = verify_opts(nonce_cache: cache)

      assert SIWX.verify({:spec, signed}, opts) == {:error, :invalid_siwx_nonce}

      assert :ok =
               ETSCache.put_new(
                 elem(cache, 1),
                 "siwx:issued:" <> signed["nonce"],
                 {:siwx_nonce, :issued}
               )

      assert {:ok, _identity} = SIWX.verify({:spec, signed}, opts)
      assert SIWX.verify({:spec, signed}, opts) == {:error, :invalid_siwx_nonce}
    end

    test "with a nonce cache, an invalid proof does not consume the nonce" do
      cache = {ETSCache, start_cache()}
      challenge = challenge()
      {:ok, signed} = SIWX.sign(challenge, evm_signer(), chain_id: @evm_chain)
      {:ok, other} = LocalKey.new(@other_private_key)
      {:ok, forged} = SIWX.sign(challenge, other, chain_id: @evm_chain, address: @address)
      opts = verify_opts(nonce_cache: cache)

      assert :ok =
               ETSCache.put_new(
                 elem(cache, 1),
                 "siwx:issued:" <> signed["nonce"],
                 {:siwx_nonce, :issued}
               )

      assert SIWX.verify({:spec, forged}, opts) == {:error, :invalid_siwx_signature}
      assert {:ok, _identity} = SIWX.verify({:spec, signed}, opts)
    end

    test "returns the chain errors" do
      malformed = Map.put(signed_evm(), "chainId", "eip155:base")
      assert SIWX.verify({:spec, malformed}, verify_opts()) == {:error, :invalid_siwx_chain_id}

      unknown = Map.put(signed_evm(), "chainId", "cosmos:hub")

      assert SIWX.verify({:spec, unknown}, verify_opts()) ==
               {:error, :invalid_siwx_unsupported_chain}

      unlisted = Map.put(signed_evm(), "chainId", "eip155:1")

      assert SIWX.verify({:spec, unlisted}, verify_opts()) ==
               {:error, :invalid_siwx_unsupported_chain}

      wrong_type = Map.put(signed_evm(), "type", "ed25519")

      assert SIWX.verify({:spec, wrong_type}, verify_opts()) ==
               {:error, :invalid_siwx_unsupported_chain}
    end

    test "returns invalid_siwx_malformed_signature" do
      short = Map.put(signed_evm(), "signature", "0x1234")

      assert SIWX.verify({:spec, short}, verify_opts()) ==
               {:error, :invalid_siwx_malformed_signature}

      bad_address = Map.put(signed_evm(), "address", "0x123")

      assert SIWX.verify({:spec, bad_address}, verify_opts()) ==
               {:error, :invalid_siwx_malformed_signature}

      assert SIWX.verify({:spec, signed_evm()}, verify_opts(evm_verifier: MalformedVerifier)) ==
               {:error, :invalid_siwx_malformed_signature}

      assert SIWX.verify(
               {:spec, signed_evm()},
               verify_opts(evm_verifier: InvalidAddressVerifier)
             ) ==
               {:error, :invalid_siwx_malformed_signature}

      {:ok, solana} = SolanaKey.new(@solana_seed)
      {:ok, signed_solana} = SIWX.sign(challenge(), solana, chain_id: @solana_chain)

      assert SIWX.verify({:spec, Map.put(signed_solana, "address", "nope")}, verify_opts()) ==
               {:error, :invalid_siwx_malformed_signature}

      assert SIWX.verify({:spec, Map.put(signed_solana, "signature", "111")}, verify_opts()) ==
               {:error, :invalid_siwx_malformed_signature}
    end

    test "returns invalid_siwx_signature when the signer does not control the address" do
      {:ok, other} = LocalKey.new(@other_private_key)

      assert {:ok, forged} =
               SIWX.sign(challenge(), other, chain_id: @evm_chain, address: @address)

      assert SIWX.verify({:spec, forged}, verify_opts()) == {:error, :invalid_siwx_signature}

      tampered = Map.put(signed_evm(), "statement", "changed")
      assert SIWX.verify({:spec, tampered}, verify_opts()) == {:error, :invalid_siwx_signature}
    end

    test "returns invalid_siwx_verifier_error when the verifier fails or raises" do
      assert SIWX.verify({:spec, signed_evm()}, verify_opts(evm_verifier: ErrorVerifier)) ==
               {:error, :invalid_siwx_verifier_error}

      assert SIWX.verify({:spec, signed_evm()}, verify_opts(evm_verifier: RaisingVerifier)) ==
               {:error, :invalid_siwx_verifier_error}

      assert SIWX.verify({:spec, signed_evm()}, verify_opts(evm_verifier: GarbageVerifier)) ==
               {:error, :invalid_siwx_verifier_error}
    end

    test "verifies legacy proofs over the signed text" do
      {:ok, {:legacy, proof} = decoded} = legacy_header() |> SIWX.decode_signed()

      assert {:ok, %{address: @address, chain_id: "eip155:8453", fields: fields}} =
               SIWX.verify(decoded, verify_opts())

      assert fields["type"] == "eip191"
      assert fields["statement"] == "Access purchased content"

      {:ok, other} = LocalKey.new(@other_private_key)
      {:ok, forged_signature} = LocalKey.sign_message(other, proof["message"])
      forged = {:legacy, Map.put(proof, "signature", forged_signature)}
      assert SIWX.verify(forged, verify_opts()) == {:error, :invalid_siwx_signature}

      garbage = {:legacy, Map.put(proof, "signature", "0x" <> String.duplicate("00", 65))}
      assert SIWX.verify(garbage, verify_opts()) == {:error, :invalid_siwx_malformed_signature}
    end

    test "raises for invalid options" do
      assert_raise NimbleOptions.ValidationError, fn ->
        SIWX.verify({:spec, signed_evm()}, domain: @domain)
      end

      assert_raise NimbleOptions.ValidationError, ~r/nonce_cache/, fn ->
        SIWX.verify({:spec, signed_evm()}, verify_opts(nonce_cache: "not-an-adapter"))
      end
    end
  end

  describe "legacy_notice/1" do
    test "emits telemetry and logs a warning once" do
      handler_id = {__MODULE__, :legacy}
      test_pid = self()

      :telemetry.attach(
        handler_id,
        [:x402, :siwx, :legacy],
        fn name, measurements, metadata, _config ->
          send(test_pid, {:telemetry, name, measurements, metadata})
        end,
        nil
      )

      on_exit(fn -> :telemetry.detach(handler_id) end)

      :persistent_term.erase({SIWX, :legacy_format_warned})

      log = capture_log(fn -> assert :ok = SIWX.legacy_notice(:gate) end)
      assert log =~ "deprecated"

      assert_receive {:telemetry, [:x402, :siwx, :legacy], %{count: 1},
                      %{status: :ok, source: :gate}}

      assert capture_log(fn -> SIWX.legacy_notice(:gate) end) == ""
      assert_receive {:telemetry, [:x402, :siwx, :legacy], _measurements, _metadata}
    end
  end

  describe "encode/1 and decode/1" do
    test "roundtrips a valid SIWX payload" do
      payload = legacy_payload()

      assert {:ok, message} = SIWX.encode(payload)
      assert {:ok, ^payload} = SIWX.decode(message)
    end

    test "renders the strict EIP-4361 text" do
      assert {:ok, message} = SIWX.encode(legacy_payload())

      assert message ==
               """
               example.com wants you to sign in with your Ethereum account:
               0x1111111111111111111111111111111111111111

               Access purchased content

               URI: https://example.com/protected
               Version: 1
               Chain ID: 1
               Nonce: abc12345
               Issued At: 2026-02-16T12:00:00Z
               Expiration Time: 2026-02-16T13:00:00Z\
               """
    end

    test "supports integer chain_id on encode" do
      payload = Map.put(legacy_payload(), :chain_id, 8453)

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
      invalid_address = Map.put(legacy_payload(), :address, "0x123")
      assert SIWX.encode(invalid_address) == {:error, {:invalid_field, :address}}

      invalid_chain_id = Map.put(legacy_payload(), :chain_id, "solana:mainnet")
      assert SIWX.encode(invalid_chain_id) == {:error, {:invalid_field, :chain_id}}

      invalid_nonce = Map.put(legacy_payload(), :nonce, "short")
      assert SIWX.encode(invalid_nonce) == {:error, {:invalid_field, :nonce}}

      invalid_version = Map.put(legacy_payload(), :version, "2")
      assert SIWX.encode(invalid_version) == {:error, {:invalid_field, :version}}

      invalid_expiration =
        legacy_payload()
        |> Map.put(:issued_at, "2026-02-16T13:00:00Z")
        |> Map.put(:expiration_time, "2026-02-16T12:00:00Z")

      assert SIWX.encode(invalid_expiration) == {:error, {:invalid_field, :expiration_time}}
    end

    test "returns invalid_message when format is malformed" do
      assert SIWX.decode("not a siwx message") == {:error, :invalid_message}
      assert SIWX.decode(nil) == {:error, :invalid_message}
    end

    test "returns invalid field errors for malformed message fields" do
      payload = legacy_payload()
      {:ok, message} = SIWX.encode(payload)

      invalid_chain_message = String.replace(message, "Chain ID: 1", "Chain ID: abc")
      assert SIWX.decode(invalid_chain_message) == {:error, {:invalid_field, :chain_id}}

      invalid_address_message =
        String.replace(message, payload.address, "0x111111111111111111111111111111111111111")

      assert SIWX.decode(invalid_address_message) == {:error, {:invalid_field, :address}}
    end

    test "rejects messages with an empty domain" do
      {:ok, message} = SIWX.encode(legacy_payload())

      # The first line ends with the SIWE suffix but carries no domain.
      empty_domain_message = String.replace(message, "example.com", "")

      assert SIWX.decode(empty_domain_message) == {:error, {:invalid_field, :domain}}
    end

    test "rejects messages whose first line lacks the SIWE suffix" do
      {:ok, message} = SIWX.encode(legacy_payload())

      # Dropping the leading space breaks the " wants you to sign in..." suffix.
      no_suffix_message = String.replace(message, "example.com wants", "example.com-wants")

      assert SIWX.decode(no_suffix_message) == {:error, :invalid_message}
    end

    test "rejects messages with an empty prefixed field value" do
      {:ok, message} = SIWX.encode(legacy_payload())

      empty_uri_message =
        String.replace(message, "URI: https://example.com/protected", "URI: ")

      assert SIWX.decode(empty_uri_message) == {:error, {:invalid_field, :uri}}
    end

    test "rejects messages with a mislabeled field line" do
      {:ok, message} = SIWX.encode(legacy_payload())

      mislabeled_message = String.replace(message, "Version: 1", "Ver: 1")

      assert SIWX.decode(mislabeled_message) == {:error, :invalid_message}
    end

    test "rejects empty or malformed field values on encode" do
      empty_address = Map.put(legacy_payload(), :address, "")
      assert SIWX.encode(empty_address) == {:error, {:invalid_field, :address}}

      empty_statement = Map.put(legacy_payload(), :statement, "")
      assert SIWX.encode(empty_statement) == {:error, {:invalid_field, :statement}}

      multiline_statement = Map.put(legacy_payload(), :statement, "line one\nline two")
      assert SIWX.encode(multiline_statement) == {:error, {:invalid_field, :statement}}

      empty_uri = Map.put(legacy_payload(), :uri, "")
      assert SIWX.encode(empty_uri) == {:error, {:invalid_field, :uri}}

      schemeless_uri = Map.put(legacy_payload(), :uri, "not-a-uri")
      assert SIWX.encode(schemeless_uri) == {:error, {:invalid_field, :uri}}

      empty_nonce = Map.put(legacy_payload(), :nonce, "")
      assert SIWX.encode(empty_nonce) == {:error, {:invalid_field, :nonce}}

      empty_issued_at = Map.put(legacy_payload(), :issued_at, "")
      assert SIWX.encode(empty_issued_at) == {:error, {:invalid_field, :issued_at}}

      malformed_issued_at = Map.put(legacy_payload(), :issued_at, "yesterday at noon")
      assert SIWX.encode(malformed_issued_at) == {:error, {:invalid_field, :issued_at}}
    end

    test "accepts decimal-string chain ids and rejects non-positive ones" do
      decimal_chain_id = Map.put(legacy_payload(), :chain_id, "8453")
      assert {:ok, message} = SIWX.encode(decimal_chain_id)
      assert {:ok, decoded} = SIWX.decode(message)
      assert decoded.chain_id == "eip155:8453"

      zero_chain_id = Map.put(legacy_payload(), :chain_id, 0)
      assert SIWX.encode(zero_chain_id) == {:error, {:invalid_field, :chain_id}}

      negative_chain_id = Map.put(legacy_payload(), :chain_id, "-1")
      assert SIWX.encode(negative_chain_id) == {:error, {:invalid_field, :chain_id}}

      nil_chain_id = Map.put(legacy_payload(), :chain_id, nil)
      assert SIWX.encode(nil_chain_id) == {:error, {:invalid_field, :chain_id}}
    end
  end

  describe "encode_header/1 and decode_header/1 (deprecated)" do
    setup :legacy_context

    test "roundtrips a valid header payload", %{legacy: legacy} do
      payload = %{message: "sign-in message", signature: "0xabcdef"}

      assert {:ok, encoded_header} = legacy.encode_header(payload)

      assert legacy.decode_header(encoded_header) ==
               {:ok, %{"message" => "sign-in message", "signature" => "0xabcdef"}}
    end

    test "returns invalid payload for malformed encode payloads", %{legacy: legacy} do
      assert legacy.encode_header(nil) == {:error, :invalid_payload}
      assert legacy.encode_header(%{message: "only message"}) == {:error, :invalid_payload}

      assert legacy.encode_header(%{message: "", signature: "0xabc"}) ==
               {:error, :invalid_payload}
    end

    test "returns invalid_json when the payload cannot be JSON-encoded", %{legacy: legacy} do
      invalid_utf8 = <<0xFF, 0xFE>>

      assert legacy.encode_header(%{message: invalid_utf8, signature: "0xabc"}) ==
               {:error, :invalid_json}
    end

    test "returns decode errors for malformed headers", %{legacy: legacy} do
      assert legacy.decode_header("%%") == {:error, :invalid_base64}
      assert legacy.decode_header("") == {:error, :invalid_base64}
      assert legacy.decode_header(nil) == {:error, :invalid_base64}

      invalid_json = Base.encode64("{")
      assert legacy.decode_header(invalid_json) == {:error, :invalid_json}

      not_map = Base.encode64("[]")
      assert legacy.decode_header(not_map) == {:error, :invalid_json}

      missing_signature = Base.encode64(Jason.encode!(%{"message" => "ok"}))
      assert legacy.decode_header(missing_signature) == {:error, :invalid_payload}
    end
  end

  # -- Helpers ----------------------------------------------------------------

  defp evm_signer do
    {:ok, signer} = LocalKey.new(@private_key)
    signer
  end

  defp challenge(opts \\ []) do
    SIWX.challenge(Keyword.merge([domain: @domain, uri: @uri, supported_chains: @chains], opts))
  end

  defp signed_evm(opts \\ []) do
    {:ok, signed} = SIWX.sign(challenge(opts), evm_signer(), chain_id: @evm_chain)
    signed
  end

  defp verify_opts(extra \\ []) do
    Keyword.merge([domain: @domain, uri: @uri, supported_chains: @chains], extra)
  end

  defp start_cache do
    name = String.to_atom("siwx_nonce_cache_#{System.unique_integer([:positive, :monotonic])}")
    start_supervised!({ETSCache, name: name, ttl_ms: 60_000})
    name
  end

  # A pre-0.7.0 header: the signed EIP-4361 text itself plus its signature.
  defp legacy_header do
    now = DateTime.utc_now()

    payload = %{
      legacy_payload()
      | domain: @domain,
        address: @address,
        uri: @uri,
        chain_id: @evm_chain,
        nonce: String.duplicate("ab", 16),
        issued_at: DateTime.to_iso8601(now),
        expiration_time: DateTime.to_iso8601(DateTime.add(now, 300, :second))
    }

    {:ok, message} = SIWX.encode(payload)
    {:ok, signature} = LocalKey.sign_message(evm_signer(), message)
    Base.encode64(Jason.encode!(%{"message" => message, "signature" => signature}))
  end

  defp legacy_payload do
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
