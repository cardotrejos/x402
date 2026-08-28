defmodule X402.Extensions.OfferReceiptTest do
  use ExUnit.Case, async: true

  alias X402.Extensions.OfferReceipt
  alias X402.Extensions.OfferReceipt.JWS
  alias X402.Signer.LocalKey

  doctest X402.Extensions.OfferReceipt

  # Deterministic test key (same key used across the client test suite).
  @private_key "0x" <> String.duplicate("11", 32)

  @resource_url "https://api.example.com/premium-data"
  @asset "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
  @pay_to "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
  @payer "0x857b06519E91e3A54538791bDbb0E22373e36b66"
  @kid "did:web:api.example.com#key-1"

  # Spec §4.4: base64url of {"alg":"ES256K","kid":"did:web:api.example.com#key-1"}
  @spec_jws_header "eyJhbGciOiJFUzI1NksiLCJraWQiOiJkaWQ6d2ViOmFwaS5leGFtcGxlLmNvbSNrZXktMSJ9"

  defp signer do
    {:ok, signer} = LocalKey.new(@private_key)
    signer
  end

  defp offer_payload(overrides \\ []) do
    {:ok, payload} =
      OfferReceipt.offer_payload(
        Keyword.merge(
          [
            resource_url: @resource_url,
            scheme: "exact",
            network: "eip155:8453",
            asset: @asset,
            pay_to: @pay_to,
            amount: "10000",
            valid_until: 1_703_123_516
          ],
          overrides
        )
      )

    payload
  end

  defp receipt_payload(overrides \\ []) do
    {:ok, payload} =
      OfferReceipt.receipt_payload(
        Keyword.merge(
          [
            resource_url: @resource_url,
            network: "eip155:8453",
            payer: @payer,
            issued_at: 1_703_123_456
          ],
          overrides
        )
      )

    payload
  end

  # Independent digest compositions straight from the specification text
  # (§3.2 domain, §4.3 / §5.3 types), so a regression in the module's hashing
  # cannot cancel itself out.

  @domain_type "EIP712Domain(string name,string version,uint256 chainId)"
  @offer_type "Offer(uint256 version,string resourceUrl,string scheme,string network," <>
                "string asset,string payTo,string amount,uint256 validUntil)"
  @receipt_type "Receipt(uint256 version,string network,string resourceUrl,string payer," <>
                  "uint256 issuedAt,string transaction)"

  defp manual_domain_separator(name) do
    ExKeccak.hash_256(
      ExKeccak.hash_256(@domain_type) <>
        ExKeccak.hash_256(name) <>
        ExKeccak.hash_256("1") <>
        <<1::unsigned-big-integer-size(256)>>
    )
  end

  defp manual_offer_digest(payload) do
    struct_hash =
      ExKeccak.hash_256(
        ExKeccak.hash_256(@offer_type) <>
          <<payload["version"]::unsigned-big-integer-size(256)>> <>
          ExKeccak.hash_256(payload["resourceUrl"]) <>
          ExKeccak.hash_256(payload["scheme"]) <>
          ExKeccak.hash_256(payload["network"]) <>
          ExKeccak.hash_256(payload["asset"]) <>
          ExKeccak.hash_256(payload["payTo"]) <>
          ExKeccak.hash_256(payload["amount"]) <>
          <<Map.get(payload, "validUntil", 0)::unsigned-big-integer-size(256)>>
      )

    ExKeccak.hash_256(<<0x19, 0x01>> <> manual_domain_separator("x402 offer") <> struct_hash)
  end

  defp manual_receipt_digest(payload) do
    struct_hash =
      ExKeccak.hash_256(
        ExKeccak.hash_256(@receipt_type) <>
          <<payload["version"]::unsigned-big-integer-size(256)>> <>
          ExKeccak.hash_256(payload["network"]) <>
          ExKeccak.hash_256(payload["resourceUrl"]) <>
          ExKeccak.hash_256(payload["payer"]) <>
          <<payload["issuedAt"]::unsigned-big-integer-size(256)>> <>
          ExKeccak.hash_256(Map.get(payload, "transaction", ""))
      )

    ExKeccak.hash_256(<<0x19, 0x01>> <> manual_domain_separator("x402 receipt") <> struct_hash)
  end

  describe "offer_payload/1" do
    test "converts integer amounts to strings (EIP-712 amount is a string)" do
      assert offer_payload(amount: 10_000)["amount"] == "10000"
    end

    test "omits validUntil when not given" do
      {:ok, payload} =
        OfferReceipt.offer_payload(
          resource_url: @resource_url,
          scheme: "exact",
          network: "eip155:8453",
          asset: @asset,
          pay_to: @pay_to,
          amount: "10000"
        )

      refute Map.has_key?(payload, "validUntil")
    end

    test "raises on missing required options (programmer error)" do
      assert_raise NimbleOptions.ValidationError, fn ->
        OfferReceipt.offer_payload(resource_url: @resource_url)
      end
    end
  end

  describe "receipt_payload/1" do
    test "defaults issuedAt to the current time" do
      before = System.os_time(:second)

      {:ok, payload} =
        OfferReceipt.receipt_payload(
          resource_url: @resource_url,
          network: "eip155:8453",
          payer: @payer
        )

      assert payload["issuedAt"] >= before
      assert payload["issuedAt"] <= System.os_time(:second)
    end

    test "includes transaction only when given" do
      refute Map.has_key?(receipt_payload(), "transaction")
      assert receipt_payload(transaction: "0xabc")["transaction"] == "0xabc"
    end
  end

  describe "EIP-712 digests (spec §3.2, §4.3, §5.3)" do
    test "offer digest matches an independent composition of the spec formula" do
      payload = offer_payload()
      assert {:ok, digest} = OfferReceipt.offer_digest(payload)
      assert digest == manual_offer_digest(payload)
    end

    test "receipt digest matches an independent composition of the spec formula" do
      payload = receipt_payload(transaction: "0x" <> String.duplicate("ab", 32))
      assert {:ok, digest} = OfferReceipt.receipt_digest(payload)
      assert digest == manual_receipt_digest(payload)
    end

    test "absent validUntil hashes as zero and equals an explicit zero (§4.3)" do
      without = Map.delete(offer_payload(), "validUntil")
      with_zero = Map.put(without, "validUntil", 0)

      assert OfferReceipt.offer_digest(without) == OfferReceipt.offer_digest(with_zero)
    end

    test "absent transaction hashes as the empty string (§5.3)" do
      without = receipt_payload()
      with_empty = Map.put(without, "transaction", "")

      assert OfferReceipt.receipt_digest(without) == OfferReceipt.receipt_digest(with_empty)
    end

    test "missing required payload fields are structured errors" do
      assert {:error, {:missing_field, "amount"}} =
               offer_payload() |> Map.delete("amount") |> OfferReceipt.offer_digest()

      assert {:error, {:missing_field, "payer"}} =
               receipt_payload() |> Map.delete("payer") |> OfferReceipt.receipt_digest()
    end

    test "uint256-overflowing fields fail closed instead of truncating" do
      huge = Integer.pow(2, 256)

      assert {:error, {:invalid_field, "validUntil"}} =
               offer_payload() |> Map.put("validUntil", huge) |> OfferReceipt.offer_digest()

      assert {:error, {:invalid_field, "issuedAt"}} =
               receipt_payload() |> Map.put("issuedAt", huge) |> OfferReceipt.receipt_digest()
    end

    test "mistyped fields are structured errors" do
      assert {:error, {:invalid_field, "resourceUrl"}} =
               offer_payload() |> Map.put("resourceUrl", 42) |> OfferReceipt.offer_digest()

      assert {:error, {:invalid_field, "issuedAt"}} =
               receipt_payload() |> Map.put("issuedAt", "soon") |> OfferReceipt.receipt_digest()
    end
  end

  describe "sign_offer/3 and verify_offer/2 (EIP-712)" do
    test "produces the transmitted envelope shape from §3.1 / §4.4" do
      assert {:ok, offer} = OfferReceipt.sign_offer(offer_payload(), signer(), accept_index: 0)

      assert Map.keys(offer) |> Enum.sort() == ["acceptIndex", "format", "payload", "signature"]
      assert offer["format"] == "eip712"
      assert offer["acceptIndex"] == 0
      assert offer["payload"] == offer_payload()
      assert String.match?(offer["signature"], ~r/^0x[0-9a-f]{130}$/)
    end

    test "verified payloads strip unsigned extra keys" do
      # Only the canonical fields enter the struct hash — an extra key added
      # after signing must not come back looking signed.
      assert {:ok, offer} = OfferReceipt.sign_offer(offer_payload(), signer())

      inflated = put_in(offer, ["payload", "unsignedNote"], "added in transit")

      assert {:ok, %{payload: verified}} = OfferReceipt.verify_offer(inflated)
      refute Map.has_key?(verified, "unsignedNote")
    end

    test "an absent validUntil is signed and transmitted as 0 (§4.3)" do
      payload = Map.delete(offer_payload(), "validUntil")
      assert {:ok, offer} = OfferReceipt.sign_offer(payload, signer())
      assert offer["payload"]["validUntil"] == 0
      refute Map.has_key?(offer, "acceptIndex")
    end

    test "round-trips: verification recovers the signing address" do
      signer = signer()
      assert {:ok, offer} = OfferReceipt.sign_offer(offer_payload(), signer)

      assert {:ok, %{format: "eip712", signer: recovered, payload: payload}} =
               OfferReceipt.verify_offer(offer)

      assert recovered == signer.address
      assert payload == offer["payload"]
    end

    test "accepts a matching :expected_signer case-insensitively" do
      signer = signer()
      assert {:ok, offer} = OfferReceipt.sign_offer(offer_payload(), signer)

      upcased = "0x" <> String.upcase(String.trim_leading(signer.address, "0x"))
      assert {:ok, _verified} = OfferReceipt.verify_offer(offer, expected_signer: upcased)
    end

    test "rejects a non-matching :expected_signer (§4.5.1 authorization)" do
      assert {:ok, offer} = OfferReceipt.sign_offer(offer_payload(), signer())

      assert {:error, :unauthorized_signer} =
               OfferReceipt.verify_offer(offer, expected_signer: @pay_to)
    end

    test "a tampered payload no longer recovers the signing address" do
      signer = signer()
      assert {:ok, offer} = OfferReceipt.sign_offer(offer_payload(), signer)

      tampered = put_in(offer, ["payload", "amount"], "1")
      assert {:ok, %{signer: recovered}} = OfferReceipt.verify_offer(tampered)
      assert recovered != signer.address

      assert {:error, :unauthorized_signer} =
               OfferReceipt.verify_offer(tampered, expected_signer: signer.address)
    end

    test "rejects unknown payload versions (§4.5)" do
      assert {:ok, offer} = OfferReceipt.sign_offer(offer_payload(), signer())
      unversioned = put_in(offer, ["payload", "version"], 2)

      assert {:error, {:unsupported_payload_version, 2}} =
               OfferReceipt.verify_offer(unversioned)
    end

    test "rejects malformed envelopes" do
      assert {:error, :invalid_envelope} = OfferReceipt.verify_offer(%{"format" => "eip712"})
      assert {:error, :invalid_envelope} = OfferReceipt.verify_offer(%{})

      assert {:error, {:unsupported_format, "pgp"}} =
               OfferReceipt.verify_offer(%{"format" => "pgp", "signature" => "sig"})
    end
  end

  describe "sign_receipt/2 and verify_receipt/2 (EIP-712)" do
    test "an absent transaction is signed and transmitted as \"\" (§5.3)" do
      assert {:ok, receipt} = OfferReceipt.sign_receipt(receipt_payload(), signer())
      assert receipt["payload"]["transaction"] == ""
      assert Map.keys(receipt) |> Enum.sort() == ["format", "payload", "signature"]
    end

    test "round-trips with and without a transaction hash" do
      signer = signer()

      for overrides <- [[], [transaction: "0x" <> String.duplicate("ab", 32)]] do
        payload = receipt_payload(overrides)
        assert {:ok, receipt} = OfferReceipt.sign_receipt(payload, signer)

        assert {:ok, %{format: "eip712", signer: recovered}} =
                 OfferReceipt.verify_receipt(receipt, expected_signer: signer.address)

        assert recovered == signer.address
      end
    end

    test "a tampered payer fails the expected-signer check" do
      signer = signer()
      assert {:ok, receipt} = OfferReceipt.sign_receipt(receipt_payload(), signer)

      tampered = put_in(receipt, ["payload", "payer"], @pay_to)

      assert {:error, :unauthorized_signer} =
               OfferReceipt.verify_receipt(tampered, expected_signer: signer.address)
    end
  end

  describe "JWS artifacts" do
    setup do
      {public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      {secp_public, secp_private} = :crypto.generate_key(:ecdh, :secp256k1)
      %{ed: {public, seed}, secp: {secp_public, secp_private}}
    end

    test "sign_offer_jws/2 omits the payload from the envelope (§3.1.1)", %{ed: {_pub, seed}} do
      assert {:ok, offer} =
               OfferReceipt.sign_offer_jws(offer_payload(),
                 alg: "EdDSA",
                 kid: @kid,
                 key: seed,
                 accept_index: 0
               )

      assert Map.keys(offer) |> Enum.sort() == ["acceptIndex", "format", "signature"]
      assert offer["format"] == "jws"
      refute Map.has_key?(offer, "payload")
    end

    test "the protected header matches the spec's §4.4 example encoding", %{secp: {_pub, priv}} do
      assert {:ok, offer} =
               OfferReceipt.sign_offer_jws(offer_payload(), alg: "ES256K", kid: @kid, key: priv)

      assert [@spec_jws_header, _payload, _signature] = String.split(offer["signature"], ".")
    end

    test "the JWS payload segment is JCS-canonicalized (§10)", %{ed: {_pub, seed}} do
      payload = offer_payload()

      assert {:ok, offer} =
               OfferReceipt.sign_offer_jws(payload, alg: "EdDSA", kid: @kid, key: seed)

      [_header, payload_b64, _signature] = String.split(offer["signature"], ".")
      assert {:ok, canonical} = JWS.canonicalize(payload)
      assert Base.url_decode64!(payload_b64, padding: false) == canonical
    end

    test "offer round-trips through verify_offer/2", %{ed: {public, seed}} do
      payload = offer_payload()

      assert {:ok, offer} =
               OfferReceipt.sign_offer_jws(payload, alg: "EdDSA", kid: @kid, key: seed)

      assert {:ok, %{format: "jws", header: header, payload: verified}} =
               OfferReceipt.verify_offer(offer, public_key: public)

      assert header == %{"alg" => "EdDSA", "kid" => @kid}
      assert verified == payload
    end

    test "receipt round-trips through verify_receipt/2 with ES256K", %{secp: {public, priv}} do
      payload = receipt_payload()

      assert {:ok, receipt} =
               OfferReceipt.sign_receipt_jws(payload, alg: "ES256K", kid: @kid, key: priv)

      assert {:ok, %{format: "jws", payload: verified}} =
               OfferReceipt.verify_receipt(receipt, public_key: public)

      assert verified == payload
    end

    test "rejects a verified JWS whose payload is not a JSON object", %{ed: {public, seed}} do
      # A validly signed JWS over a JSON array: the signature checks out,
      # but the payload cannot be an offer or receipt.
      header = Base.url_encode64(~s({"alg":"EdDSA","kid":"#{@kid}"}), padding: false)
      payload = Base.url_encode64("[1]", padding: false)
      signing_input = header <> "." <> payload
      signature = :crypto.sign(:eddsa, :none, signing_input, [seed, :ed25519])
      jws = signing_input <> "." <> Base.url_encode64(signature, padding: false)

      assert {:error, :invalid_envelope} =
               OfferReceipt.verify_offer(%{"format" => "jws", "signature" => jws},
                 public_key: public
               )
    end

    test "a signed offer JWS never verifies as a receipt (kind confusion)", %{ed: {public, seed}} do
      # A public offer JWS is signed by the same key that signs receipts — if
      # verify_receipt accepted it, an attacker could present the published
      # offer as forged settlement evidence.
      assert {:ok, offer} =
               OfferReceipt.sign_offer_jws(offer_payload(), alg: "EdDSA", kid: @kid, key: seed)

      assert {:error, _kind_mismatch} = OfferReceipt.verify_receipt(offer, public_key: public)

      assert {:ok, receipt} =
               OfferReceipt.sign_receipt_jws(receipt_payload(),
                 alg: "EdDSA",
                 kid: @kid,
                 key: seed
               )

      assert {:error, _kind_mismatch2} = OfferReceipt.verify_offer(receipt, public_key: public)
    end

    test "optional fields stay omitted in JWS payloads", %{ed: {public, seed}} do
      payload = Map.delete(offer_payload(), "validUntil")

      assert {:ok, offer} =
               OfferReceipt.sign_offer_jws(payload, alg: "EdDSA", kid: @kid, key: seed)

      assert {:ok, %{payload: verified}} = OfferReceipt.verify_offer(offer, public_key: public)
      refute Map.has_key?(verified, "validUntil")
    end

    test "verification requires a public key", %{ed: {_public, seed}} do
      assert {:ok, offer} =
               OfferReceipt.sign_offer_jws(offer_payload(), alg: "EdDSA", kid: @kid, key: seed)

      assert {:error, :missing_public_key} = OfferReceipt.verify_offer(offer)
    end

    test "a tampered JWS payload is rejected", %{ed: {public, seed}} do
      assert {:ok, offer} =
               OfferReceipt.sign_offer_jws(offer_payload(), alg: "EdDSA", kid: @kid, key: seed)

      [header, payload_b64, signature] = String.split(offer["signature"], ".")

      forged_payload =
        payload_b64
        |> Base.url_decode64!(padding: false)
        |> String.replace("10000", "20000")
        |> Base.url_encode64(padding: false)

      forged = %{offer | "signature" => Enum.join([header, forged_payload, signature], ".")}

      assert {:error, :signature_mismatch} = OfferReceipt.verify_offer(forged, public_key: public)
    end

    test "the :algs allowlist is enforced", %{secp: {public, priv}} do
      assert {:ok, offer} =
               OfferReceipt.sign_offer_jws(offer_payload(), alg: "ES256K", kid: @kid, key: priv)

      assert {:error, {:unsupported_algorithm, "ES256K"}} =
               OfferReceipt.verify_offer(offer, public_key: public, algs: ["EdDSA"])
    end

    test "signing validates the payload first", %{ed: {_public, seed}} do
      assert {:error, {:missing_field, "amount"}} =
               offer_payload()
               |> Map.delete("amount")
               |> OfferReceipt.sign_offer_jws(alg: "EdDSA", kid: @kid, key: seed)

      assert {:error, {:missing_field, "payer"}} =
               receipt_payload()
               |> Map.delete("payer")
               |> OfferReceipt.sign_receipt_jws(alg: "EdDSA", kid: @kid, key: seed)
    end
  end

  describe "validate_offer/1 and validate_receipt/1" do
    test "accepts valid EIP-712 and JWS envelopes" do
      assert {:ok, eip712} = OfferReceipt.sign_offer(offer_payload(), signer(), accept_index: 1)
      assert :ok = OfferReceipt.validate_offer(eip712)

      {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)

      assert {:ok, jws} =
               OfferReceipt.sign_offer_jws(offer_payload(), alg: "EdDSA", kid: @kid, key: seed)

      assert :ok = OfferReceipt.validate_offer(jws)
    end

    test "rejects EIP-712 envelopes without a payload" do
      assert {:error, {:missing_field, "payload"}} =
               OfferReceipt.validate_offer(%{"format" => "eip712", "signature" => "0x00"})
    end

    test "rejects EIP-712 envelopes with malformed signatures" do
      {:ok, offer} = OfferReceipt.sign_offer(offer_payload(), signer())

      assert {:error, :invalid_signature} =
               OfferReceipt.validate_offer(Map.put(offer, "signature", "0xdead"))

      assert {:error, :invalid_signature} =
               OfferReceipt.validate_offer(
                 Map.put(offer, "signature", "0x" <> String.duplicate("zz", 65))
               )
    end

    test "rejects JWS envelopes that carry a payload (§3.1.1)" do
      assert {:error, {:invalid_field, "payload"}} =
               OfferReceipt.validate_offer(%{
                 "format" => "jws",
                 "payload" => %{"version" => 1},
                 "signature" => "a.b.c"
               })
    end

    test "rejects JWS envelopes without a compact serialization" do
      assert {:error, :invalid_jws} =
               OfferReceipt.validate_offer(%{"format" => "jws", "signature" => "onlyonepart"})
    end

    test "rejects unknown formats and missing formats" do
      assert {:error, {:unsupported_format, "pgp"}} =
               OfferReceipt.validate_offer(%{"format" => "pgp", "signature" => "sig"})

      assert {:error, {:missing_field, "format"}} = OfferReceipt.validate_offer(%{})
    end

    test "rejects non-integer acceptIndex values" do
      {:ok, offer} = OfferReceipt.sign_offer(offer_payload(), signer())

      assert {:error, {:invalid_field, "acceptIndex"}} =
               OfferReceipt.validate_offer(Map.put(offer, "acceptIndex", "first"))
    end

    test "validates receipt payload fields" do
      {:ok, receipt} = OfferReceipt.sign_receipt(receipt_payload(), signer())
      assert :ok = OfferReceipt.validate_receipt(receipt)

      missing = update_in(receipt, ["payload"], &Map.delete(&1, "issuedAt"))
      assert {:error, {:missing_field, "issuedAt"}} = OfferReceipt.validate_receipt(missing)

      mistyped = put_in(receipt, ["payload", "transaction"], 7)
      assert {:error, {:invalid_field, "transaction"}} = OfferReceipt.validate_receipt(mistyped)
    end

    test "rejects envelopes that are not maps" do
      assert {:error, :invalid_envelope} = OfferReceipt.validate_offer("nope")
      assert {:error, :invalid_envelope} = OfferReceipt.validate_receipt(nil)
    end

    test "rejects an EIP-712 envelope whose payload is not a map" do
      assert {:error, {:invalid_field, "payload"}} =
               OfferReceipt.validate_offer(%{
                 "format" => "eip712",
                 "payload" => "nope",
                 "signature" => "0x00"
               })
    end

    test "rejects a JWS envelope without a signature" do
      assert {:error, :invalid_jws} = OfferReceipt.validate_offer(%{"format" => "jws"})
    end

    test "rejects mistyped string fields in offer payloads" do
      {:ok, offer} = OfferReceipt.sign_offer(offer_payload(), signer())

      mistyped = put_in(offer, ["payload", "resourceUrl"], 123)

      assert {:error, {:invalid_field, "resourceUrl"}} =
               OfferReceipt.validate_offer(mistyped)
    end

    test "rejects a mistyped validUntil in offer payloads" do
      {:ok, offer} = OfferReceipt.sign_offer(offer_payload(), signer())

      mistyped = put_in(offer, ["payload", "validUntil"], "later")

      assert {:error, {:invalid_field, "validUntil"}} =
               OfferReceipt.validate_offer(mistyped)
    end

    test "rejects a mistyped issuedAt in receipt payloads" do
      {:ok, receipt} = OfferReceipt.sign_receipt(receipt_payload(), signer())

      mistyped = put_in(receipt, ["payload", "issuedAt"], "soon")

      assert {:error, {:invalid_field, "issuedAt"}} =
               OfferReceipt.validate_receipt(mistyped)
    end
  end

  describe "build_extension/1" do
    test "wraps offers in the info/schema declaration with the §6.1 schema" do
      {:ok, offer} = OfferReceipt.sign_offer(offer_payload(), signer(), accept_index: 0)
      extension = OfferReceipt.build_extension([offer])

      assert extension["info"] == %{"offers" => [offer]}

      assert extension["schema"] == %{
               "$schema" => "https://json-schema.org/draft/2020-12/schema",
               "type" => "object",
               "properties" => %{
                 "offers" => %{
                   "type" => "array",
                   "items" => %{
                     "type" => "object",
                     "properties" => %{
                       "format" => %{"type" => "string", "const" => "eip712"},
                       "acceptIndex" => %{"type" => "integer"},
                       "payload" => %{
                         "type" => "object",
                         "properties" => %{
                           "version" => %{"type" => "integer"},
                           "resourceUrl" => %{"type" => "string"},
                           "scheme" => %{"type" => "string"},
                           "network" => %{"type" => "string"},
                           "asset" => %{"type" => "string"},
                           "payTo" => %{"type" => "string"},
                           "amount" => %{"type" => "string"},
                           "validUntil" => %{"type" => "integer"}
                         },
                         "required" => [
                           "version",
                           "resourceUrl",
                           "scheme",
                           "network",
                           "asset",
                           "payTo",
                           "amount"
                         ]
                       },
                       "signature" => %{"type" => "string"}
                     },
                     "required" => ["format", "payload", "signature"]
                   }
                 }
               },
               "required" => ["offers"]
             }
    end

    test "builds the §6.3 schema for JWS offers" do
      {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)

      {:ok, offer} =
        OfferReceipt.sign_offer_jws(offer_payload(), alg: "EdDSA", kid: @kid, key: seed)

      extension = OfferReceipt.build_extension([offer])

      assert extension["schema"]["properties"]["offers"]["items"] == %{
               "type" => "object",
               "properties" => %{
                 "format" => %{"type" => "string", "const" => "jws"},
                 "acceptIndex" => %{"type" => "integer"},
                 "signature" => %{
                   "type" => "string",
                   "description" => "JWS compact serialization containing the offer payload"
                 }
               },
               "required" => ["format", "signature"]
             }
    end

    test "raises on empty lists, mixed formats, and invalid offers" do
      {:ok, eip712} = OfferReceipt.sign_offer(offer_payload(), signer())
      {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)

      {:ok, jws} =
        OfferReceipt.sign_offer_jws(offer_payload(), alg: "EdDSA", kid: @kid, key: seed)

      assert_raise ArgumentError, fn -> OfferReceipt.build_extension([]) end
      assert_raise ArgumentError, fn -> OfferReceipt.build_extension([eip712, jws]) end

      assert_raise ArgumentError, fn ->
        OfferReceipt.build_extension([Map.delete(eip712, "payload")])
      end
    end
  end

  describe "build_receipt_extension/1" do
    test "wraps the receipt with the §6.5 schema (EIP-712)" do
      {:ok, receipt} = OfferReceipt.sign_receipt(receipt_payload(), signer())
      extension = OfferReceipt.build_receipt_extension(receipt)

      assert extension["info"] == %{"receipt" => receipt}

      assert extension["schema"] == %{
               "$schema" => "https://json-schema.org/draft/2020-12/schema",
               "type" => "object",
               "properties" => %{
                 "receipt" => %{
                   "type" => "object",
                   "properties" => %{
                     "format" => %{"type" => "string", "const" => "eip712"},
                     "payload" => %{
                       "type" => "object",
                       "properties" => %{
                         "version" => %{"type" => "integer"},
                         "network" => %{"type" => "string"},
                         "resourceUrl" => %{"type" => "string"},
                         "payer" => %{"type" => "string"},
                         "issuedAt" => %{"type" => "integer"},
                         "transaction" => %{"type" => "string"}
                       },
                       "required" => ["version", "network", "resourceUrl", "payer", "issuedAt"]
                     },
                     "signature" => %{"type" => "string"}
                   },
                   "required" => ["format", "payload", "signature"]
                 }
               },
               "required" => ["receipt"]
             }
    end

    test "builds the §6.7 schema for JWS receipts" do
      {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)

      {:ok, receipt} =
        OfferReceipt.sign_receipt_jws(receipt_payload(), alg: "EdDSA", kid: @kid, key: seed)

      extension = OfferReceipt.build_receipt_extension(receipt)

      assert extension["schema"]["properties"]["receipt"] == %{
               "type" => "object",
               "properties" => %{
                 "format" => %{"type" => "string", "const" => "jws"},
                 "signature" => %{
                   "type" => "string",
                   "description" => "JWS compact serialization containing the receipt payload"
                 }
               },
               "required" => ["format", "signature"]
             }
    end

    test "raises on invalid receipts" do
      assert_raise ArgumentError, fn ->
        OfferReceipt.build_receipt_extension(%{"format" => "eip712"})
      end

      assert_raise ArgumentError, fn -> OfferReceipt.build_receipt_extension("receipt") end
    end
  end

  describe "fetch_offers/1 and fetch_receipt/1" do
    setup do
      {:ok, offer} = OfferReceipt.sign_offer(offer_payload(), signer(), accept_index: 0)
      {:ok, receipt} = OfferReceipt.sign_receipt(receipt_payload(), signer())
      %{offer: offer, receipt: receipt}
    end

    test "reads offers from a full payment-required map", %{offer: offer} do
      payment_required = %{
        "x402Version" => 2,
        "accepts" => [],
        "extensions" => %{"offer-receipt" => OfferReceipt.build_extension([offer])}
      }

      assert {:ok, [^offer]} = OfferReceipt.fetch_offers(payment_required)
    end

    test "reads offers from a bare extensions map", %{offer: offer} do
      extensions = %{"offer-receipt" => OfferReceipt.build_extension([offer])}
      assert {:ok, [^offer]} = OfferReceipt.fetch_offers(extensions)
    end

    test "reports absence and malformed declarations" do
      assert {:error, :extension_not_present} = OfferReceipt.fetch_offers(%{"accepts" => []})

      assert {:error, {:invalid_extension, {:missing_field, "info"}}} =
               OfferReceipt.fetch_offers(%{"offer-receipt" => %{"schema" => %{}}})

      assert {:error, {:invalid_extension, {:missing_field, "offers"}}} =
               OfferReceipt.fetch_offers(%{"offer-receipt" => %{"info" => %{}}})

      assert {:error, {:invalid_extension, :not_a_map}} =
               OfferReceipt.fetch_offers(%{"offer-receipt" => "yes"})
    end

    test "is fail-closed on a structurally invalid offer", %{offer: offer} do
      broken = Map.delete(offer, "signature")

      extensions = %{"offer-receipt" => %{"info" => %{"offers" => [offer, broken]}}}

      assert {:error, {:invalid_extension, {:invalid_offer, 1, :invalid_signature}}} =
               OfferReceipt.fetch_offers(extensions)

      assert {:error, {:invalid_extension, {:invalid_offer, 0, :invalid_envelope}}} =
               OfferReceipt.fetch_offers(%{"offer-receipt" => %{"info" => %{"offers" => ["x"]}}})
    end

    test "reads and validates the settlement receipt", %{receipt: receipt} do
      settlement = %{
        "success" => true,
        "extensions" => %{"offer-receipt" => OfferReceipt.build_receipt_extension(receipt)}
      }

      assert {:ok, ^receipt} = OfferReceipt.fetch_receipt(settlement)

      assert {:error, :extension_not_present} = OfferReceipt.fetch_receipt(%{"success" => true})

      assert {:error, {:invalid_extension, {:missing_field, "receipt"}}} =
               OfferReceipt.fetch_receipt(%{"offer-receipt" => %{"info" => %{}}})

      broken = update_in(receipt, ["payload"], &Map.delete(&1, "network"))

      assert {:error, {:invalid_extension, {:missing_field, "network"}}} =
               OfferReceipt.fetch_receipt(%{
                 "offer-receipt" => %{"info" => %{"receipt" => broken}}
               })
    end
  end

  describe "extract_payload/1" do
    test "decodes the JWS payload without verification" do
      {_public, seed} = :crypto.generate_key(:eddsa, :ed25519)
      payload = offer_payload()

      {:ok, offer} = OfferReceipt.sign_offer_jws(payload, alg: "EdDSA", kid: @kid, key: seed)
      assert {:ok, ^payload} = OfferReceipt.extract_payload(offer)
    end

    test "rejects malformed envelopes" do
      assert {:error, {:missing_field, "signature"}} =
               OfferReceipt.extract_payload(%{"format" => "jws"})

      assert {:error, {:missing_field, "payload"}} =
               OfferReceipt.extract_payload(%{"format" => "eip712", "payload" => "nope"})

      assert {:error, :invalid_envelope} = OfferReceipt.extract_payload(%{})
    end
  end
end
