defmodule X402.Extensions.OfferReceipt do
  @moduledoc """
  Offer-and-receipt extension for x402: signed offers and signed receipts.

  Implements the
  [offer-and-receipt extension](https://github.com/x402-foundation/x402/blob/main/specs/extensions/extension-offer-and-receipt.md):
  the resource server cryptographically commits to the payment terms it
  advertises (a **signed offer** placed under
  `extensions["offer-receipt"].info.offers[]` of the payment requirements)
  and, after successful payment and delivery, confirms the transaction (a
  **signed receipt** under `extensions["offer-receipt"].info.receipt` of the
  settlement response). Both artifacts are portable, independently
  verifiable, and identical for x402 v1 and v2.

  Two signature formats are supported, per the specification (§3.1):

    * `"eip712"` — an EIP-712 typed-data signature with the fixed domain
      `{name: "x402 offer" | "x402 receipt", version: "1", chainId: 1}`
      (chain-agnostic by design, §3.2) and the canonical `Offer` / `Receipt`
      types from §4.3 and §5.3. Signing goes through the `X402.Signer`
      behaviour; verification recovers the signer address. Requires the
      optional `ex_keccak` (and, for verification, `ex_secp256k1`)
      dependencies.
    * `"jws"` — a compact JWS (`header.payload.signature`) with `ES256K` or
      `EdDSA`, implemented with OTP `:crypto` by
      `X402.Extensions.OfferReceipt.JWS`. The protected header carries the
      mandatory `alg` and `kid` (a DID URL) fields (§3.3); payloads are
      JCS-canonicalized (§10).

  ## Server side: issuing offers and receipts

      {:ok, signer} = X402.Signer.LocalKey.new(private_key)

      {:ok, payload} =
        X402.Extensions.OfferReceipt.offer_payload(
          resource_url: "https://api.example.com/premium-data",
          scheme: "exact",
          network: "eip155:8453",
          asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
          pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
          amount: "10000",
          valid_until: System.os_time(:second) + 300
        )

      {:ok, offer} = X402.Extensions.OfferReceipt.sign_offer(payload, signer, accept_index: 0)

      extensions = %{"offer-receipt" => X402.Extensions.OfferReceipt.build_extension([offer])}

  ## Client side: verifying

      {:ok, [offer]} = X402.Extensions.OfferReceipt.fetch_offers(payment_required)

      {:ok, %{signer: signer_address, payload: payload}} =
        X402.Extensions.OfferReceipt.verify_offer(offer)

  A valid signature only proves *which key* signed — it does not prove the
  key was **authorized** for the offered resource. Verifiers must apply an
  authorization policy (§4.5.1); the simplest is checking the recovered
  signer against the offer's `payTo` address, which `verify_offer/2` supports
  through the `:expected_signer` option.

  ## Boundaries

    * JWS verification takes an explicit `:public_key` — this library never
      resolves `kid` DID URLs (no network access); resolve the key yourself
      and check its authorization per §4.5.1.
    * The JWS algorithms are limited to what OTP `:crypto` provides:
      `ES256K` and `EdDSA` (both spec-named algorithms are covered).
  """

  alias X402.EIP3009
  alias X402.EIP712
  alias X402.Extensions.OfferReceipt.JWS
  alias X402.Signer
  alias X402.Utils

  @extension_key "offer-receipt"
  @payload_version 1
  @schema_uri "https://json-schema.org/draft/2020-12/schema"

  # EIP-712 constants (§3.2, §4.3, §5.3). The domain deliberately hardcodes
  # chainId 1: EIP-712 is used as an off-chain signing format and the payment
  # network is identified by the payload's `network` field.
  @domain_type "EIP712Domain(string name,string version,uint256 chainId)"
  @offer_type "Offer(uint256 version,string resourceUrl,string scheme,string network," <>
                "string asset,string payTo,string amount,uint256 validUntil)"
  @receipt_type "Receipt(uint256 version,string network,string resourceUrl,string payer," <>
                  "uint256 issuedAt,string transaction)"

  @offer_domain_name "x402 offer"
  @receipt_domain_name "x402 receipt"

  @domain_fields [
    %{"name" => "name", "type" => "string"},
    %{"name" => "version", "type" => "string"},
    %{"name" => "chainId", "type" => "uint256"}
  ]

  @offer_fields [
    %{"name" => "version", "type" => "uint256"},
    %{"name" => "resourceUrl", "type" => "string"},
    %{"name" => "scheme", "type" => "string"},
    %{"name" => "network", "type" => "string"},
    %{"name" => "asset", "type" => "string"},
    %{"name" => "payTo", "type" => "string"},
    %{"name" => "amount", "type" => "string"},
    %{"name" => "validUntil", "type" => "uint256"}
  ]

  @receipt_fields [
    %{"name" => "version", "type" => "uint256"},
    %{"name" => "network", "type" => "string"},
    %{"name" => "resourceUrl", "type" => "string"},
    %{"name" => "payer", "type" => "string"},
    %{"name" => "issuedAt", "type" => "uint256"},
    %{"name" => "transaction", "type" => "string"}
  ]

  # x402 v1 human-readable network identifiers → CAIP-2, per the reference
  # implementation. Offer and receipt payloads MUST use CAIP-2 (§4.2, §5.2).
  @v1_evm_networks %{
    "ethereum" => 1,
    "sepolia" => 11_155_111,
    "abstract" => 2741,
    "abstract-testnet" => 11_124,
    "base" => 8453,
    "base-sepolia" => 84_532,
    "avalanche" => 43_114,
    "avalanche-fuji" => 43_113,
    "iotex" => 4689,
    "sei" => 1329,
    "sei-testnet" => 1328,
    "polygon" => 137,
    "polygon-amoy" => 80_002,
    "peaq" => 3338,
    "story" => 1514,
    "educhain" => 41_923,
    "skale-base-sepolia" => 324_705_682
  }

  @v1_solana_networks %{
    "solana" => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
    "solana-devnet" => "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1",
    "solana-testnet" => "solana:4uhcVJyU9pJkvQyS88uRDiswHXSCkY3z"
  }

  @offer_payload_schema [
    resource_url: [type: :string, required: true, doc: "The paid resource URL."],
    scheme: [type: :string, required: true, doc: "Payment scheme identifier (e.g. `\"exact\"`)."],
    network: [
      type: :string,
      required: true,
      doc: "Network identifier — CAIP-2 or an x402 v1 name (converted via `to_caip2/1`)."
    ],
    asset: [type: :string, required: true, doc: "Token contract address or `\"native\"`."],
    pay_to: [type: :string, required: true, doc: "Recipient wallet address."],
    amount: [
      type: {:or, [:string, :non_neg_integer]},
      required: true,
      doc: "Required payment amount in atomic units (encoded as a string)."
    ],
    valid_until: [
      type: :non_neg_integer,
      doc: "Unix timestamp (seconds) when the offer expires. Omit for no expiry."
    ]
  ]

  @receipt_payload_schema [
    resource_url: [type: :string, required: true, doc: "The paid resource URL."],
    network: [
      type: :string,
      required: true,
      doc: "Network identifier — CAIP-2 or an x402 v1 name (converted via `to_caip2/1`)."
    ],
    payer: [type: :string, required: true, doc: "Payer identifier (commonly a wallet address)."],
    issued_at: [
      type: :non_neg_integer,
      doc: "Unix timestamp (seconds) the receipt was issued. Defaults to the current time."
    ],
    transaction: [
      type: :string,
      doc: """
      Blockchain transaction hash. Optional — receipts are privacy-minimal
      by default; include it when verifiability matters more than privacy.
      """
    ]
  ]

  @sign_opts_schema [
    accept_index: [
      type: :non_neg_integer,
      doc: """
      Index into `accepts[]` this offer corresponds to. An unsigned
      convenience field (§4.1.1) — clients match offers by payload fields.
      """
    ]
  ]

  @verify_opts_schema [
    expected_signer: [
      type: :string,
      doc: """
      EIP-712 only: EVM address the recovered signer must equal
      (case-insensitive), e.g. the offer's `payTo`. When the recovered signer
      differs, verification fails with `{:error, :unauthorized_signer}`.
      """
    ],
    public_key: [
      type: :string,
      doc: """
      JWS only (required for `"jws"` artifacts): raw public key bytes — a
      32-byte Ed25519 key for `EdDSA`, a SEC1 secp256k1 point for `ES256K`.
      """
    ],
    algs: [
      type: {:list, {:in, ["ES256K", "EdDSA"]}},
      default: ["ES256K", "EdDSA"],
      doc: "JWS only: accepted algorithms."
    ]
  ]

  @typedoc "A signed offer or receipt envelope in wire shape (string keys)."
  @type envelope :: %{optional(String.t()) => term()}

  @typedoc "An offer or receipt payload in wire shape (string keys)."
  @type payload :: %{optional(String.t()) => term()}

  @typedoc "A built `extensions[\"offer-receipt\"]` value (`info` + `schema`)."
  @type t :: %{optional(String.t()) => map()}

  @typedoc "The result of a successful verification."
  @type verification :: %{
          optional(:signer) => String.t(),
          optional(:header) => map(),
          format: String.t(),
          payload: payload()
        }

  @type payload_error ::
          {:missing_field, String.t()}
          | {:invalid_field, String.t()}
          | {:unsupported_payload_version, term()}
          | {:unknown_network, String.t()}

  @type verify_error ::
          payload_error()
          | JWS.verify_error()
          | {:unsupported_format, term()}
          | :invalid_envelope
          | :missing_public_key
          | :unauthorized_signer
          | :missing_dependency
          | :invalid_signature

  # ---------------------------------------------------------------------------
  # Payload construction (server side)
  # ---------------------------------------------------------------------------

  @doc since: "0.6.0"
  @doc group: :offers
  @doc """
  Builds an offer payload (§4.2) in wire shape.

  The `:network` is normalized to CAIP-2 with `to_caip2/1`, as the
  specification requires for offer payloads. `version` is always the current
  payload schema version (`1`).

  ## Options

  #{NimbleOptions.docs(@offer_payload_schema)}

  ## Examples

      iex> X402.Extensions.OfferReceipt.offer_payload(
      ...>   resource_url: "https://api.example.com/premium-data",
      ...>   scheme: "exact",
      ...>   network: "base",
      ...>   asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      ...>   pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      ...>   amount: 10_000,
      ...>   valid_until: 1_703_123_516
      ...> )
      {:ok,
       %{
         "version" => 1,
         "resourceUrl" => "https://api.example.com/premium-data",
         "scheme" => "exact",
         "network" => "eip155:8453",
         "asset" => "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
         "payTo" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
         "amount" => "10000",
         "validUntil" => 1703123516
       }}

      iex> X402.Extensions.OfferReceipt.offer_payload(
      ...>   resource_url: "https://a.example",
      ...>   scheme: "exact",
      ...>   network: "unknown-net",
      ...>   asset: "native",
      ...>   pay_to: "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      ...>   amount: "1"
      ...> )
      {:error, {:unknown_network, "unknown-net"}}
  """
  @spec offer_payload(keyword()) :: {:ok, payload()} | {:error, {:unknown_network, String.t()}}
  def offer_payload(opts) when is_list(opts) do
    opts = NimbleOptions.validate!(opts, @offer_payload_schema)

    with {:ok, network} <- to_caip2(Keyword.fetch!(opts, :network)) do
      payload = %{
        "version" => @payload_version,
        "resourceUrl" => Keyword.fetch!(opts, :resource_url),
        "scheme" => Keyword.fetch!(opts, :scheme),
        "network" => network,
        "asset" => Keyword.fetch!(opts, :asset),
        "payTo" => Keyword.fetch!(opts, :pay_to),
        "amount" => to_amount_string(Keyword.fetch!(opts, :amount))
      }

      {:ok, maybe_put(payload, "validUntil", Keyword.get(opts, :valid_until))}
    end
  end

  @doc since: "0.6.0"
  @doc group: :receipts
  @doc """
  Builds a receipt payload (§5.2) in wire shape.

  Receipts are privacy-minimal by default: `transaction` is only included
  when passed. `:issued_at` defaults to the current Unix time.

  ## Options

  #{NimbleOptions.docs(@receipt_payload_schema)}

  ## Examples

      iex> X402.Extensions.OfferReceipt.receipt_payload(
      ...>   resource_url: "https://api.example.com/premium-data",
      ...>   network: "eip155:8453",
      ...>   payer: "0x857b06519E91e3A54538791bDbb0E22373e36b66",
      ...>   issued_at: 1_703_123_456
      ...> )
      {:ok,
       %{
         "version" => 1,
         "network" => "eip155:8453",
         "resourceUrl" => "https://api.example.com/premium-data",
         "payer" => "0x857b06519E91e3A54538791bDbb0E22373e36b66",
         "issuedAt" => 1703123456
       }}
  """
  @spec receipt_payload(keyword()) :: {:ok, payload()} | {:error, {:unknown_network, String.t()}}
  def receipt_payload(opts) when is_list(opts) do
    opts = NimbleOptions.validate!(opts, @receipt_payload_schema)

    with {:ok, network} <- to_caip2(Keyword.fetch!(opts, :network)) do
      payload = %{
        "version" => @payload_version,
        "network" => network,
        "resourceUrl" => Keyword.fetch!(opts, :resource_url),
        "payer" => Keyword.fetch!(opts, :payer),
        "issuedAt" => Keyword.get_lazy(opts, :issued_at, fn -> System.os_time(:second) end)
      }

      {:ok, maybe_put(payload, "transaction", Keyword.get(opts, :transaction))}
    end
  end

  # ---------------------------------------------------------------------------
  # EIP-712 signing (server side)
  # ---------------------------------------------------------------------------

  @doc since: "0.6.0"
  @doc group: :offers
  @doc """
  Signs an offer payload as an EIP-712 artifact through an `X402.Signer`.

  Computes the EIP-712 digest with the fixed offer domain
  (`name: "x402 offer"`, `version: "1"`, `chainId: 1`, §3.2) and the
  canonical `Offer` type (§4.3), signs it through `signer`, and returns the
  transmitted envelope

      %{"format" => "eip712", "payload" => payload, "signature" => "0x..."}

  Per §4.3, an absent `validUntil` is signed **and transmitted** as `0`.
  Requires the optional `ex_keccak` dependency (`{:error,
  :missing_dependency}` without it).

  ## Options

  #{NimbleOptions.docs(@sign_opts_schema)}
  """
  @spec sign_offer(payload(), Signer.t(), keyword()) ::
          {:ok, envelope()} | {:error, verify_error() | term()}
  def sign_offer(payload, signer, opts \\ []) when is_map(payload) and is_list(opts) do
    opts = NimbleOptions.validate!(opts, @sign_opts_schema)
    payload = normalize_offer_payload(payload)

    with {:ok, digest} <- offer_digest(payload),
         typed_data = typed_data("Offer", @offer_domain_name, @offer_fields, payload),
         {:ok, signature} <- Signer.sign_eip712(signer, digest, typed_data) do
      envelope = %{
        "format" => "eip712",
        "payload" => payload,
        "signature" => "0x" <> Base.encode16(signature, case: :lower)
      }

      {:ok, maybe_put(envelope, "acceptIndex", Keyword.get(opts, :accept_index))}
    end
  end

  @doc since: "0.6.0"
  @doc group: :receipts
  @doc """
  Signs a receipt payload as an EIP-712 artifact through an `X402.Signer`.

  Uses the fixed receipt domain (`name: "x402 receipt"`, `version: "1"`,
  `chainId: 1`, §3.2) and the canonical `Receipt` type (§5.3). Per §5.3, an
  absent `transaction` is signed **and transmitted** as `""`.
  """
  @spec sign_receipt(payload(), Signer.t()) :: {:ok, envelope()} | {:error, term()}
  def sign_receipt(payload, signer) when is_map(payload) do
    payload = normalize_receipt_payload(payload)

    with {:ok, digest} <- receipt_digest(payload),
         typed_data = typed_data("Receipt", @receipt_domain_name, @receipt_fields, payload),
         {:ok, signature} <- Signer.sign_eip712(signer, digest, typed_data) do
      {:ok,
       %{
         "format" => "eip712",
         "payload" => payload,
         "signature" => "0x" <> Base.encode16(signature, case: :lower)
       }}
    end
  end

  # ---------------------------------------------------------------------------
  # JWS signing (server side)
  # ---------------------------------------------------------------------------

  @doc since: "0.6.0"
  @doc group: :offers
  @doc """
  Signs an offer payload as a compact JWS artifact.

  The payload travels inside the JWS, so the envelope omits `payload`
  (§3.1.1). Optional payload fields stay omitted (no zero-filling — that
  rule is EIP-712 specific).

  `key_opts` are the `X402.Extensions.OfferReceipt.JWS.sign/2` options
  (`:alg`, `:kid`, `:key`) plus the `:accept_index` envelope option.

  ## Examples

      {:ok, offer} =
        X402.Extensions.OfferReceipt.sign_offer_jws(payload,
          alg: "EdDSA",
          kid: "did:web:api.example.com#key-1",
          key: ed25519_seed,
          accept_index: 0
        )
  """
  @spec sign_offer_jws(payload(), keyword()) ::
          {:ok, envelope()} | {:error, JWS.sign_error() | payload_error()}
  def sign_offer_jws(payload, key_opts) when is_map(payload) and is_list(key_opts) do
    {opts, key_opts} = Keyword.split(key_opts, [:accept_index])

    with :ok <- validate_offer_payload(payload),
         {:ok, jws} <- JWS.sign(payload, key_opts) do
      envelope = %{"format" => "jws", "signature" => jws}
      {:ok, maybe_put(envelope, "acceptIndex", Keyword.get(opts, :accept_index))}
    end
  end

  @doc since: "0.6.0"
  @doc group: :receipts
  @doc """
  Signs a receipt payload as a compact JWS artifact.

  See `sign_offer_jws/2`; `key_opts` are `:alg`, `:kid`, and `:key`.
  """
  @spec sign_receipt_jws(payload(), keyword()) ::
          {:ok, envelope()} | {:error, JWS.sign_error() | payload_error()}
  def sign_receipt_jws(payload, key_opts) when is_map(payload) and is_list(key_opts) do
    with :ok <- validate_receipt_payload(payload),
         {:ok, jws} <- JWS.sign(payload, key_opts) do
      {:ok, %{"format" => "jws", "signature" => jws}}
    end
  end

  # ---------------------------------------------------------------------------
  # Verification (client side)
  # ---------------------------------------------------------------------------

  @doc since: "0.6.0"
  @doc group: :offers
  @doc """
  Verifies a signed offer envelope (§4.5).

  For `"eip712"` artifacts, recomputes the EIP-712 digest from the payload
  **exactly as transmitted** and recovers the signer address (requires the
  optional `ex_secp256k1` / `ex_keccak` dependencies). For `"jws"`
  artifacts, verifies the compact JWS against the `:public_key` option.

  Returns `{:ok, %{format: ..., payload: ...}}` with `:signer` (EIP-712, the
  recovered address) or `:header` (JWS, the protected header with `alg` and
  `kid`).

  > #### Signature validity is not authorization {: .warning}
  >
  > A valid signature proves which key signed, not that the key was
  > authorized for `payload.resourceUrl` (§4.5.1). Check the signer against
  > your authorization policy — for the common `payTo`-signs deployment,
  > pass `expected_signer: payload["payTo"]`.

  ## Options

  #{NimbleOptions.docs(@verify_opts_schema)}
  """
  @spec verify_offer(envelope(), keyword()) :: {:ok, verification()} | {:error, verify_error()}
  def verify_offer(envelope, opts \\ []) when is_map(envelope) and is_list(opts) do
    verify(envelope, opts, &offer_digest/1)
  end

  @doc since: "0.6.0"
  @doc group: :receipts
  @doc """
  Verifies a signed receipt envelope (§5.5).

  Same contract as `verify_offer/2`, with the receipt domain and types.
  `issuedAt` policy checks (freshness) and on-chain `transaction` checks are
  the caller's responsibility.
  """
  @spec verify_receipt(envelope(), keyword()) :: {:ok, verification()} | {:error, verify_error()}
  def verify_receipt(envelope, opts \\ []) when is_map(envelope) and is_list(opts) do
    verify(envelope, opts, &receipt_digest/1)
  end

  @doc since: "0.6.0"
  @doc group: :offers
  @doc """
  Extracts the payload from a signed envelope **without verifying it**.

  For `"eip712"` the transmitted `payload` is returned; for `"jws"` the JWS
  payload segment is decoded. Use `verify_offer/2` / `verify_receipt/2` for
  verified reads.

  ## Examples

      iex> X402.Extensions.OfferReceipt.extract_payload(%{
      ...>   "format" => "eip712",
      ...>   "payload" => %{"version" => 1},
      ...>   "signature" => "0xsig"
      ...> })
      {:ok, %{"version" => 1}}

      iex> X402.Extensions.OfferReceipt.extract_payload(%{"format" => "carrier-pigeon"})
      {:error, {:unsupported_format, "carrier-pigeon"}}
  """
  @spec extract_payload(envelope()) :: {:ok, payload()} | {:error, verify_error()}
  def extract_payload(%{"format" => "eip712", "payload" => payload}) when is_map(payload),
    do: {:ok, payload}

  def extract_payload(%{"format" => "eip712"}), do: {:error, {:missing_field, "payload"}}

  def extract_payload(%{"format" => "jws", "signature" => jws}) when is_binary(jws),
    do: JWS.peek_payload(jws)

  def extract_payload(%{"format" => "jws"}), do: {:error, {:missing_field, "signature"}}
  def extract_payload(%{"format" => format}), do: {:error, {:unsupported_format, format}}
  def extract_payload(_envelope), do: {:error, :invalid_envelope}

  # ---------------------------------------------------------------------------
  # EIP-712 digests
  # ---------------------------------------------------------------------------

  @doc since: "0.6.0"
  @doc group: :offers
  @doc """
  Computes the EIP-712 digest of an offer payload (§4.3).

  Returns `keccak256(0x19 0x01 || domainSeparator || structHash)` where the
  domain is `{name: "x402 offer", version: "1", chainId: 1}`. An absent
  `validUntil` is hashed as `0`. Requires the optional `ex_keccak`
  dependency.
  """
  @spec offer_digest(payload()) ::
          {:ok, <<_::256>>} | {:error, payload_error() | :missing_dependency}
  def offer_digest(payload) when is_map(payload) do
    digest(payload, @offer_domain_name, @offer_type, offer_hash_fields())
  end

  @doc since: "0.6.0"
  @doc group: :receipts
  @doc """
  Computes the EIP-712 digest of a receipt payload (§5.3).

  The domain is `{name: "x402 receipt", version: "1", chainId: 1}`; an
  absent `transaction` is hashed as `""`. Requires the optional `ex_keccak`
  dependency.
  """
  @spec receipt_digest(payload()) ::
          {:ok, <<_::256>>} | {:error, payload_error() | :missing_dependency}
  def receipt_digest(payload) when is_map(payload) do
    digest(payload, @receipt_domain_name, @receipt_type, receipt_hash_fields())
  end

  # ---------------------------------------------------------------------------
  # Extension envelope (declaration)
  # ---------------------------------------------------------------------------

  @doc since: "0.6.0"
  @doc group: :declaration
  @doc """
  Builds the `extensions["offer-receipt"]` value for payment requirements.

  Takes the signed offer envelopes for the response's `accepts[]` entries
  and returns the `%{"info" => %{"offers" => offers}, "schema" => schema}`
  declaration (§4.1, §6.1/§6.3). All offers must share one signature format
  — the specification's schemas are format-specific and servers use one
  format consistently (§6). Raises `ArgumentError` for empty, mixed-format,
  or structurally invalid offers (programmer errors).
  """
  @spec build_extension([envelope()]) :: t()
  def build_extension(offers) when is_list(offers) and offers != [] do
    format = uniform_format!(offers)

    Enum.each(offers, fn offer ->
      case validate_offer(offer) do
        :ok -> :ok
        {:error, reason} -> raise ArgumentError, "invalid signed offer: #{inspect(reason)}"
      end
    end)

    %{
      "info" => %{"offers" => offers},
      "schema" => offers_schema(format)
    }
  end

  def build_extension(other) do
    raise ArgumentError, "expected a non-empty list of signed offers, got: #{inspect(other)}"
  end

  @doc since: "0.6.0"
  @doc group: :declaration
  @doc """
  Builds the `extensions["offer-receipt"]` value for a settlement response.

  Takes the signed receipt envelope and returns the
  `%{"info" => %{"receipt" => receipt}, "schema" => schema}` declaration
  (§5.1, §6.5/§6.7). Raises `ArgumentError` for a structurally invalid
  receipt (programmer error).
  """
  @spec build_receipt_extension(envelope()) :: t()
  def build_receipt_extension(receipt) when is_map(receipt) do
    case validate_receipt(receipt) do
      :ok -> :ok
      {:error, reason} -> raise ArgumentError, "invalid signed receipt: #{inspect(reason)}"
    end

    %{
      "info" => %{"receipt" => receipt},
      "schema" => receipt_schema(Map.fetch!(receipt, "format"))
    }
  end

  def build_receipt_extension(other) do
    raise ArgumentError, "expected a signed receipt map, got: #{inspect(other)}"
  end

  @doc since: "0.6.0"
  @doc group: :declaration
  @doc """
  Fetches and validates the signed offers from a payment-required map.

  Accepts either the full decoded `PAYMENT-REQUIRED` map (looks under
  `"extensions"`) or the extensions map itself. Validation is fail-closed:
  every offer envelope must be structurally valid per §3.1.1
  (`"eip712"` offers carry a payload and a 65-byte hex signature; `"jws"`
  offers carry a three-part compact JWS and **no** payload).

  ## Examples

      iex> X402.Extensions.OfferReceipt.fetch_offers(%{"accepts" => []})
      {:error, :extension_not_present}
  """
  @spec fetch_offers(map()) ::
          {:ok, [envelope()]}
          | {:error, :extension_not_present | {:invalid_extension, term()}}
  def fetch_offers(map) when is_map(map) do
    with {:ok, info} <- fetch_info(map) do
      case Map.get(info, "offers") do
        offers when is_list(offers) and offers != [] -> validate_offers(offers)
        _missing -> {:error, {:invalid_extension, {:missing_field, "offers"}}}
      end
    end
  end

  @doc since: "0.6.0"
  @doc group: :declaration
  @doc """
  Fetches and validates the signed receipt from a settlement response map.

  Accepts either the full decoded settlement response (looks under
  `"extensions"`) or the extensions map itself.
  """
  @spec fetch_receipt(map()) ::
          {:ok, envelope()}
          | {:error, :extension_not_present | {:invalid_extension, term()}}
  def fetch_receipt(map) when is_map(map) do
    with {:ok, info} <- fetch_info(map) do
      validate_fetched_receipt(Map.get(info, "receipt"))
    end
  end

  @spec validate_fetched_receipt(term()) ::
          {:ok, envelope()} | {:error, {:invalid_extension, term()}}
  defp validate_fetched_receipt(%{} = receipt) do
    case validate_receipt(receipt) do
      :ok -> {:ok, receipt}
      {:error, reason} -> {:error, {:invalid_extension, reason}}
    end
  end

  defp validate_fetched_receipt(_missing),
    do: {:error, {:invalid_extension, {:missing_field, "receipt"}}}

  @doc since: "0.6.0"
  @doc group: :declaration
  @doc """
  Validates the structure of a signed offer envelope (§3.1.1, §4.2).

  ## Examples

      iex> X402.Extensions.OfferReceipt.validate_offer(%{
      ...>   "format" => "jws",
      ...>   "signature" => "eyJhbGciOiJFUzI1NksiLCJraWQiOiJrIn0.eyJ2ZXJzaW9uIjoxfQ.c2ln"
      ...> })
      :ok

      iex> X402.Extensions.OfferReceipt.validate_offer(%{
      ...>   "format" => "jws",
      ...>   "payload" => %{"version" => 1},
      ...>   "signature" => "a.b.c"
      ...> })
      {:error, {:invalid_field, "payload"}}
  """
  @spec validate_offer(envelope()) :: :ok | {:error, verify_error()}
  def validate_offer(envelope) when is_map(envelope) do
    with :ok <- validate_accept_index(envelope) do
      validate_envelope(envelope, &validate_offer_payload/1)
    end
  end

  def validate_offer(_envelope), do: {:error, :invalid_envelope}

  @doc since: "0.6.0"
  @doc group: :declaration
  @doc """
  Validates the structure of a signed receipt envelope (§3.1.1, §5.2).
  """
  @spec validate_receipt(envelope()) :: :ok | {:error, verify_error()}
  def validate_receipt(envelope) when is_map(envelope) do
    validate_envelope(envelope, &validate_receipt_payload/1)
  end

  def validate_receipt(_envelope), do: {:error, :invalid_envelope}

  # ---------------------------------------------------------------------------
  # Network conversion
  # ---------------------------------------------------------------------------

  @doc since: "0.6.0"
  @doc """
  Converts a network identifier to CAIP-2 format.

  Offer and receipt payloads must carry CAIP-2 identifiers even in x402 v1
  flows (§4.2, §5.2). Strings that already contain a `:` are passed through;
  x402 v1 names are mapped (`"base"` → `"eip155:8453"`, `"solana"` → its
  CAIP-2 chain reference); anything else is `{:error, {:unknown_network,
  network}}`.

  ## Examples

      iex> X402.Extensions.OfferReceipt.to_caip2("eip155:8453")
      {:ok, "eip155:8453"}

      iex> X402.Extensions.OfferReceipt.to_caip2("base-sepolia")
      {:ok, "eip155:84532"}

      iex> X402.Extensions.OfferReceipt.to_caip2("solana")
      {:ok, "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"}

      iex> X402.Extensions.OfferReceipt.to_caip2("mystery-chain")
      {:error, {:unknown_network, "mystery-chain"}}
  """
  @spec to_caip2(String.t()) :: {:ok, String.t()} | {:error, {:unknown_network, String.t()}}
  def to_caip2(network) when is_binary(network) do
    normalized = String.downcase(network)

    cond do
      String.contains?(network, ":") -> {:ok, network}
      is_map_key(@v1_evm_networks, normalized) -> {:ok, "eip155:#{@v1_evm_networks[normalized]}"}
      is_map_key(@v1_solana_networks, normalized) -> {:ok, @v1_solana_networks[normalized]}
      true -> {:error, {:unknown_network, network}}
    end
  end

  # ---------------------------------------------------------------------------
  # Shared verification
  # ---------------------------------------------------------------------------

  @spec verify(envelope(), keyword(), (payload() -> {:ok, <<_::256>>} | {:error, term()})) ::
          {:ok, verification()} | {:error, verify_error()}
  defp verify(envelope, opts, digest_fun) do
    opts = NimbleOptions.validate!(opts, @verify_opts_schema)

    case envelope do
      %{"format" => "eip712", "payload" => payload, "signature" => signature}
      when is_map(payload) and is_binary(signature) ->
        verify_eip712(payload, signature, opts, digest_fun)

      %{"format" => "jws", "signature" => jws} when is_binary(jws) ->
        verify_jws(jws, opts)

      %{"format" => format} when format in ["eip712", "jws"] ->
        {:error, :invalid_envelope}

      %{"format" => format} ->
        {:error, {:unsupported_format, format}}

      _envelope ->
        {:error, :invalid_envelope}
    end
  end

  @spec verify_eip712(payload(), String.t(), keyword(), fun()) ::
          {:ok, verification()} | {:error, verify_error()}
  defp verify_eip712(payload, signature, opts, digest_fun) do
    with :ok <- ensure_payload_version(payload),
         {:ok, digest} <- digest_fun.(payload),
         {:ok, signer} <- EIP3009.recover_signer(digest, signature),
         :ok <- check_expected_signer(signer, Keyword.get(opts, :expected_signer)) do
      {:ok, %{format: "eip712", signer: signer, payload: payload}}
    end
  end

  @spec verify_jws(String.t(), keyword()) :: {:ok, verification()} | {:error, verify_error()}
  defp verify_jws(jws, opts) do
    case Keyword.get(opts, :public_key) do
      nil ->
        {:error, :missing_public_key}

      public_key ->
        with {:ok, %{header: header, payload: payload}} <-
               JWS.verify(jws, public_key, algs: Keyword.fetch!(opts, :algs)),
             :ok <- ensure_map_payload(payload),
             :ok <- ensure_payload_version(payload) do
          {:ok, %{format: "jws", header: header, payload: payload}}
        end
    end
  end

  @spec ensure_map_payload(term()) :: :ok | {:error, :invalid_envelope}
  defp ensure_map_payload(payload) when is_map(payload), do: :ok
  defp ensure_map_payload(_payload), do: {:error, :invalid_envelope}

  @spec ensure_payload_version(payload()) ::
          :ok | {:error, {:unsupported_payload_version, term()}}
  defp ensure_payload_version(payload) do
    case Utils.map_value(payload, {"version", :version}) do
      @payload_version -> :ok
      version -> {:error, {:unsupported_payload_version, version}}
    end
  end

  @spec check_expected_signer(String.t(), String.t() | nil) ::
          :ok | {:error, :unauthorized_signer}
  defp check_expected_signer(_signer, nil), do: :ok

  defp check_expected_signer(signer, expected) do
    case String.downcase(signer) == String.downcase(expected) do
      true -> :ok
      false -> {:error, :unauthorized_signer}
    end
  end

  # ---------------------------------------------------------------------------
  # EIP-712 hashing
  # ---------------------------------------------------------------------------

  # {wire key, kind, default} — `kind` selects string-hash vs uint256 word,
  # `default` fills the spec's zero-value for optional fields (§4.3, §5.3).
  @spec offer_hash_fields() :: [{String.t(), :string | :uint256, term()}]
  defp offer_hash_fields do
    [
      {"version", :uint256, nil},
      {"resourceUrl", :string, nil},
      {"scheme", :string, nil},
      {"network", :string, nil},
      {"asset", :string, nil},
      {"payTo", :string, nil},
      {"amount", :string, nil},
      {"validUntil", :uint256, 0}
    ]
  end

  @spec receipt_hash_fields() :: [{String.t(), :string | :uint256, term()}]
  defp receipt_hash_fields do
    [
      {"version", :uint256, nil},
      {"network", :string, nil},
      {"resourceUrl", :string, nil},
      {"payer", :string, nil},
      {"issuedAt", :uint256, nil},
      {"transaction", :string, ""}
    ]
  end

  # The struct hashing is built on the shared X402.EIP712 primitives. Only the
  # domain separator is computed locally: the offer-receipt domain has three
  # fields (name, version, chainId — no verifyingContract, §3.2), while
  # X402.EIP712.domain_separator/1 covers the common four-field x402 shape.
  @spec digest(payload(), String.t(), String.t(), [{String.t(), atom(), term()}]) ::
          {:ok, <<_::256>>} | {:error, payload_error() | :missing_dependency}
  defp digest(payload, domain_name, type_string, fields) do
    with {:ok, keccak} <- EIP712.keccak_module(),
         {:ok, words} <- field_words(payload, fields, keccak),
         {:ok, struct_hash} <- EIP712.hash_struct(type_string, words),
         {:ok, domain_separator} <- domain_separator(domain_name, keccak) do
      {:ok, keccak.hash_256(<<0x19, 0x01>> <> domain_separator <> struct_hash)}
    end
  end

  @spec domain_separator(String.t(), module()) ::
          {:ok, <<_::256>>} | {:error, :missing_dependency | :invalid_word}
  defp domain_separator(domain_name, keccak) do
    EIP712.hash_struct(@domain_type, [
      keccak.hash_256(domain_name),
      keccak.hash_256("1"),
      <<1::unsigned-big-integer-size(256)>>
    ])
  end

  @spec field_words(payload(), [{String.t(), atom(), term()}], module()) ::
          {:ok, [<<_::256>>]} | {:error, payload_error()}
  defp field_words(payload, fields, keccak) do
    fields
    |> Enum.reduce_while({:ok, []}, fn field, {:ok, acc} ->
      case field_word(payload, field, keccak) do
        {:ok, word} -> {:cont, {:ok, [word | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, words} -> {:ok, Enum.reverse(words)}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec field_word(payload(), {String.t(), atom(), term()}, module()) ::
          {:ok, binary()} | {:error, payload_error()}
  defp field_word(payload, {key, kind, default}, keccak) do
    case fetch_hash_value(payload, key, default) do
      {:ok, value} -> encode_word(kind, key, value, keccak)
      {:error, reason} -> {:error, reason}
    end
  end

  @spec fetch_hash_value(payload(), String.t(), term()) ::
          {:ok, term()} | {:error, {:missing_field, String.t()}}
  defp fetch_hash_value(payload, key, default) do
    case Utils.map_value(payload, {key, String.to_atom(key)}) do
      nil when is_nil(default) -> {:error, {:missing_field, key}}
      nil -> {:ok, default}
      value -> {:ok, value}
    end
  end

  @spec encode_word(:string | :uint256, String.t(), term(), module()) ::
          {:ok, binary()} | {:error, {:invalid_field, String.t()}}
  defp encode_word(:string, _key, value, keccak) when is_binary(value),
    do: {:ok, keccak.hash_256(value)}

  defp encode_word(:uint256, key, value, _keccak) do
    case EIP712.encode_uint256(value) do
      {:ok, word} -> {:ok, word}
      {:error, _reason} -> {:error, {:invalid_field, key}}
    end
  end

  defp encode_word(_kind, key, _value, _keccak), do: {:error, {:invalid_field, key}}

  @spec typed_data(String.t(), String.t(), [map()], payload()) :: Signer.typed_data()
  defp typed_data(primary_type, domain_name, fields, payload) do
    %{
      "types" => %{"EIP712Domain" => @domain_fields, primary_type => fields},
      "primaryType" => primary_type,
      "domain" => %{"name" => domain_name, "version" => "1", "chainId" => 1},
      "message" => payload
    }
  end

  # ---------------------------------------------------------------------------
  # Payload normalization and validation
  # ---------------------------------------------------------------------------

  @spec normalize_offer_payload(payload()) :: payload()
  defp normalize_offer_payload(payload),
    do: Map.put_new(payload, "validUntil", 0)

  @spec normalize_receipt_payload(payload()) :: payload()
  defp normalize_receipt_payload(payload),
    do: Map.put_new(payload, "transaction", "")

  @spec validate_offer_payload(term()) :: :ok | {:error, payload_error()}
  defp validate_offer_payload(payload) when is_map(payload) do
    with :ok <- ensure_payload_version(payload),
         :ok <- require_strings(payload, ~w(resourceUrl scheme network asset payTo amount)) do
      optional_integer(payload, "validUntil")
    end
  end

  defp validate_offer_payload(_payload), do: {:error, {:invalid_field, "payload"}}

  @spec validate_receipt_payload(term()) :: :ok | {:error, payload_error()}
  defp validate_receipt_payload(payload) when is_map(payload) do
    with :ok <- ensure_payload_version(payload),
         :ok <- require_strings(payload, ~w(network resourceUrl payer)),
         :ok <- require_integer(payload, "issuedAt") do
      optional_string(payload, "transaction")
    end
  end

  defp validate_receipt_payload(_payload), do: {:error, {:invalid_field, "payload"}}

  @spec require_strings(payload(), [String.t()]) :: :ok | {:error, payload_error()}
  defp require_strings(payload, keys) do
    Enum.reduce_while(keys, :ok, fn key, :ok ->
      case Map.get(payload, key) do
        value when is_binary(value) and value != "" -> {:cont, :ok}
        nil -> {:halt, {:error, {:missing_field, key}}}
        _invalid -> {:halt, {:error, {:invalid_field, key}}}
      end
    end)
  end

  @spec require_integer(payload(), String.t()) :: :ok | {:error, payload_error()}
  defp require_integer(payload, key) do
    case Map.get(payload, key) do
      value when is_integer(value) and value >= 0 -> :ok
      nil -> {:error, {:missing_field, key}}
      _invalid -> {:error, {:invalid_field, key}}
    end
  end

  @spec optional_integer(payload(), String.t()) :: :ok | {:error, payload_error()}
  defp optional_integer(payload, key) do
    case Map.get(payload, key) do
      nil -> :ok
      value when is_integer(value) and value >= 0 -> :ok
      _invalid -> {:error, {:invalid_field, key}}
    end
  end

  @spec optional_string(payload(), String.t()) :: :ok | {:error, payload_error()}
  defp optional_string(payload, key) do
    case Map.get(payload, key) do
      nil -> :ok
      value when is_binary(value) -> :ok
      _invalid -> {:error, {:invalid_field, key}}
    end
  end

  @spec validate_envelope(envelope(), (term() -> :ok | {:error, term()})) ::
          :ok | {:error, verify_error()}
  defp validate_envelope(%{"format" => "eip712"} = envelope, payload_validator) do
    with {:ok, payload} <- fetch_map(envelope, "payload"),
         :ok <- payload_validator.(payload) do
      validate_hex_signature(Map.get(envelope, "signature"))
    end
  end

  defp validate_envelope(%{"format" => "jws"} = envelope, _payload_validator) do
    with :ok <- ensure_no_payload(envelope) do
      validate_compact_jws(Map.get(envelope, "signature"))
    end
  end

  defp validate_envelope(%{"format" => format}, _payload_validator),
    do: {:error, {:unsupported_format, format}}

  defp validate_envelope(_envelope, _payload_validator),
    do: {:error, {:missing_field, "format"}}

  @spec fetch_map(envelope(), String.t()) :: {:ok, map()} | {:error, payload_error()}
  defp fetch_map(envelope, key) do
    case Map.get(envelope, key) do
      %{} = value -> {:ok, value}
      nil -> {:error, {:missing_field, key}}
      _invalid -> {:error, {:invalid_field, key}}
    end
  end

  # §3.1.1: for JWS the payload MUST be omitted — the JWS already carries it.
  @spec ensure_no_payload(envelope()) :: :ok | {:error, {:invalid_field, String.t()}}
  defp ensure_no_payload(envelope) do
    case Map.has_key?(envelope, "payload") do
      false -> :ok
      true -> {:error, {:invalid_field, "payload"}}
    end
  end

  @spec validate_hex_signature(term()) :: :ok | {:error, :invalid_signature}
  defp validate_hex_signature("0x" <> hex) when byte_size(hex) == 130 do
    case Base.decode16(hex, case: :mixed) do
      {:ok, _bytes} -> :ok
      :error -> {:error, :invalid_signature}
    end
  end

  defp validate_hex_signature(_signature), do: {:error, :invalid_signature}

  @spec validate_compact_jws(term()) :: :ok | {:error, :invalid_jws}
  defp validate_compact_jws(jws) when is_binary(jws) do
    case String.split(jws, ".") do
      [_header, _payload, _signature] -> :ok
      _parts -> {:error, :invalid_jws}
    end
  end

  defp validate_compact_jws(_jws), do: {:error, :invalid_jws}

  @spec validate_accept_index(envelope()) :: :ok | {:error, {:invalid_field, String.t()}}
  defp validate_accept_index(envelope) do
    case Map.get(envelope, "acceptIndex") do
      nil -> :ok
      index when is_integer(index) and index >= 0 -> :ok
      _invalid -> {:error, {:invalid_field, "acceptIndex"}}
    end
  end

  @spec validate_offers([term()]) ::
          {:ok, [envelope()]} | {:error, {:invalid_extension, term()}}
  defp validate_offers(offers) do
    offers
    |> Enum.with_index()
    |> Enum.reduce_while({:ok, offers}, fn {offer, index}, acc ->
      case is_map(offer) && validate_offer(offer) do
        :ok ->
          {:cont, acc}

        false ->
          {:halt, {:error, {:invalid_extension, {:invalid_offer, index, :invalid_envelope}}}}

        {:error, reason} ->
          {:halt, {:error, {:invalid_extension, {:invalid_offer, index, reason}}}}
      end
    end)
  end

  @spec fetch_info(map()) :: {:ok, map()} | {:error, term()}
  defp fetch_info(map) do
    extensions =
      case Utils.map_value(map, {"extensions", :extensions}) do
        %{} = nested -> nested
        _other -> map
      end

    case Map.get(extensions, @extension_key) do
      %{"info" => %{} = info} -> {:ok, info}
      %{} -> {:error, {:invalid_extension, {:missing_field, "info"}}}
      nil -> {:error, :extension_not_present}
      _invalid -> {:error, {:invalid_extension, :not_a_map}}
    end
  end

  # ---------------------------------------------------------------------------
  # Declaration schemas (§6)
  # ---------------------------------------------------------------------------

  @spec uniform_format!([envelope()]) :: String.t()
  defp uniform_format!(offers) do
    formats = offers |> Enum.map(&(is_map(&1) && Map.get(&1, "format"))) |> Enum.uniq()

    case formats do
      [format] when format in ["eip712", "jws"] ->
        format

      _mixed ->
        raise ArgumentError,
              ~s{all offers must share one signature format ("eip712" or "jws"), } <>
                "got: #{inspect(formats)}"
    end
  end

  @spec offers_schema(String.t()) :: map()
  defp offers_schema(format) do
    %{
      "$schema" => @schema_uri,
      "type" => "object",
      "properties" => %{
        "offers" => %{
          "type" => "array",
          "items" => envelope_schema(format, :offer)
        }
      },
      "required" => ["offers"]
    }
  end

  @spec receipt_schema(String.t()) :: map()
  defp receipt_schema(format) do
    %{
      "$schema" => @schema_uri,
      "type" => "object",
      "properties" => %{"receipt" => envelope_schema(format, :receipt)},
      "required" => ["receipt"]
    }
  end

  @spec envelope_schema(String.t(), :offer | :receipt) :: map()
  defp envelope_schema("eip712", artifact) do
    properties = %{
      "format" => %{"type" => "string", "const" => "eip712"},
      "payload" => payload_schema(artifact),
      "signature" => %{"type" => "string"}
    }

    %{
      "type" => "object",
      "properties" => maybe_accept_index(properties, artifact),
      "required" => ["format", "payload", "signature"]
    }
  end

  defp envelope_schema("jws", artifact) do
    properties = %{
      "format" => %{"type" => "string", "const" => "jws"},
      "signature" => %{
        "type" => "string",
        "description" =>
          "JWS compact serialization containing the #{artifact_name(artifact)} payload"
      }
    }

    %{
      "type" => "object",
      "properties" => maybe_accept_index(properties, artifact),
      "required" => ["format", "signature"]
    }
  end

  @spec maybe_accept_index(map(), :offer | :receipt) :: map()
  defp maybe_accept_index(properties, :offer),
    do: Map.put(properties, "acceptIndex", %{"type" => "integer"})

  defp maybe_accept_index(properties, :receipt), do: properties

  @spec artifact_name(:offer | :receipt) :: String.t()
  defp artifact_name(:offer), do: "offer"
  defp artifact_name(:receipt), do: "receipt"

  @spec payload_schema(:offer | :receipt) :: map()
  defp payload_schema(:offer) do
    %{
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
      "required" => ["version", "resourceUrl", "scheme", "network", "asset", "payTo", "amount"]
    }
  end

  defp payload_schema(:receipt) do
    %{
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
    }
  end

  # ---------------------------------------------------------------------------
  # Small helpers
  # ---------------------------------------------------------------------------

  @spec to_amount_string(String.t() | non_neg_integer()) :: String.t()
  defp to_amount_string(amount) when is_binary(amount), do: amount
  defp to_amount_string(amount) when is_integer(amount), do: Integer.to_string(amount)

  @spec maybe_put(map(), String.t(), term()) :: map()
  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
