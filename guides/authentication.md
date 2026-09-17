# Authentication Extensions

Payment authorization and application authentication are separate checks.
The authentication extensions announce a server's expectations; they do not
grant access or automatically enforce those expectations.

## Authentication hints

`auth-hints` associates credential methods with zero-based indexes in the
`accepts` array of a payment-required response:

```elixir
alias X402.Extensions.AuthHints

method =
  AuthHints.oauth2(
    token_type: "Bearer",
    authorization_server: "https://auth.example.com",
    token_endpoint: "https://auth.example.com/token"
  )

auth_requirements = [[accept_indexes: [0], methods: [method]]]
extension = AuthHints.extension(auth_requirements)
```

Add `{X402.Extensions.AuthHints.Adapter, auth_requirements: auth_requirements}`
to the gate's `:extensions` option to advertise these hints. The adapter
omits indexes outside the current requirements. `AuthHints.sign_in_with_x/0`
builds a SIWX method hint instead.

Your application acquires and validates OAuth tokens or DPoP proofs. A SIWX
hint does not configure the gate's `:siwx` verifier or storage. Validate
credentials before serving the protected resource, regardless of whether a
client acknowledges the hints. Treat advertised URLs as untrusted metadata,
not permission to fetch arbitrary hosts or send credentials to them.

## HTTP message signatures

`X402.Extensions.HTTPMessageSignatures.Adapter` advertises registration and
signature preferences through the same gate option:

```elixir
signature_extension =
  {X402.Extensions.HTTPMessageSignatures.Adapter,
   registration_url: "https://api.example.com/signature-agents",
   signature_schemes: ["ed25519"],
   tags: ["web-bot-auth"]}
```

Use `X402.HTTPSignature` to sign messages and explicitly require the fields
your application depends on. This example generates a temporary demonstration
key, signs a request, and verifies it using only its public key:

```elixir
alias X402.HTTPSignature
alias X402.HTTPSignature.Key

{:ok, signing_key} = Key.generate("ed25519")
{:ok, public_key} = signing_key |> Key.to_jwk() |> Key.from_jwk()

message = %{
  method: "GET",
  url: "https://api.example.com/resource?view=summary",
  headers: []
}

covered = ["@method", "@target-uri"]

{:ok, signature_headers} =
  HTTPSignature.sign(message, signing_key,
    components: covered,
    tag: "web-bot-auth",
    ttl: 60,
    nonce: true
  )

signed_message = %{message | headers: message.headers ++ signature_headers}

{:ok, verified} =
  HTTPSignature.verify(signed_message,
    keys: [public_key],
    algorithms: ["ed25519"],
    tag: "web-bot-auth",
    required_components: covered,
    required_params: ["created", "expires", "nonce"],
    max_age: 60
  )
```

In production, load signing keys from your application's key store. Supply
trusted verification keys or a trusted resolver; a `keyid` is only a lookup
hint, not proof that a key belongs to an authorized caller. Reconstruct the
original target URI carefully behind proxies. Include the payment header
and other security-relevant fields in both signing and required coverage.

Time checks limit signature age but do not prevent replay. Atomically record
and reject reused `verified.params["nonce"]` values under the trusted signer
identity until expiry. For body integrity, compute and verify a content digest
yourself, and require its header to be covered.

## Public key directory

`X402.Plug.HTTPSignatureDirectory` serves
`/.well-known/http-message-signatures-directory` with public JWKs, response
signatures, and a cache lifetime. Configure `keys: [signing_key]`, or a
zero-arity function returning current signing keys for rotation. Private
material signs the response but is not published in the directory.

Directory publication does not establish caller trust. Verification never
fetches directories automatically. Your application controls registration,
origin validation, caching, and key revocation.

## Supported profile

Supported algorithms are Ed25519, ECDSA P-256/SHA-256, and RSA-PSS/SHA-512.
Requests and responses support ordinary fields, derived components, signature
parameters, and request-bound response components through `;req`.

This is not all of RFC 9421: HMAC, RSA-v1.5, P-384, the `sf`, `key`, `bs`,
and `tr` component parameters, and `Accept-Signature` negotiation are not
implemented. Neither the adapter nor the directory Plug automatically verifies
incoming requests. See `X402.HTTPSignature` for the full supported profile.
