defmodule X402.TestAuthKeys do
  @moduledoc false

  @doc "Returns `{base64_secret, public_key}` for a fresh Ed25519 key."
  def ed25519 do
    {public_key, private_key} = :crypto.generate_key(:eddsa, :ed25519)
    {Base.encode64(private_key <> public_key), public_key}
  end

  @doc "Returns the base64 Ed25519 secret for a fresh key."
  def ed25519_secret, do: elem(ed25519(), 0)

  @doc "Returns `{pem_secret, public_key}` for a fresh P-256 (secp256r1) key."
  def ec_p256 do
    {public_key, private_key} = :crypto.generate_key(:ecdh, :secp256r1)

    der =
      <<48, 119, 2, 1, 1, 4, 32, private_key::binary, 160, 10, 6, 8, 42, 134, 72, 206, 61, 3, 1,
        7, 161, 68, 3, 66, 0, public_key::binary>>

    pem =
      "-----BEGIN EC PRIVATE KEY-----\n" <>
        Base.encode64(der, line_length: 64) <> "\n-----END EC PRIVATE KEY-----\n"

    {pem, public_key}
  end

  @doc "Returns the P-256 PEM secret for a fresh key."
  def ec_p256_secret, do: elem(ec_p256(), 0)

  @doc "Re-wraps a raw ES256 `r || s` signature into its DER encoding."
  def es256_der(<<r::binary-size(32), s::binary-size(32)>>) do
    content = der_int(r) <> der_int(s)
    <<48, byte_size(content), content::binary>>
  end

  defp der_int(<<0, rest::binary>>), do: der_int(rest)

  defp der_int(<<first::size(8), _::binary>> = bin) when first >= 0x80,
    do: <<2, byte_size(bin) + 1, 0, bin::binary>>

  defp der_int(bin), do: <<2, byte_size(bin), bin::binary>>
end
