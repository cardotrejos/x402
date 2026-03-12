defmodule X402.Header do
  @moduledoc false

  # Maximum byte size for any x402 encoded header value before Base64/JSON
  # decoding is attempted. Shared by PaymentRequired, PaymentResponse, and
  # PaymentSignature to ensure a single change updates all three decoders.
  @max_header_bytes 8_192

  @doc """
  Returns the maximum allowed byte size for encoded x402 header values.
  Callers should set `@max_header_bytes X402.Header.max_header_bytes()` to
  reference this constant at compile time.
  """
  def max_header_bytes, do: @max_header_bytes
end
