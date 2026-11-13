defmodule X402.HeaderTest do
  use ExUnit.Case, async: true

  alias X402.ExtensionResponses
  alias X402.Header
  alias X402.PaymentRequired
  alias X402.PaymentResponse
  alias X402.PaymentSignature

  describe "max_header_bytes/0" do
    test "every header decoder rejects values one byte over the limit" do
      limit = Header.max_header_bytes()
      oversized = String.duplicate("A", limit + 1)

      assert PaymentRequired.decode(oversized) == {:error, :payload_too_large}
      assert PaymentResponse.decode(oversized) == {:error, :payload_too_large}
      assert PaymentSignature.decode(oversized) == {:error, :payload_too_large}
      assert ExtensionResponses.decode(oversized) == {:error, :payload_too_large}
    end

    test "every header decoder gets past the size guard at exactly the limit" do
      limit = Header.max_header_bytes()
      at_limit = String.duplicate("A", limit)

      refute PaymentRequired.decode(at_limit) == {:error, :payload_too_large}
      refute PaymentResponse.decode(at_limit) == {:error, :payload_too_large}
      refute PaymentSignature.decode(at_limit) == {:error, :payload_too_large}
      refute ExtensionResponses.decode(at_limit) == {:error, :payload_too_large}
    end
  end
end
