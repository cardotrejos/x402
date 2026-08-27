defmodule X402.MCPTest do
  use ExUnit.Case, async: true

  doctest X402.MCP

  alias X402.MCP

  @payment %{"x402Version" => 2, "accepted" => %{"scheme" => "exact"}, "payload" => %{}}
  @payment_required %{
    "x402Version" => 2,
    "error" => "Payment required",
    "accepts" => [%{"scheme" => "exact"}]
  }

  describe "payment meta keys" do
    test "match the MCP transport spec" do
      assert MCP.payment_meta_key() == "x402/payment"
      assert MCP.payment_response_meta_key() == "x402/payment-response"
    end
  end

  describe "fetch_payment/1" do
    test "reads the payment from an atom-keyed _meta" do
      request = %{name: "search", _meta: %{"x402/payment" => @payment}}

      assert MCP.fetch_payment(request) == {:ok, @payment}
    end

    test "rejects payments without the payload structure" do
      request = %{"_meta" => %{"x402/payment" => %{"x402Version" => 2}}}

      assert MCP.fetch_payment(request) == :error
    end

    test "rejects non-map payments and non-map _meta" do
      assert MCP.fetch_payment(%{"_meta" => %{"x402/payment" => "paid"}}) == :error
      assert MCP.fetch_payment(%{"_meta" => "nope"}) == :error
    end
  end

  describe "put_payment/2" do
    test "preserves existing _meta entries" do
      request = %{"name" => "search", "_meta" => %{"traceId" => "abc"}}

      assert MCP.put_payment(request, @payment) == %{
               "name" => "search",
               "_meta" => %{"traceId" => "abc", "x402/payment" => @payment}
             }
    end

    test "keeps an atom :_meta key to avoid duplicate keys on encoding" do
      request = %{name: "search", _meta: %{"traceId" => "abc"}}
      updated = MCP.put_payment(request, @payment)

      assert updated[:_meta] == %{"traceId" => "abc", "x402/payment" => @payment}
      refute Map.has_key?(updated, "_meta")
    end
  end

  describe "put_payment_response/2" do
    test "preserves existing _meta entries" do
      result = %{"content" => [], "_meta" => %{"traceId" => "abc"}}
      receipt = %{"success" => true}

      assert MCP.put_payment_response(result, receipt) == %{
               "content" => [],
               "_meta" => %{"traceId" => "abc", "x402/payment-response" => receipt}
             }
    end
  end

  describe "fetch_payment_response/1" do
    test "rejects receipts without the success field" do
      result = %{"_meta" => %{"x402/payment-response" => %{"transaction" => "0xabc"}}}

      assert MCP.fetch_payment_response(result) == :error
    end
  end

  describe "fetch_payment_required/1" do
    test "requires isError to be true" do
      result = %{"structuredContent" => @payment_required, "content" => []}

      assert MCP.fetch_payment_required(result) == :error
    end

    test "falls back to parsing content[0].text as JSON" do
      result = %{
        "isError" => true,
        "content" => [%{"type" => "text", "text" => Jason.encode!(@payment_required)}]
      }

      assert MCP.fetch_payment_required(result) == {:ok, @payment_required}
    end

    test "prefers structuredContent over content text" do
      other = Map.put(@payment_required, "error", "from content")

      result = %{
        "isError" => true,
        "structuredContent" => @payment_required,
        "content" => [%{"type" => "text", "text" => Jason.encode!(other)}]
      }

      assert MCP.fetch_payment_required(result) == {:ok, @payment_required}
    end

    test "rejects non-JSON and non-PaymentRequired content" do
      not_json = %{"isError" => true, "content" => [%{"type" => "text", "text" => "boom"}]}
      wrong = %{"isError" => true, "content" => [%{"type" => "text", "text" => ~s({"a":1})}]}
      not_text = %{"isError" => true, "content" => [%{"type" => "image", "data" => "..."}]}
      empty = %{"isError" => true, "content" => []}

      assert MCP.fetch_payment_required(not_json) == :error
      assert MCP.fetch_payment_required(wrong) == :error
      assert MCP.fetch_payment_required(not_text) == :error
      assert MCP.fetch_payment_required(empty) == :error
    end

    test "requires accepts to be a list" do
      invalid = %{"x402Version" => 2, "accepts" => %{}}
      result = %{"isError" => true, "structuredContent" => invalid, "content" => []}

      assert MCP.fetch_payment_required(result) == :error
    end
  end

  describe "fetch_payment_required_from_error/1" do
    test "reads PaymentRequired directly from -32042 error data" do
      error = %{"code" => -32_042, "message" => "Elicitation", "data" => @payment_required}

      assert MCP.fetch_payment_required_from_error(error) == {:ok, @payment_required}
    end

    test "supports atom keys" do
      error = %{code: 402, message: "Payment required", data: @payment_required}

      assert MCP.fetch_payment_required_from_error(error) == {:ok, @payment_required}
    end

    test "rejects 402 errors without PaymentRequired data" do
      assert MCP.fetch_payment_required_from_error(%{"code" => 402, "data" => %{}}) == :error
      assert MCP.fetch_payment_required_from_error(%{"code" => 402}) == :error
    end

    test "rejects other error codes and non-map errors" do
      error = %{"code" => -32_600, "data" => @payment_required}

      assert MCP.fetch_payment_required_from_error(error) == :error
      assert MCP.fetch_payment_required_from_error(:timeout) == :error
    end
  end

  describe "payment_required_result/1" do
    test "content text and structuredContent carry identical data" do
      assert {:ok, result} = MCP.payment_required_result(@payment_required)
      assert result["isError"] == true
      assert result["structuredContent"] == @payment_required
      assert [%{"type" => "text", "text" => text}] = result["content"]
      assert Jason.decode!(text) == @payment_required
    end

    test "rejects maps that cannot be encoded as JSON" do
      invalid = Map.put(@payment_required, "extra", {:not, :json})

      assert MCP.payment_required_result(invalid) == {:error, :invalid_payment_required}
    end

    test "rejects non-PaymentRequired input" do
      assert MCP.payment_required_result("nope") == {:error, :invalid_payment_required}
    end
  end
end
