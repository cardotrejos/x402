defmodule X402.Paywall.DefaultTest do
  use ExUnit.Case, async: true
  doctest X402.Paywall.Default

  alias X402.PaymentRequired
  alias X402.Paywall.Default

  @conn_info %{method: "GET", request_path: "/api/resource", status: 402}

  @accept %{
    "scheme" => "exact",
    "network" => "eip155:84532",
    "amount" => "10000",
    "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
    "payTo" => "0x1111111111111111111111111111111111111111",
    "maxTimeoutSeconds" => 60,
    "extra" => %{"name" => "USDC", "version" => "2"}
  }

  defp payment_required(overrides \\ %{}) do
    Map.merge(
      %{
        "x402Version" => 2,
        "error" => "PAYMENT-SIGNATURE header is required",
        "resource" => %{
          "url" => "http://www.example.com/api/resource",
          "description" => "Premium market data",
          "mimeType" => "application/json"
        },
        "accepts" => [@accept],
        "extensions" => %{}
      },
      overrides
    )
  end

  describe "render/2" do
    test "renders price, network, asset, and recipient" do
      assert {:ok, html} = Default.render(payment_required(), @conn_info)

      assert html =~ "10000"
      assert html =~ "eip155:84532"
      assert html =~ "Base Sepolia"
      assert html =~ "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
      assert html =~ "0x1111111111111111111111111111111111111111"
      assert html =~ "Premium market data"
    end

    test "embeds the exact Base64 PAYMENT-REQUIRED header value" do
      payload = payment_required()
      {:ok, encoded_header} = PaymentRequired.encode(payload)

      assert {:ok, html} = Default.render(payload, @conn_info)
      assert html =~ encoded_header
    end

    test "uses the service name as the page title when present" do
      payload =
        payment_required(%{
          "resource" => %{
            "url" => "http://www.example.com/api/resource",
            "description" => "Premium market data",
            "mimeType" => "application/json",
            "serviceName" => "Acme Data"
          }
        })

      assert {:ok, html} = Default.render(payload, @conn_info)
      assert html =~ "<title>Acme Data</title>"
      assert html =~ "<h1>Acme Data</h1>"
    end

    test "escapes hostile descriptions and service names" do
      payload =
        payment_required(%{
          "resource" => %{
            "url" => "http://www.example.com/api/resource",
            "description" => "<script>alert('desc')</script>",
            "mimeType" => "application/json",
            "serviceName" => "\"><img src=x onerror=alert(1)>"
          }
        })

      assert {:ok, html} = Default.render(payload, @conn_info)

      refute html =~ "<script>alert"
      refute html =~ "<img src=x"
      assert html =~ "&lt;script&gt;alert(&#39;desc&#39;)&lt;/script&gt;"
      assert html =~ "&quot;&gt;&lt;img src=x onerror=alert(1)&gt;"
    end

    test "keeps the embedded configuration JSON script-safe" do
      payload =
        payment_required(%{
          "resource" => %{
            "url" => "http://www.example.com/api/resource",
            "description" => "</script><script>alert('json')</script>",
            "mimeType" => "application/json"
          }
        })

      assert {:ok, html} = Default.render(payload, @conn_info)

      # The hostile description must never appear as a raw closing tag,
      # neither in the markup nor inside the JSON config block.
      refute html =~ "</script><script>alert"
    end

    test "labels upto amounts as maximums" do
      payload = payment_required(%{"accepts" => [Map.put(@accept, "scheme", "upto")]})

      assert {:ok, html} = Default.render(payload, @conn_info)
      assert html =~ "(maximum)"
    end

    test "numbers the options when several are advertised" do
      solana = %{
        @accept
        | "network" => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
          "asset" => "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
          "extra" => %{}
      }

      assert {:ok, html} =
               Default.render(payment_required(%{"accepts" => [@accept, solana]}), @conn_info)

      assert html =~ "Option 1"
      assert html =~ "Option 2"
      assert html =~ "Solana"
    end

    test "renders a note when no options are advertised" do
      assert {:ok, html} = Default.render(payment_required(%{"accepts" => []}), @conn_info)
      assert html =~ "No payment options were advertised."
    end

    test "returns an error for payloads the header encoder rejects" do
      payload = payment_required(%{"extensions" => %{"bad" => {:not, :json}}})

      assert {:error, :invalid_json} = Default.render(payload, @conn_info)
    end

    test "produces a lean, self-contained page" do
      assert {:ok, html} = Default.render(payment_required(), @conn_info)

      # No external requests: no src/href/url() pointing anywhere.
      refute html =~ "http-equiv"
      refute html =~ ~r/<(script|link|img|iframe)[^>]*\ssrc=/
      refute html =~ "<link"
      refute html =~ "@import"
      assert byte_size(html) < 16_384
    end

    test "guards content delivery against cross-origin and redirected HTML" do
      assert {:ok, html} = Default.render(payment_required(), @conn_info)

      # document.write executes as the current origin — the script must gate
      # it on same-origin, non-redirected responses (security review finding).
      assert html =~ "response.redirected"
      assert html =~ "window.location.origin"
      assert html =~ ~r/sameOrigin && !response\.redirected/
    end

    test "never re-enables payment after a settled payment fails to display" do
      assert {:ok, html} = Default.render(payment_required(), @conn_info)

      # A deliver() failure after response.ok must not re-enable the pay
      # button — a retry would sign a fresh nonce and settle a second payment.
      assert html =~ "Do not pay again"
    end
  end
end
