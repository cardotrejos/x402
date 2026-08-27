defmodule X402.Paywall.Default do
  @moduledoc """
  Self-contained HTML paywall page for browser-facing 402 responses.

  Renders a single lean page — inline CSS, no external requests, no build
  step — from a v2 `PaymentRequired` payload:

    * the resource description plus amount, asset, network, and recipient
      for every advertised payment option
    * the exact Base64 `PAYMENT-REQUIRED` header value for tooling, with
      manual retry instructions
    * a minimal EIP-1193 (`window.ethereum`) payment flow for `"exact"` EVM
      options using the default `eip3009` asset transfer method: connect a
      wallet, sign the `TransferWithAuthorization` typed data via
      `eth_signTypedData_v4`, assemble the v2 `PaymentPayload`, and retry the
      request with a `PAYMENT-SIGNATURE` header

  Without a browser wallet — or when no advertised option is wallet-payable —
  the page degrades to the requirement details and the manual header
  instructions. All interpolated values are HTML-escaped and the embedded
  configuration JSON is encoded script-safe, so route descriptions and
  service names cannot inject markup.

  Configure it through `X402.Plug.PaymentGate`:

      plug X402.Plug.PaymentGate,
        paywall: X402.Paywall.Default,
        routes: [...]
  """

  @behaviour X402.Paywall

  alias X402.PaymentRequired
  alias X402.Utils

  @default_title "Payment required"

  @network_names %{
    "eip155:1" => "Ethereum",
    "eip155:10" => "OP Mainnet",
    "eip155:137" => "Polygon",
    "eip155:8453" => "Base",
    "eip155:84532" => "Base Sepolia",
    "eip155:43114" => "Avalanche",
    "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp" => "Solana",
    "solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1" => "Solana Devnet"
  }

  @page_style ~S"""
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 2rem 1rem; display: flex; justify-content: center; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; line-height: 1.5; background: #f4f5f7; color: #1c2024; }
  main { width: 100%; max-width: 34rem; background: #fff; border: 1px solid #d9dde3; border-radius: 12px; padding: 1.75rem; }
  .status { margin: 0 0 0.5rem; font-size: 0.8rem; letter-spacing: 0.08em; text-transform: uppercase; color: #6b7280; }
  h1 { margin: 0 0 0.5rem; font-size: 1.4rem; }
  .description { margin: 0 0 1.25rem; color: #4b5563; }
  .option { border: 1px solid #e5e7eb; border-radius: 8px; padding: 0.75rem 1rem; margin: 0 0 1rem; }
  .option h2 { margin: 0 0 0.5rem; font-size: 0.95rem; }
  dl { margin: 0; }
  dl div { display: flex; gap: 0.75rem; padding: 0.2rem 0; }
  dt { flex: 0 0 6.5rem; color: #6b7280; }
  dd { margin: 0; overflow-wrap: anywhere; }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.85em; }
  button { appearance: none; border: 0; border-radius: 8px; padding: 0.65rem 1.1rem; font-size: 1rem; font-weight: 600; background: #1d4ed8; color: #fff; cursor: pointer; }
  button:disabled { opacity: 0.6; cursor: wait; }
  #x402-status { min-height: 1.25rem; color: #4b5563; }
  #x402-status[data-kind="error"] { color: #b91c1c; }
  details { margin-top: 1.25rem; border-top: 1px solid #e5e7eb; padding-top: 1rem; }
  summary { cursor: pointer; font-weight: 600; }
  pre { background: #f4f5f7; border: 1px solid #e5e7eb; border-radius: 8px; padding: 0.75rem; overflow-x: auto; white-space: pre-wrap; word-break: break-all; font-size: 0.75rem; }
  @media (prefers-color-scheme: dark) {
    body { background: #111418; color: #e5e7eb; }
    main { background: #1a1f26; border-color: #2c333d; }
    .description, dt, #x402-status { color: #9ca3af; }
    #x402-status[data-kind="error"] { color: #f87171; }
    .option, details { border-color: #2c333d; }
    pre { background: #111418; border-color: #2c333d; }
  }
  """

  # The script reads all dynamic data from the JSON <script type="application/json">
  # config block, so it needs no interpolation and stays free of injection paths.
  @page_script ~S"""
  (function () {
    "use strict";

    var config = JSON.parse(document.getElementById("x402-config").textContent);
    var button = document.getElementById("x402-pay");
    var statusEl = document.getElementById("x402-status");

    function setStatus(message, kind) {
      statusEl.textContent = message;
      statusEl.dataset.kind = kind || "info";
    }

    function walletPayable(option) {
      var extra = option.extra || {};
      var transferMethod = extra.assetTransferMethod || "eip3009";
      return option.scheme === "exact" &&
        typeof option.network === "string" &&
        option.network.indexOf("eip155:") === 0 &&
        transferMethod === "eip3009" &&
        typeof extra.name === "string" &&
        typeof extra.version === "string";
    }

    var option = (config.accepts || []).filter(walletPayable)[0];

    if (!option) {
      setStatus("No option payable with a browser wallet was advertised. See the tooling instructions below.");
      return;
    }

    if (!window.ethereum || typeof window.ethereum.request !== "function") {
      setStatus("No EIP-1193 browser wallet detected. See the tooling instructions below.");
      return;
    }

    button.hidden = false;
    button.addEventListener("click", pay);

    function chainId(network) {
      return parseInt(network.split(":")[1], 10);
    }

    function randomNonce() {
      var bytes = new Uint8Array(32);
      crypto.getRandomValues(bytes);
      var hex = "";
      for (var i = 0; i < bytes.length; i++) {
        hex += bytes[i].toString(16).padStart(2, "0");
      }
      return "0x" + hex;
    }

    function buildTypedData(from) {
      var now = Math.floor(Date.now() / 1000);
      return {
        types: {
          EIP712Domain: [
            { name: "name", type: "string" },
            { name: "version", type: "string" },
            { name: "chainId", type: "uint256" },
            { name: "verifyingContract", type: "address" }
          ],
          TransferWithAuthorization: [
            { name: "from", type: "address" },
            { name: "to", type: "address" },
            { name: "value", type: "uint256" },
            { name: "validAfter", type: "uint256" },
            { name: "validBefore", type: "uint256" },
            { name: "nonce", type: "bytes32" }
          ]
        },
        primaryType: "TransferWithAuthorization",
        domain: {
          name: option.extra.name,
          version: option.extra.version,
          chainId: chainId(option.network),
          verifyingContract: option.asset
        },
        message: {
          from: from,
          to: option.payTo,
          value: option.amount,
          validAfter: String(now - 60),
          validBefore: String(now + (option.maxTimeoutSeconds || 60)),
          nonce: randomNonce()
        }
      };
    }

    function encodeBase64(text) {
      var bytes = new TextEncoder().encode(text);
      var binary = "";
      for (var i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary);
    }

    async function ensureChain() {
      var wanted = "0x" + chainId(option.network).toString(16);
      var current = await window.ethereum.request({ method: "eth_chainId" });
      if (String(current).toLowerCase() === wanted) {
        return;
      }
      await window.ethereum.request({
        method: "wallet_switchEthereumChain",
        params: [{ chainId: wanted }]
      });
    }

    function paymentError(response) {
      var header = response.headers.get("payment-required");
      if (!header) {
        return null;
      }
      try {
        return JSON.parse(atob(header)).error || null;
      } catch (error) {
        return null;
      }
    }

    function showResult(text) {
      var heading = document.createElement("h1");
      heading.textContent = "Payment accepted";
      var body = document.createElement("pre");
      body.textContent = text;
      document.querySelector("main").replaceChildren(heading, body);
    }

    async function deliver(response) {
      var contentType = response.headers.get("content-type") || "";
      var text = await response.text();
      if (contentType.indexOf("text/html") === 0) {
        document.open();
        document.write(text);
        document.close();
      } else {
        showResult(text);
      }
    }

    async function pay() {
      button.disabled = true;
      try {
        setStatus("Connecting wallet…");
        var accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
        var from = accounts[0];
        await ensureChain();
        setStatus("Waiting for signature…");
        var typedData = buildTypedData(from);
        var signature = await window.ethereum.request({
          method: "eth_signTypedData_v4",
          params: [from, JSON.stringify(typedData)]
        });
        var paymentPayload = {
          x402Version: 2,
          accepted: option,
          payload: { signature: signature, authorization: typedData.message }
        };
        if (config.extensions && Object.keys(config.extensions).length > 0) {
          paymentPayload.extensions = config.extensions;
        }
        setStatus("Submitting payment…");
        var response = await fetch(window.location.href, {
          headers: { "PAYMENT-SIGNATURE": encodeBase64(JSON.stringify(paymentPayload)) }
        });
        if (!response.ok) {
          throw new Error(paymentError(response) || "Payment failed with status " + response.status + ".");
        }
        setStatus("Payment accepted. Loading content…");
        await deliver(response);
      } catch (error) {
        var message = error && error.message ? error.message : "Payment failed.";
        if (error && error.code === 4001) {
          message = "Signature request rejected.";
        }
        setStatus(message, "error");
        button.disabled = false;
      }
    }
  })();
  """

  @doc since: "0.6.0"
  @doc """
  Renders the default HTML paywall page.

  Returns `{:error, reason}` when the payload cannot be encoded as a
  `PAYMENT-REQUIRED` header value (see `X402.PaymentRequired.encode/1`).

  ## Examples

      iex> payment_required = %{
      ...>   "x402Version" => 2,
      ...>   "error" => "PAYMENT-SIGNATURE header is required",
      ...>   "resource" => %{
      ...>     "url" => "https://example.com/premium",
      ...>     "description" => "Premium report",
      ...>     "mimeType" => "application/json"
      ...>   },
      ...>   "accepts" => [
      ...>     %{
      ...>       "scheme" => "exact",
      ...>       "network" => "eip155:84532",
      ...>       "amount" => "10000",
      ...>       "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      ...>       "payTo" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      ...>       "maxTimeoutSeconds" => 60,
      ...>       "extra" => %{"name" => "USDC", "version" => "2"}
      ...>     }
      ...>   ],
      ...>   "extensions" => %{}
      ...> }
      iex> conn_info = %{method: "GET", request_path: "/premium", status: 402}
      iex> {:ok, html} = X402.Paywall.Default.render(payment_required, conn_info)
      iex> html =~ "Premium report" and html =~ "Base Sepolia"
      true
  """
  @impl X402.Paywall
  @spec render(map(), X402.Paywall.conn_info()) :: {:ok, iodata()} | {:error, term()}
  def render(payment_required, conn_info)
      when is_map(payment_required) and is_map(conn_info) do
    case PaymentRequired.encode(payment_required) do
      {:ok, encoded_header} -> {:ok, page(payment_required, encoded_header)}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc since: "0.6.0"
  @doc """
  Returns a human-readable display name for a CAIP-2 network identifier.

  ## Examples

      iex> X402.Paywall.Default.network_display_name("eip155:8453")
      "Base"

      iex> X402.Paywall.Default.network_display_name("eip155:999999")
      "EVM chain 999999"

      iex> X402.Paywall.Default.network_display_name("otherchain:mainnet")
      "otherchain:mainnet"
  """
  @spec network_display_name(String.t()) :: String.t()
  def network_display_name(network) when is_binary(network) do
    case Map.fetch(@network_names, network) do
      {:ok, name} -> name
      :error -> fallback_network_name(network)
    end
  end

  @spec fallback_network_name(String.t()) :: String.t()
  defp fallback_network_name("eip155:" <> chain_id), do: "EVM chain #{chain_id}"
  defp fallback_network_name(network), do: network

  @spec page(map(), String.t()) :: String.t()
  defp page(payment_required, encoded_header) do
    resource = ensure_map(Utils.map_value(payment_required, {"resource", :resource}))
    accepts = ensure_list(Utils.map_value(payment_required, {"accepts", :accepts}))
    title = page_title(resource)
    description = Utils.map_value(resource, {"description", :description}) || @default_title
    config_json = Jason.encode!(payment_required, escape: :html_safe)

    """
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>#{escape(title)}</title>
    <style>#{@page_style}</style>
    </head>
    <body>
    <main>
    <p class="status">HTTP 402 &middot; Payment required</p>
    <h1>#{escape(title)}</h1>
    <p class="description">#{escape(description)}</p>
    #{options_html(accepts)}
    <section class="wallet">
    <button id="x402-pay" type="button" hidden>Pay with browser wallet</button>
    <p id="x402-status" role="status"><noscript>Enable JavaScript to pay with a browser wallet, or use the tooling instructions below.</noscript></p>
    </section>
    <details>
    <summary>Pay with your own tooling</summary>
    <p>This response also carries the value below in its <code>PAYMENT-REQUIRED</code> header. Decode the Base64 JSON, sign a payment for one of the advertised options, and retry the request with the signed payload Base64-encoded in a <code>PAYMENT-SIGNATURE</code> header.</p>
    <pre>#{escape(encoded_header)}</pre>
    </details>
    </main>
    <script type="application/json" id="x402-config">#{config_json}</script>
    <script>#{@page_script}</script>
    </body>
    </html>
    """
  end

  @spec page_title(map()) :: String.t()
  defp page_title(resource) do
    case Utils.map_value(resource, {"serviceName", :serviceName}) do
      service_name when is_binary(service_name) and service_name != "" -> service_name
      _missing -> @default_title
    end
  end

  @spec options_html([term()]) :: String.t()
  defp options_html([]), do: ~s(<p class="description">No payment options were advertised.</p>)

  defp options_html(accepts) do
    total = length(accepts)

    accepts
    |> Enum.with_index(1)
    |> Enum.map_join("\n", fn {accept, index} -> option_html(accept, index, total) end)
  end

  @spec option_html(term(), pos_integer(), pos_integer()) :: String.t()
  defp option_html(accept, index, total) when is_map(accept) do
    scheme = Utils.map_value(accept, {"scheme", :scheme})
    network = Utils.map_value(accept, {"network", :network})

    """
    <section class="option">
    #{option_heading(index, total)}<dl>
    <div><dt>Amount</dt><dd><code>#{escape(Utils.map_value(accept, {"amount", :amount}))}</code> atomic units#{amount_note(scheme)}</dd></div>
    <div><dt>Network</dt><dd>#{escape(network_name(network))} &middot; <code>#{escape(network)}</code></dd></div>
    <div><dt>Asset</dt><dd><code>#{escape(Utils.map_value(accept, {"asset", :asset}))}</code></dd></div>
    <div><dt>Pay to</dt><dd><code>#{escape(Utils.map_value(accept, {"payTo", :payTo}))}</code></dd></div>
    <div><dt>Scheme</dt><dd><code>#{escape(scheme)}</code></dd></div>
    </dl>
    </section>
    """
  end

  defp option_html(_accept, _index, _total), do: ""

  @spec option_heading(pos_integer(), pos_integer()) :: String.t()
  defp option_heading(_index, 1), do: ""
  defp option_heading(index, _total), do: "<h2>Option #{index}</h2>\n"

  @spec amount_note(term()) :: String.t()
  defp amount_note("upto"), do: " (maximum)"
  defp amount_note(_scheme), do: ""

  @spec network_name(term()) :: String.t()
  defp network_name(network) when is_binary(network), do: network_display_name(network)
  defp network_name(_network), do: "Unknown network"

  @spec ensure_map(term()) :: map()
  defp ensure_map(value) when is_map(value), do: value
  defp ensure_map(_value), do: %{}

  @spec ensure_list(term()) :: [term()]
  defp ensure_list(value) when is_list(value), do: value
  defp ensure_list(_value), do: []

  @spec escape(term()) :: String.t()
  defp escape(nil), do: ""

  defp escape(value) when is_binary(value) do
    value
    |> String.replace("&", "&amp;")
    |> String.replace("<", "&lt;")
    |> String.replace(">", "&gt;")
    |> String.replace("\"", "&quot;")
    |> String.replace("'", "&#39;")
  end

  defp escape(value) when is_number(value) or is_atom(value), do: value |> to_string() |> escape()
  defp escape(value), do: value |> inspect() |> escape()
end
