# X402

[![Hex.pm](https://img.shields.io/hexpm/v/x402.svg)](https://hex.pm/packages/x402)
[![Downloads](https://img.shields.io/hexpm/dt/x402.svg)](https://hex.pm/packages/x402)
[![Docs](https://img.shields.io/badge/hex-docs-blue.svg)](https://hexdocs.pm/x402)
[![CI](https://github.com/cardotrejos/x402/actions/workflows/ci.yml/badge.svg)](https://github.com/cardotrejos/x402/actions/workflows/ci.yml)
[![Coverage](https://img.shields.io/badge/coverage-99%25-brightgreen.svg)](https://github.com/cardotrejos/x402)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**The Elixir SDK for the [x402](https://x402.org) HTTP payment protocol.**

x402 is an open standard for internet-native payments built around the HTTP `402 Payment Required` status code. This library provides everything you need to accept or make x402 payments in Elixir.

## Features

- **Protocol primitives** — encode/decode `PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, and `PAYMENT-RESPONSE` headers
- **Facilitator client** — verify and settle payments via any x402 facilitator
- **Plug middleware** — drop-in payment gate for Phoenix and Plug apps
- **Wallet validation** — EVM (Ethereum, Base, Polygon) and Solana address validation
- **Zero lock-in** — works with any facilitator, any chain, any framework
- **Fully typed** — comprehensive typespecs and Dialyzer-clean

## Installation

Add `x402` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:x402, "~> 0.1"},
    {:finch, "~> 0.19"}  # HTTP client (required for facilitator calls)
  ]
end
```

## Quick Start

### Accept payments in Phoenix

```elixir
# In your router or endpoint
plug X402.Plug.PaymentGate,
  facilitator_url: "https://x402.org/facilitator",
  routes: %{
    "GET /api/weather" => %{
      price: "0.005",
      network: "eip155:8453",
      pay_to: "0xYourWalletAddress",
      description: "Weather data API"
    }
  }
```

That's it. Requests without payment get a `402` response with payment instructions. Requests with a valid `PAYMENT-SIGNATURE` header are verified and passed through.

### Encode/decode headers manually

```elixir
# Build a PAYMENT-REQUIRED response
{:ok, header} = X402.PaymentRequired.encode(%{
  accepts: [%{
    scheme: "exact",
    network: "eip155:8453",
    price: "0.01",
    pay_to: "0xYourWallet"
  }],
  description: "Premium API access"
})

# Decode an incoming PAYMENT-SIGNATURE
{:ok, payload} = X402.PaymentSignature.decode(signature_header)

# Verify payment via facilitator
{:ok, result} = X402.Facilitator.verify(payload, requirements)
```

### Verify payments programmatically

```elixir
# Start the facilitator client in your supervision tree
children = [
  {Finch, name: MyApp.Finch},
  {X402.Facilitator, name: MyApp.Facilitator, finch: MyApp.Finch}
]

# Then verify payments
{:ok, %{status: 200}} = X402.Facilitator.verify(
  MyApp.Facilitator,
  payment_payload,
  payment_requirements
)
```

## Documentation

Full documentation is available at [HexDocs](https://hexdocs.pm/x402).

- [Getting Started](https://hexdocs.pm/x402/getting-started.html)
- [Plug/Phoenix Integration](https://hexdocs.pm/x402/plug-integration.html)
- [API Reference](https://hexdocs.pm/x402/api-reference.html)

## x402 Protocol

x402 is an open standard by [Coinbase](https://coinbase.com) for HTTP-native payments:

1. Client requests a paid resource
2. Server returns `402 Payment Required` with pricing info
3. Client pays (USDC on Base, Solana, etc.)
4. Client retries with `PAYMENT-SIGNATURE` header
5. Server verifies via facilitator and serves the resource

Learn more at [x402.org](https://x402.org) and [docs.x402.org](https://docs.x402.org).

## Related

- [`x402_proxy`](https://github.com/cardotrejos/x402_proxy) — reverse proxy that adds x402 payment gating to any API
- [x402 TypeScript SDK](https://github.com/coinbase/x402) — official Coinbase SDK
- [x402 Python SDK](https://pypi.org/project/x402/) — Python implementation

## License

MIT License — see [LICENSE](LICENSE) for details.
