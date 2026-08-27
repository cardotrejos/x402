# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub private vulnerability reporting](https://github.com/cardotrejos/x402/security/advisories/new)
on this repository. Do **not** open a public issue for security reports.

You can expect an acknowledgement within 72 hours. Please include a minimal
reproduction and the affected version. Coordinated disclosure is appreciated;
we will credit reporters in the release notes unless you prefer otherwise.

## Supported versions

Only the latest release published on [Hex.pm](https://hex.pm/packages/x402)
receives security fixes.

## Trust model

This library implements the **resource server** and **facilitator client**
roles of the x402 payment protocol. Understanding what it does and does not
verify matters for deploying it safely:

- **Payment signature verification is delegated to the facilitator you
  configure.** `X402.Plug.PaymentGate` validates payload structure, matches
  requirements, and runs cheap local pre-checks (payTo binding, exact amount
  equality, validity windows), but it performs no signature cryptography and
  no on-chain checks. Your resource server's payment security equals your
  facilitator's — choose one you trust, and note that no x402 SDK's server
  role independently verifies settlement on-chain.
- **Facilitator transport is enforced to `https://`** (loopback exempt for
  development), with TLS peer verification and system CA certificates on the
  default pool. Per-request facilitator authentication (Coinbase CDP JWT) is
  supported via `X402.Facilitator.Auth`.
- **Inbound payment headers are capped at 8 KB before any decoding** and
  fail closed on malformed Base64/JSON.
- **Replay protection** in `X402.Plug.PaymentGate` (the payment-identifier
  cache claim) is **per-node** with the bundled ETS adapter. In a clustered
  deployment each node claims independently — use a shared adapter
  (implementing `X402.Extensions.PaymentIdentifier.Cache`) if a duplicate
  request served by a second node is unacceptable for your resource.

## Known advisories affecting the wider x402 ecosystem

This SDK is not affected by, but its design responds to,
[GHSA-3j63-5h8p-gf7c](https://github.com/advisories/GHSA-3j63-5h8p-gf7c)
(route-matching bypass in the legacy TypeScript middleware — this SDK matches
on decoded `path_info` segments and carries regression tests for that bug
class) and
[GHSA-qr2g-p6q7-w82m](https://github.com/advisories/GHSA-qr2g-p6q7-w82m)
(SVM duplicate settlement in the official SDKs — this SDK does not implement
SVM settlement).
