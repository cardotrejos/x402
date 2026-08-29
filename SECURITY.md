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

This library implements the payer client, resource server, facilitator client,
and self-hosted EVM/SVM facilitator roles of the x402 payment protocol.
Understanding which checks are enabled in each deployment matters:

- **Resource servers delegate verification and settlement to their configured
  facilitator by default.** `X402.Plug.PaymentGate` always validates payload
  structure, matches the complete advertised requirements, and runs the
  registered scheme's local pre-checks. Exact-EVM routes can additionally run
  `X402.Verify.EVM` at `:structural`, `:signature`, or `:full` through the
  `:local_verification` option. This narrows trust in the facilitator but does
  not replace the settle call; choose and authenticate a facilitator you trust,
  or operate the bundled facilitator engines yourself.
- **Facilitator transport is enforced to `https://`** (loopback exempt for
  development), with TLS peer verification and system CA certificates on the
  default pool. Per-request facilitator authentication (Coinbase CDP JWT) is
  supported via `X402.Facilitator.Auth`.
- **Inbound payment headers are capped at 8 KB before any decoding** and
  fail closed on malformed Base64/JSON.
- **Replay protection** in `X402.Plug.PaymentGate` is **per-node** with the
  bundled ETS adapter. In a clustered deployment, configure a shared adapter;
  `X402.Extensions.PaymentIdentifier.RedisCache` provides an atomic Redis
  implementation. Replay keys for the built-in EVM and SVM schemes derive
  from signature-covered payment identity rather than unsigned client fields.
- **ERC-6492 counterfactual settlement is allowlist-gated.** The facilitator
  engine (`X402.Facilitator.Engine`) signs caller-supplied factory calldata
  only toward addresses explicitly listed in `:eip6492_allowed_factories`,
  capped by `:max_deploy_gas_limit`. The default empty allowlist rejects
  every counterfactual payment at verify and again at settle's independent
  re-verify, so an engine that never opts in never broadcasts
  caller-supplied calldata. Allowlist only factories you have audited — a
  listed factory receives deployment transactions paid for by your fee
  payer.
- **SVM duplicate-settlement protection is opt-in.** Production
  `X402.Facilitator.SVMEngine` deployments should configure both
  `:settlement_cache` and `:pending_settlement_store`. Without the cache,
  concurrent settle calls can all broadcast; without the pending store, an
  uncertain broadcast cannot be reconciled on retry.
- **The cryptographic verification and transaction-settlement paths have not
  yet received an independent third-party audit.** The project is still on a
  pre-1.0 release line; apply normal defense in depth, conservative allowlists,
  and testnet/live-smoke validation before handling production value.

## Known advisories affecting the wider x402 ecosystem

This SDK is not affected by, but its design responds to,
[GHSA-3j63-5h8p-gf7c](https://github.com/advisories/GHSA-3j63-5h8p-gf7c)
(route-matching bypass in the legacy TypeScript middleware — this SDK matches
on decoded `path_info` segments and carries regression tests for that bug
class) and
[GHSA-qr2g-p6q7-w82m](https://github.com/advisories/GHSA-qr2g-p6q7-w82m)
(SVM duplicate settlement in the official SDKs — the bundled SVM engine has
an atomic settlement-cache integration, but operators must configure it).
