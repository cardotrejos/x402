# Quality Status — x402 Elixir SDK

> Last updated: 2026-08-28

## Current Grades

| Area | Grade | Notes |
|------|-------|-------|
| Tests | A | 95% line-coverage floor (97.0% on the v0.6.0 release candidate); 295 doctests + 1,430 tests |
| Architecture | A | Flat modules, behaviours, minimal deps — Dashbit-level |
| Docs | A | ExDoc builds cleanly; public modules and APIs are documented with release-version metadata |
| Type Safety | A | Dialyzer-clean; public APIs are expected to carry typespecs |
| Security | B+ | Fail-closed verification, TLS and size caps, canonical replay keys; independent crypto/settlement audit remains a v1.0 gate |
| Optional Deps | A | Compiles cleanly with `--no-optional-deps` |

## Coverage Target
- **Hard minimum:** 95% line coverage via ExCoveralls
- Run: `MIX_ENV=test mix coveralls`
- CI enforces this — PRs that drop below 95% fail

## Known Debt

- [ ] Property-based tests (StreamData) for PaymentRequired encode/decode
- [ ] SIWX fuzzing — edge cases in EVM signature recovery
- [ ] Benchmark idempotency cache under high concurrency (bench_ets_cache.exs exists but not in CI)
- [ ] Independent audit of cryptographic verification and facilitator settlement paths
- [ ] Credential-backed EVM/SVM settlement and Redis conformance matrix in a protected release environment
- [ ] Official upstream cross-language e2e harness acceptance and recurring run

## Testing Stack

- ExUnit (standard)
- ExCoveralls (coverage)
- Bypass (HTTP mocking for facilitator tests)
- Mox (behaviour mocking via `X402.Facilitator.HTTPBehaviour`)
- Doctests enabled on all public modules

## CI Checks (GitHub Actions)

1. `mix compile --warnings-as-errors`
2. `mix format --check-formatted`
3. `mix credo --strict`
4. `mix coveralls` (must be ≥95%)
5. `mix compile --no-optional-deps --warnings-as-errors`
6. Compile and smoke-test `integration/consumer`
7. `mix dialyzer --format github`

Release candidates additionally build ExDoc, audit Hex dependencies, inspect
the generated package, and run a clean exact-version downstream smoke test.
Credential-backed CDP, Redis, and chain settlement suites remain explicit live
gates rather than default PR checks.
