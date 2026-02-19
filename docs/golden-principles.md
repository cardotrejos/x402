# Golden Principles — x402

Mechanical rules enforced by cleanup tasks. Violations get auto-fixed PRs.

## Code Principles

1. **Parse at the boundary** — All external data (HTTP headers, JSON payloads) must be validated through structs with `@enforce_keys`. No raw maps past the boundary.

2. **Behaviours for all external calls** — Every module that makes external calls (HTTP, ETS, system) must define a `@behaviour`. This enables Mox testing and swap-ability.

3. **No side effects in pure modules** — `PaymentRequired`, `PaymentSignature`, `PaymentResponse` are pure data modules. They parse and build. They never call HTTP or touch state.

4. **Telemetry on every public operation** — Every public function that does meaningful work must emit a `:telemetry` event. No silent operations.

5. **Doctests are real tests** — Every `@doc` with an example must be a working doctest. If the API changes, the doctest breaks, and that's the point.

## Style Principles

6. **One module per file** — No multi-module files except for private helper structs.

7. **@spec on every public function** — No exceptions. Dialyzer must pass clean.

8. **No magic strings** — Use module attributes or dedicated constant modules for repeated strings (header names, error codes).

## Dependency Principles

9. **No Phoenix imports** — This is a pure library. Any Phoenix dependency is a bug.

10. **Req for HTTP** — No HTTPoison, Tesla, or :httpc. Req is the only HTTP client.
