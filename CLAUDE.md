<coding_guidelines>
# CLAUDE.md — x402 Elixir SDK

The authoritative contributor guide is [AGENTS.md](AGENTS.md). Read it first; it covers the
module map, key commands, testing rules, CI readiness, and the protocol reference.

## Non-negotiables (from AGENTS.md)

- `@spec` on ALL public functions — no exceptions
- `@moduledoc` on ALL public modules
- `{:ok, result} | {:error, atom}` — never raise for expected failures
- Flat module naming: `X402.Wallet` not `X402.Utils.Validators.Wallet`
- Behaviours for extensibility (`@callback`), not app env config
- Don't add Ecto, Phoenix, or other heavy deps
- Don't make Finch required — it's optional
- Don't add runtime deps on optional libraries
</coding_guidelines>
