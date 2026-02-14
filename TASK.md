# Task: Final Polish for Hex.pm Publish

## Goal
Prepare x402 library for publishing to Hex.pm. Everything must be ready for `mix hex.publish`.

## Steps

1. **mix.exs package metadata**: Add/verify all hex.pm fields:
   - `description` (one-line summary)
   - `package` with `licenses: ["MIT"]`, `links`, `files`, `maintainers`
   - `source_url` pointing to GitHub
   - `homepage_url` pointing to docs or GitHub
   - Verify `name: "x402"` is correct

2. **Verify mix hex.build works**: Run `mix hex.build` and check output for warnings

3. **README badges**: Add badges for:
   - Hex.pm version: `[![Hex.pm](https://img.shields.io/hexpm/v/x402.svg)](https://hex.pm/packages/x402)`
   - Hex.pm downloads: `[![Downloads](https://img.shields.io/hexpm/dt/x402.svg)](https://hex.pm/packages/x402)`
   - CI status (already exists)
   - License badge

4. **mix compile --no-optional-deps --warnings-as-errors**: Must pass (Finch is optional!)

5. **ExDoc extras**: Verify `docs` config in mix.exs includes:
   - `main: "readme"` or `main: "X402"`
   - `extras: ["README.md", "CHANGELOG.md", "LICENSE"]`
   - `source_ref` pointing to main branch

6. **CHANGELOG.md**: Create with initial 0.1.0 entry listing all features

7. **LICENSE**: Verify MIT license file exists

8. **Run ALL quality gates**:
   - `mix compile --warnings-as-errors`
   - `mix compile --no-optional-deps --warnings-as-errors`
   - `mix test` (0 failures)
   - `mix format --check-formatted`
   - `mix credo --strict`

## Completion
When done, run: `openclaw system event --text "Done: x402 hex publish prep" --mode now`
