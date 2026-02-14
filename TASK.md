# Task: CI/Coverage Setup

Set up GitHub Actions CI and code coverage for the x402 Elixir library.

## Read First
- CLAUDE.md — all coding standards
- mix.exs — current project config

## Requirements

### 1. mix ci alias
Add a `ci` alias to mix.exs that runs all quality checks in order:
```elixir
defp aliases do
  [
    ci: [
      "compile --warnings-as-errors",
      "format --check-formatted",
      "credo --strict",
      "test --cover"
    ]
  ]
end
```

### 2. Fix preferred_cli_env deprecation
Move `preferred_cli_env` from `project/0` to a new `cli/0` function in mix.exs:
```elixir
def cli do
  [preferred_envs: [coveralls: :test, "coveralls.detail": :test, "coveralls.html": :test, "coveralls.github": :test, ci: :test]]
end
```

### 3. GitHub Actions CI (.github/workflows/ci.yml)
```yaml
name: CI
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        elixir: ['1.19']
        otp: ['27']
    steps:
      - uses: actions/checkout@v4
      - uses: erlef/setup-beam@v1
        with:
          elixir-version: ${{ matrix.elixir }}
          otp-version: ${{ matrix.otp }}
      - name: Cache deps
        uses: actions/cache@v4
        with:
          path: |
            deps
            _build
          key: ${{ runner.os }}-mix-${{ hashFiles('mix.lock') }}
          restore-keys: ${{ runner.os }}-mix-
      - run: mix deps.get
      - run: mix compile --warnings-as-errors
      - run: mix format --check-formatted
      - run: mix credo --strict
      - run: mix test
      - run: mix compile --no-optional-deps --warnings-as-errors
        name: Compile without optional deps
```

### 4. ExCoveralls Configuration
Ensure excoveralls is properly configured in mix.exs with minimum coverage of 90%.
Add to project config:
```elixir
test_coverage: [tool: ExCoveralls, minimum_coverage: 90],
```

### 5. README Badge
Add CI badge to README.md:
```markdown
[![CI](https://github.com/cardotrejos/x402/actions/workflows/ci.yml/badge.svg)](https://github.com/cardotrejos/x402/actions/workflows/ci.yml)
```

### Quality Gates
- mix compile --warnings-as-errors
- mix format --check-formatted
- mix credo --strict — 0 issues
- The CI workflow YAML must be valid

When done, run: openclaw system event --text "Done: x402 ci coverage" --mode now
