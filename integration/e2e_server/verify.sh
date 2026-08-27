#!/usr/bin/env bash
# Local smoke verification for the e2e harness server component.
#
# Boots the real server supervision tree against a stub facilitator and
# asserts the harness wire contract (402 + PAYMENT-REQUIRED without payment,
# 200 + PAYMENT-RESPONSE with a well-formed PAYMENT-SIGNATURE, /health,
# /close). Run from anywhere; requires Elixir >= 1.15 with Hex installed.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

mix local.hex --force --if-missing >/dev/null
mix deps.get
mix compile --warnings-as-errors
mix format --check-formatted
mix test
