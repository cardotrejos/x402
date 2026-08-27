#!/usr/bin/env bash
# Regenerates the ready-to-copy upstream component from this project's source.
#
# The upstream component (upstream/servers/elixir/http/bandit/) is the same
# server with two differences: it depends on the published Hex package instead
# of the local path, and it ships no test suite or bundled catalog fixture
# (the harness injects E2E_MECHANISMS_CATALOG). Its mix.exs, scripts, and
# test.config.json are maintained by hand; lib/ is copied verbatim from here.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

DEST="upstream/servers/elixir/http/bandit"

rm -rf "$DEST/lib"
mkdir -p "$DEST/lib"
cp -R lib/. "$DEST/lib/"

echo "Synced lib/ -> $DEST/lib/"
