# Upstream patches for admitting the Elixir e2e server component

Target: [x402-foundation/x402](https://github.com/x402-foundation/x402) at HEAD
`8468e3ad331a277379a3e48441eac3259fe75a60` ("Fix SVM upto facilitator RPC
configuration examples (#3277)").

The component itself is `upstream/servers/elixir/http/bandit/` in this
directory — copy it verbatim to `e2e/servers/elixir/http/bandit/` in the
foundation repo. It depends on the published Hex package (`{:x402, "~> 0.5"}`),
ships its own `install.sh` / `build.sh` / `run.sh`, and declares a full local
`test.config.json` overlay (endpoints, environment, capability matrix), so the
harness does not need catalog-driven config synthesis for Elixir.

What the component declares (what the SDK supports today):

| Dimension | Value |
|---|---|
| `x402Version` | 2 (server implements v2 only) |
| `protocolFamilies` | `["evm"]` |
| `schemes` | `["exact"]` |
| `evm.assetTransferMethods` | `["eip3009"]` |
| transport | `http` |
| `extensions` | `[]` (no bazaar discovery declaration yet) |
| paid endpoints | `GET /exact/evm/eip3009` |

## Required patches

### 1. `e2e/src/component.ts` — discovery language whitelist

Discovery walks `servers/<language>/<transport>/...` and skips directories
whose language is not whitelisted.

```diff
-const LANGUAGES = new Set(['typescript', 'go', 'python']);
+const LANGUAGES = new Set(['typescript', 'go', 'python', 'elixir']);
```

No change is needed in `resolveRunCommand`: it prefers a local `run.sh` when
present (there is **no run-command whitelist at HEAD**), and the component
ships one (`exec mix run --no-halt`). `isComponentDir` already recognizes the
directory via its `test.config.json`.

`synthesizeVanillaConfig` and `enrichConfigFromMechanisms` are bypassed because
the component carries a full local `test.config.json` (the same overlay escape
hatch `clients/typescript/http/svm-smart-wallet` uses); for an Elixir server
`enrichConfigFromMechanisms` returns the config unchanged (its SDK whitelist is
`['typescript', 'python', 'go']`), which is exactly what an explicit overlay
needs. Scenario generation does **not** gate on the *server's* language —
`schemesForSdkNetwork` is only consulted for client and facilitator languages —
so no `SdkId` change is required for this component to be paired with existing
TS/Go/Python clients and facilitators.

### 2. `e2e/setup.sh` — install/build walk language whitelist

`process_role_v2` skips unknown language directories:

```diff
     case "$language" in
-      typescript|go|python) ;;
+      typescript|go|python|elixir) ;;
       *) continue ;;
     esac
```

`has_setup_work` already fires on the component's `install.sh` / `build.sh`,
so `default_install` / `default_build` need no Mix knowledge.

### 3. `e2e/config/mechanisms_evm.json` — list Elixir on the route it serves

Route support is listed per route via `sdks` (README: "Route support is
**listed** on each route via `sdks`, never inferred"). The Elixir server's own
catalog loader (`lib/e2e_server/catalog.ex`, the analogue of
`servers/python/catalog.py`) selects routes by `"elixir"` membership:

```diff
     "/exact/evm/eip3009": {
       "scheme": "exact",
       "assetTransferMethod": "eip3009",
       "sdks": [
         "typescript",
         "go",
-        "python"
+        "python",
+        "elixir"
       ],
```

This is runtime-safe for the TS harness (catalog JSON is parsed untyped; the
`sdks.includes(...)` checks only ever probe for the querying SDK's own id).
For type honesty, optionally widen the union in `e2e/src/mechanisms.ts`:

```diff
-export type SdkId = 'typescript' | 'python' | 'go';
+export type SdkId = 'typescript' | 'python' | 'go' | 'elixir';
```

### 4. `.github/workflows/e2e_tests.yml` — BEAM toolchain step

The workflow installs Go, uv/Python, and builds the TS SDK before
`./setup.sh`. Add an Erlang/Elixir setup step alongside them (after
"Install Python", before "Install and build TypeScript SDK"):

```diff
       - name: Install Python
         if: steps.families.outputs.configured == 'true'
         run: uv python install 3.10

+      - name: Setup Erlang/Elixir
+        if: steps.families.outputs.configured == 'true'
+        uses: erlef/setup-beam@8aa8a857c6be0daae6e97272bb299d5b942675a4 # v1.20.4
+        with:
+          otp-version: "27"
+          elixir-version: "1.18"
+
       - name: Install and build TypeScript SDK
```

(The workflow pins actions by commit SHA; pin whatever current `erlef/setup-beam`
release is trusted at merge time.) No new secrets are needed: the component
only reads `SERVER_EVM_ADDRESS`, which the workflow already writes to `e2e/.env`,
and family selection (`scripts/ci-select-families.sh`) is catalog-driven.

## Optional / cosmetic patches

- `e2e/src/cli/filters.ts` — `SDK_ALIASES` could gain `ex: 'elixir'`;
  `--sdk=elixir` already works because unknown ids pass through lowercased.
  (Note `--sdk` keeps only scenarios whose client, server, **and** facilitator
  are that language, so an elixir-only `--sdk` run matches nothing until Elixir
  client/facilitator components exist. Use `--servers=elixir/http/bandit`
  to select the server directly.)
- `e2e/README.md` — extend the "Add an HTTP framework" table with an Elixir
  row (`servers/elixir/http/<name>/` + local `install.sh`/`run.sh` +
  `test.config.json` overlay).
- `e2e/src/mechanisms.ts` — to eventually drop the local `test.config.json`
  overlay and go fully catalog-driven (vanilla inference), add `'elixir'` to
  the whitelist inside `enrichConfigFromMechanisms`
  (`['typescript', 'python', 'go']`) as well as `SdkId`. Not required for
  admission; the overlay is the smaller first step.

## Behavior notes for upstream reviewers

- **Readiness / lifecycle**: the server prints `Server listening on port N`
  on stdout after the listener is bound (the `readyLog` the
  `GenericServerProxy` waits for), serves `GET /health`
  (`{"status": "healthy", ...}`) and `POST /close` (responds
  `{"message": "Server shutting down gracefully", ...}` then exits 0).
- **Startup route check**: after health, the harness GETs every declared paid
  route without payment; the component answers `402` with a Base64
  `PAYMENT-REQUIRED` header (v2 `PaymentRequired` schema), never 404/405.
- **Config**: `PORT`, `FACILITATOR_URL`, `SERVER_EVM_ADDRESS`,
  `EVM_NETWORK` (CAIP-2, defaults to the catalog testnet `eip155:84532`),
  and `E2E_MECHANISMS_CATALOG` are honored; `E2E_EXCLUDE_SCHEMES` /
  `E2E_EXCLUDE_NETWORKS` narrow the served routes. Routes whose network payee
  is unset are dropped (unconfigured catalog paths answer 501 with the same
  payload shape as the Python servers).
- **Prices**: the catalog's `"$0.001"` USD price is converted against the
  network's default USD asset (Base Sepolia USDC, 6 decimals → amount
  `"1000"`, `extra: {"name": "USDC", "version": "2"}`), matching the
  TypeScript SDK's `DEFAULT_ASSETS` table.
- **Extensions**: the component declares `extensions: []`. The catalog route
  lists `bazaar`, but the endpoint overlay intentionally omits it — the Elixir
  SDK does not yet emit the bazaar discovery declaration on payment
  requirements, and `shouldRunDiscoveryValidation` only runs against servers
  whose config declares bazaar support, so bazaar-enabled runs skip this
  server. Add the declaration (and drop the narrowing) once the SDK ships it.
- **Not supported yet** (kept out of the declared surface): `upto` over
  Permit2 (the SDK supports the `upto` scheme but only the `eip3009` transfer
  method), `batch-settlement`, `permit2`, non-`authorization` payment flows
  (`upfront`, `escrow`), MCP transport, and non-EVM families.
