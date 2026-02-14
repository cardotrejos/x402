# Task: Build the Facilitator Client

Read CLAUDE.md for coding standards. This is an Elixir LIBRARY following Dashbit/Jose Valim conventions.

## Modules to create:

### 1. lib/x402/facilitator.ex — X402.Facilitator (GenServer)
- start_link/1 with NimbleOptions validation for: :name, :url (default "https://x402.org/facilitator"), :finch (required), :max_retries (default 2), :retry_backoff_ms (default 100), :receive_timeout_ms (default 5000)
- verify/2 and verify/3: verify payment payload against requirements via facilitator /verify
- settle/2 and settle/3: settle payment via facilitator /settle  
- child_spec/1 for supervision tree integration
- Returns {:ok, %{status: integer, body: map}} or {:error, %X402.Facilitator.Error{}}
- Emits telemetry events via :telemetry.span

### 2. lib/x402/facilitator/http.ex — X402.Facilitator.HTTP
- Pure HTTP transport functions (no GenServer state)
- request/5: makes the actual Finch HTTP request
- Retry logic with exponential backoff for transient errors (408, 429, 500, 502, 503, 504)
- Structured error types

### 3. lib/x402/facilitator/error.ex — X402.Facilitator.Error
- Defexception with fields: type, status, body, reason, retryable, attempt
- Nice message/1 implementation

## Tests (use Bypass to mock HTTP):
- Successful verify and settle
- HTTP errors (400, 401, 500)
- Transient errors with retry
- Timeout handling
- Invalid JSON responses
- NimbleOptions validation errors

Test files: test/x402/facilitator_test.exs, test/x402/facilitator/http_test.exs
Create test/support/test_helpers.ex with shared Bypass setup.

Run mix test && mix compile --warnings-as-errors. Commit when passing.
When finished, run: openclaw system event --text "Done: x402 facilitator client" --mode now
