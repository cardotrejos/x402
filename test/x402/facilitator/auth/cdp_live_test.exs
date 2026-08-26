defmodule X402.Facilitator.Auth.CDPLiveTest do
  use ExUnit.Case, async: false

  @moduletag :smoke

  @moduledoc """
  Live smoke tests against Coinbase's hosted x402 facilitator.

  These tests make real network calls to `https://api.cdp.coinbase.com/` and
  are excluded from the default test run (`ExUnit.start(exclude: [:smoke])`).
  They prove that the JWT built by `X402.Facilitator.Auth.CDP` is accepted by
  the real service and that the v2 payment wire format round-trips end to end.

  Configuration is read from environment variables:

    * `CDP_API_KEY_ID` / `CDP_API_KEY_SECRET` — facilitator credentials
      (required for the auth and end-to-end tests).
    * `X402_FACILITATOR_URL` — facilitator base URL (defaults to the CDP
      hosted facilitator).
    * `X402_PAYER_KEY` — hex private key of a wallet funded with the payment
      asset; enables the end-to-end `isValid: true` / settle assertions. The
      receiver defaults to a fresh burner wallet so the payer is never the
      recipient of its own payment.
    * `X402_CONTRACT` — the ERC-20 payment asset (defaults to USDC on Base
      Sepolia: `0x036CbD53842c5426634e7929541eC2318f3dCF7e`).
    * `X402_NETWORK` — CAIP-2 network (default `eip155:84532`).
    * `X402_RESOURCE` — resource URL (default `https://x402.org/smoke-test`).
    * `X402_MAX_TIMEOUT` — `maxTimeoutSeconds` (default `300`).
    * `X402_TOKEN_NAME` / `X402_TOKEN_VERSION` — EIP-712 domain
      (defaults `USDC` / `2`).
    * `X402_SETTLE` — set to `1` to also settle the verified payment.

  The tiered tests mean the suite is useful at every level of setup:

    1. **Negative control** — always runs, needs no credentials.
    2. **Authentication** — needs only the API credentials; proves the JWT is
       accepted (the payment itself is deliberately invalid).
    3. **End-to-end verify** — additionally needs `X402_PAYER_KEY`; asserts
       `isValid: true` on `/verify`.
    4. **Settlement** — same requirements plus `X402_SETTLE=1`; settles the
       verified payment and asserts `success: true` with a transaction hash.

  Typical run on Base Sepolia (faucet-fund `X402_PAYER_KEY` first):

      CDP_API_KEY_ID=... CDP_API_KEY_SECRET=... \\
        X402_PAYER_KEY=... X402_SETTLE=1 \\
        mix test test/x402/facilitator/auth/cdp_live_test.exs --only smoke
  """

  alias X402.Facilitator
  alias X402.Facilitator.Auth.CDP
  alias X402.Facilitator.Error
  alias X402.TestPayments

  import X402.TestHelpers

  @facilitator_url "https://api.cdp.coinbase.com/platform/v2/x402"

  describe "negative control" do
    test "CDP rejects a JWT signed with unknown credentials (401)" do
      {secret, _public_key} = X402.TestAuthKeys.ed25519()

      facilitator =
        start_smoke_facilitator(%{
          facilitator_url: @facilitator_url,
          api_key_id: "00000000-0000-0000-0000-000000000000",
          api_key_secret: secret
        })

      assert {:error, %Error{status: 401}} =
               Facilitator.verify(facilitator, %{"p" => 1}, %{"r" => 1})
    end
  end

  describe "authentication" do
    test "CDP accepts our JWT and rejects the (invalid) payment, not the auth" do
      config = live_config()
      assert_credentials!(config)
      payments = config.payments

      facilitator = start_smoke_facilitator(config)

      result =
        Facilitator.verify(
          facilitator,
          TestPayments.auth_payload(payments),
          TestPayments.requirements(payments)
        )

      assert_not_auth_rejected(result, config)
    end
  end

  describe "end-to-end verify and settle" do
    test "verifies a real signed payment and optionally settles it", %{} do
      config = live_config()
      assert_credentials!(config)
      payments = config.payments
      assert is_binary(payments.payer_key), "set X402_PAYER_KEY to run the end-to-end smoke test"

      facilitator = start_smoke_facilitator(config)
      payload = TestPayments.payload(payments, payments.payer_key)
      requirements = TestPayments.requirements(payments)

      assert {:ok, %{status: 200, body: %{"isValid" => true, "payer" => payer}}} =
               Facilitator.verify(facilitator, payload, requirements)

      expected_payer = TestPayments.derive_address(payments.payer_key)
      assert String.downcase(payer) == String.downcase(expected_payer)

      if payments.settle? do
        assert {:ok,
                %{
                  status: 200,
                  body: %{"success" => true, "transaction" => transaction}
                }} = Facilitator.settle(facilitator, payload, requirements)

        assert is_binary(transaction) and transaction != ""
      end
    end
  end

  defp live_config do
    %{
      payments: TestPayments.from_env(),
      facilitator_url: System.get_env("X402_FACILITATOR_URL") || @facilitator_url,
      api_key_id: System.get_env("CDP_API_KEY_ID"),
      api_key_secret: System.get_env("CDP_API_KEY_SECRET")
    }
  end

  defp assert_credentials!(config) do
    valid? = fn value -> is_binary(value) and value != "" end

    assert valid?.(config.api_key_id),
           "set CDP_API_KEY_ID / CDP_API_KEY_SECRET to run the live CDP smoke test"

    assert valid?.(config.api_key_secret),
           "set CDP_API_KEY_ID / CDP_API_KEY_SECRET to run the live CDP smoke test"
  end

  defp assert_not_auth_rejected(result, config) do
    case result do
      {:ok, %{status: 200, body: %{"isValid" => false}}} ->
        :ok

      {:ok, %{status: status, body: body}} when status in 200..299 ->
        flunk("CDP unexpectedly accepted the invalid payment (#{status}): #{inspect(body)}")

      {:error, %Error{status: 401, body: body}} ->
        flunk(
          "CDP rejected our JWT with 401. Wrong headers/claims/signature. Body: #{inspect(body)}"
        )

      {:error, %Error{status: status, body: _body}} when status in 400..499 ->
        :ok

      {:error, %Error{status: status, body: body}} when status in 500..599 ->
        flunk(
          "CDP returned #{status}: #{inspect(body)}. Transient upstream failure — " <>
            "rerun the smoke test (facilitator: #{config.facilitator_url})."
        )

      other ->
        flunk("Unexpected facilitator result: #{inspect(other)}")
    end
  end

  defp start_smoke_facilitator(config) do
    {:ok, finch: finch} = setup_finch(%{})
    name = String.to_atom("smoke_facilitator_#{System.unique_integer([:positive, :monotonic])}")

    start_supervised!(
      {Facilitator,
       name: name,
       finch: finch,
       url: config.facilitator_url,
       auth: {CDP, api_key_id: config.api_key_id, api_key_secret: config.api_key_secret}}
    )

    name
  end
end
