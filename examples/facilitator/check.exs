# Boot check for the example facilitator.
#
# Starts a stub JSON-RPC node on the port RPC_URL points at (localhost
# only), then exercises the running facilitator: GET /supported and a
# structurally invalid POST /verify (no chain access needed).
#
#     PRIVATE_KEY="0x$(printf '11%.0s' {1..32})" \
#       RPC_URL=http://localhost:4545 PORT=4022 mix run check.exs

defmodule FacilitatorCheck.StubRPC do
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    {:ok, body, conn} = read_body(conn)

    response =
      case Jason.decode!(body) do
        requests when is_list(requests) -> Enum.map(requests, &result/1)
        request -> result(request)
      end

    conn
    |> put_resp_content_type("application/json")
    |> send_resp(200, Jason.encode!(response))
  end

  defp result(%{"id" => id, "method" => "eth_chainId"}),
    do: %{"jsonrpc" => "2.0", "id" => id, "result" => "0x14a34"}

  defp result(%{"id" => id}), do: %{"jsonrpc" => "2.0", "id" => id, "result" => "0x"}
end

defmodule FacilitatorCheck do
  @finch FacilitatorExample.finch_name()

  def run do
    maybe_start_stub_rpc()
    base = "http://localhost:#{FacilitatorExample.port()}"

    check_supported(base)
    check_structural_verify(base)

    IO.puts("OK: facilitator booted, /supported and /verify answer as expected")
  end

  defp maybe_start_stub_rpc do
    uri = URI.parse(System.get_env("RPC_URL", "https://sepolia.base.org"))

    if uri.host in ["localhost", "127.0.0.1"] do
      {:ok, _pid} = Bandit.start_link(plug: FacilitatorCheck.StubRPC, port: uri.port)
    end
  end

  defp check_supported(base) do
    {:ok, %{status: 200, body: body}} =
      :get |> Finch.build("#{base}/supported") |> Finch.request(@finch)

    %{"kinds" => [%{"scheme" => "exact"} | _], "signers" => %{"eip155:*" => [_address]}} =
      Jason.decode!(body)
  end

  defp check_structural_verify(base) do
    requirements = %{
      "scheme" => "exact",
      "network" => System.get_env("NETWORK", "eip155:84532"),
      "amount" => "10000",
      "asset" => "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
      "payTo" => "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
      "maxTimeoutSeconds" => 60,
      "extra" => %{"name" => "USDC", "version" => "2"}
    }

    payload = %{
      "x402Version" => 2,
      "accepted" => requirements,
      "payload" => %{
        "signature" => "0x" <> String.duplicate("11", 65),
        "authorization" => %{
          "from" => "0x857b06519E91e3A54538791bDbb0E22373e36b66",
          "to" => requirements["payTo"],
          # Mismatches the required amount: rejected structurally, no RPC.
          "value" => "999",
          "validAfter" => "0",
          "validBefore" => "32503680000",
          "nonce" => "0x" <> String.duplicate("ab", 32)
        }
      }
    }

    body =
      Jason.encode!(%{
        "x402Version" => 2,
        "paymentPayload" => payload,
        "paymentRequirements" => requirements
      })

    {:ok, %{status: 200, body: response}} =
      :post
      |> Finch.build("#{base}/verify", [{"content-type", "application/json"}], body)
      |> Finch.request(@finch)

    %{
      "isValid" => false,
      "invalidReason" => "invalid_exact_evm_payload_authorization_value_mismatch"
    } = Jason.decode!(response)
  end
end

FacilitatorCheck.run()
