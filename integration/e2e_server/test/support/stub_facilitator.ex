defmodule E2eServer.StubFacilitator do
  @moduledoc """
  Minimal x402 v2 facilitator stub for the local smoke test.

  Accepts the v2 facilitator wire format (`POST /verify`, `POST /settle` with
  `{"x402Version": 2, "paymentPayload": ..., "paymentRequirements": ...}`)
  and approves everything structurally: `/verify` answers `isValid: true`,
  `/settle` answers `success: true` with a fake transaction hash and echoes
  the requirements' network. Each call is reported to the configured test
  process as `{:facilitator, :verify | :settle, body}`.
  """

  use Plug.Router

  plug(Plug.Parsers, parsers: [:json], json_decoder: Jason)
  plug(:match)
  plug(:dispatch)

  @fake_transaction "0x" <> String.duplicate("ab", 32)

  post "/verify" do
    notify(:verify, conn.body_params)

    payer = get_in(conn.body_params, ["paymentPayload", "payload", "from"]) || zero_address()

    send_json(conn, 200, %{"isValid" => true, "payer" => payer})
  end

  post "/settle" do
    notify(:settle, conn.body_params)

    network = get_in(conn.body_params, ["paymentRequirements", "network"]) || "eip155:84532"

    send_json(conn, 200, %{
      "success" => true,
      "transaction" => @fake_transaction,
      "network" => network,
      "payer" => zero_address()
    })
  end

  match _ do
    send_json(conn, 404, %{"error" => "Not found"})
  end

  defp notify(operation, body) do
    case :persistent_term.get({__MODULE__, :listener}, nil) do
      pid when is_pid(pid) -> send(pid, {:facilitator, operation, body})
      _absent -> :ok
    end
  end

  @doc "Registers the test process that receives `{:facilitator, op, body}` messages."
  @spec listen(pid()) :: :ok
  def listen(pid), do: :persistent_term.put({__MODULE__, :listener}, pid)

  defp zero_address, do: "0x" <> String.duplicate("00", 19) <> "01"

  defp send_json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end
end
