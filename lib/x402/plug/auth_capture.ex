if Code.ensure_loaded?(Plug.Conn) do
  defmodule X402.Plug.AuthCapture do
    @moduledoc false

    alias X402.AuthCapture.EVM
    alias X402.AuthCapture.Output
    alias X402.AuthCapture.Resource
    alias X402.AuthCapture.Transport
    alias X402.Plug.EscrowBuffer

    @options [
      resource: [type: {:custom, Transport, :validate_resource, []}, required: true],
      handler: [type: {:fun, 1}, required: true]
    ]

    @doc false
    @spec validate(term()) :: {:ok, map() | nil} | {:error, term()}
    def validate(nil), do: {:ok, nil}

    def validate(opts) when is_list(opts) do
      with {:ok, opts} <- NimbleOptions.validate(opts, @options),
           %Resource{} <- opts[:resource] do
        {:ok, Map.new(opts)}
      else
        nil -> {:error, "expected an auth-capture resource"}
        {:error, reason} -> {:error, Exception.message(reason)}
      end
    end

    def validate(_opts), do: {:error, "expected resource and handler options"}

    @doc false
    @spec run(map(), Plug.Conn.t(), map(), map()) :: {tuple(), Plug.Conn.t()}
    def run(config, conn, envelope, requirements) do
      ref = make_ref()

      try do
        result =
          Resource.run_guarded(config.resource, envelope, requirements, fn ->
            buffered =
              EscrowBuffer.run(conn, config.handler, fn adapter ->
                Process.put(ref, adapter)
              end)

            encode_response(buffered)
          end)

        {result, %{conn | adapter: Process.get(ref, conn.adapter)}}
      after
        Process.delete(ref)
      end
    end

    @spec encode_response(Plug.Conn.t()) :: {:ok, map(), non_neg_integer()} | {:error, term()}
    defp encode_response(%{status: status}) when status >= 400, do: {:error, :handler_failed}

    defp encode_response(conn) do
      with {:ok, amount} <- EVM.parse_uint256(conn.private[:x402_settlement_amount]),
           true <- div(byte_size(conn.resp_body) + 2, 3) * 4 < Output.max_bytes() do
        {:ok,
         %{
           "status" => conn.status,
           "headers" => Enum.map(conn.resp_headers, fn {name, value} -> [name, value] end),
           "body" => Base.encode64(IO.iodata_to_binary(conn.resp_body))
         }, amount}
      else
        false -> {:error, :response_too_large}
        {:error, _reason} = error -> error
      end
    end

    @doc false
    @spec restore(Plug.Conn.t(), map()) :: Plug.Conn.t()
    def restore(conn, response) do
      %{
        conn
        | status: response["status"],
          resp_body: Base.decode64!(response["body"]),
          resp_headers: Enum.map(response["headers"], fn [name, value] -> {name, value} end),
          resp_cookies: %{},
          private: Map.delete(conn.private, :before_send),
          state: :set
      }
    end
  end
end
