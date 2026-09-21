if Code.ensure_loaded?(Plug.Conn) do
  defmodule X402.Plug.EscrowBuffer do
    @moduledoc false
    alias Plug.Conn.Adapter
    alias X402.AuthCapture.Output
    @behaviour Adapter

    @doc false
    @spec run(Plug.Conn.t(), (Plug.Conn.t() -> Plug.Conn.t())) :: Plug.Conn.t()
    def run(conn, handler) do
      run(conn, handler, fn _adapter -> :ok end)
    end

    @doc false
    @spec run(Plug.Conn.t(), function(), function()) :: Plug.Conn.t()
    def run(conn, handler, observe_adapter) do
      caller = self()
      owner = spawn(fn -> discard_sent_notifications(caller) end)

      try do
        run_buffered(conn, handler, owner, observe_adapter)
      after
        send(owner, :stop)
      end
    end

    # Plug 1.14 requires a pid owner and sends completion messages even for
    # a buffer. Keep them from masquerading as real sends to the HTTP owner.
    @spec discard_sent_notifications(pid()) :: :ok
    defp discard_sent_notifications(caller) do
      monitor = Process.monitor(caller)

      receive do
        :stop -> :ok
        {:DOWN, ^monitor, :process, ^caller, _reason} -> :ok
      end
    end

    @spec run_buffered(Plug.Conn.t(), function(), pid(), function()) :: Plug.Conn.t()
    defp run_buffered(conn, handler, owner, observe_adapter) do
      tag = {make_ref(), observe_adapter}
      buffered = %{conn | adapter: {__MODULE__, {tag, conn.adapter}}, owner: owner}

      case handler.(buffered) do
        %Plug.Conn{adapter: {__MODULE__, {^tag, _adapter}}, state: state} = result
        when state in [:set, :sent] ->
          result = if state == :set, do: Plug.Conn.send_resp(result), else: result
          {__MODULE__, {^tag, adapter}} = result.adapter

          %{
            result
            | adapter: adapter,
              owner: conn.owner,
              state: :set,
              private: Map.delete(result.private, :before_send),
              resp_cookies: %{}
          }

        _invalid ->
          raise ArgumentError,
                "escrow handler must return its connection with a buffered response"
      end
    end

    @impl true
    @spec send_resp(term(), Plug.Conn.status(), Plug.Conn.headers(), Plug.Conn.body()) ::
            {:ok, binary(), term()}
    def send_resp(payload, _status, _headers, body), do: {:ok, bounded_body(body), payload}

    @spec bounded_body(iodata()) :: binary()
    defp bounded_body(body) do
      if :erlang.iolist_size(body) > Output.max_bytes(),
        do: raise(ArgumentError, "escrow response exceeds its size limit")

      IO.iodata_to_binary(body)
    end

    @impl true
    @spec read_req_body(term(), keyword()) :: tuple()
    def read_req_body({tag, {adapter, payload}}, opts) do
      case adapter.read_req_body(payload, opts) do
        {status, body, next} when status in [:ok, :more] ->
          {_ref, observe_adapter} = tag
          observe_adapter.({adapter, next})
          {status, body, {tag, {adapter, next}}}

        {:error, _reason} = error ->
          error
      end
    end

    @impl true
    @spec get_peer_data(term()) :: Plug.Conn.Adapter.peer_data()
    def get_peer_data({_tag, {adapter, payload}}), do: adapter.get_peer_data(payload)

    @impl true
    @spec get_http_protocol(term()) :: Plug.Conn.Adapter.http_protocol()
    def get_http_protocol({_tag, {adapter, payload}}), do: adapter.get_http_protocol(payload)

    if {:get_sock_data, 1} in Adapter.behaviour_info(:callbacks) do
      @impl true
      @spec get_sock_data(term()) :: Plug.Conn.Adapter.sock_data()
      def get_sock_data({_tag, {adapter, payload}}), do: adapter.get_sock_data(payload)
    end

    if {:get_ssl_data, 1} in Adapter.behaviour_info(:callbacks) do
      @impl true
      @spec get_ssl_data(term()) :: Plug.Conn.Adapter.ssl_data()
      def get_ssl_data({_tag, {adapter, payload}}), do: adapter.get_ssl_data(payload)
    end

    @impl true
    @spec send_file(term(), term(), term(), term(), term(), term()) :: no_return()
    def send_file(_payload, _status, _headers, _file, _offset, _length), do: unsupported!()

    @impl true
    @spec send_chunked(term(), term(), term()) :: no_return()
    def send_chunked(_payload, _status, _headers), do: unsupported!()

    @impl true
    @spec chunk(term(), term()) :: no_return()
    def chunk(_payload, _body), do: unsupported!()

    @impl true
    @spec inform(term(), term(), term()) :: no_return()
    def inform(_payload, _status, _headers), do: unsupported!()

    @impl true
    @spec push(term(), term(), term()) :: no_return()
    def push(_payload, _path, _headers), do: unsupported!()

    @impl true
    @spec upgrade(term(), term(), term()) :: no_return()
    def upgrade(_payload, _protocol, _opts), do: unsupported!()

    @spec unsupported!() :: no_return()
    defp unsupported! do
      raise ArgumentError,
            "escrow requires a buffered response; streaming, files, upgrades and early hints are unsupported"
    end
  end
end
