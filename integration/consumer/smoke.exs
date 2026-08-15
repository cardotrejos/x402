:ok = X402.Telemetry.emit(:payment_required, :encode, :ok)

case X402.Facilitator.HTTP.secure_pool_opts() do
  [conn_opts: [transport_opts: [verify: :verify_peer, cacerts: certificates]]]
  when is_list(certificates) and certificates != [] ->
    :ok

  invalid_options ->
    raise "unexpected secure pool options: #{inspect(invalid_options)}"
end
