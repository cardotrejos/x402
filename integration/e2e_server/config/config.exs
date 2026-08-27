import Config

# In test, the smoke test boots the server supervisor itself with an
# explicit configuration instead of reading the process environment.
if config_env() == :test do
  config :x402_e2e_server, start_server: false
end
