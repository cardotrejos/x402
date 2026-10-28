defmodule X402.TestUnloaded do
  @moduledoc false

  # Modules with optional callbacks, for tests that run them while the module
  # is not loaded yet (interactive mode loads modules lazily). Each module is
  # used by one test only, so unloading it cannot race with async tests.

  import ExUnit.Assertions

  @doc "Unloads `module` so the next call has to load it from its `.beam`."
  def unload!(module) do
    :code.purge(module)
    :code.delete(module)
    :code.purge(module)
    refute :erlang.module_loaded(module)
    module
  end

  defmodule ExtensionAdvertise do
    @moduledoc false
    @behaviour X402.Extension

    @impl true
    def key, do: "unloaded-advertise"

    @impl true
    def advertise(_opts, _context), do: %{"info" => %{"loaded" => true}}
  end

  defmodule ExtensionNotify do
    @moduledoc false
    @behaviour X402.Extension

    @impl true
    def key, do: "unloaded-notify"

    @impl true
    def after_verify(_payload, _requirements, _result, opts) do
      send(opts[:test_pid], {:unloaded_after_verify, __MODULE__})
    end

    @impl true
    def after_settle(_payload, _requirements, _result, opts) do
      send(opts[:test_pid], {:unloaded_after_settle, __MODULE__})
    end
  end

  defmodule HooksProtectedRequest do
    @moduledoc false

    def on_protected_request(_context, _metadata), do: {:halt, :skip_payment}
  end

  defmodule HooksPaymentCanceled do
    @moduledoc false

    def on_verified_payment_canceled(_context, metadata) do
      send(metadata.test_pid, {:unloaded_canceled, metadata.hook_module})
    end
  end
end
