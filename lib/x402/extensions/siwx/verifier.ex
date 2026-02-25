defmodule X402.Extensions.SIWX.Verifier do
  @moduledoc """
  Behaviour for SIWX signature verification.

  Implementations verify a SIWX message signature and return whether the
  signature matches the claimed wallet address.
  """

  use X402.Behaviour, callbacks: [verify_signature: 3]

  @typedoc "Verifier return value."
  @type verify_result :: {:ok, boolean()} | {:error, term()}

  @doc """
  Verifies a signature against a message and claimed wallet address.
  """
  @callback verify_signature(
              message :: String.t(),
              signature :: String.t(),
              address :: String.t()
            ) ::
              verify_result()

  @doc since: "0.3.0"
  @doc """
  Validates that a value is a module implementing `X402.Extensions.SIWX.Verifier`.

  This function is intended for `NimbleOptions` custom validation.
  """
  @spec validate_module(term()) :: :ok | {:error, String.t()}
  def validate_module(module),
    do: X402.Behaviour.validate_implementation(module, __MODULE__, @required_callbacks)
end
