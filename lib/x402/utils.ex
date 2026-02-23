defmodule X402.Utils do
  @moduledoc false

  @spec decode_base64(String.t()) :: {:ok, String.t()} | {:error, :invalid_base64}
  def decode_base64(""), do: {:error, :invalid_base64}

  def decode_base64(value) do
    case Base.decode64(value) do
      {:ok, decoded} -> {:ok, decoded}
      :error -> {:error, :invalid_base64}
    end
  end
end
