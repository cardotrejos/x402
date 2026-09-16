defmodule X402.Client.SignerValidationTest do
  use ExUnit.Case, async: true

  alias X402.Client.Finch, as: FinchClient
  alias X402.MCP.Client, as: MCPClient
  alias X402.Signer.LocalKey
  alias X402.Signer.SolanaKey

  defmodule AddressOnlySigner do
    @moduledoc false
    defstruct []

    @doc false
    @spec address(struct()) :: {:ok, String.t()}
    def address(_signer), do: {:ok, "unused"}
  end

  defmodule SigningOnlySigner do
    @moduledoc false
    defstruct []

    @doc false
    @spec sign_eip712(struct(), binary(), map()) :: {:ok, binary()}
    def sign_eip712(_signer, _digest, _typed_data), do: {:ok, <<0::520>>}

    @doc false
    @spec sign_ed25519(struct(), binary()) :: {:ok, binary()}
    def sign_ed25519(_signer, _message), do: {:ok, <<0::512>>}
  end

  defmodule WrongAritySigner do
    @moduledoc false
    defstruct []

    @doc false
    @spec address(struct()) :: {:ok, String.t()}
    def address(_signer), do: {:ok, "unused"}

    @doc false
    @spec sign_eip712(struct(), binary()) :: {:ok, binary()}
    def sign_eip712(_signer, _digest), do: {:ok, <<0::520>>}

    @doc false
    @spec sign_ed25519(binary()) :: {:ok, binary()}
    def sign_ed25519(_message), do: {:ok, <<0::512>>}
  end

  for client <- [FinchClient, MCPClient] do
    describe "#{inspect(client)}.validate_signer/1" do
      @client client

      test "accepts EVM and Solana signers" do
        {:ok, evm_signer} = LocalKey.new(<<1::256>>)
        {:ok, svm_signer} = SolanaKey.new(<<1::256>>)

        assert @client.validate_signer(evm_signer) == {:ok, evm_signer}
        assert @client.validate_signer(svm_signer) == {:ok, svm_signer}
      end

      test "requires an address callback and a supported signing callback" do
        for signer <- [%AddressOnlySigner{}, %SigningOnlySigner{}, %WrongAritySigner{}] do
          assert @client.validate_signer(signer) ==
                   {:error, "expected a struct implementing X402.Signer"}
        end
      end
    end
  end
end
