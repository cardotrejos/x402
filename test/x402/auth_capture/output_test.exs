defmodule X402.AuthCapture.OutputTest do
  use ExUnit.Case, async: true
  import Bitwise
  alias X402.AuthCapture.Output

  test "bounds plain JSON values before encoding and encoded escape expansion" do
    assert Output.encode(%{value: [true, false, nil, 1, -10, 1.5, "plain"]}) ==
             Jason.encode(%{value: [true, false, nil, 1, -10, 1.5, "plain"]})

    assert Output.encode(String.duplicate("x", Output.max_bytes())) == {:error, :invalid_output}

    assert Output.encode(String.duplicate("\0", div(Output.max_bytes(), 2))) ==
             {:error, :invalid_output}

    assert Output.encode(List.duplicate("x", div(Output.max_bytes(), 2))) ==
             {:error, :invalid_output}

    assert Output.encode(%{String.duplicate("x", Output.max_bytes()) => 1}) ==
             {:error, :invalid_output}

    assert Output.encode(Enum.reduce(1..66, nil, fn _, nested -> [nested] end)) ==
             {:error, :invalid_output}

    assert Output.encode(1 <<< 1024) == {:ok, Integer.to_string(1 <<< 1024)}
  end

  test "rejects custom encoders and non-JSON values without executing user code" do
    for value <- [%URI{}, self(), fn -> :ok end, {:tuple}, [1 | :tail], %{1 => 2}, <<255>>] do
      assert Output.encode(value) == {:error, :invalid_output}
    end
  end
end
