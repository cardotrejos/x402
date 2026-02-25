defmodule X402.Credo.Checks.NoPhoenixImports do
  @moduledoc """
  Ensures no Phoenix modules are imported in the x402 library.

  x402 is a pure Elixir library — it must never depend on Phoenix.

  ## AGENT REMEDIATION
  If this check fails, you imported a Phoenix module (e.g., Phoenix.Controller,
  Phoenix.LiveView, Phoenix.HTML). This library must work without Phoenix.

  **Fix:** Remove the Phoenix import and use pure Elixir alternatives:
  - Instead of `Phoenix.Controller.json/2` → return data, let the caller render
  - Instead of `Phoenix.HTML` → use plain strings
  - The only allowed Plug dependency is `Plug.Conn` (for the PaymentGate plug)
  """

  use Credo.Check,
    base_priority: :high,
    category: :design

  @phoenix_modules ~w(Phoenix.Controller Phoenix.LiveView Phoenix.HTML Phoenix.Channel Phoenix.Router Phoenix.Endpoint)

  @impl true
  def run(%SourceFile{} = source_file, params) do
    issue_meta = IssueMeta.for(source_file, params)

    source_file
    |> SourceFile.source()
    |> String.split("\n")
    |> Enum.with_index(1)
    |> Enum.reduce([], fn {line, line_no}, issues ->
      if phoenix_import?(line) do
        [issue_for(issue_meta, line_no, line) | issues]
      else
        issues
      end
    end)
  end

  defp phoenix_import?(line) do
    Enum.any?(@phoenix_modules, fn mod ->
      String.contains?(line, mod)
    end)
  end

  defp issue_for(issue_meta, line_no, line) do
    format_issue(issue_meta,
      message:
        "Phoenix module detected in pure library. REMOVE this import — x402 must work without Phoenix. Use pure Elixir alternatives.",
      line_no: line_no,
      trigger: String.trim(line)
    )
  end
end
