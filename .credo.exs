# ExSlop adds Credo checks for patterns common in generated code. The plugin
# enables its recommended set; `extra` adds opt-in checks this codebase
# already passes, so they guard against regressions.
%{
  configs: [
    %{
      name: "default",
      files: %{
        included: ["lib/", "test/", "mix.exs"],
        excluded: [~r"/_build/", ~r"/deps/"]
      },
      strict: true,
      plugins: [{ExSlop, []}],
      checks: %{
        extra: [
          {ExSlop.Check.Readability.ObviousComment, []},
          {ExSlop.Check.Refactor.ListFold, []},
          {ExSlop.Check.Refactor.PreferEnumSlice, []},
          {ExSlop.Check.Refactor.UseMapJoin, []},
          {Credo.Check.Refactor.DoubleBooleanNegation, []},
          {Credo.Check.Refactor.MapMap, []}
        ]
      }
    }
  ]
}
