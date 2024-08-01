%{
  configs: [
    %{
      name: "default",
      checks: %{
        extra: [
          {Credo.Check.Refactor.Nesting, max_nesting: 3},
          {Credo.Check.Refactor.CyclomaticComplexity, max_complexity: 14}
        ],
        disabled: [
          {Credo.Check.Readability.PredicateFunctionNames, false}
        ]
      }
    }
  ]
}
