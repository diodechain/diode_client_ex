%{
  configs: [
    %{
      name: "default",

      checks: [
        {Credo.Check.Refactor.Nesting, max_nesting: 3},
        {Credo.Check.Refactor.CyclomaticComplexity, max_complexity: 14}
      ]
    }
  ]
}
