# Start Anvil in background so :anvil tests run; if Foundry is not installed or Anvil
# fails to start, exclude :anvil tests so mix test still passes.
case DiodeClient.Anvil.Helper.start_anvil() |> IO.inspect() do
  {:ok, _} ->
    DiodeClient.Anvil.Helper.ensure_test_env(wallet: "test_anvil", deploy_contracts: true)
    :ok
  {:error, reason} ->
    Logger.warning("Failed to start Anvil: #{reason} - excluding :anvil tests")
    ExUnit.configure(exclude: [anvil: true])
end

IO.puts("Testing using address: #{DiodeClient.Base16.encode(DiodeClient.address())}")
ExUnit.start()
