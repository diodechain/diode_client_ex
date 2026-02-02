# Start Anvil in background so :anvil tests run; if Foundry is not installed or Anvil
# fails to start, exclude :anvil tests so mix test still passes.
case DiodeClient.Anvil.Helper.start_anvil() do
  {:ok, _} -> :ok
  {:error, _} -> ExUnit.configure(exclude: [anvil: true])
end

DiodeClient.Anvil.Helper.ensure_test_env(wallet: "test_anvil")

ExUnit.start()
