# Using the Anvil shell in tests

[Anvil](https://getfoundry.sh/) is a local test chain from Foundry. `DiodeClient.Shell.Anvil` lets libraries that depend on `:diode_client` run unit and integration tests against a temporary chain without hitting real networks.

RPC URL and chain ID are configurable via `ANVIL_RPC_URL` (default `http://127.0.0.1:8545`) and `ANVIL_CHAIN_ID` (default `31337`).

## Prerequisites

- [Foundry](https://getfoundry.sh/) (`anvil` and `forge` on `PATH`). Install with: `curl -L https://foundry.paradigm.xyz | bash` then `foundryup`.
- Optional: [diode_contract](https://github.com/diodechain/diode_contract) and `ANVIL_CONTRACT_REPO_PATH` if you need `DiodeClient.Contracts.Factory.contracts(DiodeClient.Shell.Anvil)` (e.g. identity/factory tests).

## Starting Anvil for tests

- **Manual**: In a separate terminal run `anvil` (default: `http://127.0.0.1:8545`). Leave it running while you run `mix test`.
- **Helper (recommended)**: Call `DiodeClient.Anvil.Helper.start_anvil()` from your `test/test_helper.exs` before `ExUnit.start()`. It spawns Anvil in the background and waits until the RPC is reachable (or times out). If Foundry is not installed or Anvil fails to start, exclude `:anvil` tests so `mix test` still passes. See the test_helper examples below.

## Initialization in `test/test_helper.exs`

### 1. Start Anvil in background + wallet (recommended)

`mix test` works with no manual Anvil:

```elixir
case DiodeClient.Anvil.Helper.start_anvil() do
  {:ok, _} -> :ok
  {:error, _} -> ExUnit.configure(exclude: [anvil: true])
end
DiodeClient.Anvil.Helper.ensure_test_env(wallet: "test_anvil")
ExUnit.start()
```

### 2. Anvil only (manual start)

You start Anvil yourself; no contract deployment:

```elixir
DiodeClient.Anvil.Helper.ensure_test_env(wallet: "test_anvil")
ExUnit.start()
```

### 3. Exclude `:anvil` when Anvil is not running

So `mix test` passes without Foundry:

```elixir
if not DiodeClient.Anvil.Helper.anvil_reachable?() do
  ExUnit.configure(exclude: [anvil: true])
end
DiodeClient.Anvil.Helper.ensure_test_env(wallet: "test_anvil")
ExUnit.start()
```

### 4. Anvil + deploy diode_contract

For tests that need `Factory.contracts(DiodeClient.Shell.Anvil)`:

```elixir
case DiodeClient.Anvil.Helper.ensure_test_env(wallet: "test_anvil", deploy_contracts: true) do
  :ok -> :ok
  {:error, :anvil_not_reachable} -> ExUnit.configure(exclude: [anvil: true])
  {:error, _} -> ExUnit.configure(exclude: [anvil: true])
end
ExUnit.start()
```

## In your tests

- Use `DiodeClient.Shell.Anvil` like any other shell: `Anvil.peak()`, `Anvil.get_account(address)`, `Anvil.call(...)`, etc.
- Tag tests that require Anvil with `@tag :anvil` so you can exclude them when Anvil is not running: `mix test --exclude anvil`.
- If you use `ensure_test_env(deploy_contracts: true)`, you can call `DiodeClient.Contracts.Factory.contracts(DiodeClient.Shell.Anvil)` and use factory/drive/BNS addresses in tests.

## Helpers

- `DiodeClient.Anvil.Helper.start_anvil(opts \\ [])` – spawns Anvil in the background and waits until the RPC is reachable. Options: `:rpc_url`, `:timeout` (ms), `:port`, `:args`. Returns `{:ok, port}` or `{:error, :executable_not_found}` / `{:error, :timeout}`. Use in test_helper so `mix test` works without manually starting Anvil.
- `DiodeClient.Anvil.Helper.anvil_reachable?(rpc_url \\ nil)` – returns whether the Anvil RPC endpoint is reachable (e.g. to conditionally exclude `:anvil` tests).
- `DiodeClient.Anvil.Helper.ensure_test_env(opts \\ [])` – one-shot setup: optional wallet (`:wallet`), optional deploy of diode_contract (`:deploy_contracts`), optional `:rpc_url`. Returns `:ok` or `{:error, reason}` (e.g. `:anvil_not_reachable`).

## Environment variables

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `ANVIL_RPC_URL` | `http://127.0.0.1:8545` | Anvil JSON-RPC URL. |
| `ANVIL_CHAIN_ID` | `31337` | Anvil chain ID. |
| `ANVIL_CONTRACT_REPO_PATH` | (none) | Path to a clone of [diode_contract](https://github.com/diodechain/diode_contract); if unset, deployment clones to a temp dir. |
