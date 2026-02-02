# DiodeClient

DiodeClient secure end-to-end encrypted connections between any two machines. Connections are established
either through direct peer-to-peer TCP connections or bridged via the Diode network. To learn more about the
decentralized Diode network visit https://diode.io/

Example usage with a simple server + client. For this to work open each in individual terminal:


```elixir
# Server
DiodeClient.interface_add("example_server_interface")
address = DiodeClient.Base16.encode(DiodeClient.address())

{:ok, port} = DiodeClient.port_listen(5000)
spawn_link(fn ->
  IO.puts("server #{address} started")
  {:ok, ssl} = DiodeClient.port_accept(port)
  peer = DiodeClient.Port.peer(ssl)
  IO.puts("got a connection from #{Base.encode16(peer)}")
  :ssl.controlling_process(ssl, self())
  :ssl.setopts(ssl, [packet: :line, active: true])
  for x <- 1..10 do
    IO.puts("sending message #{x}")
    :ssl.send(ssl, "Hello #{Base.encode16(peer)} this is message #{x}\n")
  end
  receive do
    {:ssl_closed, _ssl} -> IO.puts("closed!")
  end
end)

```

And the client. Here insert in the server address the address that has been printed above.
For example `server_address = "0x389eba94b330140579cdce1feb1a6e905ff876e6"`

```elixir
  # Client: Below enter your server address
  server_address = "0x389eba94b330140579cdce1feb1a6e905ff876e6"
  DiodeClient.interface_add("example_client_interface")

  spawn_link(fn ->
    {:ok, ssl} = DiodeClient.port_connect(server_address, 5000)
    :ssl.controlling_process(ssl, self())
    :ssl.setopts(ssl, [packet: :line, active: true])
    Enum.reduce_while(1..10, nil, fn _, _ ->
      receive do
        {:ssl, _ssl, msg} -> {:cont, IO.inspect(msg)}
        other -> {:halt, IO.inspect(other)}
      end
    end)
    :ssl.close(ssl)
    IO.puts("closed!")
  end)
```

And the client. Here insert in the server address the address that has been printed above.
For example `server_address = "0x389eba94b330140579cdce1feb1a6e905ff876e6"`

```elixir
  # Client:
  server_address = "0x389eba94b330140579cdce1feb1a6e905ff876e6"
  DiodeClient.interface_add("example_client_interface")

  spawn_link(fn ->
    {:ok, ssl} = DiodeClient.port_connect(server_address, 5000)
    :ssl.controlling_process(ssl, self())
    :ssl.setopts(ssl, [packet: :line, active: true])
    Enum.reduce_while(1..10, nil, fn _, _ ->
      receive do
        {:ssl, _ssl, msg} -> {:cont, IO.inspect(msg)}
        other -> {:halt, IO.inspect(other)}
      end
    end)
    :ssl.close(ssl)
    IO.puts("closed!")
  end)
```

## Blockchain Interaction

For limited access to supported blockchain source of truth data :diode_client supports reading from smart contracts and calling contract methods. For each supported blockchain there is a `Shell` configured, currently supported blockchains are:

- Diode L1 (DiodeClient.Shell) - deprecated
- Moonbeam (Diodeclient.Shell.Moonbeam) - https://moonbeam.network/
- Oasis Sapphire (DiodeClient.Shell.OasisSapphire) - https://oasis.net/sapphire

Each of these support `call/5` and other methods to read contract data and send transactions.

- **Anvil** (DiodeClient.Shell.Anvil) – local test chain from [Foundry](https://getfoundry.sh/). Use it in **unit and integration tests** so downstream libraries can run tests against a temporary chain without hitting real networks. RPC URL and chain ID are configurable via `ANVIL_RPC_URL` (default `http://127.0.0.1:8545`) and `ANVIL_CHAIN_ID` (default `31337`).

Example of making a ZTNA contract call on Oasis Sapphire:

```elixir
alias Diodeclient.{Base16, Shell}

Shell.OasisSapphire.call(
  Base16.decode("0xb78700e7254F54b418bdF6DE7109128D1Fe8E8DD"), 
  "getPropertyValue", 
  ["address", "string"], 
  [Base16.decode("0x90983fc294577b6f00CBd5D3b26aDf2e85Ca2Cac"), "public"], 
  result_types: "string"
)

```

### Using the Anvil shell in downstream unit tests

Libraries that depend on `:diode_client` can run tests against a local Anvil chain so they don’t touch real networks. Add the following to your **test helper** and tag tests that need Anvil.

**Prerequisites**

- [Foundry](https://getfoundry.sh/) (`anvil` and `forge` on `PATH`). Install with: `curl -L https://foundry.paradigm.xyz | bash` then `foundryup`.
- Optional: [diode_contract](https://github.com/diodechain/diode_contract) and `ANVIL_CONTRACT_REPO_PATH` if you need `DiodeClient.Contracts.Factory.contracts(DiodeClient.Shell.Anvil)` (e.g. identity/factory tests).

**Starting Anvil for tests**

- **Manual**: In a separate terminal run `anvil` (default: `http://127.0.0.1:8545`). Leave it running while you run `mix test`.
- **Helper (recommended)**: Call `DiodeClient.Anvil.Helper.start_anvil()` from your `test/test_helper.exs` before `ExUnit.start()`. It spawns Anvil in the background and waits until the RPC is reachable (or times out). If Foundry is not installed or Anvil fails to start, exclude `:anvil` tests so `mix test` still passes. See the test_helper examples below.

**Initialization in `test/test_helper.exs`**

1. **Start Anvil in background + wallet** (recommended; `mix test` works with no manual Anvil):

   ```elixir
   case DiodeClient.Anvil.Helper.start_anvil() do
     {:ok, _} -> :ok
     {:error, _} -> ExUnit.configure(exclude: [anvil: true])
   end
   DiodeClient.Anvil.Helper.ensure_test_env(wallet: "test_anvil")
   ExUnit.start()
   ```

2. **Anvil only** (you start Anvil manually; no contract deployment):

   ```elixir
   DiodeClient.Anvil.Helper.ensure_test_env(wallet: "test_anvil")
   ExUnit.start()
   ```

3. **Exclude `:anvil` when Anvil is not running** (so `mix test` passes without Foundry):

   ```elixir
   if not DiodeClient.Anvil.Helper.anvil_reachable?() do
     ExUnit.configure(exclude: [anvil: true])
   end
   DiodeClient.Anvil.Helper.ensure_test_env(wallet: "test_anvil")
   ExUnit.start()
   ```

4. **Anvil + deploy diode_contract** (for tests that need `Factory.contracts(DiodeClient.Shell.Anvil)`):

   ```elixir
   case DiodeClient.Anvil.Helper.ensure_test_env(wallet: "test_anvil", deploy_contracts: true) do
     :ok -> :ok
     {:error, :anvil_not_reachable} -> ExUnit.configure(exclude: [anvil: true])
     {:error, _} -> ExUnit.configure(exclude: [anvil: true])
   end
   ExUnit.start()
   ```

**In your tests**

- Use `DiodeClient.Shell.Anvil` like any other shell: `Anvil.peak()`, `Anvil.get_account(address)`, `Anvil.call(...)`, etc.
- Tag tests that require Anvil with `@tag :anvil` so you can exclude them when Anvil is not running: `mix test --exclude anvil`.
- If you use `ensure_test_env(deploy_contracts: true)`, you can call `DiodeClient.Contracts.Factory.contracts(DiodeClient.Shell.Anvil)` and use factory/drive/BNS addresses in tests.

**Helpers**

- `DiodeClient.Anvil.Helper.start_anvil(opts \\ [])` – spawns Anvil in the background and waits until the RPC is reachable. Options: `:rpc_url`, `:timeout` (ms), `:port`, `:args`. Returns `{:ok, port}` or `{:error, :executable_not_found}` / `{:error, :timeout}`. Use in test_helper so `mix test` works without manually starting Anvil.
- `DiodeClient.Anvil.Helper.anvil_reachable?(rpc_url \\ nil)` – returns whether the Anvil RPC endpoint is reachable (e.g. to conditionally exclude `:anvil` tests).
- `DiodeClient.Anvil.Helper.ensure_test_env(opts \\ [])` – one-shot setup: optional wallet (`:wallet`), optional deploy of diode_contract (`:deploy_contracts`), optional `:rpc_url`. Returns `:ok` or `{:error, reason}` (e.g. `:anvil_not_reachable`).

**Environment variables**

| Variable | Default | Description |
| -------- | ------- | ----------- |
| `ANVIL_RPC_URL` | `http://127.0.0.1:8545` | Anvil JSON-RPC URL. |
| `ANVIL_CHAIN_ID` | `31337` | Anvil chain ID. |
| `ANVIL_CONTRACT_REPO_PATH` | (none) | Path to a clone of [diode_contract](https://github.com/diodechain/diode_contract); if unset, deployment clones to a temp dir. |

## Encryption and Authentication

For encryption standard TLS as builtin into Erlang from OpenSSL is used. For authentication though the Ethereum signature scheme using the elliptic curve `secp256k1` is used. The generated public addresses of the form `0x389eba94b330140579cdce1feb1a6e905ff876e6` actually represent hashes of public keys. When opening a port using `DiodeClient.port_open("0x389eba94b330140579cdce1feb1a6e905ff876e6", 5000)` this first locates the correct peer and then uses cryptographic handshakes to ensure the peer is in fact in possession of the corresponding private key.

To this regard the `DiodeClient` will by default store private keys in local files. In the example above `example_client_interface` and `example_server_interface`. These represent both the address as well as the private key needed to authenticate as such.

## Todos

* Add actual support for multiple interfaces in a single session
* Add standard contract call interfaces e.g. for BNS to be able to resolve human readable names such as `somename.diode`

## Installation

The package can be installed by adding `diode_client` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:diode_client, "~> 1.1"}
  ]
end
```
