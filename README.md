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

## Blockchain Interaction

For limited access to supported blockchain source of truth data `:diode_client` supports reading from smart contracts and calling contract methods. For each supported blockchain there is a `Shell` configured, currently supported blockchains are:

- Diode L1 (`DiodeClient.Shell`) - deprecated
- Moonbeam (`DiodeClient.Shell.Moonbeam`) - https://moonbeam.network/
- Oasis Sapphire (`DiodeClient.Shell.OasisSapphire`) - https://oasis.net/sapphire
- Anvil (`DiodeClient.Shell.Anvil`) – local test chain from [Foundry](https://getfoundry.sh/); see [docs/anvil.md](docs/anvil.md) for test setup

Each shell supports `call/5` and other methods to read contract data and send transactions.

Example of making a ZTNA contract call on Oasis Sapphire:

```elixir
alias DiodeClient.{Base16, Shell}

Shell.OasisSapphire.call(
  Base16.decode("0xb78700e7254F54b418bdF6DE7109128D1Fe8E8DD"),
  "getPropertyValue",
  ["address", "string"],
  [Base16.decode("0x90983fc294577b6f00CBd5D3b26aDf2e85Ca2Cac"), "public"],
  result_types: "string"
)
```

## Mix tasks

When using this repo as a dependency, run these from your application root (they start `:diode_client` and use your configured wallet). Run `mix help` for the full list or `mix help <task>` for details.

| Task | Description |
| ---- | ----------- |
| `mix diode.bns` | BNS register, unregister, whoami, version |
| `mix diode.resolve` | Resolve an address or BNS name (drive, members) |
| `mix diode.nodes` | List or fetch Diode network nodes |
| `mix diode.get_object` | Print a Diode ticket object for an address |
| `mix diode.publish` | Listen on a port and echo traffic |
| `mix diode.udp` | Publish or consume a Diode UDP port |
| `mix diode.evm_call` | Trace an `eth_call` via `cast` (Oasis Sapphire) |
| `mix diode.evm_transaction` | Send a test Oasis Sapphire transaction via `cast` |

Examples:

```bash
mix diode.bns whoami
mix diode.bns register myname.diode 0x...
mix diode.resolve 0x...
mix diode.nodes get 0x...
mix diode.get_object 0x...
mix diode.publish 5000
mix diode.udp publish 5000
mix diode.udp consume 0x... 5000
mix diode.evm_call request.json
mix diode.evm_transaction
```

For BNS tasks, set `SEED_LIST` to reach the network (e.g. `export SEED_LIST=us1.prenet.diode.io`).

## Architecture

Internal design notes for contributors:

- [Connection process and lifecycle](docs/connection-lifecycle.md) — relay `Connection` states, `remote_closed`, block subscribe/poll fallback, Manager restarts
- [Anvil test shell](docs/anvil.md) — local chain setup for tests

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
