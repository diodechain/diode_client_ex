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
