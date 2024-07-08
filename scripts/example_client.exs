#!/usr/bin/env elixir
Mix.install([{:diode_client, path: "../"}])

# Client: Below enter your server address
server_address = "0x389eba94b330140579cdce1feb1a6e905ff876e6"
DiodeClient.interface_add("example_client_interface")
address = DiodeClient.Base16.encode(DiodeClient.address())

spawn_link(fn ->
  IO.puts("client #{address} started")
  {:ok, ssl} = DiodeClient.port_connect(server_address, 5000)
  :ssl.controlling_process(ssl, self())
  :ssl.setopts(ssl, packet: :line, active: true)

  Enum.reduce_while(1..10, nil, fn _, _ ->
    receive do
      {:ssl, _ssl, msg} -> {:cont, IO.inspect(msg)}
      other -> {:halt, IO.inspect(other)}
    end
  end)

  :ssl.close(ssl)
  IO.puts("closed!")
end)

Process.sleep(:infinity)
