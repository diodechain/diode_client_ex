#!/usr/bin/env elixir
Mix.install([{:diode_client, path: "../"}])

DiodeClient.interface_add("example_server_interface")
address = DiodeClient.Base16.encode(DiodeClient.address())

{:ok, port} = DiodeClient.port_listen(5000)

spawn_link(fn ->
  IO.puts("server #{address} started")
  {:ok, ssl} = DiodeClient.port_accept(port)
  peer = DiodeClient.Port.peer(ssl)
  IO.puts("got a connection from #{Base.encode16(peer)}")
  :ssl.controlling_process(ssl, self())
  :ssl.setopts(ssl, packet: :line, active: true)

  for x <- 1..10 do
    IO.puts("sending message #{x}")
    :ssl.send(ssl, "Hello #{Base.encode16(peer)} this is message #{x}\n")
  end

  receive do
    {:ssl_closed, _ssl} -> IO.puts("closed!")
  end
end)

Process.sleep(:infinity)
