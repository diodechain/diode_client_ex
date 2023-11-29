#!/usr/bin/env elixir
# This is a sample port publisher, that listens on port 80 and forwards it to local port 8080
Mix.install([{:diode_client, path: "../"}, {:socket2, "~> 2.0.4"}])

defmodule Listener do
  def loop(socket, port) do
    case DiodeClient.Port.accept(socket) do
      {:ok, remote} ->
        {:ok, {:undefined, peer}} = :ssl.peername(remote)
        IO.puts("Accepted connection from #{DiodeClient.Base16.encode(peer)}")
        local = Socket.TCP.connect!("localhost", port)
        pid = spawn(__MODULE__, :client_loop, [remote, local])
        Socket.TCP.process!(local, pid)
        Socket.TCP.options!(local, mode: :active)
        :ssl.controlling_process(remote, pid)
        :ssl.setopts(remote, active: true)

      {:error, :closed} ->
        IO.puts("Socket closed")
        :ok

      {:error, :timeout} ->
        IO.puts("Socket timeout")
        :ok
    end

    loop(socket, port)
  end

  def client_loop(remote, local) do
    receive do
      {:ssl, ^remote, data} ->
        Socket.Stream.send!(local, data)
        client_loop(remote, local)

      {:ssl_closed, ^remote} ->
        IO.puts("Remote closed")
        :ok

      {:ssl_error, ^remote, reason} ->
        IO.puts("Remote error: #{inspect(reason)}")
        :ok

      {:tcp, ^local, data} ->
        :ssl.send(remote, data)
        client_loop(remote, local)

      {:tcp_closed, ^local} ->
        IO.puts("Local closed")
        :ok

      {:tcp_error, ^local, reason} ->
        IO.puts("Local error: #{inspect(reason)}")
        :ok
    end
  end
end

# :hackney_trace.enable(:max, :io)
Logger.configure(level: :debug)
Logger.put_application_level(:diode_client, :debug)

DiodeClient.interface_add("listener_interface")
IO.puts("Interface Address: 0x" <> Base.encode16(DiodeClient.address(), case: :lower))
{:ok, socket} = DiodeClient.Port.listen(:binary.decode_unsigned("tls:80"))
IO.puts("Listening on port 80")
Listener.loop(socket, 8080)
