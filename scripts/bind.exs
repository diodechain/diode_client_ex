#! /usr/bin/env elixir
Mix.install([{:diode_client, path: "../"}, :socket2])

defmodule Bind do
  def loop(socket, diode_address, diode_port) do
    case :gen_tcp.accept(socket) do
      {:ok, local} ->
        case DiodeClient.Port.connect(diode_address, :binary.decode_unsigned("tls:#{diode_port}")) do
          {:ok, remote} ->
            pid = spawn(__MODULE__, :client_loop, [remote, local])

            # set owner of localhost connection
            :gen_tcp.controlling_process(local, pid)

            # set owner of diode connection
            :ssl.controlling_process(remote, pid)
            :ssl.setopts(remote, active: true)

          {:error, :closed} ->
            IO.puts("Socket closed")
            :ok

          {:error, :timeout} ->
            IO.puts("Socket timeout")
            :ok
        end
    end

    # call itself at the end to accept multiple connections after each other
    loop(socket, diode_address, diode_port)
  end

  def client_loop(remote, local) do
    # pattern match on socket - "let it crash"
    receive do
      {:ssl, ^remote, data} ->
        :gen_tcp.send(local, data)
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

# this code all runs first

# call like this from scripts dir: elixir bind.exs 1080 "0xe4297e2c6b87650090a3a8da45b8520dd870efc1" 1080
args = System.argv()

port = Enum.at(args, 0) |> String.to_integer()
diode_address = Enum.at(args, 1)
diode_port = Enum.at(args, 2) |> String.to_integer()

# :hackney_trace.enable(:max, :io)
# Logger.configure(level: :debug)
# Logger.put_application_level(:diode_client, :debug)

DiodeClient.interface_add("bind_interface")
IO.puts("Interface Address: 0x" <> Base.encode16(DiodeClient.address(), case: :lower))
{:ok, socket} = :gen_tcp.listen(port, active: true)
IO.puts("Binding to localhost:#{port}")
Bind.loop(socket, diode_address, diode_port)
