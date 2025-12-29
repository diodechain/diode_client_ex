defmodule Mix.Tasks.Diode.Publish do
  @moduledoc """
  Diode Publish CLI
  """
  require Logger

  defp init() do
    Logger.configure(level: :debug)
    Application.ensure_all_started(:diode_client)
    w = DiodeClient.ensure_wallet()
    IO.puts("Diode Client Address: #{DiodeClient.Wallet.printable(w)}")
  end

  def run([port_num]) do
    init()

    case Integer.parse(port_num) do
      {port_num, ""} ->
        IO.puts("Publishing port #{port_num}...")
        publish(port_num)

      _ ->
        IO.puts("Invalid port number: #{port_num}")
        System.halt(1)
    end
  end

  def run(_) do
    IO.puts("Usage: mix diode.publish <port_num>")
    System.halt(1)
  end

  def publish(port_num) do
    DiodeClient.Acceptor.listen(port_num,
      callback: fn socket ->
        IO.puts("Accepted connection on port #{port_num} #{inspect(socket)}")
        :ssl.setopts(socket, active: true, packet: 2)
        echo_loop(socket)
      end
    )

    IO.puts("Listening on port #{port_num}")
    :timer.sleep(:infinity)
  end

  def echo_loop(socket) do
    receive do
      msg -> msg
    end
    |> case do
      {:ssl, ^socket, data} ->
        :ok = :ssl.send(socket, data)
        IO.puts("Received #{byte_size(data)} bytes")
        echo_loop(socket)

      {:ssl_closed, ^socket} ->
        IO.puts("Socket closed")
        :ok

      other ->
        IO.puts("Unhandled message: #{inspect(other)}")
        echo_loop(socket)
    end
  end
end
