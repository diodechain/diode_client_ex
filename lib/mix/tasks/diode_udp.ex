defmodule Mix.Tasks.Diode.Udp do
  @moduledoc """
  Diode Publish CLI
  """
  require Logger

  defp init(whom) do
    Logger.configure(level: :debug)
    Application.ensure_all_started(:diode_client)
    DiodeClient.interface_add(whom)
    w = DiodeClient.wallet()
    IO.puts("Diode Client Address: #{DiodeClient.Wallet.printable(w)}")
  end

  def run(["publish", port_num]) do
    init("publisher_interface")

    case Integer.parse(port_num) do
      {port_num, ""} ->
        IO.puts("Publishing port #{port_num}...")
        publish(port_num)

      _ ->
        IO.puts("Invalid port number: #{port_num}")
        System.halt(1)
    end
  end

  def run(["consume", address, port_num]) do
    init("consumer_interface")

    case Integer.parse(port_num) do
      {port_num, ""} ->
        IO.puts("Consuming port #{port_num} from #{address}...")
        consume(address, port_num)

      _ ->
        IO.puts("Invalid port number: #{port_num}")
        System.halt(1)
    end
  end

  def run(_) do
    IO.puts("Usage: mix diode.udp publish <port_num>")
    IO.puts("Usage: mix diode.udp consume <address> <port_num>")
    System.halt(1)
  end

  def consume(address, port_num) do
    case DiodeClient.Port.connect(address, port_num, access: "u2", print?: true) do
      {:ok, socket} ->
        IO.puts("Consumed connection on port #{port_num} #{inspect(socket)}")
        echo_loop(socket)

      {:error, reason} ->
        IO.puts("Error consuming port #{port_num} from #{address}: #{inspect(reason)}")
        System.halt(1)
    end
  end

  def publish(port_num) do
    DiodeClient.Acceptor.listen(port_num,
      callback: fn socket ->
        IO.puts("Accepted connection on port #{port_num} #{inspect(socket)}")
      end,
      access: "u2",
      print?: true
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
