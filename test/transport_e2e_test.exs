defmodule DiodeClient.TransportE2ETest do
  @moduledoc """
  End-to-end path matching Ranch 2 + cowboy_clear after accept:

    1. Transport.listen (map opts like Ranch 2)
    2. Transport.accept
    3. Transport.handshake/2  — MFA Ranch uses when :ranch.handshake(Ref) has no opts
    4. send/recv over the accepted socket

  Regression: only handshake/3 existed, so production RemoteEndpoint crashed with
  `{:undef, [{DiodeClient.Transport, :handshake, [socket, 5000], []}]}`.
  """
  use ExUnit.Case, async: false

  alias DiodeClient.{Acceptor, Port, Rlpx, Transport}

  @moduletag timeout: 60_000

  setup do
    if Process.whereis(DiodeClient.Manager) == nil do
      case DiodeClient.interface_add("transport_e2e_test", DiodeClient.Sup) do
        {:ok, _} -> :ok
        {:error, {:already_started, _}} -> :ok
      end
    end

    :ok
  end

  test "accept + ranch handshake/2 + echo over local diode port" do
    # Arbitrary free diode app port (logical port; Transport maps to tls:<n>)
    app_port = 19_000 + :rand.uniform(1000)
    portnum = Rlpx.bin2uint("tls:#{app_port}")

    trans_opts = %{
      num_acceptors: 1,
      max_connections: 16,
      sendfile: true,
      socket_opts: [port: app_port]
    }

    assert {:ok, listener} = Transport.listen(trans_opts)
    assert %Acceptor.Listener{portnum: ^portnum} = listener

    parent = self()

    {:ok, _server} =
      Task.start_link(fn ->
        assert {:ok, socket} = Transport.accept(listener, 15_000)

        # Exact 2-arity call ranch.erl makes for cowboy_clear (no handshake opts)
        assert {:ok, socket} = apply(Transport, :handshake, [socket, 5000])

        assert {:ok, "ping"} = Transport.recv(socket, 0, 5_000)
        assert :ok = Transport.send(socket, "pong")
        send(parent, :server_ok)
      end)

    {address, local_tcp_port} = await_local_port(portnum)

    assert {:ok, client} =
             Port.direct_connect(String.to_charlist(address), local_tcp_port, :client, 10_000)

    assert :ok = :ssl.setopts(client, active: false, mode: :binary, packet: :raw)
    assert :ok = :ssl.send(client, "ping")
    assert {:ok, "pong"} = :ssl.recv(client, 0, 10_000)

    assert_receive :server_ok, 5_000
    :ssl.close(client)
  end

  defp await_local_port(portnum, attempts \\ 50)

  defp await_local_port(_portnum, 0), do: flunk("LocalAcceptor never became ready")

  defp await_local_port(portnum, attempts) do
    case Acceptor.local_port(portnum) do
      {address, port} when is_binary(address) and is_integer(port) and port > 0 ->
        {address, port}

      _ ->
        Process.sleep(50)
        await_local_port(portnum, attempts - 1)
    end
  end
end
