defmodule DiodeClient.LocalAcceptor do
  use GenServer
  use DiodeClient.Log
  alias DiodeClient.{Acceptor, Connection, LocalAcceptor}
  defstruct [:backlog, :socket, :portnum]

  def start_link(portnum) do
    state = %LocalAcceptor{portnum: portnum, backlog: %{}}
    GenServer.start_link(__MODULE__, state, hibernate_after: 5_000)
  end

  @impl true
  def init(state) do
    send(self(), :open)
    {:ok, state}
  end

  @impl true
  def handle_info(:open, state = %LocalAcceptor{portnum: portnum}) do
    case :ssl.listen(0, Connection.ssl_options()) do
      {:ok, socket} ->
        spawn_link(fn -> loop(socket, portnum) end)
        {:noreply, %LocalAcceptor{state | socket: socket}}

      {:error, reason} ->
        log("failed opening local socket: #{inspect(reason)}")
        Process.send_after(self(), :open, 5_000)
        {:noreply, state}
    end
  end

  @impl true
  def handle_call(:local_port, _from, state = %LocalAcceptor{socket: socket}) do
    case socket do
      nil ->
        {:reply, nil, state}

      socket ->
        {:ok, {address, port}} = :ssl.sockname(socket)
        address = resolve_address(address)
        {:reply, {address, port}, state}
    end
  end

  defp resolve_address(address) do
    case address do
      {0, 0, 0, 0} -> local_address(:inet)
      {0, 0, 0, 0, 0, 0, 0, 0} -> local_address(:inet6)
      other -> List.to_string(:inet.ntoa(other))
    end
  end

  def local_address(family) do
    case :os.type() do
      {:win32, _} ->
        {ret, 0} = System.cmd("ipconfig", [])

        regex =
          case family do
            :inet ->
              ~r/IPv4.+ (([0-9]{1,3}\.){3}([0-9]{1,3}))/

            :inet6 ->
              ~r/IPv4.+ (([0-9]{1,3}\.){3}([0-9]{1,3}))/
              # TODO
              # :inet6 -> ~r/IPv6.+ (([0-9]{1,3}\.){3}([0-9]{1,3}))/
          end

        case Regex.run(regex, ret) do
          nil -> nil
          [_ret, match | _rest] -> match
        end

      {:unix, _} ->
        case :net.getifaddrs() do
          {:ok, ifs} ->
            Enum.filter(ifs, fn %{flags: flags, addr: %{family: addr_family}} ->
              addr_family == family and :up in flags and :running in flags and
                :loopback not in flags
            end)
            |> case do
              [] -> nil
              [%{addr: %{addr: addr}} | _rest] -> List.to_string(:inet.ntoa(addr))
            end

          {:error, _reason} ->
            # mobile ios/android
            nil
        end
    end
  end

  @tls_timeout 5_000
  def loop(socket, portnum) do
    {:ok, client} = :ssl.transport_accept(socket)

    case :ssl.handshake(client, Connection.ssl_options(), @tls_timeout) do
      {:error, reason} ->
        log("ssl handshake failed for #{inspect(reason)}")
        :ssl.close(client)

      {:ok, ssl} ->
        GenServer.call(Acceptor, {:inject, portnum, ssl})
    end

    loop(socket, portnum)
  end
end
