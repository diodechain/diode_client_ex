defmodule DiodeClient.Control do
  @moduledoc false
  use GenServer
  require Logger
  require Logger
  alias DiodeClient.{Acceptor, Connection, Control, Port, Rlp, Rlpx}
  @control_port 320_922
  defstruct [:tried, :peer, :resolved_address, :waiting, :socket, :resolved_ports]

  def start_link(peer) do
    state = %Control{peer: peer, tried: 0, waiting: [], resolved_ports: %{}}
    GenServer.start_link(__MODULE__, state, hibernate_after: 5_000)
  end

  def whereis(peer) do
    case :global.whereis_name({__MODULE__, peer}) do
      :undefined -> nil
      pid -> pid
    end
  end

  defp ensure_peer(peer) do
    case whereis(peer) do
      nil ->
        case Supervisor.start_child(DiodeClient.Sup.name(), %{
               id: peer,
               start: {Control, :start_link, [peer]},
               restart: :temporary
             }) do
          {:ok, pid} ->
            pid

          {:error, reason} ->
            Logger.debug("couldn't start control plane for #{inspect(reason)}")
            nil
        end

      pid ->
        pid
    end
  end

  def resolve_local(peer, portnum) do
    pid = ensure_peer(peer)

    if pid == nil do
      nil
    else
      case GenServer.call(pid, {:resolve_local, portnum}, :infinity) do
        nil ->
          nil

        {"", _port} ->
          nil

        {address, port} = _addr ->
          # Logger.info("resolve_local: #{inspect(addr)}")
          address = String.to_charlist(address)

          case :ssl.connect(address, port, Connection.ssl_options(role: :client), 5_000) do
            {:ok, ssl} ->
              NetworkMonitor.close_on_down(ssl, :ssl)
              :ssl.controlling_process(ssl, self())
              ssl

            {:error, _reason} ->
              # Logger.info("resolve_local failed for #{inspect(reason)}")
              nil
          end
      end
    end
  end

  @impl true
  def init(state) do
    :global.register_name({__MODULE__, state.peer}, self())
    Port.listen(@control_port, local: false, callback: &accept_socket/1)
    {:ok, state}
  end

  defp accept_socket(ssl) do
    peer = Port.peer(ssl)

    # Think about how to make this less promiscuous
    # e.g. reduce to known peers or such
    case ensure_peer(peer) do
      nil ->
        :ssl.close(ssl)

      other ->
        GenServer.call(other, {:accept, ssl})
    end
  end

  @impl true
  def handle_call({:accept, socket}, _from, state) do
    if state.socket == nil do
      :ssl.controlling_process(socket, self())
      :ssl.setopts(socket, active: true, packet: 2)
      {:reply, :ok, %Control{state | socket: socket}}
    else
      Logger.debug("ignoring socket on control plane since i'm open already")
      :ssl.close(socket)
      {:reply, :ok, state}
    end
  end

  def handle_call({:resolve_local, portnum}, _from, state) do
    %Control{resolved_address: addr, resolved_ports: ports} =
      state =
      try_connection(state)
      |> request_port(portnum)

    port = Map.get(ports, portnum)

    if addr == nil or port == nil do
      {:reply, nil, state}
    else
      {:reply, {addr, port}, state}
    end
  end

  defp try_connection(state = %Control{socket: nil, peer: peer, tried: 0}) do
    state = %Control{state | tried: 1}

    case Port.connect(peer, @control_port, local: false) do
      {:ok, pid} ->
        :ssl.setopts(pid, active: true, packet: 2)
        %Control{state | socket: pid}

      {:error, _reason} ->
        # Logger.debug("control plane failed for #{inspect(reason)}")
        state
    end
  end

  defp try_connection(state = %Control{}) do
    state
  end

  defp request_port(state = %Control{socket: nil}, _portnum) do
    state
  end

  defp request_port(state = %Control{resolved_ports: ports}, portnum) do
    if Map.has_key?(ports, portnum) do
      state
    else
      do_request_port(state, portnum)
    end
  end

  defp do_request_port(state = %Control{socket: socket, resolved_ports: ports}, portnum) do
    :ssl.send(socket, Rlp.encode!(["RESOLVE", portnum]))

    receive do
      {:ssl, _socket, data} ->
        data = Rlp.decode!(data)
        bin_portnum = Rlpx.uint2bin(portnum)

        case data do
          ["RESOLVED", ^bin_portnum] ->
            Logger.debug("failed to resolve #{inspect(portnum)}")
            state

          ["RESOLVED", ^bin_portnum, ret_addr, ret_port] ->
            %Control{
              state
              | resolved_ports: Map.put(ports, portnum, Rlpx.bin2uint(ret_port)),
                resolved_address: ret_addr
            }

          other ->
            handle_request(state, other)
        end
    after
      5_000 ->
        :ssl.close(socket)
        Logger.debug("failed control plane on timeout")
        %Control{state | socket: nil}
    end
  end

  @impl true
  def handle_info({:ssl_closed, closed_socket}, state = %Control{socket: socket}) do
    if socket == closed_socket do
      {:noreply, %Control{state | socket: nil}}
    else
      {:noreply, state}
    end
  end

  def handle_info({:ssl, _socket, data}, state) do
    state = handle_request(state, Rlp.decode!(data))
    {:noreply, state}
  end

  defp handle_request(state = %Control{socket: socket}, request) do
    case request do
      ["RESOLVE", portnum] ->
        portnum = Rlpx.bin2uint(portnum)

        case Acceptor.local_port(portnum) do
          nil ->
            :ssl.send(socket, Rlp.encode!(["RESOLVED", portnum]))

          {address, port} ->
            :ssl.send(socket, Rlp.encode!(["RESOLVED", portnum, address, port]))
        end

      other ->
        Logger.debug("received unknown request #{inspect(other)}")
    end

    state
  end
end
