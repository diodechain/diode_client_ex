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
        {:reply, {address, port}, state}
    end
  end

  def loop(socket, portnum) do
    {:ok, client} = :ssl.transport_accept(socket)
    GenServer.call(Acceptor, {:inject, portnum, client})
    loop(socket, portnum)
  end
end
