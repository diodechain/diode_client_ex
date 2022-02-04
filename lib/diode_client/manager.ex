defmodule DiodeClient.Manager do
  @moduledoc """
    Manages the server connections
  """
  alias DiodeClient.{Connection, Manager}
  use GenServer
  defstruct [:conns, :server_list, :waiting, :best]

  defmodule Info do
    # server_address is the diode public key
    # server_url is the url to connect
    defstruct [:latency, :server_address, :server_url, :port, :key, :pid, :start]
  end

  def start_link([]) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__, hibernate_after: 5_000)
  end

  @impl true
  def init(_arg) do
    Process.flag(:trap_exit, true)
    state = %Manager{server_list: seed_list(), conns: %{}, waiting: []}
    {:ok, state, {:continue, :init}}
  end

  defp seed_keys(), do: [:eu1, :us1, :as1, :eu2, :us2, :as2]

  defp seed_list() do
    Enum.map(seed_keys(), fn pre ->
      {pre, %Info{server_url: "#{pre}.prenet.diode.io", port: 41046, key: pre}}
    end)
    |> Map.new()
  end

  def get_connection() do
    GenServer.call(__MODULE__, :get_connection, :infinity)
  end

  def connections() do
    GenServer.call(__MODULE__, :connections)
  end

  @impl true
  def handle_info({:EXIT, pid, reason}, %Manager{conns: conns} = state) do
    if Map.has_key?(conns, pid) do
      %Info{key: key} = Map.fetch!(conns, pid)
      Process.send_after(self(), {:restart_conn, key}, 15_000)
      state = %Manager{state | conns: Map.delete(conns, pid)}
      {:noreply, refresh_best(state)}
    else
      if reason == :normal do
        {:noreply, state}
      else
        {:stop, reason}
      end
    end
  end

  def handle_info({:restart_conn, key}, state) do
    {:noreply, restart_conn(key, state)}
  end

  @impl true
  def handle_cast({:update_info, cpid, info}, %Manager{conns: conns} = state) do
    case Map.get(conns, cpid) do
      nil ->
        {:noreply, state}

      old_info ->
        new_info = struct!(old_info, info)
        state = %Manager{state | conns: Map.put(conns, cpid, new_info)}
        {:noreply, refresh_best(state)}
    end
  end

  defp restart_conn(key, %Manager{server_list: servers, conns: conns} = state) do
    info = %Info{server_url: server, port: port, key: ^key} = Map.get(servers, key)
    {:ok, pid} = Connection.start_link(server, port, key)
    conns = Map.put(conns, pid, %Info{info | pid: pid, start: System.os_time()})
    %Manager{state | conns: conns}
  end

  @impl true
  def handle_call(:connections, _from, %Manager{conns: conns} = state) do
    {:reply, Map.keys(conns), state}
  end

  def handle_call({:get_info, cpid, key}, _from, %Manager{conns: conns} = state) do
    case Map.get(conns, cpid) do
      nil -> {:reply, nil, state}
      %Info{} = info -> {:reply, Map.get(info, key), state}
    end
  end

  def handle_call(
        :get_connection,
        from,
        %Manager{best: nil, waiting: waiting} = state
      ) do
    %Manager{best: best} = state = refresh_best(state)

    if best == nil do
      {:noreply, %Manager{state | waiting: waiting ++ [from]}}
    else
      {:reply, best, state}
    end
  end

  def handle_call(:get_connection, _from, %Manager{best: best} = state) do
    {:reply, best, state}
  end

  defp refresh_best(%Manager{conns: conns, waiting: waiting} = state) do
    Enum.filter(Map.values(conns), fn %Info{server_address: addr} -> addr != nil end)
    |> Enum.sort(fn %Info{latency: a}, %Info{latency: b} -> a < b end)
    |> Enum.take(1)
    |> case do
      [] ->
        %Manager{state | best: nil}

      [%Info{pid: pid}] ->
        for from <- waiting, do: GenServer.reply(from, pid)
        %Manager{state | best: pid, waiting: []}
    end
  end

  @impl true
  def handle_continue(:init, state) do
    state =
      Enum.reduce(seed_keys(), state, fn key, state ->
        restart_conn(key, state)
      end)

    {:noreply, state}
  end

  def get_connection_info(cpid, key) when key == :server_address or key == :latency do
    GenServer.call(__MODULE__, {:get_info, cpid, key})
  end

  def update_info(cpid, info) do
    GenServer.cast(__MODULE__, {:update_info, cpid, info})
  end
end
