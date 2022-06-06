defmodule DiodeClient.Manager do
  @moduledoc """
    Manages the server connections
  """
  alias DiodeClient.{Connection, Manager, Rlpx}
  use GenServer
  defstruct [:conns, :server_list, :waiting, :best, :peak, :online]

  defmodule Info do
    # server_address is the diode public key
    # server_url is the url to connect
    defstruct [:latency, :server_address, :server_url, :port, :key, :pid, :start, :peak]
  end

  def start_link([]) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__, hibernate_after: 5_000)
  end

  @impl true
  def init(_arg) do
    Process.flag(:trap_exit, true)
    state = %Manager{server_list: seed_list(), conns: %{}, waiting: [], online: true}
    {:ok, state, {:continue, :init}}
  end

  defp seed_keys(), do: [:eu1, :us1, :as1, :eu2, :us2, :as2]

  defp seed_list() do
    Enum.map(seed_keys(), fn pre ->
      {pre, %Info{server_url: "#{pre}.prenet.diode.io", port: 41046, key: pre}}
    end)
    |> Map.new()
  end

  @doc """
    get_connection and get_peak are linked in that peak will never return a block
    higher than any of the connections returned by get_connection has reported.
  """
  def get_connection() do
    GenServer.call(__MODULE__, :get_connection, :infinity)
  end

  @doc """
    get_connection and get_peak are linked in that peak will never return a block
    higher than any of the connections returned by get_connection has reported.
  """
  def get_peak() do
    case GenServer.call(__MODULE__, :get_peak, :infinity) do
      nil -> Connection.peak(get_connection())
      peak -> peak
    end
  end

  def connections() do
    GenServer.call(__MODULE__, :connections)
  end

  def online?() do
    GenServer.call(__MODULE__, :online?)
  end

  def set_online(online) do
    GenServer.call(__MODULE__, {:set_online, online})
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

  defp restart_all(state) do
    Enum.reduce(seed_keys(), state, fn key, state ->
      restart_conn(key, state)
    end)
  end

  defp restart_conn(_key, %Manager{online: false} = state) do
    state
  end

  defp restart_conn(key, %Manager{server_list: servers, conns: conns} = state) do
    info = %Info{server_url: server, port: port, key: ^key} = Map.get(servers, key)

    pid =
      case Connection.start_link(server, port, key) do
        {:ok, pid} -> pid
        {:error, {:already_started, pid}} -> pid
      end

    conns = Map.put(conns, pid, %Info{info | pid: pid, start: System.os_time()})
    %Manager{state | conns: conns}
  end

  @impl true
  def handle_call(:online?, _from, %Manager{online: online} = state) do
    {:reply, online and length(connected(state)) > 0, state}
  end

  def handle_call(
        {:set_online, new_online},
        _from,
        %Manager{online: online, server_list: servers} = state
      ) do
    state = %Manager{state | online: new_online}
    pids = Map.keys(servers)

    state =
      cond do
        new_online == online ->
          state

        new_online ->
          restart_all(state)

        not new_online ->
          for pid <- pids, do: GenServer.cast(pid, :stop)
          %Manager{state | server_list: seed_list(), conns: %{}, best: nil}
      end

    {:reply, :ok, state}
  end

  def handle_call(:connections, _from, %Manager{conns: conns} = state) do
    {:reply, Map.keys(conns), state}
  end

  def handle_call(:get_peak, _from, %Manager{peak: peak} = state) do
    {:reply, peak, state}
  end

  def handle_call({:get_info, cpid, key}, _from, %Manager{conns: conns} = state) do
    case Map.get(conns, cpid) do
      nil -> {:reply, nil, state}
      %Info{} = info -> {:reply, Map.get(info, key), state}
    end
  end

  def handle_call(:get_connection, from, %Manager{online: false, waiting: waiting} = state) do
    {:noreply, %Manager{state | waiting: waiting ++ [from]}}
  end

  def handle_call(:get_connection, from, %Manager{best: nil, waiting: waiting} = state) do
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

  defp connected(%Manager{conns: conns}) do
    Enum.filter(Map.values(conns), fn %Info{server_address: addr, peak: peak} ->
      addr != nil and peak != nil
    end)
  end

  defp refresh_best(%Manager{waiting: waiting, peak: last_peak} = state) do
    connected = connected(state)

    peaks =
      Enum.map(connected, fn %Info{peak: a} -> block_number(a) end)
      |> Enum.sort(:desc)

    # IO.puts("PEAKS: #{inspect(peaks)}")

    min_peak = List.last(Enum.take(peaks, floor(length(peaks) / 2) + 1)) || 0
    # IO.puts("MIN_PEAK: #{min_peak}")
    min_peak = max(min_peak, block_number(last_peak))
    # IO.puts("MIN_PEAK2: #{min_peak}")

    Enum.filter(connected, fn %Info{peak: peak} -> block_number(peak) >= min_peak end)
    |> Enum.sort(fn %Info{latency: a}, %Info{latency: b} -> a < b end)
    |> List.first()
    |> case do
      nil ->
        %Manager{state | best: nil}

      %Info{pid: pid, peak: new_peak} ->
        peak = if block_number(new_peak) > block_number(last_peak), do: new_peak, else: last_peak
        for from <- waiting, do: GenServer.reply(from, pid)
        %Manager{state | best: pid, waiting: [], peak: peak}
    end
  end

  defp block_number(nil), do: 0
  defp block_number(block), do: Rlpx.bin2uint(block["number"])

  @impl true
  def handle_continue(:init, state) do
    {:noreply, restart_all(state)}
  end

  def get_connection_info(cpid, key) when key == :server_address or key == :latency do
    GenServer.call(__MODULE__, {:get_info, cpid, key})
  end

  def update_info(cpid, info) do
    GenServer.cast(__MODULE__, {:update_info, cpid, info})
  end
end
