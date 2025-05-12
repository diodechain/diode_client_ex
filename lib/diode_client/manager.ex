defmodule DiodeClient.Manager do
  @moduledoc false
  alias DiodeClient.{Connection, Manager, Rlpx}
  use GenServer
  require Logger

  defstruct [
    :conns,
    :server_list,
    :waiting,
    :best,
    :peaks,
    :online,
    :shells,
    :sticky,
    :best_timestamp
  ]

  defmodule Info do
    @moduledoc false
    # server_address is the diode public key
    # server_url is the url to connect
    defstruct [
      :latency,
      :server_address,
      :server_url,
      :ports,
      :key,
      :pid,
      :started_at,
      :peaks,
      :created_at,
      :type
    ]
  end

  def start_link([]) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__, hibernate_after: 5_000)
  end

  @impl true
  def init(_arg) do
    Process.flag(:trap_exit, true)
    :timer.send_interval(60_000, self(), :refresh)
    send(self(), :refresh)

    state = %Manager{
      conns: %{},
      online: true,
      peaks: %{},
      server_list: seed_list(),
      shells: MapSet.new(default_shells()),
      waiting: [],
      best: []
    }

    {:ok, state, {:continue, :init}}
  end

  def default_shells() do
    [DiodeClient.Shell.Moonbeam, DiodeClient.Shell]
  end

  def await() do
    if Process.whereis(__MODULE__) == nil do
      Process.sleep(1_000)
      await()
    end
  end

  defp default_seed_keys(), do: [:eu1, :us1, :as1, :eu2, :us2, :as2]
  defp extra_ports(:eu1), do: [443]
  defp extra_ports(:as1), do: [443]
  defp extra_ports(:us1), do: [443]
  defp extra_ports(_), do: []

  defp seed_list() do
    DiodeClient.Store.fetch(:seed_list, &initial_seed_list/0)
  end

  def seed_list_override() do
    System.get_env("SEED_LIST")
  end

  defp initial_seed_list() do
    if seed_list_override() == nil do
      Enum.map(default_seed_keys(), fn pre ->
        {pre,
         %Info{
           server_url: "#{pre}.prenet.diode.io",
           ports: [41_046, 993, 1723, 10_000] ++ extra_ports(pre),
           key: pre,
           type: :seed,
           created_at: System.os_time()
         }}
      end)
    else
      seed_list_override()
      |> String.split(",")
      |> Enum.map(fn url ->
        {url, ports} =
          case String.split(url, ":") do
            [url] -> {url, [41_046, 993, 1723, 10_000]}
            [url, port] -> {url, [String.to_integer(port)]}
          end

        key = String.to_atom(url)

        {key,
         %Info{server_url: url, ports: ports, key: key, created_at: System.os_time(), type: :seed}}
      end)
    end
    |> Map.new()
  end

  def add_connection(server) do
    ports = [DiodeClient.Object.Server.edge_port(server)]
    url = DiodeClient.Object.Server.host(server)
    key = String.to_atom(url)

    conn =
      {key,
       %Info{server_url: url, ports: ports, key: key, created_at: System.os_time(), type: :manual}}

    GenServer.call(__MODULE__, {:add_connection, conn})
  end

  def add_connection() do
    addr = DiodeClient.Wallet.new() |> DiodeClient.Wallet.address!()

    with [server | _] <- DiodeClient.Shell.get_nodes(addr) do
      add_connection(server)
    end
  end

  def drop_connection(key) do
    GenServer.call(__MODULE__, {:drop_connection, key})
  end

  @doc """
    get_connection and get_peak are linked in that peak will never return a block
    higher than any of the connections returned by get_connection has reported.
  """
  def get_connection() do
    GenServer.call(__MODULE__, :get_connection, :infinity)
    |> Enum.random()
  end

  @doc """
    get_sticky_connection is special as it will always return the same connection
    once it has returned a connection.
  """
  def get_sticky_connection() do
    Process.whereis(__MODULE__.Sticky) || resolve_sticky_connection()
  end

  defp resolve_sticky_connection() do
    conn = GenServer.call(__MODULE__, :get_sticky_connection?)

    if conn == nil do
      Process.sleep(1_000)
      resolve_sticky_connection()
    else
      conn
    end
  end

  def get_connection?() do
    GenServer.call(__MODULE__, :get_connection?, :infinity)
    |> Enum.random()
  end

  def set_connection(conn) do
    GenServer.cast(__MODULE__, {:set_connection, conn})
  end

  @doc """
    get_connection and get_peak are linked in that peak will never return a block
    higher than any of the connections returned by get_connection has reported.
  """
  def get_peak(shell) do
    case GenServer.call(__MODULE__, {:get_peak, shell}, :infinity) do
      nil -> Connection.peak(get_connection(), shell)
      peak -> peak
    end
  end

  def connections() do
    connection_map()
    |> Map.keys()
  end

  def connection_map() do
    GenServer.call(__MODULE__, :connections)
  end

  def connected_connections() do
    connection_map()
    |> Enum.filter(fn {_pid, %Info{server_address: addr, peaks: peaks}} ->
      addr != nil and map_size(peaks) > 0
    end)
  end

  def ranked_connections() do
    connection_map()
    |> Enum.sort_by(fn {_pid, %Info{server_address: addr, peaks: peaks, latency: latency}} ->
      online? = addr != nil and map_size(peaks) > 0
      {not online?, latency}
    end)
    |> Enum.map(fn {pid, %Info{latency: latency, key: key, type: type}} ->
      {latency, pid, key, type}
    end)
  end

  @target_connections 8
  def refresh() do
    current = ranked_connections()
    len = length(current)

    if len >= @target_connections do
      {_, _, key, type} = List.last(current)

      if type == :manual do
        drop_connection(key)
      end
    end

    len = length(ranked_connections())

    if seed_list_override() == nil and len < @target_connections do
      for _ <- (len + 1)..@target_connections do
        add_connection()
      end
    end
  end

  def online?() do
    GenServer.call(__MODULE__, :online?)
  end

  def set_online(online) do
    GenServer.call(__MODULE__, {:set_online, online})
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, reason}, state) do
    handle_exit(pid, reason, state)
  end

  def handle_info({:EXIT, pid, reason}, state) do
    handle_exit(pid, reason, state)
  end

  def handle_info({:restart_conn, key}, state) do
    {:noreply, restart_conn(key, state)}
  end

  def handle_info(:refresh, state) do
    spawn(fn -> refresh() end)
    {:noreply, state}
  end

  defp handle_exit(pid, reason, state = %Manager{conns: conns}) do
    if Map.has_key?(conns, pid) do
      %Info{key: key} = Map.fetch!(conns, pid)
      Process.send_after(self(), {:restart_conn, key}, 15_000)
      state = %Manager{state | conns: Map.delete(conns, pid)}
      {:noreply, update(state)}
    else
      Logger.debug("Connection down: #{inspect(pid)} #{inspect(reason)}")
      {:noreply, state}
    end
  end

  @impl true
  def handle_cast({:set_connection, cpid}, state = %Manager{conns: _conns}) do
    {:noreply, %Manager{state | best: [cpid]}}
  end

  def handle_cast({:update_info, cpid, info}, state = %Manager{conns: conns}) do
    case Map.get(conns, cpid) do
      nil ->
        {:noreply, state}

      old_info ->
        case struct!(old_info, info) do
          ^old_info ->
            {:noreply, state}

          new_info = %{peaks: %{}} ->
            state =
              %Manager{state | conns: Map.put(conns, cpid, new_info)}
              |> update()

            {:noreply, state}
        end
    end
  end

  defp restart_all(state) do
    Enum.reduce(Map.keys(seed_list()), state, fn key, state ->
      restart_conn(key, state)
    end)
  end

  defp restart_conn(_key, state = %Manager{online: false}) do
    state
  end

  defp restart_conn(key, state = %Manager{server_list: servers}) do
    do_restart_conn(Map.get(servers, key), state)
  end

  defp do_restart_conn(nil, state) do
    # Can be nil if the server is not in the seed list and was dropped
    # with :drop_connection
    state
  end

  defp do_restart_conn(info, state = %Manager{peaks: peaks, conns: conns}) do
    pid =
      case Connection.start_link(info.server_url, info.ports) do
        {:ok, pid} ->
          Process.monitor(pid)

          for {shell, _} <- peaks do
            GenServer.cast(pid, {:subscribe, shell})
          end

          pid

        {:error, {:already_started, pid}} ->
          pid
      end

    conns = Map.put(conns, pid, %Info{info | pid: pid, started_at: System.os_time(), peaks: %{}})
    %Manager{state | conns: conns}
  end

  @impl true
  def handle_call(:online?, _from, state = %Manager{online: online}) do
    {:reply, online and length(connected(state)) > 0, state}
  end

  def handle_call(
        {:set_online, new_online},
        _from,
        state = %Manager{online: online, server_list: servers}
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
          %Manager{state | server_list: seed_list(), conns: %{}, best: []}
      end

    {:reply, :ok, state}
  end

  def handle_call(:connections, _from, state = %Manager{conns: conns}) do
    {:reply, conns, state}
  end

  def handle_call(
        {:get_peak, shell},
        _from,
        state = %Manager{peaks: peaks, conns: conns, shells: shells}
      ) do
    state = %{state | shells: MapSet.put(shells, shell)}

    for c <- Map.keys(conns), do: GenServer.cast(c, {:subscribe, shell})
    {:reply, Map.get(peaks, shell), state}
  end

  def handle_call({:get_info, cpid, key}, _from, state = %Manager{conns: conns}) do
    case Map.get(conns, cpid) do
      nil -> {:reply, nil, state}
      %Info{} = info -> {:reply, Map.get(info, key), state}
    end
  end

  def handle_call(:get_connection?, _from, state = %Manager{online: online, best: best}) do
    if online and length(best) > 0 do
      {:reply, best, state}
    else
      {:reply, nil, state}
    end
  end

  def handle_call(:get_connection, from, state = %Manager{online: false, waiting: waiting}) do
    {:noreply, %Manager{state | waiting: waiting ++ [from]}}
  end

  def handle_call(:get_connection, from, state = %Manager{best: [], waiting: waiting}) do
    {:noreply, %Manager{state | waiting: waiting ++ [from]}}
  end

  def handle_call(:get_connection, _from, state = %Manager{best: best}) do
    {:reply, best, state}
  end

  def handle_call(
        :get_sticky_connection?,
        _from,
        state = %Manager{sticky: sticky, online: online, best: best, conns: conns}
      ) do
    pid = Process.whereis(__MODULE__.Sticky)

    cond do
      pid != nil ->
        {:reply, pid, state}

      sticky != nil ->
        Enum.find(conns, fn {_, %Info{server_url: url}} -> url == sticky end)
        |> set_sticky(state)

      best == [] or online == false ->
        {:reply, nil, state}

      true ->
        Enum.filter(conns, fn {_, %Info{type: type}} -> type == :seed end)
        |> Enum.sort_by(fn {_, %Info{latency: latency}} -> latency end)
        |> List.first()
        |> set_sticky(state)
    end
  end

  def handle_call(
        {:add_connection, {key, info}},
        _from,
        state = %Manager{server_list: server_list}
      ) do
    server_list = Map.put(server_list, key, info)
    state = %Manager{state | server_list: server_list}
    {:reply, :ok, restart_conn(key, state)}
  end

  def handle_call(
        {:drop_connection, key},
        _from,
        state = %Manager{server_list: server_list, conns: conns}
      ) do
    server_list = Map.delete(server_list, key)
    result = Enum.find(conns, fn {_, %Info{key: key2}} -> key2 == key end)

    state =
      if result do
        {pid, _info} = result
        GenServer.cast(pid, :stop)
        %Manager{state | server_list: server_list, conns: Map.delete(conns, pid)}
      else
        %Manager{state | server_list: server_list}
      end

    {:reply, :ok, state}
  end

  defp connected(%Manager{conns: conns, shells: shells, peaks: peaks}) do
    Enum.filter(Map.values(conns), fn %Info{server_address: addr, peaks: conn_peaks} ->
      addr != nil and
        Enum.all?(shells, fn shell ->
          block_number(conn_peaks[shell]) >= block_number(peaks[shell])
        end)
    end)
  end

  def update(state) do
    state = update_peaks(state)
    pids = Enum.map(connected(state), fn %Info{pid: pid} -> pid end)
    best = Enum.filter(state.best, fn pid -> pid in pids end)

    if length(best) == 0 or
         System.os_time(:second) - state.best_timestamp > 30 do
      update_best(state)
    else
      %{state | best: best}
    end
  end

  defp update_peaks(state = %Manager{peaks: last_peaks, shells: shells}) do
    connected = connected(state)

    # Reject single node connections
    connected = if length(connected) < min(2, map_size(seed_list())), do: [], else: connected

    # Get the highest peak for each shell
    peaks =
      for shell <- shells do
        peak =
          Enum.map(connected, fn %Info{peaks: peaks} -> peaks[shell] end)
          |> Enum.sort_by(&block_number/1, :desc)
          # Security factor, we chose the lowest peak of the top 3 (e.g. 3 nodes have seen this)
          |> Enum.take(3)
          |> List.last()

        if block_number(peak) > block_number(last_peaks[shell]) do
          {shell, peak}
        else
          {shell, last_peaks[shell]}
        end
      end
      |> Map.new()

    %Manager{state | peaks: peaks}
  end

  defp update_best(state = %Manager{waiting: waiting, best: prev_best}) do
    new_best =
      connected(state)
      # Sort by latency and return the first one
      |> Enum.sort_by(fn %Info{latency: latency} -> latency end)

    if peak = List.first(new_best) do
      new_best =
        Enum.filter(new_best, fn %Info{latency: latency} -> latency < 2 * peak.latency end)

      if prev_best != new_best do
        servers =
          Enum.map_join(new_best, ", ", fn %{server_url: url, latency: latency} ->
            "#{url}: #{trunc(latency)}"
          end)

        Logger.info("Best connection changed to [#{servers}] #{length(new_best)}")
      end

      for from <- waiting, do: GenServer.reply(from, peak.pid)

      %Manager{
        state
        | best: Enum.map(new_best, fn %Info{pid: pid} -> pid end),
          waiting: [],
          best_timestamp: System.os_time(:second)
      }
    else
      %Manager{state | best: []}
    end
  end

  defp block_number(nil), do: 0
  defp block_number(block), do: Rlpx.bin2uint(block["number"])

  @impl true
  def handle_continue(:init, state) do
    {:noreply, restart_all(state)}
  end

  def get_connection_info(cpid, key) when key in [:server_address, :latency, :server_url] do
    GenServer.call(__MODULE__, {:get_info, cpid, key})
  end

  def update_info(cpid, info) do
    GenServer.cast(__MODULE__, {:update_info, cpid, info})
  end

  defp set_sticky(nil, state) do
    {:reply, nil, state}
  end

  defp set_sticky({pid, info}, state) do
    Logger.info("Setting sticky connection to #{inspect(info.server_url)}")
    Process.register(pid, __MODULE__.Sticky)
    {:reply, pid, %Manager{state | sticky: info.server_url}}
  end
end
