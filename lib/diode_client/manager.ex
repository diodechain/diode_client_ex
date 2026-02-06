defmodule DiodeClient.Manager do
  @moduledoc false
  alias DiodeClient.{Connection, Manager, NodeScorer, Rlpx}
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
      :open_port_count,
      :key,
      :pid,
      :started_at,
      :peaks,
      :created_at,
      :type,
      :reset_count,
      :max_uptime
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

  def update_seed_list(list) do
    System.put_env("SEED_LIST", list)
    list = initial_seed_list()

    if map_size(list) > 0 do
      DiodeClient.Store.put(:seed_list, list)
      for {_, %{key: key}} <- connection_map(), do: drop_connection(key)
      GenServer.call(__MODULE__, {:reset_server_list, list})
    else
      {:error, :no_seed_list}
    end
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

  def add_connection(server, type \\ :manual) do
    ports = [DiodeClient.Object.Server.edge_port(server)]
    url = DiodeClient.Object.Server.host(server)
    key = String.to_atom(url)

    conn =
      {key,
       %Info{server_url: url, ports: ports, key: key, created_at: System.os_time(), type: type}}

    GenServer.call(__MODULE__, {:add_connection, conn})
  end

  def add_connection() do
    addr = DiodeClient.Wallet.new() |> DiodeClient.Wallet.address!()

    with [server | _] <- DiodeClient.Shell.get_nodes(addr) do
      add_connection(server)
    end
  end

  def add_connection_address(address) do
    Debouncer.immediate(
      {__MODULE__, :add_connection_address, address},
      fn ->
        with [server] when is_list(server) <- DiodeClient.Shell.get_node(address) do
          DiodeClient.Object.decode_rlp_list!(server)
          |> add_connection(:peer)
        end
      end,
      60_000
    )
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
    case GenServer.call(__MODULE__, :get_connection?, :infinity) do
      [] -> nil
      conns -> Enum.random(conns)
    end
  end

  def set_connection(conn) do
    GenServer.cast(__MODULE__, {:set_connection, conn})
  end

  @doc """
    get_connection and get_peak are linked in that peak will never return a block
    higher than any of the connections returned by get_connection has reported.
  """
  def get_peak(shell) when is_atom(shell) do
    _chain_id = shell.chain_id()

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

  def ranked_info() do
    connection_map()
    |> Enum.sort_by(fn {_pid, %Info{server_address: addr, peaks: peaks, latency: latency}} ->
      online? = addr != nil and map_size(peaks) > 0
      {not online?, latency}
    end)
  end

  def ranked_connections() do
    ranked_info()
    |> Enum.map(fn {pid, %Info{latency: latency, key: key, type: type}} ->
      {latency, pid, key, type}
    end)
  end

  @target_connections 10
  def refresh() do
    current = ranked_connections()
    len = length(current)

    if len >= @target_connections do
      # Find find the slowest half of the connections
      slowest_half = Enum.reverse(current) |> Enum.take(div(len, 2))
      # Remove at least 1 connection, and at most half of the excess connections
      removals = max(1, div(len - @target_connections, 2))

      _ =
        Enum.reduce_while(slowest_half, removals, fn {_, pid, key, type}, removals ->
          if removals > 0 and type in [:manual, :peer] and
               get_connection_info(pid, :open_port_count) in [0, nil] do
            drop_connection(key)
            {:cont, removals - 1}
          else
            {:cont, removals}
          end
        end)
    end

    new_len = length(ranked_connections())

    if seed_list_override() == nil and new_len < @target_connections do
      for _ <- (new_len + 1)..@target_connections do
        add_connection()
      end
    end

    removed = len - new_len
    added = max(0, @target_connections - new_len)

    Logger.debug(
      "DiodeClient.Manager: removed #{removed}, added #{added} connections, new length #{new_len + added}"
    )
  end

  def online?() do
    GenServer.call(__MODULE__, :online?)
  end

  def set_online(online) do
    GenServer.cast(__MODULE__, {:set_online, online})
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

  def handle_info(:update, state) do
    {:noreply, update(state)}
  end

  defp handle_exit(pid, reason, state = %Manager{conns: conns}) do
    case Map.pop(conns, pid) do
      {%Info{key: key, server_url: server_url, type: type}, conns} ->
        if reason != :normal do
          Logger.info("Connection down: #{inspect(server_url)} for: #{inspect(reason)}")
          NodeScorer.report_failure(server_url)
        end

        state =
          if type == :seed do
            delay = NodeScorer.get_delay(server_url)
            Process.send_after(self(), {:restart_conn, key}, delay)
            %{state | conns: conns}
          else
            do_drop_connection(key, state)
          end

        {:noreply, schedule_update(state)}

      {nil, _conns} ->
        Logger.debug("Connection down: #{inspect(pid)} #{inspect(reason)}")
        {:noreply, state}
    end
  end

  @impl true
  def handle_cast({:set_online, new_online}, state) do
    {:noreply, do_set_online(state, new_online)}
  end

  @impl true
  def handle_cast({:set_connection, cpid}, state = %Manager{conns: _conns}) do
    {:noreply, %{state | best: [cpid]}}
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
              %{state | conns: Map.put(conns, cpid, new_info)}
              |> schedule_update()

            {:noreply, state}
        end
    end
  end

  defp restart_all(state = %Manager{server_list: servers}) do
    (Map.keys(servers) ++ Map.keys(seed_list()))
    |> Enum.uniq()
    |> Enum.reduce(state, fn key, state ->
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
            safe_send(pid, {:subscribe, shell})
          end

          pid

        {:error, {:already_started, pid}} ->
          pid
      end

    conns = Map.put(conns, pid, %{info | pid: pid, peaks: %{}})
    %Manager{state | conns: conns}
  end

  @impl true
  def handle_call(:online?, _from, state = %Manager{online: online}) do
    {:reply, online and map_size(connected(state)) > 0, state}
  end

  def handle_call({:set_online, new_online}, _from, state) do
    {:reply, :ok, do_set_online(state, new_online)}
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
    for c <- Map.keys(conns), do: safe_send(c, {:subscribe, shell})
    {:reply, Map.get(peaks, shell), state}
  end

  @legal_keys [
    :server_address,
    :latency,
    :server_url,
    :open_port_count,
    :peaks,
    :reset_count,
    :max_uptime,
    :started_at
  ]
  def handle_call({:get_info, cpid}, _from, state = %Manager{conns: conns}) do
    case Map.get(conns, cpid) do
      nil ->
        {:reply, %{}, state}

      %Info{} = info ->
        {:reply,
         Map.from_struct(info)
         |> Enum.filter(fn {key, _value} -> key in @legal_keys end)
         |> Map.new(), state}
    end
  end

  def handle_call(:get_connection?, _from, state = %Manager{online: online, best: best}) do
    {:reply, if(online, do: best, else: []), state}
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
        connected(state)
        |> Enum.filter(fn {_, %Info{type: type}} -> type == :seed end)
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
    if Map.has_key?(server_list, key) do
      {:reply, :ok, state}
    else
      server_list = Map.put(server_list, key, info)
      state = %Manager{state | server_list: server_list}
      {:reply, :ok, restart_conn(key, state)}
    end
  end

  def handle_call({:reset_server_list, list}, _from, state) do
    {:reply, :ok, restart_all(%{state | server_list: list, sticky: nil, best: [], peaks: %{}})}
  end

  def handle_call({:drop_connection, key}, _from, state) do
    {:reply, :ok, do_drop_connection(key, state)}
  end

  defp do_drop_connection(key, state = %Manager{server_list: server_list, conns: conns}) do
    server_list = Map.delete(server_list, key)
    result = Enum.find(conns, fn {_, %Info{key: key2}} -> key2 == key end)

    if result do
      {pid, _info} = result
      safe_send(pid, :stop)
      %{state | server_list: server_list, conns: Map.delete(conns, pid)}
    else
      %{state | server_list: server_list}
    end
  end

  defp connected(%Manager{conns: conns, shells: shells, peaks: peaks}) do
    connected =
      Enum.filter(conns, fn {_, %Info{server_address: addr, peaks: conn_peaks}} ->
        addr != nil and
          Enum.all?(shells, fn shell ->
            block_number(conn_peaks[shell]) >= block_number(peaks[shell])
          end)
      end)
      |> Map.new()

    # Reject single node connections
    if map_size(connected) < min_connections() do
      %{}
    else
      connected
    end
  end

  defp min_connections() do
    # When the node list is force set by the user we ignore the usual minimum requirement.
    min(3, map_size(seed_list()))
  end

  defp schedule_update(state) do
    pid = self()
    debounce_timeout = if state.best == [], do: 100, else: 5_000

    Debouncer.immediate(
      {__MODULE__, :update},
      fn ->
        send(pid, :update)
      end,
      debounce_timeout
    )

    state
  end

  defp update(state) do
    state = update_peaks(state)

    pids =
      Map.values(state.conns)
      |> Enum.filter(fn %Info{server_address: addr, peaks: conn_peaks} ->
        # 1. Remove connections that have no address
        # 2. Remove connections that have a lower peak than the current best
        addr != nil and
          Enum.all?(state.peaks, fn {shell, peak} ->
            block_number(conn_peaks[shell]) >= block_number(peak)
          end)
      end)
      |> Enum.map(fn %{pid: pid} -> pid end)

    best = Enum.filter(state.best, fn pid -> pid in pids end)

    if best == [] or
         System.os_time(:second) - state.best_timestamp > 30 do
      update_best(state)
    else
      %{state | best: best}
    end
  end

  defp update_peaks(state = %Manager{peaks: last_peaks, shells: shells}) do
    connected = Map.values(connected(state))
    len = length(connected)
    min_agreement = min(2, min_connections())

    drop =
      if len > 1 do
        # We remove the bottom 20% (but at least 1) of the connected nodes to avoid stale peaks
        max(1, div(len, 5))
      else
        # If there is only one connected node, we don't remove any
        0
      end

    # Get the highest peak for each shell
    peaks =
      for shell <- shells do
        blocks = Enum.map(connected, fn %Info{peaks: peaks} -> peaks[shell] end)

        peak =
          blocks
          |> Enum.sort_by(&block_number/1, :desc)
          # We remove the bottom 20% of the connected nodes to avoid stale peaks
          |> Enum.take(len - drop)
          |> List.last()

        blocks = Enum.filter(blocks, fn block -> block_number(block) == block_number(peak) end)
        candidates = Enum.group_by(blocks, fn block -> block_hash(block) end)

        if map_size(candidates) > 1 do
          Logger.warning(
            "Multiple blocks with the same block_number=#{block_number(peak)} found for shell #{shell}"
          )
        end

        if block_number(peak) > 0 do
          {_hash, agreement = [peak | _]} =
            Enum.max_by(candidates, fn {_hash, blocks} -> length(blocks) end)

          if length(agreement) >= min_agreement and
               block_number(peak) > block_number(last_peaks[shell]) do
            {shell, peak}
          end
        end || {shell, last_peaks[shell]}
      end
      |> Map.new()

    %Manager{state | peaks: peaks}
  end

  defp update_best(state = %Manager{waiting: waiting, best: prev_best, peaks: peaks}) do
    new_best =
      Map.values(connected(state))
      # Filter out nodes that have a lower peak than the current best
      |> Enum.filter(fn %Info{peaks: conn_peaks} ->
        Enum.all?(peaks, fn {shell, peak} ->
          block_number(peak) <= block_number(conn_peaks[shell])
        end)
      end)
      # Sort by latency
      |> Enum.sort_by(fn %Info{latency: latency} -> latency end)

    if peak = List.first(new_best) do
      new_best =
        Enum.filter(new_best, fn %Info{latency: latency} -> latency < 2 * peak.latency end)

      new_best_pids = Enum.map(new_best, fn %{pid: pid} -> pid end)

      if prev_best != new_best_pids do
        servers =
          Enum.map_join(new_best, ", ", fn %{server_url: url, latency: latency} ->
            "#{url}: #{trunc(latency)}"
          end)

        Logger.debug("Best connection changed to [#{servers}]")
      end

      for from <- waiting, do: GenServer.reply(from, new_best_pids)

      %Manager{
        state
        | best: new_best_pids,
          waiting: [],
          best_timestamp: System.os_time(:second)
      }
    else
      %Manager{state | best: []}
    end
  end

  defp block_number(nil), do: 0
  defp block_number(block), do: Rlpx.bin2uint(block["number"])
  defp block_hash(nil), do: nil
  defp block_hash(block), do: DiodeClient.Base16.encode(block["block_hash"])

  @impl true
  def handle_continue(:init, state) do
    {:noreply, restart_all(state)}
  end

  def get_connection_info(cpid, key) when key in @legal_keys do
    get_connection_info(cpid) |> Map.get(key)
  end

  def get_connection_info(cpid) do
    GenServer.call(__MODULE__, {:get_info, cpid})
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
    {:reply, pid, %{state | sticky: info.server_url}}
  end

  defp do_set_online(state = %Manager{online: online, server_list: servers}, new_online) do
    state = %{state | online: new_online}
    pids = Map.keys(servers)

    cond do
      new_online == online ->
        state

      new_online ->
        restart_all(state)

      not new_online ->
        for pid <- pids, do: safe_send(pid, :stop)
        %{state | server_list: seed_list(), conns: %{}, best: []}
    end
  end

  defp safe_send(nil, _message), do: :ok
  defp safe_send(pid, message) when is_atom(pid), do: safe_send(Process.whereis(pid), message)
  defp safe_send(pid, message) when is_pid(pid), do: send(pid, message)
end
