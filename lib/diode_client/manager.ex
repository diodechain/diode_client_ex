defmodule DiodeClient.Manager do
  @moduledoc false
  alias DiodeClient.{
    Block,
    Connection,
    Manager,
    Manager.ChainPeaks,
    Manager.LocalPeakPoller,
    NodeScorer,
    Rlpx
  }

  use GenServer
  require Logger

  @ticket_shell DiodeClient.Shell.Moonbeam

  defstruct [
    :conns,
    :server_list,
    :waiting_traffic,
    :waiting_for_peak,
    :traffic_best,
    :chain_peaks,
    :online,
    :shells,
    :sticky,
    :traffic_best_timestamp,
    :debounce_timeout,
    :peak_subscribers,
    :peak_subscriber_refs,
    :local_peak_pollers,
    :last_reported_uncle_block,
    :rpc_failed_at,
    :sticky_unhealthy_since
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

  @initial_debounce_timeout 100

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
      chain_peaks: %{},
      server_list: seed_list(),
      shells: MapSet.new(default_shells()),
      waiting_traffic: [],
      waiting_for_peak: %{},
      traffic_best: [],
      debounce_timeout: @initial_debounce_timeout,
      peak_subscribers: %{},
      peak_subscriber_refs: %{},
      local_peak_pollers: %{},
      last_reported_uncle_block: %{},
      rpc_failed_at: %{},
      sticky_unhealthy_since: nil
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
  Returns a low-latency relay for Diode traffic (ports, objects, default RPC).
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
  Returns the consensus chain peak for `shell` from per-chain supermajority.
  """
  def get_peak(shell) when is_atom(shell) do
    # sanity check that the shell is valid
    _chain_id = shell.chain_id()
    GenServer.call(__MODULE__, {:get_peak, shell}, :infinity)
  end

  @doc """
  Subscribes the calling process to peak changes for the given shell.

  The caller receives `{DiodeClient.Manager, shell, :peak, block}` on every new peak.
  Use `unsubscribe_peak/1` to unsubscribe, or the subscription is cleared when the process exits.
  """
  def subscribe_peak(shell) when is_atom(shell) do
    _chain_id = shell.chain_id()
    GenServer.call(__MODULE__, {:subscribe_peak, shell}, :infinity)
  end

  @doc """
  Unsubscribes the calling process from peak changes for the given shell.
  """
  def unsubscribe_peak(shell) when is_atom(shell) do
    _chain_id = shell.chain_id()
    GenServer.call(__MODULE__, {:unsubscribe_peak, shell}, :infinity)
  end

  @doc """
  Returns a relay at the consensus peak for `shell`, preferring low latency.
  Falls back to `get_connection/0` when no qualifying relay exists.
  """
  def get_chain_connection(shell) when is_atom(shell) do
    _chain_id = shell.chain_id()

    case GenServer.call(__MODULE__, {:get_chain_connection, shell}, :infinity) do
      pid when is_pid(pid) -> pid
      [] -> get_connection()
      pids when is_list(pids) -> Enum.random(pids)
    end
  end

  @rpc_failure_cooldown_ms 60_000
  @sticky_hold_ms 120_000

  @doc false
  def clear_sticky_connection(pid, reason \\ :rpc_failure) do
    GenServer.cast(__MODULE__, {:clear_sticky, pid, reason})
  end

  @doc false
  def connection_rpc_failed(pid, reason) do
    GenServer.cast(__MODULE__, {:connection_rpc_failed, pid, reason})
  end

  @doc false
  def connection_rpc_ok(pid) do
    GenServer.cast(__MODULE__, {:connection_rpc_ok, pid})
  end

  @doc false
  def tx_relay_candidates(shell) when is_atom(shell) do
    _chain_id = shell.chain_id()
    GenServer.call(__MODULE__, {:tx_relay_candidates, shell}, :infinity)
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

    added =
      if seed_list_override() == nil and new_len < @target_connections do
        for _ <- (new_len + 1)..@target_connections do
          add_connection()
        end

        max(0, new_len - @target_connections)
      else
        0
      end

    removed = len - new_len

    if removed > 0 or added > 0 do
      Logger.debug(
        "DiodeClient.Manager: removed #{removed}, added #{added} connections, new length #{new_len + added}"
      )
    end
  end

  def online?() do
    GenServer.call(__MODULE__, :online?)
  end

  def set_online(online) do
    GenServer.cast(__MODULE__, {:set_online, online})
  end

  @impl true
  def handle_info({:DOWN, ref, :process, pid, reason}, state) do
    state = remove_peak_subscriber(ref, state)
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
        if reason != :normal do
          Logger.debug("Connection down: #{inspect(pid)} #{inspect(reason)}")
        end

        {:noreply, state}
    end
  end

  @impl true
  def handle_cast({:set_online, new_online}, state) do
    {:noreply, do_set_online(state, new_online)}
  end

  def handle_cast({:local_peak, shell, block}, state = %Manager{chain_peaks: chain_peaks}) do
    old_peaks = chain_peaks
    new_peaks = %{shell => block}
    notify_peak_subscribers(state.peak_subscribers, old_peaks, new_peaks)

    waiting_for_peak =
      case Map.pop(state.waiting_for_peak, shell) do
        {nil, rest} ->
          rest

        {pids, rest} ->
          for pid <- pids, do: GenServer.reply(pid, block)
          rest
      end

    state =
      state
      |> Map.put(:chain_peaks, Map.put(chain_peaks, shell, block))
      |> Map.put(:waiting_for_peak, waiting_for_peak)

    {:noreply, state}
  end

  @impl true
  def handle_cast({:set_connection, cpid}, state = %Manager{conns: _conns}) do
    {:noreply, %{state | traffic_best: [cpid]}}
  end

  def handle_cast({:clear_sticky, pid, _reason}, state) do
    {:noreply, do_clear_sticky(pid, state)}
  end

  def handle_cast({:connection_rpc_failed, pid, reason}, state) do
    {:noreply, apply_connection_rpc_failed(state, pid, reason)}
  end

  def handle_cast({:connection_rpc_ok, pid}, state) do
    {:noreply, heal_sticky_if_ok(pid, state)}
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

  defp do_restart_conn(info, state = %Manager{chain_peaks: chain_peaks, conns: conns}) do
    pid =
      case Connection.start_link(info.server_url, info.ports) do
        {:ok, pid} ->
          Process.monitor(pid)

          for {shell, _} <- chain_peaks do
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
    {:reply, online and any_authenticated?(state), state}
  end

  def handle_call({:set_online, new_online}, _from, state) do
    {:reply, :ok, do_set_online(state, new_online)}
  end

  def handle_call(:connections, _from, state = %Manager{conns: conns}) do
    {:reply, conns, state}
  end

  def handle_call(
        {:get_peak, shell},
        from,
        state = %Manager{chain_peaks: chain_peaks, conns: conns, shells: shells}
      ) do
    if local_shell?(shell) and Map.get(chain_peaks, shell) == nil do
      peak = shell.peak()

      state = %{state | chain_peaks: Map.put(chain_peaks, shell, peak)}

      {:reply, peak, state}
    else
      state = %{state | shells: MapSet.put(shells, shell)}
      for c <- Map.keys(conns), do: safe_send(c, {:subscribe, shell})

      if peak = Map.get(chain_peaks, shell) do
        {:reply, peak, state}
      else
        waiting_for_peak = Map.get(state.waiting_for_peak, shell, []) ++ [from]

        {:noreply,
         %{state | waiting_for_peak: Map.put(state.waiting_for_peak, shell, waiting_for_peak)}}
      end
    end
  end

  def handle_call({:subscribe_peak, shell}, {pid, _tag}, state) do
    state = ensure_shell_subscription(shell, state)
    state = ensure_local_peak_poller(shell, state)
    ref = Process.monitor(pid)

    subscribers = Map.get(state.peak_subscribers, shell, []) ++ [{pid, ref}]
    peak_subscribers = Map.put(state.peak_subscribers, shell, subscribers)
    peak_subscriber_refs = Map.put(state.peak_subscriber_refs, ref, {shell, pid})

    {:reply, :ok,
     %{state | peak_subscribers: peak_subscribers, peak_subscriber_refs: peak_subscriber_refs}}
  end

  def handle_call({:unsubscribe_peak, shell}, {pid, _tag}, state) do
    case remove_peak_subscriber_for_pid(pid, shell, state) do
      {:ok, new_state} -> {:reply, :ok, new_state}
      :error -> {:reply, :ok, state}
    end
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

  def handle_call(:get_connection?, _from, state = %Manager{online: online, traffic_best: best}) do
    {:reply, if(online, do: best, else: []), state}
  end

  def handle_call(
        :get_connection,
        from,
        state = %Manager{online: false, waiting_traffic: waiting}
      ) do
    {:noreply, %Manager{state | waiting_traffic: waiting ++ [from]}}
  end

  def handle_call(
        :get_connection,
        from,
        state = %Manager{traffic_best: [], waiting_traffic: waiting}
      ) do
    {:noreply, %Manager{state | waiting_traffic: waiting ++ [from]}}
  end

  def handle_call(:get_connection, _from, state = %Manager{traffic_best: best}) do
    {:reply, best, state}
  end

  def handle_call({:get_chain_connection, shell}, _from, state) do
    {:reply, chain_connection_pids(state, shell), state}
  end

  def handle_call({:tx_relay_candidates, shell}, _from, state) do
    {:reply, tx_relay_candidates(state, shell), state}
  end

  def handle_call(
        :get_sticky_connection?,
        _from,
        state = %Manager{sticky: sticky, online: online, traffic_best: best, conns: conns}
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
        traffic_viable_conns(state)
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
    {:reply, :ok,
     restart_all(%{
       state
       | server_list: list,
         sticky: nil,
         traffic_best: [],
         chain_peaks: %{}
     })}
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

  defp any_authenticated?(%Manager{conns: conns}) do
    Enum.any?(conns, fn {_pid, %Info{server_address: addr}} -> addr != nil end)
  end

  defp min_connections() do
    min(3, map_size(seed_list()))
  end

  defp traffic_viable?(%Info{server_address: addr, peaks: conn_peaks}, %Manager{
         chain_peaks: chain_peaks
       }) do
    if addr == nil do
      false
    else
      diode_peak = Map.get(chain_peaks, DiodeClient.Shell)
      ticket_peak = Map.get(chain_peaks, @ticket_shell)
      diode_block = Map.get(conn_peaks, DiodeClient.Shell)
      ticket_block = Map.get(conn_peaks, @ticket_shell)

      diode_ok =
        is_nil(diode_peak) or block_number(diode_block) >= block_number(diode_peak)

      ticket_ok =
        is_nil(ticket_peak) or
          (ticket_block != nil and
             ticket_epoch(ticket_block) >= ticket_epoch(ticket_peak))

      diode_ok and ticket_ok
    end
  end

  defp ticket_epoch(block) do
    if Block.diode?(block) do
      Block.epoch(block)
    else
      case Map.get(block, "timestamp") do
        nil -> 0
        "" -> 0
        _ -> Block.epoch(block)
      end
    end
  end

  defp traffic_viable_conns(state = %Manager{conns: conns}) do
    conns
    |> Enum.filter(fn {_pid, info} -> traffic_viable?(info, state) end)
    |> Map.new()
  end

  defp chain_connection_pids(state = %Manager{}, shell) do
    ChainPeaks.connected_for_shell(shell, state.conns, state.chain_peaks, min_connections())
    |> Enum.sort_by(fn {_pid, %Info{latency: latency}} -> latency end)
    |> Enum.map(fn {pid, _} -> pid end)
  end

  defp tx_relay_candidates(state = %Manager{}, shell) do
    now = System.monotonic_time(:millisecond)

    viable? = fn pid ->
      case Map.get(state.conns, pid) do
        %Info{} = info ->
          traffic_viable?(info, state) and not rpc_failed_recently?(state, pid, now)

        _ ->
          false
      end
    end

    sticky = Process.whereis(__MODULE__.Sticky)
    traffic_seeds = traffic_viable_seed_pids(state, now)
    chain_pids = chain_connection_pids(state, shell)

    [sticky | traffic_seeds ++ chain_pids]
    |> Enum.reject(&is_nil/1)
    |> Enum.uniq()
    |> Enum.filter(viable?)
  end

  defp traffic_viable_seed_pids(state = %Manager{traffic_best: best}, now) do
    best
    |> Enum.filter(fn pid ->
      case Map.get(state.conns, pid) do
        %Info{type: :seed} = info ->
          traffic_viable?(info, state) and not rpc_failed_recently?(state, pid, now)

        _ ->
          false
      end
    end)
    |> Enum.sort_by(fn pid ->
      case Map.get(state.conns, pid) do
        %Info{latency: latency} -> latency
        _ -> 100_000_000_000_000
      end
    end)
  end

  defp apply_connection_rpc_failed(state, pid, reason) do
    now = System.monotonic_time(:millisecond)

    state =
      case Map.get(state.conns, pid) do
        %Info{server_url: server_url} ->
          if reason in [:timeout, :remote_closed] do
            NodeScorer.report_failure(server_url)
          end

          %{state | rpc_failed_at: Map.put(state.rpc_failed_at, pid, now)}

        _ ->
          %{state | rpc_failed_at: Map.put(state.rpc_failed_at, pid, now)}
      end

    maybe_release_sticky_after_hold(pid, now, state)
  end

  defp rpc_failed_recently?(
         %Manager{rpc_failed_at: failed_at, sticky_unhealthy_since: unhealthy_since},
         pid,
         now
       ) do
    sticky_held_unhealthy? =
      unhealthy_since != nil and Process.whereis(__MODULE__.Sticky) == pid

    recent_failure? =
      case Map.get(failed_at, pid) do
        nil -> false
        failed_ms -> now - failed_ms < @rpc_failure_cooldown_ms
      end

    sticky_held_unhealthy? or recent_failure?
  end

  defp maybe_release_sticky_after_hold(pid, now, state = %Manager{}) do
    if Process.whereis(__MODULE__.Sticky) == pid do
      since = state.sticky_unhealthy_since || now
      state = %{state | sticky_unhealthy_since: since}

      if now - since >= @sticky_hold_ms do
        do_clear_sticky(pid, state)
      else
        state
      end
    else
      state
    end
  end

  defp heal_sticky_if_ok(pid, state = %Manager{}) do
    if Process.whereis(__MODULE__.Sticky) == pid do
      %{
        state
        | sticky_unhealthy_since: nil,
          rpc_failed_at: Map.delete(state.rpc_failed_at, pid)
      }
    else
      state
    end
  end

  defp do_clear_sticky(pid, state = %Manager{}) do
    if Process.whereis(__MODULE__.Sticky) == pid do
      try do
        Process.unregister(__MODULE__.Sticky)
      rescue
        ArgumentError -> :ok
      end

      %{state | sticky: nil, sticky_unhealthy_since: nil}
    else
      state
    end
  end

  defp schedule_update(state) do
    pid = self()

    Debouncer.immediate(
      {__MODULE__, :update},
      fn -> send(pid, :update) end,
      state.debounce_timeout
    )

    state
  end

  defp update(state) do
    state = update_chain_peaks(state)
    traffic_candidates = Map.values(traffic_viable_conns(state))
    viable_best = Enum.filter(state.traffic_best, &traffic_best_pid_viable?(state, &1))

    if viable_best == [] or
         System.os_time(:second) - state.traffic_best_timestamp > 30 do
      update_traffic_best(state, traffic_candidates)
    else
      %{state | traffic_best: viable_best}
    end
  end

  defp traffic_best_pid_viable?(state = %Manager{conns: conns}, pid) do
    case Map.get(conns, pid) do
      %Info{} = info -> traffic_viable?(info, state)
      _ -> false
    end
  end

  defp update_chain_peaks(
         state = %Manager{
           chain_peaks: last_peaks,
           shells: shells,
           last_reported_uncle_block: last_reported_uncle_block,
           conns: conns
         }
       ) do
    min_conn = min_connections()
    opts = [min_connections: min_conn]

    {chain_peaks, last_reported_uncle_block} =
      Enum.reduce(shells, {%{}, last_reported_uncle_block}, fn shell, {peaks, reported} ->
        connected =
          ChainPeaks.connected_for_shell(shell, conns, last_peaks, min_conn)
          |> Map.values()

        {peak, reported} =
          ChainPeaks.consensus_peak_for_shell(
            shell,
            connected,
            Map.get(last_peaks, shell),
            reported,
            opts
          )

        {Map.put(peaks, shell, peak), reported}
      end)

    debounce_timeout =
      if state.debounce_timeout == @initial_debounce_timeout and
           state.traffic_best != [] and
           not Enum.any?(state.chain_peaks, fn {_shell, peak} -> block_number(peak) == 0 end) do
        5_000
      else
        state.debounce_timeout
      end

    waiting_for_peak =
      Enum.filter(state.waiting_for_peak, fn {shell, pids} ->
        if peak = chain_peaks[shell] do
          for pid <- pids, do: GenServer.reply(pid, peak)
          false
        else
          true
        end
      end)
      |> Map.new()

    notify_peak_subscribers(state.peak_subscribers, state.chain_peaks, chain_peaks)

    %Manager{
      state
      | chain_peaks: chain_peaks,
        waiting_for_peak: waiting_for_peak,
        debounce_timeout: debounce_timeout,
        last_reported_uncle_block: last_reported_uncle_block
    }
  end

  defp notify_peak_subscribers(peak_subscribers, old_peaks, new_peaks) do
    for {shell, subscribers} <- peak_subscribers,
        new_block = new_peaks[shell],
        block_number(new_block) != block_number(Map.get(old_peaks, shell)) do
      msg = {__MODULE__, shell, :peak, new_block}

      for {pid, _ref} <- subscribers do
        send(pid, msg)
      end
    end

    :ok
  end

  defp update_traffic_best(
         state = %Manager{waiting_traffic: waiting, traffic_best: prev_best},
         traffic_candidates
       ) do
    new_best =
      traffic_candidates
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

        Logger.debug("Traffic best connection changed to [#{servers}]")
      end

      for from <- waiting, do: GenServer.reply(from, new_best_pids)

      %Manager{
        state
        | traffic_best: new_best_pids,
          waiting_traffic: [],
          traffic_best_timestamp: System.os_time(:second)
      }
    else
      best = Enum.filter(prev_best, &traffic_best_pid_viable?(state, &1))

      %Manager{state | traffic_best: best}
    end
  end

  defp block_number(nil), do: 0
  defp block_number(block), do: Rlpx.bin2uint(block["number"])

  @impl true
  def handle_continue(:init, state) do
    {:noreply, restart_all(state)}
  end

  def get_connection_info(cpid, key) when key in @legal_keys do
    get_connection_info(cpid) |> Map.get(key)
  end

  def get_connection_info(cpid) do
    GenServer.call(__MODULE__, {:get_info, cpid})
  catch
    :exit, {:noproc, _} -> %{}
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
        %{state | server_list: seed_list(), conns: %{}, traffic_best: []}
    end
  end

  defp safe_send(nil, _message), do: :ok
  defp safe_send(pid, message) when is_atom(pid), do: safe_send(Process.whereis(pid), message)
  defp safe_send(pid, message) when is_pid(pid), do: send(pid, message)

  defp local_shell?(shell) do
    function_exported?(shell, :local_peak?, 0) and shell.local_peak?()
  end

  defp ensure_local_peak_poller(shell, state = %Manager{local_peak_pollers: pollers}) do
    if local_shell?(shell) and not Map.has_key?(pollers, shell) do
      case LocalPeakPoller.start_link(shell) do
        {:ok, pid} -> %{state | local_peak_pollers: Map.put(pollers, shell, pid)}
        {:error, _} -> state
      end
    else
      state
    end
  end

  defp stop_local_peak_poller_if_unsubscribed(
         shell,
         state = %Manager{
           peak_subscribers: subs,
           local_peak_pollers: pollers
         }
       ) do
    if local_shell?(shell) and (subs[shell] || []) == [] do
      case Map.pop(pollers, shell) do
        {nil, _} ->
          state

        {pid, pollers} ->
          Process.exit(pid, :normal)
          %{state | local_peak_pollers: pollers}
      end
    else
      state
    end
  end

  defp ensure_shell_subscription(shell, state = %Manager{shells: shells, conns: conns}) do
    state = %{state | shells: MapSet.put(shells, shell)}
    for c <- Map.keys(conns), do: safe_send(c, {:subscribe, shell})
    state
  end

  defp remove_peak_subscriber(ref, state = %Manager{peak_subscriber_refs: refs}) do
    case Map.pop(refs, ref) do
      {nil, _} ->
        state

      {{shell, pid}, refs} ->
        subscribers =
          (state.peak_subscribers[shell] || [])
          |> Enum.reject(fn {p, _} -> p == pid end)

        peak_subscribers =
          if subscribers == [] do
            Map.delete(state.peak_subscribers, shell)
          else
            Map.put(state.peak_subscribers, shell, subscribers)
          end

        state = %{state | peak_subscribers: peak_subscribers, peak_subscriber_refs: refs}
        stop_local_peak_poller_if_unsubscribed(shell, state)
    end
  end

  defp remove_peak_subscriber_for_pid(pid, shell, state) do
    subscribers = state.peak_subscribers[shell] || []

    case Enum.split_with(subscribers, fn {p, _} -> p == pid end) do
      {[], _} ->
        :error

      {[{^pid, ref}], rest} ->
        Process.demonitor(ref, [:flush])
        refs = Map.delete(state.peak_subscriber_refs, ref)

        peak_subscribers =
          if rest == [] do
            Map.delete(state.peak_subscribers, shell)
          else
            Map.put(state.peak_subscribers, shell, rest)
          end

        new_state = %{state | peak_subscribers: peak_subscribers, peak_subscriber_refs: refs}
        new_state = stop_local_peak_poller_if_unsubscribed(shell, new_state)
        {:ok, new_state}
    end
  end

  @doc false
  def __test_tx_relay_candidates__(state, shell) do
    tx_relay_candidates(state, shell)
  end

  @doc false
  def __test_clear_sticky__(state, pid) do
    do_clear_sticky(pid, state)
  end

  @doc false
  def __test_connection_rpc_failed__(state, pid, reason \\ :timeout) do
    apply_connection_rpc_failed(state, pid, reason)
  end

  @doc false
  def __test_connection_rpc_ok__(state, pid) do
    heal_sticky_if_ok(pid, state)
  end

  # Test-only helpers for diagnosing "Best connection changed" log behavior.
  @doc false
  def __test_simulate_update__(state) do
    prev_best = state.traffic_best
    prev_urls = __test_best_urls__(state, prev_best)

    state = update_chain_peaks(state)
    traffic_candidates = Map.values(traffic_viable_conns(state))
    viable_best = Enum.filter(state.traffic_best, &traffic_best_pid_viable?(state, &1))

    recompute_reason =
      cond do
        viable_best == [] -> :best_not_viable
        System.os_time(:second) - state.traffic_best_timestamp > 30 -> :timestamp_expired
        true -> :no_recompute
      end

    {state, would_log} =
      case recompute_reason do
        :no_recompute ->
          {%{state | traffic_best: viable_best}, false}

        _ ->
          prev_for_log = state.traffic_best
          state = update_traffic_best(state, traffic_candidates)
          {state, prev_for_log != state.traffic_best}
      end

    new_best = state.traffic_best
    new_urls = __test_best_urls__(state, new_best)

    connected_count =
      state.shells
      |> Enum.map(fn shell ->
        ChainPeaks.connected_for_shell(shell, state.conns, state.chain_peaks, min_connections())
        |> map_size()
      end)
      |> Enum.min(fn -> 0 end)

    diag = %{
      prev_best: prev_best,
      new_best: new_best,
      prev_urls: prev_urls,
      new_urls: new_urls,
      would_log: would_log,
      pids_changed: prev_best != new_best,
      urls_unchanged_pids_changed: prev_urls == new_urls and prev_best != new_best,
      recompute_reason: recompute_reason,
      connected_count: connected_count
    }

    {state, diag}
  end

  @doc false
  def __test_best_urls__(state, pids) do
    Enum.map(pids, fn pid ->
      case Map.get(state.conns, pid) do
        %Info{server_url: url} -> url
        _ -> nil
      end
    end)
  end
end
