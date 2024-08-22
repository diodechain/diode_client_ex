defmodule DiodeClient.Manager do
  @moduledoc false
  alias DiodeClient.{Connection, Manager, Rlpx}
  use GenServer
  defstruct [:conns, :server_list, :waiting, :best, :peaks, :online, :shell]

  defmodule Info do
    @moduledoc false
    # server_address is the diode public key
    # server_url is the url to connect
    defstruct [:latency, :server_address, :server_url, :ports, :key, :pid, :start, :peaks]
  end

  def start_link([]) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__, hibernate_after: 5_000)
  end

  @impl true
  def init(_arg) do
    Process.flag(:trap_exit, true)

    state = %Manager{
      conns: %{},
      online: true,
      peaks: %{},
      server_list: seed_list(),
      shell: DiodeClient.Shell.Moonbeam,
      waiting: []
    }

    {:ok, state, {:continue, :init}}
  end

  defp default_seed_keys(), do: [:eu1, :us1, :as1, :eu2, :us2, :as2]
  defp extra_ports(:eu1), do: [443]
  defp extra_ports(:as1), do: [443]
  defp extra_ports(:us1), do: [443]
  defp extra_ports(_), do: []

  defp seed_list() do
    if System.get_env("SEED_LIST") == nil do
      Enum.map(default_seed_keys(), fn pre ->
        {pre,
         %Info{
           server_url: "#{pre}.prenet.diode.io",
           ports: [41_046, 993, 1723, 10_000] ++ extra_ports(pre),
           key: pre
         }}
      end)
    else
      System.get_env("SEED_LIST")
      |> String.split(",")
      |> Enum.map(fn url ->
        {url, ports} =
          case String.split(url, ":") do
            [url] -> {url, [41_046, 993, 1723, 10_000]}
            [url, port] -> {url, [String.to_integer(port)]}
          end

        key = String.to_atom(url)
        {key, %Info{server_url: url, ports: ports, key: key}}
      end)
    end
    |> Map.new()
  end

  @doc """
    get_connection and get_peak are linked in that peak will never return a block
    higher than any of the connections returned by get_connection has reported.
  """
  def get_connection() do
    GenServer.call(__MODULE__, :get_connection, :infinity)
  end

  def get_connection?() do
    GenServer.call(__MODULE__, :get_connection?, :infinity)
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
    GenServer.call(__MODULE__, :connections)
  end

  def online?() do
    GenServer.call(__MODULE__, :online?)
  end

  def set_online(online) do
    GenServer.call(__MODULE__, {:set_online, online})
  end

  @impl true
  def handle_info({:EXIT, pid, reason}, state = %Manager{conns: conns, shell: shell}) do
    if Map.has_key?(conns, pid) do
      %Info{key: key} = Map.fetch!(conns, pid)
      Process.send_after(self(), {:restart_conn, key}, 15_000)
      state = %Manager{state | conns: Map.delete(conns, pid)}
      {:noreply, refresh_best(state, shell)}
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
  def handle_cast({:set_connection, cpid}, state = %Manager{conns: _conns}) do
    {:noreply, %Manager{state | best: cpid}}
  end

  def handle_cast({:update_info, cpid, info}, state = %Manager{conns: conns}) do
    case Map.get(conns, cpid) do
      nil ->
        {:noreply, state}

      old_info ->
        case struct!(old_info, info) do
          ^old_info ->
            {:noreply, state}

          new_info = %{peaks: peaks} ->
            state =
              Enum.reduce(
                Map.keys(peaks),
                %Manager{state | conns: Map.put(conns, cpid, new_info)},
                fn shell, state ->
                  refresh_best(state, shell)
                end
              )

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

  defp restart_conn(key, state = %Manager{server_list: servers, conns: conns}) do
    info = %Info{server_url: server, ports: ports, key: ^key} = Map.get(servers, key)

    pid =
      case Connection.start_link(server, ports, key) do
        {:ok, pid} -> pid
        {:error, {:already_started, pid}} -> pid
      end

    conns = Map.put(conns, pid, %Info{info | pid: pid, start: System.os_time()})
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
          %Manager{state | server_list: seed_list(), conns: %{}, best: nil}
      end

    {:reply, :ok, state}
  end

  def handle_call(:connections, _from, state = %Manager{conns: conns}) do
    {:reply, Map.keys(conns), state}
  end

  def handle_call({:get_peak, shell}, _from, state = %Manager{peaks: peaks}) do
    {:reply, Map.get(peaks, shell), state}
  end

  def handle_call({:get_info, cpid, key}, _from, state = %Manager{conns: conns}) do
    case Map.get(conns, cpid) do
      nil -> {:reply, nil, state}
      %Info{} = info -> {:reply, Map.get(info, key), state}
    end
  end

  def handle_call(:get_connection?, _from, state = %Manager{online: online, best: best}) do
    if online and best != nil do
      {:reply, best, state}
    else
      {:reply, nil, state}
    end
  end

  def handle_call(:get_connection, from, state = %Manager{online: false, waiting: waiting}) do
    {:noreply, %Manager{state | waiting: waiting ++ [from]}}
  end

  def handle_call(
        :get_connection,
        from,
        state = %Manager{best: nil, waiting: waiting, shell: shell}
      ) do
    %Manager{best: best} = state = refresh_best(state, shell)

    if best == nil do
      {:noreply, %Manager{state | waiting: waiting ++ [from]}}
    else
      {:reply, best, state}
    end
  end

  def handle_call(:get_connection, _from, state = %Manager{best: best}) do
    {:reply, best, state}
  end

  defp connected(%Manager{conns: conns, shell: shell}) do
    Enum.filter(Map.values(conns), fn %Info{server_address: addr, peaks: peaks} ->
      addr != nil and Map.get(peaks, shell) != nil
    end)
  end

  defp refresh_best(state = %Manager{waiting: waiting, peaks: last_peaks}, shell) do
    connected =
      connected(state) |> Enum.reject(fn %Info{peaks: peaks} -> Map.get(peaks, shell) == nil end)

    # Reject single node connections
    connected = if length(connected) < 2, do: [], else: connected

    last_peak = Map.get(last_peaks, shell)

    new_peaks =
      Enum.map(connected, fn %Info{peaks: %{^shell => peak}} -> block_number(peak) end)
      |> Enum.sort(:desc)

    # Trying to have at least three nodes available
    min_peak = List.last(Enum.take(new_peaks, 3)) || 0
    min_peak = max(min_peak, block_number(last_peak))

    Enum.filter(connected, fn %Info{peaks: %{^shell => peak}} ->
      block_number(peak) >= min_peak
    end)
    |> Enum.sort(fn %Info{latency: a}, %Info{latency: b} -> a < b end)
    |> List.first()
    |> case do
      nil ->
        if shell == state.shell do
          %Manager{state | best: nil}
        else
          state
        end

      %Info{pid: pid, peaks: %{^shell => new_peak}} ->
        peak = if block_number(new_peak) > block_number(last_peak), do: new_peak, else: last_peak

        if shell == state.shell do
          for from <- waiting, do: GenServer.reply(from, pid)
          %Manager{state | best: pid, waiting: [], peaks: Map.put(last_peaks, shell, peak)}
        else
          %Manager{state | peaks: Map.put(last_peaks, shell, peak)}
        end
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
end
