defmodule DiodeClient.TxFailoverTest do
  use ExUnit.Case, async: false

  alias DiodeClient.{Connection, Manager, Shell}
  alias DiodeClient.Manager.Info
  alias DiodeClient.Shell.Common
  alias DiodeClient.Rlpx

  @shells [DiodeClient.Shell.Moonbeam, DiodeClient.Shell]
  @eu1_url "eu1.prenet.diode.io"
  @us1_url "us1.prenet.diode.io"
  @as1_url "as1.prenet.diode.io"

  defmodule MockRelay do
    @moduledoc false
    use GenServer

    def start_link(opts \\ []) do
      GenServer.start_link(__MODULE__, Map.new(opts), name: Keyword.get(opts, :name))
    end

    def init(state), do: {:ok, state}

    def handle_call(:reset_count, _from, state) do
      {:reply, Map.get(state, :reset_count, 0), state}
    end

    def handle_call({:rpc, _cmd, _req, _rlp, _time, _pid}, _from, state = %{mode: :hang}) do
      {:noreply, state}
    end

    def handle_call({:rpc, _cmd, req, _rlp, _time, _pid}, _from, state = %{response: response}) do
      {:reply, [req, ["response" | List.wrap(response)]], state}
    end

    def handle_call({:rpc, _cmd, req, _rlp, _time, _pid}, _from, state) do
      {:reply, [req, ["error", "remote_closed"]], state}
    end

    def handle_cast({:rpc_timeout, _req}, state) do
      count = Map.get(state, :reset_count, 0) + 1
      {:noreply, Map.put(state, :reset_count, count)}
    end
  end

  defp block(n) do
    %{
      "number" => Rlpx.uint2bin(n),
      "block_hash" => :crypto.hash(:sha256, <<n>>),
      "timestamp" => Rlpx.uint2bin(n * 6)
    }
  end

  defp peaks(n), do: Map.new(@shells, fn shell -> {shell, block(n)} end)

  defp spawn_conn_holder(), do: spawn_link(fn -> Process.sleep(:infinity) end)

  defp info(url, pid, height, latency, opts \\ []) do
    %Info{
      server_url: url,
      server_address: <<0::160>>,
      pid: pid,
      key: String.to_atom(url),
      latency: latency,
      peaks: peaks(height),
      type: Keyword.get(opts, :type, :seed)
    }
  end

  defp base_manager_state(conns, opts) do
    height = Keyword.get(opts, :height, 100)

    %Manager{
      conns: conns,
      shells: MapSet.new(@shells),
      chain_peaks: peaks(height),
      traffic_best: Keyword.get(opts, :best, []),
      traffic_best_timestamp: System.os_time(:second),
      debounce_timeout: 100,
      online: true,
      server_list: %{},
      waiting_traffic: [],
      waiting_for_peak: %{},
      sticky: Keyword.get(opts, :sticky, nil),
      peak_subscribers: %{},
      peak_subscriber_refs: %{},
      local_peak_pollers: %{},
      rpc_failed_at: %{},
      sticky_unhealthy_since: nil
    }
  end

  describe "Connection.rpc timeout handling" do
    test "returns {:error, :timeout} instead of raising on GenServer timeout" do
      {:ok, hang_pid} = MockRelay.start_link(mode: :hang)

      assert {:error, :timeout} =
               Connection.rpc(hang_pid, ["sendtransaction"], timeout: 50)
    end

    test "sends rpc_timeout cast to wedged connection" do
      {:ok, hang_pid} = MockRelay.start_link(mode: :hang)

      Connection.rpc(hang_pid, ["sendtransaction"], timeout: 50)
      Process.sleep(20)

      assert GenServer.call(hang_pid, :reset_count) == 1
    end
  end

  describe "Manager tx relay candidates" do
    test "orders sticky before traffic seeds and chain pool, deduped" do
      eu1 = spawn_conn_holder()
      us1 = spawn_conn_holder()
      as1 = spawn_conn_holder()

      conns = %{
        eu1 => info(@eu1_url, eu1, 100, 100),
        us1 => info(@us1_url, us1, 100, 200),
        as1 => info(@as1_url, as1, 100, 300)
      }

      Process.register(eu1, Manager.Sticky)

      state =
        base_manager_state(conns,
          best: [eu1, us1, as1]
        )

      candidates = Manager.__test_tx_relay_candidates__(state, DiodeClient.Shell.Moonbeam)

      assert candidates == [eu1, us1, as1]
    end

    test "excludes recently failed relay from candidates" do
      eu1 = spawn_conn_holder()
      us1 = spawn_conn_holder()

      conns = %{
        eu1 => info(@eu1_url, eu1, 100, 100),
        us1 => info(@us1_url, us1, 100, 200)
      }

      state =
        base_manager_state(conns, best: [eu1, us1])
        |> Map.put(:rpc_failed_at, %{eu1 => System.monotonic_time(:millisecond)})

      candidates = Manager.__test_tx_relay_candidates__(state, DiodeClient.Shell.Moonbeam)

      assert candidates == [us1]
      refute eu1 in candidates
    end

    test "clear_sticky unregisters sticky pid and clears sticky url" do
      eu1 = spawn_conn_holder()
      Process.register(eu1, Manager.Sticky)

      state =
        base_manager_state(%{}, sticky: @eu1_url)
        |> Manager.__test_clear_sticky__(eu1)

      assert Process.whereis(Manager.Sticky) == nil
      assert state.sticky == nil
      assert state.sticky_unhealthy_since == nil
    end
  end

  describe "Manager sticky 2-minute hold" do
    test "rpc failure on sticky sets unhealthy_since but keeps sticky within hold" do
      eu1 = spawn_conn_holder()
      us1 = spawn_conn_holder()
      Process.register(eu1, Manager.Sticky)

      conns = %{
        eu1 => info(@eu1_url, eu1, 100, 100),
        us1 => info(@us1_url, us1, 100, 200)
      }

      state =
        base_manager_state(conns, best: [eu1, us1], sticky: @eu1_url)
        |> Manager.__test_connection_rpc_failed__(eu1, :timeout)

      assert Process.whereis(Manager.Sticky) == eu1
      assert state.sticky == @eu1_url
      assert is_integer(state.sticky_unhealthy_since)
      assert Map.has_key?(state.rpc_failed_at, eu1)

      candidates = Manager.__test_tx_relay_candidates__(state, DiodeClient.Shell.Moonbeam)
      assert candidates == [us1]
      refute eu1 in candidates
    end

    test "sticky remains excluded while unhealthy_since is set even after cooldown window" do
      eu1 = spawn_conn_holder()
      us1 = spawn_conn_holder()
      Process.register(eu1, Manager.Sticky)

      conns = %{
        eu1 => info(@eu1_url, eu1, 100, 100),
        us1 => info(@us1_url, us1, 100, 200)
      }

      old_failure = System.monotonic_time(:millisecond) - 90_000

      state =
        base_manager_state(conns, best: [eu1, us1], sticky: @eu1_url)
        |> Map.put(:sticky_unhealthy_since, old_failure)
        |> Map.put(:rpc_failed_at, %{eu1 => old_failure})

      candidates = Manager.__test_tx_relay_candidates__(state, DiodeClient.Shell.Moonbeam)
      assert candidates == [us1]
      refute eu1 in candidates
    end

    test "rpc failure clears sticky after 2-minute hold expires" do
      eu1 = spawn_conn_holder()
      us1 = spawn_conn_holder()
      Process.register(eu1, Manager.Sticky)

      conns = %{
        eu1 => info(@eu1_url, eu1, 100, 100),
        us1 => info(@us1_url, us1, 100, 200)
      }

      past = System.monotonic_time(:millisecond) - 120_000

      state =
        base_manager_state(conns, best: [eu1, us1], sticky: @eu1_url)
        |> Map.put(:sticky_unhealthy_since, past)
        |> Manager.__test_connection_rpc_failed__(eu1, :timeout)

      assert Process.whereis(Manager.Sticky) == nil
      assert state.sticky == nil
      assert state.sticky_unhealthy_since == nil
    end

    test "connection_rpc_ok on sticky clears hold and restores candidate eligibility" do
      eu1 = spawn_conn_holder()
      us1 = spawn_conn_holder()
      Process.register(eu1, Manager.Sticky)

      conns = %{
        eu1 => info(@eu1_url, eu1, 100, 100),
        us1 => info(@us1_url, us1, 100, 200)
      }

      state =
        base_manager_state(conns, best: [eu1, us1], sticky: @eu1_url)
        |> Map.put(:sticky_unhealthy_since, System.monotonic_time(:millisecond))
        |> Map.put(:rpc_failed_at, %{eu1 => System.monotonic_time(:millisecond)})
        |> Manager.__test_connection_rpc_ok__(eu1)

      assert state.sticky_unhealthy_since == nil
      refute Map.has_key?(state.rpc_failed_at, eu1)
      assert state.sticky == @eu1_url
      assert Process.whereis(Manager.Sticky) == eu1

      candidates = Manager.__test_tx_relay_candidates__(state, DiodeClient.Shell.Moonbeam)
      assert candidates == [eu1, us1]
    end

    test "non-sticky failure does not clear sticky or set sticky_unhealthy_since" do
      eu1 = spawn_conn_holder()
      us1 = spawn_conn_holder()
      Process.register(eu1, Manager.Sticky)

      conns = %{
        eu1 => info(@eu1_url, eu1, 100, 100),
        us1 => info(@us1_url, us1, 100, 200)
      }

      state =
        base_manager_state(conns, best: [eu1, us1], sticky: @eu1_url)
        |> Manager.__test_connection_rpc_failed__(us1, :remote_closed)

      assert Process.whereis(Manager.Sticky) == eu1
      assert state.sticky == @eu1_url
      assert state.sticky_unhealthy_since == nil
      assert Map.has_key?(state.rpc_failed_at, us1)
    end
  end

  describe "Shell.Common rpc_with_tx_failover" do
    test "fails over from wedged relay to healthy relay" do
      {:ok, hang_pid} = MockRelay.start_link(mode: :hang)
      {:ok, ok_pid} = MockRelay.start_link(response: ["0xabc"])

      cmd = ["glmr:sendtransaction", <<>>]

      assert ["0xabc"] =
               Common.__test_rpc_with_tx_failover__(
                 DiodeClient.Shell.Moonbeam,
                 cmd,
                 [
                   hang_pid,
                   ok_pid
                 ],
                 timeout: 50
               )
    end

    test "returns {:error, :relay_exhausted} when all candidates fail" do
      {:ok, hang1} = MockRelay.start_link(mode: :hang)
      {:ok, hang2} = MockRelay.start_link(mode: :hang)

      cmd = ["sendtransaction", <<>>]

      assert {:error, :relay_exhausted} =
               Common.__test_rpc_with_tx_failover__(Shell, cmd, [hang1, hang2], timeout: 50)
    end

    test "retries on remote_closed and succeeds on next candidate" do
      {:ok, closed_pid} = MockRelay.start_link()
      {:ok, ok_pid} = MockRelay.start_link(response: ["0xdeadbeef"])

      cmd = ["sendtransaction", <<>>]

      assert ["0xdeadbeef"] =
               Common.__test_rpc_with_tx_failover__(Shell, cmd, [closed_pid, ok_pid])
    end
  end
end
