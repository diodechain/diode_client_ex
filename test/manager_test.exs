defmodule DiodeClientManagerTest do
  @moduledoc """
  Tests for DiodeClient.Manager. Anvil-tagged tests require the Diode client
  application (interface) and optionally a running Anvil instance.
  """
  use ExUnit.Case, async: false
  @moduletag timeout: 15_000

  alias DiodeClient.Manager
  alias DiodeClient.Shell.Anvil
  alias DiodeClient.Rlpx

  setup do
    if Process.whereis(Manager) == nil do
      assert {:ok, _} = DiodeClient.interface_add("manager_test", DiodeClient.Sup)
    end

    Manager.await()
    :ok
  end

  describe "subscribe_peak" do
    @tag :anvil
    test "subscribe_peak and unsubscribe_peak roundtrip" do
      assert :ok = Manager.subscribe_peak(Anvil)
      assert :ok = Manager.unsubscribe_peak(Anvil)
    end

    @tag :anvil
    test "subscriber process exit cleans up without crashing Manager" do
      pid =
        spawn(fn ->
          Manager.subscribe_peak(Anvil)
          Process.sleep(:infinity)
        end)

      Process.sleep(100)
      Process.exit(pid, :kill)
      Process.sleep(100)

      # Manager should still be alive and responsive
      assert Process.whereis(Manager) != nil
      assert :ok = Manager.subscribe_peak(Anvil)
      assert :ok = Manager.unsubscribe_peak(Anvil)
    end

    @tag :anvil
    test "receives peak when Diode network produces new block" do
      # Manager tracks Moonbeam/Shell from Diode P2P; subscribe and wait for a block
      shell = DiodeClient.Shell.Moonbeam
      assert :ok = Manager.subscribe_peak(shell)

      received =
        receive do
          {Manager, ^shell, :peak, block} ->
            Rlpx.bin2uint(block["number"])
        after
          30_000 -> nil
        end

      assert :ok = Manager.unsubscribe_peak(shell)
      assert received != nil, "expected peak message (Moonbeam ~12s block time)"
    end
  end

  describe "update and connected optimizations" do
    @tag :anvil
    test "get_connection and get_peak linkage - peak never exceeds connection-reported peaks" do
      # Invariant: peak will never return a block higher than any connected connection has reported
      shell = DiodeClient.Shell.Moonbeam
      peak = Manager.get_peak(shell)
      assert is_map(peak) or peak == nil

      if peak != nil do
        peak_num = Rlpx.bin2uint(peak["number"])
        connected = Manager.connected_connections()

        for {pid, %{peaks: peaks}} <- connected do
          conn_peak = peaks[shell]

          if conn_peak != nil do
            conn_num = Rlpx.bin2uint(conn_peak["number"])

            assert peak_num <= conn_num,
                   "peak #{peak_num} should be <= conn #{inspect(pid)} peak #{conn_num} (invariant)"
          end
        end
      end
    end

    @tag :anvil
    test "online? and get_connection consistency" do
      online = Manager.online?()

      if online do
        conn = Manager.get_connection()
        assert is_pid(conn), "online? true implies get_connection returns a connection pid"
      end
    end

    @tag :anvil
    test "connection_map and ranked_connections after many update cycles" do
      # Stress the update path by triggering multiple updates and verifying consistency
      shells = Manager.default_shells()

      for _ <- 1..5 do
        for shell <- shells do
          _ = Manager.get_peak(shell)
        end
      end

      conn_map = Manager.connection_map()
      assert is_map(conn_map)
      ranked = Manager.ranked_connections()
      assert is_list(ranked)
      assert length(ranked) == map_size(conn_map)
    end
  end
end
