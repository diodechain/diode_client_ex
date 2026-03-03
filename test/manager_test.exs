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
end
