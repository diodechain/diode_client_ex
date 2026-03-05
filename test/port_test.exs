defmodule DiodeClientPortTest do
  @moduledoc """
  Tests for DiodeClient.Port. Regression test: server_candidates returns
  `{pid, info}` tuples; do_connect must pass the pid (not the tuple) to
  Connection.rpc to avoid FunctionClauseError in GenServer.whereis/1.
  """
  use ExUnit.Case, async: false
  @moduletag timeout: 15_000

  alias DiodeClient.{Manager, Port}

  setup do
    if Process.whereis(Manager) == nil do
      assert {:ok, _} = DiodeClient.interface_add("port_test", DiodeClient.Sup)
    end

    Manager.await()
    :ok
  end

  @tag :anvil
  @doc """
  Regression: Port.connect_address must not crash when Manager.connected_connections()
  returns {pid, info} tuples. Previously, the tuple was passed to GenServer.call,
  causing FunctionClauseError in GenServer.whereis/1.
  """
  test "connect_address with local: false does not crash when server_candidates has connections" do
    # Warm up Manager so we may have connected peers
    for _ <- 1..3 do
      for shell <- Manager.default_shells() do
        _ = Manager.get_peak(shell)
      end
    end

    # Random 20-byte destination; server will reject or return error, but we must not crash
    destination = :crypto.strong_rand_bytes(20)

    result =
      try do
        Port.connect_address(destination, 443, local: false)
      rescue
        e in [FunctionClauseError] -> {:regression_crash, e}
      catch
        :exit, {:function_clause, _} -> :regression_crash
        :exit, reason -> {:exit, reason}
      end

    # Must not crash with FunctionClauseError in GenServer.whereis (regression)
    refute result == :regression_crash
    refute match?({:regression_crash, _}, result)

    # Expect {:error, _} (typical) or {:ok, _}; exact error varies
    assert match?({:ok, _}, result) or match?({:error, _}, result) or match?({:exit, _}, result)
  end
end
