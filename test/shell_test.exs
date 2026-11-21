defmodule DiodeClientShellTest do
  use ExUnit.Case
  @moduletag timeout: 1000

  test "await_all" do
    promise = fn -> :ok end
    assert DiodeClient.Shell.await_all([promise]) == [:ok]
  end

  test "await_all failure" do
    promise = fn -> raise "error" end
    assert_raise RuntimeError, fn -> DiodeClient.Shell.await_all([promise]) end
  end

  test "retired Moonbeam chain id returns nil and Base is default ticket shell" do
    assert DiodeClient.shell_for_chain_id(1284) == nil
    assert DiodeClient.shell_for_chain_id(8453) == DiodeClient.Shell.Base
    assert DiodeClient.shell_for_chain_id(15) == DiodeClient.Shell
    assert DiodeClient.Manager.ticket_shell() == DiodeClient.Shell.Base
    assert DiodeClient.Manager.default_shells() == [DiodeClient.Shell.Base, DiodeClient.Shell]
    refute DiodeClient.Shell.Moonbeam in DiodeClient.shells()
    refute DiodeClient.Shell.Moonbeam in DiodeClient.Contracts.Factory.shells()
  end
end
