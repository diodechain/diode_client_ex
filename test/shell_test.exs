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
end
