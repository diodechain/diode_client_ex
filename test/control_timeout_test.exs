defmodule DiodeClientControlTimeoutTest do
  use ExUnit.Case, async: false

  alias DiodeClient.{Control, Port}

  defmodule Hang do
    use GenServer
    def start_link(_), do: GenServer.start_link(__MODULE__, nil)
    def init(nil), do: {:ok, nil}
    def handle_call(_msg, _from, state), do: {:noreply, state}
  end

  test "resolve_local honors a short timeout" do
    peer = :crypto.strong_rand_bytes(20)
    {:ok, pid} = Hang.start_link(nil)
    :yes = :global.register_name({Control, peer}, pid)

    {usec, result} =
      :timer.tc(fn ->
        Control.resolve_local(peer, 3000, 100)
      end)

    assert result == nil
    assert usec < 1_000_000
  end

  test "Port.connect with timeout: 0 returns timeout at once" do
    dest = :crypto.strong_rand_bytes(20)
    assert {:error, :timeout} = Port.connect(dest, 3000, [timeout: 0], 0)
  end

  test "Port.connect honors timeout: 100 when Control never replies" do
    peer = :crypto.strong_rand_bytes(20)
    {:ok, pid} = Hang.start_link(nil)
    :yes = :global.register_name({Control, peer}, pid)

    {usec, result} =
      :timer.tc(fn ->
        Port.connect(peer, 3000, timeout: 100)
      end)

    assert result == {:error, "not found"} or result == {:error, :timeout}
    assert usec < 1_000_000
  end

  test "Port.connect uses half the budget for resolve_local then tries relay" do
    peer = :crypto.strong_rand_bytes(20)
    {:ok, pid} = Hang.start_link(nil)
    :yes = :global.register_name({Control, peer}, pid)

    {usec, result} =
      :timer.tc(fn ->
        Port.connect(peer, 3000, timeout: 400)
      end)

    # Half of 400ms is spent on resolve_local, then relay sees no ticket.
    assert result == {:error, "not found"}
    assert usec < 2_000_000
  end

  test "Port.connect with only_local: true does not fall back to relay" do
    peer = :crypto.strong_rand_bytes(20)
    {:ok, pid} = Hang.start_link(nil)
    :yes = :global.register_name({Control, peer}, pid)

    {usec, result} =
      :timer.tc(fn ->
        Port.connect(peer, 3000, only_local: true, timeout: 100)
      end)

    assert result == {:error, "local connection not found"}
    assert usec < 1_000_000
  end
end
