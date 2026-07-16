defmodule DiodeClient.ConnectionRpcTest do
  @moduledoc """
  Unit tests for Connection.rpc disconnect handling and Shell.rpc_retriable.

  Uses stub GenServers that speak the Connection RPC reply protocol so we can
  kill a "connection" process without a live relay.
  """
  use ExUnit.Case, async: true
  @moduletag timeout: 5_000

  alias DiodeClient.{Connection, Shell}

  defmodule StubConn do
    @moduledoc false
    use GenServer

    # Unlinked so Process.exit(..., :kill) does not take down the test process.
    def start(opts), do: GenServer.start(__MODULE__, opts)

    @impl true
    def init(opts), do: {:ok, Map.new(opts)}

    @impl true
    def handle_call({:rpc, _cmd, _req, _rlp, _time, _pid}, _from, state = %{die: true}) do
      {:stop, :normal, state}
    end

    def handle_call({:rpc, _cmd, req, _rlp, _time, _pid}, _from, state = %{reply: rest}) do
      {:reply, [req, ["response" | List.wrap(rest)]], state}
    end

    def handle_call({:rpc, _cmd, req, _rlp, _time, _pid}, _from, state = %{error: reason}) do
      {:reply, [req, ["error", reason]], state}
    end

    def handle_call({:rpc, _cmd, _req, _rlp, _time, _pid}, from, state = %{hang: true}) do
      if notify = state[:notify], do: send(notify, :rpc_accepted)
      {:noreply, Map.put(state, :from, from)}
    end
  end

  describe "Connection.rpc on dead connection" do
    test "returns remote_closed when connection process is already gone (noproc)" do
      {:ok, pid} = Agent.start(fn -> :ok end)
      ref = Process.monitor(pid)
      Process.exit(pid, :kill)
      assert_receive {:DOWN, ^ref, :process, ^pid, :killed}

      assert Connection.rpc(pid, ["getblockpeak"]) == {:error, "remote_closed"}
    end

    test "returns remote_closed when connection stops during the call (normal)" do
      {:ok, pid} = StubConn.start(die: true)
      assert Connection.rpc(pid, ["getblockpeak"]) == {:error, "remote_closed"}
    end

    test "returns remote_closed when connection is killed mid-call" do
      {:ok, pid} = StubConn.start(hang: true, notify: self())
      parent = self()

      spawn(fn ->
        send(parent, {:rpc_result, Connection.rpc(pid, ["getblockpeak"])})
      end)

      assert_receive :rpc_accepted, 1_000

      ref = Process.monitor(pid)
      Process.exit(pid, :kill)
      assert_receive {:DOWN, ^ref, :process, ^pid, :killed}
      assert_receive {:rpc_result, {:error, "remote_closed"}}, 1_000
    end

    test "returns remote_closed when connection reports remote_closed" do
      {:ok, pid} = StubConn.start(error: "remote_closed")
      assert Connection.rpc(pid, ["getblockpeak"]) == {:error, "remote_closed"}
    end

    test "returns successful response from live stub" do
      {:ok, pid} = StubConn.start(reply: ["ok"])
      assert Connection.rpc(pid, ["getblockpeak"]) == ["ok"]
    end
  end

  describe "Shell.rpc_retriable" do
    test "retries on another connection after the first is killed mid-call" do
      {:ok, bad} = StubConn.start(hang: true, notify: self())
      {:ok, good} = StubConn.start(reply: ["retried"])

      attempts = :atomics.new(1, signed: false)
      parent = self()

      get_conn = fn ->
        case :atomics.add_get(attempts, 1, 1) do
          1 -> bad
          _ -> good
        end
      end

      spawn(fn ->
        send(parent, {:retry_result, Shell.rpc_retriable(["getblockpeak"], get_conn)})
      end)

      assert_receive :rpc_accepted, 1_000
      ref = Process.monitor(bad)
      Process.exit(bad, :kill)
      assert_receive {:DOWN, ^ref, :process, ^bad, :killed}

      assert_receive {:retry_result, ["retried"]}, 1_000
      assert :atomics.get(attempts, 1) == 2
    end

    test "retries on another connection when the first stops without reply" do
      {:ok, bad} = StubConn.start(die: true)
      {:ok, good} = StubConn.start(reply: ["from-good"])

      attempts = :atomics.new(1, signed: false)

      get_conn = fn ->
        case :atomics.add_get(attempts, 1, 1) do
          1 -> bad
          _ -> good
        end
      end

      assert Shell.rpc_retriable(["getaccount", 1, <<0::160>>], get_conn) == ["from-good"]
      assert :atomics.get(attempts, 1) == 2
    end

    test "await_all does not raise when a killed connection is retried successfully" do
      {:ok, bad} = StubConn.start(die: true)
      {:ok, good} = StubConn.start(reply: ["ok"])

      attempts = :atomics.new(1, signed: false)

      get_conn = fn ->
        case :atomics.add_get(attempts, 1, 1) do
          1 -> bad
          _ -> good
        end
      end

      assert Shell.await_all([fn -> Shell.rpc_retriable(["ping"], get_conn) end]) == [["ok"]]
    end
  end
end
