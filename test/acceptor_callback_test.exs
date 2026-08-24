defmodule DiodeClientAcceptorCallbackTest do
  use ExUnit.Case, async: false

  alias DiodeClient.{Acceptor, Manager, Port}

  setup do
    if Process.whereis(Manager) == nil do
      assert {:ok, _} = DiodeClient.interface_add("acceptor_callback_test", DiodeClient.Sup)
    end

    Manager.await()
    :ok
  end

  test "callback listen starts a LocalAcceptor" do
    portnum = 31_000 + :rand.uniform(1000)
    {:ok, listener} = Port.listen(portnum, callback: fn _sock -> :ok end)

    local =
      Enum.find_value(1..50, fn _ ->
        case Acceptor.local_port(portnum) do
          {_, port} when is_integer(port) ->
            port

          port when is_integer(port) ->
            port

          _ ->
            Process.sleep(20)
            nil
        end
      end)

    assert is_integer(local)
    Port.close(listener)
  end

  test "callback listen with local: false does not start a LocalAcceptor" do
    portnum = 32_000 + :rand.uniform(1000)
    {:ok, listener} = Port.listen(portnum, callback: fn _sock -> :ok end, local: false)
    Process.sleep(50)
    assert Acceptor.local_port(portnum) == nil
    Port.close(listener)
  end
end
