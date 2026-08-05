defmodule DiodeClient.TransportTest do
  use ExUnit.Case, async: true

  alias DiodeClient.Transport

  describe "listen_port/1" do
    test "reads port from keyword list (Ranch 1 / legacy callers)" do
      assert Transport.listen_port(port: 80, backlog: 1024) == 80
    end

    test "reads port from Ranch 2 transport opts map socket_opts" do
      opts = %{
        num_acceptors: 3,
        max_connections: 16_384,
        sendfile: true,
        socket_opts: [port: 80, nodelay: true]
      }

      assert Transport.listen_port(opts) == 80
    end

    test "prefers top-level :port on map when present" do
      assert Transport.listen_port(%{port: 443, socket_opts: [port: 80]}) == 443
    end

    test "raises when port is missing from keyword list" do
      assert_raise KeyError, fn -> Transport.listen_port([]) end
    end

    test "raises when port is missing from map socket_opts" do
      assert_raise KeyError, fn ->
        Transport.listen_port(%{num_acceptors: 1, socket_opts: [nodelay: true]})
      end
    end
  end
end
