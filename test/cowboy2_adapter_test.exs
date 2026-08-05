defmodule DiodeClient.Cowboy2AdapterTest do
  use ExUnit.Case, async: true

  alias DiodeClient.Cowboy2Adapter
  alias DiodeClient.Transport

  @ref :cowboy2_adapter_test_ref
  @trans_opts %{num_acceptors: 1, max_connections: 16, socket_opts: [port: 80]}
  @proto_opts %{env: %{dispatch: []}}

  describe "patch_transport/1" do
    test "rewrites ranch_listener_sup (Ranch 1.x / older Plug.Cowboy) to Diode transport" do
      mfa =
        {:ranch_listener_sup, :start_link,
         [@ref, :ranch_tcp, @trans_opts, :cowboy_clear, @proto_opts]}

      assert {:ranch_listener_sup, :start_link,
              [@ref, Transport, trans_opts, :cowboy_clear, @proto_opts]} =
               Cowboy2Adapter.patch_transport(mfa)

      assert Map.get(trans_opts, :sendfile) == true
      assert Map.drop(trans_opts, [:sendfile]) == @trans_opts
    end

    test "rewrites ranch_embedded_sup (Ranch 2.x / Plug.Cowboy 2.8+) to Diode transport" do
      mfa =
        {:ranch_embedded_sup, :start_link,
         [@ref, :ranch_tcp, @trans_opts, :cowboy_clear, @proto_opts]}

      assert {:ranch_embedded_sup, :start_link,
              [@ref, Transport, trans_opts, :cowboy_clear, @proto_opts]} =
               Cowboy2Adapter.patch_transport(mfa)

      assert Map.get(trans_opts, :sendfile) == true
      assert Map.drop(trans_opts, [:sendfile]) == @trans_opts
    end

    test "preserves sendfile true when already set on transport opts" do
      opts = Map.put(@trans_opts, :sendfile, true)
      mfa = {:ranch_embedded_sup, :start_link, [@ref, :ranch_ssl, opts, :cowboy_tls, @proto_opts]}

      assert {:ranch_embedded_sup, :start_link,
              [@ref, Transport, ^opts, :cowboy_tls, @proto_opts]} =
               Cowboy2Adapter.patch_transport(mfa)
    end

    test "raises FunctionClauseError for unexpected MFA (does not silently drop starts)" do
      bad = List.to_tuple([:unknown_sup, :start_link, [@ref]])

      assert_raise FunctionClauseError, fn ->
        Cowboy2Adapter.patch_transport(bad)
      end
    end
  end
end
