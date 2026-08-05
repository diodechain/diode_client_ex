defmodule DiodeClient.Cowboy2AdapterTest do
  use ExUnit.Case, async: true

  alias DiodeClient.Cowboy2Adapter
  alias DiodeClient.Transport

  @ref :cowboy2_adapter_test_ref
  @trans_opts %{num_acceptors: 1, max_connections: 16, socket_opts: [port: 80]}
  @proto_opts %{env: %{dispatch: []}}

  describe "patch_transport/1" do
    for sup <- [:ranch_listener_sup, :ranch_embedded_sup] do
      test "rewrites #{sup} transport MFA to Diode transport with sendfile" do
        sup = unquote(sup)

        mfa =
          {sup, :start_link, [@ref, :ranch_tcp, @trans_opts, :cowboy_clear, @proto_opts]}

        assert {^sup, :start_link, [@ref, Transport, trans_opts, :cowboy_clear, @proto_opts]} =
                 Cowboy2Adapter.patch_transport(mfa)

        assert Map.get(trans_opts, :sendfile) == true
        assert Map.drop(trans_opts, [:sendfile]) == @trans_opts
      end
    end

    test "raises FunctionClauseError for unexpected MFA (does not silently drop starts)" do
      bad = {:unknown_sup, :start_link, [@ref]}

      assert_raise FunctionClauseError, fn ->
        apply(Cowboy2Adapter, :patch_transport, [bad])
      end
    end
  end
end
