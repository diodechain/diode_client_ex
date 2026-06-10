defmodule DiodeClient.Shell.OasisSapphireTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias DiodeClient.Shell.OasisSapphire

  @identity <<0xAB::160>>

  @rpc_error %{
    "code" => -32000,
    "message" => "invalid signed simulate call query: base block not found"
  }

  describe "meta_nonce_from_call/2" do
    test "returns integer nonce unchanged" do
      assert OasisSapphire.meta_nonce_from_call(7, @identity) == 7
    end

    test "returns 0 when the identity contract reverts" do
      log =
        capture_log(fn ->
          assert OasisSapphire.meta_nonce_from_call(:revert, @identity) == 0
        end)

      assert log =~ "reverted"
    end

    test "returns {:error, reason} for transient Sapphire RPC failures" do
      log =
        capture_log(fn ->
          assert OasisSapphire.meta_nonce_from_call({:error, @rpc_error}, @identity) ==
                   {:error, @rpc_error}
        end)

      assert log =~ "get_meta_nonce: nonce lookup"
      assert log =~ "base block not found"
    end
  end

  describe "send_transaction/5 meta_transaction nonce errors" do
    test "returns {:error, _} when nonce lookup fails" do
      result =
        OasisSapphire.send_transaction(
          <<0::160>>,
          "Version",
          [],
          [],
          meta_transaction: true,
          nonce: {:error, @rpc_error},
          identity: @identity
        )

      assert {:error, @rpc_error} = result
    end
  end
end
