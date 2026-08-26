defmodule DiodeClient.Shell.OasisSapphireTest do
  use ExUnit.Case, async: true

  alias DiodeClient.Shell.OasisSapphire

  describe "signed_call_block_index/2" do
    test "uses head minus two when no block is passed" do
      assert OasisSapphire.signed_call_block_index([], 15_459_735) == 15_459_733
    end

    test "uses head minus two for latest block opt" do
      assert OasisSapphire.signed_call_block_index([block: "latest"], 15_459_735) == 15_459_733
    end

    test "ignores stale PeakBlock header far behind the live head" do
      stale = %{"number" => :binary.encode_unsigned(15_459_680, :big)}

      assert OasisSapphire.signed_call_block_index([block: stale], 15_459_735) == 15_459_733
    end

    test "accepts a recent block header within the leash range" do
      recent = %{"number" => :binary.encode_unsigned(15_459_730, :big)}

      assert OasisSapphire.signed_call_block_index([block: recent], 15_459_735) == 15_459_730
    end

    test "caps an integer block at head minus two" do
      assert OasisSapphire.signed_call_block_index([block: 99_999_999], 15_459_735) == 15_459_733
    end

    test "uses head minus two when integer block is too stale" do
      assert OasisSapphire.signed_call_block_index([block: 15_459_680], 15_459_735) == 15_459_733
    end
  end
end
