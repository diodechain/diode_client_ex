defmodule DiodeClientShellAnvilTest do
  @moduledoc """
  Tests for DiodeClient.Shell.Anvil. Integration tests (tagged :anvil) require
  a running Anvil instance at ANVIL_RPC_URL (default http://127.0.0.1:8545).
  Run `anvil` in another terminal, then: mix test test/shell_anvil_test.exs
  """
  use ExUnit.Case, async: false
  @moduletag timeout: 10_000

  alias DiodeClient.Shell.Anvil
  alias DiodeClient.Contracts.Factory

  describe "default config" do
    @tag :anvil_config
    test "rpc_url default when ANVIL_RPC_URL unset" do
      # Cannot unset env in another process; test default by checking module
      assert Anvil.rpc_url() in [
               "http://127.0.0.1:8545",
               System.get_env("ANVIL_RPC_URL") || "http://127.0.0.1:8545"
             ]
    end

    @tag :anvil_config
    test "chain_id default when ANVIL_CHAIN_ID unset" do
      # Default Anvil chain id is 31337
      cid = Anvil.chain_id()
      assert is_integer(cid)
      assert cid in [31337, String.to_integer(System.get_env("ANVIL_CHAIN_ID") || "31337")]
    end

    @tag :anvil_config
    test "prefix is empty" do
      assert Anvil.prefix() == ""
    end

    @tag :anvil_config
    test "default_gas_limit" do
      assert Anvil.default_gas_limit() == 10_000_000
    end
  end

  describe "Anvil integration" do
    @tag :anvil
    test "peak returns a block map with expected keys" do
      block = Anvil.peak()
      assert is_map(block)
      assert Map.has_key?(block, "number")
      assert Map.has_key?(block, "block_hash")
      assert Map.has_key?(block, "timestamp")
    end

    @tag :anvil
    test "get_account for first Anvil account returns Account struct" do
      # Well-known first Anvil account
      addr = DiodeClient.Base16.decode("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
      account = Anvil.get_account(addr)
      assert %DiodeClient.Account{} = account
      assert is_integer(account.nonce)
      assert is_integer(account.balance)
    end

    @tag :anvil
    test "gas_price returns integer or nil" do
      result = DiodeClient.Shell.Common.gas_price(Anvil)
      assert result == nil or (is_integer(result) and result >= 0)
    end

    @tag :anvil
    test "get_block_header returns block map for latest" do
      peak = Anvil.peak()
      block_num = DiodeClient.Block.number(peak)
      header = Anvil.get_block_header(block_num)
      assert is_map(header)
      assert Map.get(header, "number") != nil
    end
  end

  describe "Factory Anvil contracts" do
    @tag :anvil
    @tag :anvil_contracts
    test "contracts(Anvil) raises when not set" do
      # Clear any previously set contracts so we test the raise
      try do
        :persistent_term.erase({DiodeClient.Contracts.Factory, :anvil_contracts})
      rescue
        _ -> :ok
      end

      assert_raise RuntimeError, ~r/Anvil contracts not deployed/, fn ->
        Factory.contracts(Anvil)
      end
    end

    @tag :anvil
    @tag :anvil_contracts
    test "set_anvil_contracts and get_anvil_contracts" do
      # Build a minimal list for testing (addresses are dummy)
      list = %DiodeClient.Contracts.List{
        bns: <<0::160>>,
        bns_postfix: "anvil",
        drive_invites: <<0::160>>,
        drive_member_version: 114,
        drive_member: <<0::160>>,
        drive_version: 159,
        drive: <<0::160>>,
        factory: <<0::160>>,
        fleet_member: <<0::160>>,
        proxy_code_hash: <<0::256>>
      }

      Factory.set_anvil_contracts(list)
      assert Factory.get_anvil_contracts() == list
      assert Factory.contracts(Anvil) == list
    end
  end

end
