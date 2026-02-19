defmodule DiodeClientShellAnvilTest do
  @moduledoc """
  Tests for DiodeClient.Shell.Anvil. Integration tests (tagged :anvil) require
  a running Anvil instance at ANVIL_RPC_URL (default http://127.0.0.1:8545).
  Run `anvil` in another terminal, then: mix test test/shell_anvil_test.exs
  """
  use ExUnit.Case, async: false
  @moduletag timeout: 10_000

  alias DiodeClient.Shell.Anvil
  alias DiodeClient.Wallet
  alias DiodeClient.Hash
  alias DiodeClient.Contracts.Factory
  alias DiodeClient.Contracts.BNS

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
      assert cid in [31_337, String.to_integer(System.get_env("ANVIL_CHAIN_ID") || "31337")]
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

  test "BNS is deployed" do
    assert {:ok, _} = DiodeClient.Anvil.Helper.deploy_contracts()
    assert {["ok", _tx_hash], _tx} = BNS.register("anviltest.anvil", DiodeClient.address())
    assert DiodeClient.address() == BNS.resolve_name("anviltest.anvil")
    assert BNS.is_bns(Factory.contracts(Anvil).bns)
  end

  test "get_account returns Account struct" do
    assert {:ok, _} = DiodeClient.Anvil.Helper.deploy_contracts()
    assert {["ok", _tx_hash], _tx} = BNS.register("anviltest2.anvil", DiodeClient.address())
    account = Anvil.get_account(DiodeClient.address())
    assert account.nonce > 0
    assert account.balance > 0
    assert account.code_hash == DiodeClient.Hash.keccak_256("")
    assert account.storage_root == Anvil.get_account_root(DiodeClient.address())
    assert account.storage_root == Anvil.get_account_root(Wallet.address!(Wallet.new()))
    assert account.storage_root == nil

    contract = Anvil.get_account(Factory.contracts(Anvil).bns)
    assert byte_size(contract.code_hash) == 32
    assert byte_size(contract.storage_root) == 32
  end

  test "identity salt" do
    assert {:ok, _} = DiodeClient.Anvil.Helper.deploy_contracts()

    shell = DiodeClient.Shell.Anvil
    c = Factory.contracts(shell)
    identity = Hash.create2(c.factory, c.proxy_code_hash, Factory.identity_salt(shell))

    real_identity =
      shell.call(c.factory, "Create2Address", ["bytes32"], [Factory.identity_salt(shell)],
        result_types: "address"
      )

    assert identity == real_identity
  end

  describe "Anvil process death" do
    @tag :anvil
    test "when anvil dies, anvil_reachable? is false" do
      # Start a fresh Anvil on a distinct port so we don't kill the shared one
      port_num = 28_546
      rpc_url = "http://127.0.0.1:#{port_num}"
      assert {:ok, port} = DiodeClient.Anvil.Helper.start_anvil(port: port_num, rpc_url: rpc_url)

      assert DiodeClient.Anvil.Helper.anvil_reachable?(rpc_url) == true

      # Artificially kill the anvil process (simulates crash or external kill)
      DiodeClient.Anvil.Helper.stop_anvil(port)

      # Allow process to fully terminate before checking reachability
      Process.sleep(300)

      assert DiodeClient.Anvil.Helper.anvil_reachable?(rpc_url) == false,
             "expected anvil to be unreachable after process kill"
    end
  end
end
