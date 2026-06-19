defmodule DiodeClient.Contracts.Registry do
  @moduledoc """
  Read-only accessors for the Moonbeam `DiodeRegistryLight` contract.

  Uses on-chain view calls only (no direct storage reads).
  """
  alias DiodeClient.{Base16, Contracts.Utils}

  @address Base16.decode("0xD78653669fd3df4dF8F3141Ffa53462121d117a4")
  @shell DiodeClient.Shell.Moonbeam

  @seconds_per_epoch 2_592_000

  def address(), do: @address
  def shell(), do: @shell
  def seconds_per_epoch(), do: @seconds_per_epoch

  def version(block \\ nil) do
    Utils.call(@shell, @address, "Version", [], [], "uint256", block)
  end

  def epoch(block \\ nil) do
    Utils.call(@shell, @address, "Epoch", [], [], "uint256", block)
  end

  def current_epoch(block \\ nil) do
    Utils.call(@shell, @address, "currentEpoch", [], [], "uint256", block)
  end

  def epoch_sync_needed?(block \\ nil) do
    epoch(block) != current_epoch(block)
  end

  def token(block \\ nil) do
    Utils.call(@shell, @address, "Token", [], [], "address", block)
  end

  def fleet_array(block \\ nil) do
    Utils.call(@shell, @address, "FleetArray", [], [], "address[]", block)
  end

  def relay_array(block \\ nil) do
    Utils.call(@shell, @address, "RelayArray", [], [], "address[]", block)
  end

  def get_fleet(fleet, block \\ nil) when is_binary(fleet) do
    [exists, current_balance, withdraw_request_size, withdrawable_balance, current_epoch, score] =
      Utils.call(
        @shell,
        @address,
        "GetFleet",
        ["address"],
        [fleet],
        "(bool,uint256,uint256,uint256,uint256,uint256)",
        block
      )

    %{
      exists: exists in [1, true],
      current_balance: current_balance,
      withdraw_request_size: withdraw_request_size,
      withdrawable_balance: withdrawable_balance,
      current_epoch: current_epoch,
      score: score
    }
  end

  def get_node(fleet, node, block \\ nil)
      when is_binary(fleet) and is_binary(node) do
    [node_address, score] =
      Utils.call(
        @shell,
        @address,
        "GetNode",
        ["address", "address"],
        [fleet, node],
        "(address,uint256)",
        block
      )

    %{node: node_address, score: score}
  end
end
