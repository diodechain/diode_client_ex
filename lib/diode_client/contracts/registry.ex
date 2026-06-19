defmodule DiodeClient.Contracts.Registry do
  @moduledoc """
  Read-only accessors for the Moonbeam `DiodeRegistryLight` contract.

  Uses on-chain view calls only (no direct storage reads).

  `seconds_per_epoch/0` returns a fixed protocol constant (30 days), not a value
  read from the contract.
  """
  alias DiodeClient.{Base16, Contracts.Utils}

  @address Base16.decode("0xD78653669fd3df4dF8F3141Ffa53462121d117a4")
  @shell DiodeClient.Shell.Moonbeam

  @seconds_per_epoch 2_592_000

  @doc """
  Returns the `DiodeRegistryLight` contract address on Moonbeam.
  """
  def address(), do: @address

  @doc """
  Returns the shell used for registry view calls (`DiodeClient.Shell.Moonbeam`).
  """
  def shell(), do: @shell

  @doc """
  Returns the protocol constant for seconds per epoch (30 days, `2_592_000`).

  This value is not queried on-chain; the contract does not expose an accessor for it.
  """
  def seconds_per_epoch(), do: @seconds_per_epoch

  @doc """
  Returns the on-chain registry version.

  Optional `block` selects the block for the view call (defaults to latest).
  """
  def version(block \\ nil) do
    Utils.call(@shell, @address, "Version", [], [], "uint256", block)
  end

  @doc """
  Returns the epoch computed from the current block timestamp.

  Optional `block` selects the block for the view call (defaults to latest).
  """
  def epoch(block \\ nil) do
    Utils.call(@shell, @address, "Epoch", [], [], "uint256", block)
  end

  @doc """
  Returns the epoch stored in contract state.

  Optional `block` selects the block for the view call (defaults to latest).
  """
  def current_epoch(block \\ nil) do
    Utils.call(@shell, @address, "currentEpoch", [], [], "uint256", block)
  end

  @doc """
  Returns whether the computed epoch differs from the stored epoch.

  When `true`, an epoch sync transaction is needed on-chain.

  Optional `block` selects the block for the view call (defaults to latest).
  """
  def epoch_sync_needed?(block \\ nil) do
    epoch(block) != current_epoch(block)
  end

  @doc """
  Returns the DIODE token contract address used by the registry.

  Optional `block` selects the block for the view call (defaults to latest).
  """
  def token(block \\ nil) do
    Utils.call(@shell, @address, "Token", [], [], "address", block)
  end

  @doc """
  Returns the list of registered fleet contract addresses.

  Optional `block` selects the block for the view call (defaults to latest).
  """
  def fleet_array(block \\ nil) do
    Utils.call(@shell, @address, "FleetArray", [], [], "address[]", block)
  end

  @doc """
  Returns the list of registered relay addresses.

  Optional `block` selects the block for the view call (defaults to latest).
  """
  def relay_array(block \\ nil) do
    Utils.call(@shell, @address, "RelayArray", [], [], "address[]", block)
  end

  @doc """
  Returns fleet state for the given fleet address.

  Returns a map with:

    * `:exists` - whether the fleet is registered
    * `:current_balance` - fleet balance in wei
    * `:withdraw_request_size` - pending withdraw request size
    * `:withdrawable_balance` - balance available to withdraw
    * `:current_epoch` - fleet's stored epoch
    * `:score` - fleet score

  Optional `block` selects the block for the view call (defaults to latest).
  """
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
      exists: normalize_exists(exists),
      current_balance: current_balance,
      withdraw_request_size: withdraw_request_size,
      withdrawable_balance: withdrawable_balance,
      current_epoch: current_epoch,
      score: score
    }
  end

  @doc """
  Returns node state for the given fleet and node addresses.

  Returns a map with:

    * `:node` - the node's on-chain address
    * `:score` - the node's score

  Optional `block` selects the block for the view call (defaults to latest).
  """
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

  @doc false
  def normalize_exists(value), do: value in [1, true]
end
