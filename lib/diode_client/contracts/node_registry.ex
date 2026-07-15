defmodule DiodeClient.Contracts.NodeRegistry do
  @moduledoc """
  This module is used to create and manage the node registry contract.
  The node registry is used to register and manage nodes.
  """
  alias DiodeClient.{Base16}

  @address Base16.decode("0xc4b466f63c0A31302Bc8A688A7c90e1199Bb6f84")
  @shell DiodeClient.Shell.Moonbeam

  # Do post-freeze
  # @address Base16.decode("0xBC7a66a80E760dD0D84f6e39Df6cfD937C6c94F6")
  # @shell DiodeClient.Shell.Base

  def version(block \\ nil) do
    DiodeClient.Contracts.Utils.call(@shell, @address, "version", [], [], "uint256", block)
  end

  def nodes(block \\ nil) do
    DiodeClient.Contracts.Utils.call(@shell, @address, "getNodes", [], [], "address[]", block)
  end

  def nodes_above(min_stake, block \\ nil) do
    DiodeClient.Contracts.Utils.call(
      @shell,
      @address,
      "getNodesAbove",
      ["uint256"],
      [min_stake],
      "address[]",
      block
    )
  end

  def node(address, block \\ nil) do
    # struct Node {
    #   address accountant;
    #   address nodeAddress;
    #   uint256 stake;

    [accountant, node_address, stake] =
      DiodeClient.Contracts.Utils.call(
        @shell,
        @address,
        "nodes",
        ["address"],
        [address],
        "(address,address,uint256)",
        block
      )

    %{accountant: accountant, node_address: node_address, stake: stake}
  end
end
