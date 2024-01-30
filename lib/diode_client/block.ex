defmodule DiodeClient.Block do
  @moduledoc """
  Block related helper functions
  """
  def number(block) do
    DiodeClient.Rlpx.bin2uint(block["number"])
  end

  def hash(block) do
    DiodeClient.Rlpx.bin2uint(block["block_hash"])
  end

  def miner_signature(block) do
    block["miner_signature"]
  end

  def nonce(block) do
    block["nonce"]
  end

  def previous_block(block) do
    block["previous_block"]
  end

  def state_hash(block) do
    block["state_hash"]
  end

  def timestamp(block) do
    DiodeClient.Rlpx.bin2uint(block["timestamp"])
  end

  def transaction_hash(block) do
    block["transaction_hash"]
  end
end
