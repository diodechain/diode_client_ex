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

  def epoch(block) do
    if diode?(block) do
      div(number(block), 40_320)
    else
      div(timestamp(block), 2_592_000)
    end
  end

  def diode?(block) do
    miner_signature(block) not in [nil, ""]
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

  def nano_timestamp(block) do
    DiodeClient.Rlpx.bin2uint(block["timestamp"]) * 1_000_000_000
  end

  def transaction_hash(block) do
    block["transaction_hash"]
  end
end
