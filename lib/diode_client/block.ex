defmodule DiodeClient.Block do
  @moduledoc """
  Block related helper functions
  """
  def number(block_number) when is_integer(block_number) do
    block_number
  end

  def number(block) when is_map(block) or is_list(block) do
    DiodeClient.Rlpx.bin2uint(block["number"])
  end

  def hash(block) when is_map(block) or is_list(block) do
    DiodeClient.Rlpx.bin2uint(block["block_hash"])
  end

  def epoch(block) when is_map(block) or is_list(block) do
    if diode?(block) do
      div(number(block), 40_320)
    else
      div(timestamp(block), 2_592_000)
    end
  end

  def diode?(block) when is_map(block) or is_list(block) do
    miner_signature(block) not in [nil, ""]
  end

  def miner_signature(block) when is_map(block) or is_list(block) do
    block["miner_signature"]
  end

  def nonce(block) when is_map(block) or is_list(block) do
    block["nonce"]
  end

  def previous_block(block) when is_map(block) or is_list(block) do
    block["previous_block"]
  end

  def state_hash(block) when is_map(block) or is_list(block) do
    block["state_hash"]
  end

  def timestamp(block) when is_map(block) or is_list(block) do
    DiodeClient.Rlpx.bin2uint(block["timestamp"])
  end

  def nano_timestamp(block) when is_map(block) or is_list(block) do
    DiodeClient.Rlpx.bin2uint(block["timestamp"]) * 1_000_000_000
  end

  def transaction_hash(block) when is_map(block) or is_list(block) do
    block["transaction_hash"]
  end
end
