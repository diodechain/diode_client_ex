defmodule DiodeClient.Manager.ChainPeaks do
  @moduledoc false
  alias DiodeClient.{Base16, Manager.Info, Rlpx}

  @default_stale_threshold 64
  @moonbeam_stale_threshold 128
  @diode_stale_threshold 64

  @doc """
  Returns authenticated connections at or above the reported peak for `shell` only.
  """
  def connected_for_shell(shell, conns, chain_peaks, min_connections) do
    reported = block_number(Map.get(chain_peaks, shell))

    connected =
      conns
      |> Enum.filter(fn {_pid, %Info{server_address: addr, peaks: conn_peaks}} ->
        addr != nil and block_number(Map.get(conn_peaks, shell)) >= reported
      end)
      |> Map.new()

    if map_size(connected) < min_connections, do: %{}, else: connected
  end

  @doc """
  Computes the consensus peak block for one shell using strict majority at the leading height.
  """
  def consensus_peak_for_shell(
        shell,
        connected_infos,
        last_peak,
        last_reported_uncle_block,
        opts
      ) do
    min_connections = Keyword.fetch!(opts, :min_connections)
    len = length(connected_infos)

    if len < min_connections do
      {last_peak, last_reported_uncle_block}
    else
      do_consensus_peak_for_shell(
        shell,
        connected_infos,
        last_peak,
        last_reported_uncle_block
      )
    end
  end

  defp do_consensus_peak_for_shell(
         shell,
         connected_infos,
         last_peak,
         last_reported_uncle_block
       ) do
    last_peak_num = block_number(last_peak)

    blocks_with_num =
      connected_infos
      |> Enum.map(fn %Info{peaks: peaks} -> Map.get(peaks, shell) end)
      |> Enum.reject(&is_nil/1)
      |> Enum.map(fn block -> {block, block_number(block)} end)

    case blocks_with_num do
      [] ->
        {last_peak, last_reported_uncle_block}

      _ ->
        max_num = blocks_with_num |> Enum.map(&elem(&1, 1)) |> Enum.max()
        threshold = stale_threshold(shell)

        trimmed =
          Enum.filter(blocks_with_num, fn {_, num} -> max_num - num <= threshold end)

        majority = div(length(trimmed), 2) + 1
        heights = trimmed |> Enum.map(&elem(&1, 1)) |> Enum.uniq() |> Enum.sort(:desc)

        {peak, uncle_reported} =
          Enum.reduce_while(heights, {last_peak, last_reported_uncle_block}, fn height,
                                                                                {acc, reported} ->
            blocks_at_height =
              trimmed
              |> Enum.filter(fn {_, num} -> num == height end)
              |> Enum.map(&elem(&1, 0))

            candidates = group_by_hash(blocks_at_height)

            reported =
              if map_size(candidates) > 1 and Map.get(reported, shell) != height do
                require Logger

                Logger.debug(
                  "Multiple uncle blocks with the same block_number=#{height} found for shell #{inspect(shell)}"
                )

                Map.put(reported, shell, height)
              else
                reported
              end

            case resolve_peak_from_candidates(candidates) do
              {agreement, block} ->
                if length(agreement) >= majority and height > last_peak_num do
                  {:halt, {block, reported}}
                else
                  {:cont, {acc, reported}}
                end

              nil ->
                {:cont, {acc, reported}}
            end
          end)

        {peak, uncle_reported}
    end
  end

  defp group_by_hash(blocks) do
    hash_cache = Map.new(Enum.uniq(blocks), fn block -> {block, block_hash(block)} end)

    Enum.group_by(blocks, fn block -> Map.fetch!(hash_cache, block) end)
  end

  defp resolve_peak_from_candidates(candidates) do
    case Enum.sort_by(candidates, fn {_hash, blocks} -> length(blocks) end, :desc) do
      [{_hash, agreement = [block | _]}] ->
        {agreement, block}

      [{_hash, agreement = [block | _]}, {_challenger_hash, challenger} | _rest] ->
        if length(agreement) > length(challenger) do
          {agreement, block}
        else
          nil
        end

      _ ->
        nil
    end
  end

  def stale_threshold(DiodeClient.Shell.Moonbeam), do: @moonbeam_stale_threshold
  def stale_threshold(DiodeClient.Shell), do: @diode_stale_threshold
  def stale_threshold(_shell), do: @default_stale_threshold

  defp block_number(nil), do: 0
  defp block_number(block), do: Rlpx.bin2uint(block["number"])

  defp block_hash(nil), do: nil
  defp block_hash(block), do: Base16.encode(block["block_hash"])
end
