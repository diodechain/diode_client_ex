defmodule DiodeClient.Manager.ChainPeaksTest do
  use ExUnit.Case, async: true

  alias DiodeClient.Manager.ChainPeaks
  alias DiodeClient.Manager.Info
  alias DiodeClient.Rlpx

  @shell DiodeClient.Shell.Moonbeam
  @opts [min_connections: 3]

  defp block(n) do
    %{"number" => Rlpx.uint2bin(n), "block_hash" => :crypto.hash(:sha256, <<n>>)}
  end

  defp info(n) do
    %Info{
      server_address: <<0::160>>,
      peaks: %{@shell => block(n)}
    }
  end

  describe "consensus_peak_for_shell/5" do
    test "strict majority promotes to highest height" do
      connected = for n <- [101, 101, 101, 100, 100], do: info(n)
      last = block(100)

      {peak, _} =
        ChainPeaks.consensus_peak_for_shell(@shell, connected, last, %{}, @opts)

      assert Rlpx.bin2uint(peak["number"]) == 101
    end

    test "minority ahead waits for majority" do
      connected = for n <- [101, 101, 100, 100, 100], do: info(n)
      last = block(100)

      {peak, _} =
        ChainPeaks.consensus_peak_for_shell(@shell, connected, last, %{}, @opts)

      assert Rlpx.bin2uint(peak["number"]) == 100
    end

    test "gross stale nodes are trimmed before majority" do
      connected = for n <- [1000, 1000, 1000, 10, 10], do: info(n)
      last = block(900)

      {peak, _} =
        ChainPeaks.consensus_peak_for_shell(@shell, connected, last, %{}, @opts)

      assert Rlpx.bin2uint(peak["number"]) == 1000
    end

    test "per-shell connected ignores other shells" do
      conns = %{
        :stale => %Info{
          server_address: <<1::160>>,
          peaks: %{@shell => block(50), DiodeClient.Shell => block(100)}
        },
        :a => %Info{
          server_address: <<2::160>>,
          peaks: %{@shell => block(100), DiodeClient.Shell => block(100)}
        },
        :b => %Info{
          server_address: <<3::160>>,
          peaks: %{@shell => block(100), DiodeClient.Shell => block(100)}
        }
      }

      chain_peaks = %{@shell => block(100), DiodeClient.Shell => block(100)}

      connected =
        ChainPeaks.connected_for_shell(@shell, conns, chain_peaks, 2)

      assert map_size(connected) == 2
      refute Map.has_key?(connected, :stale)
    end
  end
end
