defmodule DiodeClient.ManagerBestChangeTest do
  @moduledoc """
  Exercises sticky `best` and reported-peak alignment in `Manager.update/1`.

  The log compares PID lists, not URLs. These tests cover:
  - **Stable**: no repeated logs when peaks and PIDs stay stable.
  - **PID swap**: same URL, different connection PID (reconnect).
  - **Sticky best**: viable best kept when connected quorum flickers.
  - **Reported peaks**: physical consensus ahead of best does not clear best.
  """
  use ExUnit.Case, async: true

  alias DiodeClient.Manager
  alias DiodeClient.Manager.Info
  alias DiodeClient.Rlpx

  @shells [DiodeClient.Shell.Moonbeam, DiodeClient.Shell]
  @eu1_url "eu1.prenet.diode.io"
  @us1_url "us1.prenet.diode.io"
  @as1_url "as1.prenet.diode.io"

  defp block(n) do
    %{"number" => Rlpx.uint2bin(n), "block_hash" => :crypto.hash(:sha256, <<n>>)}
  end

  defp peaks(n), do: Map.new(@shells, fn shell -> {shell, block(n)} end)

  defp spawn_conn_holder(), do: spawn_link(fn -> Process.sleep(:infinity) end)

  defp info(url, pid, height, latency) do
    %Info{
      server_url: url,
      server_address: <<0::160>>,
      pid: pid,
      key: String.to_atom(url),
      latency: latency,
      peaks: peaks(height),
      type: :seed
    }
  end

  defp base_state(conns, opts) do
    height = Keyword.get(opts, :height, 100)

    %Manager{
      conns: conns,
      shells: MapSet.new(@shells),
      physical_peaks: peaks(height),
      peaks: peaks(height),
      best: Keyword.get(opts, :best, []),
      best_timestamp: Keyword.get(opts, :best_timestamp, System.os_time(:second)),
      debounce_timeout: 100,
      online: true,
      server_list: %{},
      waiting: [],
      waiting_for_peak: %{},
      sticky: nil,
      peak_subscribers: %{},
      peak_subscriber_refs: %{},
      local_peak_pollers: %{}
    }
  end

  defp run_updates(state, count) do
    Enum.reduce(1..count, {state, []}, fn _, {s, acc} ->
      {s, diag} = Manager.__test_simulate_update__(s)
      {s, [diag | acc]}
    end)
    |> then(fn {final_state, diags} -> {final_state, Enum.reverse(diags)} end)
  end

  describe "best connection changed diagnostics" do
    test "stable PIDs and peaks do not repeat would_log after settling" do
      eu1 = spawn_conn_holder()
      us1 = spawn_conn_holder()
      as1 = spawn_conn_holder()

      conns = %{
        eu1 => info(@eu1_url, eu1, 100, 100),
        us1 => info(@us1_url, us1, 100, 200),
        as1 => info(@as1_url, as1, 100, 300)
      }

      state = base_state(conns, best: [eu1])
      {_final_state, diags} = run_updates(state, 10)

      assert Enum.all?(conns, fn {pid, _} -> Process.alive?(pid) end)

      log_count = Enum.count(diags, & &1.would_log)

      assert log_count <= 1,
             "expected at most one would_log with stable PIDs/peaks, got #{log_count}: #{inspect(diags)}"

      refute Enum.any?(diags, & &1.urls_unchanged_pids_changed),
             "stable scenario should not log due to same URL with different PIDs"
    end

    test "same URL with new PID (reconnect) triggers would_log with urls_unchanged_pids_changed" do
      eu1_old = spawn_conn_holder()
      eu1_new = spawn_conn_holder()
      us1 = spawn_conn_holder()
      as1 = spawn_conn_holder()

      conns = %{
        eu1_new => info(@eu1_url, eu1_new, 100, 100),
        us1 => info(@us1_url, us1, 100, 200),
        as1 => info(@as1_url, as1, 100, 300)
      }

      # Manager still references the dead connection PID (as after exit before :update).
      state = base_state(conns, best: [eu1_old])

      {_state, diag} = Manager.__test_simulate_update__(state)

      assert diag.would_log,
             "expected would_log when best PID is stale and eu1 reconnected with a new PID"

      assert diag.new_urls == [@eu1_url]
      assert hd(diag.new_best) == eu1_new
      refute hd(diag.new_best) == eu1_old

      # Stale PID is not in conns, so prev_urls is [nil]; new_urls is eu1 — same host, new PID.
      assert diag.prev_urls == [nil]
      assert diag.pids_changed
      assert diag.prev_best == [eu1_old]
    end

    test "sticky best kept when connected quorum drops but best node still viable" do
      us1 = spawn_conn_holder()
      as1 = spawn_conn_holder()
      eu1 = spawn_conn_holder()

      # Reported peaks follow us1 (best); eu1 is stale but us1 remains viable.
      drop_state =
        base_state(
          %{
            eu1 => info(@eu1_url, eu1, 50, 100),
            us1 => info(@us1_url, us1, 100, 200),
            as1 => info(@as1_url, as1, 100, 300)
          },
          best: [us1],
          height: 100
        )

      {_drop_state, drop_diag} = Manager.__test_simulate_update__(drop_state)

      assert drop_diag.connected_count == 0,
             "stale eu1 with reported peak 100 leaves only 2 qualifying nodes (need 3)"

      assert drop_diag.new_best == [us1],
             "viable us1 should stay best despite connected quorum flicker"

      refute drop_diag.would_log
      refute drop_diag.pids_changed
    end

    test "physical peak ahead of best does not clear best when reported peaks match best" do
      eu1 = spawn_conn_holder()
      us1 = spawn_conn_holder()
      as1 = spawn_conn_holder()

      conns = %{
        eu1 => info(@eu1_url, eu1, 100, 100),
        us1 => info(@us1_url, us1, 105, 200),
        as1 => info(@as1_url, as1, 105, 300)
      }

      state =
        base_state(conns, best: [eu1])
        |> Map.put(:physical_peaks, peaks(105))
        |> Map.put(:peaks, peaks(100))

      {_state, diag} = Manager.__test_simulate_update__(state)

      assert diag.new_best == [eu1]
      refute diag.would_log
      refute diag.pids_changed
    end

    test "startup-like drop and recover does not repeat would_log for same eu1 PID" do
      eu1 = spawn_conn_holder()
      us1 = spawn_conn_holder()
      as1 = spawn_conn_holder()

      conns_full = %{
        eu1 => info(@eu1_url, eu1, 100, 100),
        us1 => info(@us1_url, us1, 100, 200),
        as1 => info(@as1_url, as1, 100, 300)
      }

      {settled, _} =
        base_state(conns_full, best: [eu1])
        |> Manager.__test_simulate_update__()

      # Only two seed connections up — connected quorum empty, eu1 still viable.
      drop_state =
        base_state(
          %{
            eu1 => info(@eu1_url, eu1, 100, 100),
            us1 => info(@us1_url, us1, 100, 200)
          },
          best: [eu1],
          height: 100
        )

      {_drop_state, drop_diag} = Manager.__test_simulate_update__(drop_state)

      assert drop_diag.connected_count == 0
      assert drop_diag.new_best == [eu1]
      refute drop_diag.would_log

      recover_state = %{settled | conns: conns_full}
      {_recover_state, recover_diag} = Manager.__test_simulate_update__(recover_state)

      refute recover_diag.would_log
      assert recover_diag.new_best == [eu1]
    end
  end
end
