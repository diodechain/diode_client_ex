defmodule DiodeClient.Manager.ChainRoutingTest do
  @moduledoc """
  Prefixed-chain RPC routing must not fall back to traffic-best relays that
  never reported a peak for that chain (they answer with 401 "bad input").
  """
  use ExUnit.Case, async: true

  alias DiodeClient.Manager
  alias DiodeClient.Manager.Info
  alias DiodeClient.Rlpx

  @base DiodeClient.Shell.Base
  @diode DiodeClient.Shell
  @moonbeam DiodeClient.Shell.Moonbeam

  defp block(n) do
    %{
      "number" => Rlpx.uint2bin(n),
      "block_hash" => :crypto.hash(:sha256, <<n>>),
      "timestamp" => Rlpx.uint2bin(n * 6)
    }
  end

  defp spawn_conn_holder(), do: spawn(fn -> Process.sleep(:infinity) end)

  defp info(url, pid, peaks, latency, opts \\ []) do
    %Info{
      server_url: url,
      server_address: <<0::160>>,
      pid: pid,
      key: String.to_atom(url),
      latency: latency,
      peaks: peaks,
      type: Keyword.get(opts, :type, :seed)
    }
  end

  defp base_manager_state(conns, opts) do
    height = Keyword.get(opts, :height, 100)

    %Manager{
      conns: conns,
      shells: MapSet.new([@base, @diode, @moonbeam]),
      chain_peaks: %{
        @base => block(height),
        @diode => block(height),
        @moonbeam => block(height)
      },
      traffic_best: Keyword.get(opts, :best, []),
      traffic_best_timestamp: System.os_time(:second),
      debounce_timeout: 100,
      online: true,
      server_list: %{},
      waiting_traffic: [],
      waiting_for_peak: %{},
      waiting_chain: %{},
      sticky: Keyword.get(opts, :sticky, nil),
      peak_subscribers: %{},
      peak_subscriber_refs: %{},
      local_peak_pollers: %{},
      rpc_failed_at: %{},
      sticky_unhealthy_since: nil
    }
  end

  describe "chain_connection_pids" do
    test "never includes traffic-best relays without a Base peak" do
      base_ok = spawn_conn_holder()
      traffic_only = spawn_conn_holder()

      conns = %{
        base_ok =>
          info("34.51.36.33", base_ok, %{@base => block(100), @diode => block(100)}, 200),
        traffic_only => info("100.42.185.191", traffic_only, %{@diode => block(100)}, 50)
      }

      state = base_manager_state(conns, best: [traffic_only, base_ok], height: 100)
      pids = Manager.__test_chain_connection_pids__(state, @base)

      assert pids == [base_ok]
      refute traffic_only in pids
    end

    test "returns a single Base-capable relay even below consensus quorum size" do
      only = spawn_conn_holder()
      no_base = spawn_conn_holder()

      conns = %{
        only => info("as1.prenet.diode.io", only, %{@base => block(100)}, 100),
        no_base => info("eu2.prenet.diode.io", no_base, %{@diode => block(100)}, 80)
      }

      state = base_manager_state(conns, best: [no_base], height: 100)
      assert Manager.__test_chain_connection_pids__(state, @base) == [only]
    end

    test "falls back to stale Base-capable relay rather than empty / traffic-only" do
      stale = spawn_conn_holder()
      no_base = spawn_conn_holder()

      conns = %{
        stale => info("as1.prenet.diode.io", stale, %{@base => block(90)}, 100),
        no_base => info("100.42.185.191", no_base, %{@diode => block(100)}, 40)
      }

      state = base_manager_state(conns, best: [no_base], height: 100)
      assert Manager.__test_chain_connection_pids__(state, @base) == [stale]
    end
  end

  describe "tx_relay_candidates for prefixed shells" do
    test "excludes seeds that lack a peak for the target chain" do
      base_ok = spawn_conn_holder()
      no_base = spawn_conn_holder()

      conns = %{
        base_ok =>
          info(
            "as1.prenet.diode.io",
            base_ok,
            %{@base => block(100), @moonbeam => block(100), @diode => block(100)},
            100
          ),
        no_base =>
          info("100.42.185.191", no_base, %{@diode => block(100), @moonbeam => block(100)}, 50)
      }

      state = base_manager_state(conns, best: [no_base, base_ok], height: 100)
      candidates = Manager.__test_tx_relay_candidates__(state, @base)

      assert candidates == [base_ok]
      refute no_base in candidates
    end

    test "prefers lower-latency chain-capable relays" do
      eu1 = spawn_conn_holder()
      us1 = spawn_conn_holder()

      peaks = %{@base => block(100), @moonbeam => block(100), @diode => block(100)}

      conns = %{
        eu1 => info("eu1.prenet.diode.io", eu1, peaks, 100),
        us1 => info("us1.prenet.diode.io", us1, peaks, 200)
      }

      state = base_manager_state(conns, best: [us1, eu1], height: 100)
      assert Manager.__test_tx_relay_candidates__(state, @base) == [eu1, us1]
    end
  end
end
