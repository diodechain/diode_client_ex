defmodule DiodeClient.NodeScorerTest do
  use ExUnit.Case, async: false

  @base_delay_ms 0
  @failure_decrement 10
  @delay_factor_ms_per_point 1_000
  @max_extra_delay_ms 120_000
  @min_score -100

  setup do
    start_supervised(DiodeClient.NodeScorer)
    :ok
  end

  describe "initial behaviour" do
    test "unknown node has base delay only (no extra delay)" do
      assert DiodeClient.NodeScorer.get_delay("unknown.example.com") == @base_delay_ms
    end

    test "different unknown nodes each get base delay" do
      assert DiodeClient.NodeScorer.get_delay("a.prenet.diode.io") == @base_delay_ms
      assert DiodeClient.NodeScorer.get_delay("b.prenet.diode.io") == @base_delay_ms
    end

    test "node_id can be string or atom" do
      assert DiodeClient.NodeScorer.get_delay("eu1.prenet.diode.io") == @base_delay_ms
      assert DiodeClient.NodeScorer.get_delay(:eu1) == @base_delay_ms
    end

    test "get_delay returns base_delay when NodeScorer is not running" do
      stop_supervised(DiodeClient.NodeScorer)
      assert DiodeClient.NodeScorer.get_delay("any.node") == @base_delay_ms
    end
  end

  describe "failure cases" do
    test "one failure increases delay above base" do
      DiodeClient.NodeScorer.report_failure("bad.node")
      expected = @base_delay_ms + @failure_decrement * @delay_factor_ms_per_point
      assert DiodeClient.NodeScorer.get_delay("bad.node") == expected
    end

    test "repeated failures increase delay further" do
      node = "flaky.node"
      DiodeClient.NodeScorer.report_failure(node)
      DiodeClient.NodeScorer.report_failure(node)
      DiodeClient.NodeScorer.report_failure(node)
      # score -30 => extra 30_000 ms
      expected = @base_delay_ms + 30 * @delay_factor_ms_per_point
      assert DiodeClient.NodeScorer.get_delay(node) == expected
    end

    test "delay is capped (score clamped at min, extra at max_extra)" do
      node = "very_bad.node"
      # 20 failures => score clamped at -100 => extra = min(120_000, 100_000) = 100_000
      for _ <- 1..20, do: DiodeClient.NodeScorer.report_failure(node)

      expected =
        @base_delay_ms + min(@max_extra_delay_ms, -@min_score * @delay_factor_ms_per_point)

      assert DiodeClient.NodeScorer.get_delay(node) == expected
    end

    test "report_failure when scorer not running returns :ok and does not crash" do
      stop_supervised(DiodeClient.NodeScorer)
      assert DiodeClient.NodeScorer.report_failure("any") == :ok
    end
  end

  describe "success cases" do
    test "one success keeps delay at base (positive score)" do
      DiodeClient.NodeScorer.report_success("good.node")
      assert DiodeClient.NodeScorer.get_delay("good.node") == @base_delay_ms
    end

    test "repeated successes keep delay at base" do
      node = "stable.node"
      for _ <- 1..5, do: DiodeClient.NodeScorer.report_success(node)
      assert DiodeClient.NodeScorer.get_delay(node) == @base_delay_ms
    end

    test "success after failures reduces delay" do
      node = "recovering.node"
      DiodeClient.NodeScorer.report_failure(node)
      DiodeClient.NodeScorer.report_failure(node)

      assert DiodeClient.NodeScorer.get_delay(node) ==
               @base_delay_ms + 20 * @delay_factor_ms_per_point

      DiodeClient.NodeScorer.report_success(node)
      # score -20 + 5 = -15 => extra 15_000
      assert DiodeClient.NodeScorer.get_delay(node) ==
               @base_delay_ms + 15 * @delay_factor_ms_per_point

      DiodeClient.NodeScorer.report_success(node)
      # score -15 + 5 = -10
      assert DiodeClient.NodeScorer.get_delay(node) ==
               @base_delay_ms + 10 * @delay_factor_ms_per_point
    end

    test "enough successes after failures bring delay back to base" do
      node = "recovered.node"
      DiodeClient.NodeScorer.report_failure(node)
      DiodeClient.NodeScorer.report_failure(node)
      # score -20; need 4 successes to reach 0
      for _ <- 1..4, do: DiodeClient.NodeScorer.report_success(node)
      assert DiodeClient.NodeScorer.get_delay(node) == @base_delay_ms
    end

    test "report_success when scorer not running returns :ok and does not crash" do
      stop_supervised(DiodeClient.NodeScorer)
      assert DiodeClient.NodeScorer.report_success("any") == :ok
    end
  end

  describe "per-node isolation" do
    test "failures for one node do not affect another node's delay" do
      DiodeClient.NodeScorer.report_failure("bad.one")
      assert DiodeClient.NodeScorer.get_delay("good.one") == @base_delay_ms
    end

    test "successes for one node do not affect another node's delay" do
      DiodeClient.NodeScorer.report_success("good.one")
      assert DiodeClient.NodeScorer.get_delay("unknown.one") == @base_delay_ms
    end
  end
end
