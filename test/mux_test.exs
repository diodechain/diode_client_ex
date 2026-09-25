defmodule DiodeClient.MuxTest do
  use ExUnit.Case, async: true

  alias DiodeClient.Mux

  defp frame(payload), do: [<<0>>, payload]

  defp channels(pairs) do
    Map.new(pairs, fn {id, payloads} ->
      {id, Enum.map(payloads, &frame/1)}
    end)
  end

  defp sent_ids({_channels, _usage, sent, _cursor}), do: Enum.map(sent, &elem(&1, 0))

  defp drain(channels, usage, limit \\ Mux.usage_limit(), cursor \\ nil) do
    Mux.drain(channels, usage, limit, cursor)
  end

  describe "round robin" do
    test "equal quantum-sized chunks alternate, lower id first" do
      q = Mux.quantum()
      channels = channels(a: repeated(3, q), b: repeated(3, q))
      assert sent_ids(drain(channels, 0, 10_000_000)) == [:a, :b, :a, :b, :a, :b]
    end

    test "a trickle does not run to completion ahead of a deep backlog" do
      q = Mux.quantum()
      channels = channels(trickle: repeated(5, 200), bulk: repeated(3, q))
      ids = sent_ids(drain(channels, 0, 10_000_000))
      assert hd(ids) == :bulk or Enum.at(ids, 1) == :bulk
      assert :trickle in ids
      refute ids == List.duplicate(:trickle, 5) ++ List.duplicate(:bulk, 3)
    end

    test "eight ports each get a turn before any port repeats" do
      q = Mux.quantum()

      channels =
        Map.new(1..8, fn n ->
          {:"p#{n}", [frame(<<n::size(q * 8)>>)]}
        end)

      assert sent_ids(drain(channels, 0, 10_000_000)) ==
               Enum.map(1..8, &:"p#{&1}")
    end

    test "a control frame waits its turn instead of preempting bulk ports" do
      q = Mux.quantum()

      channels =
        channels(bulk_a: [<<0::size(q * 8)>>], bulk_b: [<<0::size(q * 8)>>], ctrl: [<<1>>])

      ids = sent_ids(drain(channels, 0, 10_000_000))
      assert ids == [:bulk_a, :bulk_b, :ctrl]
    end

    test "small frames yield after one quantum so the other channel runs" do
      channels = channels(a: repeated(200, 1_000), b: repeated(200, 1_000))
      ids = sent_ids(drain(channels, 0, 10_000_000))
      assert burst_bytes(ids, 1_000) <= Mux.quantum()
      assert Enum.count(ids, &(&1 == :a)) == 200
      assert Enum.count(ids, &(&1 == :b)) == 200
    end
  end

  describe "in-flight window" do
    test "both streams share the 128KB window" do
      channels = channels(a: repeated(4, 40_000), b: repeated(4, 40_000))
      {rest, usage, sent, _cursor} = drain(channels, 0)
      ids = sent_ids({rest, usage, sent, nil})

      assert usage >= Mux.usage_limit()
      assert :a in ids and :b in ids
      assert Mux.to_list(rest.a) != [] and Mux.to_list(rest.b) != []

      {_rest, _usage, more, _} = drain(rest, usage)
      assert more == []
    end

    test "a frame that lands on the limit holds the next frame" do
      channels = channels(a: [<<0::size(128_000 * 8)>>, <<1>>])
      {rest, usage, sent, _} = drain(channels, 0)
      assert length(sent) == 1
      assert usage == 128_000
      assert length(Mux.to_list(rest.a)) == 1

      {_rest, _usage, held, _} = drain(rest, usage)
      assert held == []
    end

    test "one byte over the limit holds every remaining frame" do
      channels = channels(a: [<<1>>, <<2>>])
      {rest, usage, sent, _} = drain(channels, Mux.usage_limit() + 1)
      assert sent == []
      assert length(Mux.to_list(rest.a)) == 2
      assert usage == Mux.usage_limit() + 1
    end

    test "acking the window continues the rotation" do
      channels = channels(a: repeated(4, 40_000), b: repeated(4, 40_000))
      {rest, usage, first, cursor} = drain(channels, 0, 160_000)
      assert sent_ids({rest, usage, first, cursor}) == [:a, :b, :a, :b]
      assert cursor == :b
      {_rest, _usage, second, _} = drain(rest, 0, 10_000_000, cursor)
      assert sent_ids({nil, 0, second, nil}) == [:b, :a, :b, :a]
    end
  end

  describe "edge cases" do
    test "empty backlogs and an empty map send nothing" do
      assert Mux.pick(%{}) == nil
      assert Mux.pick(%{a: []}) == nil
      assert match?({_, 0, [], nil}, drain(%{a: []}, 0))
    end

    test "append keeps per-channel order under a deep queue" do
      backlog =
        Enum.reduce(1..500, [], fn n, acc ->
          Mux.append(acc, [<<n::16>>, <<n>>])
        end)

      listed = Mux.to_list(backlog)
      assert length(listed) == 500
      assert hd(listed) == [<<1::16>>, <<1>>]
      assert List.last(listed) == [<<500::16>>, <<500>>]
    end

    test "backlog bytes count every queued payload" do
      backlog =
        []
        |> Mux.append(frame(<<0::size(1000 * 8)>>))
        |> Mux.append(frame(<<0::size(1000 * 8)>>))

      assert Mux.backlog_bytes(backlog) == 2 * (1 + 1000)
    end
  end

  describe "performance" do
    test "enqueue and drain of 20k frames stays linear" do
      small = time_drain(2_000)
      large = time_drain(8_000)
      assert large < small * 10
      assert large < 1_000_000
    end

    test "fifty channels each send once without a slow scan" do
      channels =
        Map.new(1..50, fn n ->
          {n, [frame(<<n>>)]}
        end)

      {micro, ids} =
        :timer.tc(fn ->
          sent_ids(drain(channels, 0, 10_000_000))
        end)

      assert ids == Enum.to_list(1..50)
      assert micro < 100_000
    end
  end

  defp burst_bytes(ids, frame_size) do
    ids
    |> Enum.chunk_by(& &1)
    |> Enum.map(&(length(&1) * frame_size))
    |> Enum.max()
  end

  defp time_drain(n) do
    {micro, _} =
      :timer.tc(fn ->
        channels = channels(a: repeated(n, 64), b: repeated(n, 64))
        drain(channels, 0, 100_000_000)
      end)

    micro
  end

  defp repeated(n, size), do: for(_ <- 1..n, do: <<0::size(size * 8)>>)
end
