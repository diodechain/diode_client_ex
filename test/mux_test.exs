defmodule DiodeClient.MuxTest do
  use ExUnit.Case, async: true

  alias DiodeClient.Mux

  defp frame(payload), do: [<<0>>, payload]

  defp channels(pairs) do
    Map.new(pairs, fn {id, payloads} ->
      {id, Enum.map(payloads, &frame/1)}
    end)
  end

  defp sent_ids({_channels, _usage, sent}), do: Enum.map(sent, fn {id, _req, _payload} -> id end)

  describe "shortest backlog" do
    test "equal chunk sizes do not alternate; the later channel id is drained first" do
      # Enum.min keeps the challenger when sizes are equal, so the later map
      # key wins the tie. That send makes its backlog strictly smaller, and
      # shortest-queue priority then drains it before the other port runs.
      channels = channels(a: repeated(4, 1000), b: repeated(4, 1000))

      assert sent_ids(Mux.drain(channels, 0, 10_000_000)) ==
               [:b, :b, :b, :b, :a, :a, :a, :a]
    end

    test "a trickle channel is fully drained before a 15MB-style backlog moves" do
      # Two transfers at once. One port has a few small frames queued; the
      # other already holds a deep backlog (the steady state of a 15MB
      # download/upload). Strict shortest-queue priority serves only the
      # trickle until it is empty.
      trickle = repeated(5, 200)
      bulk = repeated(30, 20_000)
      channels = channels(trickle: trickle, bulk: bulk)

      assert sent_ids(Mux.drain(channels, 0, 10_000_000)) ==
               List.duplicate(:trickle, 5) ++ List.duplicate(:bulk, 30)
    end

    test "eight ports: the smallest backlog runs to completion before the next" do
      channels =
        channels(
          p1: repeated(1, 10),
          p2: repeated(2, 10),
          p3: repeated(3, 10),
          p4: repeated(4, 10),
          p5: repeated(5, 10),
          p6: repeated(6, 10),
          p7: repeated(7, 10),
          p8: repeated(8, 10)
        )

      ids = sent_ids(Mux.drain(channels, 0, 10_000_000))
      assert Enum.take(ids, 1) == [:p1]
      assert Enum.at(ids, 1) == :p2
      assert List.last(ids) == :p8
      assert length(ids) == 36
    end

    test "a single control frame jumps ahead of every bulk port" do
      channels = channels(bulk_a: repeated(10, 5_000), bulk_b: repeated(10, 5_000), ctrl: [<<1>>])
      assert hd(sent_ids(Mux.drain(channels, 0))) == :ctrl
    end
  end

  describe "in-flight window" do
    test "one stream fills the shared 128KB window before the other is admitted" do
      channels = channels(a: repeated(4, 40_000), b: repeated(4, 40_000))
      {rest, usage, sent} = Mux.drain(channels, 0)

      assert sent_ids({rest, usage, sent}) == [:b, :b, :b, :b]
      assert usage == 160_000
      assert rest.b == []
      assert length(rest.a) == 4

      {_, _usage, more} = Mux.drain(rest, usage)
      assert more == []

      assert sent_ids(Mux.drain(rest, 0)) == [:a, :a, :a, :a]
    end

    test "a frame that lands exactly on the limit does not stop the next frame" do
      channels = channels(a: [<<0::size(128_000 * 8)>>, <<1>>])
      {_rest, usage, sent} = Mux.drain(channels, 0)
      assert length(sent) == 2
      assert usage == 128_001
    end

    test "one byte over the limit holds every remaining frame" do
      channels = channels(a: [<<1>>, <<2>>])
      {rest, usage, sent} = Mux.drain(channels, Mux.usage_limit() + 1)
      assert sent == []
      assert length(rest.a) == 2
      assert usage == Mux.usage_limit() + 1
    end
  end

  describe "edge cases" do
    test "empty backlogs and an empty map send nothing" do
      assert Mux.pick(%{}) == nil
      assert Mux.pick(%{a: []}) == nil
      assert Mux.drain(%{a: []}, 0) == {%{a: []}, 0, []}
    end

    test "append keeps per-channel order under a deep queue" do
      backlog =
        Enum.reduce(1..500, [], fn n, acc ->
          Mux.append(acc, [<<n::16>>, <<n>>])
        end)

      assert length(backlog) == 500
      assert hd(backlog) == [<<1::16>>, <<1>>]
      assert List.last(backlog) == [<<500::16>>, <<500>>]
    end

    test "backlog bytes count every queued payload" do
      assert Mux.backlog_bytes([frame(<<0::size(1000 * 8)>>), frame(<<0::size(1000 * 8)>>)]) ==
               2 * (1 + 1000)
    end

    test "acking the window still serves the later channel id before the other" do
      channels = channels(a: repeated(6, 30_000), b: repeated(6, 30_000))
      {sent, _} = slide(channels, 0, [])
      ids = sent_ids({nil, 0, sent})
      assert ids == List.duplicate(:b, 6) ++ List.duplicate(:a, 6)
    end
  end

  defp slide(channels, usage, acc) do
    {rest, usage, sent} = Mux.drain(channels, usage)

    cond do
      sent != [] ->
        slide(rest, usage, acc ++ sent)

      Enum.any?(rest, fn {_id, backlog} -> backlog != [] end) ->
        slide(rest, 0, acc)

      true ->
        {acc, rest}
    end
  end

  defp repeated(n, size), do: for(_ <- 1..n, do: <<0::size(size * 8)>>)
end
