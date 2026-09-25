defmodule DiodeClient.Mux do
  @moduledoc """
  Outbound frame scheduler for one relay connection.

  `portopen`, `portsend`, and `portclose` share one TLS socket. Each port
  is a channel. `drain/4` serves a channel until it has sent `quantum/0`
  bytes (64KB), then rotates to the next channel. Sending stops once
  `usage` is at least `usage_limit/0` (128KB in flight). A frame that
  starts under the limit is still sent if it crosses the limit; the
  following frame waits.

  Backlogs are `:queue`s with an explicit byte counter, so enqueue is
  O(1). The relay counterpart is `Network.Mux`.
  """

  @usage_limit 128_000
  @quantum 64_000

  @doc "Bytes that may be in flight before an ack is required."
  def usage_limit, do: @usage_limit

  @doc "Maximum bytes one channel sends before the next channel runs."
  def quantum, do: @quantum

  @doc "Append `frame` (`[req, payload]`) to a backlog."
  def append(backlog, frame) when is_list(frame) do
    {queue, bytes} = normalize(backlog)
    {:queue.in(frame, queue), bytes + frame_bytes(frame)}
  end

  @doc "Whether a backlog has no frames."
  def empty?(backlog) do
    {queue, _bytes} = normalize(backlog)
    :queue.is_empty(queue)
  end

  @doc "Byte size of a backlog, including request ids and payloads."
  def backlog_bytes(backlog) do
    {_queue, bytes} = normalize(backlog)
    bytes
  end

  @doc "Frames in a backlog, oldest first."
  def to_list(backlog) do
    {queue, _bytes} = normalize(backlog)
    :queue.to_list(queue)
  end

  @doc """
  Admit frames in quantum round-robin.

  `cursor` is the channel id that should run next, or `nil`. Returns
  `{channels, usage, sent, cursor}`. `sent` is `{channel_id, req, payload}`.
  Empty backlogs stay in `channels` so the caller can keep latency timestamps.
  """
  def drain(channels, usage, limit \\ @usage_limit, cursor \\ nil)

  def drain(channels, usage, limit, cursor)
      when is_map(channels) and is_integer(usage) and is_integer(limit) do
    channels = Map.new(channels, fn {id, backlog} -> {id, normalize(backlog)} end)
    {channels, usage, sent, cursor} = take(channels, usage, limit, ring(channels, cursor), 0, [])
    {channels, usage, Enum.reverse(sent), cursor}
  end

  @doc "The channel that would run next, or nil."
  def pick(channels) when is_map(channels) do
    channels = Map.new(channels, fn {id, backlog} -> {id, normalize(backlog)} end)

    case ring(channels, nil) do
      [] -> nil
      [id | _] -> {id, to_list(channels[id])}
    end
  end

  defp take(channels, usage, limit, order, _turn, acc) when usage >= limit do
    {channels, usage, acc, cursor(order)}
  end

  defp take(channels, usage, _limit, [], _turn, acc) do
    {channels, usage, acc, nil}
  end

  defp take(channels, usage, limit, order = [id | rest], turn, acc) do
    cond do
      empty?(channels[id]) ->
        take(channels, usage, limit, rest, 0, acc)

      turn >= @quantum ->
        take(channels, usage, limit, rest ++ [id], 0, acc)

      true ->
        send_frame(channels, usage, limit, order, turn, acc)
    end
  end

  defp send_frame(channels, usage, limit, [id | rest], turn, acc) do
    [_req, payload] = peek(channels[id])
    size = byte_size(payload)

    if turn > 0 and turn + size > @quantum do
      take(channels, usage, limit, rest ++ [id], 0, acc)
    else
      emit(channels, usage, limit, id, rest, turn, acc)
    end
  end

  defp emit(channels, usage, limit, id, rest, turn, acc) do
    {{:value, [req, payload]}, queue} = :queue.out(elem(channels[id], 0))
    bytes = elem(channels[id], 1) - frame_bytes([req, payload])
    channels = Map.put(channels, id, {queue, bytes})
    usage = usage + byte_size(payload)
    turn = turn + byte_size(payload)

    order =
      cond do
        empty?(channels[id]) -> rest
        turn >= @quantum -> rest ++ [id]
        true -> [id | rest]
      end

    next_turn = if hd_is(order, id), do: turn, else: 0
    take(channels, usage, limit, order, next_turn, [{id, req, payload} | acc])
  end

  defp hd_is([id | _], id), do: true
  defp hd_is(_, _), do: false

  defp peek({queue, _bytes}) do
    {:value, frame} = :queue.peek(queue)
    frame
  end

  defp ring(channels, cursor) do
    ids =
      channels
      |> Enum.reject(fn {_id, backlog} -> empty?(backlog) end)
      |> Enum.map(&elem(&1, 0))
      |> Enum.sort()

    rotate(ids, cursor)
  end

  defp rotate(ids, nil), do: ids
  defp rotate([], _cursor), do: []

  defp rotate(ids, cursor) do
    case Enum.split_while(ids, &(&1 != cursor)) do
      {_head, []} -> ids
      {head, tail} -> tail ++ head
    end
  end

  defp cursor([]), do: nil
  defp cursor([id | _]), do: id

  defp normalize(frames) when is_list(frames) do
    Enum.reduce(frames, {:queue.new(), 0}, fn frame, {queue, bytes} ->
      {:queue.in(frame, queue), bytes + frame_bytes(frame)}
    end)
  end

  defp normalize({queue, bytes}) when is_integer(bytes), do: {queue, bytes}

  defp frame_bytes(frame), do: :erlang.iolist_size(frame)
end
