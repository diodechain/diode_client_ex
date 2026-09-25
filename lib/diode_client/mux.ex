defmodule DiodeClient.Mux do
  @moduledoc """
  Outbound frame scheduler for one relay connection.

  `portopen`, `portsend`, and `portclose` share a single TLS socket. Each
  port is a channel. `drain/2` admits frames in shortest-backlog-first
  order and stops once more than `usage_limit/0` bytes are in flight.

  This is the client half of the same job `Network.Sender` does on the
  relay (`flat_size` partitions, 64KB coalesce, no in-flight cap). The two
  schedulers are not interchangeable today:

    * Client weight is `iolist_size` of the unsent backlog (real bytes).
      Relay weight is `:erts_debug.flat_size/1` of the queue term, which
      ignores refc binary payloads larger than 64 bytes.
    * Client backpressure is a global 128KB in-flight cap. The relay
      queue is unbounded and the socket writer coalesces up to 64KB.
    * Both break equal-weight ties by map iteration order, which is not
      stable across OTP versions, and both append with `++` (quadratic
      in queue depth). The tie winner is then drained to completion, so
      two equal transfers do not share the socket.

  Merge options, cheapest first:

    1. Keep two modules, but give both this API (`enqueue/3`, `drain/2`,
       `release/2`) and a shared weight function. Behavior stays local;
       tests can run the same scenarios against each.
    2. Move this module into `diode_client` (already a `diode_node` dep)
       and pass the weight and limit as options. One implementation,
       two configurations.
    3. Replace both with one deficit round-robin queue (fixed byte
       quantum, queue module instead of list `++`). That removes the
       strict-priority starvation, the key-order tie break, and the
       quadratic enqueue. It is a behavior change on the wire and needs
       the stress tests in `test/mux_test.exs` on both sides.

  Simplifications that make the current rule less error prone:

    * Store each backlog in `:queue` and measure bytes explicitly.
    * Cap in-flight bytes per channel, not only globally, so one 15MB
      transfer cannot hold the window while another never starts.
    * Count payload bytes, never term size.
    * Round-robin equal-weight channels instead of map key order.
  """

  @usage_limit 128_000

  @doc "Bytes that may be sent before an ack (`release/2`) is required."
  def usage_limit, do: @usage_limit

  @doc "Append `frame` (`[req, payload]`) to the channel backlog."
  def append(backlog, frame) when is_list(backlog) and is_list(frame) do
    backlog ++ [frame]
  end

  @doc "Byte size of a backlog, including request ids and payloads."
  def backlog_bytes(backlog) when is_list(backlog) do
    :erlang.iolist_size(backlog)
  end

  @doc """
  Admit frames while `usage` is within the limit.

  Returns `{channels, usage, sent}` where `sent` is `{channel_id, req, payload}`
  in send order. A frame that crosses the limit is still admitted; the next
  one waits. Empty backlogs stay in `channels` so the caller can keep
  latency timestamps for those ids.
  """
  def drain(channels, usage, limit \\ @usage_limit)
      when is_map(channels) and is_integer(usage) and is_integer(limit) do
    do_drain(channels, usage, limit, [])
  end

  @doc "The non-empty channel with the smallest backlog, or nil."
  def pick(channels) when is_map(channels) do
    channels
    |> Enum.reject(fn {_id, backlog} -> backlog == [] end)
    |> Enum.min(&lighter?/2, fn -> nil end)
  end

  defp do_drain(channels, usage, limit, acc) when usage > limit do
    {channels, usage, Enum.reverse(acc)}
  end

  defp do_drain(channels, usage, limit, acc) do
    case pick(channels) do
      nil ->
        {channels, usage, Enum.reverse(acc)}

      {id, [[req, payload] | rest]} ->
        channels = Map.put(channels, id, rest)
        do_drain(channels, usage + byte_size(payload), limit, [{id, req, payload} | acc])
    end
  end

  defp lighter?({_, a}, {_, b}), do: backlog_bytes(a) < backlog_bytes(b)
end
