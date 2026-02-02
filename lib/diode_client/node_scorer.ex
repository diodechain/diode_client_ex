defmodule DiodeClient.NodeScorer do
  @moduledoc """
  Tracks per-node connection outcomes and drives backoff for reconnect attempts.

  ## Reasoning

  Not all nodes are equally reliable. Some accept connections and stay up; others
  fail to connect, drop connections, or crash. Without scoring we would retry
  bad nodes as often as good ones, wasting time and resources. The scorer
  records failures and successes per node (by server URL) and increases the
  delay before the next connect/restart attempt when a node has a negative
  score. That way we back off from unreliable nodes while still trying good
  ones at the normal rate.

  Score is an integer in a bounded range. It decreases on failures (e.g. connect
  error or connection process crash) and increases when a connection becomes
  stable (e.g. first peak received). The delay before the next attempt is
  base delay plus extra time when the score is negative; the worse the score,
  the longer we wait.

  ## Well-behaved nodes

  - **Stable seed**: Connects once, receives peaks, stays up. Score moves from 0
    toward the positive cap with each reported success; delay stays at base
    (e.g. 15 s) on restart.
  - **Brief outage then recovery**: Node fails once or twice (e.g. SSL closed),
    then restarts and gets a peak. Score dips then recovers; after a few
    successes it is back in positive territory and delay is base again.
  - **New node**: Never seen before has score 0, so delay is base—no penalty
    until we see failures.

  ## Misbehaving nodes

  - **Repeated connect failures**: Node is down or rejecting connections. Each
    failed connect decrements the score; delay grows (e.g. 15 s + 10 s per
    negative point, capped). We retry less often and avoid hammering a bad host.
  - **Connect then drop**: Node accepts TLS then closes the connection or
    crashes. Manager reports a crash, score drops; next restart is delayed.
    If this repeats, score stays negative and we back off further.
  - **Flaky node**: Intermittent failures and successes. Score oscillates;
    average behaviour determines whether we tend toward base delay (more
    successes) or longer delays (more failures).
  """
  use GenServer

  @default_score 0
  @min_score -100
  @max_score 100
  @failure_decrement 10
  @success_increment 5
  @base_delay_ms 0
  @max_extra_delay_ms 120_000
  @delay_factor_ms_per_point 1_000

  def start_link(opts \\ []) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Reports a connection failure or abort for the given node (server URL).
  """
  def report_failure(node_id) when is_binary(node_id) or is_atom(node_id) do
    if pid = Process.whereis(__MODULE__) do
      GenServer.cast(pid, {:report_failure, to_string(node_id)})
    end

    :ok
  end

  @doc """
  Reports a stable connection for the given node (server URL).
  """
  def report_success(node_id) when is_binary(node_id) or is_atom(node_id) do
    if pid = Process.whereis(__MODULE__) do
      GenServer.cast(pid, {:report_success, to_string(node_id)})
    end

    :ok
  end

  @doc """
  Returns the recommended delay in milliseconds before the next connect/restart attempt.
  Returns base_delay when NodeScorer is not running.
  """
  def get_delay(node_id) when is_binary(node_id) or is_atom(node_id) do
    if pid = Process.whereis(__MODULE__) do
      GenServer.call(pid, {:get_delay, to_string(node_id)})
    else
      @base_delay_ms
    end
  end

  @impl true
  def init(_opts) do
    {:ok, %{}}
  end

  @impl true
  def handle_cast({:report_failure, node_id}, state) do
    entry = Map.get(state, node_id, %{score: @default_score})
    current = Map.get(entry, :score, @default_score)
    score = max(@min_score, current - @failure_decrement)
    state = Map.put(state, node_id, %{entry | score: score})
    {:noreply, state}
  end

  def handle_cast({:report_success, node_id}, state) do
    entry = Map.get(state, node_id, %{score: @default_score})
    current = Map.get(entry, :score, @default_score)
    score = min(@max_score, current + @success_increment)
    state = Map.put(state, node_id, %{entry | score: score})
    {:noreply, state}
  end

  @impl true
  def handle_call({:get_delay, node_id}, _from, state) do
    score =
      case Map.get(state, node_id) do
        nil -> @default_score
        %{score: s} -> s
      end

    delay =
      if score < 0 do
        extra = min(@max_extra_delay_ms, -score * @delay_factor_ms_per_point)
        @base_delay_ms + extra
      else
        @base_delay_ms
      end

    {:reply, delay, state}
  end
end
