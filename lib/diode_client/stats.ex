defmodule DiodeClient.Stats do
  @moduledoc false
  use GenServer
  alias DiodeClient.Stats
  defstruct [:totals, :intervalls]

  def get(key \\ :totals) do
    GenServer.call(__MODULE__, {:get_stats, key})
  end

  def get_sum(key \\ :totals) do
    get(key)
    |> Enum.reduce(%{}, fn
      {{type, from, :self}, amount}, ret ->
        Map.update(ret, {type, from}, amount, fn x -> x + amount end)

      {{type, :self, to}, amount}, ret ->
        Map.update(ret, {type, to}, amount, fn x -> x + amount end)
    end)
  end

  def submit(type, from, to, amount) do
    GenServer.cast(__MODULE__, {:stat, type, from, to, amount})
  end

  def start_link([]) do
    GenServer.start_link(__MODULE__, %Stats{totals: %{}, intervalls: %{10 => {%{}, %{}}}},
      hibernate_after: 5_000,
      name: __MODULE__
    )
  end

  @impl true
  def init(stats = %Stats{intervalls: intervalls}) do
    for key <- Map.keys(intervalls) do
      :timer.send_interval(key * 1000, {:intervall, key})
    end

    {:ok, stats}
  end

  @impl true
  def handle_call(
        {:get_stats, key},
        _from,
        stats = %Stats{totals: totals, intervalls: intervalls}
      ) do
    ret =
      if key == :totals do
        totals
      else
        {now, _prev} = Map.get(intervalls, key, {%{}, %{}})
        now
      end

    {:reply, ret, stats}
  end

  @impl true
  def handle_info({:intervall, key}, stats = %Stats{intervalls: intervalls}) do
    intervalls = Map.update!(intervalls, key, fn {_prev, now} -> {now, %{}} end)
    {:noreply, %Stats{stats | intervalls: intervalls}}
  end

  @impl true
  def handle_cast(
        {:stat, type, from, to, amount},
        stats = %Stats{totals: totals, intervalls: intervalls}
      ) do
    totals = add(totals, type, from, to, amount)

    intervalls =
      Enum.map(intervalls, fn {key, {prev, now}} ->
        now = add(now, type, from, to, amount)
        {key, {prev, now}}
      end)
      |> Map.new()

    {:noreply, %Stats{stats | totals: totals, intervalls: intervalls}}
  end

  defp add(map, type, from, to, amount) do
    Map.update(map, {type, from, to}, amount, fn x -> x + amount end)
  end
end
