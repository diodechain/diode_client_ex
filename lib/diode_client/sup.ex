defmodule DiodeClient.Sup do
  @moduledoc false
  alias DiodeClient.{Acceptor, Manager, NodeScorer, Stats}

  def start_link(name) do
    Supervisor.start_link(__MODULE__, name, name: name(name))
  end

  def child_spec(name) do
    %{
      id: name,
      start: {__MODULE__, :start_link, [name]},
      type: :supervisor
    }
  end

  def init(_name) do
    Supervisor.init([Stats, Acceptor, NodeScorer, Manager],
      strategy: :one_for_one,
      max_restarts: 1000
    )
  end

  def name(name \\ :default) do
    {:global, {__MODULE__, name}}
  end
end
