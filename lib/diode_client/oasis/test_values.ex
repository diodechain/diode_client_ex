defmodule DiodeClient.TestValues do
  @moduledoc false
  def put(key, value) do
    value = Map.put(:persistent_term.get(__MODULE__, %{}), key, value)
    :persistent_term.put(__MODULE__, value)
  end

  def get(key) do
    :persistent_term.get(__MODULE__, %{})
    |> Map.get(key, nil)
  end

  def clear() do
    :persistent_term.put(__MODULE__, %{})
  end
end
