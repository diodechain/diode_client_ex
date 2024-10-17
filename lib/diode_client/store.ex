defmodule DiodeClient.Store do
  @moduledoc false

  def get(key) do
    :persistent_term.get({__MODULE__, key}, nil)
  end

  def put(key, value) do
    :persistent_term.put({__MODULE__, key}, value)
  end

  def fetch(key, fun) do
    case get(key) do
      nil ->
        value = fun.()
        :persistent_term.put({__MODULE__, key}, value)
        value

      value ->
        value
    end
  end
end
