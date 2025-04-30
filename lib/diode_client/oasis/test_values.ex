defmodule DiodeClient.TestValues do
  @moduledoc false
  def put(key, value) do
    :persistent_term.put(key, value)
  end

  def get(key) do
    :persistent_term.get(key, nil)
  end
end
