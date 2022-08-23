defmodule DiodeClient.BertExt do
  @moduledoc false
  @spec encode!(any()) :: binary()
  def encode!(term) do
    :erlang.term_to_binary(term_to_binary(term))
  end

  defp term_to_binary(map) when is_map(map) do
    ^map = Map.from_struct(map)

    map
    |> Map.to_list()
    |> Enum.map(fn {key, value} -> {key, term_to_binary(value)} end)
    |> Enum.into(%{})
  end

  defp term_to_binary(list) when is_list(list) do
    Enum.map(list, &term_to_binary(&1))
  end

  defp term_to_binary(tuple) when is_tuple(tuple) do
    Tuple.to_list(tuple)
    |> Enum.map(&term_to_binary(&1))
    |> List.to_tuple()
  end

  defp term_to_binary(other) do
    other
  end

  @spec decode!(binary()) :: any()
  def decode!(term) do
    :erlang.binary_to_term(term, [:safe])
  end
end
