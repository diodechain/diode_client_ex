defmodule DiodeClient.ETSLru do
  @moduledoc false
  use GenServer

  def start_link(name, max_size, filter \\ fn _ -> true end) do
    GenServer.start_link(__MODULE__, {name, max_size, filter}, hibernate_after: 5_000)
  end

  @impl true
  def init({name, max_size, filter}) do
    name = new(name, max_size, filter)
    {:ok, name}
  end

  def new(name, max_size, filter \\ fn _ -> true end) do
    name =
      case name do
        nil -> :ets.new(name, [:public])
        _other -> :ets.new(name, [:named_table, :public])
      end

    :ets.insert(name, {:meta, 0, max_size, filter})
    name
  end

  def destroy(name) do
    :ets.delete(name)
  end

  def put(lru, key, value) do
    filter_fun = filter(lru)

    cond do
      not filter_fun.(value) ->
        delete(lru, key)

      get(lru, key) == value ->
        nil

      true ->
        key = {:key, key}
        n = :ets.update_counter(lru, :meta, 1)

        :ets.insert(lru, {key, value, n})
        :ets.insert(lru, {n, key})

        max_size = :ets.lookup_element(lru, :meta, 3)
        del = n - max_size

        if del > 0 do
          [{^del, key}] = :ets.lookup(lru, del)
          :ets.delete(lru, del)

          case :ets.lookup(lru, key) do
            [{^key, _value, ^del}] -> :ets.delete(lru, key)
            _ -> :ok
          end
        end
    end

    value
  end

  def get(lru, key, default \\ nil) do
    case :ets.lookup(lru, {:key, key}) do
      [{_key, value, _n}] -> value
      [] -> default
    end
  end

  def delete(lru, key) do
    :ets.delete(lru, {:key, key})
  end

  def fetch(lru, key, fun) do
    if :ets.whereis(lru) == :undefined do
      fun.()
    else
      case :ets.lookup(lru, {:key, key}) do
        [{_key, value, _n}] ->
          value

        [] ->
          :global.trans({key, self()}, fn ->
            fetch_nolock(lru, key, fun)
          end)
      end
    end
  end

  def update(lru, key, fun) do
    :global.trans({key, self()}, fn ->
      put(lru, key, eval(fun))
    end)
  end

  def fetch_nolock(lru, key, fun) do
    case :ets.lookup(lru, {:key, key}) do
      [{_key, value, _n}] -> value
      [] -> put(lru, key, eval(fun))
    end
  end

  def size(lru) do
    total_size = :ets.info(lru, :size)
    div(total_size - 1, 2)
  end

  def to_list(lru) do
    for {{:key, key}, value, _n} <- :ets.tab2list(lru), do: {key, value}
  end

  def filter(lru) do
    :ets.lookup_element(lru, :meta, 4)
  end

  def update_filter(lru, fun) do
    :ets.update_element(lru, :meta, [{4, fun}])
  end

  def max_size(lru) do
    :ets.lookup_element(lru, :meta, 3)
  end

  def flush(lru) do
    filter = filter(lru)
    max_size = max_size(lru)
    :ets.delete_all_objects(lru)
    :ets.insert(lru, {:meta, 0, max_size, filter})
  end

  #
  # Private functions below
  #

  defp eval(fun) when is_function(fun, 0) do
    fun.()
  end

  defp eval({m, f, a}) do
    apply(m, f, a)
  end
end
