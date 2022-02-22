defmodule DiodeClient.Log do
  require Logger
  @doc false
  defmacro __using__(_opts) do
    quote do
      defmacrop log(string, args \\ []) do
        quote do
          DiodeClient.Log.debug(__MODULE__, unquote(string), unquote(args))
        end
      end
    end
  end

  def enable_debug() do
    :persistent_term.put(DiodeClient.Log, true)
  end

  def debug(module, string, args) do
    if :persistent_term.get(DiodeClient.Log, false) do
      :io_lib.format("~p #{inspect(module)} #{string}", [self() | args])
      |> Logger.debug()
    end
  end
end
