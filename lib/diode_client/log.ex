defmodule DiodeClient.Log do
  @doc false
  defmacro __using__(_opts) do
    quote do
      require Logger

      defmacrop log(string, args \\ []) do
        quote do
          Logger.info(
            :io_lib.format("~p #{inspect(__MODULE__)} #{unquote(string)}", [
              self() | unquote(args)
            ])
          )
        end
      end
    end
  end
end
