defmodule DiodeClient.Acceptor do
  use GenServer
  use DiodeClient.Log
  alias DiodeClient.{Acceptor, Port}
  defstruct [:backlog, :ports]

  @timeout 30_000
  @max_backlog 120

  defmodule Listener do
    defstruct [:portnum, :opts]
  end

  def start_link([]) do
    GenServer.start_link(__MODULE__, [], name: __MODULE__, hibernate_after: 5_000)
  end

  @impl true
  def init([]) do
    {:ok, %Acceptor{backlog: %{}, ports: %{}}}
  end

  def listen(portnum, options \\ []) when is_integer(portnum) do
    case GenServer.call(Acceptor, {:open, portnum, options}) do
      {:ok, portnum} -> {:ok, %Listener{portnum: portnum, opts: options}}
      other -> other
    end
  end

  def accept(%Listener{portnum: portnum} = listener, timeout \\ :infinity) do
    {time, ret} = :timer.tc(fn -> do_accept(portnum, timeout) end)
    timeout = if timeout == :infinity, do: :infinity, else: timeout - time

    case ret do
      {:error, :timeout} -> {:error, :timeout}
      {:error, _reason} -> accept(listener, timeout)
      socket -> {:ok, socket}
    end
  end

  def close(%Listener{portnum: portnum}) do
    GenServer.cast(__MODULE__, {:close, portnum})
  end

  defp do_accept(portnum, timeout) do
    GenServer.call(Acceptor, {:accept, portnum, timeout}, :infinity)
    |> case do
      {:error, :timeout} ->
        {:error, :timeout}

      pid when is_pid(pid) ->
        Process.link(pid)

        case Port.tls_handshake(pid) do
          {:ok, socket} ->
            socket

          {:error, reason} ->
            log("port closed during handshake (~p)", [reason])
            Port.close(pid)
            {:error, reason}
        end
    end
  end

  @impl true
  def handle_call({:open, portnum, options}, _from, %Acceptor{ports: ports} = state) do
    new_value =
      case Keyword.fetch(options, :callback) do
        {:ok, callback} when is_function(callback, 1) -> callback
        {:ok, _other} -> :invalid_callback
        :error -> []
      end

    {reply, state} =
      if new_value == :invalid_callback do
        {{:error, :invalid_callback}, state}
      else
        state =
          if is_function(new_value) do
            do_close(portnum, state)
            %Acceptor{state | ports: Map.put(ports, portnum, new_value)}
          else
            new_value =
              case Map.get(ports, portnum, []) do
                list when is_list(list) -> new_value ++ list
                callback when is_function(callback) -> new_value
              end

            %Acceptor{state | ports: Map.put(ports, portnum, new_value)}
          end

        {{:ok, portnum}, state}
      end

    {:reply, reply, state}
  end

  def handle_call({:close, portnum}, _from, %Acceptor{} = state) do
    {:reply, :ok, do_close(portnum, state)}
  end

  def handle_call(
        {:accept, portnum, timeout},
        from,
        %Acceptor{backlog: backlog, ports: ports} = state
      ) do
    case Map.get(backlog, portnum) do
      [request] ->
        {request, Map.delete(backlog, portnum)}

      [request | rest] ->
        {request, Map.put(backlog, portnum, rest)}

      nil ->
        :wait
    end
    |> case do
      :wait ->
        if is_integer(timeout),
          do: Process.send_after(self(), {:accept_timeout, portnum, from}, timeout)

        ports = Map.update(ports, portnum, [from], fn list -> list ++ [from] end)
        {:noreply, %Acceptor{state | ports: ports}}

      {request, backlog} ->
        {:reply, request, %Acceptor{state | backlog: backlog}}
    end
  end

  def handle_call(
        {:inject, portnum, request},
        _from,
        %Acceptor{backlog: backlog, ports: ports} = state
      )
      when is_pid(request) do
    case Map.get(ports, portnum) do
      [client | rest] ->
        ports = Map.put(ports, portnum, rest)
        GenServer.reply(client, request)
        {:reply, :ok, %Acceptor{state | ports: ports}}

      [] ->
        list = Map.get(backlog, portnum, [])

        if length(list) >= @max_backlog do
          Process.exit(request, :backlog_full)
          {:reply, {:error, :backlog_full}, state}
        else
          backlog = Map.put(backlog, portnum, list ++ [request])
          Process.send_after(self(), {:backlog_timeout, portnum, request}, @timeout)
          {:reply, :ok, %Acceptor{state | backlog: backlog}}
        end

      callback when is_function(callback, 1) ->
        spawn(fn ->
          Process.link(request)
          callback.(request)
        end)

        {:reply, :ok, state}

      nil ->
        {:reply, {:error, :access_denied}, state}
    end
  end

  @impl true
  def handle_info({:backlog_timeout, portnum, request}, %Acceptor{backlog: backlog} = state) do
    backlog =
      case Map.get(backlog, portnum) do
        nil ->
          backlog

        list ->
          if request in list do
            Process.exit(request, :backlog_timeout)
            list = List.delete(list, request)
            Map.put(backlog, portnum, list)
          else
            backlog
          end
      end

    {:noreply, %Acceptor{state | backlog: backlog}}
  end

  def handle_info({:accept_timeout, portnum, from}, %Acceptor{ports: ports} = state) do
    ports =
      case Map.get(ports, portnum) do
        list when is_list(list) ->
          if from in list do
            GenServer.reply(from, :timeout)
            Map.put(ports, portnum, List.delete(list, from))
          else
            ports
          end

        _other ->
          ports
      end

    {:noreply, %Acceptor{state | ports: ports}}
  end

  defp do_close(portnum, %Acceptor{ports: ports} = state) do
    case Map.get(ports, portnum) do
      list when is_list(list) -> list
      _other -> []
    end
    |> Enum.each(fn from -> GenServer.reply(from, {:error, :port_closed}) end)

    %Acceptor{state | ports: Map.delete(ports, portnum)}
  end
end
