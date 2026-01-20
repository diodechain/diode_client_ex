defmodule DiodeClient.Acceptor do
  @moduledoc false
  use GenServer
  require Logger
  alias DiodeClient.{Acceptor, Port}
  defstruct [:backlog, :ports, :local_ports, :backup]

  @timeout 30_000
  @max_backlog 120

  defmodule Listener do
    @moduledoc """
    A listener for incoming connections.
    """
    defstruct [:portnum, :opts]

    @type t :: %__MODULE__{
            portnum: integer(),
            opts: keyword()
          }
  end

  def start_link([]) do
    state = %Acceptor{backlog: %{}, ports: %{}, local_ports: %{}, backup: %{}}
    GenServer.start_link(__MODULE__, state, name: __MODULE__, hibernate_after: 5_000)
  end

  @impl true
  def init(state) do
    case Application.fetch_env(:diode_client, :backup) do
      {:ok, backup} -> {:ok, state, {:continue, {:restore, backup}}}
      _ -> {:ok, state}
    end
  end

  @doc """
  Listen on a port.

  Returns `{:ok, listener}`, or `{:error, reason}`.

  This can be used to accept ports in a tcp/ip fashion using the `DiodeClient.Port.accept/2` function.

  Example:
  ```
  {:ok, listener} = DiodeClient.Acceptor.listen(80)
  {:ok, socket} = DiodeClient.Port.accept(listener)
  ```

  An alternative is to passe the `callback` option to the `listen/2` function.

  Example:

  ```
  {:ok, listener} = DiodeClient.Acceptor.listen(80, callback: fn socket ->
    IO.puts("Accepted connection on port 80 \#{inspect(socket)}")
  end)
  ```
  """
  def listen(portnum, options \\ []) when is_integer(portnum) do
    case GenServer.call(Acceptor, {:open, portnum, options}) do
      {:ok, portnum} -> {:ok, %Listener{portnum: portnum, opts: options}}
      other -> other
    end
  end

  def local_port(portnum) do
    case GenServer.call(Acceptor, {:local_port, portnum}) do
      nil -> nil
      pid -> GenServer.call(pid, :local_port)
    end
  end

  def accept(listener = %Listener{portnum: portnum}, timeout \\ :infinity) do
    {time, ret} = :timer.tc(fn -> do_accept(portnum, timeout) end)
    timeout = if timeout == :infinity, do: :infinity, else: timeout - time

    case ret do
      {:error, :timeout} ->
        if timeout == :infinity do
          accept(listener, timeout)
        else
          {:error, :timeout}
        end

      {:error, _reason} ->
        accept(listener, timeout)

      socket ->
        {:ok, socket}
    end
  end

  def close(%Listener{portnum: portnum}) do
    GenServer.cast(__MODULE__, {:close, portnum})
  end

  def all_ports() do
    GenServer.call(__MODULE__, :all_ports)
  end

  defp do_accept(portnum, timeout) do
    GenServer.call(Acceptor, {:accept, portnum, timeout}, :infinity)
    |> case do
      {:error, :timeout} ->
        {:error, :timeout}

      {request, listener_options} ->
        init_socket(request, listener_options)
    end
  end

  defp init_socket(%{type: :open1, ref: pid}, _listener_options) when is_pid(pid) do
    if Process.alive?(pid) do
      Process.link(pid)

      case Port.tls_handshake(pid) do
        {:ok, socket} ->
          socket

        {:error, reason} ->
          Logger.debug("port closed during handshake (#{reason})")
          Port.close(pid)
          {:error, reason}
      end
    else
      {:error, :retry}
    end
  end

  defp init_socket(%{type: :open1, ref: ssl}, _listener_options) do
    # local ssl sockets already have gotten their tls handshake done
    :ssl.controlling_process(ssl, self())
    ssl
  end

  defp init_socket(%{type: :open2, from: conn, ref: physical_port}, listener_options) do
    address = DiodeClient.Connection.server_url(conn)

    if opt_print?(listener_options) do
      "#{address}:#{physical_port}"
    else
      Port.direct_connect(address, physical_port, :server)
    end
  end

  defp close_socket(%{ref: pid}, reason) when is_pid(pid), do: Process.exit(pid, reason)
  defp close_socket(%{type: :open1, ref: ssl}, _reason), do: :ssl.close(ssl)
  defp close_socket(%{type: :open2, ref: _physical_port}, _reason), do: :ok

  @impl true
  def handle_call(:all_ports, _from, state = %Acceptor{ports: ports}) do
    {:reply, ports, state}
  end

  def handle_call(
        {:open, portnum, listener_options},
        _from,
        state = %Acceptor{ports: ports, local_ports: local}
      ) do
    new_value = {[], listener_options}
    backup = Map.put(state.backup, portnum, new_value)
    state = %{state | backup: backup}
    Application.put_env(:diode_client, :backup, backup)

    state =
      if is_function(opt_callback(listener_options)) do
        do_close(portnum, state)
        %Acceptor{state | ports: Map.put(ports, portnum, new_value)}
      else
        {old_list, _old_options} = Map.get(ports, portnum, {[], nil})
        new_value = {old_list ++ [new_value], listener_options}
        local = open_local(local, portnum, listener_options)
        %Acceptor{state | ports: Map.put(ports, portnum, new_value), local_ports: local}
      end

    {:reply, {:ok, portnum}, state}
  end

  def handle_call({:local_port, portnum}, _from, state = %Acceptor{local_ports: local}) do
    {:reply, Map.get(local, portnum), state}
  end

  def handle_call({:close, portnum}, _from, state = %Acceptor{}) do
    {:reply, :ok, do_close(portnum, state)}
  end

  def handle_call(
        {:accept, portnum, timeout},
        from,
        state = %Acceptor{backlog: backlog, ports: ports}
      ) do
    {_, listener_options} = Map.get(ports, portnum, {[], []})

    case Map.get(backlog, portnum, []) do
      [request] ->
        {request, Map.delete(backlog, portnum)}

      [request | rest] ->
        {request, Map.put(backlog, portnum, rest)}

      [] ->
        :wait
    end
    |> case do
      :wait ->
        if is_integer(timeout),
          do: Process.send_after(self(), {:accept_timeout, portnum, from}, timeout)

        ports =
          Map.update(ports, portnum, {[from], []}, fn {list, options} ->
            {list ++ [from], options}
          end)

        {:noreply, %Acceptor{state | ports: ports}}

      {request, backlog} ->
        {:reply, {request, listener_options}, %Acceptor{state | backlog: backlog}}
    end
  end

  def handle_call(
        {:inject, portnum, request},
        _from,
        state = %Acceptor{backlog: backlog, ports: ports}
      ) do
    case Map.get(ports, portnum) do
      {[client | rest], listener_options} ->
        ports = Map.put(ports, portnum, {rest, listener_options})
        GenServer.reply(client, {request, listener_options})
        {:reply, :ok, %Acceptor{state | ports: ports}}

      {[], listener_options} ->
        callback = opt_callback(listener_options)

        if is_function(callback) do
          spawn(fn ->
            case init_socket(request, listener_options) do
              {:error, _} -> :nop
              socket -> callback.(socket)
            end
          end)

          {:reply, :ok, state}
        else
          list = Map.get(backlog, portnum, [])

          if length(list) >= @max_backlog do
            close_socket(request.ref, :backlog_full)
            {:reply, {:error, :backlog_full}, state}
          else
            backlog = Map.put(backlog, portnum, list ++ [request])
            Process.send_after(self(), {:backlog_timeout, portnum, request}, @timeout)
            {:reply, :ok, %Acceptor{state | backlog: backlog}}
          end
        end

      nil ->
        {:reply, {:error, :access_denied}, state}
    end
  end

  defp open_local(local_ports, portnum, options) do
    if Keyword.get(options, :local, true) do
      case Map.get(local_ports, portnum) do
        pid when is_pid(pid) ->
          local_ports

        nil ->
          {:ok, pid} = DiodeClient.LocalAcceptor.start_link(portnum)
          Map.put(local_ports, portnum, pid)
      end
    else
      local_ports
    end
  end

  @impl true
  def handle_info({:backlog_timeout, portnum, request}, state = %Acceptor{backlog: backlog}) do
    backlog =
      case Map.get(backlog, portnum) do
        nil ->
          backlog

        list ->
          if request in list do
            close_socket(request, :backlog_timeout)
            list = List.delete(list, request)
            Map.put(backlog, portnum, list)
          else
            backlog
          end
      end

    {:noreply, %Acceptor{state | backlog: backlog}}
  end

  def handle_info({:accept_timeout, portnum, from}, state = %Acceptor{ports: ports}) do
    {list, options} = Map.get(ports, portnum) || {[], nil}

    ports =
      if from in list do
        GenServer.reply(from, {:error, :timeout})
        Map.put(ports, portnum, {List.delete(list, from), options})
      else
        ports
      end

    {:noreply, %Acceptor{state | ports: ports}}
  end

  @impl true
  def handle_continue({:restore, backup}, state) do
    state =
      Enum.reduce(backup, state, fn {portnum, {_list, listener_options}}, state ->
        {:reply, _, state} = handle_call({:open, portnum, listener_options}, nil, state)
        state
      end)

    {:noreply, state}
  end

  defp do_close(portnum, state = %Acceptor{ports: ports, local_ports: local, backup: backup}) do
    {list, _options} = Map.get(ports, portnum, {[], nil})
    Enum.each(list, fn from -> GenServer.reply(from, {:error, :port_closed}) end)

    if pid = Map.get(local, portnum) do
      GenServer.stop(pid, :closed, 1_000)
    end

    %Acceptor{
      state
      | ports: Map.delete(ports, portnum),
        local_ports: Map.delete(local, portnum),
        backup: Map.delete(backup, portnum)
    }
  end

  defp opt_callback(listener_options) do
    case Keyword.fetch(listener_options, :callback) do
      {:ok, callback} when is_function(callback, 1) -> callback
      {:ok, _other} -> :invalid_callback
      :error -> nil
    end
  end

  defp opt_print?(listener_options) do
    Keyword.get(listener_options, :print?, false)
  end
end
