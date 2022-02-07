defmodule DiodeClient.Port do
  alias DiodeClient.{Acceptor, Control, Port, Certs, Connection, Wallet}
  use GenServer
  use DiodeClient.Log

  defstruct [:conn, :peer, :portnum, :port_ref, :opts, :controlling_process, :queue]

  def start_link(conn, port_ref, portnum \\ nil, peer \\ nil) do
    case GenServer.start_link(__MODULE__, [conn, port_ref, portnum, peer], hibernate_after: 5_000) do
      {:ok, pid} ->
        Process.monitor(pid)
        {:ok, pid}

      other ->
        other
    end
  end

  @impl true
  def init([conn, port_ref, portnum, peer]) do
    {:ok,
     %Port{
       conn: conn,
       peer: peer,
       portnum: portnum,
       port_ref: port_ref,
       opts: %{
         mode: :binary,
         active: false,
         packet: :raw,
         packet_size: 4096,
         header: 0
       },
       controlling_process: nil,
       queue: :queue.new()
     }}
  end

  defp transport_option(pid) do
    {:ok, {:undefined, remote}} = peername(pid)

    Connection.ssl_options()
    |> Keyword.put(:cb_info, {Port, Port.Msg, Port.Closed, Port.Error})
    |> Keyword.put(:verify_fun, {&__MODULE__.check_remote/3, Wallet.from_address(remote)})
  end

  def update_peer_port(pid, peer, portnum) do
    GenServer.call(pid, {:update_peer_port, peer, portnum})
  end

  def setopts(pid, opts) do
    # log("Port.setopts: ~p ~p", [pid, opts])
    GenServer.call(pid, {:setopts, opts})
  end

  def getopts(pid, opts) do
    # log("Port.getopts: ~p ~p", [pid, opts])
    {:ok, GenServer.call(pid, {:getopts, opts})}
  end

  def peername(pid) do
    # log("Port.peername: ~p", [pid])
    {:ok, GenServer.call(pid, :peername)}
  end

  def sockname(_pid) do
    {:ok, {:undefined, :none}}
    # log("Port.sockname: ~p", [pid])
    # {:ok, GenServer.call(pid, :sockname)}
  end

  def port(pid) do
    # log("Port.port: ~p", [pid])
    {:ok, GenServer.call(pid, :portnum)}
  end

  def shutdown(_pid, :write) do
    :ok
  end

  def shutdown(pid, _mode) do
    close(pid)
  end

  def close(%Acceptor.Listener{} = listener) do
    Acceptor.close(listener)
  end

  def close(pid) when is_pid(pid) do
    GenServer.cast(pid, :stop)
  end

  def peer(pid) when is_pid(pid) do
    {:ok, {:undefined, peer}} = peername(pid)
    peer
  end

  def peer(ssl) when is_tuple(ssl) do
    Wallet.from_pubkey(Certs.extract(ssl)) |> Wallet.address!()
  end

  def controlling_process(pid, cpid) do
    # log("Port.controlling_process: ~p ~p", [pid, cpid])
    GenServer.call(pid, {:controlling_process, cpid})
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, reason}, state = %Port{controlling_process: cpid}) do
    if cpid == pid do
      {:stop, reason, state}
    else
      {:noreply, state}
    end
  end

  @impl true
  def handle_cast(:stop, state) do
    {:stop, :normal, state}
  end

  def handle_cast({:send, msg}, state = %Port{queue: queue}) do
    # log("Port.recv: ~p bytes (~p)", [
    #   byte_size(msg),
    #   DiodeClient.Base16.encode(:crypto.hash(:md5, msg))
    # ])

    state =
      %Port{state | queue: :queue.in(msg, queue)}
      |> flush()

    {:noreply, state}
  end

  @impl true
  def handle_call({:controlling_process, new_cpid}, _, state = %Port{controlling_process: cpid}) do
    if cpid != nil do
      Process.unlink(cpid)
    end

    if new_cpid != nil do
      Process.link(new_cpid)
      Process.monitor(new_cpid)
    end

    {:reply, :ok, %Port{state | controlling_process: new_cpid}}
  end

  def handle_call({:update_peer_port, peer, portnum}, _, state) do
    {:reply, :ok, %Port{state | peer: peer, portnum: portnum}}
  end

  def handle_call({:setopts, new_opts}, _, state = %Port{opts: opts}) do
    opts =
      Enum.reduce(new_opts, opts, fn {key, value}, opts ->
        Map.put(opts, key, value)
      end)

    {:reply, :ok, flush(%Port{state | opts: opts})}
  end

  def handle_call({:send_out, msg}, _, state = %Port{port_ref: port_ref, conn: conn}) do
    Connection.rpc_async(conn, ["portsend", port_ref, msg])
    {:reply, :ok, state}
  end

  def handle_call(cmd, _, state = %Port{peer: peer}) do
    ret =
      case cmd do
        {:getopts, opts} -> Enum.map(opts, fn opt -> {opt, Map.get(state.opts, opt)} end)
        :sockname -> {:undefined, :none}
        :peername -> {:undefined, peer}
        :portnum -> 0
      end

    {:reply, ret, state}
  end

  @packet_limit 65000
  def send(pid, msg) do
    msg = :erlang.iolist_to_binary(msg)

    if byte_size(msg) > @packet_limit do
      rest = binary_part(msg, @packet_limit, byte_size(msg) - @packet_limit)
      msg = binary_part(msg, 0, @packet_limit)

      case Port.send(pid, msg) do
        :ok -> Port.send(pid, rest)
        err -> err
      end
    else
      try do
        GenServer.call(pid, {:send_out, msg}, :infinity)
      catch
        :exit, msg -> {:error, msg}
      end
    end
  end

  def chunk_size() do
    131_071
  end

  def sendfile(socket, filename, offset, bytes)
      when is_list(filename) or is_atom(filename) or is_binary(filename) do
    case :file.open(filename, [:read, :raw, :binary]) do
      {:ok, raw_file} ->
        if offset != 0 do
          {:ok, _} = :file.position(raw_file, {:bof, offset})
        end

        try do
          sendfile_loop(socket, raw_file, bytes, 0, chunk_size())
        after
          :ok = :file.close(raw_file)
        end

      {:error, _reason} = error ->
        error
    end
  end

  def sendfile(socket, raw_file, offset, bytes) do
    initial =
      case :file.position(raw_file, {:cur, 0}) do
        {:ok, ^offset} ->
          offset

        {:ok, initial} ->
          {:ok, _} = :file.position(raw_file, {:bof, offset})
          initial
      end

    case sendfile_loop(socket, raw_file, bytes, 0, chunk_size()) do
      {:ok, _sent} = ret ->
        {:ok, _} = :file.position(raw_file, {:bof, initial})
        ret

      {:error, _reason} = error ->
        error
    end
  end

  defp sendfile_loop(_socket, _raw_file, sent, sent, _chunk_size) when sent != 0 do
    # All requested data has been read and sent, return number of bytes sent.
    {:ok, sent}
  end

  defp sendfile_loop(socket, raw_file, bytes, sent, chunk_size) do
    case :file.read(raw_file, read_size(bytes, sent, chunk_size)) do
      {:ok, io_data} ->
        case __MODULE__.send(socket, io_data) do
          :ok ->
            sent2 = :erlang.iolist_size(io_data) + sent
            sendfile_loop(socket, raw_file, bytes, sent2, chunk_size)

          {:error, _reason} = error ->
            error
        end

      :eof ->
        {:ok, sent}

      {:error, _reason} = error ->
        error
    end
  end

  defp read_size(0, _sent, chunk_size) do
    chunk_size
  end

  defp read_size(bytes, sent, chunk_size) do
    Kernel.min(bytes - sent, chunk_size)
  end

  @impl true
  def terminate(reason, %Port{controlling_process: cpid}) do
    log("Port.terminate(~p, ~p)", [reason, cpid])
    if cpid != nil, do: Kernel.send(cpid, {Port.Closed, self()})
  end

  @tls_timeout 60_000
  @dialyzer {:nowarn_function, tls_connect: 1}
  def tls_connect(pid) do
    opts = transport_option(pid)
    :ssl.connect(pid, opts, @tls_timeout)
  end

  def tls_handshake(pid) do
    opts = transport_option(pid)
    :ssl.handshake(pid, opts, @tls_timeout)
  end

  def check_remote(cert, event, remote) do
    case event do
      {:bad_cert, :selfsigned_peer} ->
        actual = Wallet.from_pubkey(Certs.id_from_der(cert))

        if Wallet.equal?(remote, actual) do
          {:valid, remote}
        else
          {:fail, event}
        end

      _ ->
        {:fail, event}
    end
  end

  def monitor({:sslsocket, {Port, port, _type, _xtra}, _pids}) when is_pid(port) do
    Process.monitor(port)
  end

  def monitor(_other) do
    :ok
  end

  defp flush(state = %Port{controlling_process: cpid, queue: queue, opts: opts}) do
    active = opts[:active]

    if :queue.is_empty(queue) or active == false or active == 0 do
      # log("Port.noflush: ~p ~p", [:queue.len(queue), active])
      state
    else
      {{:value, msg}, queue} = :queue.out(queue)
      Kernel.send(cpid, {Port.Msg, self(), msg})

      if active == 1 do
        Kernel.send(cpid, {Port.Msg_passive, self()})
      end

      active =
        case active do
          true -> true
          n when n > 1 -> n - 1
          _other -> false
        end

      %Port{state | opts: %{opts | active: active}, queue: queue}
      |> flush()
    end
  end

  def connect(destination, port, options \\ []) when is_integer(port) do
    access = Keyword.get(options, :access, "rw")
    local = Keyword.get(options, :local, true)

    if access == "rw" and local do
      case Control.resolve_local(destination, port) do
        nil -> do_connect(destination, port, options)
        ssl -> {:ok, ssl}
      end
    else
      do_connect(destination, port, options)
    end
  end

  defp do_connect(destination, port, options) do
    access = Keyword.get(options, :access, "rw")

    DiodeClient.default_conn()
    |> DiodeClient.Connection.rpc([
      "portopen",
      destination,
      port,
      access
    ])
    |> case do
      ["ok", pid] ->
        update_peer_port(pid, destination, port)
        tls_connect(pid)

      [:error, reason] ->
        {:error, reason}
    end
  end

  defdelegate listen(portnum, opts \\ []), to: DiodeClient.Acceptor
  defdelegate accept(portnum, timeout \\ :infinity), to: DiodeClient.Acceptor
end
