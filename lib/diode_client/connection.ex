defmodule DiodeClient.Connection do
  alias DiodeClient.{
    Acceptor,
    Certs,
    Connection,
    Manager,
    Port,
    Random,
    Rlp,
    Rlpx,
    Secp256k1,
    Ticket,
    Wallet
  }

  import Ticket
  use GenServer
  use DiodeClient.Log

  @ticket_grace 1024 * 1024
  @ticket_size @ticket_grace * 4
  @vsn 1000
  @ping 15_000
  @inital_latency 100_000_000_000_000

  defmodule Cmd do
    defstruct [:cmd, :reply, :send_reply, :port, :time, :size]
  end

  defmodule Channel do
    defstruct [:times, :backlog]

    def latency(%Channel{times: queue}) do
      case :queue.peek(queue) do
        :empty -> 0
        {:value, t} -> System.monotonic_time() - t
      end
    end

    def empty?(%Channel{times: tq, backlog: bq}) do
      :queue.is_empty(tq) and bq == []
    end

    def size(%Channel{backlog: bq}) do
      :erlang.iolist_size(bq)
    end
  end

  @enforce_keys [:events, :fleet, :server, :port]
  defstruct recv_id: %{},
            ports: %{},
            channels: %{},
            channel_usage: 0,
            unpaid_bytes: 0,
            paid_bytes: 0,
            conns: 1,
            events: nil,
            fleet: nil,
            server: nil,
            port: nil,
            latency: @inital_latency,
            server_wallet: nil,
            socket: nil,
            peak: nil,
            pending_tickets: %{},
            ticket_count: 0,
            blocked: []

  def start_link(server, port, id) do
    GenServer.start_link(__MODULE__, [server, port],
      name: id,
      hibernate_after: 5_000
    )
  end

  def init([server, port]) do
    Process.flag(:trap_exit, true)
    {conns, bytes} = {1, 0}

    state = %Connection{
      recv_id: %{},
      unpaid_bytes: bytes,
      paid_bytes: bytes,
      conns: conns,
      events: :queue.new(),
      fleet: fleet_address(),
      server: server,
      port: port
    }

    {:ok, state, {:continue, :init}}
  end

  def latency(pid) do
    Manager.get_connection_info(pid, :latency) || @inital_latency
  end

  def server_address(pid) do
    Manager.get_connection_info(pid, :server_address) || ""
  end

  def peak(pid) do
    call(pid, :peak)
  end

  def handle_continue(:init, state = %Connection{server: server}) do
    log("DiodeClient creating connection to #{server}")
    {:ok, socket} = connect(state)
    server_wallet = Wallet.from_pubkey(Certs.extract(socket))

    :ok = :ssl.setopts(socket, active: true)
    set_keepalive(socket)

    :timer.send_interval(@ping, :ping)

    pid = self()
    spawn_link(fn -> handshake(pid) end)

    # Updating ets state cache
    state = update_info(%Connection{state | socket: socket, server_wallet: server_wallet})
    {:noreply, state}
  end

  defp update_info(state = %Connection{server_wallet: wallet, latency: latency, peak: peak}) do
    address = if wallet == nil, do: nil, else: Wallet.address!(wallet)
    Manager.update_info(self(), %{latency: latency, server_address: address, peak: peak})
    state
  end

  defp connect(state = %Connection{server: server, port: port}, count \\ 0) do
    backoff = fib(count) * 1_000

    if backoff > 0 do
      log("DiodeClient.Connect delayed by #{backoff}ms")
      Process.sleep(backoff)
    end

    :ssl.connect(String.to_charlist(server), port, ssl_options(), 5000)
    |> case do
      {:ok, socket} ->
        {:ok, socket}

      {:error, reason} ->
        log("DiodeClient.Connect failed to #{server}: #{reason}")

        %{state | latency: @inital_latency}
        |> update_info()
        |> connect(count + 1)
    end
  end

  # 0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 377, 610, 987, 1597, 2584, 4181, 6765, 10946, 17711, 28657, 46368, 75025, 121393, 196418, 317811
  def fib(0), do: 0

  def fib(n) when n >= 14, do: fib(n - 1)

  def fib(n) do
    {ret, _} =
      Enum.reduce(1..n, {0, 1}, fn _n, {i, j} ->
        {i + j, i}
      end)

    ret
  end

  defp insert_cmd(
         state = %Connection{recv_id: recv_id, channels: channels},
         req,
         cmd = %Cmd{port: id, time: time},
         rlp
       ) do
    default = fn -> %Channel{times: :queue.new(), backlog: []} end
    ch = Map.get_lazy(channels, id, default)
    ch = %Channel{ch | times: :queue.in(time, ch.times), backlog: ch.backlog ++ [[req, rlp]]}
    channels = Map.put(channels, id, ch)

    sched_cmd(%Connection{
      state
      | recv_id: Map.put(recv_id, req, cmd),
        channels: channels
    })
  end

  defp pop_cmd(
         state = %Connection{recv_id: recv_id, channels: channels, channel_usage: usage},
         req,
         %Cmd{port: id, time: time, size: size}
       ) do
    ch = %Channel{times: queue} = Map.fetch!(channels, id)
    {_, queue} = :queue.out(queue)
    ch = %Channel{ch | times: queue}

    channels =
      if Channel.empty?(ch) do
        Map.delete(channels, id)
      else
        Map.put(channels, id, ch)
      end

    latency = System.monotonic_time() - time

    sched_cmd(%Connection{
      state
      | recv_id: Map.delete(recv_id, req),
        channels: channels,
        channel_usage: usage - size,
        latency: latency
    })
    |> update_info()
  end

  @usage_limit 128_000
  defp sched_cmd(state = %Connection{channel_usage: usage}) when usage > @usage_limit do
    state
  end

  defp sched_cmd(state = %Connection{channels: channels, channel_usage: usage, recv_id: recv_id}) do
    Enum.reject(channels, fn {_, %Channel{backlog: backlog}} -> backlog == [] end)
    |> Enum.min(fn {_, a}, {_, b} -> Channel.size(a) < Channel.size(b) end, fn -> nil end)
    |> case do
      {id, ch = %Channel{backlog: [[req, rlp] | backlog]}} ->
        state = ssl_send!(state, rlp)
        state = maybe_create_ticket(state)
        %Cmd{send_reply: reply} = Map.fetch!(recv_id, req)
        if reply != nil, do: GenServer.reply(reply, :ok)
        channels = Map.put(channels, id, %Channel{ch | backlog: backlog})
        sched_cmd(%Connection{state | channels: channels, channel_usage: usage + byte_size(rlp)})

      nil ->
        state
    end
  end

  def handle_call({:rpc, cmd, req, rlp, time, pid}, from, state) do
    cmd = %Cmd{cmd: cmd, reply: from, time: time, port: pid, size: byte_size(rlp)}
    {:noreply, insert_cmd(state, req, cmd, rlp)}
  end

  def handle_call({:rpc_async, cmd, req, rlp, time, pid}, from, state) do
    cmd = %Cmd{cmd: cmd, send_reply: from, time: time, port: pid, size: byte_size(rlp)}
    {:noreply, insert_cmd(state, req, cmd, rlp)}
  end

  def handle_call(:peak, from, state = %Connection{peak: nil, blocked: blocked}) do
    {:noreply, %Connection{state | blocked: [from | blocked]}}
  end

  def handle_call(:peak, _from, state = %Connection{peak: peak}) do
    {:reply, peak, state}
  end

  def handle_cast({:rpc, cmd, req, rlp, time, pid}, state) do
    cmd = %Cmd{cmd: cmd, reply: nil, time: time, port: pid, size: byte_size(rlp)}
    {:noreply, insert_cmd(state, req, cmd, rlp)}
  end

  defp handshake(pid) do
    ["ok"] = rpc(pid, ["hello", @vsn])
    :ok = update_block(pid)
  end

  defp to_bin(num) do
    Rlpx.uint2bin(num)
  end

  defp to_num(bin) do
    Rlpx.bin2uint(bin)
  end

  def check(_cert, event, state) do
    case event do
      {:bad_cert, :selfsigned_peer} -> {:valid, state}
      _ -> {:fail, event}
    end
  end

  defp maybe_create_ticket(
         state = %Connection{unpaid_bytes: ub, paid_bytes: pb, ticket_count: tc},
         force \\ false
       ) do
    if force or ub >= pb + @ticket_grace do
      {req, state} = do_create_ticket(state)

      if tc < 3 do
        wait_for_ticket(req, state)
      else
        state
      end
    else
      state
    end
  end

  defp do_create_ticket(
         state = %Connection{
           conns: conns,
           unpaid_bytes: unpaid_bytes,
           paid_bytes: paid_bytes,
           peak: peak,
           server_wallet: server_wallet,
           pending_tickets: pending_tickets,
           ticket_count: tc
         }
       ) do
    count =
      div(unpaid_bytes + 400 - paid_bytes, @ticket_size)
      |> max(1)

    # {:ok, stats} = :ssl.getstat(state.socket, [:send_pend])
    # log("do_create_ticket: ~p ~p ~p", [count, unpaid_bytes, stats])
    # if rem(tc, 60) == 0 do
    #   :io.format(".~n")
    # else
    #   :io.format(".")
    # end

    # Definining an alternative node hint
    # <<0>> means it's a preferred node
    # <<1>> means it's a secondary node
    me = self()
    alt = DiodeClient.connections() |> Enum.find(fn pid -> pid != me end)

    local =
      case DiodeClient.default_conn() do
        ^me -> <<1>> <> server_address(alt)
        nil -> <<1>> <> server_address(alt)
        pid -> <<0>> <> server_address(pid)
      end

    tck =
      ticket(
        server_id: Wallet.address!(server_wallet),
        total_connections: conns,
        total_bytes: paid_bytes + @ticket_size * count,
        local_address: local,
        block_number: to_num(peak["number"]),
        block_hash: peak["block_hash"],
        fleet_contract: fleet_address()
      )
      |> Ticket.device_sign(Wallet.privkey!(DiodeClient.wallet()))

    data = [
      "ticket",
      Ticket.block_number(tck),
      Ticket.fleet_contract(tck),
      Ticket.total_connections(tck),
      Ticket.total_bytes(tck),
      Ticket.local_address(tck),
      Ticket.device_signature(tck)
    ]

    req = req_id()
    # log("maybe_create_ticket => ~p", [data])
    msg = Rlp.encode!([req, data])

    state = %Connection{
      state
      | pending_tickets: Map.put(pending_tickets, req, tck),
        paid_bytes: Ticket.total_bytes(tck),
        ticket_count: tc + 1
    }

    {req, ssl_send!(state, msg)}
  end

  defp wait_for_ticket(
         req,
         state = %Connection{
           events: events,
           unpaid_bytes: unpaid_bytes,
           pending_tickets: pending_tickets,
           socket: socket
         }
       ) do
    msg =
      receive do
        {:ssl, ^socket, msg} -> msg
      after
        5000 -> throw(:missing_ticket_reply)
      end

    # log("wait_for_ticket => ~p", [Rlp.decode!(msg)])

    case Rlp.decode!(msg) do
      [^req, reply] ->
        tck = Map.get(pending_tickets, req)
        state = %Connection{state | unpaid_bytes: unpaid_bytes + byte_size(msg)}
        handle_ticket(state, tck, [req, reply])

      _other ->
        wait_for_ticket(req, %Connection{state | events: :queue.in(msg, events)})
    end
  end

  def handle_ticket(
        state = %Connection{
          unpaid_bytes: unpaid_bytes,
          pending_tickets: pending_tickets
        },
        _tck,
        [req, reply]
      ) do
    state = %Connection{state | pending_tickets: Map.delete(pending_tickets, req)}

    case reply do
      ["response", "thanks!", _bytes] ->
        state

      ["response", "too_low", _peak, rlp_conns, rlp_bytes, _address, _signature] ->
        new_bytes = to_num(rlp_bytes)
        new_conns = to_num(rlp_conns)

        state =
          if new_bytes > unpaid_bytes do
            # this must be a continuiation of a previous connection
            %Connection{
              state
              | conns: new_conns,
                paid_bytes: new_bytes,
                unpaid_bytes: new_bytes + unpaid_bytes
            }
          else
            %Connection{state | conns: new_conns + 1}
          end

        # log("too_low: paid: ~p unpaid: ~p", [state.paid_bytes, state.unpaid_bytes])
        {req, state} = do_create_ticket(state)
        wait_for_ticket(req, state)
    end
  end

  def handle_info({:DOWN, _ref, :process, pid, _reason}, state = %Connection{ports: ports}) do
    Enum.find(ports, fn {_port_ref, {port_pid, _status}} -> pid == port_pid end)
    |> case do
      {ref, {_pid, status}} ->
        if status == :up, do: rpc_cast(self(), ["portclose", ref])
        {:noreply, %Connection{state | ports: Map.put(ports, ref, {pid, :down})}}

      nil ->
        # This just means :EXIT was handled before :DOWN
        # log("received down for unknown port ~p: ~p", [pid, reason])
        {:noreply, state}
    end
  end

  def handle_info({:EXIT, pid, reason}, state = %Connection{ports: ports, socket: socket}) do
    # When a port crashes we just clean it up, but don't need to follow
    # Others though we might need to follow, so we hard match here
    Enum.find(ports, fn {_port_ref, {port_pid, _status}} -> pid == port_pid end)
    |> case do
      {ref, {_pid, status}} ->
        log("removing port ~p: ~p ~180p", [ref, pid, reason])
        if status == :up, do: rpc_cast(self(), ["portclose", ref])
        {:noreply, %Connection{state | ports: Map.delete(ports, ref)}}

      nil ->
        if reason != :normal do
          log("other pid crashed: ~180p", [reason])
          if socket != nil, do: :ssl.close(socket)
          # This might be a parent exiting
          {:stop, reason, state}
        else
          {:noreply, state}
        end
    end
  end

  def handle_info(what, state) do
    state = maybe_create_ticket(state)

    case clientloop(what, state) do
      {:noreply, state = %Connection{socket: socket}} ->
        if not :queue.is_empty(state.events) do
          {{:value, msg}, events} = :queue.out(state.events)
          handle_info({:ssl, socket, msg}, %Connection{state | events: events})
        else
          {:noreply, state}
        end

      other ->
        other
    end
  end

  defp clientloop(what, state = %Connection{socket: socket, server: server, blocked: blocked}) do
    case what do
      {:ssl, ^socket, rlp} ->
        {:noreply, handle_msg(rlp, state)}

      {:ssl, wrong_socket, _rlp} ->
        log("DiodeClient flushing ssl #{inspect(wrong_socket)} != #{inspect(socket)}")
        {:noreply, state}

      {:ssl_closed, ^socket} ->
        log("DiodeClient.ssl_closed() #{server}")
        {:noreply, reset(state), {:continue, :init}}

      {:ssl_closed, wrong_socket} ->
        log("DiodeClient flushing ssl_close #{inspect(wrong_socket)} != #{inspect(socket)}")

        {:noreply, state}

      {pid, :quit} ->
        send(pid, {:ret, :ok})
        {:stop, :quit, state}

      {pid, :bytes} ->
        send(pid, {:ret, state.unpaid_bytes - state.paid_bytes})
        {:noreply, state}

      {pid, :ping} ->
        send(pid, {:ret, :pong})
        {:noreply, state}

      {pid, :peerid} ->
        send(pid, {:ret, Wallet.from_pubkey(Certs.extract(socket))})
        {:noreply, state}

      {:peak, peak} ->
        Enum.each(blocked, fn from ->
          GenServer.reply(from, peak)
        end)

        state =
          %Connection{state | peak: peak, blocked: []}
          |> update_info()
          |> maybe_create_ticket(state.peak == nil)

        {:noreply, state}

      :ping ->
        pid = self()
        Debouncer.immediate(pid, fn -> update_block(pid) end, @ping)
        {:noreply, state}

      msg ->
        log("Unhandled: #{inspect(msg)}")
        {:stop, :unhandled, state}
    end
  end

  defp reset(state = %Connection{ports: ports, recv_id: recv_id, conns: conns, channels: chs}) do
    Enum.each(ports, fn {_, {pid, status}} ->
      Process.unlink(pid)
      if status == :up, do: Port.close(pid)

      receive do
        {:EXIT, ^pid, _reason} -> :ok
      after
        0 -> :ok
      end
    end)

    Enum.each(recv_id, fn {req, %Cmd{reply: reply}} ->
      if reply != nil, do: GenServer.reply(reply, [req, ["error", "remote_closed"]])
    end)

    Enum.each(chs, fn {_, %Channel{backlog: backlog}} ->
      Enum.each(backlog, fn [req, _rlp] ->
        %Cmd{send_reply: reply} = Map.fetch!(recv_id, req)
        if reply != nil, do: GenServer.reply(reply, {:error, :remote_closed})
      end)
    end)

    %Connection{
      state
      | events: :queue.new(),
        socket: nil,
        channels: %{},
        channel_usage: 0,
        peak: nil,
        ports: %{},
        recv_id: %{},
        conns: conns + 1,
        ticket_count: 0,
        pending_tickets: %{}
    }
  end

  defp update_block(pid) do
    case rpc(pid, ["getblockpeak"]) do
      [num] ->
        [block] = rpc(pid, ["getblockheader", to_num(num) - 3])
        send(pid, {:peak, Rlpx.list2map(block)})
        :ok

      error ->
        error
    end
  end

  defp handle_msg(
         rlp,
         state = %Connection{
           unpaid_bytes: ub,
           ports: ports,
           recv_id: recv_id,
           pending_tickets: pending_tickets
         }
       ) do
    state = %Connection{state | unpaid_bytes: ub + byte_size(rlp)}

    msg = [req | _rest] = Rlp.decode!(rlp)

    case Map.get(recv_id, req) do
      nil ->
        case Map.get(pending_tickets, req) do
          nil -> handle_request(state, msg)
          tck -> handle_ticket(state, tck, msg)
        end

      # log("handle_msg => ~p", [msg])

      cmd = %Cmd{cmd: name, reply: from} ->
        {msg, state} =
          case {name, msg} do
            {"portopen", [^req, ["response", "ok", port_ref]]} ->
              {:ok, pid} = Port.start_link(self(), port_ref)

              {[req, ["response", "ok", pid]],
               %Connection{state | ports: Map.put(ports, port_ref, {pid, :up})}}

            _other ->
              {msg, state}
          end

        if from != nil, do: GenServer.reply(from, msg)
        # log("handle_msg reply ~p => ~p", [name, msg])
        pop_cmd(state, req, cmd)
    end
  end

  defp handle_request(
         state = %Connection{ports: ports},
         [ref, [command | params]]
       ) do
    case {command, params} do
      {"block", [_num]} ->
        state

      {"ping", []} ->
        {state, ["response", "pong"]}

      {"portopen", [port, port_ref, from]} ->
        port = to_num(port)

        {:ok, pid} = Port.start_link(self(), port_ref, port, from)

        {state, msg} =
          case GenServer.call(Acceptor, {:inject, port, pid}) do
            :ok ->
              state = %Connection{state | ports: Map.put(ports, port_ref, {pid, :up})}
              msg = ["response", port_ref, "ok"]
              {state, msg}

            {:error, message} ->
              Process.unlink(pid)
              Port.close(pid)
              {state, ["error", port_ref, inspect(message)]}
          end

        msg = Rlp.encode!([ref, msg])
        ssl_send!(state, msg)

      {"portsend", [port_ref, msg]} ->
        with {pid, :up} <- ports[port_ref] do
          GenServer.cast(pid, {:send, msg})
        end

        state

      {"portclose", [port_ref]} ->
        log("Received portclose for ~180p", [port_ref])

        with {pid, :up} <- ports[port_ref] do
          Port.close(pid)
          %Connection{state | ports: Map.put(ports, port_ref, {pid, :down})}
        else
          _other -> state
        end

      other ->
        log("Ignoring unknown server event ~p", [other])
    end
  end

  def rpc(pid, [cmd | _rest] = data) do
    req = req_id()
    rlp = Rlp.encode!([req | [data]])

    call(pid, {:rpc, cmd, req, rlp, System.monotonic_time(), self()})
    |> case do
      [^req, ["error" | rest]] -> [:error | rest]
      [^req, ["response" | rest]] -> rest
    end
  end

  def rpc_async(pid, [cmd | _rest] = data) do
    req = req_id()
    rlp = Rlp.encode!([req | [data]])
    call(pid, {:rpc_async, cmd, req, rlp, System.monotonic_time(), self()})
  end

  defp call(pid, args) do
    GenServer.call(pid, args, :infinity)
  end

  def rpc_cast(pid, [cmd | _rest] = data) do
    req = req_id()
    rlp = Rlp.encode!([req | [data]])
    GenServer.cast(pid, {:rpc, cmd, req, rlp, System.monotonic_time(), self()})
  end

  defp req_id() do
    Random.uint31h()
    |> to_bin()
  end

  def ssl_options() do
    wallet = DiodeClient.wallet()
    private = Wallet.privkey!(wallet)
    public = Wallet.pubkey_long!(wallet)
    cert = Secp256k1.selfsigned(private, public)

    [
      mode: :binary,
      packet: 2,
      cert: cert,
      cacerts: [cert],
      versions: [:"tlsv1.2"],
      verify: :verify_peer,
      verify_fun: {&__MODULE__.check/3, nil},
      fail_if_no_peer_cert: true,
      eccs: [:secp256k1],
      active: false,
      reuseaddr: true,
      key: {:ECPrivateKey, Secp256k1.der_encode_private(private, public)},
      delay_send: true,
      reuse_sessions: true,
      send_timeout: 30_000,
      send_timeout_close: true
    ]
  end

  defp ssl_send!(state = %Connection{socket: socket, unpaid_bytes: up}, msg) do
    # IO.puts("send size: #{byte_size(msg)}")
    :ok = :ssl.send(socket, msg)
    %Connection{state | unpaid_bytes: up + byte_size(msg)}
  end

  defp fleet_address() do
    Base.decode16!("6000000000000000000000000000000000000000")
  end

  defp set_keepalive(socket) do
    set_keepalive(:os.type(), socket)
  end

  # 4.2. The setsockopt function call
  #
  #   All you need to enable keepalive for a specific socket is to set the specific socket option on the socket itself.
  #   The prototype of the function is as follows:
  #
  #   int setsockopt(int s, int level, int optname,
  #                   const void *optval, socklen_t optlen)
  #
  #   The first parameter is the socket, previously created with the socket(2); the second one must be
  #   SOL_SOCKET, and the third must be SO_KEEPALIVE . The fourth parameter must be a boolean integer value, indicating
  #   that we want to enable the option, while the last is the size of the value passed before.
  #
  #   According to the manpage, 0 is returned upon success, and -1 is returned on error (and errno is properly set).
  #
  #   There are also three other socket options you can set for keepalive when you write your application. They all use
  #   the SOL_TCP level instead of SOL_SOCKET, and they override system-wide variables only for the current socket. If
  #   you read without writing first, the current system-wide parameters will be returned.
  #
  #   TCP_KEEPCNT: the number of unacknowledged probes to send before considering the connection dead and notifying the
  #   application layer
  #
  #   TCP_KEEPIDLE: the interval between the last data packet sent (simple ACKs are not considered data) and the first
  #   keepalive probe; after the connection is marked to need keepalive, this counter is not used any further
  #
  #   TCP_KEEPINTVL: the interval between subsequential keepalive probes, regardless of what the connection has
  #   exchanged in the meantime
  defp set_keepalive({:unix, :linux}, socket) do
    sol_socket = 1
    so_keepalive = 9

    ipproto_tcp = 6
    tcp_keepcnt = 6
    tcp_keepidle = 4
    tcp_keepintvl = 5

    :ok = set_tcpopt(socket, sol_socket, so_keepalive, 1)
    :ok = set_tcpopt(socket, ipproto_tcp, tcp_keepcnt, 5)
    :ok = set_tcpopt(socket, ipproto_tcp, tcp_keepidle, 60)
    :ok = set_tcpopt(socket, ipproto_tcp, tcp_keepintvl, 60)
    :ok
  end

  defp set_keepalive(_other, socket) do
    :ok = :ssl.setopts(socket, keepalive: true)
    :ok
  end

  defp set_tcpopt(socket, level, opt, value) do
    :ssl.setopts(socket, [{:raw, level, opt, <<value::unsigned-little-size(32)>>}])
  end
end
