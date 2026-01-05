defmodule DiodeClient.Connection do
  @moduledoc false
  alias DiodeClient.{
    Acceptor,
    Base16,
    Block,
    Certs,
    Connection,
    Manager,
    Port,
    Random,
    Rlp,
    Rlpx,
    Secp256k1,
    Ticket,
    TicketV1,
    TicketV2,
    Wallet
  }

  import TicketV1
  import TicketV2
  use GenServer
  require Logger

  @ticket_grace 1024 * 1024
  @ticket_size @ticket_grace * 4
  @vsn 1000
  @ping 3_000
  @inital_latency 100_000_000_000_000
  @packet_header 2

  defmodule Cmd do
    @moduledoc false
    defstruct [:cmd, :reply, :send_reply, :port, :time, :size]
  end

  defmodule Channel do
    @moduledoc false
    alias DiodeClient.Connection
    defstruct [:times, :backlog]

    def latency(%Channel{times: queue}) do
      case :queue.peek(queue) do
        :empty -> 0
        {:value, t} -> Connection.timestamp() - t
      end
    end

    def empty?(%Channel{times: tq, backlog: bq}) do
      :queue.is_empty(tq) and bq == []
    end

    def size(%Channel{backlog: bq}) do
      :erlang.iolist_size(bq)
    end
  end

  @enforce_keys [:events, :fleet, :server, :server_ports]
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
            server_ports: nil,
            latency: @inital_latency,
            server_wallet: nil,
            socket: nil,
            ticket_shell: nil,
            shells: nil,
            peaks: %{},
            pending_tickets: %{},
            ticket_count: 0,
            last_ticket: nil,
            blocked: [],
            shutdown: false

  def start_link(server, ports) when is_list(ports) do
    GenServer.start_link(__MODULE__, [server, ports], hibernate_after: 5_000)
  end

  @impl true
  def init([server, ports]) do
    Process.flag(:trap_exit, true)
    :timer.send_interval(@ping, :ping)
    {conns, bytes} = {1, 0}

    state = %Connection{
      recv_id: %{},
      unpaid_bytes: bytes,
      paid_bytes: bytes,
      conns: conns,
      events: :queue.new(),
      fleet: DiodeClient.fleet_address(),
      ticket_shell: DiodeClient.Shell.Moonbeam,
      shells: MapSet.new(DiodeClient.Manager.default_shells()),
      server: server,
      server_ports: ports
    }

    {:ok, state, {:continue, :init}}
  end

  defmacrop debug(format) do
    quote do
      Logger.debug("DiodeClient[#{var!(state).server}] " <> unquote(format))
    end
  end

  defmacrop warning(format) do
    quote do
      Logger.warning("DiodeClient[#{var!(state).server}] " <> unquote(format))
    end
  end

  def latency(pid) do
    Manager.get_connection_info(pid, :latency) || @inital_latency
  end

  def server_address(pid) do
    Manager.get_connection_info(pid, :server_address) || ""
  end

  def server_url(pid) do
    Manager.get_connection_info(pid, :server_url) || ""
  end

  def peak(pid, shell) do
    call(pid, {:peak, shell})
  end

  @impl true
  def handle_continue(:init, state = %Connection{}) do
    init_loop(state, 0)
  end

  defp update_info(
         state = %Connection{server_wallet: wallet, latency: latency, peaks: peaks, ports: ports}
       ) do
    address = if wallet == nil, do: nil, else: Wallet.address!(wallet)

    Manager.update_info(self(), %{
      latency: latency,
      server_address: address,
      peaks: peaks,
      open_port_count: map_size(ports)
    })

    state
  end

  def init_loop(state = %Connection{server_ports: ports}, count) do
    receive do
      :ping ->
        init_loop(state, count)

      msg = :stop ->
        handle_info(msg, state)

      msg = {:subscribe, _} ->
        {:noreply, state} = handle_info(msg, state)
        init_loop(state, count)
    after
      0 ->
        backoff = min(fib(count) * :timer.seconds(1), :timer.seconds(120))
        port = Enum.at(ports, rem(count, length(ports)))

        if backoff > 0 do
          debug("connect() delayed by #{backoff}ms, trying port #{port}")
          Process.sleep(backoff)
        end

        case connect(state, port) do
          {:retry, state} -> init_loop(state, count + 1)
          {:noreply, state} -> {:noreply, state}
        end
    end
  end

  defp connect(state = %Connection{server: server}, port) do
    now = timestamp()

    :ssl.connect(String.to_charlist(server), port, ssl_options(role: :client), 25_000)
    |> case do
      {:ok, socket} ->
        NetworkMonitor.close_on_down(socket, :ssl)
        state = %{state | latency: timestamp() - now}

        server_wallet = Wallet.from_pubkey(Certs.extract(socket))
        :ok = :ssl.setopts(socket, active: true)
        set_keepalive(socket)
        pid = self()

        spawn_link(fn ->
          ["ok"] = rpc(pid, ["hello", @vsn])

          for shell <- state.shells do
            :ok = update_block(pid, shell, nil)
          end
        end)

        # Updating ets state cache
        state =
          %Connection{state | socket: socket, server_wallet: server_wallet}
          |> update_info()

        {:noreply, state}

      {:error, reason} ->
        debug("connect() failed: #{inspect(reason)}")

        state = update_info(%{state | latency: @inital_latency})
        {:retry, state}
    end
  end

  def timestamp() do
    System.os_time(:millisecond)
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
    ch = %{ch | times: :queue.in(time, ch.times), backlog: ch.backlog ++ [[req, rlp]]}
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
         %Cmd{port: id, time: time, size: size, cmd: cmd}
       ) do
    ch = %Channel{times: queue} = Map.fetch!(channels, id)
    {_, queue} = :queue.out(queue)
    ch = %{ch | times: queue}

    channels =
      if Channel.empty?(ch) do
        Map.delete(channels, id)
      else
        Map.put(channels, id, ch)
      end

    latency =
      if String.ends_with?(cmd, "getblockpeak") do
        if state.latency == @inital_latency do
          timestamp() - time
        else
          (9 * state.latency + (timestamp() - time)) / 10
        end
      else
        state.latency
      end

    sched_cmd(%{
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
        %Cmd{cmd: cmd, send_reply: reply} = Map.fetch!(recv_id, req)

        if cmd in ["portopen", "portopen2"] do
          "sending #{cmd} for #{if is_binary(id), do: Base16.encode(id), else: inspect(id)}"
          |> debug()
        end

        state = ssl_send!(state, rlp)
        state = maybe_create_ticket(state)

        if reply != nil, do: GenServer.reply(reply, :ok)
        channels = Map.put(channels, id, %{ch | backlog: backlog})
        sched_cmd(%{state | channels: channels, channel_usage: usage + byte_size(rlp)})

      nil ->
        state
    end
  end

  @impl true
  def handle_call({:rpc, cmd, req, rlp, time, pid}, from, state) do
    cmd = %Cmd{cmd: cmd, reply: from, time: time, port: pid, size: byte_size(rlp)}
    {:noreply, insert_cmd(state, req, cmd, rlp)}
  end

  def handle_call({:rpc_async, cmd, req, rlp, time, pid}, from, state) do
    cmd = %Cmd{cmd: cmd, send_reply: from, time: time, port: pid, size: byte_size(rlp)}
    {:noreply, insert_cmd(state, req, cmd, rlp)}
  end

  def handle_call(
        {:peak, shell},
        from,
        state = %Connection{peaks: peaks, blocked: blocked}
      ) do
    case Map.get(peaks, shell) do
      nil ->
        {:noreply,
         %Connection{
           state
           | blocked: [{shell, from} | blocked],
             peaks: Map.put(peaks, shell, nil)
         }}

      peak ->
        {:reply, peak, state}
    end
  end

  @impl true
  def handle_cast({:rpc, cmd, req, rlp, time, pid}, state) do
    cmd = %Cmd{cmd: cmd, reply: nil, time: time, port: pid, size: byte_size(rlp)}
    {:noreply, insert_cmd(state, req, cmd, rlp)}
  end

  defp to_bin(num) do
    Rlpx.uint2bin(num)
  end

  defp to_num(bin) do
    Rlpx.bin2uint(bin)
  end

  def check(_cert, event, state) do
    case event do
      # All diode certificates are self signed
      {:bad_cert, :selfsigned_peer} -> {:valid, state}
      # Date + time of the certs is not important
      {:bad_cert, :cert_expired} -> {:valid, state}
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

  defp do_create_ticket(state = %Connection{peaks: peaks, ticket_shell: ticket_shell}) do
    peak = Map.get(peaks, ticket_shell)

    if peak == nil do
      # setting last_ticket to nil will cause a new ticket to be created as soon as blocks are synced
      {:error, %{state | last_ticket: nil}}
    else
      do_create_ticket(state, peak)
    end
  end

  defp do_create_ticket(
         state = %Connection{
           conns: conns,
           unpaid_bytes: unpaid_bytes,
           paid_bytes: paid_bytes,
           server_wallet: server_wallet,
           pending_tickets: pending_tickets,
           ticket_count: tc,
           last_ticket: last_ticket,
           ticket_shell: ticket_shell
         },
         peak
       ) do
    count =
      div(unpaid_bytes + 400 - paid_bytes, @ticket_size)
      |> max(1)

    # Definining an alternative node hint
    # <<0>> means it's a preferred node
    # <<1>> means it's a secondary node
    me = self()
    alt = DiodeClient.connections() |> Enum.find(fn pid -> pid != me end)

    local =
      case DiodeClient.Manager.get_connection?() do
        ^me -> <<1>> <> server_address(alt)
        nil -> <<1>> <> server_address(alt)
        pid -> <<0>> <> server_address(pid)
      end

    tck =
      if Block.diode?(peak) do
        ticket(
          server_id: Wallet.address!(server_wallet),
          total_connections: conns,
          total_bytes: paid_bytes + @ticket_size * count,
          local_address: local,
          block_number: Block.number(peak),
          block_hash: Block.hash(peak),
          fleet_contract: DiodeClient.fleet_address()
        )
      else
        ticketv2(
          server_id: Wallet.address!(server_wallet),
          epoch: Block.epoch(peak),
          chain_id: ticket_shell.chain_id(),
          total_connections: conns,
          total_bytes: paid_bytes + @ticket_size * count,
          local_address: local,
          fleet_contract: DiodeClient.fleet_address()
        )
      end

    if last_ticket != nil and Ticket.epoch(last_ticket) != Ticket.epoch(tck) do
      raise "DiodeClient epoch mismatch"
    end

    tck = Ticket.device_sign(tck, Wallet.privkey!(DiodeClient.wallet()))
    req = req_id()
    msg = Rlp.encode!([req, Ticket.message(tck)])

    state = %{
      state
      | pending_tickets: Map.put(pending_tickets, req, tck),
        paid_bytes: Ticket.total_bytes(tck),
        ticket_count: tc + 1,
        last_ticket: tck
    }

    {req, ssl_send!(state, msg)}
  end

  defp wait_for_ticket(:error, state) do
    state
  end

  defp wait_for_ticket(
         req,
         state = %Connection{
           events: events,
           unpaid_bytes: unpaid_bytes,
           pending_tickets: pending_tickets,
           socket: socket,
           server: server
         }
       ) do
    msg =
      receive do
        {:ssl, ^socket, msg} -> msg
      after
        15_000 -> raise "DiodeClient missing ticket reply"
      end

    case Rlp.decode!(msg) do
      [^req, reply] ->
        tck = Map.get(pending_tickets, req)
        DiodeClient.Stats.submit(:relay, server, :self, byte_size(msg) + @packet_header)
        state = %{state | unpaid_bytes: unpaid_bytes + byte_size(msg) + @packet_header}
        handle_ticket(state, tck, [req, reply])

      _other ->
        wait_for_ticket(req, %{state | events: :queue.in(msg, events)})
    end
  end

  def handle_ticket(
        state = %Connection{pending_tickets: pending_tickets},
        ticket(),
        [req, reply]
      ) do
    state = %{state | pending_tickets: Map.delete(pending_tickets, req)}

    case reply do
      ["response", "thanks!", _bytes] ->
        state

      ["response", "too_low", _peak, rlp_conns, rlp_bytes, _address, _signature] ->
        new_bytes = to_num(rlp_bytes)
        new_conns = to_num(rlp_conns)
        create_update_ticket(state, new_bytes, new_conns)
    end
  end

  def handle_ticket(state = %Connection{pending_tickets: pending_tickets}, ticketv2(), [
        req,
        reply
      ]) do
    state = %{state | pending_tickets: Map.delete(pending_tickets, req)}

    case reply do
      ["response", "thanks!", _bytes] ->
        state

      ["response", "too_low", _chain_id, _epoch, rlp_conns, rlp_bytes, _address, _signature] ->
        new_bytes = to_num(rlp_bytes)
        new_conns = to_num(rlp_conns)
        create_update_ticket(state, new_bytes, new_conns)
    end
  end

  defp create_update_ticket(state = %Connection{unpaid_bytes: unpaid_bytes}, new_bytes, new_conns) do
    state =
      if new_bytes > unpaid_bytes do
        # this must be a continuiation of a previous connection
        %{
          state
          | conns: new_conns,
            paid_bytes: new_bytes,
            unpaid_bytes: new_bytes + min(unpaid_bytes, @ticket_size)
        }
      else
        %{state | conns: new_conns + 1}
      end

    {req, state} = do_create_ticket(state)
    wait_for_ticket(req, state)
  end

  @impl true
  def handle_info({:subscribe, shell}, state = %Connection{}) do
    state = %{state | shells: MapSet.put(state.shells, shell)}
    queue_update_blocks(state)
    {:noreply, state}
  end

  def handle_info(:stop, state) do
    maybe_shutdown(%{state | shutdown: true})
  end

  def handle_info({:DOWN, _ref, :process, pid, _reason}, state = %Connection{ports: ports}) do
    Enum.find(ports, fn {_port_ref, {port_pid, _status}} -> pid == port_pid end)
    |> case do
      {ref, {_pid, status}} ->
        if status == :up, do: rpc_cast(self(), ["portclose", ref])
        {:noreply, %{state | ports: Map.put(ports, ref, {pid, :down})}}

      nil ->
        # This just means :EXIT was handled before :DOWN
        {:noreply, state}
    end
  end

  def handle_info({:EXIT, pid, reason}, state = %Connection{ports: ports, socket: socket}) do
    # When a port crashes we just clean it up, but don't need to follow
    # Others though we might need to follow, so we hard match here
    Enum.find(ports, fn {_port_ref, {port_pid, _status}} -> pid == port_pid end)
    |> case do
      {ref, {_pid, status}} ->
        debug("removing port #{Base16.encode(ref)}: #{inspect(pid)} #{inspect(reason)}")
        if status == :up, do: rpc_cast(self(), ["portclose", ref])
        maybe_shutdown(%{state | ports: Map.delete(ports, ref)})

      nil ->
        if reason != :normal do
          debug("other pid crashed: #{inspect(reason)}")
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
        if :queue.is_empty(state.events) do
          {:noreply, state}
        else
          {{:value, msg}, events} = :queue.out(state.events)
          handle_info({:ssl, socket, msg}, %{state | events: events})
        end

      other ->
        other
    end
  end

  defp clientloop({:ssl, socket, rlp}, state = %Connection{}) do
    if socket == state.socket do
      {:noreply, handle_msg(rlp, state)}
    else
      debug("flushing ssl #{inspect(socket)} != #{inspect(state.socket)}")
      {:noreply, state}
    end
  end

  defp clientloop({:ssl_closed, socket}, state = %Connection{}) do
    if socket == state.socket do
      debug("ssl_closed()")
      {:noreply, reset(state), {:continue, :init}}
    else
      debug("flushing ssl_close #{inspect(socket)} != #{inspect(state.socket)}")
      {:noreply, state}
    end
  end

  defp clientloop(what, state = %Connection{socket: socket, blocked: blocked, peaks: peaks}) do
    case what do
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

      {:peak, shell, peak} ->
        blocked =
          Enum.filter(blocked, fn {s, from} ->
            if s == shell do
              GenServer.reply(from, peak)
              false
            else
              true
            end
          end)

        state =
          %{state | peaks: Map.put(peaks, shell, peak), blocked: blocked}
          |> update_info()

        state =
          if shell == state.ticket_shell and state.last_ticket == nil,
            do: maybe_create_ticket(state, true),
            else: state

        {:noreply, state}

      :ping ->
        queue_update_blocks(state)
        {:noreply, state}

      msg ->
        warning("unhandled: #{inspect(msg)}")
        {:stop, :unhandled, state}
    end
  end

  defp queue_update_blocks(%Connection{shells: shells, peaks: peaks}, pid \\ self()) do
    for shell <- shells do
      Debouncer.immediate(
        {pid, shell},
        fn -> update_block(pid, shell, peaks[shell]) end,
        shell.block_time()
      )
    end
  end

  @block_delay 3
  defp update_block(pid, shell, peak) do
    last_peak_num = if peak == nil, do: 0, else: Block.number(peak)

    with [binnum] <- rpc(pid, [shell.prefix() <> "getblockpeak"]) do
      new_peak_num = to_num(binnum) - @block_delay

      if new_peak_num > last_peak_num do
        with [block] <- rpc(pid, [shell.prefix() <> "getblockheader", new_peak_num]) do
          send(pid, {:peak, shell, Rlpx.list2map(block)})
          :ok
        end
      end
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
        peaks: %{},
        ports: %{},
        recv_id: %{},
        conns: conns + 1,
        ticket_count: 0,
        last_ticket: nil,
        pending_tickets: %{},
        server_wallet: nil
    }
    |> update_info()
  end

  defp handle_msg(
         rlp,
         state = %Connection{
           unpaid_bytes: ub,
           ports: ports,
           recv_id: recv_id,
           pending_tickets: pending_tickets,
           server: server
         }
       ) do
    DiodeClient.Stats.submit(:relay, server, :self, byte_size(rlp) + @packet_header)
    state = %{state | unpaid_bytes: ub + byte_size(rlp) + @packet_header}
    msg = [req | _rest] = Rlp.decode!(rlp)

    case Map.get(recv_id, req) do
      nil ->
        case Map.get(pending_tickets, req) do
          nil -> handle_request(state, msg)
          tck -> handle_ticket(state, tck, msg)
        end

      cmd = %Cmd{cmd: name, reply: from} ->
        {msg, state} =
          case {name, msg} do
            {"portopen2", [^req, ["response", "ok", port_num]]} ->
              debug("received portopen2 ack for #{Base16.encode(port_num)}")
              {[req, ["response", "ok", Rlpx.bin2uint(port_num)]], state}

            {"portopen", [^req, ["response", "ok", port_ref]]} ->
              debug("received portopen ack for #{Base16.encode(port_ref)}")
              {:ok, pid} = Port.start_link(self(), port_ref)

              {[req, ["response", "ok", pid]],
               %{state | ports: Map.put(ports, port_ref, {pid, :up})}}

            _other ->
              {msg, state}
          end

        if from != nil, do: GenServer.reply(from, msg)
        pop_cmd(state, req, cmd)
    end
  end

  defp handle_request(
         state = %Connection{ports: ports},
         [ref, ["portopen", port, port_ref, from]]
       ) do
    debug("received portopen for #{Base16.encode(port_ref)}")
    port = to_num(port)

    {:ok, pid} = Port.start_link(self(), port_ref, port, from)

    {state, msg} =
      case GenServer.call(Acceptor, {:inject, port, pid}) do
        :ok ->
          state = %{state | ports: Map.put(ports, port_ref, {pid, :up})}
          msg = ["response", port_ref, "ok"]
          {state, msg}

        {:error, message} ->
          debug(
            "reject portopen on port #{port} ref: #{Base16.encode(port_ref)} reason: #{inspect(message)}"
          )

          Process.unlink(pid)
          Port.close(pid)
          {state, ["error", port_ref, inspect(message)]}
      end

    msg = Rlp.encode!([ref, msg])
    ssl_send!(state, msg)
  end

  defp handle_request(
         state = %Connection{},
         [ref, ["portopen2", port, physical_port | _rest]]
       ) do
    debug("received portopen2 for #{Base16.encode(physical_port)}")
    port = to_num(port)

    {state, msg} =
      case Port.direct_connect(server_url(self()), Rlpx.bin2uint(physical_port), :server) do
        {:error, reason} ->
          debug(
            "reject portopen2 on port #{port} ref: #{Base16.encode(physical_port)} reason: #{inspect(reason)}"
          )

          {state, ["error", physical_port, inspect(reason)]}

        {:ok, ssl} ->
          case GenServer.call(Acceptor, {:inject, port, ssl}) do
            :ok ->
              {state, ["response", physical_port, "ok"]}

            {:error, message} ->
              debug(
                "reject portopen on port #{port} ref: #{Base16.encode(physical_port)} reason: #{inspect(message)}"
              )

              :ssl.close(ssl)
              {state, ["error", physical_port, inspect(message)]}
          end
      end

    msg = Rlp.encode!([ref, msg])
    ssl_send!(state, msg)
  end

  defp handle_request(
         state = %Connection{ports: ports},
         [_ref, [command | params]]
       ) do
    case {command, params} do
      {"block", [_num]} ->
        state

      {"ping", []} ->
        {state, ["response", "pong"]}

      {"ticket_request", [usage]} ->
        usage = to_num(usage)
        create_update_ticket(state, usage, state.conns)

      {"portsend", [port_ref, msg]} ->
        with {pid, :up} <- ports[port_ref] do
          GenServer.cast(pid, {:send, msg})
        end

        state

      {"portclose", [port_ref]} ->
        debug("received portclose for #{Base16.encode(port_ref)}")

        case ports[port_ref] do
          {pid, :up} ->
            GenServer.cast(pid, :remote_close)
            %{state | ports: Map.put(ports, port_ref, {pid, :down})}

          _other ->
            state
        end

      {"trace", [timestamp, edge, msg]} ->
        dt =
          Rlpx.bin2uint(timestamp)
          |> DateTime.from_unix!(:millisecond)
          |> DateTime.truncate(:second)
          |> to_string()

        Logger.info("TRACE> #{dt} #{edge} #{msg}")
        state

      other ->
        debug("ignoring unknown server event #{inspect(other)}")
        state
    end
  end

  def rpc(pid, data = [cmd | _rest], opts \\ []) do
    timeout = Keyword.get(opts, :timeout, 120_000)
    req = req_id()
    rlp = Rlp.encode!([req | [data]])

    call(pid, {:rpc, cmd, req, rlp, timestamp(), self()}, timeout)
    |> case do
      [^req, ["error", "remote_closed"]] ->
        Logger.warning(
          "DiodeClient remote_closed during RPC(#{inspect(cmd)}) from #{server_url(pid)}"
        )

        {:error, "remote_closed"}

      [^req, ["error", reason]] ->
        {:error, reason}

      [^req, ["error" | rest]] ->
        {:error, rest}

      [^req, ["response" | rest]] ->
        rest
    end
  end

  def rpc_async(pid, data = [cmd | _rest], id \\ self()) do
    req = req_id()
    rlp = Rlp.encode!([req | [data]])
    call(pid, {:rpc_async, cmd, req, rlp, timestamp(), id})
  end

  defp call(pid, args, timeout \\ :infinity) do
    GenServer.call(pid, args, timeout)
  catch
    :exit, {:noproc, _reason} ->
      Process.exit(pid, :normal)
      exit(:connection_shutdown)

    :exit, {:normal, _reason} ->
      Process.exit(pid, :normal)
      exit(:connection_shutdown)

    :exit, reason ->
      Process.exit(pid, reason)
      raise "DiodeClient exception: #{inspect(reason)}"
  end

  def rpc_cast(pid, data = [cmd | _rest]) do
    req = req_id()
    rlp = Rlp.encode!([req | [data]])
    GenServer.cast(pid, {:rpc, cmd, req, rlp, timestamp(), self()})
  end

  defp req_id() do
    Random.uint31h()
    |> to_bin()
  end

  def ssl_options(opts \\ []) do
    # Can be :server or :client
    role = Keyword.get(opts, :role, :server)
    wallet = DiodeClient.wallet()
    private = Wallet.privkey!(wallet)
    public = Wallet.pubkey_long!(wallet)
    cert = Secp256k1.selfsigned(private, public)

    [
      active: false,
      cacerts: [cert],
      cert: cert,
      delay_send: true,
      eccs: [:secp256k1],
      key: {:ECPrivateKey, Secp256k1.der_encode_private(private, public)},
      log_alert: false,
      log_level: :warning,
      mode: :binary,
      nodelay: false,
      packet: @packet_header,
      reuse_sessions: true,
      reuseaddr: true,
      send_timeout_close: true,
      send_timeout: 30_000,
      show_econnreset: true,
      verify_fun: {&check/3, nil},
      verify: :verify_peer,
      versions: [:"tlsv1.2"]
    ] ++
      if role == :server do
        [fail_if_no_peer_cert: true]
      else
        []
      end
  end

  defp ssl_send!(state = %Connection{socket: socket, unpaid_bytes: up, server: server}, msg) do
    with {:error, reason} <- :ssl.send(socket, msg) do
      warning("SSL send error: #{inspect(reason)}")
      send(self(), {:ssl_closed, socket})
    end

    DiodeClient.Stats.submit(:relay, :self, server, byte_size(msg) + @packet_header)
    %Connection{state | unpaid_bytes: up + byte_size(msg) + @packet_header}
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

  defp maybe_shutdown(state = %Connection{shutdown: shutdown, ports: ports, socket: socket}) do
    if shutdown == false or map_size(ports) > 0 do
      {:noreply, state}
    else
      if socket != nil, do: :ssl.close(socket)
      {:stop, :normal, %Connection{state | socket: nil}}
    end
  end
end
