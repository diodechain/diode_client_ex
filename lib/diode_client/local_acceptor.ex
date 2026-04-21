defmodule DiodeClient.LocalAcceptor do
  @moduledoc false
  use GenServer
  require Logger
  alias DiodeClient.{Acceptor, Connection, LocalAcceptor}
  defstruct [:backlog, :socket, :portnum]

  def start_link(portnum) do
    state = %LocalAcceptor{portnum: portnum, backlog: %{}}
    GenServer.start_link(__MODULE__, state, hibernate_after: 5_000)
  end

  @impl true
  def init(state) do
    send(self(), :open)
    {:ok, state}
  end

  @impl true
  def handle_info(:open, state = %LocalAcceptor{portnum: portnum}) do
    case :ssl.listen(0, Connection.ssl_options()) do
      {:ok, socket} ->
        spawn_link(fn -> loop(socket, portnum) end)
        {:noreply, %LocalAcceptor{state | socket: socket}}

      {:error, reason} ->
        Logger.debug("failed opening local socket: #{inspect(reason)}")
        Process.send_after(self(), :open, 5_000)
        {:noreply, state}
    end
  end

  @impl true
  def handle_call(:local_port, _from, state = %LocalAcceptor{socket: socket}) do
    case socket do
      nil ->
        {:reply, nil, state}

      socket ->
        {:ok, {address, port}} = :ssl.sockname(socket)
        address = resolve_address(address)
        {:reply, {address, port}, state}
    end
  end

  defp resolve_address(address) do
    case address do
      {0, 0, 0, 0} -> local_address(:inet)
      {0, 0, 0, 0, 0, 0, 0, 0} -> local_address(:inet6)
      other -> List.to_string(:inet.ntoa(other))
    end
  end

  def local_address(family) do
    case :os.type() do
      {:win32, _} ->
        windows_local_address(family)

      {:unix, _} ->
        case :net.getifaddrs() do
          {:ok, ifs} ->
            Enum.filter(ifs, fn %{flags: flags, addr: %{family: addr_family}} ->
              addr_family == family and :up in flags and :running in flags and
                :loopback not in flags
            end)
            |> case do
              [] -> nil
              [%{addr: %{addr: addr}} | _rest] -> List.to_string(:inet.ntoa(addr))
            end

          {:error, _reason} ->
            # mobile ios/android
            nil
        end
    end
  end

  # On Windows :net.getifaddrs/0 is not available, so we first try the
  # cross-platform :inet.getifaddrs/0 (no subprocess required) and only
  # fall back to parsing `ipconfig` output if that returns nothing usable.
  # Some Windows installs don't have `ipconfig` on PATH, so we try the
  # absolute System32 path first.
  defp windows_local_address(family) do
    case inet_getifaddrs_pick(family) do
      nil -> windows_ipconfig_address(family)
      address -> address
    end
  end

  defp inet_getifaddrs_pick(family) do
    expected_size =
      case family do
        :inet -> 4
        :inet6 -> 8
      end

    case :inet.getifaddrs() do
      {:ok, ifs} ->
        Enum.find_value(ifs, fn {_name, props} ->
          inet_getifaddrs_props_address(props, expected_size)
        end)

      _ ->
        nil
    end
  end

  defp inet_getifaddrs_props_address(props, expected_size) do
    flags = Keyword.get(props, :flags, [])

    if :up in flags and :running in flags and :loopback not in flags do
      inet_getifaddrs_first_addr(props, expected_size)
    end
  end

  defp inet_getifaddrs_first_addr(props, expected_size) do
    props
    |> Keyword.get_values(:addr)
    |> Enum.find(fn addr -> is_tuple(addr) and tuple_size(addr) == expected_size end)
    |> case do
      nil -> nil
      addr -> List.to_string(:inet.ntoa(addr))
    end
  end

  defp windows_ipconfig_address(family) do
    regex =
      case family do
        :inet ->
          ~r/IPv4.+ (([0-9]{1,3}\.){3}([0-9]{1,3}))/

        :inet6 ->
          ~r/IPv6.+ (([a-f0-9:]+:+)+[a-f0-9]+)/i
      end

    with {:ok, ret} <- run_ipconfig(),
         [_ret, match | _rest] <- Regex.run(regex, ret) do
      match
    else
      _ -> nil
    end
  end

  defp run_ipconfig() do
    Enum.find_value(ipconfig_candidates(), fn path ->
      with exe when is_binary(exe) <- System.find_executable(path),
           {out, 0} <- System.cmd(exe, []) do
        {:ok, out}
      else
        _ -> nil
      end
    end)
  end

  defp ipconfig_candidates() do
    system_root = System.get_env("SystemRoot") || System.get_env("WINDIR") || "C:\\Windows"

    Enum.uniq([
      Path.join([system_root, "System32", "ipconfig.exe"]),
      "C:\\Windows\\System32\\ipconfig.exe",
      "ipconfig"
    ])
  end

  @tls_timeout 5_000
  def loop(socket, portnum) do
    {:ok, client} = :ssl.transport_accept(socket)
    NetworkMonitor.close_on_down(client, :ssl)

    case :ssl.handshake(client, Connection.ssl_options(), @tls_timeout) do
      {:error, reason} ->
        Logger.debug("ssl handshake failed for #{inspect(reason)}")
        :ssl.close(client)

      {:ok, ssl} ->
        GenServer.call(Acceptor, {:inject, portnum, %{type: :open1, from: self(), ref: ssl}})
    end

    loop(socket, portnum)
  end
end
