#!/usr/bin/env elixir
# This is a sample socks server
Mix.install([
  {:diode_client, path: "../"},
  :socket2,
  :oncrash
])

defmodule Socks do
  @udp_port 1080

  @socksVer4 0x04
  @socksVer5 0x05
  @socks4CmdConnect 0x01

  @typeDomain 0x03
  @typeIPv4 0x01
  # @typeIPv6 0x04

  @socks5CmdConnect 0x01
  # @socks5CmdBind 0x02
  @socks5CmdUDPAssoc 0x03

  @socks5ReplySuccess 0x00
  @socks5ReplyConnectionError 0x05
  @socks5Reserved 0x00

  def id(socket), do: :erlang.phash2(socket)

  def loop_udp(socket) do
    receive do
      any ->
        IO.inspect(any, label: "UDP")
    end

    loop_udp(socket)
  end

  def loop(socket) do
    {:ok, local} = :gen_tcp.accept(socket)
    pid = spawn(__MODULE__, :client_loop, [local])
    # set owner of localhost connection
    :gen_tcp.controlling_process(local, pid)
    loop(socket)
  end

  def client_loop(local) do
    IO.puts("[#{id(local)}] Accepted connection")

    OnCrash.call(fn reason ->
      if reason != :normal do
        IO.puts("[#{id(local)}] Failed for #{inspect(reason)}")
      end
    end)

    {time, {:ok, request}} = :timer.tc(fn -> parse_socks_request(local) end)
    IO.puts("[#{id(local)}] Request to #{request.url} parsed after #{div(time, 1000) / 1000}ms")

    with [_, bns] <- Regex.run(~r"^([^/]+)\.diode\.link", request.url) do
      if String.starts_with?(bns, "0x") do
        [DiodeClient.Base16.decode(bns)]
      else
        DiodeClient.Contracts.BNS.resolve_name_all(bns <> ".diode")
      end
      |> connect_web3(request, local)
    else
      _ -> connect_web2(request, local)
    end
    |> maybe_error(request, local)
  end

  defp maybe_error(:ok, _request, _local), do: :ok

  defp maybe_error(:connection_error, request, local) do
    :gen_tcp.send(local, request.error_reply)
  end

  def connect_web2(request, local) do
    {:ok, remote} =
      :gen_tcp.connect(
        String.to_charlist(request.url),
        request.port,
        [:binary, active: true],
        15_000
      )

    :gen_tcp.send(local, request.reply)
    client_loop(:gen_tcp, remote, local)
  end

  def connect_web3([dst | rest], request, local) do
    port = :binary.decode_unsigned("tls:#{request.port}")

    case DiodeClient.Port.connect(dst, port) do
      {:ok, remote} ->
        :gen_tcp.send(local, request.reply)
        :ssl.setopts(remote, active: true)
        client_loop(:ssl, remote, local)

      error ->
        IO.puts("Failed to connect to #{inspect(dst)} with #{inspect(error)}")
        connect_web3(rest, request, local)
    end
  end

  def connect_web3([], _request, _local), do: :connection_error

  def parse_socks_request(local, rest \\ "") do
    data =
      rest <>
        receive do
          {:tcp, ^local, data} -> data
        after
          5_000 ->
            IO.inspect(rest, label: "TIMEOUT")
            raise "timeout"
        end

    case parse_preamble(data) do
      {:reply, resp, data} ->
        :gen_tcp.send(local, resp)
        parse_socks_request2(local, data)

      :incomplete ->
        parse_socks_request(local, data)

      {:error, reason} ->
        raise inspect(reason)

      {:ok, request} ->
        {:ok, request}
    end
  end

  def parse_socks_request2(local, rest \\ "") do
    data =
      rest <>
        receive do
          {:tcp, ^local, data} -> data
        after
          50_000 ->
            IO.inspect(rest, label: "TIMEOUT2")
            raise "timeout2"
        end

    case parse_preamble2(data) do
      :incomplete ->
        parse_socks_request2(local, data)

      {:error, reason} ->
        raise inspect(reason)

      {:ok, request} ->
        {:ok, request}
    end
  end

  # hand_shake only support SOCKS4A + SOCKS5
  defp parse_preamble(
         <<@socksVer4, @socks4CmdConnect, port::unsigned-big-size(16), 0::unsigned-size(32),
           rest::binary()>>
       ) do
    with {userid, rest} when is_binary(userid) <- read_string(rest),
         {host, rest} <- read_string(rest) do
      {:ok,
       %{
         vsn: @socksVer4,
         url: host,
         port: port,
         rest: rest,
         reply: <<@socksVer4, 0x5A, port::unsigned-big-size(16), 0, 0, 0, 1>>,
         error_reply: <<@socksVer4, 0x5B, port::unsigned-big-size(16), 0, 0, 0, 1>>
       }}
    end
  end

  defp parse_preamble(
         <<@socksVer4, @socks4CmdConnect, _port::unsigned-big-size(16), a, b, c, d,
           _rest::binary()>>
       )
       when a != 0 or b != 0 or c != 0 or d != 0,
       do: {:error, {:invalid_socks4_ip, {a, b, c, d}}}

  defp parse_preamble(<<@socksVer4, otherCmd, _::binary()>>) when otherCmd != @socks4CmdConnect,
    do: {:error, :invalid_socks4_command}

  defp parse_preamble(<<@socksVer5, auth_len, _auth::binary-size(auth_len), rest::binary()>>) do
    {:reply, <<@socksVer5, 0>>, rest}
  end

  defp parse_preamble(<<version, _rest::binary()>>)
       when version != @socksVer4 and version != @socksVer5,
       do: {:error, :invalid_socks_version}

  defp parse_preamble(_other), do: :incomplete

  defp parse_preamble2(
         <<@socksVer5, @socks5CmdConnect, _, @typeDomain, domain_len,
           domain::binary-size(domain_len), port::unsigned-big-size(16), rest::binary()>>
       ) do
    {:ok,
     %{
       vsn: @socksVer5,
       url: domain,
       port: port,
       rest: rest,
       # send confirmation: version 5, no authentication required
       reply:
         <<@socksVer5, @socks5ReplySuccess, @socks5Reserved, @typeIPv4, 0, 0, 0, 1,
           port::unsigned-big-size(16)>>,
       error_reply:
         <<@socksVer5, @socks5ReplyConnectionError, @socks5Reserved, @typeIPv4, 0, 0, 0, 1,
           port::unsigned-big-size(16)>>
     }}
  end

  defp parse_preamble2(
         <<@socksVer5, @socks5CmdUDPAssoc, _, @typeDomain, domain_len,
           _domain::binary-size(domain_len), _port::unsigned-big-size(16), _rest::binary()>>
       ) do
    {:reply,
     <<@socksVer5, @socks5ReplySuccess, @socks5Reserved, @typeIPv4, 127, 0, 0, 1,
       @udp_port::unsigned-big-size(16)>>}
  end

  defp parse_preamble2(<<@socksVer5, _cmd, _, otherType, _rest::binary()>>)
       when otherType != @typeDomain,
       do: {:error, :invalid_socks5_address_type}

  defp parse_preamble2(<<@socksVer5, otherCmd, _rest::binary()>>)
       when otherCmd not in [@socks5CmdConnect, @socks5CmdUDPAssoc],
       do: {:error, :invalid_socks5_cmd}

  defp parse_preamble2(<<version, _rest::binary()>>)
       when version != @socksVer5,
       do: {:error, :invalid_socks_version}

  defp parse_preamble2(_other), do: :incomplete

  defp read_string(<<>>), do: :incomplete
  defp read_string(<<0, rest::binary()>>), do: {"", rest}

  defp read_string(<<char, rest::binary()>>) do
    {str, rest} = read_string(rest)
    {<<char, str::binary>>, rest}
  end

  def client_loop(remote_proto, remote, local) do
    # pattern match on socket - "let it crash"
    receive do
      {:ssl, ^remote, data} ->
        :gen_tcp.send(local, data)
        client_loop(remote_proto, remote, local)

      {:ssl_closed, ^remote} ->
        IO.puts("[#{id(local)}] Remote closed")
        :ok

      {:ssl_error, ^remote, reason} ->
        IO.puts("[#{id(local)}] Remote error: #{inspect(reason)}")
        :ok

      {:tcp, ^remote, data} ->
        :gen_tcp.send(local, data)
        client_loop(remote_proto, remote, local)

      {:tcp_closed, ^remote} ->
        IO.puts("[#{id(local)}] Remote closed")
        :ok

      {:tcp_error, ^remote, reason} ->
        IO.puts("[#{id(local)}] Remote error: #{inspect(reason)}")
        :ok

      {:tcp, ^local, data} ->
        remote_proto.send(remote, data)
        client_loop(remote_proto, remote, local)

      {:tcp_closed, ^local} ->
        IO.puts("[#{id(local)}] Local closed")
        :ok

      {:tcp_error, ^local, reason} ->
        IO.puts("[#{id(local)}] Local error: #{inspect(reason)}")
        :ok

      other ->
        IO.inspect(other, "[#{id(local)}] UNHANDLED")
        :ok
    end
  end
end

# :hackney_trace.enable(:max, :io)
Logger.configure(level: :debug)
# Logger.put_application_level(:diode_client, :info)

DiodeClient.interface_add("listener_interface")
IO.puts("Interface Address: 0x" <> Base.encode16(DiodeClient.address(), case: :lower))

tcp_port = 1080
udp_port = 1080

spawn(fn ->
  IO.puts("Starting Socks Server on localhost:#{tcp_port}")
  {:ok, socket} = :gen_tcp.listen(tcp_port, [{:active, true}, :binary, {:reuseaddr, true}])
  Socks.loop(socket)
end)

{:ok, socket} = :gen_udp.open(udp_port, [{:active, true}, :binary, {:reuseaddr, true}])
Socks.loop_udp(socket)
Process.sleep(:infinity)
