defmodule DiodeClient.SocksProxySsl do
  require Logger

  @moduledoc """
  DiodeClient Transport interface for use with Cowboy2 Adapter
  and `:hackeny`. Potentially more depending on interface compatibility

  # Example using hackney to make http requests via Diode:

  ```
  {:ok, ref} = :hackney.connect(SocksProxySsl, "https://someurl.com", 443)
  ```
  """

  # alias DiodeClient.Rlpx

  def connect(target_url, target_port, opts \\ [], timeout \\ 5000)
      when is_integer(target_port) do
    # OnCrash.call(fn x ->
    #   IO.inspect(x, label: "from oncrashcall")
    # end)

    # hackney is written in erlang, which uses lists. decode here:
    target_url =
      if is_binary(target_url) do
        target_url
      else
        List.to_string(target_url)
      end

    proxy_address = opts[:proxy_address]
    proxy_port = opts[:proxy_port]

    if proxy_address != nil and proxy_port != nil do
      case DiodeClient.Transport.connect(proxy_address, proxy_port, opts, timeout) do
        {:ok, conn} ->
          # negotiate socks5 connection
          ## https://en.wikipedia.org/wiki/SOCKS#SOCKS5
          ## https://www.rfc-editor.org/rfc/rfc1928

          socks_version = 0x05
          nauth = 0x01
          auth = 0x00

          # send client greeting
          :ok = DiodeClient.Transport.send(conn, <<socks_version, nauth, auth>>)

          # server response
          {:ok, <<^socks_version, ^auth>>} = DiodeClient.Transport.recv(conn, 2)

          addr_type = 0x03
          addr_length = byte_size(target_url)
          addr_name = target_url
          cmd = 0x01

          port_big_endian = <<target_port::16>>

          connection_request =
            <<socks_version, cmd, 0x00, addr_type, addr_length>> <> addr_name <> port_big_endian

          # send client connection request
          :ok = DiodeClient.Transport.send(conn, connection_request)

          # server response
          case DiodeClient.Transport.recv(conn, 3) do
            {:ok, <<^socks_version, status, 0x00>>} ->
              case DiodeClient.Transport.recv(conn, 1) do
                {:ok, <<0x01>>} ->
                  {:ok, _ipv4_bytes} = DiodeClient.Transport.recv(conn, 4)

                  continue_connect(conn, target_url)

                {:ok, <<0x04>>} ->
                  {:ok, _ipv6_bytes} = DiodeClient.Transport.recv(conn, 16)
                  continue_connect(conn, target_url)

                error ->
                  {error, {:socks_status, status}}
              end

            error ->
              error
          end

        _ ->
          {:error, "connect failed"}
      end
    else
      {:error,
       "'proxy_address' and/or 'proxy_port' not specified. If using hackey, include them in 'connect_options'."}
    end
  end

  @dialyzer {:nowarn_function, continue_connect: 2}
  def continue_connect(conn, target_url) do
    {:ok, _port_bytes} = DiodeClient.Transport.recv(conn, 2)
    # hackney is written in erlang, which uses lists for strings. encode here:
    host = URI.parse("https://" <> target_url).host |> String.to_charlist()

    ssl_opts =
      [
        :binary,
        {:active, false},
        {:packet, :raw},
        {:secure_renegotiate, true},
        {:reuse_sessions, true},
        {:cb_info, {DiodeClient.Transport, :ssl, :ssl_closed, :ssl_error, :ssl_passive}}
      ] ++ :hackney_ssl.check_hostname_opts(host) ++ :hackney_ssl.cipher_opts()

    :ssl.connect(conn, ssl_opts, 60_000)
  end

  def sockname(ssl) when is_tuple(ssl), do: :ssl.sockname(ssl)
  def sockname(port), do: DiodeClient.Port.sockname(port)

  def handshake(pid, _opts, _timeout) do
    {:ok, pid}
  end

  defdelegate controlling_process(pid, dst), to: :ssl
  defdelegate peername(pid), to: :ssl
  defdelegate setopts(pid, opts), to: :ssl
  defdelegate getopts(pid, opts), to: :ssl
  defdelegate send(pid, data), to: :ssl
  defdelegate recv(pid, length), to: :ssl
  defdelegate recv(pid, length, timeout), to: :ssl
  defdelegate shutdown(pid, reason), to: :ssl
  defdelegate close(pid), to: :ssl

  def sendfile(socket, path, offset, bytes) do
    :ranch_transport.sendfile(name(), socket, path, offset, bytes,
      chunk_size: DiodeClient.Port.chunk_size()
    )
  end

  def messages(), do: {:ssl, :ssl_closed, :ssl_error, :ssl_passive}
  def messages(_pid), do: {:ssl, :ssl_closed, :ssl_error}
  def name(), do: __MODULE__
  def secure(), do: true
end
