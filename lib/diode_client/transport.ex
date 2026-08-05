defmodule DiodeClient.Transport do
  @moduledoc """
  DiodeClient Transport interface for use with Cowboy2 Adapter
  and `:hackeny`. Potentially more depending on interface compatibility

  # Example using hackney to make http requests via Diode:

  ```
  {:ok, ref} = :hackney.connect(DiodeClient.Transport, address, port)
  request = {:get, path, [], ""}
  {:ok, status, headers, ^ref} = :hackney.send_request(ref, request)
  {:ok, content} = :hackney.body(ref)
  ```
  """
  alias DiodeClient.Rlpx

  @spec connect(binary(), integer(), keyword, integer()) :: {:ok, pid()} | {:error, any()}
  def connect(addr, port, opts \\ [], timeout \\ 5000) when is_integer(port) do
    port = Rlpx.bin2uint("tls:#{port}")

    DiodeClient.Port.connect(addr, port, opts, timeout)
    |> maybe_reset_options()
  end

  # Ranch 1 passes a keyword list; Ranch 2 passes a transport opts map with :socket_opts.
  @doc false
  def listen(opts) when is_list(opts) or is_map(opts) do
    port = listen_port(opts)
    portnum = Rlpx.bin2uint("tls:#{port}")
    DiodeClient.Port.listen(portnum)
  end

  @doc false
  def listen_port(opts) when is_list(opts), do: Keyword.fetch!(opts, :port)

  def listen_port(opts) when is_map(opts) do
    Keyword.fetch!(Map.get(opts, :socket_opts, []), :port)
  end

  @spec accept(DiodeClient.Acceptor.Listener.t(), any) :: {:error, any()} | {:ok, pid()}
  def accept(portnum, timeout) do
    DiodeClient.Port.accept(portnum, timeout)
    |> maybe_reset_options()
  end

  def sockname(ssl) when is_tuple(ssl), do: :ssl.sockname(ssl)

  def sockname(%DiodeClient.Acceptor.Listener{}) do
    # Ranch only needs a sockname after listen; diode ports are virtual.
    {:ok, {{0, 0, 0, 0}, 0}}
  end

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
    apply(:ranch_transport, :sendfile, [
      name(),
      socket,
      path,
      offset,
      bytes,
      chunk_size: DiodeClient.Port.chunk_size()
    ])
  end

  def messages(), do: {:ssl, :ssl_closed, :ssl_error, :ssl_passive}
  def messages(_pid), do: {:ssl, :ssl_closed, :ssl_error}
  def name(), do: __MODULE__
  def secure(), do: true

  defp maybe_reset_options(ret) do
    case ret do
      {:ok, pid} ->
        setopts(pid, packet: :raw, active: false, mode: :binary)
        {:ok, pid}

      other ->
        other
    end
  end
end
