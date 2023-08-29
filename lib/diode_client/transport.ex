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

  @spec listen(keyword) :: DiodeClient.Acceptor.Listener.t()
  def listen(opts) do
    port = Keyword.fetch!(opts, :port)
    portnum = Rlpx.bin2uint("tls:#{port}")
    DiodeClient.Port.listen(portnum)
  end

  @spec accept(DiodeClient.Acceptor.Listener.t(), any) :: {:error, any()} | {:ok, pid()}
  def accept(portnum, timeout) do
    DiodeClient.Port.accept(portnum, timeout)
    |> maybe_reset_options()
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
