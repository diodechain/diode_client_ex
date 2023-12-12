#!/usr/bin/env elixir
# This is a sample port publisher, that listens on port 80 and forwards it to local port 8080
Mix.install([
  {:diode_client, path: "../"},
  :socket2,
  :oncrash
])

defmodule Listener do
  def id(socket), do: :erlang.phash2(socket)

  def accept(remote, cmd) do
    {:ok, {:undefined, peer}} = :ssl.peername(remote)
    IO.puts("[#{id(remote)}] Accepted connection from #{DiodeClient.Base16.encode(peer)}")

    OnCrash.call(fn reason ->
      if reason != :normal do
        IO.puts("[#{id(remote)}] Failed for #{inspect(reason)}")
      end
    end)

    :ssl.controlling_process(remote, self())
    :ssl.setopts(remote, active: true)
    {time, {:ok, request}} = :timer.tc(fn -> parse_http_request(remote) end)
    uri = URI.parse(request.query_string)
    script = Path.join(File.cwd!(), "index.html")

    env = %{
      "REQUEST_METHOD" => request.method,
      "CONTENT_LENGTH" => "#{byte_size(request.body)}",
      "CONTENT_TYPE" => request["content-type"] || "",
      "QUERY_STRING" => uri.query || "",
      "REQUEST_URI" => uri.path,
      "REDIRECT_STATUS" => "200",
      "SCRIPT_FILENAME" => script,
      "GATEWAY_INTERFACE" => "CGI/1.1"
    }

    local = Socket.Port.open!(cmd, env: env)

    if request.body != "" do
      Socket.Stream.send!(local, request.body)
    end

    client_loop(local, remote)
    {time, request.query_string}
  end

  def parse_http_request(remote, rest \\ "") do
    data =
      rest <>
        receive do
          {:ssl, ^remote, data} -> data
        after
          5_000 -> raise "timeout"
        end

    case header_and_body(data) do
      :error ->
        parse_http_request(remote, data)

      {:ok, request} ->
        case request["content-length"] do
          nil ->
            {:ok, request}

          length ->
            length = String.to_integer(length)

            if byte_size(request.body) < length do
              parse_http_request(remote, data)
            else
              {:ok, request}
            end
        end
    end
  end

  defp header_and_body(data) do
    case String.split(data, "\r\n\r\n", parts: 2) do
      [header, body] ->
        request =
          header
          |> String.split("\r\n")
          |> Enum.reduce(%{}, fn line, request ->
            case String.split(line, ": ", parts: 2) do
              [key, value] ->
                Map.put(request, String.downcase(key), value)

              [headline] ->
                [method, path | _version] = String.split(headline, " ")

                request
                |> Map.put(:method, method)
                |> Map.put(:query_string, path)
            end
          end)
          |> Map.put(:body, body)

        {:ok, request}

      _other ->
        :error
    end
  end

  def client_loop(local, remote, ret \\ "") do
    receive do
      {_port, {:data, data}} ->
        client_loop(local, remote, ret <> data)

      {_port, {:exit_status, status}} ->
        if status != 0 do
          IO.puts("Local error: #{inspect(status)}")
        end

        :ssl.send(remote, html_reply(ret))
        :ssl.close(remote)
        :ok

      {:EXIT, _port, reason} ->
        IO.puts("Local error: #{inspect(reason)}")
        :ok

      other ->
        IO.inspect(other, label: "OTHER")
        :ok
    end
  end

  def html_reply(body) do
    {:ok, response} = header_and_body(body)

    now = DateTime.utc_now() |> Calendar.strftime("%a, %d %b %y %X %Z")

    "HTTP/1.1 #{response["status"] || "200 OK"}\r\n" <>
      "Date: #{now}\r\n" <>
      "Content-Type: #{response["content-type"] || "text/html; charset=UTF-8"}\r\n" <>
      "Content-Length: #{byte_size(response.body)}\r\n" <>
      "\r\n" <>
      response.body
  end
end

# :hackney_trace.enable(:max, :io)
# Logger.configure(level: :debug)
Logger.put_application_level(:diode_client, :info)

DiodeClient.interface_add("listener_interface")
IO.puts("Interface Address: 0x" <> Base.encode16(DiodeClient.address(), case: :lower))

{:ok, _socket} =
  DiodeClient.Port.listen(:binary.decode_unsigned("tls:80"),
    callback: fn socket ->
      {total_time, {read_time, info}} =
        :timer.tc(fn ->
          Listener.accept(socket, "php-cgi")
        end)

      IO.puts(
        "[#{Listener.id(socket)}] request to #{inspect(info)} took #{div(total_time, 1000)}ms (#{div(read_time, 1000)}ms read)})"
      )
    end
  )

IO.puts("Listening on port 80")
Process.sleep(:infinity)
