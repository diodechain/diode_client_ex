#!/usr/bin/env elixir
# This is a sample port publisher, that listens on port 80 and forwards it to local port 8080
Mix.install([{:diode_client, path: "../"}, {:socket2, path: "../../../elixir-socket"}])

defmodule Listener do
  def loop(socket, cmd) do
    case DiodeClient.Port.accept(socket) do
      {:ok, remote} ->
        {:ok, {:undefined, peer}} = :ssl.peername(remote)
        IO.puts("Accepted connection from #{DiodeClient.Base16.encode(peer)}")

        pid =
          spawn(fn ->
            {:ok, request} = parse_http_request(remote)
            uri = URI.parse(request.query_string)
            script = Path.join(File.cwd!(), "index.html")

            env =
              %{
                "REQUEST_METHOD" => request.method,
                "CONTENT_LENGTH" => "#{byte_size(request.body)}",
                "CONTENT_TYPE" => request["content-type"] || "",
                "QUERY_STRING" => request.query_string,
                "REQUEST_URI" => uri.path,
                "REDIRECT_STATUS" => "200",
                "SCRIPT_FILENAME" => script,
                "GATEWAY_INTERFACE" => "CGI/1.1"
              }
              |> IO.inspect(label: "ENV")

            local = Socket.Port.open!(cmd, env: env)

            if request.body != "" do
              Socket.Stream.send!(local, request.body)
            end

            client_loop(local, remote)
          end)

        :ssl.controlling_process(remote, pid)
        :ssl.setopts(remote, active: true)

      {:error, :closed} ->
        IO.puts("Socket closed")
        :ok

      {:error, :timeout} ->
        IO.puts("Socket timeout")
        :ok
    end

    loop(socket, cmd)
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
      :error -> parse_http_request(remote, data)
      request -> request
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
        :ssl.send(remote, html_reply(ret) |> IO.inspect(label: "REPLY"))
        IO.puts("Pogram exit: #{inspect(status)}")
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
Logger.configure(level: :debug)
Logger.put_application_level(:diode_client, :debug)

DiodeClient.interface_add("listener_interface")
IO.puts("Interface Address: 0x" <> Base.encode16(DiodeClient.address(), case: :lower))
{:ok, socket} = DiodeClient.Port.listen(:binary.decode_unsigned("tls:80"))
IO.puts("Listening on port 80")
Listener.loop(socket, "php-cgi")
