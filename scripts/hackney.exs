#!/usr/bin/env elixir
Mix.install([:oncrash, :hackney, {:diode_client, path: "../"}, :profiler])

:c.c(:hackney)
:c.c(:hackney_request)
:c.c(:hackney_response)
:hackney_trace.enable(:max, :io)
Logger.configure(level: :debug)
# Logger.put_application_level(:diode_client, :info)
DiodeClient.Log.enable_debug()
DiodeClient.interface_add()
IO.puts("0x" <> Base.encode16(DiodeClient.address(), case: :lower))
Application.ensure_all_started(:hackney)

# address = "0x35480f4de422827d4fd80c47a5cf5f2f4622f2aa"
# port = 80
# path = "/lol"
# {:ok, sock} = DiodeClient.Transport.connect(address, port, local: false)
# :ok = DiodeClient.Transport.send(sock, "GET #{path} HTTP/1.1\r\nHost: #{address}\r\n\r\n")
# receive do
#   some -> IO.inspect(some)
# end

address = "0x35480f4de422827d4fd80c47a5cf5f2f4622f2aa"
port = 80
path = "/lol"

{:ok, ref} =
  :hackney.connect(DiodeClient.Transport, address, port,
    connect_timeout: 60_000,
    recv_timeout: 60_000,
    connect_options: [local: false]
  )

{:ok, _status, _headers, ^ref} = :hackney.send_request(ref, {:get, path, [], []})

{:ok, content} = :hackney.body(ref)
IO.puts(content)
