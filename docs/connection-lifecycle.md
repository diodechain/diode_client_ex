# Connection process and lifecycle

This document describes how `DiodeClient.Connection` and `DiodeClient.Manager` manage relay connections, block subscriptions, and `remote_closed` handling. It is aimed at contributors debugging connection resets, peak polling, or RPC failures.

## Overview

| Process | Role |
| ------- | ---- |
| `DiodeClient.Manager` | Owns one `Connection` per seed relay; routes traffic; aggregates chain peaks |
| `DiodeClient.Connection` | One TLS session to a relay; multiplexes ports, RPC, tickets, and block peaks |
| Poll subprocess | Linked fallback when `subscribe` RPC fails; polls `getblockpeak` / `getblockheader` on `block_time` interval |

Each seed node gets a globally registered `Connection` (`{:global, {Connection, server_url}}`). The Manager starts connections, monitors them, and restarts seed connections after abnormal exit.

## Connection states

A `Connection` GenServer moves through these phases:

1. **Init / backoff** — `init_loop/2` waits (exponential backoff + `NodeScorer` delay), then calls `connect/2`.
2. **Connected** — SSL socket open; `server_wallet` set; block subscriptions started; RPC and port traffic active.
3. **Reset** — Socket closed and state cleared; pending RPC callers receive `remote_closed`; process stays alive and returns to init/backoff via `{:continue, :init}`.
4. **Shutdown** — On `:stop` when no ports remain; GenServer exits `:normal`.

`reset/1` is the central teardown for a dropped relay link. It does **not** stop the `Connection` process — it clears ephemeral state and triggers reconnect:

```elixir
# Simplified outcomes of reset/1
socket: nil
peaks: %{}
subscribed: %{}      # allows re-subscribe on reconnect
recv_id / channels cleared; pending replies → remote_closed
reset_count incremented
→ {:continue, :init}  # from ssl_closed handler
```

## How connections start and restart

**Manager → Connection**

- `Manager.restart_conn/2` calls `Connection.start_link(server_url, ports)`.
- After start, Manager sends `{:subscribe, shell}` for every shell it already tracks.
- Manager monitors each Connection PID; on abnormal exit of a **seed** connection it schedules `{:restart_conn, key}` after `NodeScorer` delay.

**Connection → relay**

- `connect/2` opens TLS (`:ssl.connect/4`), extracts the relay wallet from the peer cert, sends `hello`, and spawns a **linked** process that calls `subscribe_block!/2` for each subscribed shell.

## Block subscription and poll fallback

Relays can push new block headers via `subscribe`. When that RPC fails, `Connection` falls back to polling.

```
connect/2
  └─ spawn_link subscribe_block!(conn, shell)   # per shell
       ├─ mark_subscribed (dedupe via GenServer call)
       ├─ rpc subscribe → ["ok"]                  # push path: relay sends blockheader
       └─ rpc subscribe → {:error, _}             # fallback path:
            └─ spawn_link poll(conn, shell)
                 ├─ monitor Connection PID
                 ├─ every shell.block_time(): getblockpeak + getblockheader
                 ├─ send {:peak, shell, block} to Connection
                 └─ on {:DOWN, conn}: exit :ok
```

**Poll subprocess lifetime**

- Poll processes are **linked** to `Connection` (via `spawn_link` in `subscribe_block!/2`).
- They **survive** in-process `reset/1` / reconnect: `Connection` does not die on `ssl_closed`, so poll keeps running and receives `{:DOWN, ...}` only when the GenServer actually terminates.
- On reconnect, `connect/2` spawns fresh `subscribe_block!/2` workers; `mark_subscribed` prevents duplicate subscribe attempts for the same shell until `reset/1` clears `subscribed`.

**Why poll must tolerate `remote_closed`**

During `reset/1`, pending and in-flight RPCs are answered with `["error", "remote_closed"]`. `Connection.rpc/3` surfaces that as `{:error, "remote_closed"}`.

Before handling errors, the poll loop pattern-matched only list replies (`[binnum] = rpc(...)`). A `MatchError` in the linked poll process caused:

1. `Connection` to receive `{:EXIT, poll_pid, {%MatchError{}, _}}`
2. `handle_info({:EXIT, ...})` to treat it as a non-port crash → close SSL and **stop** the whole `Connection` GenServer

That turned a transient disconnect during fallback polling into a full connection death (and Manager restart). The fix retries on the next `block_time` tick instead.

Expected poll behaviour on errors:

| RPC result | Poll action |
| ---------- | ----------- |
| `[binnum]` + `[block]` | `send {:peak, ...}`; continue loop |
| `{:error, "remote_closed"}` | Skip tick; continue loop (relay resetting or socket down) |
| `{:error, other}` | Same — continue loop |
| Unexpected shape | `with`/`else` continues loop (no crash) |
| `{:DOWN, conn}` | Exit `:ok` |

## `remote_closed` propagation

`remote_closed` is the uniform signal that the relay link is gone or resetting. It covers both an in-process socket reset and a dead `Connection` GenServer.

| Layer | Behaviour |
| ----- | --------- |
| `reset/1` | Replies blocked `peak/1` waiters indirectly (peaks cleared); sync RPC gets `[req, ["error", "remote_closed"]]`; async RPC gets `{:error, :remote_closed}` |
| `Connection.call/3` | On GenServer gone (`:noproc`, `:normal`, `:killed`, `:shutdown`) exits `:connection_shutdown` |
| `Connection.rpc/3` | Maps `remote_closed` replies **and** `:connection_shutdown` exits to `{:error, "remote_closed"}` and logs a warning |
| `Shell.chain_rpc/2` / `Shell.chain_cached_rpc/2` | Retries once on another chain connection |
| `Shell.Common` (`eth_getTransactionReceipt`) | Retries once on `remote_closed` |
| Poll fallback | Retries on next interval (no crash) |

Callers of `Shell.rpc/1` or `Connection.rpc/3` should treat `{:error, "remote_closed"}` as transient unless it persists across reconnect. Do not let `:connection_shutdown` propagate through `Shell.await_all/1` — `rpc/3` converts it first.

## SSL close and failure paths

| Event | Handler | Outcome |
| ----- | ------- | ------- |
| `{:ssl_closed, socket}` | `clientloop/2` | `NodeScorer.report_failure`, `reset/1`, `{:continue, :init}` |
| SSL send error | `ssl_send!/2` | Injects `{:ssl_closed, socket}` |
| Linked non-port EXIT (abnormal) | `handle_info({:EXIT, ...})` | Close socket; **stop** Connection with reason |
| Port EXIT / DOWN | Port cleanup; `portclose` RPC if needed |
| Manager `:stop` | `maybe_shutdown/1` | Close socket when no ports left; exit `:normal` |
| Manager `drop_connection/1` | Sends `:stop` to Connection | Graceful shutdown path |

The poll `MatchError` path was incorrectly using the "linked non-port EXIT" branch — fixing poll error handling keeps reconnect inside the intended `ssl_closed` → `reset` → `init_loop` cycle.

## Tickets and peaks

- **Peaks** — Push (`blockheader` message) or poll (`{:peak, shell, block}`) → `consume_block/3` → `Manager.update_info` → chain peak consensus (see [manager-peak-traffic-split plan](plan/manager-peak-traffic-split.md)).
- **Tickets** — Created after a peak is available for `ticket_shell` (default Moonbeam). `last_ticket: :pending` defers ticket creation until the first peak after reset.

## Related modules

- `DiodeClient.Manager` — connection pool, peak aggregation, traffic routing
- `DiodeClient.Manager.LocalPeakPoller` — HTTP poll fallback for local shells (e.g. Anvil), separate from relay poll
- `DiodeClient.Port` — per-tunnel processes tied to a `Connection`
- `DiodeClient.NodeScorer` — backoff delays after connect failures and abnormal disconnects
