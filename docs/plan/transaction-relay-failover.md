# Plan: Transaction Relay Failover on Sticky Hang

**Status:** Design (issue #17)  
**Owner package:** `diode_client_ex`  
**Related:** [connection-lifecycle.md](../connection-lifecycle.md), [manager-peak-traffic-split.md](manager-peak-traffic-split.md) Phase 4

---

## 1. Executive summary

Production outages show that transaction submission can stall for 120 seconds per attempt when a seed relay is wedged (half-open TCP, no `ssl_closed`). Reads continue working via `get_chain_connection/1`, but writes are pinned to a single globally registered sticky `Connection` with no health check and no pool failover.

This plan closes that gap by:

1. Treating RPC **timeout** like **`remote_closed`** at the error surface (retryable, no `RuntimeError`).
2. **Invalidating sticky** and marking the wedged connection as failed when a transaction RPC times out or returns a transport error.
3. **Retrying `send_transaction` across a bounded relay pool** (sticky first, then traffic-best seeds, then `chain_connection` peers) within a fixed total budget.
4. Optionally shortening the per-attempt timeout for write RPCs so failover completes in seconds, not minutes.

The design extends existing Phase 4 failover work from the peak/traffic split plan and matches patterns already used by `chain_cached_rpc/2` and `eth_getTransactionReceipt`.

---

## 2. Problem statement

| Path | Connection selection | On `remote_closed` | On GenServer timeout (120s) |
|------|---------------------|-------------------|------------------------------|
| Reads (`chain_rpc`, `cached_rpc`) | `get_chain_connection/1` pool | Retry once on another conn | Raises `RuntimeError`; no pool failover |
| Writes (`send_transaction`) | `get_sticky_connection/0` (single PID) | No retry in `send_transaction` | Same sticky PID reused; 120s × N |

**Observed production symptom:** identical `#PID<...>` in consecutive `{:timeout, {GenServer, :call, ...}}` exceptions ~2 minutes apart (`ddrive` `TxQueue`).

**Root causes in code:**

- `Shell.Common.send_transaction/2` always calls `Shell.sticky_conn()` with no fallback.
- `Manager.get_sticky_connection?` returns the registered PID while alive — no viability or RPC health check.
- `Connection.call/3` catches `:exit` on timeout, kills the connection, and **raises** — callers cannot retry; sticky may re-bind to the same `server_url`.
- Internal `:ping` interval only wakes the local GenServer; it does not probe the remote relay.

---

## 3. Product context and design goals

### 3.1 Why sticky exists

From the peak/traffic split architecture:

- **Traffic** (ports, objects, default RPC, **sticky tx send**, ticket hints) optimizes for **latency and stability**.
- **Chain peaks** optimize for **consensus**, independent of traffic.

Sticky transaction routing is intentional: it keeps submission on the lowest-latency **traffic-viable seed** for ticket alignment and predictable relay affinity. The fix must preserve this happy-path behavior, not replace sticky with random pool selection on every send.

### 3.2 Design goals

| Goal | Rationale |
|------|-----------|
| **Bounded failover latency** | Users and `TxQueue` must not wait 120s per wedged relay |
| **Consistent transient errors** | Match `{:error, "remote_closed"}` pattern; avoid `RuntimeError` for transport failures |
| **Minimal API break** | `send_transaction/1` return shape stays `{result, tx}`; document new `result` error atoms |
| **Align with Phase 4** | Extend `get_chain_connection/1` failover to writes where relay semantics allow |
| **No false-positive resets** | Slow relays must not be dropped on single slow RPC unless timeout budget is exceeded |

### 3.3 Non-goals (v1)

- Rewriting ticket creation / preferred-server-id logic
- Cross-client split-brain tx ordering guarantees
- Full active SSL application-level keepalive (defer to v2 if needed)
- Changing default 120s timeout for non-transaction RPCs

---

## 4. Proposed solution overview

Combine issue options **A + C + B** in three layers:

```
send_transaction(tx)
    │
    ▼
Shell.Common.rpc_with_tx_failover(shell, cmd, rlp)
    │
    ├─ attempt 1: sticky_conn (or next after clear)
    ├─ attempt 2..N: ordered relay candidates (deduped PIDs)
    │
    ▼
Connection.rpc(conn, cmd, timeout: tx_timeout)
    │
    ├─ success → return response
    ├─ {:error, "remote_closed"} → next candidate
    ├─ {:error, :timeout} → Manager.clear_sticky(conn); reset conn; next candidate
    └─ budget exhausted → {:error, :relay_exhausted}
```

**Layer 1 — Error surface (`Connection`)**  
Map GenServer call timeout to `{:error, :timeout}` instead of raising. On timeout, asynchronously notify `Manager` and `reset/1` the wedged connection to clear `recv_id` backlog (same as `remote_closed` teardown).

**Layer 2 — Sticky lifecycle (`Manager`)**  
Add `clear_sticky_connection/1` (optional `reason`) to unregister `Manager.Sticky`, clear `state.sticky` URL binding when the failed PID matches, and exclude that PID from the next candidate list for a short cooldown (e.g. 60s, reusing `NodeScorer` delay semantics).

**Layer 3 — Write-path failover (`Shell.Common`)**  
New internal helper `rpc_with_tx_failover/3` used by all three `send_transaction/2` clauses. Builds an ordered candidate list and tries each until success or budget exhausted.

---

## 5. Relay candidate ordering

### 5.1 Candidate pool (ordered, deduped)

For shell `S`, build `candidates(S)`:

1. **Current sticky** (if registered and not in cooldown)
2. **Other traffic-viable seeds** from `traffic_best`, sorted by latency (same filter as `get_sticky_connection?`)
3. **`chain_connection_pids(S)`** — relays at consensus peak for `S`, sorted by latency

All candidates must pass existing `traffic_viable?/2` (Diode block ≥ chain peak; ticket-shell epoch current). This reuses gates from §8.5 of the peak/traffic split plan — no new eligibility rules.

### 5.2 Product decision: may tx use any chain-qualified relay?

**Recommendation: yes, with ordering above.**

Rationale:

- `sendtransaction` / `sendmetatransaction` are relay RPC commands that forward to chain infrastructure; they are not tied to a single seed's ticket state the way port tunnels are.
- Reads already use `get_chain_connection/1` for Moonbeam/Oasis JSON-RPC; writes should fail over to the same qualified set when sticky is dead.
- Sticky remains the **preferred** path for latency and ticket affinity on the happy path.

Document this in `connection-lifecycle.md` and changelog.

### 5.3 Time budgets

| Parameter | Default | Notes |
|-----------|---------|-------|
| `tx_rpc_timeout` | `30_000` ms | Per-attempt GenServer call timeout for write RPCs only |
| `tx_failover_attempts` | `3` | Max distinct relay PIDs per `send_transaction` call |
| `tx_failover_total_timeout` | `45_000` ms | Wall-clock cap across all attempts |

Worst-case user-visible delay: ~45s (not 120s × N). Configurable via optional `DiodeClient.Store` / app env keys for fleet tuning.

---

## 6. Detailed component design

### 6.1 `DiodeClient.Connection`

**`rpc/3` timeout handling**

- On `:exit, {:timeout, _}` from `GenServer.call`, return `{:error, :timeout}` (do not raise).
- Before returning, cast `Manager.connection_rpc_failed(pid, :timeout)` and call `reset/1` on self to clear wedged `recv_id` entries (prevents poisoned connection after failover).
- Keep raising for unexpected exit reasons (`:noproc`, abnormal exits) — those are distinct from slow relay.

**Write RPC timeout option**

- `send_transaction` path passes `timeout: tx_rpc_timeout` (30s default).
- Read paths keep `120_000` default unchanged.

**Optional v2: backlog / send_timeout detection**

- If `recv_id` has entries older than `tx_rpc_timeout` with no SSL progress, proactively `reset/1`. Defer to Phase 2; v1 relies on caller timeout + reset.

### 6.2 `DiodeClient.Manager`

**New APIs (internal / `@doc false` unless needed externally)**

```elixir
@doc false
def clear_sticky_connection(pid, reason \\ :rpc_failure)

@doc false
def connection_rpc_failed(pid, reason)

@doc false
def tx_relay_candidates(shell) :: [pid()]
```

**`clear_sticky_connection/2`**

- If `Process.whereis(Manager.Sticky) == pid`, unregister and set `sticky: nil`.
- Record `failed_at` for pid in short-lived ETS or map (or delegate to `NodeScorer.report_failure/1` for URL).
- Do **not** stop seed connections on first timeout — `reset/1` + reconnect is enough; `drop_connection` only if repeated failures exceed threshold (future).

**`get_sticky_connection?` enhancement (Phase 2 / optional in v1)**

- Before returning registered PID, verify `traffic_viable?` and pid ∈ `traffic_best` or `chain_connection_pids`. If not, clear and re-select.

### 6.3 `DiodeClient.Shell.Common`

Replace direct `Connection.rpc(Shell.sticky_conn(), ...)` in all `send_transaction/2` heads with:

```elixir
defp rpc_with_tx_failover(shell, cmd) do
  # build candidates via Manager.tx_relay_candidates(shell)
  # try Connection.rpc(pid, cmd, timeout: tx_rpc_timeout) with retries
end
```

Return shape unchanged: `{rpc_result, tx}` where `rpc_result` may now be `{:error, :timeout}`, `{:error, "remote_closed"}`, or `{:error, :relay_exhausted}`.

### 6.4 Downstream contract (`ddrive` `TxQueue`)

Document that transport failures surface as:

| Result | Meaning | Suggested app action |
|--------|---------|---------------------|
| `{:error, :timeout}` | Single relay exceeded per-attempt budget | Retry whole operation (library may have already failed over) |
| `{:error, :relay_exhausted}` | All candidates failed | Backoff + alert |
| `{:error, "remote_closed"}` | Should not leak after failover wrapper; if it does, retry |
| `RuntimeError` | Unexpected crash | Unchanged; treat as bug |

Apps that pattern-match `{:error, :timeout}` will work without change once library stops raising.

---

## 7. Implementation phases

### Phase 1 — Error surface + sticky invalidation (smallest useful fix)

- [ ] `Connection.rpc/3`: timeout → `{:error, :timeout}` + `reset/1` + `Manager.connection_rpc_failed/2`
- [ ] `Manager.clear_sticky_connection/2`
- [ ] `Shell.Common`: single retry on next sticky after clear (no full pool yet)
- [ ] Unit tests for timeout mapping and sticky clear
- [ ] Update `connection-lifecycle.md` timeout row

**Exit:** Second `send_transaction` after wedge uses a different PID within ~30s.

### Phase 2 — Full write-path pool failover

- [ ] `Manager.tx_relay_candidates/1`
- [ ] `Shell.Common.rpc_with_tx_failover/3` with attempt + wall-clock budgets
- [ ] Shorter `tx_rpc_timeout` for write RPCs
- [ ] Integration test: mock relay accepts TCP, never replies to `sendtransaction`
- [ ] Check off Phase 4 item in `manager-peak-traffic-split.md` (partial: tx path)

**Exit:** Acceptance criteria from issue #17 satisfied.

### Phase 3 — Proactive health (optional)

- [ ] Sticky viability check in `get_sticky_connection?`
- [ ] Stale peak / RPC failure counter exclusion
- [ ] Consider SSL keepalive tuning or application-level ping RPC

---

## 8. Testing strategy

### Unit

| Test | Module | Assert |
|------|--------|--------|
| Timeout maps to `{:error, :timeout}` | `Connection` | No raise; `reset/1` clears `recv_id` |
| Sticky cleared on failed pid | `Manager` | `Process.whereis(Sticky)` nil; next sticky differs |
| Candidate ordering | `Manager` | Sticky < traffic seeds < chain pool; deduped |
| Failover stops at budget | `Shell.Common` | Returns `{:error, :relay_exhausted}` |

### Integration

- Extend `manager_test.exs` or new `shell_tx_failover_test.exs` with test doubles / recorded stubs where live seeds are unreliable.
- Scenario: first candidate wedged (never replies), second returns `["response", tx_hash]`; assert different `Connection.server_url/1`.

### Manual

- Reproduce `ddrive` wedge against a known bad seed; confirm tx queue recovers without 120s stalls.

---

## 9. Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Duplicate tx submission if relay accepted but reply lost | Document idempotency expectations; out of scope for client (same as today) |
| Failover to relay without tx forwarding | All candidates pass `traffic_viable?`; integration test on real fleet |
| Aggressive timeout causes false failover | 30s default >> p99 tx RPC; tunable |
| `reset/1` during active port on same Connection | Tx uses seed connections; port traffic uses same pool — reset already happens on `ssl_closed`; monitor for regressions |

---

## 10. Acceptance criteria (issue #17)

- [ ] When sticky relay stops responding, transaction RPC fails over to another viable relay within bounded time (≤ `tx_failover_total_timeout`, not 120s × N).
- [ ] Failure mode surfaces retryable `{:error, :timeout}` / `{:error, :relay_exhausted}` — not only `RuntimeError`.
- [ ] Documented: tx may use any `traffic_viable?` relay; sticky is preferred, pool is fallback.
- [ ] Integration test: wedged relay on first attempt, success on second with different connection.

---

## 11. Documentation updates

- `docs/connection-lifecycle.md` — add timeout / `{:error, :timeout}` propagation table
- `docs/plan/manager-peak-traffic-split.md` — Phase 4 partial completion note
- `CHANGELOG.md` — minor version; behavior change for timeout (no API rename)
- `README.md` — optional one-liner under blockchain interaction about resilient tx send

---

## 12. Version history

| Date | Author | Change |
|------|--------|--------|
| 2026-07-15 | Cursor | Initial design for issue #17 |
