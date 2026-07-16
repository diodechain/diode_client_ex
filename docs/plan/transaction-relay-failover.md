# Plan: Transaction Relay Failover on Sticky Hang

**Status:** Implemented (PR #19, issue #17)  
**Owner package:** `diode_client_ex`  
**Related:** [connection-lifecycle.md](../connection-lifecycle.md), [manager-peak-traffic-split.md](manager-peak-traffic-split.md) Phase 4

---

## 1. Executive summary

Production outages showed that transaction submission could stall for 120 seconds per attempt when a seed relay is wedged (half-open TCP, no `ssl_closed`). Reads continued via `get_chain_connection/1`, but writes were pinned to a single sticky `Connection` with no health check and no pool failover.

This design closes that gap by:

1. Treating RPC **timeout** like **`remote_closed`** at the error surface (retryable `{:error, :timeout}`, no `RuntimeError`).
2. **Failing over `send_transaction` immediately** across a bounded relay pool (sticky first, then traffic-best seeds, then `chain_connection` peers).
3. **Holding sticky preference for 2 minutes** of continuous unhealthiness before rebinding to a different seed — so affinity is preserved through short outages, while txs still move on.
4. Using a shorter per-attempt timeout for write RPCs so failover completes in seconds, not minutes.

The design extends Phase 4 failover work from the peak/traffic split plan and matches patterns already used by `chain_cached_rpc/2` and `eth_getTransactionReceipt`.

---

## 2. Problem statement

| Path | Connection selection | On `remote_closed` | On GenServer timeout (120s) |
|------|---------------------|-------------------|------------------------------|
| Reads (`chain_rpc`, `cached_rpc`) | `get_chain_connection/1` pool | Retry once on another conn | Raises / no pool failover (pre-fix) |
| Writes (`send_transaction`) | `get_sticky_connection/0` (single PID) | No retry in `send_transaction` | Same sticky PID reused; 120s × N |

**Observed production symptom:** identical `#PID<...>` in consecutive `{:timeout, {GenServer, :call, ...}}` exceptions ~2 minutes apart (`ddrive` `TxQueue`).

**Root causes (pre-fix):**

- `Shell.Common.send_transaction/2` always called `Shell.sticky_conn()` with no fallback.
- `Manager.get_sticky_connection?` returned the registered PID while alive — no viability or RPC health check.
- Timeout raised `RuntimeError`; callers could not retry; sticky could re-bind to the same `server_url`.
- Internal `:ping` interval only wakes the local GenServer; it does not probe the remote relay.

---

## 3. Product context and design goals

### 3.1 Why sticky exists

From the peak/traffic split architecture:

- **Traffic** (ports, objects, default RPC, **sticky tx send**, ticket hints) optimizes for **latency and stability**.
- **Chain peaks** optimize for **consensus**, independent of traffic.

Sticky transaction routing is intentional: it keeps submission on the lowest-latency **traffic-viable seed** for ticket alignment and predictable relay affinity. Failover must preserve this happy-path behavior, not replace sticky with random pool selection on every send.

### 3.2 Design goals

| Goal | Rationale |
|------|-----------|
| **Stay sticky on the happy path** | Latency and ticket affinity |
| **Immediate per-tx failover** | Users and `TxQueue` must not wait 120s per wedged relay |
| **Hold sticky preference through short outages** | Only rebind after ~2 minutes of continuous unhealthiness |
| **Consistent transient errors** | Match `{:error, "remote_closed"}` pattern; avoid `RuntimeError` for transport failures |
| **Minimal API break** | `send_transaction/1` return shape stays `{result, tx}`; document new `result` error atoms |
| **Align with Phase 4** | Extend `get_chain_connection/1` failover to writes where relay semantics allow |

### 3.3 Non-goals (v1)

- Rewriting ticket creation / preferred-server-id logic
- Cross-client split-brain tx ordering guarantees
- Full active SSL application-level keepalive (defer if needed)
- Changing default 120s timeout for non-transaction RPCs

---

## 4. Solution overview

Combine issue options **A + C + B**, with a **2-minute sticky hold** on preference rebind:

```
send_transaction(tx)
    │
    ▼
Shell.Common.rpc_with_tx_failover(shell, cmd)
    │
    ├─ candidates: sticky → traffic seeds → chain pool (deduped, viable)
    ├─ attempt 1..N within 30s/attempt and 45s total
    │
    ▼
Connection.rpc(conn, cmd, timeout: tx_rpc_timeout)
    │
    ├─ success → Manager.connection_rpc_ok(conn); return response
    ├─ {:error, "remote_closed"} → Manager.connection_rpc_failed(conn, :remote_closed); next
    ├─ {:error, :timeout} → cast {:rpc_timeout, req}; connection_rpc_failed(conn, :timeout); next
    └─ budget exhausted → {:error, :relay_exhausted}
```

**Layer 1 — Error surface (`Connection`)**  
Map GenServer call timeout to `{:error, :timeout}`. On timeout, cast `{:rpc_timeout, req}` (only reset if `req` still in `recv_id`) and notify `Manager.connection_rpc_failed/2`. On success, notify `Manager.connection_rpc_ok/1`. Map `:connection_shutdown` exits to `{:error, "remote_closed"}`.

**Layer 2 — Sticky lifecycle (`Manager`)**  
On sticky RPC failure: record `rpc_failed_at`, set `sticky_unhealthy_since` if unset, **keep** sticky URL/PID until continuous unhealthiness ≥ **2 minutes** (`@sticky_hold_ms`), then `do_clear_sticky/2`. On sticky RPC success: clear `sticky_unhealthy_since` and that PID’s `rpc_failed_at` (heal). Explicit `clear_sticky_connection/2` remains an immediate force path.

**Layer 3 — Write-path failover (`Shell.Common`)**  
`rpc_with_tx_failover/3` builds ordered candidates via `Manager.tx_relay_candidates/1` and retries on `:timeout` / `"remote_closed"` within attempt and wall-clock budgets.

---

## 5. Sticky hold policy

### 5.1 Intent

| Concern | Policy |
|---------|--------|
| Prefer sticky | Yes — sticky is first in `tx_relay_candidates/1` |
| Per-tx failover while sticky is unhealthy | Immediate — skip sticky via `rpc_failed_at` / hold exclusion |
| When sticky may rebind to a different seed | Only after **2 minutes** (`@sticky_hold_ms = 120_000`) of continuous unhealthiness |
| Heal | Successful RPC on the sticky PID clears `sticky_unhealthy_since` |

### 5.2 State

| Field | Meaning |
|-------|---------|
| `state.sticky` | Preferred sticky `server_url` |
| `Manager.Sticky` | Registered sticky connection PID |
| `sticky_unhealthy_since` | Monotonic ms when sticky first failed; `nil` when healthy |
| `rpc_failed_at` | Per-PID last failure time (60s candidate cooldown) |

### 5.3 Rules

1. **`connection_rpc_failed(pid, reason)`** always records `rpc_failed_at[pid]` (and may `NodeScorer.report_failure` for `:timeout` / `:remote_closed`).
2. If `pid` is current sticky:
   - Set `sticky_unhealthy_since` if currently `nil`.
   - Call `do_clear_sticky` **only if** `now - sticky_unhealthy_since >= @sticky_hold_ms`.
3. If `pid` is not sticky: do not touch sticky preference.
4. **`connection_rpc_ok(pid)`** on sticky: set `sticky_unhealthy_since: nil` and delete `rpc_failed_at[pid]`.
5. **Candidate exclusion:** sticky PID is excluded from `tx_relay_candidates` while `sticky_unhealthy_since != nil` **or** within the 60s `rpc_failed_at` cooldown — so exclusion lasts the full hold window, not only 60s.
6. **`clear_sticky_connection/2`:** immediate unregister + clear `sticky` / `sticky_unhealthy_since` (force path; hold does not apply).

```
sticky RPC failure
       │
       ▼
 set sticky_unhealthy_since (if nil)
 exclude from candidates
 failover this tx to other relays
       │
       ├─ sticky RPC succeeds within 2 min → heal (keep sticky)
       └─ still failing after 2 min → clear sticky; next get may pick new seed
```

---

## 6. Relay candidate ordering

### 6.1 Candidate pool (ordered, deduped)

For shell `S`, `Manager.tx_relay_candidates/1` builds:

1. **Current sticky** (if registered and not excluded by hold/cooldown)
2. **Other traffic-viable seeds** from `traffic_best`, sorted by latency
3. **`chain_connection_pids(S)`** — relays at consensus peak for `S`

All candidates must pass existing `traffic_viable?/2`. No new eligibility rules.

### 6.2 Product decision: may tx use any chain-qualified relay?

**Yes, with ordering above.**

- `sendtransaction` / `sendmetatransaction` are relay forward RPCs, not port-tunnel paths tied to a single seed ticket.
- Reads already use `get_chain_connection/1`; writes fail over to the same qualified set when sticky is unhealthy.
- Sticky remains **preferred** for latency and ticket affinity on the happy path.

### 6.3 Time budgets

| Parameter | Default | Notes |
|-----------|---------|-------|
| `tx_rpc_timeout` | `30_000` ms | Per-attempt GenServer call timeout for write RPCs |
| `tx_failover_attempts` | `3` | Max distinct relay PIDs per `send_transaction` |
| `tx_failover_total_timeout` | `45_000` ms | Wall-clock cap across attempts |
| `@rpc_failure_cooldown_ms` | `60_000` ms | Per-PID exclusion after failure |
| `@sticky_hold_ms` | `120_000` ms | Continuous unhealthiness before sticky rebind |

Worst-case user-visible delay for one `send_transaction`: ~45s (not 120s × N). Sticky rebind to a different seed only after 2 minutes of continuous unhealthiness.

---

## 7. Component design (as implemented)

### 7.1 `DiodeClient.Connection`

- Timeout → `{:error, :timeout}`; cast `{:rpc_timeout, req}`; `Manager.connection_rpc_failed(pid, :timeout)`.
- Success → `Manager.connection_rpc_ok(pid)`.
- `:connection_shutdown` → `{:error, "remote_closed"}` (aligned with PR #20).
- Write path passes `timeout: 30_000`; reads keep `120_000` default.

### 7.2 `DiodeClient.Manager`

```elixir
@doc false
def clear_sticky_connection(pid, reason \\ :rpc_failure)

@doc false
def connection_rpc_failed(pid, reason)

@doc false
def connection_rpc_ok(pid)

@doc false
def tx_relay_candidates(shell) :: [pid()]
```

- `do_clear_sticky/2` wraps `Process.unregister` in `try/rescue ArgumentError` (race if PID already died).
- Hold / heal logic as in §5.

### 7.3 `DiodeClient.Shell.Common`

All `send_transaction/2` clauses use `rpc_with_tx_failover/3`. On `"remote_closed"`, calls `connection_rpc_failed(pid, :remote_closed)` (cooldown + hold), not only `clear_sticky_connection/2`.

Return shape: `{rpc_result, tx}` where `rpc_result` may be `{:error, :timeout}` or `{:error, :relay_exhausted}`.

### 7.4 Downstream contract (`ddrive` `TxQueue`)

| Result | Meaning | Suggested app action |
|--------|---------|---------------------|
| `{:error, :timeout}` | Relay exceeded per-attempt budget (library may already have failed over) | Retry whole operation |
| `{:error, :relay_exhausted}` | All candidates failed within budget | Backoff + alert |
| `{:error, "remote_closed"}` | Transient; failover wrapper retries | Retry if leaked |
| `RuntimeError` | Unexpected | Treat as bug |

---

## 8. Implementation status

### Phase 1 — Error surface + sticky lifecycle

- [x] `Connection.rpc/3`: timeout → `{:error, :timeout}` + guarded `:rpc_timeout` reset + `connection_rpc_failed/2`
- [x] `Manager.clear_sticky_connection/2` (immediate force path)
- [x] Unit tests for timeout mapping and sticky clear
- [x] `connection-lifecycle.md` timeout / sticky hold docs

### Phase 2 — Write-path pool failover

- [x] `Manager.tx_relay_candidates/1`
- [x] `Shell.Common.rpc_with_tx_failover/3` with attempt + wall-clock budgets
- [x] Shorter `tx_rpc_timeout` for write RPCs
- [x] Unit tests in `test/tx_failover_test.exs` (mock relays)
- [x] Partial Phase 4 note in `manager-peak-traffic-split.md`

### Phase 2b — Sticky 2-minute hold

- [x] `sticky_unhealthy_since` + `@sticky_hold_ms` (120s)
- [x] Hold gate in `connection_rpc_failed`; heal via `connection_rpc_ok`
- [x] Exclude sticky from candidates for the full hold window
- [x] Tests for hold / heal / clear-after-2min

### Phase 3 — Proactive health (optional, not done)

- [ ] Sticky viability check in `get_sticky_connection?`
- [ ] Stale peak / RPC failure counter exclusion beyond hold
- [ ] SSL keepalive / application-level ping RPC

---

## 9. Testing strategy

| Test | Assert |
|------|--------|
| Timeout → `{:error, :timeout}` | No raise; `:rpc_timeout` cast |
| Sticky failure within hold | Sticky URL/PID kept; excluded from candidates |
| Sticky failure after 2 min | Sticky cleared; rebind allowed |
| `connection_rpc_ok` on sticky | Hold healed; candidate restored |
| Non-sticky failure | Sticky unchanged |
| Candidate ordering | Sticky → traffic seeds → chain pool; deduped |
| Failover budget | `{:error, :relay_exhausted}` |

---

## 10. Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Duplicate tx if relay accepted but reply lost | Document idempotency; same as today |
| Failover to relay without tx forwarding | `traffic_viable?` gate + fleet validation |
| False failover on slow relay | 30s default >> p99; tunable |
| Thrashing sticky on brief blips | 2-minute hold before rebind |
| `reset/1` during port traffic on same conn | Existing `ssl_closed` behavior; monitor |

---

## 11. Acceptance criteria (issue #17)

- [x] Wedged sticky → failover to another viable relay within bounded time (≤ 45s default).
- [x] Retryable `{:error, :timeout}` / `{:error, :relay_exhausted}` — not only `RuntimeError`.
- [x] Documented: tx may use any `traffic_viable?` relay; sticky preferred; pool fallback; 2-minute sticky hold before rebind.
- [x] Unit/integration-style tests with mock wedged relays (`test/tx_failover_test.exs`).

---

## 12. Documentation updates

- [x] `docs/connection-lifecycle.md` — timeout, `connection_rpc_ok`, sticky hold
- [x] `docs/plan/manager-peak-traffic-split.md` — Phase 4 progress
- [x] This document — as-implemented design including sticky hold

---

## 13. Version history

| Date | Author | Change |
|------|--------|--------|
| 2026-07-15 | Cursor | Initial design for issue #17 |
| 2026-07-16 | Cursor | Updated to as-implemented design: immediate tx failover + 2-minute sticky hold before rebind; `connection_rpc_ok` heal path |
