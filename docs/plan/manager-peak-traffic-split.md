# Plan: Split Chain Peak Consensus from Traffic Routing in `DiodeClient.Manager`

**Status:** Implemented (2026-06-18)  
**Owner package:** `diode_client_ex` (`lib/diode_client/manager.ex` and new helpers)  
**Out of scope (v1):** Go `diode_client/rpc/client_manager.go` (latency-only; no multi-chain peak logic)

---

## 1. Overview

`DiodeClient.Manager` currently uses a single `best` connection list for two unrelated jobs:

1. **Chain peak reporting** — what block height/hash each shell (Diode, Moonbeam, Oasis, …) is considered to be at.
2. **Traffic routing** — which relay to use for port open/listen, `getobject`, default RPC, sticky transaction send, and ticket hints.

Those jobs are coupled today: reported peaks are capped to the **minimum** block among latency-selected `best` nodes, and the **connected** quorum for peak math requires a node to be current on **every** subscribed shell. That design is conservative for security but fails under real fleet conditions (Moonbeam nodes tens of thousands of blocks behind while Diode is current; minority of nodes at the true head).

This plan separates **per-chain peak consensus** from **latency-based traffic best**, keeps the public API stable where possible, and documents behavioral changes.

### Integration context

| Module | Role today | After change |
|--------|------------|--------------|
| `DiodeClient.Manager` | Combined peak + best | Orchestrator; delegates to chain + traffic subsystems |
| `DiodeClient.Connection` | Reports per-shell peaks via `update_info` | Unchanged input; triggers chain peak recompute |
| `DiodeClient.Shell.Common` | `peak/0` → `Manager.get_peak/1` | Same API; higher/fresher peaks possible |
| `DiodeClient.Shell` | `rpc/1` → `default_conn/0` | Diode shell unchanged; Moonbeam/Oasis use `get_chain_connection/1` (8.7) |
| `DiodeClient` | `default_conn/0` → `get_connection/0` | Traffic path only |
| `Connection` (tickets) | `get_connection?/0` for preferred server IDs | Traffic path only |

---

## 2. Problem statement (evidence)

Live dDrive RPC (2026-06-18) showed:

- ~37 authenticated relay connections.
- Moonbeam heights bimodal: ~23 nodes at ~16081486+, ~11 nodes **~38,000 blocks behind** (while Diode shell still current on those nodes).
- Reported Moonbeam peak lagged true max when only a **minority** of nodes were 1 block ahead of the majority (percentile trim + `min(best)` cap).

Root causes in current code:

1. **Global `connected/1`** — node must be ≥ reported peak on **all** shells to participate in peak math for **any** shell.
2. **`physical_peak_for_shell/7`** — uses `(len - drop)`-th highest block (≈80th percentile), not supermajority at the top height.
3. **`reported_peaks`** — `min(peaks among best PIDs)` ties peak to latency winners.
4. **Single `best` list** — used for both `get_connection/0` and peak gating.

---

## 3. Design principles

1. **Per-chain independence.** Peak consensus for shell `S` MUST only consider nodes’ peaks for `S` (plus global auth/liveness rules). Staleness on Moonbeam MUST NOT disqualify a node from Diode peak math.

2. **Peaks follow consensus, not latency.** `get_peak/1` MUST reflect a quorum of nodes at the leading edge for that chain, not the fastest relay.

3. **Traffic follows latency, not peak.** `get_connection/0`, sticky conn, port traffic, and object fetch defaults MUST optimize for RTT and stability, not chain head.

4. **Monotonic peaks.** `chain_peaks[shell]` MUST NOT decrease except on explicit reset (seed list change, offline, manual recovery).

5. **Backward-compatible API.** Function names `get_peak/1`, `get_connection/0`, `subscribe_peak/1` stay; document semantic change (peak may exceed any single traffic relay’s reported block).

6. **Testable pure core.** Consensus math lives in a pure module (`Manager.ChainPeaks`) with table-driven tests including live-derived scenarios.

---

## 4. Target architecture

```
Connection {:peak, shell, block}
        │
        ▼
Manager.handle_cast {:update_info, ...}
        │
        ├──► update_chain_peaks/1     (per shell, supermajority)
        │         └── chain_peaks, peak subscribers, waiting_for_peak
        │
        └──► update_traffic_best/1    (latency, auth only)
                  └── traffic_best, waiting_traffic, sticky
```

### 4.1 State rename / split

| Current field | New field | Purpose |
|---------------|-----------|---------|
| `best` | `traffic_best` | Low-latency relay PIDs for traffic |
| `best_timestamp` | `traffic_best_timestamp` | Sticky recompute throttle for traffic |
| `physical_peaks` | _(removed)_ | Replaced by `chain_peaks` |
| `peaks` | `chain_peaks` | Authoritative per-shell peak returned by `get_peak/1` |
| `waiting` | `waiting_traffic` | Blocked `get_connection` callers |

Remove: computing `chain_peaks` from `traffic_best`.

### 4.2 New module: `DiodeClient.Manager.ChainPeaks`

Pure functions (no GenServer):

- `connected_for_shell(shell, conns, chain_peaks, opts)`
- `consensus_peak_for_shell(shell, connected_infos, last_peak, opts)`
- `notify_if_changed(old, new)`

Configurable via opts (resolved in §8): supermajority threshold, stale outlier distance, uncle handling.

### 4.3 Traffic subsystem

`update_traffic_best/2`:

- Candidates: authenticated connections (`server_address != nil`) passing **traffic viability** (§8.5).
- Sort by latency; keep existing `2 * fastest_latency` cluster filter.
- Keep 30s sticky recompute when still viable.

**Traffic viability (8.5):** A relay is eligible for `traffic_best` only if:

1. `block_number(conn.peaks[DiodeClient.Shell]) >= block_number(chain_peaks[DiodeClient.Shell])`
2. `Block.epoch(conn.peaks[ticket_shell]) >= Block.epoch(chain_peaks[ticket_shell])` where `ticket_shell` is `DiodeClient.Shell.Moonbeam` today (default on `Connection` init)

Moonbeam/Oasis **block height** staleness does not exclude a relay from traffic if epoch is current. Gross epoch lag excludes the relay from port/ticket paths.

### 4.4 Public API semantics (unchanged names)

| Function | Semantics after change |
|----------|------------------------|
| `get_peak(shell)` | `chain_peaks[shell]` from consensus |
| `get_connection/0` | Random PID from `traffic_best` |
| `get_sticky_connection/0` | Lowest-latency seed from `traffic_best` (sticky register unchanged) |
| `subscribe_peak(shell)` | Message on `chain_peaks` change only |

**Removed invariant:** “peak never higher than any `get_connection` relay’s reported peak.”

---

## 5. Consensus algorithm (proposed default)

> **Subject to §8 decisions.** This is the recommended default.

For each subscribed `shell`:

1. Let `C` = `connected_for_shell(shell)` — nodes with `block_number(conn.peaks[shell]) >= block_number(chain_peaks[shell])` and `server_address != nil`.
2. If `|C| < min_connections()` → no update; `get_peak` may block (unchanged).
3. Let `max` = highest block number in `C`.
4. **Outlier trim (gross stale only):** drop nodes where `max - block_number < -stale_threshold(shell)` from consensus set `C'`. Default `stale_threshold`: shell-specific (e.g. 128 blocks Moonbeam, 64 Diode) — not the current bottom-20% percentile.
5. At height `h` from `max` downward, find block hashes with count ≥ `supermajority(|C'|)`.
6. Pick highest `h` with a winning hash; ties at same height use existing plurality / uncle hold logic.
7. Advance `chain_peaks[shell]` only if `h > old_h` and agreement ≥ threshold.

---

## 6. Implementation phases

### Phase 1 — Decouple + per-shell connected (low risk, high value)

- [x] Introduce `connected_for_shell/2`; stop using global `connected/1` in peak path.
- [x] Set `chain_peaks[shell]` from `Manager.ChainPeaks` consensus per shell.
- [x] Remove `min(best)` reported peak cap.
- [x] Add `get_chain_connection/1`; route Moonbeam/Oasis `Shell.rpc` through it (8.7).
- [x] Update tests; fix docstrings.

**Exit criteria:** Moonbeam staleness no longer poisons Diode peak; peaks no longer capped by fastest nodes.

### Phase 2 — Supermajority consensus

- [x] Extract `Manager.ChainPeaks` with new algorithm (§5).
- [x] Replace percentile `drop` logic.
- [x] Add regression tests from live histogram scenarios.

**Exit criteria:** Minority at `H+1` with majority at `H` resolves to `H+1` when ≥ supermajority at `H+1`.

### Phase 3 — Traffic rename + decouple

- [x] Rename `best` → `traffic_best` internally; keep `get_connection` behavior.
- [x] Separate debounce/sticky timers if needed.
- [x] Update `manager_best_change_test.exs` → traffic-focused tests.

### Phase 4 — Optional extensions (v2)

- [x] Failover on transport errors (`remote_closed`, `:timeout`) for `send_transaction` across relay pool (issue #17)
- [ ] Failover on known Moonbeam RPC errors across `get_chain_connection` pool
- [ ] Configurable `ticket_shell` per fleet / connection

---

## 7. Testing

### Unit tests (`test/manager_chain_peaks_test.exs`)

| Scenario | Expected `chain_peaks` |
|----------|------------------------|
| 20 @ H+1, 3 @ H | H+1 (majority) |
| 8 @ H+1, 15 @ H | **§8.1 decides** |
| 11 nodes 38k behind, 23 current | Current max (outliers trimmed) |
| Node stale Moonbeam only | Excluded from Moonbeam quorum; still in Diode quorum |
| Uncle hashes at same height | Hold / plurality per §8.3 |
| \|C\| < min_connections | No change; waiters block |

### Integration tests

- Update `manager_test.exs`: remove old peak≤conn invariant; add per-shell tests.
- Keep `manager_best_change_test.exs` for traffic sticky behavior.

### Manual verification

- `~/dDrive/dDrive rpc` histogram script (document in `notes.exs` or mix task).
- Confirm `get_peak(Moonbeam)` tracks fleet max when supermajority agrees.

---

## 8. Open product decisions

Each item needs owner sign-off before Phase 2+.

| ID | Decision | Recommendation | Chosen |
|----|----------|----------------|--------|
| **8.1** | Supermajority threshold | **Strict majority:** `floor(n/2) + 1` | **✓ Strict majority** (2026-06-18) |
| **8.2** | Minority ahead (e.g. 8 @ H+1, 15 @ H) | **Promote to H+1 only if count ≥ majority threshold; else stay at H** | **✓ Wait for majority** (2026-06-18) |
| **8.3** | Uncle / hash split at same height | **Keep current plurality; equal split → hold peak** | **✓ Plurality + hold on tie** (2026-06-18) |
| **8.4** | Traffic candidate gate | **Auth only** — no shell peak requirement | **✓ Auth only** (2026-06-18) |
| **8.5** | Ticket / port traffic gate | **Diode:** `block ≥ chain_peaks[Diode]`. **Ticket shell (Moonbeam):** `epoch(conn_peak) ≥ epoch(chain_peaks[Moonbeam])` | **✓ Diode block + ticket-shell epoch** (2026-06-18) |
| **8.6** | Gross stale threshold | **Per-shell config:** Moonbeam 128 blocks, Diode 64, default 64 | **✓ Per-shell defaults** (2026-06-18) |
| **8.7** | Phase 4 per-shell RPC routing | **Phase 1:** Moonbeam + Oasis (non-Diode shells) use `get_chain_connection(shell)`; Diode keeps `default_conn` | **✓ Moonbeam/Oasis in v1** (2026-06-18) |
| **8.8** | Backward compatibility / release | **Minor behavior change** in changelog; no API break | **✓ Minor + changelog** (2026-06-18) |
| **8.9** | `physical_peaks` vs `chain_peaks` | **Merge to `chain_peaks` only** unless debugging needs both | **✓ Single `chain_peaks`** (2026-06-18) |

### Resolved summary

| Area | Decision |
|------|----------|
| Consensus | Strict majority (`floor(n/2)+1`) per shell; wait for majority before advancing to H+1 |
| Uncles | Plurality at height; hold on tie |
| Traffic pool | Auth + Diode block gate + ticket-shell epoch gate (Moonbeam) |
| Stale trim | Moonbeam 128 blocks, Diode 64, default 64 |
| RPC routing | Moonbeam/Oasis → `get_chain_connection/1` in Phase 1; Diode → `default_conn` |
| Release | Minor version + changelog |
| State | `chain_peaks` only; `best` → `traffic_best` |

---

## 9. Risks and mitigations

| Risk | Mitigation |
|------|------------|
| Higher reported peak than any traffic relay has seen | Document; v2 `get_chain_connection` for RPC |
| Flash majority on wrong fork | Hash agreement required; monotonic advance |
| More frequent peak updates | Existing 5s debounce on Manager update |
| Split-brain across clients | Out of scope; same as today |

---

## 10. Version history

| Date | Author | Change |
|------|--------|--------|
| 2026-06-18 | Dominic | All §8 product decisions resolved via review |
