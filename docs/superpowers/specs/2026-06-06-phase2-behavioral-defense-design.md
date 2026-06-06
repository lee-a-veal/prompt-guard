# Phase 2: Behavioral Defense — Design Spec

**Date:** 2026-06-06  
**Status:** Approved  
**Deficiencies addressed:** D3 (Behavioral monitoring), D5 (Egress exfiltration), D6 (Multi-turn staging)  
**Builds on:** Phase 1 (posttooluse_guard.py, prememwrite_guard.py, scan.py, normalize.py)

---

## 1. Context and Goals

Phase 1 added per-input sanitization (Stage 1 heuristic scan + Stage 2 LLM judge on escalation) and memory-write blocking. Both operate on individual tool calls in isolation.

Phase 2 adds session awareness: the ability to detect threats that span multiple tool calls and to block URL-based exfiltration before it leaves the process. Three concrete goals:

| Goal | Deficiency | Mechanism |
|------|-----------|-----------|
| Block exfiltration URLs before WebFetch executes | D5 | `pretooluse_guard.py` + `urlscan.py` |
| Warn when session has accumulated many tainted inputs | D6 | Session state + `pretooluse_guard.py` |
| Detect suspicious tool-call sequences and rate spikes | D3 | Session state + `pretooluse_guard.py` |

Stage 2 LLM-as-judge (SKILL.md + escalation via PostToolUse hook) is already implemented and is marked complete.

---

## 2. Session State Library — `promptguard/session.py`

### 2.1 State file

```
/tmp/promptguard_{uid}_{cwd_hash}.json
```

- `uid` = `os.getuid()` — prevents cross-user state sharing on shared machines
- `cwd_hash` = first 12 hex chars of `md5(os.getcwd().encode())` — one file per working directory
- Override: `PROMPTGUARD_SESSION_FILE` env var replaces the entire path (used in tests and custom deployments)

### 2.2 Schema

```json
{
  "session_start": 1234567890.0,
  "last_seen":     1234567890.0,
  "taint_count":   3,
  "tainted_sources": ["Bash", "WebFetch"],
  "tool_calls": [
    {"ts": 1234567890.0, "tool": "Read",     "label": "/home/user/.ssh/id_rsa"},
    {"ts": 1234567895.0, "tool": "WebFetch", "label": "https://example.com"}
  ]
}
```

Fields:
- `session_start` / `last_seen` — Unix timestamps (float). Used for window expiry.
- `taint_count` — number of tool outputs that scored MEDIUM+ this session.
- `tainted_sources` — list of tool names that contributed taint (diagnostic, not deduplicated).
- `tool_calls` — chronological log of tool calls, capped at 200 entries (oldest trimmed). Each entry records the tool name and a short label (URL, command prefix, or file path).

### 2.3 Session window

A session is active if `time.time() - last_seen <= window`. Default window: **4 hours** (14 400 s). Configurable via `PROMPTGUARD_SESSION_WINDOW` (integer seconds). When the window expires, `load()` returns a fresh empty state and the old file is overwritten on the next `save()`.

### 2.4 Public API

```python
session.load()                        # → dict; fresh if missing/corrupt/expired
session.save(state)                   # atomic write (tmp → rename)
session.record_taint(tool_name)       # load → increment taint_count → save
session.record_tool_call(tool, label) # load → append → trim → save
session.get_taint_count()             # → int; 0 on any error
session.get_recent_calls(window_secs) # → list[dict] within window; [] on error
```

All functions catch every exception and never raise — a session I/O failure must not affect hook output or exit code.

### 2.5 Concurrency

Hooks are short-lived subprocesses. The `os.rename()` call on the same filesystem is atomic (POSIX). Two concurrent writes could each read stale state and overwrite each other; the last writer wins. Worst case: one taint increment is lost. Acceptable for a behavioral counter — we are not a distributed ledger.

### 2.6 Constraints

- Python 3.6.8 compatible, no third-party dependencies.
- File size is bounded: `tool_calls` cap at 200 entries, each entry is ~80 bytes → max ~16 KB per session file.

---

## 3. PostToolUse Extension — `hooks/posttooluse_guard.py`

Two new side effects are added after scanning, both wrapped in try/except:

**A. Record every tool call** (unconditional, for D3):
```python
label = _extract_label(tool_name, event.get("tool_input", {}))
session.record_tool_call(tool_name, label)
```

**B. Record taint when MEDIUM+** (for D6):
```python
if band in ("medium", "high"):
    session.record_taint(tool_name)
```

### 3.1 Label extraction

| Tool | Label |
|------|-------|
| WebFetch | `tool_input["url"][:80]` |
| Bash | `tool_input["command"][:60]` |
| Read | `tool_input["file_path"][:80]` |
| Grep | `tool_input.get("pattern", "")[:40] + " in " + tool_input.get("path", "")[:40]` |
| Glob | `tool_input.get("pattern", "")[:80]` |
| Others | `""` |

Labels are truncated and stored only for behavioral pattern detection — they are never emitted to the model as advisory content.

### 3.2 Ordering

```
parse event
├── check tool_name in _WATCHED → exit if not
├── extract text from tool_response
├── extract label from tool_input          ← new
├── session.record_tool_call(tool, label)  ← new (always, try/except)
├── scan(text)
├── if MEDIUM+:
│   ├── emit advisory                      (existing)
│   └── session.record_taint(tool_name)   ← new (try/except)
└── exit 0
```

The advisory output path is unchanged — session I/O never delays or suppresses it.

---

## 4. URL Scan Module — `promptguard/urlscan.py`

A separate module from `scan.py`. URLs are short structured strings with different attack patterns than document text; applying the document scanner to a URL produces false positives on normal web browsing.

### 4.1 Signals

| ID | Weight | Detection |
|----|--------|-----------|
| `sensitive_param_name` | 50 | Query param **name** matches: `api_key`, `apikey`, `api-key`, `token`, `secret`, `password`, `passwd`, `credential`, `auth`, `bearer`, `session`, `id_rsa`, `private_key`, `access_key`, `secret_key`, `key` |
| `base64_param_value` | 30 | Any query param **value** ≥ 20 chars matching base64 alphabet (`[A-Za-z0-9+/=]`) |
| `localhost_exfil` | 20 | Host is `localhost`, `127.0.0.1`, `0.0.0.0`, or `::1`, AND query params are present |

### 4.2 Thresholds

- Score ≥ 50 → **block** (single `sensitive_param_name` hit is sufficient)
- Score 20–49 → **warn** via `additionalContext`
- Score < 20 → allow silently

### 4.3 Tradeoffs acknowledged

Blocking a URL with `?api_key=` will also block legitimate user-requested API calls that use query-param authentication. This is intentional: query-param credentials are bad practice regardless of origin, and the block surfaces the issue to the operator. Users can set `PROMPTGUARD_MIN_BAND=high` to raise the egress block threshold, or set `PROMPTGUARD_URL_SCAN=off` to disable D5 entirely.

### 4.4 Scope

HTTP and HTTPS only. `data:`, `mailto:`, `file:` schemes: allow (out of scope for Phase 2). URL parse failure: allow silently.

### 4.5 Public API

```python
urlscan.scan(url)  # → {"risk_score": int, "risk_band": str, "signals": [...]}
```

Same return shape as `promptguard.scan.scan()` for consistency.

---

## 5. PreToolUse Guard — `hooks/pretooluse_guard.py`

Matched on `WebFetch|Bash`. Runs three checks in order. D5 can block; D6 and D3 are advisory only. If D5 blocks, D6 and D3 are skipped. Otherwise, all advisory messages are concatenated into a single `additionalContext` output.

### 5.1 D5 — Egress URL scan (WebFetch only)

```python
url = tool_input.get("url", "")
result = urlscan.scan(url)
if result["risk_band"] == "high":
    → block: "prompt-guard blocked WebFetch: {score}/100 HIGH — {signals}. ..."
elif result["risk_band"] == "medium":
    → advisory: "⚠ PROMPT-GUARD (egress): URL scored {score}/100 ..."
```

### 5.2 D6 — Session taint check (WebFetch + Bash)

```python
taint = session.get_taint_count()
threshold = int(os.environ.get("PROMPTGUARD_TAINT_THRESHOLD", "3"))
if taint >= threshold:
    → advisory: "⚠ PROMPT-GUARD (session taint): {taint} flagged inputs this session. ..."
```

Default threshold: **3**. At threshold=3, the warning fires after three separately flagged tool outputs in the same session, indicating substantial untrusted content ingestion.

### 5.3 D3 — Behavioral pattern check (WebFetch + Bash)

Two patterns:

**Pattern 1 — Read-then-fetch (60 s window, WebFetch only):**
```python
recent = session.get_recent_calls(60)
file_reads = [c for c in recent if c["tool"] in ("Read", "Grep", "Glob")]
if file_reads and tool_name == "WebFetch":
    → advisory: "⚠ PROMPT-GUARD (behavior): file read preceded this fetch within 60s ..."
```

**Pattern 2 — WebFetch rate spike (2 min window, WebFetch only):**
```python
recent = session.get_recent_calls(120)
fetches = [c for c in recent if c["tool"] == "WebFetch"]
spike_threshold = int(os.environ.get("PROMPTGUARD_RATE_THRESHOLD", "5"))
if len(fetches) >= spike_threshold:
    → advisory: "⚠ PROMPT-GUARD (behavior): {N} WebFetch calls in the last 2 min ..."
```

Note: rate spike intentionally tracks WebFetch only (not Bash), as Bash calls are common in legitimate development work (test runs, builds) and would produce excessive false positives.

### 5.4 Output format

All advisory messages are emitted as a single `hookSpecificOutput.additionalContext` string, separated by newlines. Block output is the standard `{"decision": "block", "reason": "..."}` format.

### 5.5 Environment variables

| Variable | Default | Effect |
|----------|---------|--------|
| `PROMPTGUARD_TAINT_THRESHOLD` | `3` | D6 taint count before warning |
| `PROMPTGUARD_RATE_THRESHOLD` | `5` | D3 WebFetch count in 2 min before warning |
| `PROMPTGUARD_URL_SCAN` | `on` | Set to `off` to disable D5 entirely |

---

## 6. Settings.json Changes

New `PreToolUse` entry alongside the existing `Write|Edit` entry:

```json
{
  "matcher": "WebFetch|Bash",
  "hooks": [
    {
      "type": "command",
      "command": "python3 /home/lost/projects/prompt-guard/hooks/pretooluse_guard.py"
    }
  ]
}
```

`install.sh` updated:
- `chmod +x` the new hook
- Print the `PreToolUse: WebFetch|Bash` snippet in the settings block
- Document the three new env vars

---

## 7. Testing Plan

All tests are `unittest`-based, Python 3.6.8 compatible, no third-party dependencies. Hook integration tests use subprocess (matching the existing pattern in `test_memwrite_guard.py`).

### 7.1 `tests/test_session.py` — unit tests (~12 tests)

| Test | Verifies |
|------|---------|
| `test_fresh_on_missing_file` | `load()` returns valid empty state when file absent |
| `test_fresh_on_corrupt_file` | `load()` returns empty state on JSON parse error |
| `test_session_expires_after_window` | State with old `last_seen` treated as fresh |
| `test_session_continues_within_window` | State with recent `last_seen` is returned as-is |
| `test_record_taint_increments` | `record_taint()` increments `taint_count` by 1 |
| `test_record_taint_adds_source` | `record_taint("Bash")` appends "Bash" to `tainted_sources` |
| `test_record_tool_call_appends` | `record_tool_call()` adds entry with ts, tool, label |
| `test_tool_calls_trimmed_at_200` | 201st call trims oldest, list stays at 200 |
| `test_get_recent_calls_respects_window` | Returns only calls within specified seconds |
| `test_get_taint_count_fresh` | Returns 0 for fresh session |
| `test_atomic_save_valid_json` | Written file is always valid JSON |
| `test_custom_file_env` | `PROMPTGUARD_SESSION_FILE` overrides default path |

### 7.2 `tests/test_urlscan.py` — unit tests (~11 tests)

| Test | Verifies |
|------|---------|
| `test_clean_https_url_passes` | Normal URL scores none |
| `test_url_with_normal_params_passes` | `?q=hello&lang=en` scores none |
| `test_api_key_param_caught` | `?api_key=xxx` → MEDIUM/HIGH |
| `test_token_param_caught` | `?token=xxx` → MEDIUM/HIGH |
| `test_secret_param_caught` | `?secret=xxx` → MEDIUM/HIGH |
| `test_password_param_caught` | `?password=xxx` → MEDIUM/HIGH |
| `test_base64_value_caught` | `?data=aGVsbG8gd29ybGQ=` → MEDIUM+ |
| `test_localhost_with_params_warns` | `http://localhost/?q=foo` → MEDIUM |
| `test_private_ip_caught` | `http://127.0.0.1/?k=v` → MEDIUM |
| `test_url_parse_failure_clean` | Malformed URL returns none band |
| `test_no_query_params_clean` | URL with no query string scores none |

### 7.3 `tests/test_pretooluse_guard.py` — integration tests (~14 tests)

Uses subprocess + `PROMPTGUARD_SESSION_FILE` to inject a pre-populated session state, and `PROMPTGUARD_TAINT_THRESHOLD` / `PROMPTGUARD_RATE_THRESHOLD` to control thresholds.

| Test | Verifies |
|------|---------|
| `test_non_watched_tool_ignored` | Tool not in WebFetch/Bash → no output |
| `test_bash_clean_session_no_output` | Bash with empty session → no output |
| `test_d5_blocks_api_key_url` | `?api_key=xxx` → `decision: block` |
| `test_d5_warns_localhost_url` | Localhost URL → additionalContext warning |
| `test_d5_clean_url_no_output` | Normal URL → no D5 output |
| `test_d5_disabled_by_env` | `PROMPTGUARD_URL_SCAN=off` → no D5 output |
| `test_d6_fires_at_threshold` | taint_count=3 → advisory contains "taint" |
| `test_d6_silent_below_threshold` | taint_count=2 → no D6 advisory |
| `test_d3_read_then_fetch_fires` | Session has recent Read → WebFetch → advisory |
| `test_d3_read_then_fetch_outside_window` | Read > 60s ago → no D3 advisory |
| `test_d3_rate_spike_fires` | 5 recent WebFetch calls → advisory |
| `test_d3_rate_below_threshold_silent` | 4 recent WebFetch calls → no D3 advisory |
| `test_d5_block_skips_d6_d3` | D5 block → output has only `decision`, not D6/D3 |
| `test_invalid_json_exits_cleanly` | Malformed stdin → exit 0, no output |

### 7.4 `tests/test_posttooluse_session.py` — integration tests (~5 tests)

| Test | Verifies |
|------|---------|
| `test_medium_content_writes_taint` | MEDIUM+ scan → taint_count incremented in session file |
| `test_low_content_no_taint_written` | LOW scan → taint_count unchanged |
| `test_tool_call_always_recorded` | Any watched tool → entry in tool_calls |
| `test_session_file_created_on_first_call` | Session file created if absent |
| `test_session_write_failure_does_not_suppress_advisory` | Session write error → advisory still emitted |

**Total new tests: ~42.** Combined with existing 57: **~99 tests**.

---

## 8. File Map

| Action | File |
|--------|------|
| Create | `promptguard/session.py` |
| Create | `promptguard/urlscan.py` |
| Modify | `hooks/posttooluse_guard.py` |
| Create | `hooks/pretooluse_guard.py` |
| Modify | `install.sh` |
| Modify | `~/.claude/settings.json` |
| Create | `tests/test_session.py` |
| Create | `tests/test_urlscan.py` |
| Create | `tests/test_pretooluse_guard.py` |
| Create | `tests/test_posttooluse_session.py` |

---

## 9. Known Limitations

| Limitation | Accepted? |
|-----------|----------|
| Session state race (concurrent writes lose one record) | Yes — behavioral counter, not a ledger |
| Time-window sessions: two Claude Code windows in same dir share state | Yes — slightly over-conservative, not dangerous |
| D3 read-then-fetch fires on legitimate workflows (read README, then look up a URL) | Yes — advisory only, no block; operator can raise threshold |
| D5 blocks legitimate API calls with query-param auth | Yes — by design; bad practice regardless, operator can disable |
| D3/D6 only cover WebFetch and Bash (not all tool types) | Yes — highest-risk tools; other tools tracked in session for D3 pattern matching |
| No cross-session state (session resets after 4h idle) | Yes — bounded attack window; persistent tracking is Phase 3 |

---

## 10. Out of Scope (Phase 3)

- Memory content provenance tags (D2 full coverage)
- MCP tool description auditing (D4)
- Egress markdown-image exfiltration prevention (D5 full coverage)
- Cross-session behavioral baselines
- CaMeL/FIDES taint tracking integration (D7)
