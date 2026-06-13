# Whitelist Design Spec
**Date:** 2026-06-13  
**Status:** Draft

## Problem

The heuristic scanner fires false positives when it reads content that *describes* injection patterns rather than *executing* them. Common cases:

- **prompt-guard's own source code** — `scan.py`'s regex strings contain the exact keywords the scanner detects (`ignore|disregard|override`, `run|execute|eval`, `you are now`, etc.)
- **Memory files with command documentation** — operational notes containing shell command examples trigger `embedded_command`
- **Security documentation** — any file discussing injection attacks quotes the attack patterns

The scanner correctly identifies the text pattern; the pattern just isn't an attack in context. What's needed is a way to declare specific matched text as known-benign so those signal hits are suppressed.

## Non-Goals

- **Path-level bypass** — whitelisting entire files or directories would allow a real attack hiding in a whitelisted file to go undetected. The whitelist targets specific evidence text, not content sources.
- **Signal-type bypass** — whitelisting an entire signal ID (e.g., "never report `embedded_command`") is too broad. Entries must be scoped to specific matched text.
- **Changes to `scan.py`** — the scanner stays pure. Filtering is guard-layer logic.

## Whitelist Format

A plaintext config file at `<project_root>/whitelist.conf`, overridable via `PROMPTGUARD_WHITELIST_FILE`.

```
# prompt-guard whitelist
# Format: signal_id: text_pattern
# text_pattern is a case-insensitive substring matched against the signal's evidence field.
# Lines starting with # are comments. Blank lines are ignored.

embedded_command: execute|eval|delete|rm -rf|drop table
instruction_override: ignore|disregard|forget|override|bypass
```

**Rules:**
- `signal_id` must exactly match a signal's `id` field (e.g., `embedded_command`, `instruction_override`)
- `text_pattern` is matched as a case-insensitive substring against the signal's `evidence` field
- A signal is suppressed when both its `id` and `evidence` match a whitelist entry
- Multiple entries with the same `signal_id` are OR'd — any matching pattern suppresses the signal
- The config file is loaded once per process (cached); mtime-checked on each call for hot-reload

## Architecture

### New module: `promptguard/whitelist.py`

Single responsibility: load, cache, and apply the whitelist.

```python
def load() -> list[tuple[str, str]]:
    """Return list of (signal_id, pattern) pairs from config file."""

def is_suppressed(signal: dict, entries: list) -> bool:
    """True if signal's id+evidence match any whitelist entry."""

def filter_signals(signals: list, entries: list) -> list:
    """Return only signals not suppressed by the whitelist."""
```

The module caches the parsed config keyed by `(path, mtime)`. If the file doesn't exist, returns an empty list (no suppression). If the file has a parse error on a line, that line is skipped with a stderr warning; other entries still apply.

### Changes to `guard.py`

Applied in **both** `check_output` (D1) and `check_memory_write` (D2), after `_scan()` returns and before computing advisory or recording taint:

```python
entries = _whitelist.load()
filtered_signals = _whitelist.filter_signals(result["signals"], entries)
filtered_score = min(100, sum(s["weight"] for s in filtered_signals))
filtered_band = _band(filtered_score)
```

The original `result` from `_scan()` is preserved unchanged. `filtered_signals` and `filtered_score` are used for:
- Advisory decision (emit only if `filtered_band >= _MIN_BAND`)
- Taint recording (record only if `filtered_band >= _TAINT_MIN_BAND`)
- Advisory text (lists only non-suppressed signals)

`check_pre_tool` (D5, egress URL scan) is not affected — it scans URLs, not content, and has no evidence field.

### Score recomputation

After filtering, the score is the sum of remaining signals' `weight` fields, capped at 100. This is correct because signal weights are additive — removing a signal removes its weight contribution exactly.

Obfuscation bonuses (`invisible_chars`, `homoglyphs`) are treated as signals with their own entries in the filtered list and can also be whitelisted.

## Workflow

```
1. False positive fires → see advisory with signal IDs
2. Run: python3 -m promptguard.scan --pretty <file>
3. Find the evidence field for the false-positive signal
4. Add entry to whitelist.conf: signal_id: <evidence_substring>
5. Re-run scan to verify suppression
6. Future scans: false positive is silenced; real attacks with different text still fire
```

## Security Properties

- **Precision over breadth** — entries suppress only the specific evidence text specified, not the entire signal type. A real attack using different phrasing is unaffected.
- **No path bypass** — whitelisting is based on what matched, not where content came from. An attacker cannot exploit a whitelisted path to smuggle attacks.
- **Scan still runs** — all content is scanned regardless. The whitelist filters the output, not the input.
- **Explicit user action** — the whitelist requires deliberate editing of `whitelist.conf`. It cannot be modified by tool output or injected content.
- **Taint suppression is coupled** — taint is only skipped when the filtered score (post-whitelist) is below threshold. A partially-whitelisted result that still exceeds the band still records taint.

## Testing

- `tests/test_whitelist.py` (new):
  - Load from file, missing file returns empty, malformed lines skipped
  - `is_suppressed`: case-insensitive match, wrong ID doesn't suppress, wrong pattern doesn't suppress
  - `filter_signals`: removes matched, keeps unmatched, empty entries = no suppression
  - Score recomputation: correct sum after filtering
  - Mtime-based cache invalidation
- `tests/test_scan.py` — no changes (scan.py untouched)
- `tests/test_posttooluse_session.py` — add: whitelisted signal does not increment taint

## Files Changed

| File | Change |
|------|--------|
| `promptguard/whitelist.py` | New — load, cache, filter logic |
| `promptguard/guard.py` | Apply whitelist in `check_output` and `check_memory_write` |
| `whitelist.conf` | New — empty default config with commented instructions |
| `tests/test_whitelist.py` | New — unit tests for whitelist module |
| `tests/test_posttooluse_session.py` | Add taint-suppression test |
| `scan.py` | No changes |
| `hooks/` | No changes |
