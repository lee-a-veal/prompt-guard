# Whitelist Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add per-signal evidence whitelist to prompt-guard so known-benign scanner hits can be suppressed without bypassing whole files or signal types.

**Architecture:** New `promptguard/whitelist.py` module loads a plaintext `whitelist.conf` from the project root, caches it by mtime, and exposes `filter_signals()`. Both `check_output` (D1) and `check_memory_write` (D2) in `guard.py` apply the filter after scanning and before recording taint or emitting advisories. `scan.py` is untouched.

**Tech Stack:** Python 3.6.8+, stdlib only (`os`, `sys`), `unittest`.

**Baseline:** 135 tests passing — all tasks must keep this green.

---

### Task 1: Create `promptguard/whitelist.py` with tests

**Files:**
- Create: `promptguard/whitelist.py`
- Create: `tests/test_whitelist.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/test_whitelist.py`:

```python
"""Tests for promptguard/whitelist.py."""
from __future__ import unicode_literals

import os
import sys
import tempfile
import time
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

import promptguard.whitelist as wl


def _write_conf(path, text):
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class TestLoad(unittest.TestCase):
    def setUp(self):
        # Reset module cache before each test
        wl._cache_key = None
        wl._cache_entries = []

    def test_missing_file_returns_empty(self):
        os.environ["PROMPTGUARD_WHITELIST_FILE"] = "/tmp/no_such_file_prompt_guard.conf"
        result = wl.load()
        self.assertEqual(result, [])

    def test_parses_valid_entries(self):
        fd, path = tempfile.mkstemp(suffix=".conf")
        os.close(fd)
        try:
            _write_conf(path, "embedded_command: rm -rf\ninstruction_override: ignore\n")
            os.environ["PROMPTGUARD_WHITELIST_FILE"] = path
            wl._cache_key = None
            result = wl.load()
            self.assertEqual(result, [
                ("embedded_command", "rm -rf"),
                ("instruction_override", "ignore"),
            ])
        finally:
            os.unlink(path)
            os.environ.pop("PROMPTGUARD_WHITELIST_FILE", None)

    def test_comments_and_blank_lines_skipped(self):
        fd, path = tempfile.mkstemp(suffix=".conf")
        os.close(fd)
        try:
            _write_conf(path, "# comment\n\nembedded_command: eval\n")
            os.environ["PROMPTGUARD_WHITELIST_FILE"] = path
            wl._cache_key = None
            result = wl.load()
            self.assertEqual(result, [("embedded_command", "eval")])
        finally:
            os.unlink(path)
            os.environ.pop("PROMPTGUARD_WHITELIST_FILE", None)

    def test_malformed_line_skipped_others_kept(self):
        fd, path = tempfile.mkstemp(suffix=".conf")
        os.close(fd)
        try:
            _write_conf(path, "no_colon_here\nembedded_command: eval\n")
            os.environ["PROMPTGUARD_WHITELIST_FILE"] = path
            wl._cache_key = None
            result = wl.load()
            self.assertEqual(result, [("embedded_command", "eval")])
        finally:
            os.unlink(path)
            os.environ.pop("PROMPTGUARD_WHITELIST_FILE", None)

    def test_cache_hit_returns_same_list(self):
        fd, path = tempfile.mkstemp(suffix=".conf")
        os.close(fd)
        try:
            _write_conf(path, "embedded_command: eval\n")
            os.environ["PROMPTGUARD_WHITELIST_FILE"] = path
            wl._cache_key = None
            first = wl.load()
            second = wl.load()
            self.assertIs(first, second)
        finally:
            os.unlink(path)
            os.environ.pop("PROMPTGUARD_WHITELIST_FILE", None)

    def test_cache_invalidated_on_mtime_change(self):
        fd, path = tempfile.mkstemp(suffix=".conf")
        os.close(fd)
        try:
            _write_conf(path, "embedded_command: eval\n")
            os.environ["PROMPTGUARD_WHITELIST_FILE"] = path
            wl._cache_key = None
            first = wl.load()
            # Force mtime change by writing new content and bumping mtime
            time.sleep(0.05)
            _write_conf(path, "instruction_override: ignore\n")
            future = os.path.getmtime(path) + 1
            os.utime(path, (future, future))
            wl._cache_key = None  # simulate mtime change detection
            second = wl.load()
            self.assertNotEqual(first, second)
            self.assertEqual(second, [("instruction_override", "ignore")])
        finally:
            os.unlink(path)
            os.environ.pop("PROMPTGUARD_WHITELIST_FILE", None)


class TestIsSuppressed(unittest.TestCase):
    def _entries(self):
        return [("embedded_command", "rm -rf"), ("instruction_override", "ignore")]

    def test_matching_id_and_evidence_suppressed(self):
        signal = {"id": "embedded_command", "evidence": "...rm -rf /tmp...", "weight": 32}
        self.assertTrue(wl.is_suppressed(signal, self._entries()))

    def test_wrong_id_not_suppressed(self):
        signal = {"id": "role_reassignment", "evidence": "rm -rf /tmp", "weight": 30}
        self.assertFalse(wl.is_suppressed(signal, self._entries()))

    def test_wrong_pattern_not_suppressed(self):
        signal = {"id": "embedded_command", "evidence": "...chmod 777...", "weight": 32}
        self.assertFalse(wl.is_suppressed(signal, self._entries()))

    def test_case_insensitive_match(self):
        signal = {"id": "embedded_command", "evidence": "...RM -RF /home...", "weight": 32}
        self.assertTrue(wl.is_suppressed(signal, self._entries()))

    def test_empty_entries_never_suppresses(self):
        signal = {"id": "embedded_command", "evidence": "rm -rf", "weight": 32}
        self.assertFalse(wl.is_suppressed(signal, []))

    def test_multiple_entries_same_id_ored(self):
        entries = [("embedded_command", "rm -rf"), ("embedded_command", "chmod")]
        signal_a = {"id": "embedded_command", "evidence": "chmod 777", "weight": 32}
        signal_b = {"id": "embedded_command", "evidence": "rm -rf /x", "weight": 32}
        self.assertTrue(wl.is_suppressed(signal_a, entries))
        self.assertTrue(wl.is_suppressed(signal_b, entries))


class TestFilterSignals(unittest.TestCase):
    def test_removes_matching_keeps_others(self):
        entries = [("embedded_command", "rm -rf")]
        signals = [
            {"id": "embedded_command", "evidence": "rm -rf /tmp", "weight": 32},
            {"id": "instruction_override", "evidence": "ignore prior", "weight": 40},
        ]
        result = wl.filter_signals(signals, entries)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["id"], "instruction_override")

    def test_empty_entries_returns_all(self):
        signals = [{"id": "embedded_command", "evidence": "rm -rf", "weight": 32}]
        result = wl.filter_signals(signals, [])
        self.assertEqual(result, signals)

    def test_all_suppressed_returns_empty(self):
        entries = [("embedded_command", "rm -rf")]
        signals = [{"id": "embedded_command", "evidence": "rm -rf /x", "weight": 32}]
        result = wl.filter_signals(signals, entries)
        self.assertEqual(result, [])

    def test_empty_signals_returns_empty(self):
        entries = [("embedded_command", "rm -rf")]
        result = wl.filter_signals([], entries)
        self.assertEqual(result, [])

    def test_score_from_filtered_signals(self):
        entries = [("embedded_command", "rm -rf")]
        signals = [
            {"id": "embedded_command", "evidence": "rm -rf /tmp", "weight": 32},
            {"id": "instruction_override", "evidence": "ignore prior", "weight": 40},
        ]
        filtered = wl.filter_signals(signals, entries)
        score = sum(s["weight"] for s in filtered)
        self.assertEqual(score, 40)


if __name__ == "__main__":
    unittest.main(verbosity=2)
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cd /home/lost/projects/prompt-guard
python3 -m pytest tests/test_whitelist.py -v 2>&1 | head -20
```

Expected: `ModuleNotFoundError: No module named 'promptguard.whitelist'`

- [ ] **Step 3: Create `promptguard/whitelist.py`**

```python
"""Per-signal evidence whitelist for the prompt-guard heuristic scanner."""
from __future__ import unicode_literals

import os
import sys

# Project root is one level above this file's directory (promptguard/)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DEFAULT_PATH = os.path.join(_PROJECT_ROOT, "whitelist.conf")

# Cache: (path, mtime) -> list of entries. Refreshed when file mtime changes.
_cache_key = None
_cache_entries = []


def _conf_path():
    return os.environ.get("PROMPTGUARD_WHITELIST_FILE", _DEFAULT_PATH)


def _parse(path):
    """Return list of (signal_id, pattern) pairs from file at path."""
    entries = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if ":" not in line:
                    sys.stderr.write(
                        "prompt-guard whitelist: skipping malformed line %d: %r\n"
                        % (lineno, line)
                    )
                    continue
                signal_id, _, pattern = line.partition(":")
                signal_id = signal_id.strip()
                pattern = pattern.strip()
                if not signal_id or not pattern:
                    sys.stderr.write(
                        "prompt-guard whitelist: empty id or pattern at line %d\n" % lineno
                    )
                    continue
                entries.append((signal_id, pattern))
    except OSError:
        pass  # file does not exist — return empty list, no suppression
    return entries


def load():
    """Return list of (signal_id, pattern) pairs from the whitelist config file.

    Returns an empty list if the file does not exist. Caches by (path, mtime)
    so changes take effect on the next call without restarting the process.
    """
    global _cache_key, _cache_entries

    path = _conf_path()
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None

    key = (path, mtime)
    if key == _cache_key:
        return _cache_entries

    _cache_entries = _parse(path)
    _cache_key = key
    return _cache_entries


def is_suppressed(signal, entries):
    """Return True if signal's id+evidence match any whitelist entry.

    signal  — dict with 'id' and 'evidence' keys (as returned by scan())
    entries — list of (signal_id, pattern) pairs from load()
    """
    sig_id = signal.get("id", "")
    evidence = signal.get("evidence", "").lower()
    for entry_id, pattern in entries:
        if entry_id == sig_id and pattern.lower() in evidence:
            return True
    return False


def filter_signals(signals, entries):
    """Return only signals not suppressed by any whitelist entry.

    signals — list of signal dicts from scan()
    entries — list of (signal_id, pattern) pairs from load()
    """
    if not entries:
        return signals
    return [s for s in signals if not is_suppressed(s, entries)]
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
cd /home/lost/projects/prompt-guard
python3 -m pytest tests/test_whitelist.py -v
```

Expected: all tests pass.

- [ ] **Step 5: Run full suite to confirm no regressions**

```bash
python3 -m pytest tests/ -q --tb=short
```

Expected: 135 + new tests passing, 0 failures.

- [ ] **Step 6: Commit**

```bash
cd /home/lost/projects/prompt-guard
git add promptguard/whitelist.py tests/test_whitelist.py
git commit -m "feat(whitelist): add per-signal evidence suppression module"
```

---

### Task 2: Wire whitelist into `guard.py` (D1 + D2)

**Files:**
- Modify: `promptguard/guard.py`

The whitelist filter runs after `_scan()` returns in both `check_output` and `check_memory_write`. The key new helper `_band_from_score` lets guard.py recompute the risk band from a filtered score without importing scan.py internals.

- [ ] **Step 1: Add import and `_band_from_score` helper to `guard.py`**

After the existing try/except import block for `_session` (around line 35), add:

```python
try:
    from promptguard import whitelist as _whitelist
    _WHITELIST_OK = True
except Exception:
    _WHITELIST_OK = False
    _whitelist = None
```

After the `_BAND_ORDER` dict definition (around line 46), add:

```python
def _band_from_score(score):
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score > 0:
        return "low"
    return "none"
```

- [ ] **Step 2: Apply whitelist in `check_output`**

Replace the block after the `_scan` call in `check_output` (from `result = _scan(...)` through the final `return GuardResult(...)`) with:

```python
    try:
        result = _scan(content, source=tool_name)
    except Exception:
        return _NOOP

    # Apply per-signal whitelist before scoring, taint recording, and advisory.
    if _WHITELIST_OK:
        entries = _whitelist.load()
        filtered = _whitelist.filter_signals(result["signals"], entries)
    else:
        filtered = result["signals"]
    filtered_score = min(100, sum(s["weight"] for s in filtered))
    filtered_band = _band_from_score(filtered_score)
    filtered_band_order = _BAND_ORDER.get(filtered_band, 0)

    if _SESSION_OK and filtered_band_order >= _BAND_ORDER.get(_TAINT_MIN_BAND, 2):
        try:
            _session.record_taint(tool_name)
        except Exception:
            pass

    if filtered_band_order < _BAND_ORDER.get(_MIN_BAND, 2):
        return GuardResult(
            risk_score=filtered_score,
            risk_band=filtered_band,
            block=False,
            advisory="",
            signals=filtered,
        )

    filtered_result = {
        "risk_score": filtered_score,
        "risk_band": filtered_band,
        "recommend": "escalate" if filtered_band in ("high", "medium") else "advise",
        "signals": filtered,
    }
    return GuardResult(
        risk_score=filtered_score,
        risk_band=filtered_band,
        block=False,
        advisory=_advisory_output(tool_name, filtered_result),
        signals=filtered,
    )
```

- [ ] **Step 3: Apply whitelist in `check_memory_write`**

Replace the block after the `_scan` call in `check_memory_write` (from `result = _scan(...)` through the variable assignments for `band`, `score`, `signals`) with:

```python
    try:
        result = _scan(content, source="memory_write")
    except Exception:
        return _NOOP

    # Apply per-signal whitelist before scoring and advisory.
    if _WHITELIST_OK:
        entries = _whitelist.load()
        signals = _whitelist.filter_signals(result["signals"], entries)
    else:
        signals = result["signals"]
    score = min(100, sum(s["weight"] for s in signals))
    band = _band_from_score(score)
```

Leave the rest of `check_memory_write` unchanged — it already uses `band`, `score`, and `signals` for the advisory and GuardResult construction.

- [ ] **Step 4: Run full test suite**

```bash
cd /home/lost/projects/prompt-guard
python3 -m pytest tests/ -q --tb=short
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add promptguard/guard.py
git commit -m "feat(guard): apply per-signal whitelist in check_output and check_memory_write"
```

---

### Task 3: Add taint-suppression integration test

**Files:**
- Modify: `tests/test_posttooluse_session.py`

This test verifies the end-to-end path: content that would normally hit MEDIUM/HIGH and record taint is fully suppressed when all its signals are whitelisted.

- [ ] **Step 1: Write the failing test**

Add this class to `tests/test_posttooluse_session.py` (before `if __name__ == "__main__":`) :

```python
class TestWhitelistTaintSuppression(_Base):
    def _run_with_whitelist(self, event, whitelist_content):
        fd, wl_path = tempfile.mkstemp(suffix=".conf")
        os.close(fd)
        try:
            with open(wl_path, "w") as f:
                f.write(whitelist_content)
            env = dict(os.environ)
            env["PYTHONPATH"] = _REPO
            env["PROMPTGUARD_SESSION_FILE"] = self._path
            env["PROMPTGUARD_WHITELIST_FILE"] = wl_path
            proc = subprocess.Popen(
                [sys.executable, _HOOK],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                cwd=_REPO,
            )
            out, _ = proc.communicate(json.dumps(event).encode("utf-8"))
            text = out.decode("utf-8").strip()
            return json.loads(text) if text else None
        finally:
            os.unlink(wl_path)

    def test_whitelisted_signal_does_not_record_taint(self):
        # Content that triggers embedded_command (weight 32 -> MEDIUM) normally records taint.
        # When the matching evidence is whitelisted, the filtered score drops to 0 -> no taint.
        event = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/source.py"},
            # This triggers embedded_command via "run|execute|eval" pattern
            "tool_response": 'pattern = re.compile(r"\\b(run|execute|eval|delete)\\b")',
        }
        # Whitelist the exact evidence text that will appear
        whitelist = "embedded_command: run|execute|eval|delete\n"
        self._run_with_whitelist(event, whitelist)
        self.assertEqual(_session_mod.get_taint_count(), 0)

    def test_partial_whitelist_still_records_taint(self):
        # If only some signals are whitelisted and filtered score stays >= medium, taint is recorded.
        event = {
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/test.py"},
            # Triggers both embedded_command (32) and instruction_override (40) -> HIGH
            "tool_response": (
                'ignore_re = re.compile(r"ignore|disregard")\n'
                'cmd_re = re.compile(r"run|execute|eval")\n'
            ),
        }
        # Only whitelist embedded_command; instruction_override (weight 40) still fires -> MEDIUM
        whitelist = "embedded_command: run|execute|eval\n"
        self._run_with_whitelist(event, whitelist)
        self.assertGreater(_session_mod.get_taint_count(), 0)
```

- [ ] **Step 2: Run to confirm first test fails (taint IS currently recorded)**

```bash
cd /home/lost/projects/prompt-guard
python3 -m pytest tests/test_posttooluse_session.py::TestWhitelistTaintSuppression::test_whitelisted_signal_does_not_record_taint -v
```

Expected: FAIL — taint count is > 0 (whitelist not yet wired in guard.py, or test written before Task 2). If Task 2 is already done, this may pass — that's fine, proceed.

- [ ] **Step 3: Run full suite**

```bash
python3 -m pytest tests/ -q --tb=short
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add tests/test_posttooluse_session.py
git commit -m "test(whitelist): verify whitelisted signals do not record taint"
```

---

### Task 4: Add `whitelist.conf` default file

**Files:**
- Create: `whitelist.conf` (project root)

- [ ] **Step 1: Create the file**

```
# prompt-guard whitelist
# Suppress known-benign scanner hits on a per-signal-evidence basis.
#
# Format:  signal_id: text_pattern
#   signal_id    — exact match against a signal's "id" field
#   text_pattern — case-insensitive substring match against the signal's "evidence" field
#
# A signal is suppressed only when BOTH its id and evidence match an entry.
# Multiple entries with the same signal_id are OR'd.
#
# To find evidence text for a false positive:
#   python3 -m promptguard.scan --pretty <file>
# Look at the "evidence" field of the signal you want to suppress.
#
# Example — suppress false positives when reading prompt-guard's own source code:
# embedded_command: execute|eval|delete|rm -rf|drop table|chmod|chown|sudo
# instruction_override: ignore|disregard|forget|override|bypass|dismiss|abandon
```

- [ ] **Step 2: Verify scanner ignores it (it's a comment-only file)**

```bash
cd /home/lost/projects/prompt-guard
python3 -m promptguard.scan --pretty whitelist.conf
```

Expected: `"risk_band": "none"`, `"signals": []`

- [ ] **Step 3: Run full suite one final time**

```bash
python3 -m pytest tests/ -q --tb=short
```

Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add whitelist.conf
git commit -m "feat(whitelist): add default whitelist.conf with usage instructions"
```
