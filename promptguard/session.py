"""Per-session behavioral state for prompt-guard Phase 2 (D3, D6).

Stores taint count and tool-call history in a JSON file keyed by uid+cwd.
The session window defaults to 4 hours; files older than that are treated
as a fresh session. All public functions catch every exception — a session
I/O failure must never affect hook output or exit code.

Python 3.6.8 compatible. No third-party dependencies.
"""
from __future__ import unicode_literals

import hashlib
import json
import os
import time

_DEFAULT_WINDOW = 4 * 3600  # seconds
_MAX_TOOL_CALLS = 200
_MAX_TAINT_LOG = 500
_DEFAULT_TAINT_DECAY = 3600  # 1 hour sliding window for taint count


def _taint_decay_window():
    try:
        return int(os.environ.get("PROMPTGUARD_TAINT_DECAY_WINDOW", str(_DEFAULT_TAINT_DECAY)))
    except (ValueError, TypeError):
        return _DEFAULT_TAINT_DECAY


def _session_path():
    override = os.environ.get("PROMPTGUARD_SESSION_FILE", "").strip()
    if override:
        return override
    uid = str(os.getuid())
    cwd_hash = hashlib.md5(os.getcwd().encode("utf-8")).hexdigest()[:12]
    return os.path.join("/tmp", "promptguard_%s_%s.json" % (uid, cwd_hash))


def _window():
    try:
        return int(os.environ.get("PROMPTGUARD_SESSION_WINDOW", str(_DEFAULT_WINDOW)))
    except (ValueError, TypeError):
        return _DEFAULT_WINDOW


def _empty():
    now = time.time()
    return {
        "session_start": now,
        "last_seen": now,
        "taint_count": 0,      # kept for backward compat with old session files
        "tainted_sources": [],
        "taint_log": [],       # timestamped log; get_taint_count() uses this for decay
        "tool_calls": [],
    }


def load():
    """Load session state. Returns fresh state if file is missing, corrupt, or expired."""
    try:
        with open(_session_path(), "r", encoding="utf-8") as fh:
            state = json.load(fh)
        if time.time() - state.get("last_seen", 0) > _window():
            return _empty()
        return state
    except Exception:
        return _empty()


def save(state):
    """Atomically write session state (tmp file + rename)."""
    path = _session_path()
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
        os.rename(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def record_taint(tool_name):
    """Record a taint event. Appends a timestamped entry to taint_log for decay support."""
    try:
        # load-modify-save is not atomic; concurrent hook processes may lose one
        # increment. Acceptable for a behavioral counter with no locking available.
        state = load()
        now = time.time()
        # Legacy integer counter — kept so old readers (e.g. monitoring scripts) still work.
        state["taint_count"] = state.get("taint_count", 0) + 1
        sources = state.get("tainted_sources", [])
        sources.append(tool_name)
        if len(sources) > _MAX_TAINT_LOG:
            sources = sources[-_MAX_TAINT_LOG:]
        state["tainted_sources"] = sources
        # Timestamped log used by get_taint_count() for sliding-window decay.
        log = state.get("taint_log", [])
        log.append({"ts": now, "source": tool_name})
        if len(log) > _MAX_TAINT_LOG:
            log = log[-_MAX_TAINT_LOG:]
        state["taint_log"] = log
        state["last_seen"] = now
        save(state)
    except Exception:
        pass


def record_tool_call(tool_name, label=""):
    """Append a tool-call entry; trim to _MAX_TOOL_CALLS oldest entries."""
    try:
        # load-modify-save is not atomic; concurrent hook processes may lose one
        # entry. Acceptable for a behavioral log with no locking available.
        state = load()
        calls = state.get("tool_calls", [])
        calls.append({"ts": time.time(), "tool": tool_name, "label": label})
        if len(calls) > _MAX_TOOL_CALLS:
            calls = calls[-_MAX_TOOL_CALLS:]
        state["tool_calls"] = calls
        state["last_seen"] = time.time()
        save(state)
    except Exception:
        pass


def get_taint_count():
    """Return number of taint events within the decay window (default 1 hour).

    Uses taint_log (timestamped) when present; falls back to legacy taint_count
    integer for session files written before taint_log was introduced.
    """
    try:
        state = load()
        log = state.get("taint_log")
        if log is not None:
            cutoff = time.time() - _taint_decay_window()
            return sum(1 for t in log if t.get("ts", 0) >= cutoff)
        return state.get("taint_count", 0)
    except Exception:
        return 0


def get_recent_calls(window_secs):
    """Return tool_calls entries within the last window_secs seconds."""
    try:
        cutoff = time.time() - window_secs
        return [c for c in load().get("tool_calls", []) if c.get("ts", 0) >= cutoff]
    except Exception:
        return []
