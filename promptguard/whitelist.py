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
