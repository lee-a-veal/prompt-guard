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


def parse_with_lines(path=None):
    """Return list of (signal_id, pattern, lineno) triples from the config file.

    Same parsing rules as the entries used for suppression, but keeps the source
    line number so tooling can point at a specific entry. Used by
    promptguard.whitelist_check; suppression itself uses the 2-tuple form.
    """
    return _parse_raw(path if path is not None else _conf_path())


def _parse(path):
    """Return list of (signal_id, pattern) pairs from file at path."""
    return [(sid, pat) for sid, pat, _ in _parse_raw(path)]


def _parse_raw(path):
    """Return list of (signal_id, pattern, lineno) triples from file at path."""
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
                entries.append((signal_id, pattern, lineno))
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


def matching_entries(signal, entries):
    """Return every whitelist entry that suppresses `signal`.

    Entries may be (signal_id, pattern) pairs or (signal_id, pattern, lineno)
    triples; the extra field is ignored here and preserved in the result.

    This is the single definition of "does this entry match this signal".
    is_suppressed() and promptguard.whitelist_check both go through it, so a
    liveness report can never disagree with what actually gets suppressed.
    """
    sig_id = signal.get("id", "")
    evidence = str(signal.get("evidence") or "").lower()
    return [e for e in entries if e[0] == sig_id and e[1].lower() in evidence]


def is_suppressed(signal, entries):
    """Return True if signal's id+evidence match any whitelist entry.

    signal  — dict with 'id' and 'evidence' keys (as returned by scan())
    entries — list of (signal_id, pattern) pairs from load()
    """
    return bool(matching_entries(signal, entries))


def filter_signals(signals, entries):
    """Return only signals not suppressed by any whitelist entry.

    signals — list of signal dicts from scan()
    entries — list of (signal_id, pattern) pairs from load()
    """
    if not entries:
        return signals
    return [s for s in signals if not is_suppressed(s, entries)]
