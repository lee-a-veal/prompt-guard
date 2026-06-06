#!/usr/bin/env python3
"""PreToolUse hook: block writes carrying HIGH injection signals to memory paths.

Memory files (MEMORY.md, memory/*.md, .ai-memory/, etc.) persist across
sessions and are loaded as trusted operator context. A successful injection
that writes a false fact or directive into memory affects every future
session. This hook scans the content being written and blocks HIGH-risk
writes before they reach disk; MEDIUM-risk writes produce an advisory.

Covers D2 (Memory Poisoning) from the deficiency assessment.

Exit code is always 0 -- a hook crash must not wedge the session.
"""
from __future__ import print_function, unicode_literals

import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

try:
    from promptguard.scan import scan
except Exception as exc:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": "prompt-guard memory hook import failed: %s" % exc,
        }
    }))
    sys.exit(0)

_WATCHED = {"Write", "Edit"}

# Regex patterns matched against the file path.
# Configurable via PROMPTGUARD_MEMORY_PATHS (comma-separated regex strings).
_DEFAULT_PATTERNS = [
    r"/memory/",           # */memory/*.md — Claude Code auto-memory directories
    r"MEMORY\.md$",        # top-level MEMORY.md index
    r"/\.ai-memory/",      # .ai-memory store
    r"/\.claude-mem/",     # .claude-mem store
    r"/\.thread-memory/",  # .thread-memory store
]

_raw = os.environ.get("PROMPTGUARD_MEMORY_PATHS", "").strip()
_MEMORY_PATTERNS = [p.strip() for p in _raw.split(",") if p.strip()] if _raw else _DEFAULT_PATTERNS

_BAND_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


def _is_memory_path(path):
    for pat in _MEMORY_PATTERNS:
        if re.search(pat, path):
            return True
    return False


def _content_to_scan(tool_name, tool_input):
    if tool_name == "Write":
        return tool_input.get("content") or ""
    if tool_name == "Edit":
        return tool_input.get("new_string") or ""
    return ""


def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool_name = event.get("tool_name", "")
    if tool_name not in _WATCHED:
        sys.exit(0)

    tool_input = event.get("tool_input") or {}
    file_path = tool_input.get("file_path") or ""
    if not file_path or not _is_memory_path(file_path):
        sys.exit(0)

    content = _content_to_scan(tool_name, tool_input)
    if not content.strip():
        sys.exit(0)

    try:
        result = scan(content, source="memory_write")
    except Exception as exc:
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": "prompt-guard memory scan error: %s" % exc,
            }
        }))
        sys.exit(0)

    band = result["risk_band"]
    score = result["risk_score"]
    sig_ids = ", ".join(sorted(set(s["id"] for s in result["signals"]))) or "heuristic signals"
    basename = os.path.basename(file_path)

    if _BAND_ORDER.get(band, 0) >= _BAND_ORDER["high"]:
        reason = (
            "prompt-guard blocked memory write to %s: injection signals detected "
            "(%d/100 HIGH, signals: %s). If this content derives from a trusted "
            "source, scan it manually with `python3 -m promptguard.scan` and "
            "override if it is a false positive."
            % (basename, score, sig_ids)
        )
        print(json.dumps({"decision": "block", "reason": reason}))
        sys.exit(0)

    if _BAND_ORDER.get(band, 0) >= _BAND_ORDER["medium"]:
        warning = (
            "⚠ PROMPT-GUARD (memory write): content being written to %s scored "
            "%d/100 (%s). Signals: %s. Verify this content does not originate "
            "from untrusted sources before writing."
            % (basename, score, band.upper(), sig_ids)
        )
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": warning,
            }
        }))

    sys.exit(0)


if __name__ == "__main__":
    main()
