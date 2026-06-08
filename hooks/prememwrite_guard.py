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
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

try:
    from promptguard.guard import check_memory_write
except Exception as exc:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "additionalContext": "prompt-guard memory hook import failed: %s" % exc,
        }
    }))
    sys.exit(0)

_WATCHED = {"Write", "Edit"}


def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool_name = event.get("tool_name", "")
    if tool_name not in _WATCHED:
        sys.exit(0)

    tool_input = event.get("tool_input") or {}
    file_path = tool_input.get("file_path") or tool_input.get("path") or ""
    content = tool_input.get("content") or tool_input.get("new_string") or ""

    result = check_memory_write(file_path, content)
    if result.block:
        print(json.dumps({"decision": "block", "reason": result.advisory}))
        sys.exit(0)
    if result.advisory:
        print(json.dumps({
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "additionalContext": result.advisory,
            }
        }))
    sys.exit(0)


if __name__ == "__main__":
    main()
