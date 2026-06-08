#!/usr/bin/env python3
"""PostToolUse hook: scan untrusted tool outputs for prompt injection.

Claude Code invokes this after a tool runs, passing a JSON event on stdin. We
extract the tool's *output* (the data plane -- the part Claude is about to read),
run the heuristic scanner, and on a medium/high score inject an advisory back
into the model's context via `additionalContext`. We never block here: blocking
breaks ops work, and a false positive should never stop you from reading a file.
The advisory tells Claude to treat the content as data and, when warranted, to
invoke the prompt-guard skill for a semantic verdict (the LLM-judge step).

Only tools that return content from outside the trust boundary are scanned.
Configure which ones via PROMPTGUARD_TOOLS (comma-separated); default below.

Exit code is always 0 -- a hook crash must not wedge the session. Any internal
error is swallowed and reported as a non-blocking note.
"""
from __future__ import print_function, unicode_literals

import json
import os
import sys

# Make the promptguard package importable regardless of cwd.
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))

try:
    from promptguard.guard import check_output
except Exception as exc:  # pragma: no cover - import guard
    print(json.dumps({"systemMessage": "prompt-guard hook import failed: %s" % exc}))
    sys.exit(0)


def _extract_label(tool_name, tool_input):
    """Short diagnostic label from tool_input for session logging."""
    if not tool_input:
        return ""
    if tool_name == "WebFetch":
        return str(tool_input.get("url") or "")[:80]
    if tool_name == "Bash":
        return str(tool_input.get("command") or "")[:60]
    if tool_name in ("Read", "Write"):
        return str(tool_input.get("file_path") or "")[:80]
    if tool_name == "Grep":
        pat = str(tool_input.get("pattern") or "")[:40]
        path = str(tool_input.get("path") or "")[:40]
        return (pat + " in " + path) if (pat and path) else (pat or path)
    if tool_name == "Glob":
        return str(tool_input.get("pattern") or "")[:80]
    return ""


def _extract_text(tool_response, _depth=0):
    """Pull human-readable text out of a tool response of unknown shape.

    Scans ALL keys AND values — injections hidden in dict keys, url, error,
    title, headers, metadata, etc. are not missed. Non-string primitives
    (int, bool, float, None) are skipped. Depth-limited to avoid stack
    overflow on pathologically nested responses.
    """
    if _depth > 20:
        return ""
    if tool_response is None:
        return ""
    if isinstance(tool_response, str):
        return tool_response
    if isinstance(tool_response, dict):
        parts = []
        for key, val in tool_response.items():
            if isinstance(key, str) and key.strip():
                parts.append(key)
            if isinstance(val, (str, dict, list)):
                part = _extract_text(val, _depth + 1)
                if part.strip():
                    parts.append(part)
        return "\n".join(parts)
    if isinstance(tool_response, list):
        return "\n".join(_extract_text(x, _depth + 1) for x in tool_response)
    return ""  # skip int, bool, float


def main():
    try:
        event = json.load(sys.stdin)
    except Exception:
        sys.exit(0)

    tool_name = event.get("tool_name", "")
    label = _extract_label(tool_name, event.get("tool_input"))
    text = _extract_text(event.get("tool_response"))

    result = check_output(tool_name, text, label)
    if not result.advisory:
        sys.exit(0)

    out = {
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": result.advisory,
        }
    }
    print(json.dumps(out, ensure_ascii=False))
    sys.exit(0)


if __name__ == "__main__":
    main()
