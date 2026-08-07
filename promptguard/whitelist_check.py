"""Whitelist liveness check — find entries that suppress nothing in a corpus.

Whitelist entries are anchored to a signal's *evidence text*. When a scanned
file changes shape the anchor stops matching, and the entry silently stops
suppressing anything. Nothing errors: the only symptom is a false positive
reappearing, which reads like a new detection rather than a rotted config.

That is not hypothetical. On 2026-08-07 the settings.json entry was anchored to
a `grep -qE ...` shell hook. The hook was rewritten in Python, the evidence
window moved, and settings.json became a recurring unsuppressed 32/100 MEDIUM
false positive until someone traced it back by hand.

This module scans a corpus and reports which entries matched. Run it after
editing the whitelist, or after changing a file an entry protects.

IMPORTANT — unmatched is not the same as dead. An entry matches nothing if the
file it protects was not in the corpus you scanned. Always widen the corpus
before concluding an entry is obsolete; this tool deliberately says "unmatched"
and never "delete this".

Run:
    python3 -m promptguard.whitelist_check PATH [PATH ...]
    python3 -m promptguard.whitelist_check --pretty ~/.claude .

Exit codes:  0 every entry matched   1 some entries unmatched   2 bad usage
"""
from __future__ import print_function, unicode_literals

import json
import os
import sys

from . import whitelist
from .scan import scan

# Directories that never hold scannable prose/config.
_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", "venv", ".venv", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build", ".cache",
}

# Read cap per file. The scanner truncates internally anyway; this just keeps
# the walk cheap on large logs and databases.
_MAX_BYTES = 2 * 1024 * 1024


def _is_probably_text(path):
    """Cheap binary sniff: a NUL byte in the first 4KB means skip."""
    try:
        with open(path, "rb") as fh:
            return b"\0" not in fh.read(4096)
    except OSError:
        return False


def iter_files(paths):
    """Yield readable file paths from a list of files and/or directories."""
    for root_path in paths:
        if os.path.isfile(root_path):
            yield root_path
            continue
        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for name in filenames:
                yield os.path.join(dirpath, name)


def check(paths, entries=None):
    """Scan `paths` and count how many signals each whitelist entry suppressed.

    Returns a dict with per-entry hit counts, the unmatched subset, and corpus
    stats. Matching goes through whitelist.matching_entries(), so results
    reflect real suppression behaviour rather than a reimplementation of it.
    """
    if entries is None:
        entries = whitelist.parse_with_lines()

    hits = {}          # (id, pattern, lineno) -> match count
    examples = {}      # same key -> first file that exercised it
    for entry in entries:
        hits[entry] = 0

    scanned = skipped = 0
    for path in iter_files(paths):
        try:
            if os.path.getsize(path) > _MAX_BYTES or not _is_probably_text(path):
                skipped += 1
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
        except OSError:
            skipped += 1
            continue

        scanned += 1
        if not content.strip():
            continue
        try:
            signals = scan(content, source="whitelist_check").get("signals", [])
        except Exception:
            skipped += 1
            continue

        for signal in signals:
            for entry in whitelist.matching_entries(signal, entries):
                hits[entry] += 1
                examples.setdefault(entry, path)

    unmatched = [e for e in entries if hits[e] == 0]
    return {
        "entries": len(entries),
        "matched": len(entries) - len(unmatched),
        "unmatched": len(unmatched),
        "files_scanned": scanned,
        "files_skipped": skipped,
        "results": [
            {
                "signal_id": e[0],
                "pattern": e[1],
                "line": e[2] if len(e) > 2 else None,
                "hits": hits[e],
                "first_seen_in": examples.get(e),
            }
            for e in entries
        ],
    }


def _main(argv):
    import argparse

    p = argparse.ArgumentParser(
        description="Report whitelist entries that suppress nothing in a corpus.",
        epilog="Unmatched means 'not exercised by these paths', NOT 'safe to "
               "delete' — widen the corpus before removing an entry.",
    )
    p.add_argument("paths", nargs="+", help="Files and/or directories to scan.")
    p.add_argument("--json", action="store_true", help="Machine-readable output.")
    p.add_argument("--pretty", action="store_true", help="Indent JSON output.")
    args = p.parse_args(argv)

    for path in args.paths:
        if not os.path.exists(path):
            sys.stderr.write("whitelist_check: no such path: %s\n" % path)
            return 2

    report = check(args.paths)

    if args.json or args.pretty:
        print(json.dumps(report, indent=2 if args.pretty else None, ensure_ascii=False))
    else:
        conf = whitelist._conf_path()
        print("=== whitelist liveness: %s ===" % conf)
        print("  corpus: %d files scanned, %d skipped"
              % (report["files_scanned"], report["files_skipped"]))
        print("  entries: %d matched, %d unmatched, %d total"
              % (report["matched"], report["unmatched"], report["entries"]))
        unmatched = [r for r in report["results"] if r["hits"] == 0]
        if unmatched:
            print("\n  UNMATCHED (not exercised by this corpus — verify before removing):")
            for r in unmatched:
                print("    line %-4s %s: %s"
                      % (r["line"], r["signal_id"], r["pattern"]))
            print("\n  An entry is unmatched if the file it protects was not scanned.")
            print("  Widen the corpus before concluding it is obsolete.")

    return 1 if report["unmatched"] else 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
