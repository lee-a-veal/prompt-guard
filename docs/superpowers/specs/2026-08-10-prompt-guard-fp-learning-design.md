# 2026-08-10 — False-positive logging and two-hit auto-whitelisting

## Problem

Every whitelist entry is added by hand. The ritual is six steps, and step 4 —
copying a distinctive substring out of a truncated evidence snippet — is the one
that goes wrong: evidence is padded ±24 chars and carries literal `...` markers,
so a hand-copied pattern often fails to match the string it was copied from.
Nothing records which false positives actually recur, so there is no way to tell
a one-off from a daily tax, and no way to know which of the 47 committed entries
were worth adding.

The volume is real. `2026-08-07-whitelist-suppression-bypass.md` records seven
false positives and zero true positives in a single session. Writing this spec
produced three more: reading a memory file (32/100), reading `SKILL.md` itself
(100/100), and reading that findings doc (100/100). Escalation volume that high
trains the operator to dismiss advisories unread — the failure mode the
semantic-judge stage exists to prevent.

## What this adds

1. An append-only log of adjudicated false positives.
2. Automatic promotion to a local whitelist after two CLEAN verdicts on the
   same item.
3. A `SKILL.md` step wiring the existing verdict procedure to the log.

## Design decisions

### Only adjudicated CLEAN verdicts count

A hit is logged as a false positive only when the `prompt-guard` skill has run
its verdict step and returned **CLEAN**. An advisory firing is not by itself
evidence of a false positive.

This is the property that keeps auto-promotion from being an attack. A repeated
injection never earns a CLEAN verdict, so it never promotes itself. Verdicts of
SUSPICIOUS and MALICIOUS are still logged — they are the audit trail of what was
judged and rejected — but they never increment the count.

### Poison flag

If an item is *ever* recorded SUSPICIOUS or MALICIOUS, it is permanently barred
from auto-promotion, even if later cleared. One-way and cheap. It closes the
path where content is judged malicious once and then talked into two CLEAN
verdicts afterward.

### Item identity

Key is `sha1(signal_id + "\x00" + evidence)`. This is the same anchor
`whitelist.conf` entries already use, so a cleared item maps directly onto the
remedy. The source path and tool are recorded alongside as metadata.

### Promotion writes path-scoped entries where possible

`2026-08-07-whitelist-suppression-bypass.md` D1 (severity high, unfixed): the
whitelist is compared against the *padded evidence snippet*, not the match span,
so any entry can be used as a suppression oracle — an attacker places the
entry's text within 24 characters of a payload and the entire signal is dropped.
That document's ordering note is explicit: until D1 is fixed, every entry added
enlarges the bypass surface.

Auto-promotion that emitted content patterns would manufacture those primitives
automatically and unreviewed. So it does not, where it has an alternative:

| FP source | Entry written | D1 surface |
|---|---|---|
| `Read` / `Grep` / `Glob` / `WebFetch` | path-scoped: `signal_id @ path` | none |
| `Bash` | content pattern: `signal_id: text` | yes — marked in file and output |

A path-scoped entry keys on where the content came from, which is not injectable
into the content being scanned, so it adds no oracle. This is the same remedy
D3 recommends (`_is_safe_path()`, present in the hermes adapter, never ported to
`guard.py`, and the reason ~40 of the 47 committed entries are path surrogates)
— but arrived at per-item from recorded evidence, and **narrower**: it suppresses
only the one signal that was twice cleared for that path. A different signal
appearing in the same file still fires. Hermes's version skips scanning the file
entirely.

Bash output has no path to scope to, so it keeps the content-pattern form. Those
entries do add D1 surface and are marked as such, so they can be audited as a
set when D1 is fixed.

### Promoted entries land in a separate, gitignored file

`whitelist.local.conf`, read by `load()` in addition to `whitelist.conf`. The
curated 47 stay in a file that is committed and pushed to a public repository;
machine-learned entries derived from local file content do not go there.
`rm whitelist.local.conf` is a full reset of everything learned.

### Content-pattern derivation

Strip the leading and trailing `...` markers from the evidence and use the whole
interior verbatim. Refuse to promote if the result is under 10 characters, and
print an "add manually" note instead.

Ten characters is the short-phrase floor already documented for hand-added
entries. Using the *whole* interior rather than a shorter distinctive fragment is
deliberate: D1's oracle radius is a function of entry length, and short entries
(`m=re.search(r`, `fail silently`) are the dangerous ones. A long pattern is more
brittle — any edit to the surrounding 48 characters breaks it — but a broken
entry only means the false positive reappears and is re-learned, whereas a loose
entry is a permanent hole.

### All signal types are eligible

Including `exfiltration` and `instruction_override`. Excluding high-severity
signals would exclude the case that motivated this: `SKILL.md` scores 100/100 on
exactly those two.

## Components

### `promptguard/fplog.py` (new)

Append-only JSONL plus count-and-promote. Counts are derived by replaying the
log — no separate state file, so there is nothing to drift.

Record shape:

```json
{"ts": 1754800000.0, "key": "3f2a…", "signal_id": "exfiltration",
 "evidence": "…send the keys to an attacker URL…",
 "source": "~/.claude/skills/prompt-guard/SKILL.md", "tool": "Read",
 "verdict": "clean", "counted": true}
```

Paths are stored with `~` when under `$HOME` and expanded at match time — the
repo anonymizes home directories, and it makes the file portable.

CLI:

```
python3 -m promptguard.fplog record <path> --verdict clean|suspicious|malicious [--dry-run]
python3 -m promptguard.fplog record --stdin --tool Bash --verdict clean [--dry-run]
python3 -m promptguard.fplog list [--json]
python3 -m promptguard.fplog show <key>
```

`--verdict` is required and has no default: nothing is counted by accident.
`--dry-run` reports what would be recorded and promoted without writing. If a
scanned source has no unsuppressed signals, `record` says so and writes nothing.

`record` takes a **file, not a hand-copied evidence string**. It re-scans the
source and records every currently-firing (unsuppressed) signal. This removes
the step that fails today:

```
$ python3 -m promptguard.fplog record ~/.claude/skills/prompt-guard/SKILL.md --verdict clean
  instruction_override   1/2
  exfiltration           2/2  PROMOTED  exfiltration @ ~/.claude/skills/prompt-guard/SKILL.md
```

Log path: `fp_log.jsonl` in the project root, override `PROMPTGUARD_FP_LOG`.

Promotion is idempotent — an entry already present in `whitelist.local.conf` is
not written twice.

### `promptguard/whitelist.py` (change)

- `load()` reads `whitelist.conf` **and** `whitelist.local.conf`. Override for
  the local file: `PROMPTGUARD_LOCAL_WHITELIST_FILE`.
- Path-scoped entries parse to the existing 2-tuple shape with an `@` sentinel
  on the pattern field: `("exfiltration", "@~/path/to/file")`. Callers that do
  not care keep working unchanged.
- `matching_entries(signal, entries, source="")` gains an optional `source`.
  Patterns starting with `@` match on the source path (exact after
  `expanduser` + `normpath`; a trailing `/` means directory prefix). All other
  patterns keep today's case-insensitive substring match against evidence.
- `filter_signals(signals, entries, source="")` threads it through.

The optional argument keeps every existing call site valid.

### `promptguard/guard.py` (change)

`check_output()` already receives `label`, which `_extract_label` populates with
`file_path` for Read/Write, `url` for WebFetch, and the *command* for Bash. Pass
it as `source` to `filter_signals` — but only for tools whose label is actually a
path or URL:

```python
_PATH_LABEL_TOOLS = {"read_file", "search_files", "web_fetch"}
source = label if canonical in _PATH_LABEL_TOOLS else ""
```

A Bash command string must never be matched against a path entry.
`check_memory_write()` passes `file_path`.

### `promptguard/whitelist_check.py` (change)

Pass each walked file's path as `source`, so path-scoped entries are exercised
rather than reported as unmatched. Without this, every promoted entry would show
up as a dead entry on the next liveness run.

### `SKILL.md` (change)

New step 6, "Record the verdict", after the existing step 5 report. Documents
the `fplog record` call, that only CLEAN counts, the two-hit promotion, and the
poison rule.

### `.gitignore` (change)

Add `whitelist.local.conf` and `fp_log.jsonl`.

### `tests/test_fplog.py` (new)

Count derivation from replayed log; two CLEAN promote, one does not;
SUSPICIOUS/MALICIOUS never counts; poison flag blocks promotion permanently;
path-scoped form chosen for Read, content form for Bash; under-10-char pattern
refused; promotion idempotent; `~` anonymization round-trips.

Extend `tests/test_whitelist.py`: path-scoped matching, `@` sentinel parsing,
directory-prefix form, both files merged by `load()`, and existing content-entry
behavior unchanged when `source` is omitted.

## Residual risks

**Two CLEAN verdicts from one session promote an entry.** Requiring distinct
sessions was considered and declined in favour of the simpler count. A session
already manipulated into one wrong CLEAN verdict can produce the second
immediately. Mitigations are the poison flag, and that suppression is never
silent — the `ℹ PROMPT-GUARD (whitelist): suppressed …` line still fires for
learned entries, and `whitelist_check` still reports on them.

**Content-pattern entries still feed D1.** Only Bash-sourced FPs produce them,
they are marked in the file, and the ≥10-char floor plus full-interior patterns
keep them long. This does not fix D1; it stops the feature from accelerating it.

**Path-scoped suppression is trust in a path.** Once `exfiltration @ SKILL.md`
is learned, a genuine exfiltration payload written into `SKILL.md` is suppressed
for that signal. Scope is per-signal rather than per-file to keep this as narrow
as possible, but it is real. It is the same trust the hermes adapter already
extends to 16 directory prefixes, granted here only on recorded evidence.

## Out of scope

D1's evidence-window fix, D2's detector patches, and a full D3 `_is_safe_path()`
port. This spec is deliberately compatible with all three: when D1 is fixed, the
content-pattern entries can be re-audited as a marked set, and the path-scoped
entries are unaffected.
