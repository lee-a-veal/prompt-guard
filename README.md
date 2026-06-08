# prompt-guard

[![Repo](https://img.shields.io/badge/GitHub-prompt--guard-181717?logo=github)](https://github.com/lee-a-veal/prompt-guard)

Indirect prompt-injection detection for **AI agent tool outputs**.

When an agent reads a web page, file, command output, or API response, malicious
instructions hidden in that content can hijack the agent — tell it to exfiltrate
keys, run commands, or change its goal. prompt-guard sits on that **data plane**
and flags untrusted content before the agent acts on it.

Supports Claude Code, Hermes, and OpenClaw/Grok. See [HOOKS.md](HOOKS.md) for
platform setup guides.

## Why not just validate inputs?

Input allowlists (the right tool for CLI arguments) protect the *control plane* —
what the operator types. They cannot see the *data plane* — what tools return
into the model's context. That is where indirect prompt injection lives, and it
is what this project guards. A regex blocklist on a username field detects
nothing real; a scanner on `WebFetch`/`Bash`/`Read` output detects the actual
attack.

## Architecture — hybrid, two stage

```
            TRUST BOUNDARY
trusted ────────┊──────── untrusted
(operator)      ┊  (WebFetch, Bash stdout, Read, API responses)
                ┊
   ┌────────────▼─────────────┐
   │ PostToolUse hook         │  always-on, cheap
   │  -> promptguard.scan     │  normalize → signal-score
   └────────────┬─────────────┘
        band >= medium?
                │ yes → inject advisory into context
   ┌────────────▼─────────────┐
   │ prompt-guard SKILL       │  on flagged content only
   │  LLM-as-judge verdict    │  CLEAN / SUSPICIOUS / MALICIOUS
   └──────────────────────────┘
```

- **Stage 1 — `promptguard/scan.py`** (deterministic): normalizes text to defeat
  evasion (zero-width chars, homoglyphs, leetspeak, base64), then *scores*
  weighted signals (instruction override, role reassignment, system-prompt
  probing, tool-call mimicry, exfiltration, embedded commands, obfuscation). It
  does **not** reject — it emits a risk band and the evidence.
- **Stage 2 — `skills/prompt-guard/SKILL.md`** (semantic): when Stage 1 escalates,
  Claude judges intent inside a quarantine frame, producing a verdict and a safe
  handling decision. This is the part a regex cannot do and is what makes the
  guard hard to evade.

The pairing is the point: the cheap filter keeps token cost down by only invoking
model judgment on flagged content, and the model judgment covers the novel
phrasings the filter misses.

## Install

```bash
./install.sh          # links the skill, prints the hook snippet for settings.json
```

The hook is **advisory, never blocking** — a false positive must never stop you
from reading a file. It injects a warning telling Claude to treat the content as
data; on high risk it tells Claude to invoke the `prompt-guard` skill.

### Wiring into settings.json

`install.sh` prints the snippet but does not edit `settings.json`. When merging
it in by hand, **back up first** and add prompt-guard as an *additional*
`PostToolUse` entry — do not overwrite existing hooks (e.g. audit hooks):

```bash
cp ~/.claude/settings.json ~/.claude/settings.json.bak-$(date +%Y%m%d-%H%M%S)
```

This deployment's backup lives at
`~/.claude/settings.json.bak-20260603-162442` (restore it if anything looks
off). After merging, validate the file before trusting it:

```bash
python3 -c "import json; json.load(open('$HOME/.claude/settings.json'))" && echo OK
```

Claude Code reloads hooks at session start (sometimes sooner). To disable
without removing the entry, set `PROMPTGUARD_MIN_BAND=high` or remove the
prompt-guard object from the `PostToolUse` array.

## Use the scanner directly

```bash
python3 -m promptguard.scan suspicious.html --pretty
cat page.txt | python3 -m promptguard.scan --source webfetch
```

Exit code: `0` none/low, `1` medium, `2` high.

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `PROMPTGUARD_TOOLS` | `WebFetch,Bash,Read,Grep,Glob,Fetch,mcp__fetch` | Tools to scan |
| `PROMPTGUARD_MIN_BAND` | `medium` | Minimum band that triggers an advisory |

## Test

```bash
python3 -m unittest discover -s tests -v
```

## Limitations (honest ones)

- Stage 1 is heuristic; novel attacks may score low. Stage 2 (model judgment) is
  the backstop, but it is only invoked above the threshold — so the threshold is
  a real tradeoff between cost and coverage.
- This detects and advises; it does not sandbox. It reduces the odds Claude acts
  on injected instructions; it does not make that impossible.
- Hook scanning sees tool *output*. It cannot inspect content the model obtains
  through channels Claude Code does not route through a tool.

## Layout

```
promptguard/
  normalize.py   evasion-resistant text canonicalization
  scan.py        weighted signal scorer (Stage 1)
hooks/
  posttooluse_guard.py   PostToolUse hook -> scan -> advisory
skills/prompt-guard/
  SKILL.md       LLM-as-judge methodology (Stage 2)
tests/
  test_scan.py   17 tests: benign, injection, evasion, contract
```

Python 3.6.8 compatible. No third-party dependencies.
