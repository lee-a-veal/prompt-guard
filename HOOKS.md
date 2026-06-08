# prompt-guard — Platform Setup

prompt-guard works with Claude Code, Hermes, and OpenClaw/Grok.
The scanner library (`promptguard/`) is platform-agnostic.
Each platform adapter is a thin wrapper that translates the platform's
event format to `promptguard/guard.py`.

## Platforms

| Platform | Adapter | Guide |
|----------|---------|-------|
| Claude Code | `hooks/*.py` (stdin/stdout JSON) | [docs/claude-code.md](docs/claude-code.md) |
| Hermes | `platforms/hermes/` (Python plugin) | [docs/hermes.md](docs/hermes.md) |
| OpenClaw / Grok | `platforms/openclaw/` (HTTP server + JS shim) | [docs/openclaw.md](docs/openclaw.md) |

## Quick install

```bash
bash install.sh
```

Auto-detects which platforms are present and installs each.

## Architecture

```
promptguard/         # Scanner library (platform-agnostic)
  normalize.py       # Unicode canonicalization, base64 decode
  scan.py            # Heuristic signal scoring
  session.py         # Behavioral session state (D3/D6)
  urlscan.py         # Egress URL classification (D5)
  guard.py           # Public API: check_output(), check_pre_tool(), check_memory_write()

hooks/               # Claude Code hooks (stdin/stdout JSON adapters)
platforms/
  hermes/            # Hermes plugin (Python register_hook)
  openclaw/          # OpenClaw/Grok adapter (HTTP server + JS shim)
```
