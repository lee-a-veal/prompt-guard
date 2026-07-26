# prompt-guard — OpenClaw Platform Adapter

OpenClaw adapter for the [prompt-guard](https://github.com/lee-a-veal/prompt-guard) scanner. Uses a two-component design: an HTTP guard server for real-time scanning, and a JS plugin for system-prompt guidance and a `/prompt-guard` slash command.

## Why this architecture

OpenClaw's plugin SDK (`definePluginEntry`) supports provider/tool extensions and system-prompt guidance, but **does not expose pre/post-tool interceptors**. Injecting guard logic into every tool call is therefore not possible natively.

The approach:

1. **`guard_server.py`** — a lightweight Python HTTP server on `localhost:9373` that wraps the `promptguard.guard` module and exposes `/scan`, `/scan-pre`, and `/scan-memory` endpoints. Any code running in or alongside OpenClaw calls these endpoints directly.
2. **`openclaw_plugin.js`** — an ES module that injects system-prompt guidance into all OpenClaw/Grok sessions and provides a `/prompt-guard` slash command for on-demand scanning.

Grok workspaces (e.g. `workspace-grok-4-3`) inherit all registered plugins, so no separate Grok adapter is needed.

## Defense Layers

| Layer | Mechanism | Protection |
|-------|-----------|------------|
| D1 | `POST /scan` | Content scan — flags MEDIUM+ injection signals in untrusted tool output |
| D2 | `POST /scan-memory` | Memory write block — blocks HIGH-risk writes to memory paths |
| D3 | N/A | Behavioral — not applicable (no tool interceptor hook) |
| D5 | `POST /scan-pre` | Egress scan — blocks HIGH-risk URLs in tool args |
| D6 | N/A | Session taint — not applicable (no post-tool hook) |

## Endpoints

| Method | Path | Body Fields | Guard Function |
|--------|------|-------------|----------------|
| POST | `/scan` | `tool_name`, `content`, `label` | `check_output()` |
| POST | `/scan-pre` | `tool_name`, `tool_input` (dict) | `check_pre_tool()` |
| POST | `/scan-memory` | `file_path`, `content` | `check_memory_write()` |
| GET | `/health` | — | health check |

All endpoints return HTTP 200. Errors are returned as `{ "error": "..." }` rather than crashing the server.

## Installation

```bash
bash platforms/openclaw/install.sh
```

This installs the systemd service and prints the `openclaw.json` snippet needed to activate the JS plugin.

### Manual `openclaw.json` configuration

The install script cannot edit `openclaw.json` automatically (the config schema is strict). Add these manually:

```json
{
  "plugins": {
    "allow": ["prompt-guard"],
    "entries": {
      "prompt-guard": {
        "enabled": true,
        "source": "local",
        "path": "/home/lost/projects/prompt-guard/platforms/openclaw"
      }
    }
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `GUARD_SERVER_PORT` | `9373` | Port for the HTTP scan server |
| `PROMPTGUARD_DIR` | `~/projects/prompt-guard` | Path to prompt-guard checkout |
| `PROMPTGUARD_MEMORY_PATHS` | (built-in) | Comma-separated regex patterns for memory paths |

## Slash Command

Run `/prompt-guard scan <text>` in any OpenClaw or Grok session to scan arbitrary text for injection signals. Returns the risk band, score, and advisory.

Example output:
```
⚠ risk_band=HIGH score=100
⚠ PROMPT-GUARD: untrusted content scored 100/100 (HIGH risk). Signals: instruction_override, role_reassignment, system_prompt_probe, exfiltration.
```

## Graceful Degradation

If the `promptguard.guard` package is unavailable, `guard_server.py` exits with an error and the systemd service auto-restarts. The JS plugin continues to function (slash command returns "server unavailable"). All scanner errors are caught — the OpenClaw agent loop is never interrupted.

## Files

- `guard_server.py` — HTTP server wrapping `promptguard.guard` (check_output, check_pre_tool, check_memory_write)
- `openclaw_plugin.js` — OpenClaw plugin: system-prompt guidance + `/prompt-guard` slash command
- `guard_server.service` — systemd user service unit
- `install.sh` — installs the service and prints openclaw.json config snippet
- `OPENCLAW_HOOKS.md` — detailed architecture documentation

## Comparison with Hermes Plugin

| Feature | Hermes Plugin | OpenClaw Adapter |
|---------|--------------|------------------|
| Architecture | Native Python plugin hooks | HTTP server + JS plugin |
| Pre-tool blocking | Built-in (`pre_tool_call`) | Via `POST /scan-pre` |
| Post-tool advisory | Built-in (`transform_tool_result`) | N/A (no hook) |
| D3 behavioral | Yes (session tracking) | No (no tool interceptor) |
| D6 session taint | Yes | No (no post-tool hook) |
| Manual scanning | N/A | `/prompt-guard scan <text>` |
| Coverage | Tool I/O only | Tool I/O (server) + slash command |
