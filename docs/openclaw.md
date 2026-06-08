# OpenClaw Platform Adapter

## Architecture

OpenClaw's plugin SDK (`definePluginEntry`) supports provider/tool extensions but does **not** expose pre/post-tool interceptors. Injecting guard logic into every tool call is therefore not possible natively.

The chosen approach is a two-component design:

1. **`guard_server.py`** — a lightweight Python HTTP server (stdlib `http.server`) that wraps the `promptguard.guard` module and exposes three scan endpoints over `localhost:9373`.
2. **`openclaw_plugin.js`** — an ES module plugin that injects system-prompt guidance into all OpenClaw and Grok workspace sessions, and adds a `/prompt-guard` slash command for on-demand scanning.

### Why no native hooks?

OpenClaw's `definePluginEntry` API is limited to:
- Provider extensions (adding LLM backends)
- Tool extensions (adding new callable tools)
- Agent prompt guidance (injecting text into system prompts)
- Slash commands

There is no `onBeforeTool` / `onAfterTool` lifecycle. The HTTP server approach decouples the guard from the plugin lifecycle entirely, allowing any code running in or alongside OpenClaw to call the scan endpoints directly.

### Grok workspace coverage

Grok workspaces (e.g. `workspace-grok-4-3`) run inside OpenClaw and inherit all registered plugins. No separate Grok adapter is required — the `prompt-guard` plugin's `agentPromptGuidance` is injected into both `openclaw_main` and `openclaw_workspace` surfaces, which covers Grok sessions automatically.

## Endpoints

| Method | Path           | Body fields                                  | Guard function        |
|--------|----------------|----------------------------------------------|-----------------------|
| POST   | `/scan`        | `tool_name`, `content`, `label`              | `check_output()`      |
| POST   | `/scan-pre`    | `tool_name`, `tool_input` (dict)             | `check_pre_tool()`    |
| POST   | `/scan-memory` | `file_path`, `content`                       | `check_memory_write()`|
| GET    | `/health`      | —                                            | health check          |

All endpoints return HTTP 200. Errors are returned as `{"error": "..."}` rather than crashing the server.

## Setup

```bash
bash platforms/openclaw/install.sh
```

This will:
1. Copy the systemd service unit to `~/.config/systemd/user/prompt-guard-server.service` (with the repo path substituted)
2. Enable and start the service
3. Print the `openclaw.json` snippet needed to activate the JS plugin

### Manual openclaw.json changes

The install script cannot edit `openclaw.json` automatically (OpenClaw config schema is strict — unknown keys crash the service). Make these additions manually:

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

## Environment variables

| Variable                     | Default    | Description                                       |
|------------------------------|------------|---------------------------------------------------|
| `PROMPTGUARD_MIN_BAND`       | `medium`   | Minimum risk band that generates an advisory      |
| `PROMPTGUARD_TAINT_MIN_BAND` | `medium`   | Minimum band that records session taint           |
| `PROMPTGUARD_TAINT_THRESHOLD`| `3`        | Taint count before escalation warning             |
| `PROMPTGUARD_URL_SCAN`       | `on`       | Set to `off` to disable egress URL scanning       |
| `PROMPTGUARD_DIR`            | auto       | Override repo root for import resolution          |

These can be added to the `[Service]` section of the systemd unit as `Environment=` lines.

## Changing the port

```bash
# Run on a different port
python3 platforms/openclaw/guard_server.py --port 9374
```

Update the `fetch()` URL in `openclaw_plugin.js` to match if you change the default.
