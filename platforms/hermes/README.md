# prompt-guard — Hermes Plugin

Hermes plugin that wires the [prompt-guard](https://github.com/lee-a-veal/prompt-guard) scanner into the Hermes agent loop as a native plugin. Provides the same defense layers as the Claude Code hooks but adapted to Hermes's plugin architecture.

## Defense Layers

| Layer | Hook | Protection |
|-------|------|-----------|
| D1 | `transform_tool_result` | Content scan — flags MEDIUM+ injection signals in untrusted tool output |
| D2 | `pre_tool_call` | Memory write block — blocks HIGH-risk writes to memory paths (MEMORY.md, .ai-memory, etc.) |
| D3 | `transform_tool_result` | Behavioral — warns on read-then-fetch patterns and network rate spikes |
| D5 | `pre_tool_call` | Egress scan — blocks HIGH-risk URLs (data exfiltration patterns) |
| D6 | `transform_tool_result` | Session taint — warns when flagged input count exceeds threshold |

## Hooks

- **`pre_tool_call`** — Can block tool execution (returns `{"action": "block", "message": "..."}`) for HIGH-risk operations (D2 memory writes, D5 egress URLs). Medium-risk advisories are stashed and injected via `transform_tool_result`.

- **`transform_tool_result`** — Appends advisories to tool results for MEDIUM+ content (D1), pending pre-call advisories (D2/D5 medium), session taint warnings (D6), and behavioral patterns (D3). The tool still executes; the advisory rides back to the model.

## Installation

1. Ensure the prompt-guard scanner package is available:
   ```bash
   # Option A: pip install (if published)
   pip install promptguard

   # Option B: local checkout (preferred for development)
   git clone https://github.com/lee-a-veal/prompt-guard ~/projects/prompt-guard
   ```
   Set `PROMPTGUARD_DIR` if the checkout is elswhere:
   ```bash
   export PROMPTGUARD_DIR=/path/to/prompt-guard
   ```

2. Copy this plugin directory to `~/.hermes/plugins/prompt-guard/`

3. Enable the plugin:
   ```bash
   hermes plugins enable prompt-guard
   ```

4. Start a new session (or `/reset` in an existing one) for the plugin to load.

## Configuration

All configuration is via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `PROMPTGUARD_DIR` | `~/projects/prompt-guard` | Path to prompt-guard checkout |
| `PROMPTGUARD_OUTPUT_TOOLS` | `web_search,web_extract,browser_navigate,...` | Comma-separated tools whose output is scanned (D1) |
| `PROMPTGUARD_URL_TOOLS` | `web_search,web_extract,browser_navigate,...` | Tools whose args carry URLs to scan (D5) |
| `PROMPTGUARD_CMD_TOOLS` | `terminal,execute_code` | Tools whose args may contain shell URLs (D5) |
| `PROMPTGUARD_WRITE_TOOLS` | `write_file,patch,skill_manage` | Tools that write to disk (D2) |
| `PROMPTGUARD_MIN_BAND` | `medium` | Minimum risk band for advisory injection |
| `PROMPTGUARD_TAINT_MIN_BAND` | `medium` | Minimum band for session taint tracking |
| `PROMPTGUARD_TAINT_THRESHOLD` | `3` | Taint count threshold for behavioral warning |
| `PROMPTGUARD_MEMORY_PATHS` | (built-in patterns) | Comma-separated regex patterns for memory paths |

## Graceful Degradation

If the promptguard package cannot be imported (missing, broken install), the plugin logs a warning and becomes a no-op. All scanner errors are caught and logged — the host agent loop is never interrupted by a plugin failure.

## Comparison with Claude Code Hooks

| Feature | Claude Code Hooks | Hermes Plugin |
|---------|------------------|---------------|
| Architecture | Stdin JSON → stdout JSON | Python plugin with `register(ctx)` |
| Pre-tool blocking | `{"decision": "block", "reason": "..."}` | `{"action": "block", "message": "..."}` |
| Post-tool advisory | `additionalContext` in `hookSpecificOutput` | Appended to tool result via `transform_tool_result` |
| Session tracking | File-based (`/tmp/promptguard_*.json`) | Same (promptguard.session) |
| Tool names | `WebFetch, Bash, Read, Write, Edit` | `web_search, web_extract, terminal, read_file, write_file, patch, ...` |
| Memory paths | Claude Code-specific | Hermes + Claude Code paths |

## Files

- `plugin.yaml` — Plugin metadata and hook declarations
- `__init__.py` — Hook implementations (pre_tool_call, transform_tool_result)
- `scanner.py` — Lazy import bridge to promptguard.scan/urlscan/session