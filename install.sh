#!/usr/bin/env bash
# install.sh — prompt-guard multi-platform installer
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "prompt-guard installer — repo: ${REPO}"

installed=0

# Claude Code
if [[ -d "${HOME}/.claude" ]]; then
    echo ""
    echo "==> Claude Code detected"
    SKILLS_DIR="${HOME}/.claude/skills"
    mkdir -p "${SKILLS_DIR}"
    ln -sfn "${REPO}/skills/prompt-guard" "${SKILLS_DIR}/prompt-guard"
    chmod +x "${REPO}/hooks/posttooluse_guard.py" "${REPO}/hooks/pretooluse_guard.py" "${REPO}/hooks/prememwrite_guard.py"
    echo "Linked skill -> ${SKILLS_DIR}/prompt-guard"
    echo "Add to ~/.claude/settings.json:"
    cat <<EOF
  "hooks": {
    "PostToolUse": [{ "matcher": "WebFetch|Bash|Read|Grep|Glob|Fetch|mcp__fetch",
      "hooks": [{"type": "command", "command": "python3 ${REPO}/hooks/posttooluse_guard.py", "async": true}] }],
    "PreToolUse": [
      { "matcher": "Write|Edit",
        "hooks": [{"type": "command", "command": "python3 ${REPO}/hooks/prememwrite_guard.py"}] },
      { "matcher": "WebFetch|Bash",
        "hooks": [{"type": "command", "command": "python3 ${REPO}/hooks/pretooluse_guard.py"}] }
    ]
  }
EOF
    installed=$((installed + 1))
fi

# Hermes
if [[ -d "${HOME}/.hermes" ]]; then
    echo ""
    echo "==> Hermes detected"
    bash "${REPO}/platforms/hermes/install.sh"
    installed=$((installed + 1))
fi

# OpenClaw
if [[ -d "${HOME}/.openclaw" ]]; then
    echo ""
    echo "==> OpenClaw detected"
    bash "${REPO}/platforms/openclaw/install.sh"
    installed=$((installed + 1))
fi

echo ""
if [[ $installed -eq 0 ]]; then
    echo "No supported platforms detected (~/.claude, ~/.hermes, ~/.openclaw)."
    echo "Install one of these agents and re-run."
else
    echo "Done — installed for ${installed} platform(s)."
fi
