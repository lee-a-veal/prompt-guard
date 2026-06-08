#!/usr/bin/env bash
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SERVICE_DIR="${HOME}/.config/systemd/user"
SERVICE_NAME="prompt-guard-server.service"

# Install systemd service
mkdir -p "$SERVICE_DIR"
sed "s|/home/lost/projects/prompt-guard|${REPO}|g" \
    "${REPO}/platforms/openclaw/guard_server.service" > "${SERVICE_DIR}/${SERVICE_NAME}"
systemctl --user daemon-reload
systemctl --user enable "${SERVICE_NAME}"
systemctl --user start "${SERVICE_NAME}"
echo "guard_server started at localhost:9373"

# Patch openclaw.json to enable the plugin
OPENCLAW_JSON="${HOME}/.openclaw/openclaw.json"
if [[ -f "$OPENCLAW_JSON" ]]; then
    echo "Add to ~/.openclaw/openclaw.json plugins.allow: \"prompt-guard\""
    echo "Add to plugins.entries: { \"prompt-guard\": { \"enabled\": true, \"source\": \"local\", \"path\": \"${REPO}/platforms/openclaw\" } }"
fi
