#!/usr/bin/env bash
set -euo pipefail
PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HERMES_PLUGIN_DIR="${HOME}/.hermes/plugins/prompt-guard"
mkdir -p "$(dirname "$HERMES_PLUGIN_DIR")"
ln -sfn "$PLUGIN_DIR" "$HERMES_PLUGIN_DIR"
echo "Linked platforms/hermes -> $HERMES_PLUGIN_DIR"
echo "Run: hermes plugins enable prompt-guard"
