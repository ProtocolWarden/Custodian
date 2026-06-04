#!/usr/bin/env bash
# Warm context injection — Claude Code PreToolUse adapter (injection-only).
#
# SLIM variant: unlike PlatformManifest's full ContextGuard hook, this repo's
# hook ONLY does warm leaf-doc injection (context-injection-spec §4). It never
# blocks a tool call and always exits 0 — any failure is swallowed. Engine is
# provisioned by `cl context init` into .context/.engine/; routing table in
# .context/routes.yaml; gated on .context/config.yaml injection.enabled.
#
# Receives JSON on stdin: {"tool_name": "...", "tool_input": {...}}
# Emits PreToolUse additionalContext JSON on stdout when a route matches.

set -uo pipefail

REPO_ROOT="${CLAUDE_PROJECT_DIR:-$(pwd)}"
CONFIG_FILE="${REPO_ROOT}/.context/config.yaml"

INPUT="$(cat)"
if command -v jq &>/dev/null; then
  TOOL_NAME="$(echo "$INPUT" | jq -r '.tool_name // ""')"
  TARGET_PATH="$(echo "$INPUT" | jq -r '.tool_input.file_path // .tool_input.path // ""')"
else
  TOOL_NAME="$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('tool_name',''))" 2>/dev/null || echo "")"
  TARGET_PATH="$(echo "$INPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); t=d.get('tool_input') or {}; print(t.get('file_path') or t.get('path') or '')" 2>/dev/null || echo "")"
fi

if [[ "$TOOL_NAME" == "Write" || "$TOOL_NAME" == "Edit" ]]; then
  INJECT_ENABLED=false
  if [[ -f "${CONFIG_FILE}" ]] && command -v python3 &>/dev/null; then
    INJECT_ENABLED=$(python3 -c "
try:
    import yaml
    with open('${CONFIG_FILE}') as f:
        c = yaml.safe_load(f) or {}
    print(str(c.get('injection', {}).get('enabled', False)).lower())
except Exception:
    print('false')
" 2>/dev/null || echo "false")
  fi

  if [[ "$INJECT_ENABLED" == "true" ]]; then
    # Entire emission isolated: any failure is swallowed, never blocks the call.
    {
      ENGINE="${REPO_ROOT}/.context/.engine/route.py"
      # routes.yaml uses repo-relative globs; strip the anchor prefix if absolute.
      REL_PATH="${TARGET_PATH#${REPO_ROOT}/}"
      if [[ -n "$REL_PATH" && -f "$ENGINE" ]]; then
        CTX="$(python3 "$ENGINE" --target "$REL_PATH" --root "$REPO_ROOT" 2>/dev/null || true)"
        if [[ -n "$CTX" ]]; then
          CTX="$CTX" python3 -c "
import json, os
ctx = os.environ.get('CTX', '')
print(json.dumps({
    'hookSpecificOutput': {
        'hookEventName': 'PreToolUse',
        'additionalContext': ctx,
    }
}))
" 2>/dev/null || true
        fi
      fi
    } || true
  fi
fi

exit 0
