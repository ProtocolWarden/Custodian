#!/usr/bin/env bash
# setup.sh — install Custodian commands for local developer shells and hooks.
#
# Installs Custodian into this repo's .venv, then symlinks the console scripts
# into ~/.local/bin so commands work from any repo without activating a venv.
#
# Usage:
#   ./setup.sh
#   ./setup.sh --repo-venvs      # also install editable Custodian into sibling repo .venv dirs

set -euo pipefail

CUSTODIAN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$CUSTODIAN_DIR/.venv"
LOCAL_BIN="${LOCAL_BIN:-$HOME/.local/bin}"
INSTALL_REPO_VENVS=0

for arg in "$@"; do
  case "$arg" in
    --repo-venvs)
      INSTALL_REPO_VENVS=1
      ;;
    -h|--help)
      sed -n '1,14p' "$0"
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

echo "▶ Custodian setup"
echo "  repo: $CUSTODIAN_DIR"
echo "  venv: $VENV"

if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV"
fi

"$VENV/bin/python" -m pip install --quiet --upgrade pip
"$VENV/bin/python" -m pip install --quiet -e "$CUSTODIAN_DIR"

mkdir -p "$LOCAL_BIN"
for command in \
  custodian \
  custodian-audit \
  custodian-config \
  custodian-doctor \
  custodian-fix \
  custodian-multi \
  custodian-report \
  custodian-triage
do
  ln -sfn "$VENV/bin/$command" "$LOCAL_BIN/$command"
done

if ! printf '%s' "$PATH" | tr ':' '\n' | grep -Fxq "$LOCAL_BIN"; then
  if [ -f "$HOME/.bashrc" ] && ! grep -Fq "$LOCAL_BIN" "$HOME/.bashrc"; then
    printf '\nexport PATH="%s:$PATH"\n' "$LOCAL_BIN" >> "$HOME/.bashrc"
    echo "  added $LOCAL_BIN to ~/.bashrc"
  fi
  echo "  open a new shell or run: source ~/.bashrc"
fi

if [ "$INSTALL_REPO_VENVS" -eq 1 ]; then
  WORKSPACE_DIR="$(cd "$CUSTODIAN_DIR/.." && pwd)"
  for repo_venv in "$WORKSPACE_DIR"/*/.venv/bin/python; do
    [ -x "$repo_venv" ] || continue
    echo "  installing editable Custodian into ${repo_venv%/bin/python}"
    "$repo_venv" -m pip install --quiet -e "$CUSTODIAN_DIR"
  done
fi

echo
echo "✓ Custodian commands installed"
echo "  custodian:       $LOCAL_BIN/custodian"
echo "  custodian-multi: $LOCAL_BIN/custodian-multi"
