#!/bin/bash -l
# =====================================================================
# Download Qwen3-Coder-30B-A3B-Instruct weights to /work (NOT home).
# Run ONCE on the LOGIN node (has internet):  bash download_qwen3.sh
#
# Reuses the existing `hfdl` venv (huggingface_hub 1.x, CLI = `hf`)
# that already downloaded the 32B model. Ungated repo, no token needed.
# =====================================================================
set -euo pipefail

export WORK=/work/cps/$USER
export HF_HOME="$WORK/cache/huggingface"
export HUGGINGFACE_HUB_CACHE="$HF_HOME/hub"
export PIP_CACHE_DIR="$WORK/cache/pip"
export TMPDIR="$WORK/tmp"
mkdir -p "$HF_HOME" "$PIP_CACHE_DIR" "$TMPDIR" "$WORK/models"

REPO="Qwen/Qwen3-Coder-30B-A3B-Instruct"
DEST="$WORK/models/qwen3-coder-30b-a3b-instruct"

# hf-xet acceleration + the download CLI live in the hfdl env built for the 32B.
HFDL="$WORK/envs/hfdl"
if [ ! -x "$HFDL/bin/hf" ]; then
  echo "!! hfdl env missing at $HFDL — build it first (it has huggingface_hub 1.x)"
  exit 1
fi

echo "=== downloading $REPO -> $DEST ==="
# NB: don't pass --exclude with trailing patterns — the hf CLI treats bare
# positionals as explicit FILENAMES. This repo is safetensors-only, so just
# pull the whole repo.
"$HFDL/bin/hf" download "$REPO" --local-dir "$DEST"

echo "=== done. shard listing: ==="
ls -lh "$DEST"/*.safetensors 2>/dev/null | head
echo "=== model ready at $DEST ==="
