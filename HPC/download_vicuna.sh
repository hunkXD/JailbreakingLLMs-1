#!/bin/bash -l
# =====================================================================
# Download Vicuna-13B-v1.5 (the other ORIGINAL PAIR target) to /work.
# Run ONCE on the LOGIN node (has internet):  bash download_vicuna.sh
#
# Source: lmsys/vicuna-13b-v1.5 — UNGATED, no token needed. Ships PyTorch
# .bin shards (no safetensors); vLLM loads them via --load-format auto.
#
# Reuses the existing `hfdl` venv (huggingface_hub 1.x, CLI = `hf`).
# =====================================================================
set -euo pipefail

export WORK=/work/cps/$USER
export HF_HOME="$WORK/cache/huggingface"
export HUGGINGFACE_HUB_CACHE="$HF_HOME/hub"
export PIP_CACHE_DIR="$WORK/cache/pip"
export TMPDIR="$WORK/tmp"
mkdir -p "$HF_HOME" "$PIP_CACHE_DIR" "$TMPDIR" "$WORK/models"

REPO="lmsys/vicuna-13b-v1.5"
DEST="$WORK/models/vicuna-13b-v1.5"

HFDL="$WORK/envs/hfdl"
if [ ! -x "$HFDL/bin/hf" ]; then
  echo "!! hfdl env missing at $HFDL — build it first (it has huggingface_hub 1.x)"
  exit 1
fi

echo "=== downloading $REPO -> $DEST (~26 GB) ==="
"$HFDL/bin/hf" download "$REPO" --local-dir "$DEST"

echo "=== done. weight shards: ==="
ls -lh "$DEST"/*.bin "$DEST"/*.safetensors 2>/dev/null | head
echo "=== model ready at $DEST ==="
