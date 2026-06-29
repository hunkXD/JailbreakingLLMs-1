#!/bin/bash -l
# =====================================================================
# Download Llama-2-7B-chat (the ORIGINAL PAIR target) to /work (NOT home).
# Run ONCE on the LOGIN node (has internet):  bash download_llama2.sh
#
# Source: NousResearch/Llama-2-7b-chat-hf — a bit-identical, UNGATED
# re-upload of meta-llama/Llama-2-7b-chat-hf. Same weights as the PAIR
# paper target, but no license gate / approval / token required.
# (If you later get official meta-llama access, just swap REPO back and
#  add --token "$HF_TOKEN".)
#
# Reuses the existing `hfdl` venv (huggingface_hub 1.x, CLI = `hf`) that
# already downloaded the Qwen models.
# =====================================================================
set -euo pipefail

export WORK=/work/cps/$USER
export HF_HOME="$WORK/cache/huggingface"
export HUGGINGFACE_HUB_CACHE="$HF_HOME/hub"
export PIP_CACHE_DIR="$WORK/cache/pip"
export TMPDIR="$WORK/tmp"
mkdir -p "$HF_HOME" "$PIP_CACHE_DIR" "$TMPDIR" "$WORK/models"

REPO="NousResearch/Llama-2-7b-chat-hf"        # ungated mirror of meta-llama/Llama-2-7b-chat-hf
DEST="$WORK/models/llama-2-7b-chat-hf"

HFDL="$WORK/envs/hfdl"
if [ ! -x "$HFDL/bin/hf" ]; then
  echo "!! hfdl env missing at $HFDL — build it first (it has huggingface_hub 1.x)"
  exit 1
fi

echo "=== downloading $REPO -> $DEST ==="
# Ungated repo: no token needed. Pull the whole repo (safetensors weights).
"$HFDL/bin/hf" download "$REPO" --local-dir "$DEST"

echo "=== done. shard listing: ==="
ls -lh "$DEST"/*.safetensors 2>/dev/null | head
echo "=== model ready at $DEST ==="
