#!/bin/bash -l
# =====================================================================
# Build the PAIR framework runtime env on the HPC, matching the local
# venv exactly (Python 3.10 + requirements-lock.txt). Run ONCE on the
# LOGIN node:   bash setup_pair_env.sh
#
# Separate from the vLLM env on purpose: vLLM and this share no Python
# process, so their dependency stacks never collide.
# =====================================================================
set -euo pipefail

export WORK=/work/cps/$USER
export PIP_CACHE_DIR="$WORK/cache/pip"
export TMPDIR="$WORK/tmp"
mkdir -p "$PIP_CACHE_DIR" "$TMPDIR"

LOCK="$HOME/JailbreakingLLMs/requirements-lock.txt"   # adjust if your repo is elsewhere
[ -f "$LOCK" ] || { echo "!! lockfile not found at $LOCK — transfer the repo first"; exit 1; }

. /etc/profile.d/module.sh
module purge
module load anaconda/2023.07-1
source "$(conda info --base)/etc/profile.d/conda.sh"

# Create a Python 3.10 env at a fixed prefix on /work (not in home)
if [ ! -d "$WORK/envs/pair" ]; then
  conda create -y -p "$WORK/envs/pair" python=3.10
fi
conda activate "$WORK/envs/pair"

pip install -U pip
# --no-deps: the lockfile is a complete freeze; replay exact versions without
# re-resolving (the env has a protobuf/grpcio-status combo the strict resolver
# rejects but which works fine at runtime).
pip install --no-deps -r "$LOCK"

echo "=== verifying core imports ==="
python -c "import litellm, transformers, pandas, fastchat; print('PAIR imports OK')"
semgrep --version && bandit --version || echo "(semgrep/bandit CLIs not on PATH — check)"
echo "=== PAIR env ready at $WORK/envs/pair ==="
