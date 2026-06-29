#!/bin/bash -l
# =====================================================================
# Re-run ONLY the 4 Llama-2 prompts that dropped in the full sweep
# (transient API errors, no score file written). Single GPU job, no
# sharding — targets specific dataset rows via --indices.
#
#   CWE-190_IOW-3b (idx 25)   CWE-22_ILP-2a (idx 45)
#   CWE-522_IPC-2b (idx 94)   CWE-798_UHC-2c (idx 139)
#
# Everything else (vLLM serve, python-only, codeql-bandit) is identical
# to run_llama2_pair_full.sbatch.
#
# Submit:  sbatch run_llama2_pair_missing.sbatch
# =====================================================================
#SBATCH --job-name=llama2-pair-missing
#SBATCH --partition=gpu
#SBATCH --gres=gpu:1
#SBATCH --cpus-per-task=16
#SBATCH --mem=64G
#SBATCH --time=04:00:00
#SBATCH --output=%x_%j.out
#SBATCH --error=%x_%j.err

set -euo pipefail

INDICES="25,45,94,139"     # the 4 missing prompts (0-based data_idx)
echo "=== re-running missing Llama-2 prompts: indices $INDICES ==="

# ---------- paths ----------
export WORK=/work/cps/$USER
MODEL_DIR="$WORK/models/llama-2-7b-chat-hf"
VLLM_ENV="$WORK/envs/vllm"
PAIR_ENV="$WORK/envs/pair"
SRC="$HOME/JailbreakingLLMs"

# ---------- cache redirection ----------
export HF_HOME="$WORK/cache/huggingface"
export HUGGINGFACE_HUB_CACHE="$HF_HOME/hub"
export TRANSFORMERS_CACHE="$HF_HOME/transformers"
export HF_DATASETS_CACHE="$HF_HOME/datasets"
export TORCH_HOME="$WORK/cache/torch"
export PIP_CACHE_DIR="$WORK/cache/pip"
export XDG_CACHE_HOME="$WORK/cache/xdg"
export VLLM_CACHE_ROOT="$WORK/cache/vllm"
export TMPDIR="$WORK/tmp"
mkdir -p "$HF_HOME" "$TORCH_HOME" "$PIP_CACHE_DIR" "$XDG_CACHE_HOME" "$VLLM_CACHE_ROOT" "$TMPDIR"

export HF_HUB_OFFLINE=1
export PYTHONDONTWRITEBYTECODE=1
export WANDB_MODE=offline

export VLLM_USE_DEEP_GEMM=0
export VLLM_USE_FLASHINFER_SAMPLER=0

export PATH="$WORK/tools/codeql:$PATH"

# ---------- modules ----------
. /etc/profile.d/module.sh
module purge
module load anaconda/2023.07-1
module load gcc/14.2.0 2>/dev/null || module load gcc 2>/dev/null || echo "WARN: no gcc module; relying on system gcc"
source "$(conda info --base)/etc/profile.d/conda.sh"

# ---------- per-job working copy of the code ----------
PROJECT_DIR="$WORK/runs/llama2_pair_missing_${SLURM_JOB_ID:-$$}"
mkdir -p "$PROJECT_DIR"
rsync -a --exclude='__pycache__' --exclude='*.pyc' --exclude='.git' "$SRC"/ "$PROJECT_DIR"/
cd "$PROJECT_DIR" || exit 1
export PYTHONPATH="$PROJECT_DIR:${PYTHONPATH:-}"

# ---------- API keys ----------
if [ -f "$PROJECT_DIR/.env" ]; then set -a; . "$PROJECT_DIR/.env"; set +a; fi
export LOCAL_API_KEY="local-dummy"

# ---------- pick a free port + start the local vLLM target ----------
PORT=$(python -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
export LLAMA_LOCAL_API_BASE="http://127.0.0.1:${PORT}/v1"
echo "=== vLLM will serve on $LLAMA_LOCAL_API_BASE ==="

VLLM_LOG="$PROJECT_DIR/vllm_server.log"
"$VLLM_ENV/bin/vllm" serve "$MODEL_DIR" \
  --served-model-name llama-2-7b-chat-local \
  --host 127.0.0.1 --port "$PORT" \
  --dtype float16 \
  --max-model-len 4096 \
  --gpu-memory-utilization 0.90 \
  --enforce-eager \
  --chat-template "$PROJECT_DIR/llama2_chat_template.jinja" \
  > "$VLLM_LOG" 2>&1 &
VLLM_PID=$!
trap 'echo "stopping vLLM ($VLLM_PID)"; kill $VLLM_PID 2>/dev/null || true' EXIT

# ---------- wait until the server is ready (max ~10 min) ----------
echo "=== waiting for vLLM to come up ==="
for i in $(seq 1 120); do
  if curl -sf "http://127.0.0.1:${PORT}/v1/models" >/dev/null 2>&1; then
    echo "vLLM is up after ${i}0s"; break
  fi
  if ! kill -0 $VLLM_PID 2>/dev/null; then
    echo "!! vLLM died during startup. Last 40 log lines:"; tail -40 "$VLLM_LOG"; exit 1
  fi
  sleep 10
done
curl -sf "http://127.0.0.1:${PORT}/v1/models" >/dev/null || { echo "!! vLLM never became ready"; tail -40 "$VLLM_LOG"; exit 1; }

# ---------- run the experiment ----------
conda activate "$PAIR_ENV"
codeql --version

# Only the missing rows, Python-only, target = local Llama-2.
bash Run_with_dataset.sh \
  --dataset       LLMSecEval/LLMSecEval-Prompts_dataset.csv \
  --target-model  llama-2-7b-chat-local \
  --python-only \
  --indices       "$INDICES" \
  --output-dir    "$PROJECT_DIR/LLMSecEval"

echo "=== missing-prompt re-run finished, results under $PROJECT_DIR ==="
