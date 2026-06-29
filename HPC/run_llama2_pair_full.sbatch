#!/bin/bash -l
# =====================================================================
# FULL LLMSecEval sweep with a LOCAL Llama-2-7B-chat target (the ORIGINAL
# PAIR paper target) served by vLLM on a TUHH HPC GPU node.
#
# Python-only mode: every prompt (incl. the C-only memory-safety CWEs) is
# generated in Python and judged with codeql-bandit. See --python-only in
# Run_with_dataset.sh for the rationale (LLMSecEval author L. Morelli: a
# C-targeted task can still elicit other weaknesses in Python).
#
# Topology (per array task, one GPU node each):
#   vLLM serve (local target)  <--127.0.0.1:$PORT-->  Run_with_dataset.sh
#   attacker / judge / validator call external APIs (compute nodes have
#   outbound internet, verified from node u008 in the Qwen runs).
#
# The full dataset (150 logical data rows — the CSV's multiline quoted fields
# make `wc -l` misleading) is SHARDED across the array so it does not need one
# long single job. 6 shards => 25 rows each.
#
# Submit:  sbatch run_llama2_pair_full.sbatch
# Single-node instead of array: sbatch --array=0-0 ... and set NSHARDS=1.
# =====================================================================
#SBATCH --job-name=llama2-pair-pyonly
#SBATCH --partition=gpu
#SBATCH --gres=gpu:1               # Llama-2-7B fp16 (~13 GB) fits any >=16 GB GPU.
                                   # If your Slurm requires a type: --gres=gpu:h100:1
#SBATCH --cpus-per-task=16
#SBATCH --mem=64G
#SBATCH --time=24:00:00
#SBATCH --array=0-5                # 6 shards. Keep NSHARDS below in sync.
#SBATCH --output=%x_%A_%a.out
#SBATCH --error=%x_%A_%a.err
# Email notifications: cluster requires a @tuhh.de address. To enable, uncomment:
# #SBATCH --mail-type=ALL
# #SBATCH --mail-user=cdo4933@tuhh.de

set -euo pipefail

# ---------- sharding (must match --array above) ----------
NSHARDS=6
TOTAL_ROWS=150                     # logical data rows the runner iterates (NOT wc -l)
SHARD=${SLURM_ARRAY_TASK_ID:-0}
CHUNK=$(( (TOTAL_ROWS + NSHARDS - 1) / NSHARDS ))
START_IDX=$(( SHARD * CHUNK ))
END_IDX=$(( START_IDX + CHUNK ))   # end-exclusive (Run_with_dataset.sh --end-idx)
[ "$END_IDX" -gt "$TOTAL_ROWS" ] && END_IDX="$TOTAL_ROWS"
echo "=== shard $SHARD/$NSHARDS -> rows [$START_IDX, $END_IDX) ==="

# ---------- paths ----------
export WORK=/work/cps/$USER
MODEL_DIR="$WORK/models/llama-2-7b-chat-hf"     # from download_llama2.sh
VLLM_ENV="$WORK/envs/vllm"                      # vLLM env (modern transformers)
PAIR_ENV="$WORK/envs/pair"                      # PAIR framework deps (setup_pair_env.sh)
SRC="$HOME/JailbreakingLLMs"                     # rsync source (adjust if elsewhere)

# ---------- cache redirection (keep everything off the 20 GB home quota) ----------
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

export HF_HUB_OFFLINE=1                          # weights are local; don't phone home
export PYTHONDONTWRITEBYTECODE=1
export WANDB_MODE=offline                        # sync later from a logged-in machine

# ---------- vLLM stability knobs (harmless for fp16 Llama-2) ----------
export VLLM_USE_DEEP_GEMM=0
export VLLM_USE_FLASHINFER_SAMPLER=0

# CodeQL CLI for the codeql-bandit judge (installed by setup_codeql.sh)
export PATH="$WORK/tools/codeql:$PATH"

# ---------- modules ----------
. /etc/profile.d/module.sh
module purge
module load anaconda/2023.07-1
module load gcc/14.2.0 2>/dev/null || module load gcc 2>/dev/null || echo "WARN: no gcc module; relying on system gcc"
source "$(conda info --base)/etc/profile.d/conda.sh"

# ---------- per-task working copy of the code ----------
PROJECT_DIR="$WORK/runs/llama2_pair_${SLURM_ARRAY_JOB_ID:-$$}_${SHARD}"
mkdir -p "$PROJECT_DIR"
rsync -a --exclude='__pycache__' --exclude='*.pyc' --exclude='.git' "$SRC"/ "$PROJECT_DIR"/
cd "$PROJECT_DIR" || exit 1
export PYTHONPATH="$PROJECT_DIR:${PYTHONPATH:-}"

# ---------- API keys for attacker/judge/validator (external APIs) ----------
if [ -f "$PROJECT_DIR/.env" ]; then set -a; . "$PROJECT_DIR/.env"; set +a; fi
export LOCAL_API_KEY="local-dummy"               # vLLM ignores it; framework needs the var to exist

# ---------- pick a free port + start the local vLLM target ----------
PORT=$(python -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
export LLAMA_LOCAL_API_BASE="http://127.0.0.1:${PORT}/v1"   # config.py reads this
echo "=== vLLM will serve on $LLAMA_LOCAL_API_BASE ==="

VLLM_LOG="$PROJECT_DIR/vllm_server.log"
# --chat-template: the NousResearch mirror's tokenizer_config.json has no
# chat_template, and transformers >=4.44 refuses a default one. Supply the
# canonical Llama-2 [INST]/<<SYS>> template explicitly.
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
codeql --version    # fail fast if CodeQL isn't on PATH

# FULL dataset, Python-only, this shard's row range. Target = local Llama-2.
# Attacker/validator stay on their Run_with_dataset.sh defaults (external APIs).
bash Run_with_dataset.sh \
  --dataset       LLMSecEval/LLMSecEval-Prompts_dataset.csv \
  --target-model  llama-2-7b-chat-local \
  --python-only \
  --start-idx     "$START_IDX" \
  --end-idx       "$END_IDX" \
  --output-dir    "$PROJECT_DIR/LLMSecEval"

echo "=== shard $SHARD finished, results under $PROJECT_DIR ==="
