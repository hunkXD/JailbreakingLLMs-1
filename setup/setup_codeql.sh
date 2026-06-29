#!/bin/bash -l
# =====================================================================
# Install the CodeQL CLI bundle (CLI + precompiled standard query packs
# for python/cpp) on the HPC. Run ONCE on the LOGIN node (needs internet):
#     bash setup_codeql.sh
# Adds CodeQL under $WORK/tools/codeql; the sbatch puts it on PATH.
# =====================================================================
set -euo pipefail

export WORK=/work/cps/$USER
TOOLS="$WORK/tools"
mkdir -p "$TOOLS"
cd "$TOOLS"

# The codeql-action "bundle" includes the CLI AND the compiled query packs
# (codeql/python-queries, codeql/cpp-queries). 'latest' always points at the
# newest release asset.
URL="https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz"

echo "=== downloading CodeQL bundle ==="
curl -fL --retry 3 -o codeql-bundle-linux64.tar.gz "$URL"

echo "=== extracting (creates ./codeql) ==="
rm -rf codeql            # clean any previous unpack
tar -xzf codeql-bundle-linux64.tar.gz
rm -f codeql-bundle-linux64.tar.gz

export PATH="$TOOLS/codeql:$PATH"
echo "=== verifying ==="
codeql --version
echo "--- query packs present? ---"
codeql resolve qlpacks 2>/dev/null | grep -iE "python-queries|cpp-queries" || \
  echo "(could not list packs via resolve; bundle normally includes them)"
echo "=== CodeQL ready at $TOOLS/codeql ==="
